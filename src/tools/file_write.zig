const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isPathSafe = @import("file_edit.zig").isPathSafe;
const isResolvedPathAllowed = @import("file_edit.zig").isResolvedPathAllowed;

/// Write file contents with workspace path scoping.
pub const FileWriteTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *FileWriteTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args: JsonObjectMap) anyerror!ToolResult {
        const self: *FileWriteTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "file_write";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Write contents to a file in the workspace";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file within the workspace"},"content":{"type":"string","description":"Content to write to the file"}},"required":["path","content"]}
        ;
    }

    fn execute(self: *FileWriteTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const path = root.getString(args, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        const content = root.getString(args, "content") orelse
            return ToolResult.fail("Missing 'content' parameter");

        // Build full path — absolute or relative
        const full_path = if (std.fs.path.isAbsolute(path)) blk: {
            if (self.allowed_paths.len == 0)
                return ToolResult.fail("Absolute paths not allowed (no allowed_paths configured)");
            if (std.mem.indexOfScalar(u8, path, 0) != null)
                return ToolResult.fail("Path contains null bytes");
            break :blk try allocator.dupe(u8, path);
        } else blk: {
            if (!isPathSafe(path))
                return ToolResult.fail("Path not allowed: contains traversal or absolute path");
            break :blk try std.fs.path.join(allocator, &.{ self.workspace_dir, path });
        };
        defer allocator.free(full_path);

        // Ensure parent directory exists
        if (std.fs.path.dirname(full_path)) |parent| {
            std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => {
                    std.fs.cwd().makePath(parent) catch |e| {
                        const msg = try std.fmt.allocPrint(allocator, "Failed to create directory: {}", .{e});
                        return ToolResult{ .success = false, .output = "", .error_msg = msg };
                    };
                },
            };

            // Resolve parent to validate against policy
            const resolved_parent = std.fs.cwd().realpathAlloc(allocator, parent) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to resolve path: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            defer allocator.free(resolved_parent);

            const ws_resolved: ?[]const u8 = std.fs.cwd().realpathAlloc(allocator, self.workspace_dir) catch null;
            defer if (ws_resolved) |wr| allocator.free(wr);

            if (!isResolvedPathAllowed(allocator, resolved_parent, ws_resolved orelse "", self.allowed_paths)) {
                return ToolResult.fail("Path is outside allowed areas");
            }
        }

        // Write file
        const file = std.fs.createFileAbsolute(full_path, .{}) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to create file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer file.close();

        file.writeAll(content) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to write file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        const msg = try std.fmt.allocPrint(allocator, "Written {d} bytes to {s}", .{ content.len, path });
        return ToolResult{ .success = true, .output = msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "file_write tool name" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    try std.testing.expectEqualStrings("file_write", t.name());
}

test "file_write tool schema has path and content" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "path") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "content") != null);
}

test "file_write creates file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"out.txt\", \"content\": \"written!\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "8 bytes") != null);

    // Verify file contents
    const actual = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "out.txt", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("written!", actual);
}

test "file_write creates parent dirs" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"a/b/c/deep.txt\", \"content\": \"deep\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);

    const actual = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "a/b/c/deep.txt", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("deep", actual);
}

test "file_write overwrites existing" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "exist.txt", .data = "old" });
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"exist.txt\", \"content\": \"new\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);

    const actual = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "exist.txt", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("new", actual);
}

test "file_write blocks path traversal" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"../../etc/evil\", \"content\": \"bad\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not allowed") != null);
}

test "file_write blocks absolute path" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"/etc/evil\", \"content\": \"bad\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_write missing path param" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"content\": \"data\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_write missing content param" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"file.txt\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_write empty content" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"empty.txt\", \"content\": \"\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "0 bytes") != null);
}
