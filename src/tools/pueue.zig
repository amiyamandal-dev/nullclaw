const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

/// Pueue task manager tool for long-running background commands.
pub const PueueTool = struct {
    workspace_dir: []const u8,

    pub const tool_name = "pueue";
    pub const tool_description = "Manage long-running background tasks via pueue. Enqueue commands, check status, view logs, and control task lifecycle without blocking the conversation.";
    pub const tool_params =
        \\{"type":"object","properties":{"action":{"type":"string","enum":["add","status","log","remove","kill","pause","start","clean","follow"],"description":"Pueue operation to perform"},"command":{"type":"string","description":"Shell command to enqueue (for 'add' action)"},"task_id":{"type":"string","description":"Task ID (for log/remove/kill/pause/start/follow)"},"group":{"type":"string","description":"Task group name (for add/status)"},"label":{"type":"string","description":"Human-readable label (for add)"},"delay":{"type":"string","description":"Delay before starting, e.g. '5min' or '2h' (for add)"},"lines":{"type":"integer","description":"Number of output lines to show (for log/follow, default 50)"}},"required":["action"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *PueueTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *PueueTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const action = root.getString(args, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        const Action = enum { add, status, log, remove, kill, pause, start, clean, follow };
        const action_map = std.StaticStringMap(Action).initComptime(.{
            .{ "add", .add },
            .{ "status", .status },
            .{ "log", .log },
            .{ "remove", .remove },
            .{ "kill", .kill },
            .{ "pause", .pause },
            .{ "start", .start },
            .{ "clean", .clean },
            .{ "follow", .follow },
        });

        const act = action_map.get(action) orelse {
            const msg = try std.fmt.allocPrint(allocator, "Unknown action: {s}", .{action});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        return switch (act) {
            .add => self.doAdd(allocator, args),
            .status => self.doStatus(allocator, args),
            .log => self.doTaskIdAction(allocator, args, "log"),
            .remove => self.doTaskIdAction(allocator, args, "remove"),
            .kill => self.doTaskIdAction(allocator, args, "kill"),
            .pause => self.doTaskIdAction(allocator, args, "pause"),
            .start => self.doTaskIdAction(allocator, args, "start"),
            .clean => self.runPueue(allocator, &.{ "pueue", "clean" }),
            .follow => self.doFollow(allocator, args),
        };
    }

    fn doAdd(self: *PueueTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const command = root.getString(args, "command") orelse
            return ToolResult.fail("Missing 'command' parameter for add");

        var argv_buf: [16][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "pueue";
        argc += 1;
        argv_buf[argc] = "add";
        argc += 1;

        if (root.getString(args, "group")) |group| {
            argv_buf[argc] = "--group";
            argc += 1;
            argv_buf[argc] = group;
            argc += 1;
        }

        if (root.getString(args, "label")) |label| {
            argv_buf[argc] = "--label";
            argc += 1;
            argv_buf[argc] = label;
            argc += 1;
        }

        if (root.getString(args, "delay")) |delay| {
            argv_buf[argc] = "--delay";
            argc += 1;
            argv_buf[argc] = delay;
            argc += 1;
        }

        argv_buf[argc] = "--";
        argc += 1;
        argv_buf[argc] = command;
        argc += 1;

        return self.runPueue(allocator, argv_buf[0..argc]);
    }

    fn doStatus(self: *PueueTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        if (root.getString(args, "group")) |group| {
            return self.runPueue(allocator, &.{ "pueue", "status", "--json", "--group", group });
        }
        return self.runPueue(allocator, &.{ "pueue", "status", "--json" });
    }

    fn doTaskIdAction(self: *PueueTool, allocator: std.mem.Allocator, args: JsonObjectMap, action: []const u8) !ToolResult {
        const task_id = root.getString(args, "task_id") orelse {
            const msg = try std.fmt.allocPrint(allocator, "Missing 'task_id' parameter for {s}", .{action});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        if (std.mem.eql(u8, action, "log")) {
            if (root.getInt(args, "lines")) |lines_raw| {
                var lines_buf: [16]u8 = undefined;
                const lines_str = try std.fmt.bufPrint(&lines_buf, "{d}", .{lines_raw});
                return self.runPueue(allocator, &.{ "pueue", "log", "--lines", lines_str, task_id });
            }
            return self.runPueue(allocator, &.{ "pueue", "log", task_id });
        }

        return self.runPueue(allocator, &.{ "pueue", action, task_id });
    }

    fn doFollow(self: *PueueTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const task_id = root.getString(args, "task_id") orelse {
            const msg = try std.fmt.allocPrint(allocator, "Missing 'task_id' parameter for follow", .{});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        // Use `pueue log` with lines instead of `pueue follow` (which is blocking/streaming).
        // This gives a non-blocking snapshot of recent output.
        const lines_raw = root.getInt(args, "lines") orelse 50;
        var lines_buf: [16]u8 = undefined;
        const lines_str = try std.fmt.bufPrint(&lines_buf, "{d}", .{lines_raw});
        return self.runPueue(allocator, &.{ "pueue", "log", "--lines", lines_str, task_id });
    }

    fn runPueue(self: *PueueTool, allocator: std.mem.Allocator, argv: []const []const u8) !ToolResult {
        if (builtin.is_test) return ToolResult.ok("");

        const proc = @import("process_util.zig");
        const result = proc.run(allocator, argv, .{ .cwd = self.workspace_dir }) catch {
            return ToolResult.fail("pueue not installed. Install via: cargo install pueue OR brew install pueue");
        };
        defer allocator.free(result.stderr);

        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "pueue command failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "pueue tool name" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    try std.testing.expectEqualStrings("pueue", t.name());
}

test "pueue tool schema contains all actions" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const schema = t.parametersJson();
    for ([_][]const u8{ "add", "status", "log", "remove", "kill", "pause", "start", "clean", "follow" }) |action| {
        try std.testing.expect(std.mem.indexOf(u8, schema, action) != null);
    }
}

test "pueue rejects missing action" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "pueue rejects unknown action" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"explode\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown action") != null);
}

test "pueue add missing command" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"add\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "command") != null);
}

test "pueue log missing task_id" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"log\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "task_id") != null);
}

test "pueue kill missing task_id" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"kill\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "task_id") != null);
}

test "pueue remove missing task_id" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"remove\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "task_id") != null);
}

test "pueue pause missing task_id" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"pause\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "task_id") != null);
}

test "pueue start missing task_id" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"start\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "task_id") != null);
}

test "pueue follow missing task_id" {
    var pt = PueueTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"follow\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "task_id") != null);
}
