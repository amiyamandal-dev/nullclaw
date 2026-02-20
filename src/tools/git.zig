const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isResolvedPathAllowed = @import("file_edit.zig").isResolvedPathAllowed;

/// Git operations tool for structured repository management.
pub const GitTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *GitTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args: JsonObjectMap) anyerror!ToolResult {
        const self: *GitTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "git_operations";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Perform structured Git operations (status, diff, log, branch, commit, add, checkout, stash).";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"operation":{"type":"string","enum":["status","diff","log","branch","commit","add","checkout","stash"],"description":"Git operation to perform"},"message":{"type":"string","description":"Commit message (for commit)"},"paths":{"type":"string","description":"File paths (for add)"},"branch":{"type":"string","description":"Branch name (for checkout)"},"files":{"type":"string","description":"Files to diff"},"cached":{"type":"boolean","description":"Show staged changes (diff)"},"limit":{"type":"integer","description":"Log entry count (default: 10)"},"cwd":{"type":"string","description":"Repository directory (absolute path within allowed paths; defaults to workspace)"}},"required":["operation"]}
        ;
    }

    /// Returns false if the git arguments contain dangerous patterns.
    fn sanitizeGitArgs(args: []const u8) bool {
        // Block dangerous git options that could lead to command injection
        const dangerous_prefixes = [_][]const u8{
            "--exec=",
            "--upload-pack=",
            "--receive-pack=",
            "--pager=",
            "--editor=",
        };
        const dangerous_exact = [_][]const u8{
            "--no-verify",
        };
        const dangerous_substrings = [_][]const u8{
            "$(",
            "`",
        };
        const dangerous_chars = [_]u8{ '|', ';', '>' };

        var it = std.mem.tokenizeScalar(u8, args, ' ');
        while (it.next()) |arg| {
            // Check dangerous prefixes (case-insensitive via lowercase comparison)
            for (dangerous_prefixes) |prefix| {
                if (arg.len >= prefix.len and std.ascii.eqlIgnoreCase(arg[0..prefix.len], prefix))
                    return false;
            }
            // Check exact matches (case-insensitive)
            for (dangerous_exact) |exact| {
                if (arg.len == exact.len and std.ascii.eqlIgnoreCase(arg, exact))
                    return false;
            }
            // Check dangerous substrings
            for (dangerous_substrings) |sub| {
                if (std.mem.indexOf(u8, arg, sub) != null)
                    return false;
            }
            // Check dangerous single characters
            for (arg) |ch| {
                for (dangerous_chars) |dc| {
                    if (ch == dc) return false;
                }
            }
            // Block -c config injection: exact "-c" or "-c=..." (but not "--cached", "-cached", etc.)
            if (arg.len == 2 and arg[0] == '-' and (arg[1] == 'c' or arg[1] == 'C')) {
                return false;
            }
            if (arg.len > 2 and arg[0] == '-' and (arg[1] == 'c' or arg[1] == 'C') and arg[2] == '=') {
                return false;
            }
        }
        return true;
    }

    /// Truncate a commit message to max_bytes, respecting UTF-8 boundaries.
    fn truncateCommitMessage(msg: []const u8, max_bytes: usize) []const u8 {
        if (msg.len <= max_bytes) return msg;
        var i = max_bytes;
        while (i > 0 and (msg[i] & 0xC0) == 0x80) i -= 1;
        return msg[0..i];
    }

    /// Returns true for operations that modify the repository.
    fn requiresWriteAccess(operation: []const u8) bool {
        const write_ops = [_][]const u8{
            "commit",   "push",  "merge", "rebase", "reset",
            "checkout", "add",   "rm",    "mv",     "tag",
            "branch",   "clean",
        };
        for (write_ops) |op| {
            if (std.mem.eql(u8, operation, op)) return true;
        }
        // "stash push" is write, but we check at the stash level
        if (std.mem.eql(u8, operation, "stash")) return true;
        return false;
    }

    fn execute(self: *GitTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const operation = root.getString(args, "operation") orelse
            return ToolResult.fail("Missing 'operation' parameter");

        // Sanitize all string arguments before execution
        const fields_to_check = [_][]const u8{ "message", "paths", "branch", "files", "action" };
        for (fields_to_check) |field| {
            if (root.getString(args, field)) |val| {
                if (!sanitizeGitArgs(val))
                    return ToolResult.fail("Unsafe git arguments detected");
            }
        }

        // Resolve optional cwd override
        const effective_cwd = if (root.getString(args, "cwd")) |cwd| blk: {
            if (cwd.len == 0 or !std.fs.path.isAbsolute(cwd))
                return ToolResult.fail("cwd must be an absolute path");
            if (self.allowed_paths.len == 0)
                return ToolResult.fail("cwd not allowed (no allowed_paths configured)");
            const resolved_cwd = std.fs.cwd().realpathAlloc(allocator, cwd) catch |err| {
                const err_msg = try std.fmt.allocPrint(allocator, "Failed to resolve cwd: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = err_msg };
            };
            defer allocator.free(resolved_cwd);
            const ws_resolved: ?[]const u8 = std.fs.cwd().realpathAlloc(allocator, self.workspace_dir) catch null;
            defer if (ws_resolved) |wr| allocator.free(wr);
            if (!isResolvedPathAllowed(allocator, resolved_cwd, ws_resolved orelse "", self.allowed_paths))
                return ToolResult.fail("cwd is outside allowed areas");
            break :blk cwd;
        } else self.workspace_dir;

        if (std.mem.eql(u8, operation, "status")) return self.runGitOp(allocator, effective_cwd, &.{ "status", "--porcelain=2", "--branch" });
        if (std.mem.eql(u8, operation, "diff")) return self.gitDiff(allocator, effective_cwd, args);
        if (std.mem.eql(u8, operation, "log")) return self.gitLog(allocator, effective_cwd, args);
        if (std.mem.eql(u8, operation, "branch")) return self.runGitOp(allocator, effective_cwd, &.{ "branch", "--format=%(refname:short)|%(HEAD)" });
        if (std.mem.eql(u8, operation, "commit")) return self.gitCommit(allocator, effective_cwd, args);
        if (std.mem.eql(u8, operation, "add")) return self.gitAdd(allocator, effective_cwd, args);
        if (std.mem.eql(u8, operation, "checkout")) return self.gitCheckout(allocator, effective_cwd, args);
        if (std.mem.eql(u8, operation, "stash")) return self.gitStash(allocator, effective_cwd, args);

        const msg = try std.fmt.allocPrint(allocator, "Unknown operation: {s}", .{operation});
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    }

    fn runGit(_: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: []const []const u8) !struct { stdout: []u8, stderr: []u8, success: bool } {
        var argv_buf: [32][]const u8 = undefined;
        argv_buf[0] = "git";
        const arg_count = @min(args.len, argv_buf.len - 1);
        for (args[0..arg_count], 1..) |a, i| {
            argv_buf[i] = a;
        }

        var child = std.process.Child.init(argv_buf[0 .. arg_count + 1], allocator);
        child.cwd = git_cwd;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();
        const stdout = try child.stdout.?.readToEndAlloc(allocator, 1_048_576);
        const stderr = try child.stderr.?.readToEndAlloc(allocator, 1_048_576);
        const term = try child.wait();

        const success = switch (term) {
            .Exited => |code| code == 0,
            else => false,
        };
        return .{ .stdout = stdout, .stderr = stderr, .success = success };
    }

    /// Run a simple git operation and return stdout on success.
    fn runGitOp(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: []const []const u8) !ToolResult {
        const result = try self.runGit(allocator, git_cwd, args);
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git operation failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }

    fn gitDiff(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const cached = root.getBool(args, "cached") orelse false;
        const files = root.getString(args, "files") orelse ".";

        var argv_buf: [8][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "diff";
        argc += 1;
        argv_buf[argc] = "--unified=3";
        argc += 1;
        if (cached) {
            argv_buf[argc] = "--cached";
            argc += 1;
        }
        argv_buf[argc] = "--";
        argc += 1;
        argv_buf[argc] = files;
        argc += 1;

        const result = try self.runGit(allocator, git_cwd, argv_buf[0..argc]);
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git diff failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }

    fn gitLog(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const limit_raw = root.getInt(args, "limit") orelse 10;
        const limit: usize = @intCast(@min(@max(limit_raw, 1), 1000));

        var limit_buf: [16]u8 = undefined;
        const limit_str = try std.fmt.bufPrint(&limit_buf, "-{d}", .{limit});

        const result = try self.runGit(allocator, git_cwd, &.{
            "log",
            limit_str,
            "--pretty=format:%H|%an|%ae|%ad|%s",
            "--date=iso",
        });
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git log failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        return ToolResult{ .success = true, .output = result.stdout };
    }

    fn gitCommit(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const raw_message = root.getString(args, "message") orelse
            return ToolResult.fail("Missing 'message' parameter for commit");

        if (raw_message.len == 0) return ToolResult.fail("Commit message cannot be empty");

        const message = truncateCommitMessage(raw_message, 2000);

        const result = try self.runGit(allocator, git_cwd, &.{ "commit", "-m", message });
        defer allocator.free(result.stderr);
        if (!result.success) {
            defer allocator.free(result.stdout);
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git commit failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        defer allocator.free(result.stdout);
        const out = try std.fmt.allocPrint(allocator, "Committed: {s}", .{message});
        return ToolResult{ .success = true, .output = out };
    }

    fn gitAdd(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const paths = root.getString(args, "paths") orelse
            return ToolResult.fail("Missing 'paths' parameter for add");

        const result = try self.runGit(allocator, git_cwd, &.{ "add", "--", paths });
        defer allocator.free(result.stderr);
        defer allocator.free(result.stdout);
        if (!result.success) {
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git add failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        const out = try std.fmt.allocPrint(allocator, "Staged: {s}", .{paths});
        return ToolResult{ .success = true, .output = out };
    }

    fn gitCheckout(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const branch = root.getString(args, "branch") orelse
            return ToolResult.fail("Missing 'branch' parameter for checkout");

        // Block dangerous branch names
        if (std.mem.indexOfScalar(u8, branch, ';') != null or
            std.mem.indexOfScalar(u8, branch, '|') != null or
            std.mem.indexOfScalar(u8, branch, '`') != null or
            std.mem.indexOf(u8, branch, "$(") != null)
        {
            return ToolResult.fail("Branch name contains invalid characters");
        }

        const result = try self.runGit(allocator, git_cwd, &.{ "checkout", branch });
        defer allocator.free(result.stderr);
        defer allocator.free(result.stdout);
        if (!result.success) {
            const msg = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Git checkout failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        const out = try std.fmt.allocPrint(allocator, "Switched to branch: {s}", .{branch});
        return ToolResult{ .success = true, .output = out };
    }

    fn gitStash(self: *GitTool, allocator: std.mem.Allocator, git_cwd: []const u8, args: JsonObjectMap) !ToolResult {
        const action = root.getString(args, "action") orelse "push";

        if (std.mem.eql(u8, action, "push") or std.mem.eql(u8, action, "save")) {
            const result = try self.runGit(allocator, git_cwd, &.{ "stash", "push", "-m", "auto-stash" });
            defer allocator.free(result.stderr);
            if (!result.success) {
                defer allocator.free(result.stdout);
                const msg = try allocator.dupe(u8, result.stderr);
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
            return ToolResult{ .success = true, .output = result.stdout };
        }

        if (std.mem.eql(u8, action, "pop")) {
            const result = try self.runGit(allocator, git_cwd, &.{ "stash", "pop" });
            defer allocator.free(result.stderr);
            if (!result.success) {
                defer allocator.free(result.stdout);
                const msg = try allocator.dupe(u8, result.stderr);
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
            return ToolResult{ .success = true, .output = result.stdout };
        }

        if (std.mem.eql(u8, action, "list")) {
            const result = try self.runGit(allocator, git_cwd, &.{ "stash", "list" });
            defer allocator.free(result.stderr);
            if (!result.success) {
                defer allocator.free(result.stdout);
                const msg = try allocator.dupe(u8, result.stderr);
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
            return ToolResult{ .success = true, .output = result.stdout };
        }

        const msg = try std.fmt.allocPrint(allocator, "Unknown stash action: {s}", .{action});
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "git tool name" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    try std.testing.expectEqualStrings("git_operations", t.name());
}

test "git tool schema has operation" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "operation") != null);
}

test "git rejects missing operation" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "git rejects unknown operation" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"push\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown operation") != null);
}

test "git checkout blocks injection" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"checkout\", \"branch\": \"main; rm -rf /\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    // Caught by sanitizeGitArgs in execute() before reaching gitCheckout
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsafe") != null);
}

test "git commit missing message" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"commit\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "git commit empty message" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"commit\", \"message\": \"\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "git add missing paths" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"add\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

// ── sanitizeGitArgs tests ───────────────────────────────────────────

test "sanitizeGitArgs blocks --exec=cmd" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--exec=rm -rf /"));
}

test "sanitizeGitArgs blocks --upload-pack=evil" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--upload-pack=evil"));
}

test "sanitizeGitArgs blocks --no-verify" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--no-verify"));
}

test "sanitizeGitArgs blocks command substitution $()" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("$(evil)"));
}

test "sanitizeGitArgs blocks backtick" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("`malicious`"));
}

test "sanitizeGitArgs blocks pipe" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("arg | cat /etc/passwd"));
}

test "sanitizeGitArgs blocks semicolon" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("arg; rm -rf /"));
}

test "sanitizeGitArgs blocks redirect" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("file.txt > /tmp/out"));
}

test "sanitizeGitArgs blocks -c config injection" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("-c core.sshCommand=evil"));
    try std.testing.expect(!GitTool.sanitizeGitArgs("-c=core.pager=less"));
}

test "sanitizeGitArgs blocks --pager and --editor" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--pager=less"));
    try std.testing.expect(!GitTool.sanitizeGitArgs("--editor=vim"));
}

test "sanitizeGitArgs blocks --receive-pack" {
    try std.testing.expect(!GitTool.sanitizeGitArgs("--receive-pack=evil"));
}

test "sanitizeGitArgs allows --oneline" {
    try std.testing.expect(GitTool.sanitizeGitArgs("--oneline"));
}

test "sanitizeGitArgs allows --stat" {
    try std.testing.expect(GitTool.sanitizeGitArgs("--stat"));
}

test "sanitizeGitArgs allows safe branch names" {
    try std.testing.expect(GitTool.sanitizeGitArgs("main"));
    try std.testing.expect(GitTool.sanitizeGitArgs("feature/test-branch"));
    try std.testing.expect(GitTool.sanitizeGitArgs("src/main.zig"));
    try std.testing.expect(GitTool.sanitizeGitArgs("."));
}

test "sanitizeGitArgs allows --cached (not blocked by -c check)" {
    try std.testing.expect(GitTool.sanitizeGitArgs("--cached"));
    try std.testing.expect(GitTool.sanitizeGitArgs("-cached"));
}

// ── truncateCommitMessage tests ─────────────────────────────────────

test "truncateCommitMessage short message unchanged" {
    const msg = "short message";
    try std.testing.expectEqualStrings(msg, GitTool.truncateCommitMessage(msg, 2000));
}

test "truncateCommitMessage truncates at UTF-8 boundary" {
    // "Éééééé" in UTF-8 is 12 bytes (2 bytes per accented char)
    const msg = "Éééééé ààà!"; // 20 bytes
    const truncated = GitTool.truncateCommitMessage(msg, 10);
    // Should truncate to 10 bytes which is at a clean boundary (5 Cyrillic chars)
    try std.testing.expect(truncated.len <= 10);
    // Must not end in the middle of a multi-byte sequence
    try std.testing.expect(std.unicode.utf8ValidateSlice(truncated));
}

test "truncateCommitMessage exact boundary" {
    const msg = "hello";
    try std.testing.expectEqualStrings("hello", GitTool.truncateCommitMessage(msg, 5));
    try std.testing.expectEqualStrings("hello", GitTool.truncateCommitMessage(msg, 100));
}

// ── requiresWriteAccess tests ───────────────────────────────────────

test "requiresWriteAccess returns true for commit" {
    try std.testing.expect(GitTool.requiresWriteAccess("commit"));
}

test "requiresWriteAccess returns true for push" {
    try std.testing.expect(GitTool.requiresWriteAccess("push"));
}

test "requiresWriteAccess returns true for add" {
    try std.testing.expect(GitTool.requiresWriteAccess("add"));
}

test "requiresWriteAccess returns false for status" {
    try std.testing.expect(!GitTool.requiresWriteAccess("status"));
}

test "requiresWriteAccess returns false for diff" {
    try std.testing.expect(!GitTool.requiresWriteAccess("diff"));
}

test "requiresWriteAccess returns false for log" {
    try std.testing.expect(!GitTool.requiresWriteAccess("log"));
}

// ── Integration: sanitizeGitArgs in execute ─────────────────────────

test "git execute blocks unsafe args in message" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"commit\", \"message\": \"$(evil)\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsafe") != null);
}

test "git execute blocks unsafe args in paths" {
    var gt = GitTool{ .workspace_dir = "/tmp" };
    const t = gt.tool();
    const parsed = try root.parseTestArgs("{\"operation\": \"add\", \"paths\": \"file.txt; rm -rf /\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unsafe") != null);
}
