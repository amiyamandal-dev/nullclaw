const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const google_auth = @import("google_auth.zig");

const GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me";
const PROVIDER_KEY = "google_mail";

/// Google Mail tool — send, read, search, and list Gmail messages.
/// Requires Google OAuth device code flow for authentication.
pub const GoogleMailTool = struct {
    client_id: []const u8,
    client_secret: ?[]const u8,

    pub const tool_name = "google_mail";
    pub const tool_description = "Interact with Gmail. Actions: 'connect' (OAuth setup), " ++
        "'list' (recent messages, optional max_results), " ++
        "'read' (full message by id), " ++
        "'search' (query Gmail with q parameter, optional max_results), " ++
        "'send' (send email with to/subject/body).";
    pub const tool_params =
        \\{"type":"object","properties":{"action":{"type":"string","enum":["connect","list","read","search","send"],"description":"Operation to perform"},"id":{"type":"string","description":"Message ID for read action"},"q":{"type":"string","description":"Gmail search query for search action"},"to":{"type":"string","description":"Recipient email for send action"},"subject":{"type":"string","description":"Email subject for send action"},"body":{"type":"string","description":"Email body for send action"},"max_results":{"type":"integer","description":"Max messages to return (default 10)"}},"required":["action"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *GoogleMailTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *GoogleMailTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const action = root.getString(args, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        if (std.mem.eql(u8, action, "connect")) {
            return google_auth.connectGoogle(allocator, PROVIDER_KEY, self.client_id, google_auth.GMAIL_SCOPES);
        } else if (std.mem.eql(u8, action, "list")) {
            return self.listMessages(allocator, args);
        } else if (std.mem.eql(u8, action, "read")) {
            return self.readMessage(allocator, args);
        } else if (std.mem.eql(u8, action, "search")) {
            return self.searchMessages(allocator, args);
        } else if (std.mem.eql(u8, action, "send")) {
            return self.sendMessage(allocator, args);
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Unknown action '{s}'. Use 'connect', 'list', 'read', 'search', or 'send'.", .{action});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
    }

    // ── List messages ─────────────────────────────────────────────

    fn listMessages(self: *GoogleMailTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const token = switch (google_auth.getGoogleToken(allocator, PROVIDER_KEY, self.client_id, self.client_secret)) {
            .token => |t| t,
            .err => |e| return e,
        };
        defer allocator.free(token);

        const max = getMaxResults(args);
        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, GMAIL_API_BASE ++ "/messages?maxResults={d}", .{max}) catch
            return ToolResult.fail("URL too long");

        return httpGetWithToken(allocator, url, token);
    }

    // ── Read message ──────────────────────────────────────────────

    fn readMessage(self: *GoogleMailTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const msg_id = root.getString(args, "id") orelse
            return ToolResult.fail("Missing 'id' parameter for read action");

        const token = switch (google_auth.getGoogleToken(allocator, PROVIDER_KEY, self.client_id, self.client_secret)) {
            .token => |t| t,
            .err => |e| return e,
        };
        defer allocator.free(token);

        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, GMAIL_API_BASE ++ "/messages/{s}?format=full", .{msg_id}) catch
            return ToolResult.fail("URL too long");

        return httpGetWithToken(allocator, url, token);
    }

    // ── Search messages ───────────────────────────────────────────

    fn searchMessages(self: *GoogleMailTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const query = root.getString(args, "q") orelse
            return ToolResult.fail("Missing 'q' parameter for search action");

        const token = switch (google_auth.getGoogleToken(allocator, PROVIDER_KEY, self.client_id, self.client_secret)) {
            .token => |t| t,
            .err => |e| return e,
        };
        defer allocator.free(token);

        const max = getMaxResults(args);

        // URL-encode the query by using curl's --data-urlencode is complex,
        // so we build the URL with the raw query (curl handles it)
        const url = try std.fmt.allocPrint(allocator, GMAIL_API_BASE ++ "/messages?q={s}&maxResults={d}", .{ query, max });
        defer allocator.free(url);

        return httpGetWithToken(allocator, url, token);
    }

    // ── Send message ──────────────────────────────────────────────

    fn sendMessage(self: *GoogleMailTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const to = root.getString(args, "to") orelse
            return ToolResult.fail("Missing 'to' parameter for send action");
        const subject = root.getString(args, "subject") orelse
            return ToolResult.fail("Missing 'subject' parameter for send action");
        const body = root.getString(args, "body") orelse
            return ToolResult.fail("Missing 'body' parameter for send action");

        const token = switch (google_auth.getGoogleToken(allocator, PROVIDER_KEY, self.client_id, self.client_secret)) {
            .token => |t| t,
            .err => |e| return e,
        };
        defer allocator.free(token);

        // Build RFC 2822 message
        const raw_msg = try std.fmt.allocPrint(
            allocator,
            "To: {s}\r\nSubject: {s}\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n{s}",
            .{ to, subject, body },
        );
        defer allocator.free(raw_msg);

        // Base64url encode the message
        const Encoder = std.base64.url_safe_no_pad.Encoder;
        const encoded_len = Encoder.calcSize(raw_msg.len);
        const encoded = try allocator.alloc(u8, encoded_len);
        defer allocator.free(encoded);
        _ = Encoder.encode(encoded, raw_msg);

        // Build JSON body
        const json_body = try std.fmt.allocPrint(allocator, "{{\"raw\":\"{s}\"}}", .{encoded});
        defer allocator.free(json_body);

        return httpPostWithToken(allocator, GMAIL_API_BASE ++ "/messages/send", token, json_body);
    }

    // ── Helpers ───────────────────────────────────────────────────

    fn getMaxResults(args: JsonObjectMap) u32 {
        if (root.getValue(args, "max_results")) |v| {
            switch (v) {
                .integer => |i| return if (i > 0 and i <= 100) @intCast(i) else 10,
                else => {},
            }
        }
        return 10;
    }
};

// ── HTTP helpers (curl-based, following composio pattern) ────────────

fn httpGetWithToken(allocator: std.mem.Allocator, url: []const u8, token: []const u8) !ToolResult {
    const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{token});
    defer allocator.free(auth_header);

    const argv = &[_][]const u8{
        "curl", "-sL", "-m", "15",
        "-H", auth_header,
        url,
    };

    return runCurl(allocator, argv);
}

fn httpPostWithToken(allocator: std.mem.Allocator, url: []const u8, token: []const u8, body: []const u8) !ToolResult {
    const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{token});
    defer allocator.free(auth_header);

    const argv = &[_][]const u8{
        "curl", "-sL", "-m", "15",
        "-X",   "POST",
        "-H",   auth_header,
        "-H",   "Content-Type: application/json",
        "-d",   body,
        url,
    };

    return runCurl(allocator, argv);
}

fn runCurl(allocator: std.mem.Allocator, argv: []const []const u8) !ToolResult {
    const proc = @import("process_util.zig");
    const result = try proc.run(allocator, argv, .{});
    defer allocator.free(result.stderr);
    if (result.success) {
        if (result.stdout.len > 0) return ToolResult{ .success = true, .output = result.stdout };
        allocator.free(result.stdout);
        return ToolResult{ .success = true, .output = try allocator.dupe(u8, "(empty response)") };
    }
    defer allocator.free(result.stdout);
    if (result.exit_code != null) {
        const err_out = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "curl failed with non-zero exit code");
        return ToolResult{ .success = false, .output = "", .error_msg = err_out };
    }
    return ToolResult{ .success = false, .output = "", .error_msg = "curl terminated by signal" };
}

// ── Tests ───────────────────────────────────────────────────────────

test "google_mail tool name" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    try std.testing.expectEqualStrings("google_mail", t.name());
}

test "google_mail tool schema has action" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "connect") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "list") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "read") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "search") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "send") != null);
}

test "google_mail missing action returns error" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "google_mail unknown action returns error" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"unknown\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown action") != null);
}

test "google_mail read missing id returns error" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"read\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "id") != null);
}

test "google_mail search missing q returns error" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"search\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "q") != null);
}

test "google_mail send missing to returns error" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"send\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "to") != null);
}

test "google_mail send missing subject returns error" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"send\", \"to\": \"a@b.com\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "subject") != null);
}

test "google_mail send missing body returns error" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"send\", \"to\": \"a@b.com\", \"subject\": \"hi\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "body") != null);
}

test "google_mail list not authenticated returns error" {
    var gmt = GoogleMailTool{ .client_id = "test-id", .client_secret = null };
    const t = gmt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"list\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "connect") != null);
}
