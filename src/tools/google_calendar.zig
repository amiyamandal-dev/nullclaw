const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const google_auth = @import("google_auth.zig");
const appendJsonEscaped = @import("../util.zig").appendJsonEscaped;

const CALENDAR_API_BASE = "https://www.googleapis.com/calendar/v3";
const PROVIDER_KEY = "google_calendar";

/// Google Calendar tool — list, create, update, and delete calendar events.
/// Requires Google OAuth device code flow for authentication.
pub const GoogleCalendarTool = struct {
    client_id: []const u8,
    client_secret: ?[]const u8,

    pub const tool_name = "google_calendar";
    pub const tool_description = "Interact with Google Calendar. Actions: 'connect' (OAuth setup), " ++
        "'list_events' (list events, optional calendar_id/time_min/time_max/max_results), " ++
        "'create_event' (create event with summary/start/end, optional calendar_id/description/location), " ++
        "'update_event' (update event by event_id, optional summary/start/end/description/location), " ++
        "'delete_event' (delete event by event_id, optional calendar_id).";
    pub const tool_params =
        \\{"type":"object","properties":{"action":{"type":"string","enum":["connect","list_events","create_event","update_event","delete_event"],"description":"Operation to perform"},"calendar_id":{"type":"string","description":"Calendar ID (default: primary)"},"event_id":{"type":"string","description":"Event ID for update/delete"},"summary":{"type":"string","description":"Event title"},"description":{"type":"string","description":"Event description"},"location":{"type":"string","description":"Event location"},"start":{"type":"string","description":"Start time (RFC3339, e.g. 2024-01-15T09:00:00-05:00)"},"end":{"type":"string","description":"End time (RFC3339)"},"time_min":{"type":"string","description":"Lower bound for list_events (RFC3339)"},"time_max":{"type":"string","description":"Upper bound for list_events (RFC3339)"},"max_results":{"type":"integer","description":"Max events to return (default 10)"}},"required":["action"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *GoogleCalendarTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *GoogleCalendarTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const action = root.getString(args, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        if (std.mem.eql(u8, action, "connect")) {
            return google_auth.connectGoogle(allocator, PROVIDER_KEY, self.client_id, google_auth.CALENDAR_SCOPES);
        } else if (std.mem.eql(u8, action, "list_events")) {
            return self.listEvents(allocator, args);
        } else if (std.mem.eql(u8, action, "create_event")) {
            return self.createEvent(allocator, args);
        } else if (std.mem.eql(u8, action, "update_event")) {
            return self.updateEvent(allocator, args);
        } else if (std.mem.eql(u8, action, "delete_event")) {
            return self.deleteEvent(allocator, args);
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Unknown action '{s}'. Use 'connect', 'list_events', 'create_event', 'update_event', or 'delete_event'.", .{action});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
    }

    // ── List events ───────────────────────────────────────────────

    fn listEvents(self: *GoogleCalendarTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const token = switch (google_auth.getGoogleToken(allocator, PROVIDER_KEY, self.client_id, self.client_secret)) {
            .token => |t| t,
            .err => |e| return e,
        };
        defer allocator.free(token);

        const cal_id = root.getString(args, "calendar_id") orelse "primary";
        const max = getMaxResults(args);

        var url_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer url_buf.deinit(allocator);

        try url_buf.appendSlice(allocator, CALENDAR_API_BASE ++ "/calendars/");
        try url_buf.appendSlice(allocator, cal_id);
        try url_buf.appendSlice(allocator, "/events?singleEvents=true&orderBy=startTime");

        const max_str = try std.fmt.allocPrint(allocator, "&maxResults={d}", .{max});
        defer allocator.free(max_str);
        try url_buf.appendSlice(allocator, max_str);

        if (root.getString(args, "time_min")) |tm| {
            try url_buf.appendSlice(allocator, "&timeMin=");
            try url_buf.appendSlice(allocator, tm);
        }
        if (root.getString(args, "time_max")) |tm| {
            try url_buf.appendSlice(allocator, "&timeMax=");
            try url_buf.appendSlice(allocator, tm);
        }

        return httpGetWithToken(allocator, url_buf.items, token);
    }

    // ── Create event ──────────────────────────────────────────────

    fn createEvent(self: *GoogleCalendarTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const summary = root.getString(args, "summary") orelse
            return ToolResult.fail("Missing 'summary' parameter for create_event");
        const start = root.getString(args, "start") orelse
            return ToolResult.fail("Missing 'start' parameter for create_event");
        const end = root.getString(args, "end") orelse
            return ToolResult.fail("Missing 'end' parameter for create_event");

        const token = switch (google_auth.getGoogleToken(allocator, PROVIDER_KEY, self.client_id, self.client_secret)) {
            .token => |t| t,
            .err => |e| return e,
        };
        defer allocator.free(token);

        const cal_id = root.getString(args, "calendar_id") orelse "primary";

        // Build JSON body
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(allocator);

        try body.appendSlice(allocator, "{\"summary\":\"");
        try appendJsonEscaped(&body, allocator, summary);
        try body.appendSlice(allocator, "\",\"start\":{\"dateTime\":\"");
        try appendJsonEscaped(&body, allocator, start);
        try body.appendSlice(allocator, "\"},\"end\":{\"dateTime\":\"");
        try appendJsonEscaped(&body, allocator, end);
        try body.appendSlice(allocator, "\"}");

        if (root.getString(args, "description")) |desc| {
            try body.appendSlice(allocator, ",\"description\":\"");
            try appendJsonEscaped(&body, allocator, desc);
            try body.appendSlice(allocator, "\"");
        }
        if (root.getString(args, "location")) |loc| {
            try body.appendSlice(allocator, ",\"location\":\"");
            try appendJsonEscaped(&body, allocator, loc);
            try body.appendSlice(allocator, "\"");
        }
        try body.append(allocator, '}');

        const json_body = try body.toOwnedSlice(allocator);
        defer allocator.free(json_body);

        const url = try std.fmt.allocPrint(allocator, CALENDAR_API_BASE ++ "/calendars/{s}/events", .{cal_id});
        defer allocator.free(url);

        return httpPostWithToken(allocator, url, token, json_body);
    }

    // ── Update event ──────────────────────────────────────────────

    fn updateEvent(self: *GoogleCalendarTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const event_id = root.getString(args, "event_id") orelse
            return ToolResult.fail("Missing 'event_id' parameter for update_event");

        const token = switch (google_auth.getGoogleToken(allocator, PROVIDER_KEY, self.client_id, self.client_secret)) {
            .token => |t| t,
            .err => |e| return e,
        };
        defer allocator.free(token);

        const cal_id = root.getString(args, "calendar_id") orelse "primary";

        // Build partial JSON body with only provided fields
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(allocator);

        try body.append(allocator, '{');
        var first = true;

        if (root.getString(args, "summary")) |v| {
            try appendField(&body, allocator, "summary", v, &first);
        }
        if (root.getString(args, "description")) |v| {
            try appendField(&body, allocator, "description", v, &first);
        }
        if (root.getString(args, "location")) |v| {
            try appendField(&body, allocator, "location", v, &first);
        }
        if (root.getString(args, "start")) |v| {
            if (!first) try body.append(allocator, ',');
            first = false;
            try body.appendSlice(allocator, "\"start\":{\"dateTime\":\"");
            try appendJsonEscaped(&body, allocator, v);
            try body.appendSlice(allocator, "\"}");
        }
        if (root.getString(args, "end")) |v| {
            if (!first) try body.append(allocator, ',');
            first = false;
            try body.appendSlice(allocator, "\"end\":{\"dateTime\":\"");
            try appendJsonEscaped(&body, allocator, v);
            try body.appendSlice(allocator, "\"}");
        }
        try body.append(allocator, '}');

        const json_body = try body.toOwnedSlice(allocator);
        defer allocator.free(json_body);

        const url = try std.fmt.allocPrint(allocator, CALENDAR_API_BASE ++ "/calendars/{s}/events/{s}", .{ cal_id, event_id });
        defer allocator.free(url);

        return httpPatchWithToken(allocator, url, token, json_body);
    }

    // ── Delete event ──────────────────────────────────────────────

    fn deleteEvent(self: *GoogleCalendarTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const event_id = root.getString(args, "event_id") orelse
            return ToolResult.fail("Missing 'event_id' parameter for delete_event");

        const token = switch (google_auth.getGoogleToken(allocator, PROVIDER_KEY, self.client_id, self.client_secret)) {
            .token => |t| t,
            .err => |e| return e,
        };
        defer allocator.free(token);

        const cal_id = root.getString(args, "calendar_id") orelse "primary";

        const url = try std.fmt.allocPrint(allocator, CALENDAR_API_BASE ++ "/calendars/{s}/events/{s}", .{ cal_id, event_id });
        defer allocator.free(url);

        return httpDeleteWithToken(allocator, url, token);
    }

    // ── Helpers ───────────────────────────────────────────────────

    fn getMaxResults(args: JsonObjectMap) u32 {
        if (root.getValue(args, "max_results")) |v| {
            switch (v) {
                .integer => |i| return if (i > 0 and i <= 250) @intCast(i) else 10,
                else => {},
            }
        }
        return 10;
    }

    fn appendField(body: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, key: []const u8, value: []const u8, first: *bool) !void {
        if (!first.*) try body.append(allocator, ',');
        first.* = false;
        try body.append(allocator, '"');
        try body.appendSlice(allocator, key);
        try body.appendSlice(allocator, "\":\"");
        try appendJsonEscaped(body, allocator, value);
        try body.append(allocator, '"');
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

fn httpPatchWithToken(allocator: std.mem.Allocator, url: []const u8, token: []const u8, body: []const u8) !ToolResult {
    const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{token});
    defer allocator.free(auth_header);

    const argv = &[_][]const u8{
        "curl", "-sL", "-m", "15",
        "-X",   "PATCH",
        "-H",   auth_header,
        "-H",   "Content-Type: application/json",
        "-d",   body,
        url,
    };

    return runCurl(allocator, argv);
}

fn httpDeleteWithToken(allocator: std.mem.Allocator, url: []const u8, token: []const u8) !ToolResult {
    const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{token});
    defer allocator.free(auth_header);

    const argv = &[_][]const u8{
        "curl", "-sL", "-m", "15",
        "-X",   "DELETE",
        "-H",   auth_header,
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

test "google_calendar tool name" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    try std.testing.expectEqualStrings("google_calendar", t.name());
}

test "google_calendar tool schema has action" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "connect") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "list_events") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "create_event") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "update_event") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "delete_event") != null);
}

test "google_calendar missing action returns error" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "google_calendar unknown action returns error" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"unknown\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown action") != null);
}

test "google_calendar create_event missing summary returns error" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create_event\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "summary") != null);
}

test "google_calendar create_event missing start returns error" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create_event\", \"summary\": \"test\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "start") != null);
}

test "google_calendar create_event missing end returns error" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create_event\", \"summary\": \"test\", \"start\": \"2024-01-15T09:00:00Z\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "end") != null);
}

test "google_calendar update_event missing event_id returns error" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"update_event\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "event_id") != null);
}

test "google_calendar delete_event missing event_id returns error" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"delete_event\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "event_id") != null);
}

test "google_calendar list_events not authenticated returns error" {
    var gct = GoogleCalendarTool{ .client_id = "test-id", .client_secret = null };
    const t = gct.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"list_events\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "connect") != null);
}
