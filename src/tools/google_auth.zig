const std = @import("std");
const builtin = @import("builtin");
const auth = @import("../auth.zig");
const root = @import("root.zig");
const ToolResult = root.ToolResult;

// ── Google OAuth constants ──────────────────────────────────────────

pub const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
pub const GOOGLE_DEVICE_AUTH_URL = "https://oauth2.googleapis.com/device/code";

pub const GMAIL_SCOPES = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.modify";
pub const CALENDAR_SCOPES = "https://www.googleapis.com/auth/calendar";

// ── Token helper ────────────────────────────────────────────────────

/// Retrieve a valid Google access token for the given provider key.
/// Loads from credential store, refreshes if expired.
/// Returns an allocated access token string on success, or a ToolResult error.
pub const TokenResult = union(enum) {
    token: []const u8,
    err: ToolResult,
};

pub fn getGoogleToken(
    allocator: std.mem.Allocator,
    provider_key: []const u8,
    client_id: []const u8,
    client_secret: ?[]const u8,
) TokenResult {
    if (builtin.is_test) return .{ .err = ToolResult.fail("Not authenticated. Use action='connect' first.") };

    // Try loading cached token
    const maybe_token = auth.loadCredential(allocator, provider_key) catch {
        return .{ .err = ToolResult.fail("Failed to load credentials. Use action='connect' first.") };
    };

    if (maybe_token) |token| {
        // Token is valid (loadCredential returns null if expired)
        const access = allocator.dupe(u8, token.access_token) catch {
            token.deinit(allocator);
            return .{ .err = ToolResult.fail("Memory allocation failed") };
        };
        token.deinit(allocator);
        return .{ .token = access };
    }

    // No valid token — try to refresh using stored refresh_token
    // We need to load the raw credential (even if expired) to get the refresh_token
    const raw_token = loadRawCredential(allocator, provider_key) catch {
        return .{ .err = ToolResult.fail("Not authenticated. Use action='connect' to authorize with Google.") };
    };

    if (raw_token) |raw| {
        defer raw.deinit(allocator);
        if (raw.refresh_token) |rt| {
            const new_token = auth.refreshAccessToken(
                allocator,
                GOOGLE_TOKEN_URL,
                client_id,
                rt,
                client_secret,
            ) catch {
                return .{ .err = ToolResult.fail("Token refresh failed. Use action='connect' to re-authorize.") };
            };

            // Save refreshed token
            auth.saveCredential(allocator, provider_key, new_token) catch {};

            const access = allocator.dupe(u8, new_token.access_token) catch {
                new_token.deinit(allocator);
                return .{ .err = ToolResult.fail("Memory allocation failed") };
            };
            new_token.deinit(allocator);
            return .{ .token = access };
        }
    }

    return .{ .err = ToolResult.fail("Not authenticated. Use action='connect' to authorize with Google.") };
}

/// Load credential without expiry check (to get refresh_token even when expired).
fn loadRawCredential(allocator: std.mem.Allocator, provider: []const u8) !?auth.OAuthToken {
    const platform = @import("../platform.zig");
    const home = platform.getHomeDir(allocator) catch return null;
    defer allocator.free(home);

    const file_path = try std.fs.path.join(allocator, &.{ home, ".nullclaw", "auth.json" });
    defer allocator.free(file_path);

    const file = std.fs.cwd().openFile(file_path, .{}) catch return null;
    defer file.close();

    const json_bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(json_bytes);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return null;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };

    const provider_val = root_obj.get(provider) orelse return null;
    const prov_obj = switch (provider_val) {
        .object => |obj| obj,
        else => return null,
    };

    const access_token_str = switch (prov_obj.get("access_token") orelse return null) {
        .string => |s| s,
        else => return null,
    };

    const access_token = try allocator.dupe(u8, access_token_str);
    errdefer allocator.free(access_token);

    const refresh_token: ?[]const u8 = if (prov_obj.get("refresh_token")) |rt_val| blk: {
        switch (rt_val) {
            .string => |s| break :blk if (s.len > 0) try allocator.dupe(u8, s) else null,
            else => break :blk null,
        }
    } else null;
    errdefer if (refresh_token) |rt| allocator.free(rt);

    const expires_at: i64 = if (prov_obj.get("expires_at")) |ea_val| blk: {
        switch (ea_val) {
            .integer => |i| break :blk i,
            .float => |f| break :blk @intFromFloat(f),
            else => break :blk 0,
        }
    } else 0;

    const token_type = try allocator.dupe(u8, if (prov_obj.get("token_type")) |tt_val| switch (tt_val) {
        .string => |s| s,
        else => "Bearer",
    } else "Bearer");

    return auth.OAuthToken{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_at = expires_at,
        .token_type = token_type,
    };
}

// ── Connect helper ──────────────────────────────────────────────────

/// Initiate Google OAuth device code flow.
/// Returns a ToolResult with user_code and verification_url for the LLM to present.
pub fn connectGoogle(
    allocator: std.mem.Allocator,
    provider_key: []const u8,
    client_id: []const u8,
    scope: []const u8,
) !ToolResult {
    if (builtin.is_test) return ToolResult.fail("Cannot run OAuth in test mode");

    const dc = auth.startDeviceCodeFlow(allocator, client_id, GOOGLE_DEVICE_AUTH_URL, scope) catch
        return ToolResult.fail("Failed to start Google device code flow. Check client_id configuration.");
    defer dc.deinit(allocator);

    // Present instructions to user via LLM
    const msg = try std.fmt.allocPrint(
        allocator,
        "Google authorization required.\n\n1. Go to: {s}\n2. Enter code: {s}\n\nWaiting for authorization...",
        .{ dc.verification_uri, dc.user_code },
    );
    defer allocator.free(msg);

    // Poll for token (blocks until user authorizes or timeout)
    const token = auth.pollDeviceCode(
        allocator,
        GOOGLE_TOKEN_URL,
        client_id,
        dc.device_code,
        dc.interval,
    ) catch |err| {
        const err_msg = switch (err) {
            error.DeviceCodeDenied => "Authorization was denied by the user.",
            error.DeviceCodeTimeout => "Authorization timed out. Please try again.",
            else => "Authorization failed. Please try again.",
        };
        return ToolResult.fail(err_msg);
    };

    // Save token
    auth.saveCredential(allocator, provider_key, token) catch {
        token.deinit(allocator);
        return ToolResult.fail("Authorization succeeded but failed to save credentials.");
    };
    token.deinit(allocator);

    const success_msg = try std.fmt.allocPrint(
        allocator,
        "Successfully connected to Google! Credentials saved for '{s}'.",
        .{provider_key},
    );
    return ToolResult{ .success = true, .output = success_msg };
}

// ── Tests ───────────────────────────────────────────────────────────

test "google_auth constants are valid urls" {
    try std.testing.expect(std.mem.startsWith(u8, GOOGLE_TOKEN_URL, "https://"));
    try std.testing.expect(std.mem.startsWith(u8, GOOGLE_DEVICE_AUTH_URL, "https://"));
}

test "google_auth scopes contain expected values" {
    try std.testing.expect(std.mem.indexOf(u8, GMAIL_SCOPES, "gmail") != null);
    try std.testing.expect(std.mem.indexOf(u8, CALENDAR_SCOPES, "calendar") != null);
}

test "google_auth getGoogleToken returns error in test mode" {
    const result = getGoogleToken(std.testing.allocator, "google_mail", "test-id", null);
    switch (result) {
        .err => |e| {
            try std.testing.expect(!e.success);
            try std.testing.expect(std.mem.indexOf(u8, e.error_msg.?, "connect") != null);
        },
        .token => |t| {
            std.testing.allocator.free(t);
            try std.testing.expect(false); // should not reach
        },
    }
}
