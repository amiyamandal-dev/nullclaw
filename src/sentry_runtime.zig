const std = @import("std");
const sentry = @import("sentry-zig");
const version = @import("version.zig");

const Allocator = std.mem.Allocator;

pub const Runtime = struct {
    allocator: Allocator,
    client: ?*sentry.Client = null,
    dsn: ?[]u8 = null,
    release: ?[]u8 = null,
    environment: ?[]u8 = null,

    pub fn init(allocator: Allocator) Runtime {
        var runtime = Runtime{ .allocator = allocator };
        runtime.bootstrap() catch |err| {
            std.log.warn("Sentry bootstrap disabled ({s})", .{@errorName(err)});
            runtime.resetOwned();
        };
        return runtime;
    }

    pub fn deinit(self: *Runtime) void {
        if (self.client) |client| {
            client.deinit();
            self.client = null;
        }
        self.resetOwned();
    }

    pub fn isEnabled(self: *const Runtime) bool {
        return self.client != null;
    }

    pub fn capturePanic(self: *Runtime, msg: []const u8) void {
        if (self.client) |client| {
            client.captureException("panic", msg);
        }
    }

    pub fn captureError(self: *Runtime, component: []const u8, message: []const u8) void {
        if (self.client) |client| {
            client.captureException(component, message);
        }
    }

    pub fn captureMessage(self: *Runtime, message: []const u8, level: sentry.Level) void {
        if (self.client) |client| {
            client.captureMessage(message, level);
        }
    }

    pub fn flush(self: *Runtime, timeout_ms: u64) void {
        if (self.client) |client| {
            _ = client.flush(timeout_ms);
        }
    }

    fn bootstrap(self: *Runtime) !void {
        const dsn = try getEnvVarOwned(self.allocator, "NULLCLAW_SENTRY_DSN");
        if (dsn == null) return;
        self.dsn = dsn;
        errdefer self.resetOwned();

        self.environment = try getEnvVarOwned(self.allocator, "NULLCLAW_SENTRY_ENVIRONMENT");
        if (try getEnvVarOwned(self.allocator, "NULLCLAW_SENTRY_RELEASE")) |release| {
            self.release = release;
        } else {
            self.release = try std.fmt.allocPrint(self.allocator, "nullclaw@{s}", .{version.string});
        }

        const sample_rate = readEnvF64(self.allocator, "NULLCLAW_SENTRY_SAMPLE_RATE", 1.0);
        const traces_sample_rate = readEnvF64(self.allocator, "NULLCLAW_SENTRY_TRACES_SAMPLE_RATE", 0.0);
        const debug = readEnvBool(self.allocator, "NULLCLAW_SENTRY_DEBUG", false);
        const auto_session_tracking = readEnvBool(self.allocator, "NULLCLAW_SENTRY_AUTO_SESSION", false);
        const install_signal_handlers = readEnvBool(self.allocator, "NULLCLAW_SENTRY_INSTALL_SIGNAL_HANDLERS", false);

        self.client = try sentry.init(self.allocator, .{
            .dsn = self.dsn.?,
            .release = self.release,
            .environment = self.environment,
            .sample_rate = sample_rate,
            .traces_sample_rate = traces_sample_rate,
            .debug = debug,
            .auto_session_tracking = auto_session_tracking,
            .install_signal_handlers = install_signal_handlers,
        });

        if (readEnvBool(self.allocator, "NULLCLAW_SENTRY_STARTUP_EVENT", false)) {
            self.captureMessage("nullclaw startup", .info);
        }
    }

    fn resetOwned(self: *Runtime) void {
        if (self.dsn) |value| {
            self.allocator.free(value);
            self.dsn = null;
        }
        if (self.release) |value| {
            self.allocator.free(value);
            self.release = null;
        }
        if (self.environment) |value| {
            self.allocator.free(value);
            self.environment = null;
        }
    }
};

fn getEnvVarOwned(allocator: Allocator, key: []const u8) !?[]u8 {
    return std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
}

fn readEnvBool(allocator: Allocator, key: []const u8, default_value: bool) bool {
    const raw = std.process.getEnvVarOwned(allocator, key) catch return default_value;
    defer allocator.free(raw);
    return parseBool(raw) orelse default_value;
}

fn readEnvF64(allocator: Allocator, key: []const u8, default_value: f64) f64 {
    const raw = std.process.getEnvVarOwned(allocator, key) catch return default_value;
    defer allocator.free(raw);
    return std.fmt.parseFloat(f64, std.mem.trim(u8, raw, " \t\r\n")) catch default_value;
}

fn parseBool(raw: []const u8) ?bool {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (value.len == 0) return null;
    if (std.ascii.eqlIgnoreCase(value, "1") or
        std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes") or
        std.ascii.eqlIgnoreCase(value, "on"))
    {
        return true;
    }
    if (std.ascii.eqlIgnoreCase(value, "0") or
        std.ascii.eqlIgnoreCase(value, "false") or
        std.ascii.eqlIgnoreCase(value, "no") or
        std.ascii.eqlIgnoreCase(value, "off"))
    {
        return false;
    }
    return null;
}

test "parseBool supports common true/false values" {
    try std.testing.expectEqual(@as(?bool, true), parseBool("true"));
    try std.testing.expectEqual(@as(?bool, true), parseBool("1"));
    try std.testing.expectEqual(@as(?bool, false), parseBool("false"));
    try std.testing.expectEqual(@as(?bool, false), parseBool("0"));
    try std.testing.expectEqual(@as(?bool, null), parseBool("maybe"));
}
