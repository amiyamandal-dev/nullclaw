const std = @import("std");
const build_options = @import("build_options");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const mem_root = @import("../memory/root.zig");
const Memory = mem_root.Memory;
const neo4j_mod = if (build_options.enable_memory_neo4j) @import("../memory/engines/neo4j.zig") else struct {
    pub const Neo4jMemory = struct {};
};

/// Memory relate tool — lets the agent create typed relationships between memories.
/// Requires Neo4j backend for graph features.
pub const MemoryRelateTool = struct {
    memory: ?Memory = null,
    neo4j_ptr: ?*anyopaque = null,

    pub const tool_name = "memory_relate";
    pub const tool_description = "Create a typed relationship between two memories in the knowledge graph. Requires Neo4j backend.";
    pub const tool_params =
        \\{"type":"object","properties":{"from":{"type":"string","description":"Source memory key"},"to":{"type":"string","description":"Target memory key"},"relationship":{"type":"string","enum":["relates_to","refines","depends_on","contradicts","supersedes","supports"],"description":"Relationship type"}},"required":["from","to","relationship"]}
    ;

    pub const vtable = root.ToolVTable(@This());

    pub fn tool(self: *MemoryRelateTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *MemoryRelateTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const from = root.getString(args, "from") orelse
            return ToolResult.fail("Missing 'from' parameter");
        if (from.len == 0) return ToolResult.fail("'from' must not be empty");

        const to = root.getString(args, "to") orelse
            return ToolResult.fail("Missing 'to' parameter");
        if (to.len == 0) return ToolResult.fail("'to' must not be empty");

        const relationship = root.getString(args, "relationship") orelse
            return ToolResult.fail("Missing 'relationship' parameter");
        if (relationship.len == 0) return ToolResult.fail("'relationship' must not be empty");

        if (!build_options.enable_memory_neo4j) {
            return ToolResult.fail("Graph features require Neo4j backend (not compiled)");
        }

        const neo4j_raw = self.neo4j_ptr orelse
            return ToolResult.fail("Graph features require Neo4j backend");

        const neo4j: *neo4j_mod.Neo4jMemory = @ptrCast(@alignCast(neo4j_raw));

        // Convert relationship to uppercase Cypher type
        const rel_type = relToUpper(relationship) orelse {
            const msg = try std.fmt.allocPrint(allocator, "Invalid relationship type: {s}. Use: relates_to, refines, depends_on, contradicts, supersedes, supports", .{relationship});
            return ToolResult{ .success = false, .output = msg };
        };

        const created = neo4j.createRelationship(allocator, from, to, rel_type) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to create relationship: {s}", .{@errorName(err)});
            return ToolResult{ .success = false, .output = msg };
        };

        if (created) {
            const msg = try std.fmt.allocPrint(allocator, "Created relationship: {s} --[{s}]--> {s}", .{ from, rel_type, to });
            return ToolResult{ .success = true, .output = msg };
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Could not create relationship: one or both keys not found ({s}, {s})", .{ from, to });
            return ToolResult{ .success = false, .output = msg };
        }
    }

    fn relToUpper(rel: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, rel, "relates_to")) return "RELATES_TO";
        if (std.mem.eql(u8, rel, "refines")) return "REFINES";
        if (std.mem.eql(u8, rel, "depends_on")) return "DEPENDS_ON";
        if (std.mem.eql(u8, rel, "contradicts")) return "CONTRADICTS";
        if (std.mem.eql(u8, rel, "supersedes")) return "SUPERSEDES";
        if (std.mem.eql(u8, rel, "supports")) return "SUPPORTS";
        return null;
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "memory_relate tool name" {
    var mt = MemoryRelateTool{};
    const t = mt.tool();
    try std.testing.expectEqualStrings("memory_relate", t.name());
}

test "memory_relate schema has from, to, relationship" {
    var mt = MemoryRelateTool{};
    const t = mt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "from") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "to") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "relationship") != null);
}

test "memory_relate missing from" {
    var mt = MemoryRelateTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"to\": \"b\", \"relationship\": \"relates_to\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "memory_relate missing to" {
    var mt = MemoryRelateTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"from\": \"a\", \"relationship\": \"relates_to\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "memory_relate missing relationship" {
    var mt = MemoryRelateTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"from\": \"a\", \"to\": \"b\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "memory_relate no backend graceful error" {
    var mt = MemoryRelateTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"from\": \"a\", \"to\": \"b\", \"relationship\": \"relates_to\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0 and result.error_msg == null) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "memory_relate relToUpper maps correctly" {
    try std.testing.expectEqualStrings("RELATES_TO", MemoryRelateTool.relToUpper("relates_to").?);
    try std.testing.expectEqualStrings("REFINES", MemoryRelateTool.relToUpper("refines").?);
    try std.testing.expectEqualStrings("DEPENDS_ON", MemoryRelateTool.relToUpper("depends_on").?);
    try std.testing.expectEqualStrings("CONTRADICTS", MemoryRelateTool.relToUpper("contradicts").?);
    try std.testing.expectEqualStrings("SUPERSEDES", MemoryRelateTool.relToUpper("supersedes").?);
    try std.testing.expectEqualStrings("SUPPORTS", MemoryRelateTool.relToUpper("supports").?);
    try std.testing.expect(MemoryRelateTool.relToUpper("invalid") == null);
}
