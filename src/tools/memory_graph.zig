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

/// Memory graph tool — lets the agent explore the memory knowledge graph.
/// Requires Neo4j backend for graph features.
pub const MemoryGraphTool = struct {
    memory: ?Memory = null,
    neo4j_ptr: ?*anyopaque = null,

    pub const tool_name = "memory_graph";
    pub const tool_description = "Explore the memory knowledge graph from a root key, traversing relationship hops. Requires Neo4j backend.";
    pub const tool_params =
        \\{"type":"object","properties":{"key":{"type":"string","description":"Root memory key to start traversal from"},"hops":{"type":"integer","description":"Number of hops to traverse (1-3, default 1)"}},"required":["key"]}
    ;

    pub const vtable = root.ToolVTable(@This());

    pub fn tool(self: *MemoryGraphTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *MemoryGraphTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const key = root.getString(args, "key") orelse
            return ToolResult.fail("Missing 'key' parameter");
        if (key.len == 0) return ToolResult.fail("'key' must not be empty");

        const hops_raw = root.getInt(args, "hops") orelse 1;
        const hops: u8 = if (hops_raw >= 1 and hops_raw <= 3) @intCast(hops_raw) else 1;

        if (!build_options.enable_memory_neo4j) {
            return ToolResult.fail("Graph features require Neo4j backend (not compiled)");
        }

        const neo4j_raw = self.neo4j_ptr orelse
            return ToolResult.fail("Graph features require Neo4j backend");

        const neo4j: *neo4j_mod.Neo4jMemory = @ptrCast(@alignCast(neo4j_raw));

        var graph_result = neo4j.traverseGraph(allocator, key, hops) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to traverse graph from '{s}': {s}", .{ key, @errorName(err) });
            return ToolResult{ .success = false, .output = msg };
        };
        defer graph_result.deinit(allocator);

        if (graph_result.nodes.len == 0) {
            const msg = try std.fmt.allocPrint(allocator, "No graph data found for key: {s}", .{key});
            return ToolResult{ .success = true, .output = msg };
        }

        return formatGraphResult(allocator, key, graph_result);
    }

    fn formatGraphResult(
        allocator: std.mem.Allocator,
        root_key: []const u8,
        result: neo4j_mod.Neo4jMemory.GraphResult,
    ) !ToolResult {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        // Header
        try buf.appendSlice(allocator, "Graph from '");
        try buf.appendSlice(allocator, root_key);
        try buf.appendSlice(allocator, "' (");
        var count_buf: [20]u8 = undefined;
        var count_str = std.fmt.bufPrint(&count_buf, "{d}", .{result.nodes.len}) catch "?";
        try buf.appendSlice(allocator, count_str);
        try buf.appendSlice(allocator, if (result.nodes.len == 1) " node, " else " nodes, ");
        count_str = std.fmt.bufPrint(&count_buf, "{d}", .{result.edges.len}) catch "?";
        try buf.appendSlice(allocator, count_str);
        try buf.appendSlice(allocator, if (result.edges.len == 1) " edge):\n" else " edges):\n");

        // Nodes
        try buf.appendSlice(allocator, "Nodes:\n");
        for (result.nodes) |node| {
            try buf.appendSlice(allocator, "  - ");
            try buf.appendSlice(allocator, node.key);
            try buf.appendSlice(allocator, " (");
            try buf.appendSlice(allocator, node.category);
            try buf.appendSlice(allocator, "): ");
            // Truncate long content
            const max_content: usize = 100;
            if (node.content.len > max_content) {
                try buf.appendSlice(allocator, node.content[0..max_content]);
                try buf.appendSlice(allocator, "...");
            } else {
                try buf.appendSlice(allocator, node.content);
            }
            try buf.append(allocator, '\n');
        }

        // Edges
        if (result.edges.len > 0) {
            try buf.appendSlice(allocator, "Edges:\n");
            for (result.edges) |edge| {
                try buf.appendSlice(allocator, "  - ");
                try buf.appendSlice(allocator, edge.from_key);
                try buf.appendSlice(allocator, " --[");
                try buf.appendSlice(allocator, edge.rel_type);
                try buf.appendSlice(allocator, "]--> ");
                try buf.appendSlice(allocator, edge.to_key);
                try buf.append(allocator, '\n');
            }
        }

        return ToolResult{ .success = true, .output = try buf.toOwnedSlice(allocator) };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "memory_graph tool name" {
    var mt = MemoryGraphTool{};
    const t = mt.tool();
    try std.testing.expectEqualStrings("memory_graph", t.name());
}

test "memory_graph schema has key and hops" {
    var mt = MemoryGraphTool{};
    const t = mt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "key") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "hops") != null);
}

test "memory_graph missing key" {
    var mt = MemoryGraphTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "memory_graph no backend graceful error" {
    var mt = MemoryGraphTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"test\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0 and result.error_msg == null) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}
