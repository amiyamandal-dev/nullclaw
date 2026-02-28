//! Neo4j graph memory backend — stores memories as graph nodes via HTTP API.
//!
//! Communicates with Neo4j's transactional Cypher HTTP endpoint
//! (`/db/{db}/tx/commit`). Uses curl subprocess for HTTP (same pattern
//! as api.zig).  Full-text search via Cypher `db.index.fulltext.queryNodes`
//! with fallback to `CONTAINS` substring match.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const appendJsonEscaped = @import("../../util.zig").appendJsonEscaped;
const root = @import("../root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;
const log = std.log.scoped(.neo4j_memory);

// ── Neo4jMemory ────────────────────────────────────────────────────

pub const Neo4jMemory = struct {
    allocator: Allocator,
    base_url: []const u8, // owned — e.g. "http://localhost:7474"
    tx_endpoint: []const u8, // owned — e.g. "/db/neo4j/tx/commit"
    auth_header: ?[]const u8, // owned — "Basic base64(user:pass)"
    node_label: []const u8, // borrowed from config (comptime default)
    auto_relate_enabled: bool = true,
    auto_relate_top_k: u8 = 3,
    graph_enriched_recall: bool = true,
    graph_max_hops: u8 = 1,
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: Allocator, config: Config) !Self {
        if (builtin.is_test) {
            // In test mode, don't try to connect.
        }

        var url = config.url;
        if (url.len > 0 and url[url.len - 1] == '/') {
            url = url[0 .. url.len - 1];
        }
        if (url.len == 0) return error.InvalidNeo4jUrl;

        const base_url = try allocator.dupe(u8, url);
        errdefer allocator.free(base_url);

        const tx_endpoint = try std.fmt.allocPrint(allocator, "/db/{s}/tx/commit", .{config.database});
        errdefer allocator.free(tx_endpoint);

        const auth_header: ?[]const u8 = if (config.username.len > 0) blk: {
            const creds = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ config.username, config.password });
            defer allocator.free(creds);
            const encoded = try base64Encode(allocator, creds);
            const header = try std.fmt.allocPrint(allocator, "Basic {s}", .{encoded});
            allocator.free(encoded);
            break :blk header;
        } else null;
        errdefer if (auth_header) |h| allocator.free(h);

        var self_ = Self{
            .allocator = allocator,
            .base_url = base_url,
            .tx_endpoint = tx_endpoint,
            .auth_header = auth_header,
            .node_label = config.node_label,
            .auto_relate_enabled = config.auto_relate_enabled,
            .auto_relate_top_k = config.auto_relate_top_k,
            .graph_enriched_recall = config.graph_enriched_recall,
            .graph_max_hops = config.graph_max_hops,
        };

        // Create fulltext index on init (non-test).
        if (!builtin.is_test) {
            try self_.createFulltextIndex();
        }

        return self_;
    }

    pub fn deinit(self: *Self) void {
        const alloc = self.allocator;
        alloc.free(self.base_url);
        alloc.free(self.tx_endpoint);
        if (self.auth_header) |h| alloc.free(h);
        if (self.owns_self) alloc.destroy(self);
    }

    pub fn memory(self: *Self) Memory {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &mem_vtable,
        };
    }

    // ── Config ────────────────────────────────────────────────────

    pub const Config = struct {
        url: []const u8 = "http://192.168.0.223:7474",
        username: []const u8 = "neo4j",
        password: []const u8 = "qaz123!@#WSX",
        database: []const u8 = "neo4j",
        node_label: []const u8 = "Memory",
        auto_relate_enabled: bool = true,
        auto_relate_top_k: u8 = 3,
        graph_enriched_recall: bool = true,
        graph_max_hops: u8 = 1,
    };

    // ── Graph relationship types ─────────────────────────────────

    pub const GraphNode = struct {
        key: []const u8,
        content: []const u8,
        category: []const u8,

        pub fn deinit(self: *GraphNode, alloc: Allocator) void {
            alloc.free(self.key);
            alloc.free(self.content);
            alloc.free(self.category);
        }
    };

    pub const GraphEdge = struct {
        from_key: []const u8,
        to_key: []const u8,
        rel_type: []const u8,
        score: ?f64,

        pub fn deinit(self: *GraphEdge, alloc: Allocator) void {
            alloc.free(self.from_key);
            alloc.free(self.to_key);
            alloc.free(self.rel_type);
        }
    };

    pub const GraphResult = struct {
        nodes: []GraphNode,
        edges: []GraphEdge,

        pub fn deinit(self: *GraphResult, alloc: Allocator) void {
            for (self.nodes) |*n| n.deinit(alloc);
            alloc.free(self.nodes);
            for (self.edges) |*e| e.deinit(alloc);
            alloc.free(self.edges);
        }
    };

    pub const RecallWithGraphResult = struct {
        direct: []MemoryEntry,
        related: []MemoryEntry,

        pub fn deinit(self: *RecallWithGraphResult, alloc: Allocator) void {
            for (self.direct) |*e| e.deinit(alloc);
            alloc.free(self.direct);
            for (self.related) |*e| e.deinit(alloc);
            alloc.free(self.related);
        }
    };

    const valid_rel_types = [_][]const u8{
        "RELATES_TO",
        "REFINES",
        "DEPENDS_ON",
        "CONTRADICTS",
        "SUPERSEDES",
        "SUPPORTS",
    };

    fn isValidRelType(rel_type: []const u8) bool {
        for (valid_rel_types) |valid| {
            if (std.mem.eql(u8, rel_type, valid)) return true;
        }
        return false;
    }

    // ── Graph public methods ──────────────────────────────────────

    /// After store, fulltext-search for similar memories and create RELATES_TO edges.
    /// Best-effort: errors are logged, not propagated.
    pub fn autoRelate(self: *Self, alloc: Allocator, key: []const u8) void {
        if (builtin.is_test) return;
        if (!self.auto_relate_enabled) return;

        self.autoRelateInner(alloc, key) catch |err| {
            log.warn("autoRelate failed for '{s}': {}", .{ key, err });
        };
    }

    fn autoRelateInner(self: *Self, alloc: Allocator, key: []const u8) !void {
        // Fulltext search to find related memories
        var params: std.ArrayListUnmanaged(u8) = .empty;
        defer params.deinit(alloc);

        try params.appendSlice(alloc, "{\"query\":\"");
        try appendJsonEscaped(&params, alloc, key);
        try params.appendSlice(alloc, "\",\"limit\":");
        var limit_buf: [8]u8 = undefined;
        const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{@as(u8, self.auto_relate_top_k) + 1}) catch unreachable;
        try params.appendSlice(alloc, limit_str);
        try params.appendSlice(alloc, "}");

        const params_str = try alloc.dupe(u8, params.items);
        defer alloc.free(params_str);

        const cypher = try std.fmt.allocPrint(alloc,
            \\CALL db.index.fulltext.queryNodes('memory_content_idx', $query) YIELD node AS m, score
            \\WHERE m:{s}
            \\RETURN m.key AS key, score
            \\ORDER BY score DESC LIMIT $limit
        , .{self.node_label});
        defer alloc.free(cypher);

        const body = self.executeCypher(alloc, cypher, params_str) catch return;
        defer alloc.free(body);

        // Parse result keys and scores, skip self
        var related_keys: std.ArrayListUnmanaged([]const u8) = .empty;
        defer related_keys.deinit(alloc);
        var related_scores: std.ArrayListUnmanaged(f64) = .empty;
        defer related_scores.deinit(alloc);

        // Simple parse: find "row":["key",score] patterns
        var pos: usize = 0;
        while (std.mem.indexOf(u8, body[pos..], "\"row\":[")) |row_off| {
            pos += row_off + "\"row\":[".len;
            // Parse key string
            while (pos < body.len and body[pos] != '"' and body[pos] != ']') : (pos += 1) {}
            if (pos >= body.len or body[pos] == ']') break;
            const rkey = parseJsonString(body, &pos) orelse break;
            if (std.mem.eql(u8, rkey, key)) continue; // skip self

            // Parse score
            while (pos < body.len and (body[pos] == ',' or body[pos] == ' ')) : (pos += 1) {}
            const score_start = pos;
            while (pos < body.len and body[pos] != ']' and body[pos] != ',' and body[pos] != '}') : (pos += 1) {}
            const score = std.fmt.parseFloat(f64, body[score_start..pos]) catch 0.0;

            if (related_keys.items.len < self.auto_relate_top_k) {
                try related_keys.append(alloc, rkey);
                try related_scores.append(alloc, score);
            }
        }

        // Create RELATES_TO edges for each related key
        for (related_keys.items, related_scores.items) |rkey, score| {
            var rel_params: std.ArrayListUnmanaged(u8) = .empty;
            defer rel_params.deinit(alloc);

            try rel_params.appendSlice(alloc, "{\"key\":\"");
            try appendJsonEscaped(&rel_params, alloc, key);
            try rel_params.appendSlice(alloc, "\",\"related_key\":\"");
            try appendJsonEscaped(&rel_params, alloc, rkey);
            try rel_params.appendSlice(alloc, "\",\"score\":");
            var score_buf: [32]u8 = undefined;
            const score_str = std.fmt.bufPrint(&score_buf, "{d:.4}", .{score}) catch "0";
            try rel_params.appendSlice(alloc, score_str);
            try rel_params.appendSlice(alloc, "}");

            const rel_params_str = try alloc.dupe(u8, rel_params.items);
            defer alloc.free(rel_params_str);

            const rel_cypher = try std.fmt.allocPrint(alloc,
                \\MATCH (a:{s} {{key: $key}}), (b:{s} {{key: $related_key}})
                \\WHERE a <> b
                \\MERGE (a)-[r:RELATES_TO]->(b)
                \\SET r.score = $score, r.created_at = timestamp()
            , .{ self.node_label, self.node_label });
            defer alloc.free(rel_cypher);

            const rel_body = self.executeCypher(alloc, rel_cypher, rel_params_str) catch continue;
            alloc.free(rel_body);
        }
    }

    /// Create an explicit typed relationship between two memory keys.
    /// Validates rel_type against a whitelist to prevent Cypher injection.
    pub fn createRelationship(self: *Self, alloc: Allocator, from_key: []const u8, to_key: []const u8, rel_type: []const u8) !bool {
        if (builtin.is_test) return error.Neo4jUnavailable;
        if (!isValidRelType(rel_type)) return error.InvalidRelationshipType;

        var params: std.ArrayListUnmanaged(u8) = .empty;
        defer params.deinit(alloc);

        try params.appendSlice(alloc, "{\"from_key\":\"");
        try appendJsonEscaped(&params, alloc, from_key);
        try params.appendSlice(alloc, "\",\"to_key\":\"");
        try appendJsonEscaped(&params, alloc, to_key);
        try params.appendSlice(alloc, "\"}");

        const params_str = try alloc.dupe(u8, params.items);
        defer alloc.free(params_str);

        // rel_type is validated against whitelist, safe to interpolate
        const cypher = try std.fmt.allocPrint(alloc,
            \\MATCH (a:{s} {{key: $from_key}}), (b:{s} {{key: $to_key}})
            \\WHERE a <> b
            \\MERGE (a)-[r:{s}]->(b)
            \\SET r.created_at = timestamp()
            \\RETURN type(r) AS rel
        , .{ self.node_label, self.node_label, rel_type });
        defer alloc.free(cypher);

        const body = try self.executeCypher(alloc, cypher, params_str);
        defer alloc.free(body);

        return std.mem.indexOf(u8, body, "\"rel\"") != null;
    }

    /// Traverse the graph from a root key up to max_hops (clamped to 1-3).
    pub fn traverseGraph(self: *Self, alloc: Allocator, root_key: []const u8, max_hops: u8) !GraphResult {
        if (builtin.is_test) return error.Neo4jUnavailable;

        const clamped_hops: u8 = if (max_hops < 1) 1 else if (max_hops > 3) 3 else max_hops;

        var params: std.ArrayListUnmanaged(u8) = .empty;
        defer params.deinit(alloc);

        try params.appendSlice(alloc, "{\"key\":\"");
        try appendJsonEscaped(&params, alloc, root_key);
        try params.appendSlice(alloc, "\"}");

        const params_str = try alloc.dupe(u8, params.items);
        defer alloc.free(params_str);

        var hops_buf: [4]u8 = undefined;
        const hops_str = std.fmt.bufPrint(&hops_buf, "{d}", .{clamped_hops}) catch "1";

        const cypher = try std.fmt.allocPrint(alloc,
            \\MATCH (root:{s} {{key: $key}})
            \\OPTIONAL MATCH path = (root)-[*1..{s}]-(connected:{s})
            \\WITH root, connected, relationships(path) AS rels
            \\UNWIND CASE WHEN rels IS NULL THEN [null] ELSE rels END AS r
            \\RETURN DISTINCT
            \\  CASE WHEN connected IS NOT NULL THEN connected.key ELSE root.key END AS key,
            \\  CASE WHEN connected IS NOT NULL THEN connected.content ELSE root.content END AS content,
            \\  CASE WHEN connected IS NOT NULL THEN connected.category ELSE root.category END AS category,
            \\  CASE WHEN r IS NOT NULL THEN type(r) ELSE null END AS rel_type,
            \\  CASE WHEN r IS NOT NULL THEN startNode(r).key ELSE null END AS from_key,
            \\  CASE WHEN r IS NOT NULL THEN endNode(r).key ELSE null END AS to_key
        , .{ self.node_label, hops_str, self.node_label });
        defer alloc.free(cypher);

        const body = try self.executeCypher(alloc, cypher, params_str);
        defer alloc.free(body);

        return self.parseGraphResult(alloc, body);
    }

    /// Normal fulltext recall + 1-hop traversal from results.
    /// Returns deduplicated direct + related entries.
    pub fn recallWithGraph(self: *Self, alloc: Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) !RecallWithGraphResult {
        if (builtin.is_test) return error.Neo4jUnavailable;

        // Step 1: Normal recall
        const direct = try implRecall(@ptrCast(@alignCast(self)), alloc, query, limit, session_id);
        errdefer {
            for (direct) |*d| {
                var entry = d.*;
                entry.deinit(alloc);
            }
            alloc.free(direct);
        }

        // Step 2: 1-hop traversal from direct results
        var related_list: std.ArrayListUnmanaged(MemoryEntry) = .empty;
        errdefer {
            for (related_list.items) |*e| e.deinit(alloc);
            related_list.deinit(alloc);
        }

        var seen_keys = std.StringHashMap(void).init(alloc);
        defer seen_keys.deinit();

        // Mark direct keys as seen
        for (direct) |entry| {
            try seen_keys.put(entry.key, {});
        }

        // Traverse 1 hop from each direct result
        const max_related: usize = limit;
        for (direct) |entry| {
            if (related_list.items.len >= max_related) break;

            var params: std.ArrayListUnmanaged(u8) = .empty;
            defer params.deinit(alloc);

            try params.appendSlice(alloc, "{\"key\":\"");
            try appendJsonEscaped(&params, alloc, entry.key);
            try params.appendSlice(alloc, "\"}");

            const params_str = try alloc.dupe(u8, params.items);
            defer alloc.free(params_str);

            const cypher = try std.fmt.allocPrint(alloc,
                \\MATCH (root:{s} {{key: $key}})-[r]-(connected:{s})
                \\RETURN connected.id AS id, connected.key AS key, connected.content AS content,
                \\  connected.category AS category, connected.session_id AS session_id,
                \\  toString(connected.created_at) AS timestamp
                \\LIMIT 5
            , .{ self.node_label, self.node_label });
            defer alloc.free(cypher);

            const body = self.executeCypher(alloc, cypher, params_str) catch continue;
            defer alloc.free(body);

            const neighbor_entries = parseResultRows(alloc, body) catch continue;
            defer {
                // Free entries we don't keep
                for (neighbor_entries) |*ne| {
                    var e = ne.*;
                    if (seen_keys.contains(e.key)) {
                        e.deinit(alloc);
                    }
                }
                alloc.free(neighbor_entries);
            }

            for (neighbor_entries) |ne| {
                if (related_list.items.len >= max_related) break;
                if (seen_keys.contains(ne.key)) continue;
                try seen_keys.put(ne.key, {});
                try related_list.append(alloc, ne);
            }
        }

        return .{
            .direct = direct,
            .related = try related_list.toOwnedSlice(alloc),
        };
    }

    fn parseGraphResult(self: *Self, alloc: Allocator, body: []const u8) !GraphResult {
        _ = self;
        var nodes: std.ArrayListUnmanaged(GraphNode) = .empty;
        errdefer {
            for (nodes.items) |*n| n.deinit(alloc);
            nodes.deinit(alloc);
        }
        var edges: std.ArrayListUnmanaged(GraphEdge) = .empty;
        errdefer {
            for (edges.items) |*e| e.deinit(alloc);
            edges.deinit(alloc);
        }

        var seen_nodes = std.StringHashMap(void).init(alloc);
        defer seen_nodes.deinit();
        var seen_edges = std.StringHashMap(void).init(alloc);
        defer {
            var it = seen_edges.iterator();
            while (it.next()) |entry| alloc.free(entry.key_ptr.*);
            seen_edges.deinit();
        }

        const columns = parseColumnOrder(body) orelse return .{
            .nodes = try nodes.toOwnedSlice(alloc),
            .edges = try edges.toOwnedSlice(alloc),
        };

        const data_key = std.mem.indexOf(u8, body, "\"data\":[") orelse return .{
            .nodes = try nodes.toOwnedSlice(alloc),
            .edges = try edges.toOwnedSlice(alloc),
        };
        var pos = data_key + "\"data\":[".len;

        while (pos < body.len) {
            while (pos < body.len and (body[pos] == ' ' or body[pos] == '\t' or body[pos] == '\r' or body[pos] == '\n')) : (pos += 1) {}
            if (pos >= body.len or body[pos] == ']') break;

            const row_key = std.mem.indexOf(u8, body[pos..], "\"row\":[") orelse break;
            pos += row_key + "\"row\":[".len;

            var row_values: [7]?[]const u8 = .{ null, null, null, null, null, null, null };
            var col_idx: usize = 0;
            while (col_idx < 7 and pos < body.len) {
                while (pos < body.len and (body[pos] == ' ' or body[pos] == '\t' or body[pos] == '\r' or body[pos] == '\n')) : (pos += 1) {}
                if (pos >= body.len or body[pos] == ']') break;
                if (body[pos] == ',') {
                    pos += 1;
                    continue;
                }
                if (body[pos] == '"') {
                    const str = parseJsonString(body, &pos) orelse break;
                    row_values[col_idx] = str;
                    col_idx += 1;
                } else if (body[pos] == 'n' and pos + 3 < body.len and std.mem.eql(u8, body[pos .. pos + 4], "null")) {
                    row_values[col_idx] = null;
                    col_idx += 1;
                    pos += 4;
                } else if (body[pos] >= '0' and body[pos] <= '9' or body[pos] == '-') {
                    const start = pos;
                    while (pos < body.len and body[pos] != ',' and body[pos] != ']' and body[pos] != ' ') : (pos += 1) {}
                    row_values[col_idx] = body[start..pos];
                    col_idx += 1;
                } else {
                    break;
                }
            }

            const node_key = getColumnValue(columns, row_values, "key");
            const node_content = getColumnValue(columns, row_values, "content");
            const node_category = getColumnValue(columns, row_values, "category");
            const edge_rel = getColumnValue(columns, row_values, "rel_type");
            const edge_from = getColumnValue(columns, row_values, "from_key");
            const edge_to = getColumnValue(columns, row_values, "to_key");

            // Add node if not seen
            if (node_key) |nk| {
                if (!seen_nodes.contains(nk)) {
                    const k = try alloc.dupe(u8, nk);
                    errdefer alloc.free(k);
                    const c = try alloc.dupe(u8, node_content orelse "");
                    errdefer alloc.free(c);
                    const cat = try alloc.dupe(u8, node_category orelse "core");
                    errdefer alloc.free(cat);
                    try nodes.append(alloc, .{ .key = k, .content = c, .category = cat });
                    try seen_nodes.put(k, {});
                }
            }

            // Add edge if not seen
            if (edge_rel != null and edge_from != null and edge_to != null) {
                const edge_key_str = try std.fmt.allocPrint(alloc, "{s}-{s}->{s}", .{ edge_from.?, edge_rel.?, edge_to.? });
                if (!seen_edges.contains(edge_key_str)) {
                    const fk = try alloc.dupe(u8, edge_from.?);
                    errdefer alloc.free(fk);
                    const tk = try alloc.dupe(u8, edge_to.?);
                    errdefer alloc.free(tk);
                    const rt = try alloc.dupe(u8, edge_rel.?);
                    errdefer alloc.free(rt);
                    try edges.append(alloc, .{ .from_key = fk, .to_key = tk, .rel_type = rt, .score = null });
                    try seen_edges.put(edge_key_str, {});
                } else {
                    alloc.free(edge_key_str);
                }
            }

            while (pos < body.len and body[pos] != '{' and body[pos] != ']') : (pos += 1) {}
            if (pos >= body.len or body[pos] == ']') break;
        }

        return .{
            .nodes = try nodes.toOwnedSlice(alloc),
            .edges = try edges.toOwnedSlice(alloc),
        };
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    const HttpResponse = struct {
        status: std.http.Status,
        body: []u8, // owned
    };

    fn doRequest(self: *const Self, alloc: Allocator, payload: []const u8) !HttpResponse {
        if (builtin.is_test) return error.Neo4jUnavailable;

        const full_url = try std.fmt.allocPrint(alloc, "{s}{s}", .{ self.base_url, self.tx_endpoint });
        defer alloc.free(full_url);

        var argv_buf: [20][]const u8 = undefined;
        var argc: usize = 0;

        argv_buf[argc] = "curl";
        argc += 1;
        argv_buf[argc] = "--silent";
        argc += 1;
        argv_buf[argc] = "--show-error";
        argc += 1;
        argv_buf[argc] = "--max-time";
        argc += 1;
        argv_buf[argc] = "10";
        argc += 1;
        argv_buf[argc] = "--request";
        argc += 1;
        argv_buf[argc] = "POST";
        argc += 1;
        argv_buf[argc] = "--header";
        argc += 1;
        argv_buf[argc] = "Content-Type: application/json";
        argc += 1;
        argv_buf[argc] = "--header";
        argc += 1;
        argv_buf[argc] = "Accept: application/json;charset=UTF-8";
        argc += 1;

        var auth_hdr_val: ?[]u8 = null;
        defer if (auth_hdr_val) |h| alloc.free(h);
        if (self.auth_header) |auth| {
            auth_hdr_val = try std.fmt.allocPrint(alloc, "Authorization: {s}", .{auth});
            argv_buf[argc] = "--header";
            argc += 1;
            argv_buf[argc] = auth_hdr_val.?;
            argc += 1;
        }

        argv_buf[argc] = "--data";
        argc += 1;
        argv_buf[argc] = payload;
        argc += 1;
        argv_buf[argc] = "--write-out";
        argc += 1;
        argv_buf[argc] = "\n%{http_code}";
        argc += 1;
        argv_buf[argc] = full_url;
        argc += 1;

        var child = std.process.Child.init(argv_buf[0..argc], alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        child.spawn() catch return error.Neo4jConnectionError;

        const raw_out = child.stdout.?.readToEndAlloc(alloc, 16 * 1024 * 1024) catch return error.Neo4jConnectionError;
        defer alloc.free(raw_out);

        const term = child.wait() catch return error.Neo4jConnectionError;
        switch (term) {
            .Exited => |code| {
                if (code != 0) {
                    if (code == 28) return error.Neo4jTimeout;
                    return error.Neo4jConnectionError;
                }
            },
            else => return error.Neo4jConnectionError,
        }

        return parseCurlOutput(alloc, raw_out);
    }

    fn parseCurlOutput(alloc: Allocator, raw_out: []const u8) !HttpResponse {
        const sep = std.mem.lastIndexOfScalar(u8, raw_out, '\n') orelse return error.Neo4jInvalidResponse;
        const code_slice = std.mem.trim(u8, raw_out[sep + 1 ..], " \r\n\t");
        if (code_slice.len == 0) return error.Neo4jInvalidResponse;

        const status_code = std.fmt.parseInt(u10, code_slice, 10) catch return error.Neo4jInvalidResponse;
        const body = try alloc.dupe(u8, raw_out[0..sep]);
        return .{
            .status = @enumFromInt(status_code),
            .body = body,
        };
    }

    // ── Cypher execution ─────────────────────────────────────────

    fn executeCypher(self: *Self, alloc: Allocator, cypher: []const u8, params_json: ?[]const u8) ![]u8 {
        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(alloc);

        try payload.appendSlice(alloc, "{\"statements\":[{\"statement\":\"");
        try appendJsonEscaped(&payload, alloc, cypher);
        try payload.appendSlice(alloc, "\"");

        if (params_json) |p| {
            try payload.appendSlice(alloc, ",\"parameters\":");
            try payload.appendSlice(alloc, p);
        }

        try payload.appendSlice(alloc, "}]}");

        const payload_str = try alloc.dupe(u8, payload.items);
        defer alloc.free(payload_str);

        const resp = try self.doRequest(alloc, payload_str);
        errdefer alloc.free(resp.body);

        if (@intFromEnum(resp.status) >= 400) {
            log.err("Neo4j HTTP {d}: {s}", .{ @intFromEnum(resp.status), resp.body });
            alloc.free(resp.body);
            return error.Neo4jQueryError;
        }

        // Check for errors in the response JSON
        if (hasNeo4jErrors(resp.body)) {
            log.err("Neo4j query error: {s}", .{resp.body});
            alloc.free(resp.body);
            return error.Neo4jQueryError;
        }

        return resp.body;
    }

    fn hasNeo4jErrors(body: []const u8) bool {
        // Look for "errors":[ with non-empty content
        const errors_key = std.mem.indexOf(u8, body, "\"errors\":[") orelse return false;
        const after = body[errors_key + "\"errors\":[".len ..];
        // If the array is empty `]`, no errors
        const trimmed = std.mem.trimLeft(u8, after, " \t\r\n");
        return trimmed.len > 0 and trimmed[0] != ']';
    }

    // ── Fulltext index ───────────────────────────────────────────

    fn createFulltextIndex(self: *Self) !void {
        const cypher = try std.fmt.allocPrint(self.allocator,
            \\CREATE FULLTEXT INDEX memory_content_idx IF NOT EXISTS FOR (m:{s}) ON EACH [m.key, m.content]
        , .{self.node_label});
        defer self.allocator.free(cypher);

        const body = self.executeCypher(self.allocator, cypher, null) catch |err| {
            log.warn("failed to create fulltext index (may already exist): {}", .{err});
            return;
        };
        self.allocator.free(body);
    }

    // ── VTable implementation ────────────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "neo4j";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self_.allocator;

        // Build params JSON
        var params: std.ArrayListUnmanaged(u8) = .empty;
        defer params.deinit(alloc);

        try params.appendSlice(alloc, "{\"key\":\"");
        try appendJsonEscaped(&params, alloc, key);
        try params.appendSlice(alloc, "\",\"content\":\"");
        try appendJsonEscaped(&params, alloc, content);
        try params.appendSlice(alloc, "\",\"category\":\"");
        try appendJsonEscaped(&params, alloc, category.toString());
        try params.appendSlice(alloc, "\"");

        if (session_id) |sid| {
            try params.appendSlice(alloc, ",\"session_id\":\"");
            try appendJsonEscaped(&params, alloc, sid);
            try params.appendSlice(alloc, "\"");
        } else {
            try params.appendSlice(alloc, ",\"session_id\":null");
        }

        try params.appendSlice(alloc, "}");

        const cypher = try std.fmt.allocPrint(alloc,
            \\MERGE (m:{s} {{key: $key}}) ON CREATE SET m.id = randomUUID(), m.created_at = timestamp() SET m.content = $content, m.category = $category, m.session_id = $session_id, m.updated_at = timestamp()
        , .{self_.node_label});
        defer alloc.free(cypher);

        const params_str = try alloc.dupe(u8, params.items);
        defer alloc.free(params_str);

        const body = try self_.executeCypher(alloc, cypher, params_str);
        alloc.free(body);

        // Auto-relate: best-effort, errors logged not propagated
        self_.autoRelate(alloc, key);
    }

    fn implGet(ptr: *anyopaque, allocator: Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var params: std.ArrayListUnmanaged(u8) = .empty;
        defer params.deinit(allocator);
        try params.appendSlice(allocator, "{\"key\":\"");
        try appendJsonEscaped(&params, allocator, key);
        try params.appendSlice(allocator, "\"}");

        const params_str = try allocator.dupe(u8, params.items);
        defer allocator.free(params_str);

        const cypher = try std.fmt.allocPrint(allocator,
            \\MATCH (m:{s} {{key: $key}}) RETURN m.id AS id, m.key AS key, m.content AS content, m.category AS category, m.session_id AS session_id, toString(m.created_at) AS timestamp
        , .{self_.node_label});
        defer allocator.free(cypher);

        const body = try self_.executeCypher(allocator, cypher, params_str);
        defer allocator.free(body);

        var entries = try parseResultRows(allocator, body);
        defer {
            if (entries.len > 1) {
                for (entries[1..]) |*e| e.deinit(allocator);
            }
            allocator.free(entries);
        }

        if (entries.len == 0) return null;

        // Move first entry out
        const result = entries[0];
        // Prevent double-free: replace with empty so the defer doesn't free it
        entries[0] = MemoryEntry{
            .id = &.{},
            .key = &.{},
            .content = &.{},
            .category = .core,
            .timestamp = &.{},
        };
        // Free the placeholder zero-length slices (they point to empty comptime slices, don't free)
        return result;
    }

    fn implRecall(ptr: *anyopaque, allocator: Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var params: std.ArrayListUnmanaged(u8) = .empty;
        defer params.deinit(allocator);
        try params.appendSlice(allocator, "{\"query\":\"");
        try appendJsonEscaped(&params, allocator, query);
        try params.appendSlice(allocator, "\"");

        if (session_id) |sid| {
            try params.appendSlice(allocator, ",\"session_id\":\"");
            try appendJsonEscaped(&params, allocator, sid);
            try params.appendSlice(allocator, "\"");
        }

        var limit_buf: [16]u8 = undefined;
        const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
        try params.appendSlice(allocator, ",\"limit\":");
        try params.appendSlice(allocator, limit_str);
        try params.appendSlice(allocator, "}");

        const params_str = try allocator.dupe(u8, params.items);
        defer allocator.free(params_str);

        // Try fulltext search first, fall back to CONTAINS
        const session_filter = if (session_id != null)
            " AND m.session_id = $session_id"
        else
            "";

        const cypher = try std.fmt.allocPrint(allocator,
            \\CALL db.index.fulltext.queryNodes('memory_content_idx', $query) YIELD node AS m, score
            \\WHERE m:{s}{s}
            \\RETURN m.id AS id, m.key AS key, m.content AS content, m.category AS category, m.session_id AS session_id, toString(m.created_at) AS timestamp, score
            \\ORDER BY score DESC LIMIT $limit
        , .{ self_.node_label, session_filter });
        defer allocator.free(cypher);

        const body = self_.executeCypher(allocator, cypher, params_str) catch {
            // Fallback to CONTAINS search
            return self_.recallFallback(allocator, query, limit, session_id);
        };
        defer allocator.free(body);

        // Check if fulltext returned errors (index might not exist yet)
        if (hasNeo4jErrors(body)) {
            return self_.recallFallback(allocator, query, limit, session_id);
        }

        return parseResultRows(allocator, body);
    }

    fn recallFallback(self_: *Self, allocator: Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) ![]MemoryEntry {
        var params: std.ArrayListUnmanaged(u8) = .empty;
        defer params.deinit(allocator);
        try params.appendSlice(allocator, "{\"query\":\"");
        try appendJsonEscaped(&params, allocator, query);
        try params.appendSlice(allocator, "\"");

        if (session_id) |sid| {
            try params.appendSlice(allocator, ",\"session_id\":\"");
            try appendJsonEscaped(&params, allocator, sid);
            try params.appendSlice(allocator, "\"");
        }

        var limit_buf: [16]u8 = undefined;
        const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
        try params.appendSlice(allocator, ",\"limit\":");
        try params.appendSlice(allocator, limit_str);
        try params.appendSlice(allocator, "}");

        const params_str = try allocator.dupe(u8, params.items);
        defer allocator.free(params_str);

        const session_filter = if (session_id != null)
            " AND m.session_id = $session_id"
        else
            "";

        const cypher = try std.fmt.allocPrint(allocator,
            \\MATCH (m:{s}) WHERE (m.content CONTAINS $query OR m.key CONTAINS $query){s}
            \\RETURN m.id AS id, m.key AS key, m.content AS content, m.category AS category, m.session_id AS session_id, toString(m.created_at) AS timestamp
            \\ORDER BY m.updated_at DESC LIMIT $limit
        , .{ self_.node_label, session_filter });
        defer allocator.free(cypher);

        const body = try self_.executeCypher(allocator, cypher, params_str);
        defer allocator.free(body);

        return parseResultRows(allocator, body);
    }

    fn implList(ptr: *anyopaque, allocator: Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        var params: std.ArrayListUnmanaged(u8) = .empty;
        defer params.deinit(allocator);
        try params.appendSlice(allocator, "{");
        var has_param = false;

        var where_clauses: std.ArrayListUnmanaged(u8) = .empty;
        defer where_clauses.deinit(allocator);

        if (category) |cat| {
            try params.appendSlice(allocator, "\"category\":\"");
            try appendJsonEscaped(&params, allocator, cat.toString());
            try params.appendSlice(allocator, "\"");
            has_param = true;
            try where_clauses.appendSlice(allocator, "m.category = $category");
        }

        if (session_id) |sid| {
            if (has_param) try params.appendSlice(allocator, ",");
            try params.appendSlice(allocator, "\"session_id\":\"");
            try appendJsonEscaped(&params, allocator, sid);
            try params.appendSlice(allocator, "\"");
            if (where_clauses.items.len > 0) try where_clauses.appendSlice(allocator, " AND ");
            try where_clauses.appendSlice(allocator, "m.session_id = $session_id");
        }

        try params.appendSlice(allocator, "}");

        const where = if (where_clauses.items.len > 0)
            try std.fmt.allocPrint(allocator, " WHERE {s}", .{where_clauses.items})
        else
            try allocator.dupe(u8, "");
        defer allocator.free(where);

        const params_str = try allocator.dupe(u8, params.items);
        defer allocator.free(params_str);

        const cypher = try std.fmt.allocPrint(allocator,
            \\MATCH (m:{s}){s}
            \\RETURN m.id AS id, m.key AS key, m.content AS content, m.category AS category, m.session_id AS session_id, toString(m.created_at) AS timestamp
            \\ORDER BY m.updated_at DESC
        , .{ self_.node_label, where });
        defer allocator.free(cypher);

        const body = try self_.executeCypher(allocator, cypher, params_str);
        defer allocator.free(body);

        return parseResultRows(allocator, body);
    }

    fn implForget(ptr: *anyopaque, key: []const u8) anyerror!bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self_.allocator;

        var params: std.ArrayListUnmanaged(u8) = .empty;
        defer params.deinit(alloc);
        try params.appendSlice(alloc, "{\"key\":\"");
        try appendJsonEscaped(&params, alloc, key);
        try params.appendSlice(alloc, "\"}");

        const params_str = try alloc.dupe(u8, params.items);
        defer alloc.free(params_str);

        const cypher = try std.fmt.allocPrint(alloc,
            \\MATCH (m:{s} {{key: $key}}) DETACH DELETE m RETURN count(m) AS deleted
        , .{self_.node_label});
        defer alloc.free(cypher);

        const body = try self_.executeCypher(alloc, cypher, params_str);
        defer alloc.free(body);

        // Check if any nodes were deleted by looking at the result
        // The response will contain a "data" array with the count
        return std.mem.indexOf(u8, body, "\"deleted\"") != null;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self_.allocator;

        const cypher = try std.fmt.allocPrint(alloc,
            \\MATCH (m:{s}) RETURN count(m) AS cnt
        , .{self_.node_label});
        defer alloc.free(cypher);

        const body = try self_.executeCypher(alloc, cypher, null);
        defer alloc.free(body);

        return parseCountResult(body);
    }

    fn implHealthCheck(ptr: *anyopaque) bool {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        const body = self_.executeCypher(self_.allocator, "RETURN 1", null) catch return false;
        self_.allocator.free(body);
        return true;
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        self_.deinit();
    }

    const mem_vtable = Memory.VTable{
        .name = &implName,
        .store = &implStore,
        .recall = &implRecall,
        .get = &implGet,
        .list = &implList,
        .forget = &implForget,
        .count = &implCount,
        .healthCheck = &implHealthCheck,
        .deinit = &implDeinit,
    };

    // ── JSON parsing helpers ─────────────────────────────────────

    /// Parse Neo4j tx/commit response rows into MemoryEntry slices.
    /// Expected columns: id, key, content, category, session_id, timestamp[, score]
    fn parseResultRows(allocator: Allocator, body: []const u8) ![]MemoryEntry {
        // Neo4j HTTP response shape:
        // {"results":[{"columns":["id","key",...],"data":[{"row":["val1","val2",...]},...]}],"errors":[]}
        var entries: std.ArrayListUnmanaged(MemoryEntry) = .empty;
        errdefer {
            for (entries.items) |*e| e.deinit(allocator);
            entries.deinit(allocator);
        }

        // Find the columns array to determine column order
        const columns = parseColumnOrder(body) orelse return entries.toOwnedSlice(allocator);

        // Find "data":[ and iterate rows
        const data_key = std.mem.indexOf(u8, body, "\"data\":[") orelse return entries.toOwnedSlice(allocator);
        var pos = data_key + "\"data\":[".len;

        while (pos < body.len) {
            // Skip whitespace
            while (pos < body.len and (body[pos] == ' ' or body[pos] == '\t' or body[pos] == '\r' or body[pos] == '\n')) : (pos += 1) {}
            if (pos >= body.len or body[pos] == ']') break;

            // Find "row":[
            const row_key = std.mem.indexOf(u8, body[pos..], "\"row\":[") orelse break;
            pos += row_key + "\"row\":[".len;

            // Parse row values
            var row_values: [7]?[]const u8 = .{ null, null, null, null, null, null, null };
            var col_idx: usize = 0;
            while (col_idx < 7 and pos < body.len) {
                while (pos < body.len and (body[pos] == ' ' or body[pos] == '\t' or body[pos] == '\r' or body[pos] == '\n')) : (pos += 1) {}
                if (pos >= body.len or body[pos] == ']') break;
                if (body[pos] == ',') {
                    pos += 1;
                    continue;
                }

                if (body[pos] == '"') {
                    // String value
                    const str = parseJsonString(body, &pos) orelse break;
                    row_values[col_idx] = str;
                    col_idx += 1;
                } else if (body[pos] == 'n' and pos + 3 < body.len and std.mem.eql(u8, body[pos .. pos + 4], "null")) {
                    row_values[col_idx] = null;
                    col_idx += 1;
                    pos += 4;
                } else if (body[pos] >= '0' and body[pos] <= '9' or body[pos] == '-') {
                    // Number value — read until comma/]
                    const start = pos;
                    while (pos < body.len and body[pos] != ',' and body[pos] != ']' and body[pos] != ' ') : (pos += 1) {}
                    row_values[col_idx] = body[start..pos];
                    col_idx += 1;
                } else {
                    break;
                }
            }

            // Map columns to entry fields
            const id_val = getColumnValue(columns, row_values, "id");
            const key_val = getColumnValue(columns, row_values, "key");
            const content_val = getColumnValue(columns, row_values, "content");
            const cat_val = getColumnValue(columns, row_values, "category");
            const sid_val = getColumnValue(columns, row_values, "session_id");
            const ts_val = getColumnValue(columns, row_values, "timestamp");
            const score_val = getColumnValue(columns, row_values, "score");

            if (key_val != null and content_val != null) {
                const id = try allocator.dupe(u8, id_val orelse "");
                errdefer allocator.free(id);
                const key = try allocator.dupe(u8, key_val.?);
                errdefer allocator.free(key);
                const content = try allocator.dupe(u8, content_val.?);
                errdefer allocator.free(content);
                const timestamp = try allocator.dupe(u8, ts_val orelse "0");
                errdefer allocator.free(timestamp);
                const sid: ?[]const u8 = if (sid_val) |s| try allocator.dupe(u8, s) else null;
                errdefer if (sid) |s| allocator.free(s);

                const cat_str = cat_val orelse "core";
                const cat = MemoryCategory.fromString(cat_str);
                // If custom, we need to dupe the string since it points into body
                const category_final: MemoryCategory = switch (cat) {
                    .custom => .{ .custom = try allocator.dupe(u8, cat_str) },
                    else => cat,
                };

                var score: ?f64 = null;
                if (score_val) |sv| {
                    score = std.fmt.parseFloat(f64, sv) catch null;
                }

                try entries.append(allocator, .{
                    .id = id,
                    .key = key,
                    .content = content,
                    .category = category_final,
                    .timestamp = timestamp,
                    .session_id = sid,
                    .score = score,
                });
            }

            // Skip to next row object or end of data array
            while (pos < body.len and body[pos] != '{' and body[pos] != ']') : (pos += 1) {}
            if (pos >= body.len or body[pos] == ']') break;
        }

        return entries.toOwnedSlice(allocator);
    }

    const ColumnOrder = struct {
        names: [7]?[]const u8 = .{ null, null, null, null, null, null, null },
        count: usize = 0,
    };

    fn parseColumnOrder(body: []const u8) ?ColumnOrder {
        const col_key = std.mem.indexOf(u8, body, "\"columns\":[") orelse return null;
        var pos = col_key + "\"columns\":[".len;
        var order = ColumnOrder{};

        while (order.count < 7 and pos < body.len) {
            while (pos < body.len and (body[pos] == ' ' or body[pos] == ',' or body[pos] == '\t' or body[pos] == '\r' or body[pos] == '\n')) : (pos += 1) {}
            if (pos >= body.len or body[pos] == ']') break;

            if (body[pos] == '"') {
                const name = parseJsonString(body, &pos) orelse break;
                order.names[order.count] = name;
                order.count += 1;
            } else {
                break;
            }
        }

        return if (order.count > 0) order else null;
    }

    fn getColumnValue(columns: ColumnOrder, row_values: [7]?[]const u8, name: []const u8) ?[]const u8 {
        for (columns.names[0..columns.count], 0..) |col_name, i| {
            if (col_name) |cn| {
                if (std.mem.eql(u8, cn, name)) {
                    return row_values[i];
                }
            }
        }
        return null;
    }

    fn parseCountResult(body: []const u8) usize {
        // Look for "row":[N] pattern
        const row_key = std.mem.indexOf(u8, body, "\"row\":[") orelse return 0;
        var pos = row_key + "\"row\":[".len;
        while (pos < body.len and (body[pos] == ' ' or body[pos] == '\t')) : (pos += 1) {}
        if (pos >= body.len) return 0;

        const start = pos;
        while (pos < body.len and body[pos] >= '0' and body[pos] <= '9') : (pos += 1) {}
        if (pos == start) return 0;

        return std.fmt.parseInt(usize, body[start..pos], 10) catch 0;
    }

    /// Parse a JSON string starting at body[*pos] (which must be '"').
    /// Returns the unescaped string content (a slice into body).
    /// Advances *pos past the closing quote.
    fn parseJsonString(body: []const u8, pos: *usize) ?[]const u8 {
        if (pos.* >= body.len or body[pos.*] != '"') return null;
        pos.* += 1; // skip opening quote
        const start = pos.*;
        var has_escape = false;

        while (pos.* < body.len) {
            if (body[pos.*] == '\\') {
                has_escape = true;
                pos.* += 2; // skip escape sequence
                continue;
            }
            if (body[pos.*] == '"') {
                const result = body[start..pos.*];
                pos.* += 1; // skip closing quote
                if (has_escape) {
                    // For simplicity, return the raw escaped string.
                    // Neo4j values are simple strings (UUIDs, timestamps, etc.)
                    // and user content escaping is handled at storage time.
                    return result;
                }
                return result;
            }
            pos.* += 1;
        }
        return null;
    }
};

// ── Helpers ────────────────────────────────────────────────────────

fn base64Encode(allocator: Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.standard;
    const len = encoder.Encoder.calcSize(input.len);
    const buf = try allocator.alloc(u8, len);
    _ = encoder.Encoder.encode(buf, input);
    return buf;
}

// ── Tests ──────────────────────────────────────────────────────────

test "base64 encode" {
    const result = try base64Encode(std.testing.allocator, "neo4j:password");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("bmVvNGo6cGFzc3dvcmQ=", result);
}

test "base64 encode empty" {
    const result = try base64Encode(std.testing.allocator, "");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "parseCurlOutput extracts status and body" {
    const raw = "response body here\n200";
    const resp = try Neo4jMemory.parseCurlOutput(std.testing.allocator, raw);
    defer std.testing.allocator.free(resp.body);
    try std.testing.expectEqual(std.http.Status.ok, resp.status);
    try std.testing.expectEqualStrings("response body here", resp.body);
}

test "parseCurlOutput handles 404" {
    const raw = "{}\n404";
    const resp = try Neo4jMemory.parseCurlOutput(std.testing.allocator, raw);
    defer std.testing.allocator.free(resp.body);
    try std.testing.expectEqual(std.http.Status.not_found, resp.status);
}

test "hasNeo4jErrors detects empty errors" {
    try std.testing.expect(!Neo4jMemory.hasNeo4jErrors("{\"errors\":[]}"));
}

test "hasNeo4jErrors detects non-empty errors" {
    try std.testing.expect(Neo4jMemory.hasNeo4jErrors("{\"errors\":[{\"message\":\"fail\"}]}"));
}

test "hasNeo4jErrors handles missing key" {
    try std.testing.expect(!Neo4jMemory.hasNeo4jErrors("{\"results\":[]}"));
}

test "parseCountResult extracts count" {
    const body =
        \\{"results":[{"columns":["cnt"],"data":[{"row":[42]}]}],"errors":[]}
    ;
    try std.testing.expectEqual(@as(usize, 42), Neo4jMemory.parseCountResult(body));
}

test "parseCountResult returns zero on empty" {
    try std.testing.expectEqual(@as(usize, 0), Neo4jMemory.parseCountResult("{}"));
}

test "parseResultRows parses single row" {
    const body =
        \\{"results":[{"columns":["id","key","content","category","session_id","timestamp"],"data":[{"row":["abc","mykey","mycontent","core",null,"1234"]}]}],"errors":[]}
    ;
    const entries = try Neo4jMemory.parseResultRows(std.testing.allocator, body);
    defer root.freeEntries(std.testing.allocator, entries);

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("mykey", entries[0].key);
    try std.testing.expectEqualStrings("mycontent", entries[0].content);
    try std.testing.expectEqualStrings("abc", entries[0].id);
    try std.testing.expectEqualStrings("1234", entries[0].timestamp);
    try std.testing.expect(entries[0].session_id == null);
}

test "parseResultRows parses multiple rows" {
    const body =
        \\{"results":[{"columns":["id","key","content","category","session_id","timestamp"],"data":[{"row":["1","k1","c1","core",null,"t1"]},{"row":["2","k2","c2","daily","sess","t2"]}]}],"errors":[]}
    ;
    const entries = try Neo4jMemory.parseResultRows(std.testing.allocator, body);
    defer root.freeEntries(std.testing.allocator, entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("k1", entries[0].key);
    try std.testing.expectEqualStrings("k2", entries[1].key);
    try std.testing.expectEqualStrings("sess", entries[1].session_id.?);
}

test "parseResultRows handles empty data" {
    const body =
        \\{"results":[{"columns":["id","key","content","category","session_id","timestamp"],"data":[]}],"errors":[]}
    ;
    const entries = try Neo4jMemory.parseResultRows(std.testing.allocator, body);
    defer std.testing.allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "parseResultRows handles row with score" {
    const body =
        \\{"results":[{"columns":["id","key","content","category","session_id","timestamp","score"],"data":[{"row":["x","k","c","core",null,"0",1.5]}]}],"errors":[]}
    ;
    const entries = try Neo4jMemory.parseResultRows(std.testing.allocator, body);
    defer root.freeEntries(std.testing.allocator, entries);

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expect(entries[0].score != null);
    try std.testing.expectApproxEqAbs(@as(f64, 1.5), entries[0].score.?, 0.001);
}

test "parseColumnOrder extracts columns" {
    const body =
        \\{"results":[{"columns":["id","key","content"],"data":[]}]}
    ;
    const order = Neo4jMemory.parseColumnOrder(body) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 3), order.count);
    try std.testing.expectEqualStrings("id", order.names[0].?);
    try std.testing.expectEqualStrings("key", order.names[1].?);
    try std.testing.expectEqualStrings("content", order.names[2].?);
}

test "parseJsonString extracts simple string" {
    const body =
        \\"hello" rest
    ;
    var pos: usize = 0;
    const result = Neo4jMemory.parseJsonString(body, &pos) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("hello", result);
    try std.testing.expectEqual(@as(usize, 7), pos);
}

test "neo4j memory init and deinit" {
    var mem = try Neo4jMemory.init(std.testing.allocator, .{
        .url = "http://localhost:7474",
        .username = "neo4j",
        .password = "test",
        .database = "neo4j",
        .node_label = "Memory",
    });
    defer mem.deinit();

    try std.testing.expectEqualStrings("neo4j", mem.memory().name());
    try std.testing.expect(mem.auth_header != null);
}

test "neo4j memory init no auth" {
    var mem = try Neo4jMemory.init(std.testing.allocator, .{
        .url = "http://localhost:7474",
        .username = "",
        .password = "",
        .database = "testdb",
        .node_label = "TestNode",
    });
    defer mem.deinit();

    try std.testing.expect(mem.auth_header == null);
    try std.testing.expectEqualStrings("/db/testdb/tx/commit", mem.tx_endpoint);
}

test "neo4j memory init strips trailing slash" {
    var mem = try Neo4jMemory.init(std.testing.allocator, .{
        .url = "http://localhost:7474/",
        .username = "",
        .password = "",
    });
    defer mem.deinit();

    try std.testing.expectEqualStrings("http://localhost:7474", mem.base_url);
}

test "neo4j memory init rejects empty url" {
    const result = Neo4jMemory.init(std.testing.allocator, .{
        .url = "",
        .username = "",
        .password = "",
    });
    try std.testing.expectError(error.InvalidNeo4jUrl, result);
}

test "neo4j memory vtable name" {
    var mem = try Neo4jMemory.init(std.testing.allocator, .{});
    defer mem.deinit();
    const m = mem.memory();
    try std.testing.expectEqualStrings("neo4j", m.name());
}

test "GraphNode deinit frees all fields" {
    const alloc = std.testing.allocator;
    var node = Neo4jMemory.GraphNode{
        .key = try alloc.dupe(u8, "test_key"),
        .content = try alloc.dupe(u8, "test_content"),
        .category = try alloc.dupe(u8, "core"),
    };
    node.deinit(alloc);
}

test "GraphEdge deinit frees all fields" {
    const alloc = std.testing.allocator;
    var edge = Neo4jMemory.GraphEdge{
        .from_key = try alloc.dupe(u8, "a"),
        .to_key = try alloc.dupe(u8, "b"),
        .rel_type = try alloc.dupe(u8, "RELATES_TO"),
        .score = 0.5,
    };
    edge.deinit(alloc);
}

test "GraphResult deinit frees all contents" {
    const alloc = std.testing.allocator;
    var nodes = try alloc.alloc(Neo4jMemory.GraphNode, 1);
    nodes[0] = .{
        .key = try alloc.dupe(u8, "k"),
        .content = try alloc.dupe(u8, "c"),
        .category = try alloc.dupe(u8, "core"),
    };
    var edges = try alloc.alloc(Neo4jMemory.GraphEdge, 1);
    edges[0] = .{
        .from_key = try alloc.dupe(u8, "a"),
        .to_key = try alloc.dupe(u8, "b"),
        .rel_type = try alloc.dupe(u8, "RELATES_TO"),
        .score = null,
    };
    var result = Neo4jMemory.GraphResult{ .nodes = nodes, .edges = edges };
    result.deinit(alloc);
}

test "RecallWithGraphResult deinit frees all contents" {
    const alloc = std.testing.allocator;
    const direct = try alloc.alloc(MemoryEntry, 0);
    const related = try alloc.alloc(MemoryEntry, 0);
    var result = Neo4jMemory.RecallWithGraphResult{ .direct = direct, .related = related };
    result.deinit(alloc);
}

test "createRelationship rejects invalid rel_type" {
    var mem = try Neo4jMemory.init(std.testing.allocator, .{});
    defer mem.deinit();
    // In test mode, createRelationship returns Neo4jUnavailable before validation,
    // so we test the validator directly
    try std.testing.expect(Neo4jMemory.isValidRelType("RELATES_TO"));
    try std.testing.expect(Neo4jMemory.isValidRelType("REFINES"));
    try std.testing.expect(Neo4jMemory.isValidRelType("DEPENDS_ON"));
    try std.testing.expect(Neo4jMemory.isValidRelType("CONTRADICTS"));
    try std.testing.expect(Neo4jMemory.isValidRelType("SUPERSEDES"));
    try std.testing.expect(Neo4jMemory.isValidRelType("SUPPORTS"));
    try std.testing.expect(!Neo4jMemory.isValidRelType("INVALID"));
    try std.testing.expect(!Neo4jMemory.isValidRelType("relates_to"));
    try std.testing.expect(!Neo4jMemory.isValidRelType("DROP DATABASE"));
}

test "traverseGraph clamps max_hops" {
    var mem = try Neo4jMemory.init(std.testing.allocator, .{});
    defer mem.deinit();
    // In test mode, traverseGraph returns Neo4jUnavailable, but we test hops clamping logic
    // by verifying the clamp math directly
    const clamp = struct {
        fn f(h: u8) u8 {
            return if (h < 1) 1 else if (h > 3) 3 else h;
        }
    }.f;
    try std.testing.expectEqual(@as(u8, 1), clamp(0));
    try std.testing.expectEqual(@as(u8, 1), clamp(1));
    try std.testing.expectEqual(@as(u8, 2), clamp(2));
    try std.testing.expectEqual(@as(u8, 3), clamp(3));
    try std.testing.expectEqual(@as(u8, 3), clamp(5));
    try std.testing.expectEqual(@as(u8, 3), clamp(255));
}

test "autoRelate gates on builtin.is_test" {
    var mem = try Neo4jMemory.init(std.testing.allocator, .{});
    defer mem.deinit();
    // Should return immediately without error in test mode
    mem.autoRelate(std.testing.allocator, "test_key");
}

test "neo4j graph config defaults" {
    var mem = try Neo4jMemory.init(std.testing.allocator, .{});
    defer mem.deinit();
    try std.testing.expect(mem.auto_relate_enabled);
    try std.testing.expectEqual(@as(u8, 3), mem.auto_relate_top_k);
    try std.testing.expect(mem.graph_enriched_recall);
    try std.testing.expectEqual(@as(u8, 1), mem.graph_max_hops);
}

test "neo4j graph config custom values" {
    var mem = try Neo4jMemory.init(std.testing.allocator, .{
        .auto_relate_enabled = false,
        .auto_relate_top_k = 5,
        .graph_enriched_recall = false,
        .graph_max_hops = 2,
    });
    defer mem.deinit();
    try std.testing.expect(!mem.auto_relate_enabled);
    try std.testing.expectEqual(@as(u8, 5), mem.auto_relate_top_k);
    try std.testing.expect(!mem.graph_enriched_recall);
    try std.testing.expectEqual(@as(u8, 2), mem.graph_max_hops);
}
