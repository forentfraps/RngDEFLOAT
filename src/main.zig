const std = @import("std");
const ArrayList = std.ArrayList;
const MultiArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

extern fn HealthySeed([*]u8, usize) void;

const TrieNode = struct {
    index_map: [256]u8,
    presence_map: u256,
    nodes: ArrayList(*TrieNode),
    table_index: usize,
    pub fn init(allocator: std.mem.Allocator, table_index: usize) !*@This() {
        var trie = try allocator.create(TrieNode);

        @memset(trie.index_map[0..256], 0xaa);
        trie.table_index = table_index;
        trie.presence_map = 0;
        trie.nodes = ArrayList(*TrieNode).init(allocator);

        return trie;
    }

    pub fn contains(self: *@This(), key: u8) bool {
        const bigone: u256 = 1;
        const presence_key: u256 = bigone << key;
        return (self.presence_map & presence_key) > 0;
    }

    pub fn put(self: *@This(), key: u8, node: *TrieNode) !void {
        if (self.contains(key)) {
            return;
        }
        const bigone: u256 = 1;
        const presence_key: u256 = bigone << key;
        self.presence_map |= presence_key;
        const new_index = self.nodes.items.len;

        try self.nodes.append(node);
        self.index_map[key] = @as(u8, @intCast(new_index));
        return;
    }

    pub fn get(self: *@This(), key: u8) *TrieNode {
        return self.nodes.items[@as(usize, @intCast(self.index_map[@as(usize, @intCast(key))]))];
    }
};

const EncryptEntry_default = struct {
    file_index: u32,
    table_index: u16,
    sequence_len: u4,
};

const EncryptEntryFactory = struct {
    pub fn optimal() type {
        return EncryptEntry_default;
    }

    pub fn custom(file_index: type, table_index: type, sequence_len: type) type {
        const EncryptEntry = struct {
            file_index: file_index,
            table_index: table_index,
            sequence_len: sequence_len,
        };
        return EncryptEntry;
    }
};

const EncryptEntryList = MultiArrayList(EncryptEntry_default);

const LookupPrefixTree = struct {
    raw_data: [*]u8,
    raw_size: usize,
    allocator: std.mem.Allocator,
    sequence_len: usize = 256,
    profit_len: usize = 4,
    root_node: *TrieNode = undefined,
    EncryptEntry: type,
    encryted_seq_list: *anyopaque = undefined,
    compressed_len: isize,

    pub fn build(
        allocator: std.mem.Allocator,
        table_data: []u8,
        enc_list: *EncryptEntryList,
        sequence_len: usize,
        comptime EncryptEntry: type,
    ) !@This() {
        var LPT = LookupPrefixTree{
            .raw_data = table_data.ptr,
            .raw_size = table_data.len,
            .allocator = allocator,
            .sequence_len = sequence_len,
            .profit_len = @sizeOf(EncryptEntry.table_index),
            .compressed_len = table_data.len,
        };
        LPT.root_node = try TrieNode.init(allocator, 0);
        LPT.encryted_seq_list = enc_list;
        for (table_data, 0..) |byte_value, index| {
            try (&LPT).resolve_byte_value(
                LPT.root_node,
                byte_value,
                index,
                @min(LPT.sequence_len, LPT.raw_size - index),
            );
        }
        return LPT;
    }

    pub fn resolve_byte_value(
        self: *@This(),
        local_root_node: *TrieNode,
        byte_value: u8,
        byte_index: usize,
        depth: usize,
    ) !void {
        if (depth == 0) {
            return;
        }

        if (local_root_node.contains(byte_value)) {
            return self.resolve_byte_value(
                local_root_node.get(byte_value),
                self.raw_data[byte_index + 1],
                byte_index + 1,
                depth - 1,
            );
        } else {
            var new_node = try TrieNode.init(self.allocator, byte_index);

            new_node.table_index = byte_index;
            try local_root_node.put(byte_value, new_node);
            return self.resolve_byte_value(
                new_node,
                self.raw_data[byte_index + 1],
                byte_index + 1,
                depth - 1,
            );
        }
    }

    pub fn match_seq_range(self: *@This(), seq_range: []u8, file_offset: usize) !void {
        //std.debug.print("msr called\n", .{});
        var i: usize = 0;
        while (i < (seq_range.len - self.sequence_len)) {
            const local_seq = seq_range[i .. self.sequence_len + i];
            var table_index: usize = 0;
            const found_seq_len = self.check_seq(local_seq, self.root_node, 0, &table_index);
            if (found_seq_len > self.profit_len) {
                try @constCast(self.encryted_seq_list).append(.{
                    .file_index = @as(@Type(self.EncryptEntry.file_index), @intCast(file_offset + i)),
                    .table_index = @as(@Type(self.EncryptEntry.table_index), @intCast(table_index)),
                    .sequence_len = @as(@Type(self.EncryptEntry.sequence_len), @intCast(found_seq_len)),
                });
                i += found_seq_len;
            } else {
                i += 1;
            }
        }
    }

    pub fn check_seq(self: *@This(), seq: []u8, node: *TrieNode, cur_len: usize, table_index: *usize) usize {
        //std.debug.print("cs called, curlen {d} seqlen {d}\n", .{ cur_len, seq.len });
        if (node.contains(seq[0])) {
            if (seq.len == 1) {
                table_index.* = node.table_index - self.sequence_len;
                return self.sequence_len;
            } else {
                return self.check_seq(seq[1..], node.get(seq[0]), cur_len + 1, table_index);
            }
        } else {
            if (cur_len > 0) {
                table_index.* = node.table_index + 1 - cur_len;
            }
            return cur_len;
        }
    }

    pub fn testcompress(self: *@This(), size: usize) !void {
        self.compressed_len = 0;
        self.encryted_seq_list.clearRetainingCapacity();
        const block_count = size / self.sequence_len;
        var seed: [32]u8 = undefined;
        HealthySeed(seed[0..].ptr, 32);
        var csprng = std.Random.ChaCha.init(seed);
        const test_alloc = std.heap.page_allocator;

        var buffer: [*]u8 = (try test_alloc.alloc(u8, 2 * self.sequence_len)).ptr;
        csprng.fill(buffer[0..self.sequence_len]);

        std.debug.print("starting to test compress\n", .{});
        for (0..block_count) |i| {
            try self.match_seq_range(buffer[0 .. 2 * self.sequence_len], self.sequence_len * i);
            @memcpy(buffer[0..self.sequence_len], buffer[self.sequence_len .. self.sequence_len * 2]);
            csprng.fill(buffer[self.sequence_len .. self.sequence_len * 2]);
        }
        std.debug.print("finished test compress\n", .{});
        std.debug.print("compressed other way {d} -> {d} \n", .{ self.raw_size, @as(isize, @intCast(self.raw_size)) - self.compressed_len });
        std.debug.print("ratio {}\n", .{self.calc_efficiency(size)});
        test_alloc.free(buffer[0 .. 2 * self.sequence_len]);
    }

    pub fn calc_efficiency(self: @This(), data_size: usize) f32 {
        std.debug.print("this is called\n", .{});
        var saved_bytes: usize = 0;
        for (self.encryted_seq_list.items, 0..) |entry, i| {
            std.debug.print("entry {d}\n", .{i});
            saved_bytes += entry.sequence_len - self.profit_len;
        }
        std.debug.print("Saved {d} bytes \n", .{saved_bytes});
        const sf: f32 = @floatFromInt(saved_bytes);
        const dsf: f32 = @floatFromInt(data_size);
        return sf / dsf * 100.0;
    }
};

fn initRandomTable(allocator: std.mem.Allocator, seed: [32]u8, size: usize) ![*]u8 {
    var csprng = std.Random.ChaCha.init(seed);
    const table = try allocator.alloc(u8, size);
    csprng.fill(table);
    return table.ptr;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var seed: [32]u8 = undefined;
    HealthySeed(seed[0..].ptr, 32);

    std.debug.print("building the random table\n", .{});

    var table = try initRandomTable(allocator, seed, 1 << 16);

    std.debug.print("building the trie tree\n", .{});
    const EncryptEntry_type: type = comptime EncryptEntryFactory.custom(u32, u16, u4);
    var enc_list = MultiArrayList(EncryptEntry_type).init(allocator);
    var LPT = try LookupPrefixTree.build(allocator, table[0 .. 1 << 16], &enc_list, 16, EncryptEntry_type);
    std.debug.print("starting to compress\n", .{});
    for (0..128) |_| {
        try (&LPT).testcompress(1 << 24);
    }
}
