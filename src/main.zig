const std = @import("std");
const ArrayList = std.ArrayList;
const MultiArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

extern fn HealthySeed([*]u8, usize) void;

const TrieNode_AR = struct {
    const Self = @This();
    index_map: [256]u8,
    presence_map: u256,
    nodes: ArrayList(*Self),
    table_index: usize,
    pub fn init(allocator: std.mem.Allocator, table_index: usize) !*@This() {
        var trie = try allocator.create(Self);

        @memset(trie.index_map[0..256], 0xaa);
        trie.table_index = table_index;
        trie.presence_map = 0;
        trie.nodes = ArrayList(*Self).init(allocator);

        return trie;
    }

    pub fn contains(self: *@This(), key: u8) bool {
        const bigone: u256 = 1;
        const presence_key: u256 = bigone << key;
        return (self.presence_map & presence_key) > 0;
    }

    pub fn put(self: *@This(), key: u8, node: *Self) !void {
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

    pub fn get(self: *@This(), key: u8) ?*Self {
        if (self.contains(key)) {
            return self.nodes.items[@as(usize, @intCast(self.index_map[@as(usize, @intCast(key))]))];
        } else {
            return null;
        }
    }
};

const TrieNode_HM = struct {
    const Self = @This();
    nodes: HashMap(u8, *Self),
    table_index: usize,
    pub fn init(allocator: std.mem.Allocator, table_index: usize) !*@This() {
        var trie = try allocator.create(Self);

        trie.table_index = table_index;
        trie.nodes = HashMap(u8, *Self).init(allocator);

        return trie;
    }

    pub fn put(self: *@This(), key: u8, node: *Self) !void {
        try self.nodes.putNoClobber(key, node);
        return;
    }
    pub fn get(self: *@This(), key: u8) ?*Self {
        return self.nodes.get(key);
    }
};

const TrieNode_LIN_AR = struct {
    const Self = @This();
    const array_item = struct { key: u8, item: *Self };
    table_index: usize,
    nodes: MultiArrayList(array_item),

    pub fn init(allocator: std.mem.Allocator, table_index: usize) !*Self {
        var ptr = try allocator.create(Self);

        ptr.table_index = table_index;
        ptr.nodes = MultiArrayList(array_item).init(allocator);
        return ptr;
    }

    fn binary_search(self: Self, key: u8, inserting: bool) ?usize {
        if (self.nodes.items.len == 0) {
            if (inserting) {
                return 0;
            } else {
                return null;
            }
        }
        var low: usize = 0;
        var high: usize = self.nodes.items.len - 1;
        var mid: usize = 0;
        while (low <= high) {
            mid = ((high - low) / 2) + low;
            const to_check = self.nodes.items[mid].key;
            if (to_check == key) {
                if (!inserting) {
                    return mid;
                } else {
                    return null;
                }
            } else if (to_check > key) {
                if (mid == 0) break;
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }
        if (inserting) {
            return low;
        }
        return null;
    }

    pub fn get(self: *Self, key: u8) ?*Self {
        if (self.binary_search(key, false)) |index| {
            return self.nodes.items[index].item;
        }
        return null;
    }

    pub fn put(self: *Self, key: u8, item: *Self) !void {
        if (self.binary_search(key, true)) |index_to_insert| {
            try self.nodes.insert(index_to_insert, array_item{ .key = key, .item = item });
        }
        return;
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
        return struct {
            file_index: file_index,
            table_index: table_index,
            sequence_len: sequence_len,
        };
    }
};

pub fn ULEB128_bitsize(n: usize) usize {
    var result: usize = 8;
    var arg = n >> 7;
    while (arg > 0) {
        result += 8;
        arg = arg >> 7;
    }
    return result;
}

const EncryptEntryList = MultiArrayList(EncryptEntry_default);

pub fn LookupPrefixTree(comptime EncryptEntry_type: type, comptime TrieNode: type) type {
    return struct {
        raw_data: [*]u8,
        raw_size: usize,
        allocator: std.mem.Allocator,
        sequence_len: usize = 16,
        profit_len: usize,
        root_node: *TrieNode = undefined,
        encryted_seq_list: *MultiArrayList(EncryptEntry_type) = undefined,
        compressed_len: usize,
        global_block_counter: usize = 0,
        control_bitstream_len: usize = 0,
        max_found_seq: usize = 0,
        max_save_bytes: isize = 0,
        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, table_data: []u8, enc_list: *MultiArrayList(EncryptEntry_type), sequence_len: usize, profit_len: usize) !Self {
            var LPT = Self{
                .raw_data = table_data.ptr,
                .raw_size = table_data.len,
                .allocator = allocator,
                .sequence_len = sequence_len,
                //.profit_len = @sizeOf(@typeInfo(EncryptEntry_type).@"struct".fields[2].type) + @sizeOf(@typeInfo(EncryptEntry_type).@"struct".fields[1].type) + 1,
                .profit_len = profit_len,
                .compressed_len = table_data.len,
                .encryted_seq_list = enc_list,
            };

            LPT.root_node = try TrieNode.init(allocator, 0);
            for (table_data, 0..) |byte_value, index| {
                try (&LPT).resolve_byte_value(
                    LPT.root_node,
                    byte_value,
                    index,
                    @min(LPT.sequence_len, LPT.raw_size - index),
                );
            }

            // Init other parameters as needed, like root_node, raw_data, etc.

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

            if (local_root_node.get(byte_value)) |child_node| {
                return self.resolve_byte_value(
                    child_node,
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

        pub fn match_seq_range(self: *@This(), seq_range: []const u8, file_offset: usize) !void {
            //std.debug.print("msr called\n", .{});
            var i: usize = 0;
            while (i < (seq_range.len - self.sequence_len)) {
                const local_seq = seq_range[i .. self.sequence_len + i];
                var table_index: usize = 0;
                const found_seq_len = self.check_seq(local_seq, self.root_node, 0, &table_index);
                if (found_seq_len > self.profit_len) {
                    try @constCast(self.encryted_seq_list).append(.{
                        .file_index = @as(@typeInfo(EncryptEntry_type).@"struct".fields[0].type, @intCast(file_offset + i)),
                        .table_index = @as(@typeInfo(EncryptEntry_type).@"struct".fields[1].type, @intCast(table_index)),
                        .sequence_len = @as(@typeInfo(EncryptEntry_type).@"struct".fields[2].type, @intCast(found_seq_len)),
                    });
                    self.compressed_len -= found_seq_len;
                    self.control_bitstream_len += 1 + ULEB128_bitsize(self.global_block_counter) + 1 + 3 + ULEB128_bitsize(table_index);
                    //                      control_bit | literal_block len      |      control_bit | len | offset

                    self.global_block_counter = 0;
                    i += found_seq_len;
                } else {
                    self.global_block_counter += 1;
                    i += 1;
                }
            }
        }

        pub fn check_seq(self: *@This(), seq: []const u8, node: *TrieNode, cur_len: usize, table_index: *usize) usize {
            //std.debug.print("cs called, curlen {d} seqlen {d}\n", .{ cur_len, seq.len });
            if (node.get(seq[0])) |child_node| {
                if (seq.len == 1) {
                    table_index.* = node.table_index + 1 - cur_len;
                    return cur_len;
                } else {
                    return self.check_seq(seq[1..], child_node, cur_len + 1, table_index);
                }
            } else {
                if (cur_len > 0) {
                    table_index.* = node.table_index + 1 - cur_len;
                }
                return cur_len;
            }
        }

        pub fn testcompress(self: *@This(), buffer: []const u8, header_size: usize, iteration: u128) !bool {
            //std.debug.print("\n[T] starting to compress\n", .{});
            try self.match_seq_range(buffer, 0);
            self.control_bitstream_len += 1 + ULEB128_bitsize(self.global_block_counter);
            const saved_bitstream_bytes: isize = @as(isize, @intCast(self.raw_size)) - @as(isize, @intCast(self.compressed_len + (self.control_bitstream_len / 8)));
            if (self.encryted_seq_list.items.len > self.max_found_seq) {
                self.max_found_seq = self.encryted_seq_list.items.len;
                self.max_save_bytes = saved_bitstream_bytes;
            }
            //if (saved_bitstream_bytes > 0) {
            std.debug.print("[*]\\{d} Control BitStream Format => {d} | total_seq => {d} || Maximum so far -> {d} | {d}\n", .{
                iteration,
                saved_bitstream_bytes,
                self.encryted_seq_list.items.len,
                self.max_save_bytes,
                self.max_found_seq,
            });
            //}

            //return (saved_sequence_bytes > header_size) or (saved_table_bytes > header_size);
            return saved_bitstream_bytes > header_size;
        }

        pub fn calc_efficiency(self: @This()) isize {
            var total_bytes: isize = 0;
            for (self.encryted_seq_list.items) |entry| {
                total_bytes += entry.sequence_len - @sizeOf(EncryptEntry_type);
            }
            return total_bytes;
        }
        pub fn writeCompressed(self: @This(), original_file: [*]const u8, seed: [32]u8) !void {
            //obsolete for now
            _ = try std.fs.cwd().createFile("output.enc", .{});
            var output_file = try std.fs.cwd().openFile("output.enc", .{ .mode = .write_only });
            _ = try output_file.write(seed[0..32]);
            for (self.encryted_seq_list.items) |*entry| {
                const byte_repr: [*]u8 = @ptrCast(entry);
                _ = try output_file.write(byte_repr[0..@sizeOf(EncryptEntry_type)]);
            }
            var file_ptr: usize = 0;
            for (self.encryted_seq_list.items) |entry| {
                _ = try output_file.write(original_file[file_ptr..@as(usize, @intCast(entry.file_index))]);
                file_ptr += entry.sequence_len;
            }
            output_file.close();
        }
        pub fn reset(self: *@This()) void {
            self.encryted_seq_list.clearRetainingCapacity();
            self.compressed_len = self.raw_size;
            self.global_block_counter = 0;
            self.control_bitstream_len = 0;
        }
    };
}

fn attemptFileCompress(filename: []const u8) !void {
    const table_size = 24;
    const sequence_len = 8;
    const header_size = 32 + 1;
    const EncryptEntry_type: type = EncryptEntryFactory.custom(u20, u20, u4);

    var input_file = try std.fs.cwd().openFile(filename, .{});
    const size = (try input_file.metadata()).size();
    var buffer: [*]u8 = (try std.heap.page_allocator.alloc(u8, size)).ptr;
    _ = try input_file.read(buffer[0..size]);
    var seed: [32]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    std.debug.print("[P] building the trie tree\n", .{});

    var enc_list = MultiArrayList(EncryptEntry_type).init(allocator);
    var LPT = try LookupPrefixTree(EncryptEntry_type, TrieNode_HM).init(allocator, buffer[0..size], &enc_list, sequence_len, 4);
    std.debug.print("[P] trie built\n", .{});
    var i: u128 = 0;
    while (true) {
        i += 1;
        HealthySeed(seed[0..].ptr, 32);
        var tmp_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        const tmp_allocator = tmp_arena.allocator();
        //std.debug.print("[P] building the random table\n", .{});
        const table = try initRandomTable(tmp_allocator, seed, 1 << table_size);

        //std.debug.print("[P] starting to compress \n", .{});
        const valid_seed = try (&LPT).testcompress(table[0 .. 1 << table_size], header_size, i);
        if (valid_seed) {
            std.debug.print("VALID SEED FOUND!!!\n", .{});
            std.debug.print("[SEED] {any}\n", .{seed});

            try LPT.writeCompressed(buffer, seed);
            return;
        }
        LPT.reset();
        tmp_arena.deinit();
    }
}

fn initRandomTable(allocator: std.mem.Allocator, seed: [32]u8, size: usize) ![*]u8 {
    var csprng = std.Random.ChaCha.init(seed);
    const table = try allocator.alloc(u8, size);
    csprng.fill(table);
    return table.ptr;
}

pub fn main() !void {
    try attemptFileCompress("RandomData.bin");
}
