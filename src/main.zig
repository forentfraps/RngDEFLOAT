const std = @import("std");
const ArrayList = std.ArrayList;
const MultiArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

extern fn HealthySeed([*]u8, usize) void;
// rdrand 32 bytes

const Tries = @import("tries.zig");
const TrieNode_HM = Tries.TrieNode_HM;
const TrieNode_AR = Tries.TrieNode_AR;
const TrieNode_LIN_AR = Tries.TrieNode_LIN_AR;

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

pub fn ULEB64_bitsize(n: usize) usize {
    var result: usize = 4;
    var arg = n >> 3;
    while (arg > 0) {
        result += 4;
        arg = arg >> 3;
    }
    return result;
}

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
        encrypted_entry_list: *MultiArrayList(EncryptEntry_type) = undefined,
        compressed_len: usize,
        global_block_counter: usize = 0,
        control_bitstream_len: usize = 0,
        max_length_sequence: usize = 0,
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
                .encrypted_entry_list = enc_list,
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
            // Attempts to matcha given range to a built trie

            var i: usize = 0;
            while (i < (seq_range.len - self.sequence_len)) {
                const local_seq = seq_range[i .. self.sequence_len + i];
                var table_index: usize = 0;
                const found_seq_len = self.check_seq(local_seq, self.root_node, 0, &table_index);
                if (found_seq_len > self.profit_len) {
                    try @constCast(self.encrypted_entry_list).append(.{
                        .file_index = @as(@typeInfo(EncryptEntry_type).@"struct".fields[0].type, @intCast(file_offset + i)),
                        .table_index = @as(@typeInfo(EncryptEntry_type).@"struct".fields[1].type, @intCast(table_index)),
                        .sequence_len = @as(@typeInfo(EncryptEntry_type).@"struct".fields[2].type, @intCast(found_seq_len)),
                    });
                    self.compressed_len -= found_seq_len;
                    //self.control_bitstream_len += 1 + ULEB128_bitsize(self.global_block_counter) + 1 + 3 + ULEB128_bitsize(table_index);
                    //                      control_bit | literal_block len      |      control_bit | len | offset
                    self.control_bitstream_len += 3 + ULEB64_bitsize(self.global_block_counter) + ULEB128_bitsize(table_index);

                    self.global_block_counter = 0;
                    i += found_seq_len;
                } else {
                    self.global_block_counter += 1;
                    i += 1;
                }
            }
        }

        fn check_seq(self: *@This(), seq: []const u8, node: *TrieNode, cur_len: usize, table_index: *usize) usize {
            // Check the sequence provided by match_seq_range for presence in a built trie.

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
            // Tries to compress data and checks whether it was successful

            //std.debug.print("\n[T] starting to compress\n", .{});
            try self.match_seq_range(buffer, 0);
            self.control_bitstream_len += 1 + ULEB128_bitsize(self.global_block_counter);
            const saved_bitstream_bytes: isize = @as(isize, @intCast(self.raw_size)) - @as(isize, @intCast(self.compressed_len + (self.control_bitstream_len / 8)));
            if (self.encrypted_entry_list.items.len == self.max_length_sequence and self.max_save_bytes < saved_bitstream_bytes) {
                self.max_save_bytes = saved_bitstream_bytes;
                std.debug.print("[*]\\{d} Control BitStream Format => {d} | total_seq => {d} || Maximum so far -> {d} | {d}\n", .{
                    iteration,
                    saved_bitstream_bytes,
                    self.encrypted_entry_list.items.len,
                    self.max_save_bytes,
                    self.max_length_sequence,
                });
            } else if (self.encrypted_entry_list.items.len > self.max_length_sequence) {
                self.max_save_bytes = saved_bitstream_bytes;
                self.max_length_sequence = self.encrypted_entry_list.items.len;
                std.debug.print("[*]\\{d} Control BitStream Format => {d} | total_seq => {d} || Maximum so far -> {d} | {d}\n", .{
                    iteration,
                    saved_bitstream_bytes,
                    self.encrypted_entry_list.items.len,
                    self.max_save_bytes,
                    self.max_length_sequence,
                });
            }
            return saved_bitstream_bytes > header_size;
        }

        pub fn calc_efficiency(self: @This()) isize {
            //obsolete
            var total_bytes: isize = 0;
            for (self.encrypted_entry_list.items) |entry| {
                total_bytes += entry.sequence_len - @sizeOf(EncryptEntry_type);
            }
            return total_bytes;
        }
        pub fn writeCompressed(self: @This(), original_file: [*]const u8, seed: [32]u8) !void {
            //TODO add ULEB encoding logic, after that encode the encry
            _ = try std.fs.cwd().createFile("output.enc", .{});
            var output_file = try std.fs.cwd().openFile("output.enc", .{ .mode = .write_only });
            _ = try output_file.write(seed[0..32]);
            for (self.encrypted_entry_list.items) |*entry| {
                const byte_repr: [*]u8 = @ptrCast(entry);
                _ = try output_file.write(byte_repr[0..@sizeOf(EncryptEntry_type)]);
            }
            var file_ptr: usize = 0;
            for (self.encrypted_entry_list.items) |entry| {
                _ = try output_file.write(original_file[file_ptr..@as(usize, @intCast(entry.file_index))]);
                file_ptr += entry.sequence_len;
            }
            output_file.close();
        }
        pub fn reset(self: *@This()) void {
            self.encrypted_entry_list.clearRetainingCapacity();
            self.compressed_len = self.raw_size;
            self.global_block_counter = 0;
            self.control_bitstream_len = 0;
        }
    };
}

fn attemptFileCompress(filename: []const u8) !void {
    const table_size = 16;
    const sequence_len = 8;
    const header_size = 32 + 1;
    const EncryptEntry_type: type = EncryptEntryFactory.custom(u20, u16, u3);

    var input_file = try std.fs.cwd().openFile(filename, .{});
    const size = (try input_file.metadata()).size();
    var buffer: [*]u8 = (try std.heap.page_allocator.alloc(u8, size)).ptr;
    _ = try input_file.read(buffer[0..size]);
    var seed: [32]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    std.debug.print("[P] building the trie tree\n", .{});

    var enc_list = MultiArrayList(EncryptEntry_type).init(allocator);
    var LPT = try LookupPrefixTree(EncryptEntry_type, TrieNode_HM).init(
        allocator,
        buffer[0..size],
        &enc_list,
        sequence_len,
        2,
    );
    std.debug.print("[P] trie built\n", .{});
    var i: u128 = 0;
    var table: []u8 = try allocator.alloc(u8, 1 << table_size);
    while (true) {
        initRandomTable(seed, table[0..].ptr, 1 << table_size);
        i += 1;
        HealthySeed(seed[0..].ptr, 32);
        //std.debug.print("[P] building the random table\n", .{});

        //std.debug.print("[P] starting to compress \n", .{});
        const valid_seed = try (&LPT).testcompress(table, header_size, i);
        if (valid_seed) {
            std.debug.print("VALID SEED FOUND!!!\n", .{});
            std.debug.print("[SEED] {any}\n", .{seed});

            try LPT.writeCompressed(buffer, seed);
            return;
        }
        LPT.reset();
    }
}

fn initRandomTable(seed: [32]u8, buf: [*]u8, size: usize) void {
    var csprng = std.Random.ChaCha.init(seed);
    csprng.fill(buf[0..size]);
    return;
}

pub fn main() !void {
    try attemptFileCompress("RandomData.bin");
}
