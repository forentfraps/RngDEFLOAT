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

const bs = @import("bitstream.zig");
const BitStream = bs.BitStream;

const EncryptEntry_default = struct {
    file_index: usize,
    table_index: usize,
    sequence_len: usize,
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
        root_node: *TrieNode = undefined,
        encrypted_entry_list: *MultiArrayList(EncryptEntry_type) = undefined,
        compressed_len: usize,
        global_block_counter: usize = 0,
        control_bitstream_len: usize = 0,
        max_length_sequence: usize = 0,
        max_save_bytes: isize = 0,
        bitstream: *BitStream(),

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            table_data: []u8,
            enc_list: *MultiArrayList(EncryptEntry_type),
            bitstream: *BitStream(),
            sequence_len: usize,
        ) !Self {
            var LPT = Self{
                .raw_data = table_data.ptr,
                .raw_size = table_data.len,
                .allocator = allocator,
                .sequence_len = sequence_len,
                //.profit_len = @sizeOf(@typeInfo(EncryptEntry_type).@"struct".fields[2].type) + @sizeOf(@typeInfo(EncryptEntry_type).@"struct".fields[1].type) + 1,
                //.profit_len = profit_len,
                .compressed_len = table_data.len,
                .encrypted_entry_list = enc_list,
                .bitstream = bitstream,
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

        pub fn match_seq_range(self: *@This(), seq_range: []const u8, _: usize) !void {
            // Attempts to match a given range to a built trie

            var i: usize = 0;
            while (i < (seq_range.len - self.sequence_len)) {
                const local_seq = seq_range[i .. self.sequence_len + i];
                var table_index: usize = 0;
                const found_seq_len = self.check_seq(local_seq, self.root_node, 0, &table_index);
                if (found_seq_len > (ULEB128_bitsize(self.global_block_counter) + ULEB128_bitsize(table_index)) / 8) {
                    try @constCast(self.encrypted_entry_list).append(.{
                        .file_index = @as(@typeInfo(EncryptEntry_type).@"struct".fields[0].type, @intCast(self.global_block_counter)),
                        .table_index = @as(@typeInfo(EncryptEntry_type).@"struct".fields[1].type, @intCast(table_index)),
                        .sequence_len = @as(@typeInfo(EncryptEntry_type).@"struct".fields[2].type, @intCast(found_seq_len)),
                    });
                    self.compressed_len -= found_seq_len;
                    //self.control_bitstream_len += 1 + ULEB128_bitsize(self.global_block_counter) + 1 + 3 + ULEB128_bitsize(table_index);
                    //                      control_bit | literal_block len      |      control_bit | len | offset

                    //self.control_bitstream_len += 3 + ULEB64_bitsize(self.global_block_counter) + ULEB128_bitsize(table_index);
                    try self.bitstream.pushFixedSize(@as(@typeInfo(EncryptEntry_type).@"struct".fields[2].type, @intCast(found_seq_len)));
                    try self.bitstream.pushULEB128(self.global_block_counter);
                    try self.bitstream.pushULEB128(@as(@typeInfo(EncryptEntry_type).@"struct".fields[1].type, @intCast(table_index)));

                    self.global_block_counter = 0;
                    i += found_seq_len;
                } else {
                    self.global_block_counter += 1;
                    i += 1;
                }
            }
        }

        fn check_seq(self: *@This(), seq: []const u8, node: *TrieNode, cur_len: usize, file_index: *usize) usize {
            // Check the sequence provided by match_seq_range for presence in a built trie.

            //std.debug.print("cs called, curlen {d} seqlen {d}\n", .{ cur_len, seq.len });
            if (node.get(seq[0])) |child_node| {
                if (seq.len == 1) {
                    file_index.* = node.table_index + 1 - cur_len;
                    return cur_len;
                } else {
                    return self.check_seq(seq[1..], child_node, cur_len + 1, file_index);
                }
            } else {
                if (cur_len > 0) {
                    file_index.* = node.table_index + 1 - cur_len;
                }
                return cur_len;
            }
        }

        pub fn testcompress(self: *@This(), buffer: []const u8, _: usize, iteration: u128) !bool {
            // Tries to compress data and checks whether it was successful

            //std.debug.print("\n[T] starting to compress\n", .{});
            try self.match_seq_range(buffer, 0);
            const saved_bitstream_bytes: isize = @as(isize, @intCast(self.raw_size)) - @as(
                isize,
                @intCast(self.compressed_len + self.bitstream.byte_ptr + ULEB128_bitsize(self.bitstream.byte_ptr) / 8),
            );
            if (self.encrypted_entry_list.items.len == self.max_length_sequence and self.max_save_bytes < saved_bitstream_bytes) {
                self.max_save_bytes = saved_bitstream_bytes;
                std.debug.print("[*]\\{d} Control BitStream Format maximum so far -> delta {d} | seq count {d}\n", .{
                    iteration,
                    self.max_save_bytes,
                    self.max_length_sequence,
                });
            } else if (self.encrypted_entry_list.items.len > self.max_length_sequence) {
                self.max_save_bytes = saved_bitstream_bytes;
                self.max_length_sequence = self.encrypted_entry_list.items.len;
                std.debug.print("[*]\\{d} Control BitStream Format maximum so far ->delta {d} | seq count {d}\n", .{
                    iteration,
                    self.max_save_bytes,
                    self.max_length_sequence,
                });
            }
            return saved_bitstream_bytes >= 0;
        }

        pub fn calc_efficiency(self: @This()) isize {
            //obsolete
            var total_bytes: isize = 0;
            for (self.encrypted_entry_list.items) |entry| {
                total_bytes += entry.sequence_len - @sizeOf(EncryptEntry_type);
            }
            return total_bytes;
        }
        pub fn writeCompressed(
            self: @This(),
            original_file: [*]const u8,
            original_size: usize,
            seed: [32]u8,
            output_filename: []const u8,
        ) !void {
            _ = try std.fs.cwd().createFile(output_filename, .{});
            var output_file = try std.fs.cwd().openFile(output_filename, .{ .mode = .write_only });
            // seed
            _ = try output_file.write(seed[0..32]);
            var tmp_bitstream = try BitStream().init(std.heap.page_allocator);
            defer tmp_bitstream.deinit();
            try tmp_bitstream.pushULEB128(self.bitstream.stream.items.len);
            // size of control bitstream
            _ = try output_file.write(tmp_bitstream.stream.items[0..tmp_bitstream.stream.items.len]);

            // control bitstream
            _ = try output_file.write(self.bitstream.stream.items[0..self.bitstream.stream.items.len]);

            //literal run
            var file_ptr: usize = 0;
            for (self.encrypted_entry_list.items) |entry| {
                std.debug.print("{d} -> {d}\n", .{ file_ptr, file_ptr + entry.file_index });
                _ = try output_file.write(original_file[file_ptr .. file_ptr + entry.file_index]);
                file_ptr = file_ptr + entry.file_index + entry.sequence_len;
            }
            _ = try output_file.write(original_file[file_ptr..original_size]);
            output_file.close();
        }
        pub fn reset(self: *@This()) void {
            self.encrypted_entry_list.clearRetainingCapacity();
            self.compressed_len = self.raw_size;
            self.global_block_counter = 0;
            self.control_bitstream_len = 0;
            self.bitstream.clear();
        }
    };
}

fn compress(filename: []const u8, output_filename: []const u8, table_size: usize) !void {
    const sequence_len = 8;
    const header_size = 32;
    const EncryptEntry_type: type = EncryptEntryFactory.custom(u16, u20, u4);

    var input_file = try std.fs.cwd().openFile(filename, .{});
    const size = (try input_file.metadata()).size();
    var buffer: [*]u8 = (try std.heap.page_allocator.alloc(u8, size)).ptr;
    _ = try input_file.read(buffer[0..size]);
    var seed: [32]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    std.debug.print("[P] building the trie tree\n", .{});

    var enc_list = MultiArrayList(EncryptEntry_type).init(allocator);
    var bitstream = try BitStream().init(allocator);
    var LPT = try LookupPrefixTree(EncryptEntry_type, TrieNode_HM).init(
        allocator,
        buffer[0..size],
        &enc_list,
        &bitstream,
        sequence_len,
    );

    std.debug.print("[P] trie built\n", .{});
    var i: u128 = 0;
    var table: []u8 = try allocator.alloc(u8, table_size);
    while (true) {
        initRandomTable(seed, table[0..].ptr, table_size);
        i += 1;
        HealthySeed(seed[0..].ptr, 32);
        //std.debug.print("[P] building the random table\n", .{});

        //std.debug.print("[P] starting to compress \n", .{});
        const valid_seed = try (&LPT).testcompress(table, header_size, i);
        if (valid_seed) {
            std.debug.print("VALID SEED FOUND!!!\n", .{});
            std.debug.print("[SEED] {any}\n", .{seed});
            for (LPT.encrypted_entry_list.items) |entry| {
                std.debug.print(
                    "file offset {d} table_index {d} len {d}\n",
                    .{
                        entry.file_index,
                        entry.table_index,
                        entry.sequence_len,
                    },
                );
            }

            try LPT.writeCompressed(buffer, size, seed, output_filename);
            return;
        }
        LPT.reset();
    }
}

pub fn decompress(filename: []const u8, output_filename: []const u8, table_size: usize) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var input_file = try std.fs.cwd().openFile(filename, .{});

    std.debug.print("[D] Starting to decompress\n", .{});
    _ = try std.fs.cwd().createFile(output_filename, .{});
    var output_file = try std.fs.cwd().openFile(output_filename, .{ .mode = .write_only });
    defer input_file.close();
    defer output_file.close();
    const input_file_size = (try input_file.metadata()).size();
    var seed: [32]u8 = undefined;
    _ = try input_file.read(seed[0..32]);
    std.debug.print("[D] seed {any}\n", .{seed});
    var control_bitstream_len_buffer: [64]u8 = undefined;
    var table: []u8 = try allocator.alloc(u8, table_size);
    initRandomTable(seed, table[0..].ptr, table_size);
    var bitstream = try BitStream().init(allocator);
    var end_ptr: usize = 0;
    while (true) {
        _ = try input_file.read(control_bitstream_len_buffer[end_ptr .. end_ptr + 1]);
        try bitstream.pushFixedSize(control_bitstream_len_buffer[end_ptr]);
        if (control_bitstream_len_buffer[end_ptr] & (1 << 7) == 1 << 7) {
            break;
        }
        end_ptr += 1;
    }

    std.debug.print("[D] read the length\n", .{});
    var control_bitstream_len: usize = 0;
    var initial_bitstream_pos: usize = 0;
    try bitstream.readULEB128(&control_bitstream_len, &initial_bitstream_pos);
    var control_bitstream_buffer: []u8 = try allocator.alloc(u8, control_bitstream_len);
    _ = try input_file.read(control_bitstream_buffer[0..control_bitstream_len]);
    var control_bitstream = try BitStream().initFromOwnedSlice(allocator, control_bitstream_buffer);
    var bitstream_pos: usize = 0;
    var file_pos: usize = end_ptr + 32;
    var litteral_run_buffer = try allocator.alloc(u8, 512);
    std.debug.print("[D] Prereq init, control bitstream len: {d}\n", .{control_bitstream_len});
    for (0..control_bitstream_len * 2 / 5) |i| {
        std.debug.print("[D] deciphering {d} control entry\n", .{i});
        var sequence_len: u4 = 0;
        var litteral_run_offset: usize = 0;
        var table_index: usize = 0;
        try control_bitstream.readFixedSize(&sequence_len, &bitstream_pos);
        std.debug.print("pos after first read {d}\n", .{bitstream_pos});
        try control_bitstream.readULEB128(&litteral_run_offset, &bitstream_pos);

        std.debug.print("pos after second read {d}\n", .{bitstream_pos});
        try control_bitstream.readULEB128(&table_index, &bitstream_pos);
        litteral_run_buffer = try allocator.realloc(litteral_run_buffer, litteral_run_offset);
        _ = try input_file.read(litteral_run_buffer[0..litteral_run_offset]);
        _ = try output_file.write(litteral_run_buffer[0..litteral_run_offset]);
        _ = try output_file.write(table[table_index .. table_index + @as(usize, @intCast(sequence_len))]);
        file_pos += litteral_run_offset;
        std.debug.print(
            "file offset {d} table_index {d} sequence_len {d}\n",
            .{
                litteral_run_offset,
                table_index,
                sequence_len,
            },
        );
    }

    litteral_run_buffer = try allocator.realloc(litteral_run_buffer, input_file_size - file_pos);
    _ = try input_file.read(litteral_run_buffer[0 .. input_file_size - file_pos]);
    _ = try output_file.write(litteral_run_buffer[0 .. input_file_size - file_pos]);
}

fn initRandomTable(seed: [32]u8, buf: [*]u8, size: usize) void {
    var csprng = std.Random.ChaCha.init(seed);
    csprng.fill(buf[0..size]);
    return;
}

pub fn main() !void {
    const table_size = 1 << 16;
    try compress("RandomData.bin", "RandomData.bin.rdf", table_size);
    try decompress("RandomData.bin.rdf", "RandomDataDecoded.bin", table_size);
}
