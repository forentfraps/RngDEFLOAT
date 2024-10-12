const std = @import("std");
const ArrayList = std.ArrayList;
const MultiArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const assert = std.debug.assert;

//https://github.com/cryptocode/bithacks/blob/main/bithacks.zig
pub fn requireInt(comptime T: type) void {
    comptime assert(@typeInfo(T) == .int);
}

pub fn requirePtr(comptime T: type) void {
    comptime assert(@typeInfo(T) == .pointer);
}

const BitStreamError = error{
    NotEnoughBitsInStream,
    OutOfStreamRead,
};
fn reverseBits(val: anytype) @TypeOf(val) {
    requireInt(@TypeOf(val));
    var result: @TypeOf(val) = 0;
    inline for (0..@bitSizeOf(@TypeOf(val))) |i| {
        result |= ((val >> i) & 1) << (@bitSizeOf(@TypeOf(val)) - 1 - i);
    }
    return result;
}
pub fn BitStream() type {
    return struct {
        const Self = @This();
        stream: ArrayList(u8),
        byte_ptr: usize = 0,
        bit_ptr: u3 = 0,

        pub fn init(allocator: std.mem.Allocator) !Self {
            var c = Self{ .stream = ArrayList(u8).init(allocator) };
            try c.stream.append(0);
            return c;
        }

        pub fn deinit(self: *Self) void {
            self.stream.deinit();
            self.byte_ptr = 0;
            self.bit_ptr = 0;
            return;
        }

        pub fn initFromOwnedSlice(allocator: std.mem.Allocator, slice: []u8) !Self {
            var c = Self{ .stream = ArrayList(u8).fromOwnedSlice(allocator, slice) };
            c.byte_ptr = c.stream.items.len;
            c.bit_ptr = 0;
            try c.stream.append(0);
            return c;
        }

        pub fn clear(self: *Self) void {
            self.stream.shrinkRetainingCapacity(1);
            self.stream.items[0] = 0;
            self.byte_ptr = 0;
            self.bit_ptr = 0;
        }

        pub fn append(self: *Self, bit: u1) !void {
            self.stream.items[self.byte_ptr] |= @as(u8, @intCast(bit)) << (self.bit_ptr);
            if (self.bit_ptr == 7) {
                self.bit_ptr = 0;
                try self.stream.append(0);
                self.byte_ptr += 1;
            } else {
                self.bit_ptr += 1;
            }
        }

        pub fn get(self: Self, pos: usize) !u1 {
            const byte_pos = pos / 8;
            const bit_pos: u3 = @intCast(pos - byte_pos * 8);
            if (byte_pos > self.byte_ptr) {
                return BitStreamError.OutOfStreamRead;
            } else if (byte_pos == self.byte_ptr and bit_pos > self.bit_ptr) {
                return BitStreamError.OutOfStreamRead;
            }
            return @as(u1, @intCast(((self.stream.items[byte_pos] & (@as(u8, 1) << (bit_pos))) >> (bit_pos))));
        }

        pub fn pushFixedSize(self: *Self, number: anytype) !void {
            requireInt(@TypeOf(number));
            const size = @bitSizeOf(@TypeOf(number));
            inline for (0..size) |i| {
                const bit_to_push = (number >> (i)) & 1;
                std.debug.print("{d}", .{bit_to_push});
                try self.append(@as(u1, @intCast(bit_to_push)));
            }
            std.debug.print("\npushed number {d}\n", .{number});
        }
        pub fn readFixedSize(self: Self, number: anytype, pos: *usize) !void {
            requirePtr(@TypeOf(number));
            requireInt(@TypeOf(number.*));
            const size = @bitSizeOf(@TypeOf(number.*));
            const stream_len = self.byte_ptr * 8 + self.bit_ptr;
            std.debug.print("pos: {d} stream_len in bits: {d} \n", .{
                pos.*,
                stream_len,
            });
            if (stream_len - pos.* < size) return BitStreamError.NotEnoughBitsInStream;
            number.* = 0;
            inline for (0..size) |i| {
                const fetched_bit = try self.get(pos.* + i);
                std.debug.print("fetched bit: {d} i {d}\n", .{ fetched_bit, i });
                number.* = (number.*) | (@as(@TypeOf(number.*), @intCast(fetched_bit)) << (i));
            }
            // number.* = reverseBits(number.*);
            std.debug.print("read number: {x} \n", .{number.*});

            pos.* += size;
        }
        pub fn pushULEB128(self: *Self, number: anytype) !void {
            requireInt(@TypeOf(number));
            var local_number = number;
            var pusher: u8 = 0;
            while (local_number > (0xff >> 1)) {
                pusher = @as(u8, @intCast((local_number & (0xff >> 1))));
                try self.pushFixedSize(pusher);
                local_number >>= 7;
            }
            pusher = @as(u8, @intCast(((local_number & (0xff >> 1))) | (1 << 7)));
            try self.pushFixedSize(pusher);
        }

        pub fn readULEB128(self: Self, number: *usize, pos: *usize) !void {
            number.* = 0;
            var cur_pos: usize = pos.*;
            // const stream_len = self.stream.items.len;
            var pusher: u8 = 0;
            var last_octet: bool = false;
            while (true) {
                try self.readFixedSize(&pusher, &cur_pos);
                last_octet = (pusher >> 7) == 1;
                std.debug.print("pusher prior to touching {d}\n", .{pusher});
                pusher = pusher & (0xff >> 1);
                std.debug.print("pusher {d} last {}\n", .{ pusher, last_octet });

                const shift_value: u6 = @intCast(7 * ((cur_pos - pos.* - 8) / 8));
                number.* |= (@as(usize, @intCast(pusher)) << shift_value);
                if (last_octet) {
                    pos.* = cur_pos;
                    number.* = number.*;
                    return;
                }
            }
            return BitStreamError.NotEnoughBitsInStream;
        }
        pub fn pushULEB64(self: *Self, number: anytype) !void {
            requireInt(@TypeOf(number));
            var local_number = number;
            var pusher: u4 = 0;
            while (local_number > (0xf >> 1)) {
                pusher = @as(u4, @intCast((local_number & (0xf >> 1)) << 1));
                try self.pushFixedSize(pusher);
                local_number >>= 3;
            }

            pusher = @as(u4, @intCast(((local_number & (0xf >> 1)) << 1) + 1));
            try self.pushFixedSize(pusher);
        }

        pub fn readULEB64(self: Self, number: *usize, pos: *usize) !void {
            number.* = 0;
            var cur_pos: usize = pos.*;
            const stream_len = self.stream.items.len;
            var pusher: u4 = 0;
            var last_octet: bool = false;
            while (cur_pos < stream_len and (cur_pos - pos.*) <= (@sizeOf(usize) * 8)) {
                try self.readFixedSize(&pusher, cur_pos);
                last_octet = (pusher & 1) == 1;
                pusher >>= 1;
                number.* |= (@as(usize, @intCast(pusher)) << (3 * ((cur_pos - pos.*) / 4)));
                if (last_octet) {
                    pos.* = cur_pos;
                    return;
                }
                cur_pos += 4;
            }
            return BitStreamError.NotEnoughBitsInStream;
        }
    };
}
