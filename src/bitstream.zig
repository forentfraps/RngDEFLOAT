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
    comptime assert(@typeInfo(T) == .ptr);
}

const BitStreamError = error{
    NotEnoughBitsInStream,
    OutOfStreamRead,
};

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

        pub fn initFromOwnedSlice(slice: []u8) !Self {
            var c = Self{ .stream = ArrayList(u8).fromOwnedSlice(slice) };
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
            self.stream.items[self.byte_ptr] |= @as(u8, @intCast(bit)) << self.bit_ptr;
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
            const bit_pos = pos - byte_pos * 8;
            if (byte_pos > self.byte_ptr) {
                return BitStreamError.OutOfStreamRead;
            } else if (byte_pos == self.byte_ptr and bit_pos > self.bit_ptr) {
                return BitStreamError.OutOfStreamRead;
            }
            return self.stream.items[byte_pos] & ((@as(u8, 1) << bit_pos));
        }

        pub fn pushFixedSize(self: *Self, number: anytype) !void {
            requireInt(@TypeOf(number));
            const size = @bitSizeOf(@TypeOf(number));
            inline for (0..size) |i| {
                try self.append(@as(u1, @intCast(((number >> (size - 1 - i)) & 1))));
            }
        }
        pub fn readFixedSize(self: Self, number: anytype, pos: usize) !void {
            requirePtr(@TypeOf(number));
            requireInt(@TypeOf(number.*));
            const size = @bitSizeOf(@TypeOf(number.*));
            const stream_len = self.byte_ptr * 8 + self.bit_ptr;
            if (stream_len < size) return BitStreamError.NotEnoughBitsInStream;
            number.* = 0;
            inline for (0..size) |i| {
                number.* |= @as(u8, @intCast((try self.get(pos - i)))) << i;
            }
        }
        pub fn pushULEB128(self: *Self, number: anytype) !void {
            requireInt(@TypeOf(number));
            var local_number = number;
            var pusher: u8 = 0;
            while (local_number > (0xff >> 1)) {
                pusher = @as(u8, @intCast((local_number & (0xff >> 1)) << 1));
                try self.pushFixedSize(pusher);
                local_number >>= 7;
            }
            pusher = @as(u8, @intCast(((local_number & (0xff >> 1)) << 1) + 1));
            try self.pushFixedSize(pusher);
        }

        pub fn readULEB128(self: Self, number: *usize, pos: usize) !void {
            number.* = 0;
            var cur_pos: usize = pos;
            const stream_len = self.stream.items.len;
            var pusher: u8 = 0;
            var last_octet: bool = false;
            while (cur_pos < stream_len and (cur_pos - pos) <= (@sizeOf(usize) * 8)) {
                try self.readFixedSize(&pusher, cur_pos);
                last_octet = (pusher & 1) == 1;
                pusher >>= 1;
                number.* |= (@as(usize, @intCast(pusher)) << (7 * ((cur_pos - pos) / 8)));
                if (last_octet) {
                    return;
                }
                cur_pos += 8;
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

        pub fn readULEB64(self: Self, number: *usize, pos: usize) !void {
            number.* = 0;
            var cur_pos: usize = pos;
            const stream_len = self.stream.items.len;
            var pusher: u4 = 0;
            var last_octet: bool = false;
            while (cur_pos < stream_len and (cur_pos - pos) <= (@sizeOf(usize) * 8)) {
                try self.readFixedSize(&pusher, cur_pos);
                last_octet = (pusher & 1) == 1;
                pusher >>= 1;
                number.* |= (@as(usize, @intCast(pusher)) << (3 * ((cur_pos - pos) / 4)));
                if (last_octet) {
                    return;
                }
                cur_pos += 4;
            }
            return BitStreamError.NotEnoughBitsInStream;
        }
    };
}
