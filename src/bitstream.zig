const std = @import("std");
const ArrayList = std.ArrayList;
const MultiArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const assert = std.debug.assert;

//https://github.com/cryptocode/bithacks/blob/main/bithacks.zig
pub fn requireInt(comptime T: type) type {
    comptime assert(@typeInfo(T) == .int);
}

pub fn requireIntPtr(comptime T: type) type {
    comptime assert(@typeInfo(T) == .ptr);
    requireInt(T.*);
}

const BitStreamError = error{
    NotEnoughBitsInStream,
};

pub fn BitStream() type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        stream: ArrayList(u1),

        pub fn init(allocator: std.mem.Allocator) Self {
            return Self{ .allocator = allocator, .stream = ArrayList(u1).init(allocator) };
        }

        pub fn pushFixedSize(self: Self, number: anytype) !void {
            _ = requireInt(number);
            const size = @bitSizeOf(@TypeOf(number));
            inline for (0..size) |i| {
                self.stream.append((number >> (size - 1 - i)) & 1);
            }
        }
        pub fn readFixedSize(self: Self, number: anytype, pos: usize) !void {
            _ = requireIntPtr(number);
            const size = @bitSizeOf(@TypeOf(number.*));
            const stream_len = self.stream.items.len;
            if (stream_len < size) return BitStreamError.NotEnoughBitsInStream;
            number.* = 0;
            inline for (0..size) |i| {
                number.* |= self.stream.items[pos - i] << i;
            }
        }
        pub fn pushULEB128(self: Self, number: anytype) !void {
            _ = requireInt(number);
            var local_number = number;
            var pusher: u8 = 0;
            while (local_number > (0xff >> 1)) {
                pusher = (local_number & (0xff >> 1)) << 1;
                try self.pushFixedSize(pusher);
                local_number >>= 7;
            }
            pusher = ((local_number & (0xff >> 1)) << 1) + 1;
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
    };
}
