const std = @import("std");
const ArrayList = std.ArrayList;
const MultiArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

pub const TrieNode_AR = struct {
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

pub const TrieNode_HM = struct {
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

pub const TrieNode_LIN_AR = struct {
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
