const std = @import("std");
const dns_record = @import("../resolver/dns_record.zig");

/// LRU cache node
pub fn LruNode(comptime T: type) type {
    return struct {
        const Self = @This();
        
        key: []const u8,
        value: T,
        prev: ?*Self = null,
        next: ?*Self = null,
        expires_at: u64 = 0,
        
        pub fn init(allocator: std.mem.Allocator, key: []const u8, value: T, ttl_seconds: u32) !*Self {
            const node = try allocator.create(Self);
            node.* = Self{
                .key = try allocator.dupe(u8, key),
                .value = value,
                .expires_at = std.time.timestamp() + ttl_seconds,
            };
            return node;
        }
        
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.key);
            allocator.destroy(self);
        }
        
        pub fn isExpired(self: *const Self) bool {
            return std.time.timestamp() >= self.expires_at;
        }
    };
}

/// LRU cache with TTL support
pub fn LruCache(comptime T: type) type {
    return struct {
        const Self = @This();
        const Node = LruNode(T);
        
        allocator: std.mem.Allocator,
        capacity: usize,
        size: usize,
        nodes: std.HashMap([]const u8, *Node, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
        head: ?*Node,
        tail: ?*Node,
        
        // Statistics
        hits: u64,
        misses: u64,
        evictions: u64,
        expirations: u64,
        
        pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            return Self{
                .allocator = allocator,
                .capacity = capacity,
                .size = 0,
                .nodes = std.HashMap([]const u8, *Node, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
                .head = null,
                .tail = null,
                .hits = 0,
                .misses = 0,
                .evictions = 0,
                .expirations = 0,
            };
        }
        
        pub fn deinit(self: *Self) void {
            // Clean up all nodes
            var current = self.head;
            while (current) |node| {
                const next = node.next;
                node.deinit(self.allocator);
                current = next;
            }
            self.nodes.deinit();
        }
        
        /// Get value from cache
        pub fn get(self: *Self, key: []const u8) ?T {
            if (self.nodes.get(key)) |node| {
                // Check if expired
                if (node.isExpired()) {
                    self.remove(key);
                    self.expirations += 1;
                    self.misses += 1;
                    return null;
                }
                
                // Move to front (most recently used)
                self.moveToFront(node);
                self.hits += 1;
                return node.value;
            }
            
            self.misses += 1;
            return null;
        }
        
        /// Put value in cache with TTL
        pub fn put(self: *Self, key: []const u8, value: T, ttl_seconds: u32) !void {
            if (self.nodes.get(key)) |existing_node| {
                // Update existing node
                existing_node.value = value;
                existing_node.expires_at = std.time.timestamp() + ttl_seconds;
                self.moveToFront(existing_node);
                return;
            }
            
            // Create new node
            const node = try Node.init(self.allocator, key, value, ttl_seconds);
            
            // Add to hash map
            try self.nodes.put(node.key, node);
            
            // Add to front of linked list
            self.addToFront(node);
            self.size += 1;
            
            // Check capacity and evict if necessary
            if (self.size > self.capacity) {
                try self.evictLru();
            }
        }
        
        /// Remove key from cache
        pub fn remove(self: *Self, key: []const u8) void {
            if (self.nodes.get(key)) |node| {
                _ = self.nodes.remove(key);
                self.removeFromList(node);
                node.deinit(self.allocator);
                self.size -= 1;
            }
        }
        
        /// Clear all entries
        pub fn clear(self: *Self) void {
            var current = self.head;
            while (current) |node| {
                const next = node.next;
                node.deinit(self.allocator);
                current = next;
            }
            
            self.nodes.clearAndFree();
            self.head = null;
            self.tail = null;
            self.size = 0;
        }
        
        /// Remove expired entries
        pub fn removeExpired(self: *Self) void {
            var current = self.head;
            while (current) |node| {
                const next = node.next;
                if (node.isExpired()) {
                    _ = self.nodes.remove(node.key);
                    self.removeFromList(node);
                    node.deinit(self.allocator);
                    self.size -= 1;
                    self.expirations += 1;
                }
                current = next;
            }
        }
        
        /// Get cache statistics
        pub fn getStats(self: *const Self) CacheStats {
            return CacheStats{
                .hits = self.hits,
                .misses = self.misses,
                .evictions = self.evictions,
                .expirations = self.expirations,
                .size = self.size,
                .capacity = self.capacity,
                .hit_rate = if (self.hits + self.misses > 0) 
                    @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(self.hits + self.misses)) 
                else 0.0,
            };
        }
        
        /// Move node to front of list
        fn moveToFront(self: *Self, node: *Node) void {
            if (self.head == node) return;
            
            // Remove from current position
            self.removeFromList(node);
            
            // Add to front
            self.addToFront(node);
        }
        
        /// Add node to front of list
        fn addToFront(self: *Self, node: *Node) void {
            node.next = self.head;
            node.prev = null;
            
            if (self.head) |head| {
                head.prev = node;
            }
            
            self.head = node;
            
            if (self.tail == null) {
                self.tail = node;
            }
        }
        
        /// Remove node from list
        fn removeFromList(self: *Self, node: *Node) void {
            if (node.prev) |prev| {
                prev.next = node.next;
            } else {
                self.head = node.next;
            }
            
            if (node.next) |next| {
                next.prev = node.prev;
            } else {
                self.tail = node.prev;
            }
        }
        
        /// Evict least recently used node
        fn evictLru(self: *Self) !void {
            if (self.tail) |tail| {
                _ = self.nodes.remove(tail.key);
                self.removeFromList(tail);
                tail.deinit(self.allocator);
                self.size -= 1;
                self.evictions += 1;
            }
        }
    };
}

/// Cache statistics
pub const CacheStats = struct {
    hits: u64,
    misses: u64,
    evictions: u64,
    expirations: u64,
    size: usize,
    capacity: usize,
    hit_rate: f64,
    
    pub fn toString(self: *const CacheStats, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator,
            \\Cache Statistics:
            \\  Hits: {d}
            \\  Misses: {d}
            \\  Evictions: {d}
            \\  Expirations: {d}
            \\  Size: {d}/{d}
            \\  Hit Rate: {d:.2}%
        , .{
            self.hits,
            self.misses,
            self.evictions,
            self.expirations,
            self.size,
            self.capacity,
            self.hit_rate * 100.0,
        });
    }
};

/// Thread-safe LRU cache
pub fn ThreadSafeLruCache(comptime T: type) type {
    return struct {
        const Self = @This();
        
        cache: LruCache(T),
        mutex: std.Thread.Mutex,
        
        pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            return Self{
                .cache = try LruCache(T).init(allocator, capacity),
                .mutex = std.Thread.Mutex{},
            };
        }
        
        pub fn deinit(self: *Self) void {
            self.cache.deinit();
        }
        
        pub fn get(self: *Self, key: []const u8) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.cache.get(key);
        }
        
        pub fn put(self: *Self, key: []const u8, value: T, ttl_seconds: u32) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            try self.cache.put(key, value, ttl_seconds);
        }
        
        pub fn remove(self: *Self, key: []const u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.cache.remove(key);
        }
        
        pub fn clear(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.cache.clear();
        }
        
        pub fn removeExpired(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.cache.removeExpired();
        }
        
        pub fn getStats(self: *Self) CacheStats {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.cache.getStats();
        }
    };
}

/// DNS record cache
pub const DnsRecordCache = struct {
    cache: ThreadSafeLruCache(dns_record.DnsRecordSet),
    
    pub fn init(allocator: std.mem.Allocator, capacity: usize) !DnsRecordCache {
        return DnsRecordCache{
            .cache = try ThreadSafeLruCache(dns_record.DnsRecordSet).init(allocator, capacity),
        };
    }
    
    pub fn deinit(self: *DnsRecordCache) void {
        self.cache.deinit();
    }
    
    /// Get DNS records for domain
    pub fn getDnsRecords(self: *DnsRecordCache, domain: []const u8) ?dns_record.DnsRecordSet {
        return self.cache.get(domain);
    }
    
    /// Cache DNS records for domain
    pub fn cacheDnsRecords(self: *DnsRecordCache, domain: []const u8, records: dns_record.DnsRecordSet, ttl_seconds: u32) !void {
        try self.cache.put(domain, records, ttl_seconds);
    }
    
    /// Remove DNS records for domain
    pub fn removeDnsRecords(self: *DnsRecordCache, domain: []const u8) void {
        self.cache.remove(domain);
    }
    
    /// Clear all cached records
    pub fn clearAll(self: *DnsRecordCache) void {
        self.cache.clear();
    }
    
    /// Remove expired records
    pub fn cleanupExpired(self: *DnsRecordCache) void {
        self.cache.removeExpired();
    }
    
    /// Get cache statistics
    pub fn getStats(self: *DnsRecordCache) CacheStats {
        return self.cache.getStats();
    }
};

test "LRU cache basic operations" {
    const allocator = std.testing.allocator;
    
    var cache = try LruCache(i32).init(allocator, 3);
    defer cache.deinit();
    
    // Test put and get
    try cache.put("key1", 100, 3600);
    try cache.put("key2", 200, 3600);
    try cache.put("key3", 300, 3600);
    
    try std.testing.expect(cache.get("key1").? == 100);
    try std.testing.expect(cache.get("key2").? == 200);
    try std.testing.expect(cache.get("key3").? == 300);
    
    // Test eviction
    try cache.put("key4", 400, 3600);
    try std.testing.expect(cache.get("key1") == null); // Should be evicted
    try std.testing.expect(cache.get("key4").? == 400);
    
    // Test stats
    const stats = cache.getStats();
    try std.testing.expect(stats.evictions == 1);
    try std.testing.expect(stats.size == 3);
}

test "LRU cache TTL expiration" {
    const allocator = std.testing.allocator;
    
    var cache = try LruCache(i32).init(allocator, 3);
    defer cache.deinit();
    
    // Put with very short TTL
    try cache.put("key1", 100, 0); // Expires immediately
    
    // Should be expired
    try std.testing.expect(cache.get("key1") == null);
    
    const stats = cache.getStats();
    try std.testing.expect(stats.expirations == 1);
}

test "Thread-safe cache" {
    const allocator = std.testing.allocator;
    
    var cache = try ThreadSafeLruCache(i32).init(allocator, 10);
    defer cache.deinit();
    
    try cache.put("key1", 100, 3600);
    try std.testing.expect(cache.get("key1").? == 100);
    
    cache.remove("key1");
    try std.testing.expect(cache.get("key1") == null);
}