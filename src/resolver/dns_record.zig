const std = @import("std");

/// DNS record types for ZNS
pub const DnsRecordType = enum(u16) {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    MX = 15,
    TXT = 16,
    SRV = 33,
    PTR = 12,
    NS = 2,
    SOA = 6,
    
    // ZNS-specific record types
    CRYPTO = 65280,  // 0xFF00 - Cryptocurrency address
    SOCIAL = 65281,  // 0xFF01 - Social media profiles
    WEB3 = 65282,    // 0xFF02 - Web3 metadata
    BRIDGE = 65283,  // 0xFF03 - Cross-chain bridge data
    
    pub fn toString(self: DnsRecordType) []const u8 {
        return switch (self) {
            .A => "A",
            .AAAA => "AAAA",
            .CNAME => "CNAME",
            .MX => "MX",
            .TXT => "TXT",
            .SRV => "SRV",
            .PTR => "PTR",
            .NS => "NS",
            .SOA => "SOA",
            .CRYPTO => "CRYPTO",
            .SOCIAL => "SOCIAL",
            .WEB3 => "WEB3",
            .BRIDGE => "BRIDGE",
        };
    }
};

/// DNS record structure for ZNS
pub const DnsRecord = struct {
    record_type: DnsRecordType,
    name: []const u8,
    value: []const u8,
    ttl: u32,
    signature: ?[]const u8 = null,
    
    // Additional ZNS-specific fields
    chain_id: ?u64 = null,
    priority: u16 = 0,
    weight: u16 = 0,
    port: u16 = 0,
    
    pub fn init(allocator: std.mem.Allocator, record_type: DnsRecordType, name: []const u8, value: []const u8, ttl: u32) !DnsRecord {
        return DnsRecord{
            .record_type = record_type,
            .name = try allocator.dupe(u8, name),
            .value = try allocator.dupe(u8, value),
            .ttl = ttl,
        };
    }
    
    pub fn deinit(self: *DnsRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
        if (self.signature) |sig| {
            allocator.free(sig);
        }
    }
    
    /// Check if record is expired based on TTL
    pub fn isExpired(self: *const DnsRecord, current_time: u64) bool {
        return current_time > self.ttl;
    }
    
    /// Serialize record to JSON format
    pub fn toJson(self: *const DnsRecord, allocator: std.mem.Allocator) ![]u8 {
        const has_signature = self.signature != null;
        const signature_str = if (self.signature) |sig| sig else "";
        
        const json_str = try std.fmt.allocPrint(allocator,
            \\{{
            \\  "type": "{s}",
            \\  "name": "{s}",
            \\  "value": "{s}",
            \\  "ttl": {d},
            \\  "priority": {d},
            \\  "weight": {d},
            \\  "port": {d},
            \\  "signature": {s},
            \\  "chain_id": {s}
            \\}}
        , .{
            self.record_type.toString(),
            self.name,
            self.value,
            self.ttl,
            self.priority,
            self.weight,
            self.port,
            if (has_signature) signature_str else "null",
            if (self.chain_id) |id| try std.fmt.allocPrint(allocator, "{d}", .{id}) else "null"
        });
        
        return json_str;
    }
    
    /// Parse record from JSON string
    pub fn fromJson(allocator: std.mem.Allocator, json_str: []const u8) !DnsRecord {
        // Simple JSON parsing for now - would use proper JSON parser in production
        var record = DnsRecord{
            .record_type = .A,
            .name = "",
            .value = "",
            .ttl = 0,
        };
        
        // Extract type
        if (std.mem.indexOf(u8, json_str, "\"type\": \"")) |start| {
            const type_start = start + 9;
            if (std.mem.indexOf(u8, json_str[type_start..], "\"")) |end| {
                const type_str = json_str[type_start..type_start + end];
                record.record_type = parseRecordType(type_str);
            }
        }
        
        // Extract name
        if (std.mem.indexOf(u8, json_str, "\"name\": \"")) |start| {
            const name_start = start + 9;
            if (std.mem.indexOf(u8, json_str[name_start..], "\"")) |end| {
                record.name = try allocator.dupe(u8, json_str[name_start..name_start + end]);
            }
        }
        
        // Extract value
        if (std.mem.indexOf(u8, json_str, "\"value\": \"")) |start| {
            const value_start = start + 10;
            if (std.mem.indexOf(u8, json_str[value_start..], "\"")) |end| {
                record.value = try allocator.dupe(u8, json_str[value_start..value_start + end]);
            }
        }
        
        // Extract TTL
        if (std.mem.indexOf(u8, json_str, "\"ttl\": ")) |start| {
            const ttl_start = start + 7;
            if (std.mem.indexOf(u8, json_str[ttl_start..], ",")) |end| {
                const ttl_str = json_str[ttl_start..ttl_start + end];
                record.ttl = std.fmt.parseInt(u32, ttl_str, 10) catch 0;
            }
        }
        
        return record;
    }
    
    /// Parse record type string to enum
    fn parseRecordType(type_str: []const u8) DnsRecordType {
        if (std.mem.eql(u8, type_str, "A")) return .A;
        if (std.mem.eql(u8, type_str, "AAAA")) return .AAAA;
        if (std.mem.eql(u8, type_str, "CNAME")) return .CNAME;
        if (std.mem.eql(u8, type_str, "MX")) return .MX;
        if (std.mem.eql(u8, type_str, "TXT")) return .TXT;
        if (std.mem.eql(u8, type_str, "SRV")) return .SRV;
        if (std.mem.eql(u8, type_str, "PTR")) return .PTR;
        if (std.mem.eql(u8, type_str, "NS")) return .NS;
        if (std.mem.eql(u8, type_str, "SOA")) return .SOA;
        if (std.mem.eql(u8, type_str, "CRYPTO")) return .CRYPTO;
        if (std.mem.eql(u8, type_str, "SOCIAL")) return .SOCIAL;
        if (std.mem.eql(u8, type_str, "WEB3")) return .WEB3;
        if (std.mem.eql(u8, type_str, "BRIDGE")) return .BRIDGE;
        return .A; // Default
    }
};

/// Collection of DNS records for a domain
pub const DnsRecordSet = struct {
    domain: []const u8,
    records: std.ArrayList(DnsRecord),
    last_updated: u64,
    
    pub fn init(allocator: std.mem.Allocator, domain: []const u8) !DnsRecordSet {
        return DnsRecordSet{
            .domain = try allocator.dupe(u8, domain),
            .records = std.ArrayList(DnsRecord).init(allocator),
            .last_updated = std.time.timestamp(),
        };
    }
    
    pub fn deinit(self: *DnsRecordSet, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        for (self.records.items) |*record| {
            record.deinit(allocator);
        }
        self.records.deinit();
    }
    
    /// Add a record to the set
    pub fn addRecord(self: *DnsRecordSet, record: DnsRecord) !void {
        try self.records.append(record);
        self.last_updated = std.time.timestamp();
    }
    
    /// Get all records of a specific type
    pub fn getRecordsByType(self: *const DnsRecordSet, record_type: DnsRecordType, allocator: std.mem.Allocator) ![]DnsRecord {
        var matching_records = std.ArrayList(DnsRecord).init(allocator);
        defer matching_records.deinit();
        
        for (self.records.items) |record| {
            if (record.record_type == record_type) {
                try matching_records.append(record);
            }
        }
        
        return matching_records.toOwnedSlice();
    }
    
    /// Get the first record of a specific type
    pub fn getFirstRecordByType(self: *const DnsRecordSet, record_type: DnsRecordType) ?DnsRecord {
        for (self.records.items) |record| {
            if (record.record_type == record_type) {
                return record;
            }
        }
        return null;
    }
    
    /// Remove expired records
    pub fn removeExpiredRecords(self: *DnsRecordSet, allocator: std.mem.Allocator) !void {
        const current_time = std.time.timestamp();
        var i: usize = 0;
        
        while (i < self.records.items.len) {
            if (self.records.items[i].isExpired(current_time)) {
                var removed = self.records.swapRemove(i);
                removed.deinit(allocator);
            } else {
                i += 1;
            }
        }
    }
    
    /// Export record set to JSON
    pub fn toJson(self: *const DnsRecordSet, allocator: std.mem.Allocator) ![]u8 {
        var json_parts = std.ArrayList([]u8).init(allocator);
        defer {
            for (json_parts.items) |part| {
                allocator.free(part);
            }
            json_parts.deinit();
        }
        
        const header = try std.fmt.allocPrint(allocator,
            \\{{
            \\  "domain": "{s}",
            \\  "last_updated": {d},
            \\  "records": [
        , .{ self.domain, self.last_updated });
        try json_parts.append(header);
        
        for (self.records.items, 0..) |record, i| {
            const record_json = try record.toJson(allocator);
            defer allocator.free(record_json);
            
            const record_with_comma = try std.fmt.allocPrint(allocator, "{s}{s}", .{
                record_json,
                if (i < self.records.items.len - 1) "," else ""
            });
            try json_parts.append(record_with_comma);
        }
        
        const footer = try allocator.dupe(u8, "\n  ]\n}");
        try json_parts.append(footer);
        
        // Concatenate all parts
        var total_len: usize = 0;
        for (json_parts.items) |part| {
            total_len += part.len;
        }
        
        const result = try allocator.alloc(u8, total_len);
        var pos: usize = 0;
        for (json_parts.items) |part| {
            std.mem.copy(u8, result[pos..], part);
            pos += part.len;
        }
        
        return result;
    }
};

/// ZNS-specific crypto address record
pub const CryptoAddressRecord = struct {
    domain: []const u8,
    chain: []const u8,
    address: []const u8,
    chain_id: u64,
    verified: bool = false,
    
    pub fn init(allocator: std.mem.Allocator, domain: []const u8, chain: []const u8, address: []const u8, chain_id: u64) !CryptoAddressRecord {
        return CryptoAddressRecord{
            .domain = try allocator.dupe(u8, domain),
            .chain = try allocator.dupe(u8, chain),
            .address = try allocator.dupe(u8, address),
            .chain_id = chain_id,
        };
    }
    
    pub fn deinit(self: *CryptoAddressRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        allocator.free(self.chain);
        allocator.free(self.address);
    }
    
    /// Convert to DNS record
    pub fn toDnsRecord(self: *const CryptoAddressRecord, allocator: std.mem.Allocator, ttl: u32) !DnsRecord {
        const value = try std.fmt.allocPrint(allocator, "{}:{s}", .{ self.chain_id, self.address });
        
        return DnsRecord{
            .record_type = .CRYPTO,
            .name = try allocator.dupe(u8, self.domain),
            .value = value,
            .ttl = ttl,
            .chain_id = self.chain_id,
        };
    }
};

test "DNS record creation and serialization" {
    const allocator = std.testing.allocator;
    
    // Create a DNS record
    var record = try DnsRecord.init(allocator, .A, "example.ghost", "192.168.1.1", 3600);
    defer record.deinit(allocator);
    
    // Test JSON serialization
    const json = try record.toJson(allocator);
    defer allocator.free(json);
    
    // Verify JSON contains expected fields
    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\": \"A\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\": \"example.ghost\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"value\": \"192.168.1.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"ttl\": 3600") != null);
}

test "DNS record set operations" {
    const allocator = std.testing.allocator;
    
    // Create record set
    var record_set = try DnsRecordSet.init(allocator, "example.ghost");
    defer record_set.deinit(allocator);
    
    // Add records
    const a_record = try DnsRecord.init(allocator, .A, "example.ghost", "192.168.1.1", 3600);
    const aaaa_record = try DnsRecord.init(allocator, .AAAA, "example.ghost", "2001:db8::1", 3600);
    
    try record_set.addRecord(a_record);
    try record_set.addRecord(aaaa_record);
    
    // Test record retrieval
    const first_a = record_set.getFirstRecordByType(.A);
    try std.testing.expect(first_a != null);
    try std.testing.expect(std.mem.eql(u8, first_a.?.value, "192.168.1.1"));
    
    // Test JSON export
    const json = try record_set.toJson(allocator);
    defer allocator.free(json);
    
    try std.testing.expect(std.mem.indexOf(u8, json, "\"domain\": \"example.ghost\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"records\": [") != null);
}

test "Crypto address record" {
    const allocator = std.testing.allocator;
    
    // Create crypto address record
    var crypto_record = try CryptoAddressRecord.init(allocator, "alice.ghost", "ethereum", "0x742d35Cc6634C0532925a3b844Bc9e7595f7E123", 1);
    defer crypto_record.deinit(allocator);
    
    // Convert to DNS record
    var dns_record = try crypto_record.toDnsRecord(allocator, 3600);
    defer dns_record.deinit(allocator);
    
    try std.testing.expect(dns_record.record_type == .CRYPTO);
    try std.testing.expect(std.mem.eql(u8, dns_record.name, "alice.ghost"));
    try std.testing.expect(dns_record.chain_id.? == 1);
}