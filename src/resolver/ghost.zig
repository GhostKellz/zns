const std = @import("std");
const types = @import("types.zig");

/// GhostBridge client for native .ghost domains
pub const GhostResolver = struct {
    allocator: std.mem.Allocator,
    ghostbridge_endpoint: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, ghostbridge_endpoint: []const u8) GhostResolver {
        return GhostResolver{
            .allocator = allocator,
            .ghostbridge_endpoint = ghostbridge_endpoint,
        };
    }
    
    /// Resolve native GhostChain domain
    pub fn resolve(self: *GhostResolver, domain: []const u8) !types.CryptoAddress {
        // TODO: Implement gRPC call to GhostBridge
        // For now, return mock data based on domain type
        
        const tld = types.extractTLD(domain);
        
        var mock_address: []const u8 = undefined;
        if (std.mem.eql(u8, tld, ".ghost")) {
            mock_address = "ghost1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l2l2l";
        } else if (std.mem.eql(u8, tld, ".bc")) {
            mock_address = "bc1qh4kl0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0q3u3u3u";
        } else if (std.mem.eql(u8, tld, ".kz")) {
            mock_address = "kz1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z1z";
        } else {
            mock_address = "ghost1defaultdefaultdefaultdefaultdefaultdefaultdefaultdefault";
        }
        
        return types.CryptoAddress.init(
            self.allocator, 
            domain, 
            .ghostchain, 
            mock_address
        );
    }
    
    /// Register new domain on GhostChain
    pub fn register(self: *GhostResolver, domain: []const u8, owner_pubkey: [32]u8) !types.ZNSRecord {
        
        // Create default A record
        var records = try self.allocator.alloc(types.DNSRecord, 1);
        records[0] = try types.DNSRecord.init(self.allocator, .A, "10.0.0.1", 300);
        
        const zns_record = try types.ZNSRecord.init(
            self.allocator,
            domain,
            owner_pubkey,
            records,
            300
        );
        
        // TODO: Sign with owner's private key using zcrypto
        // const zcrypto = @import("zcrypto");
        // const signable_data = try zns_record.getSignableData(self.allocator);
        // defer self.allocator.free(signable_data);
        // zns_record.signature = zcrypto.asym.ed25519.sign(signable_data, private_key);
        
        return zns_record;
    }
    
    /// Subscribe to domain changes
    pub fn subscribe(self: *GhostResolver, domain_filter: []const u8) !void {
        _ = self;
        // TODO: Implement gRPC streaming subscription to GhostBridge
        std.log.info("Subscribing to domain changes for: {s}", .{domain_filter});
    }
    
    /// Check if domain is native GhostChain domain
    pub fn supports(domain: []const u8) bool {
        const native_tlds = [_][]const u8{ ".ghost", ".bc", ".kz", ".zkellz" };
        
        for (native_tlds) |tld| {
            if (std.mem.endsWith(u8, domain, tld)) {
                return true;
            }
        }
        return false;
    }
    
    /// Get domain metadata
    pub fn getMetadata(self: *GhostResolver, domain: []const u8) !std.json.Value {
        _ = domain;
        
        // Mock metadata
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        
        const metadata_json = 
            \\{
            \\  "version": "1.0",
            \\  "type": "ghost_domain",
            \\  "services": {
            \\    "web": "https://ghostchain.io",
            \\    "ipfs": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
            \\  },
            \\  "social": {
            \\    "twitter": "@ghostchain",
            \\    "github": "ghostkellz"
            \\  }
            \\}
        ;
        
        const parsed = try std.json.parseFromSlice(std.json.Value, 
            arena.allocator(), metadata_json, .{});
        
        return parsed.value;
    }
};

test "Ghost domain support check" {
    try std.testing.expect(GhostResolver.supports("alice.ghost"));
    try std.testing.expect(GhostResolver.supports("vault.bc"));
    try std.testing.expect(GhostResolver.supports("test.kz"));
    try std.testing.expect(!GhostResolver.supports("alice.eth"));
    try std.testing.expect(!GhostResolver.supports("alice.crypto"));
}