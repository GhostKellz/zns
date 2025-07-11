const std = @import("std");
const types = @import("types.zig");
const client = @import("../http/client.zig");

/// GhostChain native domain resolver
pub const GhostResolver = struct {
    allocator: std.mem.Allocator,
    http_client: client.HttpClient,
    ghostbridge_endpoint: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, ghostbridge_endpoint: []const u8) !GhostResolver {
        return GhostResolver{
            .allocator = allocator,
            .http_client = try client.HttpClient.init(allocator),
            .ghostbridge_endpoint = ghostbridge_endpoint,
        };
    }
    
    /// Resolve GhostChain domain to crypto address
    pub fn resolve(self: *GhostResolver, domain: []const u8) !types.CryptoAddress {
        // For now, use mock data until gRPC integration
        // TODO: Implement gRPC client for GhostBridge
        
        // Mock resolution for testing - support all Ghostchain TLDs
        if (std.mem.eql(u8, domain, "alice.ghost")) {
            return types.CryptoAddress.init(
                self.allocator,
                domain,
                .ghostchain,
                "ghost1qpz3ulyq0vxpe0jx8ywm5x2rjmgz4e9hy5r5xd"
            );
        } else if (std.mem.eql(u8, domain, "vault.bc")) {
            return types.CryptoAddress.init(
                self.allocator,
                domain,
                .ghostchain,
                "ghost1v4ultg3nw7x9e0jx8ywm5x2rjmgz4e9hy5r5xd"
            );
        } else if (std.mem.eql(u8, domain, "test.kz")) {
            return types.CryptoAddress.init(
                self.allocator,
                domain,
                .ghostchain,
                "ghost1test5ulyq0vxpe0jx8ywm5x2rjmgz4e9hy5r5xd"
            );
        } else if (std.mem.eql(u8, domain, "batcher.warp")) {
            return types.CryptoAddress.init(
                self.allocator,
                domain,
                .ghostchain,
                "ghost1warp123ulyq0vxpe0jx8ywm5x2rjmgz4e9hy5r5xd"
            );
        } else if (std.mem.eql(u8, domain, "registry.gcp")) {
            return types.CryptoAddress.init(
                self.allocator,
                domain,
                .ghostchain,
                "ghost1gcp456ulyq0vxpe0jx8ywm5x2rjmgz4e9hy5r5xd"
            );
        } else if (std.mem.eql(u8, domain, "governance.arc")) {
            return types.CryptoAddress.init(
                self.allocator,
                domain,
                .ghostchain,
                "ghost1arc789ulyq0vxpe0jx8ywm5x2rjmgz4e9hy5r5xd"
            );
        } else if (std.mem.eql(u8, domain, "mykey.gpk")) {
            return types.CryptoAddress.init(
                self.allocator,
                domain,
                .ghostchain,
                "ghost1gpkabc123ulyq0vxpe0jx8ywm5x2rjmgz4e9hy5r5xd"
            );
        } else if (std.mem.eql(u8, domain, "contract.gcc")) {
            return types.CryptoAddress.init(
                self.allocator,
                domain,
                .ghostchain,
                "ghost1gccdef456ulyq0vxpe0jx8ywm5x2rjmgz4e9hy5r5xd"
            );
        } else if (std.mem.eql(u8, domain, "signer.sig")) {
            return types.CryptoAddress.init(
                self.allocator,
                domain,
                .ghostchain,
                "ghost1sigghi789ulyq0vxpe0jx8ywm5x2rjmgz4e9hy5r5xd"
            );
        }
        
        return error.DomainNotFound;
    }
    
    /// Get all crypto addresses for domain (multi-chain support)
    pub fn resolveAll(self: *GhostResolver, domain: []const u8) ![]types.CryptoAddress {
        var addresses = std.ArrayList(types.CryptoAddress).init(self.allocator);
        defer addresses.deinit();
        
        // Primary GhostChain address
        const primary = try self.resolve(domain);
        try addresses.append(primary);
        
        // Mock additional addresses for testing
        if (std.mem.eql(u8, domain, "alice.ghost")) {
            // Also has Ethereum address
            const eth_addr = try types.CryptoAddress.init(
                self.allocator,
                domain,
                .ethereum,
                "0x742d35Cc6634C0532925a3b844Bc9e7595f7E123"
            );
            try addresses.append(eth_addr);
        }
        
        return addresses.toOwnedSlice();
    }
    
    /// Get domain metadata (placeholder)
    pub fn getMetadata(self: *GhostResolver, domain: []const u8) ![]const u8 {
        _ = domain;
        
        // Return mock metadata
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
        
        return self.allocator.dupe(u8, metadata_json);
    }
    
    /// Check if domain is GhostChain domain
    pub fn supports(domain: []const u8) bool {
        const ghost_tlds = [_][]const u8{ 
            // Core identity domains
            ".ghost", ".gcc", ".sig", ".gpk", ".key", ".pin",
            // Arc/warp/gcp ecosystem domains  
            ".warp", ".arc", ".gcp",
            // Decentralized & blockchain infrastructure
            ".bc", ".zns", ".ops",
            // Reserved/future domains
            ".sid", ".dvm", ".tmp", ".dbg", ".lib", ".txo",
            // Legacy domains
            ".kz", ".zkellz"
        };
        
        for (ghost_tlds) |tld| {
            if (std.mem.endsWith(u8, domain, tld)) {
                return true;
            }
        }
        return false;
    }
};

test "Ghost domain support check" {
    // Core identity domains
    try std.testing.expect(GhostResolver.supports("alice.ghost"));
    try std.testing.expect(GhostResolver.supports("contract.gcc"));
    try std.testing.expect(GhostResolver.supports("signer.sig"));
    try std.testing.expect(GhostResolver.supports("mykey.gpk"));
    try std.testing.expect(GhostResolver.supports("device.pin"));
    
    // Arc/warp/gcp ecosystem domains
    try std.testing.expect(GhostResolver.supports("batcher.warp"));
    try std.testing.expect(GhostResolver.supports("governance.arc"));
    try std.testing.expect(GhostResolver.supports("registry.gcp"));
    
    // Infrastructure domains
    try std.testing.expect(GhostResolver.supports("vault.bc"));
    try std.testing.expect(GhostResolver.supports("root.zns"));
    try std.testing.expect(GhostResolver.supports("gateway.ops"));
    
    // Reserved domains
    try std.testing.expect(GhostResolver.supports("temp.sid"));
    try std.testing.expect(GhostResolver.supports("vm.dvm"));
    try std.testing.expect(GhostResolver.supports("test.tmp"));
    try std.testing.expect(GhostResolver.supports("debug.dbg"));
    try std.testing.expect(GhostResolver.supports("math.lib"));
    try std.testing.expect(GhostResolver.supports("tx123.txo"));
    
    // Legacy domains
    try std.testing.expect(GhostResolver.supports("test.kz"));
    try std.testing.expect(GhostResolver.supports("zkellz.zkellz"));
    
    // Non-Ghost domains should return false
    try std.testing.expect(!GhostResolver.supports("alice.eth"));
    try std.testing.expect(!GhostResolver.supports("vault.crypto"));
}