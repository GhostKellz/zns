const std = @import("std");
const types = @import("types.zig");
const client = @import("../http/client.zig");

/// Unstoppable Domains resolver
pub const UnstoppableResolver = struct {
    allocator: std.mem.Allocator,
    http_client: client.HttpClient,
    api_key: ?[]const u8 = null,
    
    const UNSTOPPABLE_API = "https://resolve.unstoppabledomains.com";
    
    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8) UnstoppableResolver {
        return UnstoppableResolver{
            .allocator = allocator,
            .http_client = client.HttpClient.init(allocator),
            .api_key = api_key,
        };
    }
    
    /// Unstoppable Domains API response format
    const UnstoppableResponse = struct {
        meta: struct {
            domain: []const u8,
            owner: ?[]const u8 = null,
            resolver: ?[]const u8 = null,
            registry: ?[]const u8 = null,
            reverse: bool = false,
        },
        records: std.json.ObjectMap,
    };
    
    /// Resolve Unstoppable domain to crypto addresses
    pub fn resolve(self: *UnstoppableResolver, domain: []const u8) !types.CryptoAddress {
        const url = try std.fmt.allocPrint(self.allocator, 
            "{s}/domains/{s}", .{ UNSTOPPABLE_API, domain });
        defer self.allocator.free(url);
        
        // Prepare headers
        var headers = std.ArrayList(client.HttpClient.HttpHeader).init(self.allocator);
        defer headers.deinit();
        
        try headers.append(.{ .name = "Accept", .value = "application/json" });
        
        if (self.api_key) |api_key| {
            const auth_header = try std.fmt.allocPrint(self.allocator, 
                "Bearer {s}", .{api_key});
            defer self.allocator.free(auth_header);
            
            try headers.append(.{ .name = "Authorization", .value = auth_header });
        }
        
        // Make request
        const response = try self.http_client.get(url, .{
            .headers = headers.items,
        });
        defer response.body[0..].deinit(self.allocator);
        
        if (response.status_code != 200) {
            return error.DomainNotFound;
        }
        
        // Parse response
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        
        const parsed = try std.json.parseFromSlice(UnstoppableResponse, 
            arena.allocator(), response.body, .{});
        
        // Find the best crypto address
        const crypto_addr = try self.extractCryptoAddress(domain, parsed.value.records);
        defer self.allocator.free(crypto_addr.address);
        
        return crypto_addr;
    }
    
    /// Extract crypto address from records
    fn extractCryptoAddress(self: *UnstoppableResolver, domain: []const u8, records: std.json.ObjectMap) !types.CryptoAddress {
        // Priority order for crypto currencies
        const crypto_keys = [_]struct {
            key: []const u8,
            chain: types.ChainType,
        }{
            .{ .key = "crypto.ETH.address", .chain = .ethereum },
            .{ .key = "crypto.BTC.address", .chain = .bitcoin },
            .{ .key = "crypto.MATIC.address", .chain = .polygon },
            .{ .key = "crypto.SOL.address", .chain = .solana },
            .{ .key = "crypto.AVAX.address", .chain = .avalanche },
            .{ .key = "crypto.BNB.address", .chain = .bsc },
            .{ .key = "crypto.FTM.address", .chain = .fantom },
        };
        
        // Try to find crypto addresses in priority order
        for (crypto_keys) |crypto_key| {
            if (records.get(crypto_key.key)) |value| {
                if (value == .string and value.string.len > 0) {
                    return types.CryptoAddress.init(
                        self.allocator, 
                        domain, 
                        crypto_key.chain, 
                        value.string
                    );
                }
            }
        }
        
        // Fallback: look for any crypto address
        var it = records.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            
            if (std.mem.startsWith(u8, key, "crypto.") and 
                std.mem.endsWith(u8, key, ".address") and
                value == .string and value.string.len > 0) {
                
                // Extract chain name from key (crypto.{CHAIN}.address)
                const chain_start = "crypto.".len;
                const chain_end = key.len - ".address".len;
                const chain_name = key[chain_start..chain_end];
                const chain = types.ChainType.fromString(chain_name);
                
                return types.CryptoAddress.init(
                    self.allocator, 
                    domain, 
                    chain, 
                    value.string
                );
            }
        }
        
        return error.DomainNotFound;
    }
    
    /// Get all crypto addresses for a domain
    pub fn resolveAll(self: *UnstoppableResolver, domain: []const u8) ![]types.CryptoAddress {
        const url = try std.fmt.allocPrint(self.allocator, 
            "{s}/domains/{s}", .{ UNSTOPPABLE_API, domain });
        defer self.allocator.free(url);
        
        // Make request
        const response = try self.http_client.get(url, .{});
        defer response.body[0..].deinit(self.allocator);
        
        if (response.status_code != 200) {
            return error.DomainNotFound;
        }
        
        // Parse response
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        
        const parsed = try std.json.parseFromSlice(UnstoppableResponse, 
            arena.allocator(), response.body, .{});
        
        // Extract all crypto addresses
        var addresses = std.ArrayList(types.CryptoAddress).init(self.allocator);
        defer addresses.deinit();
        
        var it = parsed.value.records.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            
            if (std.mem.startsWith(u8, key, "crypto.") and 
                std.mem.endsWith(u8, key, ".address") and
                value == .string and value.string.len > 0) {
                
                // Extract chain name
                const chain_start = "crypto.".len;
                const chain_end = key.len - ".address".len;
                const chain_name = key[chain_start..chain_end];
                const chain = types.ChainType.fromString(chain_name);
                
                const addr = try types.CryptoAddress.init(
                    self.allocator, 
                    domain, 
                    chain, 
                    value.string
                );
                try addresses.append(addr);
            }
        }
        
        return addresses.toOwnedSlice();
    }
    
    /// Check if domain is supported by Unstoppable Domains
    pub fn supports(domain: []const u8) bool {
        const supported_tlds = [_][]const u8{
            ".crypto", ".nft", ".x", ".wallet", ".bitcoin", 
            ".dao", ".888", ".zil", ".blockchain", ".coin"
        };
        
        for (supported_tlds) |tld| {
            if (std.mem.endsWith(u8, domain, tld)) {
                return true;
            }
        }
        return false;
    }
};

test "Unstoppable domain support check" {
    try std.testing.expect(UnstoppableResolver.supports("alice.crypto"));
    try std.testing.expect(UnstoppableResolver.supports("vault.nft"));
    try std.testing.expect(UnstoppableResolver.supports("dao.x"));
    try std.testing.expect(!UnstoppableResolver.supports("alice.eth"));
    try std.testing.expect(!UnstoppableResolver.supports("alice.ghost"));
}