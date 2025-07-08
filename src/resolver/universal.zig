const std = @import("std");
const types = @import("types.zig");
const ens = @import("ens.zig");
const unstoppable = @import("unstoppable.zig");
const ghost = @import("ghost.zig");
const zqlite_cache = @import("../cache/zqlite_cache.zig");

/// Universal resolver for all crypto domains with persistent caching
pub const UniversalResolver = struct {
    allocator: std.mem.Allocator,
    
    // Individual resolvers
    ghost_resolver: ghost.GhostResolver,
    ens_resolver: ens.ENSResolver,
    unstoppable_resolver: unstoppable.UnstoppableResolver,
    
    // ZQLite persistent cache
    cache: ?zqlite_cache.ZQLiteCache,
    
    pub fn init(
        allocator: std.mem.Allocator,
        ghostbridge_endpoint: []const u8,
        ethereum_rpc_url: []const u8,
        unstoppable_api_key: ?[]const u8,
    ) UniversalResolver {
        return UniversalResolver{
            .allocator = allocator,
            .ghost_resolver = ghost.GhostResolver.init(allocator, ghostbridge_endpoint),
            .ens_resolver = ens.ENSResolver.init(allocator, ethereum_rpc_url),
            .unstoppable_resolver = unstoppable.UnstoppableResolver.init(allocator, unstoppable_api_key),
            .cache = null,
        };
    }
    
    /// Initialize with ZQLite cache
    pub fn initWithCache(
        allocator: std.mem.Allocator,
        ghostbridge_endpoint: []const u8,
        ethereum_rpc_url: []const u8,
        unstoppable_api_key: ?[]const u8,
        cache_db_path: []const u8,
    ) !UniversalResolver {
        var resolver = init(allocator, ghostbridge_endpoint, ethereum_rpc_url, unstoppable_api_key);
        resolver.cache = try zqlite_cache.ZQLiteCache.init(allocator, cache_db_path);
        return resolver;
    }
    
    pub fn deinit(self: *UniversalResolver) void {
        if (self.cache) |*cache| {
            cache.deinit();
        }
    }
    
    /// Resolve any crypto domain to address
    pub fn resolve(self: *UniversalResolver, domain: []const u8) !types.CryptoAddress {
        // Check cache first if available
        if (self.cache) |*cache| {
            if (try cache.get(domain)) |cached| {
                return cached;
            }
        }
        
        const tld = types.extractTLD(domain);
        const domain_type = types.getDomainType(tld);
        
        // Route to appropriate resolver
        const result = switch (domain_type) {
            .ghost => try self.ghost_resolver.resolve(domain),
            .ens => try self.ens_resolver.resolve(domain),
            .unstoppable => try self.unstoppable_resolver.resolve(domain),
            .traditional => try self.resolveDNS(domain),
            .unknown => return error.UnsupportedDomain,
            .handshake => return error.UnsupportedDomain, // TODO: Implement Handshake
        };
        
        // Cache the result if cache is available
        if (self.cache) |*cache| {
            const resolver_name = switch (domain_type) {
                .ghost => "GhostResolver",
                .ens => "ENSResolver",
                .unstoppable => "UnstoppableResolver",
                .traditional => "DNSResolver",
                else => "UnknownResolver",
            };
            
            try cache.put(domain, result, resolver_name);
        }
        
        return result;
    }
    
    /// Resolve multiple domains in parallel
    pub fn resolveBatch(self: *UniversalResolver, domains: []const []const u8) ![]types.CryptoAddress {
        var results = try self.allocator.alloc(types.CryptoAddress, domains.len);
        
        // For now, resolve sequentially
        // TODO: Implement parallel resolution with TokioZ
        for (domains, 0..) |domain, i| {
            results[i] = self.resolve(domain) catch |err| switch (err) {
                error.DomainNotFound => try types.CryptoAddress.init(self.allocator, domain, .unknown, ""),
                else => return err,
            };
        }
        
        return results;
    }
    
    /// Get all crypto addresses for a domain (multi-chain)
    pub fn resolveAll(self: *UniversalResolver, domain: []const u8) ![]types.CryptoAddress {
        // Check cache first if available
        if (self.cache) |*cache| {
            const cached = try cache.getAll(domain);
            if (cached.len > 0) {
                return cached;
            }
        }
        
        const tld = types.extractTLD(domain);
        const domain_type = types.getDomainType(tld);
        
        const results = switch (domain_type) {
            .unstoppable => {
                // Unstoppable Domains support multiple chains
                return self.unstoppable_resolver.resolveAll(domain);
            },
            .ens, .ghost => {
                // Single chain domains
                const result = try self.resolve(domain);
                var single_result = try self.allocator.alloc(types.CryptoAddress, 1);
                single_result[0] = result;
                return single_result;
            },
            else => return error.UnsupportedDomain,
        };
        
        // Cache all results if cache is available
        if (self.cache) |*cache| {
            const resolver_name = switch (domain_type) {
                .ghost => "GhostResolver",
                .ens => "ENSResolver",
                .unstoppable => "UnstoppableResolver",
                else => "UnknownResolver",
            };
            
            try cache.putAll(domain, results, resolver_name);
        }
        
        return results;
    }
    
    /// Resolve traditional DNS TXT records for crypto addresses
    fn resolveDNS(self: *UniversalResolver, domain: []const u8) !types.CryptoAddress {
        _ = self;
        _ = domain;
        
        // TODO: Implement DNS TXT record resolution
        // Look for records like "crypto.ETH.address=0x..."
        
        return error.DomainNotFound;
    }
    
    /// Check if domain is supported
    pub fn supports(domain: []const u8) bool {
        return ghost.GhostResolver.supports(domain) or
               ens.ENSResolver.supports(domain) or
               unstoppable.UnstoppableResolver.supports(domain);
    }
    
    /// Get resolver type for domain
    pub fn getResolverType(domain: []const u8) types.DomainType {
        const tld = types.extractTLD(domain);
        return types.getDomainType(tld);
    }
    
    /// Clear cache
    pub fn clearCache(self: *UniversalResolver) !void {
        if (self.cache) |*cache| {
            try cache.cleanup();
        }
    }
    
    /// Get cache statistics
    pub fn getCacheStats(self: *UniversalResolver) !?zqlite_cache.ZQLiteCache.CacheStats {
        if (self.cache) |*cache| {
            return try cache.getStats();
        }
        return null;
    }
    
    /// Store metadata for a domain
    pub fn putMetadata(self: *UniversalResolver, domain: []const u8, key: []const u8, value: []const u8) !void {
        if (self.cache) |*cache| {
            try cache.putMetadata(domain, key, value);
        }
    }
    
    /// Get metadata for a domain
    pub fn getMetadata(self: *UniversalResolver, domain: []const u8, key: []const u8) !?[]const u8 {
        if (self.cache) |*cache| {
            return try cache.getMetadata(domain, key);
        }
        return null;
    }
};

/// Create a cached universal resolver with all resolvers wrapped in caching
pub fn createCachedUniversalResolver(
    allocator: std.mem.Allocator,
    ghostbridge_endpoint: []const u8,
    ethereum_rpc_url: []const u8,
    unstoppable_api_key: ?[]const u8,
    cache_db_path: []const u8,
) !UniversalResolver {
    return try UniversalResolver.initWithCache(
        allocator,
        ghostbridge_endpoint,
        ethereum_rpc_url,
        unstoppable_api_key,
        cache_db_path,
    );
}

test "Universal resolver domain type detection" {
    try std.testing.expect(UniversalResolver.supports("alice.eth"));
    try std.testing.expect(UniversalResolver.supports("vault.crypto"));
    try std.testing.expect(UniversalResolver.supports("ghostkellz.ghost"));
    try std.testing.expect(!UniversalResolver.supports("example.com"));
    
    try std.testing.expectEqual(types.DomainType.ens, UniversalResolver.getResolverType("alice.eth"));
    try std.testing.expectEqual(types.DomainType.unstoppable, UniversalResolver.getResolverType("vault.crypto"));
    try std.testing.expectEqual(types.DomainType.ghost, UniversalResolver.getResolverType("ghostkellz.ghost"));
}