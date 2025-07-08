const std = @import("std");
const zns = @import("zns");
const traits = @import("../src/resolver/traits.zig");

/// Example demonstrating the modular resolver architecture
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize registry
    var registry = traits.ResolverRegistry.init(allocator);
    defer registry.deinit();
    
    // Create and register resolvers
    try setupResolvers(&registry, allocator);
    
    // Test domains
    const test_domains = [_][]const u8{
        "alice.eth",
        "vault.crypto", 
        "test.ghost",
        "example.bc",
        "unknown.xyz",
    };
    
    std.debug.print("=== ZNS Modular Resolution Demo ===\n\n", .{});
    
    // Test single resolution
    for (test_domains) |domain| {
        std.debug.print("Resolving: {s}\n", .{domain});
        
        const result = registry.resolve(domain) catch |err| switch (err) {
            error.UnsupportedDomain => {
                std.debug.print("  ❌ Unsupported domain type\n", .{});
                continue;
            },
            error.DomainNotFound => {
                std.debug.print("  ❌ Domain not found\n", .{});
                continue;
            },
            else => {
                std.debug.print("  ❌ Error: {}\n", .{err});
                continue;
            },
        };
        defer result.deinit(allocator);
        
        std.debug.print("  ✅ {s}: {s}\n", .{ @tagName(result.chain), result.address });
        
        // Try to get metadata
        if (registry.getMetadata(domain)) |metadata| {
            defer allocator.free(metadata);
            std.debug.print("  📄 Metadata available ({d} bytes)\n", .{metadata.len});
        } else |_| {}
        
        std.debug.print("\n", .{});
    }
    
    // Test batch resolution
    std.debug.print("=== Batch Resolution ===\n", .{});
    for (test_domains) |domain| {
        if (registry.resolveAll(domain)) |addresses| {
            defer {
                for (addresses) |*addr| {
                    addr.deinit(allocator);
                }
                allocator.free(addresses);
            }
            
            std.debug.print("{s}: {d} addresses\n", .{ domain, addresses.len });
            for (addresses) |addr| {
                std.debug.print("  - {s}: {s}\n", .{ @tagName(addr.chain), addr.address });
            }
        } else |_| {}
    }
    
    // List supported TLDs
    std.debug.print("\n=== Supported TLDs ===\n", .{});
    if (registry.getSupportedTlds()) |tlds| {
        defer {
            for (tlds) |tld| {
                allocator.free(tld);
            }
            allocator.free(tlds);
        }
        
        for (tlds) |tld| {
            std.debug.print("  {s}\n", .{tld});
        }
    } else |err| {
        std.debug.print("Error getting TLDs: {}\n", .{err});
    }
}

/// Setup all available resolvers
fn setupResolvers(registry: *traits.ResolverRegistry, allocator: std.mem.Allocator) !void {
    // ENS Resolver
    {
        var ens_resolver = try allocator.create(zns.resolver.ens.ENSResolver);
        ens_resolver.* = zns.resolver.ens.ENSResolver.init(allocator, "https://eth-mainnet.alchemyapi.io/v2/demo");
        
        const ens_trait = traits.NameServiceResolver.from(zns.resolver.ens.ENSResolver, ens_resolver);
        try registry.register(ens_trait);
    }
    
    // Unstoppable Domains Resolver
    {
        var ud_resolver = try allocator.create(zns.resolver.unstoppable.UnstoppableResolver);
        ud_resolver.* = zns.resolver.unstoppable.UnstoppableResolver.init(allocator, null);
        
        const ud_trait = traits.NameServiceResolver.from(zns.resolver.unstoppable.UnstoppableResolver, ud_resolver);
        try registry.register(ud_trait);
    }
    
    // Ghost Resolver
    {
        var ghost_resolver = try allocator.create(zns.resolver.ghost.GhostResolver);
        ghost_resolver.* = zns.resolver.ghost.GhostResolver.init(allocator, "http://localhost:9090");
        
        const ghost_trait = traits.NameServiceResolver.from(zns.resolver.ghost.GhostResolver, ghost_resolver);
        try registry.register(ghost_trait);
    }
}

/// Example of using the functional lookup API
fn demonstrateFunctionalAPI(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== Functional API Demo ===\n", .{});
    
    const lookups = [_]struct {
        name: []const u8,
        domain: []const u8,
        lookup_fn: traits.LookupFn,
    }{
        .{ .name = "ENS", .domain = "alice.eth", .lookup_fn = traits.Lookups.ens_lookup },
        .{ .name = "Unstoppable", .domain = "vault.crypto", .lookup_fn = traits.Lookups.ud_lookup },
        .{ .name = "Ghost", .domain = "test.ghost", .lookup_fn = traits.Lookups.zns_lookup },
    };
    
    for (lookups) |lookup| {
        std.debug.print("Testing {s} lookup: {s}\n", .{ lookup.name, lookup.domain });
        
        if (lookup.lookup_fn(lookup.domain, allocator)) |result| {
            defer result.deinit(allocator);
            std.debug.print("  ✅ {s}: {s}\n", .{ @tagName(result.chain), result.address });
        } else |err| {
            std.debug.print("  ❌ Error: {}\n", .{err});
        }
    }
}