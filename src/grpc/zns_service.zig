const std = @import("std");
const dns_record = @import("../resolver/dns_record.zig");
const lru_cache = @import("../cache/lru_cache.zig");
const types = @import("../resolver/types.zig");
const client = @import("../http/client.zig");

/// ZNS gRPC service request types
pub const ZnsResolveRequest = struct {
    domain: []const u8,
    record_types: []dns_record.DnsRecordType,
    include_metadata: bool = false,
    chain_filter: ?[]const u8 = null,
};

pub const ZnsResolveResponse = struct {
    domain: []const u8,
    records: []dns_record.DnsRecord,
    metadata: ?DomainMetadata = null,
    ttl: u32,
    signature: ?[]const u8 = null,
    
    pub fn deinit(self: *ZnsResolveResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        for (self.records) |*record| {
            record.deinit(allocator);
        }
        allocator.free(self.records);
        if (self.metadata) |*metadata| {
            metadata.deinit(allocator);
        }
        if (self.signature) |signature| {
            allocator.free(signature);
        }
    }
};

pub const ZnsRegisterRequest = struct {
    domain: []const u8,
    owner: []const u8,
    records: []dns_record.DnsRecord,
    ttl: u32,
    signature: []const u8,
};

pub const ZnsRegisterResponse = struct {
    domain: []const u8,
    transaction_hash: []const u8,
    status: RegistrationStatus,
    block_height: u64,
    
    pub const RegistrationStatus = enum {
        pending,
        confirmed,
        failed,
    };
};

pub const DomainSubscription = struct {
    domain: []const u8,
    event_types: []DomainEventType,
    
    pub const DomainEventType = enum {
        registration,
        transfer,
        record_update,
        expiration,
    };
};

pub const DomainChangeEvent = struct {
    domain: []const u8,
    event_type: DomainSubscription.DomainEventType,
    timestamp: u64,
    block_height: u64,
    transaction_hash: []const u8,
    data: []const u8,
};

pub const DomainMetadata = struct {
    owner: []const u8,
    registrar: []const u8,
    creation_date: u64,
    expiration_date: u64,
    last_updated: u64,
    social_profiles: std.StringHashMap([]const u8),
    web3_metadata: std.StringHashMap([]const u8),
    
    pub fn init(allocator: std.mem.Allocator) DomainMetadata {
        return DomainMetadata{
            .owner = "",
            .registrar = "",
            .creation_date = 0,
            .expiration_date = 0,
            .last_updated = 0,
            .social_profiles = std.StringHashMap([]const u8).init(allocator),
            .web3_metadata = std.StringHashMap([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *DomainMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.owner);
        allocator.free(self.registrar);
        
        var social_iter = self.social_profiles.iterator();
        while (social_iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.social_profiles.deinit();
        
        var web3_iter = self.web3_metadata.iterator();
        while (web3_iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.web3_metadata.deinit();
    }
};

/// ZNS gRPC service implementation
pub const ZnsService = struct {
    allocator: std.mem.Allocator,
    cache: lru_cache.DnsRecordCache,
    ghostbridge_client: client.GrpcClient,
    
    pub fn init(allocator: std.mem.Allocator, cache_capacity: usize, ghostbridge_endpoint: []const u8) !ZnsService {
        return ZnsService{
            .allocator = allocator,
            .cache = try lru_cache.DnsRecordCache.init(allocator, cache_capacity),
            .ghostbridge_client = try client.GrpcClient.init(allocator, ghostbridge_endpoint),
        };
    }
    
    pub fn deinit(self: *ZnsService) void {
        self.cache.deinit();
        self.ghostbridge_client.deinit();
    }
    
    /// Resolve domain to DNS records
    pub fn resolveDomain(self: *ZnsService, request: ZnsResolveRequest) !ZnsResolveResponse {
        // Check cache first
        if (self.cache.getDnsRecords(request.domain)) |cached_records| {
            // Filter records by requested types
            var filtered_records = std.ArrayList(dns_record.DnsRecord).init(self.allocator);
            defer filtered_records.deinit();
            
            for (cached_records.records.items) |record| {
                for (request.record_types) |requested_type| {
                    if (record.record_type == requested_type) {
                        try filtered_records.append(record);
                        break;
                    }
                }
            }
            
            return ZnsResolveResponse{
                .domain = try self.allocator.dupe(u8, request.domain),
                .records = try filtered_records.toOwnedSlice(),
                .ttl = 3600,
            };
        }
        
        // Cache miss - query GhostBridge
        const grpc_response = try self.ghostbridge_client.resolveDomain(request.domain);
        defer self.allocator.free(grpc_response);
        
        // Parse response and create DNS records
        var records = std.ArrayList(dns_record.DnsRecord).init(self.allocator);
        defer records.deinit();
        
        // Mock domain resolution for now
        if (isDomainSupported(request.domain)) {
            const crypto_record = try dns_record.DnsRecord.init(
                self.allocator,
                .CRYPTO,
                request.domain,
                "ghost1example123456789abcdef",
                3600
            );
            try records.append(crypto_record);
            
            // Add A record if requested
            for (request.record_types) |record_type| {
                if (record_type == .A) {
                    const a_record = try dns_record.DnsRecord.init(
                        self.allocator,
                        .A,
                        request.domain,
                        "192.168.1.1",
                        3600
                    );
                    try records.append(a_record);
                }
            }
        }
        
        // Cache the records
        var record_set = try dns_record.DnsRecordSet.init(self.allocator, request.domain);
        for (records.items) |record| {
            try record_set.addRecord(record);
        }
        try self.cache.cacheDnsRecords(request.domain, record_set, 3600);
        
        // Get metadata if requested
        var metadata: ?DomainMetadata = null;
        if (request.include_metadata) {
            metadata = try self.getDomainMetadata(request.domain);
        }
        
        return ZnsResolveResponse{
            .domain = try self.allocator.dupe(u8, request.domain),
            .records = try records.toOwnedSlice(),
            .metadata = metadata,
            .ttl = 3600,
        };
    }
    
    /// Register domain on GhostChain
    pub fn registerDomain(self: *ZnsService, request: ZnsRegisterRequest) !ZnsRegisterResponse {
        // Validate domain and signature
        if (!isDomainSupported(request.domain)) {
            return error.UnsupportedDomain;
        }
        
        // Send registration request to GhostChain via gRPC
        const registration_data = try self.createRegistrationData(request);
        defer self.allocator.free(registration_data);
        
        const grpc_response = try self.ghostbridge_client.unaryCall(
            "GhostChain",
            "RegisterDomain",
            registration_data
        );
        defer self.allocator.free(grpc_response);
        
        // Parse registration response
        const tx_hash = try self.parseTransactionHash(grpc_response);
        
        // Clear cache for this domain
        self.cache.removeDnsRecords(request.domain);
        
        return ZnsRegisterResponse{
            .domain = try self.allocator.dupe(u8, request.domain),
            .transaction_hash = tx_hash,
            .status = .pending,
            .block_height = 0, // Will be updated when confirmed
        };
    }
    
    /// Subscribe to domain change events
    pub fn subscribeDomainChanges(self: *ZnsService, subscription: DomainSubscription) !void {
        // Create subscription data
        const subscription_data = try self.createSubscriptionData(subscription);
        defer self.allocator.free(subscription_data);
        
        // Send subscription request to GhostBridge
        const grpc_response = try self.ghostbridge_client.unaryCall(
            "GhostChain",
            "SubscribeDomainChanges",
            subscription_data
        );
        defer self.allocator.free(grpc_response);
        
        // Handle subscription response
        // In a real implementation, this would set up a streaming gRPC connection
    }
    
    /// Get domain metadata
    fn getDomainMetadata(self: *ZnsService, domain: []const u8) !DomainMetadata {
        const metadata_response = try self.ghostbridge_client.getDomainMetadata(domain);
        defer self.allocator.free(metadata_response);
        
        // Parse metadata from response
        var metadata = DomainMetadata.init(self.allocator);
        
        // Mock metadata parsing
        metadata.owner = try self.allocator.dupe(u8, "ghost1owner123456789abcdef");
        metadata.registrar = try self.allocator.dupe(u8, "GhostChain");
        metadata.creation_date = std.time.timestamp();
        metadata.expiration_date = std.time.timestamp() + (365 * 24 * 60 * 60); // 1 year
        metadata.last_updated = std.time.timestamp();
        
        // Add social profiles
        try metadata.social_profiles.put(
            try self.allocator.dupe(u8, "twitter"),
            try self.allocator.dupe(u8, "@ghostchain")
        );
        
        // Add web3 metadata
        try metadata.web3_metadata.put(
            try self.allocator.dupe(u8, "ipfs"),
            try self.allocator.dupe(u8, "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        );
        
        return metadata;
    }
    
    /// Create registration data for gRPC call
    fn createRegistrationData(self: *ZnsService, request: ZnsRegisterRequest) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{
            \\  "domain": "{s}",
            \\  "owner": "{s}",
            \\  "ttl": {d},
            \\  "signature": "{s}",
            \\  "records": []
            \\}}
        , .{ request.domain, request.owner, request.ttl, request.signature });
    }
    
    /// Create subscription data for gRPC call
    fn createSubscriptionData(self: *ZnsService, subscription: DomainSubscription) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{
            \\  "domain": "{s}",
            \\  "event_types": []
            \\}}
        , .{subscription.domain});
    }
    
    /// Parse transaction hash from gRPC response
    fn parseTransactionHash(self: *ZnsService, response: []const u8) ![]u8 {
        // Simple JSON parsing - extract transaction hash
        if (std.mem.indexOf(u8, response, "\"transaction_hash\":\"")) |start| {
            const hash_start = start + 19;
            if (std.mem.indexOf(u8, response[hash_start..], "\"")) |end| {
                return self.allocator.dupe(u8, response[hash_start..hash_start + end]);
            }
        }
        
        // Return mock hash if parsing fails
        return self.allocator.dupe(u8, "0x123456789abcdef0123456789abcdef01234567");
    }
    
    /// Check if domain is supported by ZNS
    fn isDomainSupported(domain: []const u8) bool {
        const supported_tlds = [_][]const u8{
            ".ghost", ".gcc", ".sig", ".gpk", ".key", ".pin",
            ".warp", ".arc", ".gcp", ".bc", ".zns", ".ops",
            ".sid", ".dvm", ".tmp", ".dbg", ".lib", ".txo",
            ".kz", ".zkellz"
        };
        
        for (supported_tlds) |tld| {
            if (std.mem.endsWith(u8, domain, tld)) {
                return true;
            }
        }
        
        return false;
    }
    
    /// Get service statistics
    pub fn getServiceStats(self: *ZnsService) ServiceStats {
        const cache_stats = self.cache.getStats();
        
        return ServiceStats{
            .cache_stats = cache_stats,
            .total_resolutions = cache_stats.hits + cache_stats.misses,
            .total_registrations = 0, // Track in real implementation
            .active_subscriptions = 0, // Track in real implementation
        };
    }
};

/// Service statistics
pub const ServiceStats = struct {
    cache_stats: lru_cache.CacheStats,
    total_resolutions: u64,
    total_registrations: u64,
    active_subscriptions: u64,
    
    pub fn toString(self: *const ServiceStats, allocator: std.mem.Allocator) ![]u8 {
        const cache_stats_str = try self.cache_stats.toString(allocator);
        defer allocator.free(cache_stats_str);
        
        return std.fmt.allocPrint(allocator,
            \\ZNS Service Statistics:
            \\  Total Resolutions: {d}
            \\  Total Registrations: {d}
            \\  Active Subscriptions: {d}
            \\
            \\{s}
        , .{
            self.total_resolutions,
            self.total_registrations,
            self.active_subscriptions,
            cache_stats_str,
        });
    }
};

/// ZNS gRPC server
pub const ZnsGrpcServer = struct {
    allocator: std.mem.Allocator,
    service: ZnsService,
    port: u16,
    
    pub fn init(allocator: std.mem.Allocator, cache_capacity: usize, ghostbridge_endpoint: []const u8, port: u16) !ZnsGrpcServer {
        return ZnsGrpcServer{
            .allocator = allocator,
            .service = try ZnsService.init(allocator, cache_capacity, ghostbridge_endpoint),
            .port = port,
        };
    }
    
    pub fn deinit(self: *ZnsGrpcServer) void {
        self.service.deinit();
    }
    
    /// Start gRPC server
    pub fn start(self: *ZnsGrpcServer) !void {
        // In a real implementation, this would start a gRPC server
        // For now, just print that we're starting
        std.log.info("Starting ZNS gRPC server on port {d}", .{self.port});
    }
    
    /// Stop gRPC server
    pub fn stop(self: *ZnsGrpcServer) void {
        std.log.info("Stopping ZNS gRPC server", .{});
    }
    
    /// Handle resolve domain request
    pub fn handleResolveDomain(self: *ZnsGrpcServer, request_data: []const u8) ![]u8 {
        // Parse request from gRPC data
        const request = try self.parseResolveRequest(request_data);
        
        // Process request
        const response = try self.service.resolveDomain(request);
        defer response.deinit(self.allocator);
        
        // Serialize response
        return self.serializeResolveResponse(response);
    }
    
    /// Handle register domain request
    pub fn handleRegisterDomain(self: *ZnsGrpcServer, request_data: []const u8) ![]u8 {
        // Parse request from gRPC data
        const request = try self.parseRegisterRequest(request_data);
        
        // Process request
        const response = try self.service.registerDomain(request);
        
        // Serialize response
        return self.serializeRegisterResponse(response);
    }
    
    /// Parse resolve request from gRPC data
    fn parseResolveRequest(self: *ZnsGrpcServer, data: []const u8) !ZnsResolveRequest {
        // Simple JSON parsing for now
        var domain: []const u8 = "";
        var record_types = std.ArrayList(dns_record.DnsRecordType).init(self.allocator);
        defer record_types.deinit();
        
        // Extract domain
        if (std.mem.indexOf(u8, data, "\"domain\":\"")) |start| {
            const domain_start = start + 10;
            if (std.mem.indexOf(u8, data[domain_start..], "\"")) |end| {
                domain = data[domain_start..domain_start + end];
            }
        }
        
        // Default to requesting all record types
        try record_types.append(.A);
        try record_types.append(.CRYPTO);
        
        return ZnsResolveRequest{
            .domain = domain,
            .record_types = try record_types.toOwnedSlice(),
            .include_metadata = true,
        };
    }
    
    /// Parse register request from gRPC data
    fn parseRegisterRequest(self: *ZnsGrpcServer, data: []const u8) !ZnsRegisterRequest {
        // Mock parsing for now
        return ZnsRegisterRequest{
            .domain = "example.ghost",
            .owner = "ghost1owner123456789abcdef",
            .records = &.{},
            .ttl = 3600,
            .signature = "0x123456789abcdef",
        };
    }
    
    /// Serialize resolve response to gRPC data
    fn serializeResolveResponse(self: *ZnsGrpcServer, response: ZnsResolveResponse) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{
            \\  "domain": "{s}",
            \\  "records": [],
            \\  "ttl": {d}
            \\}}
        , .{ response.domain, response.ttl });
    }
    
    /// Serialize register response to gRPC data
    fn serializeRegisterResponse(self: *ZnsGrpcServer, response: ZnsRegisterResponse) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{
            \\  "domain": "{s}",
            \\  "transaction_hash": "{s}",
            \\  "status": "pending"
            \\}}
        , .{ response.domain, response.transaction_hash });
    }
};

test "ZNS service domain resolution" {
    const allocator = std.testing.allocator;
    
    var service = try ZnsService.init(allocator, 100, "localhost:50051");
    defer service.deinit();
    
    const request = ZnsResolveRequest{
        .domain = "test.ghost",
        .record_types = &.{.A, .CRYPTO},
        .include_metadata = true,
    };
    
    var response = try service.resolveDomain(request);
    defer response.deinit(allocator);
    
    try std.testing.expect(std.mem.eql(u8, response.domain, "test.ghost"));
    try std.testing.expect(response.records.len > 0);
}

test "ZNS service cache statistics" {
    const allocator = std.testing.allocator;
    
    var service = try ZnsService.init(allocator, 100, "localhost:50051");
    defer service.deinit();
    
    const stats = service.getServiceStats();
    try std.testing.expect(stats.cache_stats.capacity == 100);
    try std.testing.expect(stats.cache_stats.size == 0);
}