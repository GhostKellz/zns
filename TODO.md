# 🎯 ZNS TODO - Updated Based on GhostChain Ecosystem Analysis

*Updated: July 4, 2025*  
*Context: Full GhostChain ecosystem integration with ZQUIC, zcrypto v0.5.0, and production deployment*

---

## 🚨 **CRITICAL PRIORITIES (Next 1-2 weeks)**

### **1. ZQUIC Integration for ZNS** ⚡ URGENT
**Priority: CRITICAL - Required for GhostChain ecosystem alignment**

```zig
// Current: HTTP-based resolution
// Target: ZQUIC-based DNS-over-QUIC

// Replace src/http/client.zig with ZQUIC integration
const zquic = @import("zquic");

pub const QuicDnsResolver = struct {
    zquic_client: zquic.ZQuic,
    
    pub fn resolve(self: *QuicDnsResolver, domain: []const u8) !types.CryptoAddress {
        // Use zquic_dns_query from FFI layer
        const response = try self.zquic_client.dns_query(domain, "A");
        return types.CryptoAddress.init(allocator, domain, .ghostchain, response.address);
    }
};
```

**Tasks:**
- [ ] Replace HTTP client with ZQUIC DNS-over-QUIC client
- [ ] Integrate with existing CNS/ZNS FFI functions from ZQUIC
- [ ] Update universal resolver to use QUIC transport
- [ ] Add QUIC-based DNS record caching
- [ ] Update CLI to support QUIC endpoints
- [ ] Test with real GhostBridge QUIC endpoint

**Expected Impact:** ZNS becomes part of the production ZQUIC ecosystem

### **2. zcrypto v0.5.0 Integration** 🔐 HIGH PRIORITY
**Context: zcrypto is production-ready with post-quantum crypto**

```zig
// Replace placeholder crypto verification with real zcrypto
const zcrypto = @import("zcrypto");

pub fn verifyZNSRecord(record: types.ZNSRecord) !bool {
    const signable_data = try record.getSignableData(allocator);
    defer allocator.free(signable_data);
    
    // Use real Ed25519 verification
    return zcrypto.asym.ed25519.verify(
        signable_data, 
        record.signature, 
        record.owner_pubkey
    );
}

// Add post-quantum signature support for future-proofing
pub fn verifyHybridSignature(record: types.ZNSRecord) !bool {
    // Classical verification
    const classic_valid = try verifyZNSRecord(record);
    
    // Post-quantum verification (when available)
    if (record.pq_signature) |pq_sig| {
        const pq_valid = zcrypto.pq.ml_dsa.ML_DSA_65.verify(
            signable_data,
            pq_sig,
            record.pq_pubkey.?
        );
        return classic_valid and pq_valid;
    }
    
    return classic_valid;
}
```

**Tasks:**
- [ ] Replace mock signature verification in `src/resolver/types.zig`
- [ ] Add Ed25519 keypair generation for domain registration
- [ ] Implement post-quantum signature support for future domains
- [ ] Add cryptographic domain ownership verification
- [ ] Update ZNS record format for hybrid signatures
- [ ] Add secure key derivation for subdomain management

### **3. Real GhostBridge gRPC-over-QUIC Integration** 🌉 HIGH PRIORITY
**Context: GhostBridge FFI layer is complete and production-ready**

```zig
// Replace mock Ghost domain resolution
pub const QuicGhostResolver = struct {
    zquic_client: zquic.ZQuic,
    ghostbridge_endpoint: []const u8,
    
    pub fn resolve(self: *QuicGhostResolver, domain: []const u8) !types.CryptoAddress {
        // Use real gRPC-over-QUIC call
        const request = std.fmt.allocPrint(allocator, 
            "{{\"domain\": \"{s}\"}}", .{domain});
        defer allocator.free(request);
        
        const response = try self.zquic_client.grpc_call(
            "ghost.zns.ZNSService/ResolveDomain",
            request
        );
        defer allocator.free(response);
        
        // Parse JSON response
        return parseGhostResponse(domain, response);
    }
};
```

**Tasks:**
- [ ] Replace mock implementation in `src/resolver/ghost.zig`
- [ ] Integrate with ZQUIC gRPC-over-QUIC client
- [ ] Add proper JSON-RPC parsing for GhostBridge responses
- [ ] Implement domain registration via GhostBridge
- [ ] Add subscription support for domain change notifications
- [ ] Test with live GhostBridge endpoint

**Expected Impact:** ZNS becomes a real production resolver for .ghost domains

---

## 🔥 **HIGH PRIORITY (Next month)**

### **4. Enhanced Multi-Chain Domain Resolution** 🌐
**Context: ZNS needs to be the universal resolver for entire GhostChain ecosystem**

**ENS Integration via ZQUIC:**
```zig
// Replace HTTP-based ENS with QUIC-based resolution
pub const QuicENSResolver = struct {
    zquic_client: zquic.ZQuic,
    ethereum_endpoint: []const u8, // QUIC-enabled Ethereum RPC
    
    pub fn resolve(self: *QuicENSResolver, domain: []const u8) !types.CryptoAddress {
        const namehash = try self.calculateNamehash(domain);
        defer allocator.free(namehash);
        
        // Use QUIC for Ethereum RPC calls instead of HTTP
        const call_data = try self.buildENSCallData(namehash);
        const response = try self.zquic_client.send_data(self.ethereum_endpoint, call_data);
        
        return parseETHResponse(domain, response);
    }
};
```

**Tasks:**
- [ ] Update ENS resolver to use QUIC transport
- [ ] Add support for additional blockchain networks (Polygon, Arbitrum, etc.)
- [ ] Implement cross-chain domain resolution
- [ ] Add domain metadata caching across chains
- [ ] Support for decentralized storage (IPFS) content resolution

### **5. ZWallet Domain-Based Transaction Integration** 💸
**Context: ZWallet integration is critical for user adoption**

```zig
// Enhanced domain-based transaction support
pub const DomainTransactionManager = struct {
    zns_resolver: universal.UniversalResolver,
    crypto_signer: zcrypto.asym.Ed25519KeyPair,
    
    pub fn sendToDomain(
        self: *DomainTransactionManager,
        to_domain: []const u8,
        amount: f64,
        token: []const u8,
        chain_preference: ?types.ChainType,
    ) !TransactionResult {
        // Resolve domain to address
        const resolved = try self.zns_resolver.resolve(to_domain);
        defer resolved.deinit(allocator);
        
        // Validate chain compatibility
        const target_chain = chain_preference orelse resolved.chain;
        if (target_chain != resolved.chain) {
            return error.ChainMismatch;
        }
        
        // Create and sign transaction
        const tx = try self.createTransaction(resolved.address, amount, token, target_chain);
        const signature = try self.crypto_signer.sign(tx.hash);
        
        return TransactionResult{
            .tx_hash = tx.hash,
            .resolved_address = resolved.address,
            .chain = target_chain,
            .signature = signature,
        };
    }
};
```

**Tasks:**
- [ ] Enhance `src/zwallet/integration.zig` with multi-chain support
- [ ] Add transaction fee estimation for resolved domains
- [ ] Implement address validation before transaction creation
- [ ] Add batch domain resolution for multiple recipients
- [ ] Support for smart contract interaction via domains

### **6. SQLite Persistent Cache (ZQLite Integration)** 🗄️
**Context: Production deployments need persistent caching**

```sql
-- Enhanced cache schema
CREATE TABLE domains (
    id INTEGER PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    resolver_type TEXT NOT NULL,
    last_resolved INTEGER NOT NULL,
    ttl INTEGER NOT NULL,
    signature_verified BOOLEAN DEFAULT FALSE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE domain_records (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id),
    chain_type TEXT NOT NULL,
    address TEXT NOT NULL,
    metadata TEXT, -- JSON metadata
    signature BLOB, -- Cryptographic signature
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_domains_domain ON domains(domain);
CREATE INDEX idx_records_domain_chain ON domain_records(domain_id, chain_type);
CREATE INDEX idx_records_expires ON domain_records(expires_at);
```

**Tasks:**
- [ ] Replace in-memory cache with SQLite backend
- [ ] Add cache statistics and analytics
- [ ] Implement cache cleanup and expiration
- [ ] Add signature verification caching
- [ ] Support for batch cache operations

---

## 🎯 **MEDIUM PRIORITY (Next 2-3 months)**

### **7. Plugin Architecture for Extensible Resolvers** 🔌
**Implementation from IDEAS.md:**

```zig
// Trait-based resolver system with dynamic dispatch
pub const NameServiceResolver = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    
    const VTable = struct {
        resolve: *const fn (*anyopaque, []const u8) anyerror!types.CryptoAddress,
        resolveAll: *const fn (*anyopaque, []const u8) anyerror![]types.CryptoAddress,
        supports: *const fn ([]const u8) bool,
        getMetadata: *const fn (*anyopaque, []const u8) anyerror![]const u8,
    };
};

pub const ResolverRegistry = struct {
    resolvers: std.ArrayList(NameServiceResolver),
    
    pub fn register(self: *ResolverRegistry, resolver: NameServiceResolver) !void {
        try self.resolvers.append(resolver);
    }
    
    pub fn resolve(self: *ResolverRegistry, domain: []const u8) !types.CryptoAddress {
        for (self.resolvers.items) |resolver| {
            if (resolver.vtable.supports(domain)) {
                return resolver.vtable.resolve(resolver.ptr, domain);
            }
        }
        return error.UnsupportedDomain;
    }
};
```

**Tasks:**
- [ ] Implement dynamic resolver registration system
- [ ] Add support for custom domain TLDs
- [ ] Create resolver plugin API
- [ ] Support for Handshake domains (.bit, etc.)
- [ ] Add traditional DNS fallback resolver

### **8. Production Deployment Features** 🚀
**Context: Production readiness for GhostChain mainnet**

**Tasks:**
- [ ] Add comprehensive error handling and recovery
- [ ] Implement rate limiting and DDoS protection
- [ ] Add monitoring and observability (metrics, traces)
- [ ] Create health check endpoints
- [ ] Add configuration management via environment variables
- [ ] Implement graceful shutdown and restart
- [ ] Add logging and audit trails
- [ ] Create deployment automation (Docker, Kubernetes)

### **9. Advanced DNS Features** 🌐
**Context: Complete DNS-over-QUIC implementation**

**Tasks:**
- [ ] Support for all DNS record types (MX, CNAME, SRV, etc.)
- [ ] DNSSEC validation for traditional domains
- [ ] DNS caching with TTL respect
- [ ] Recursive DNS resolution
- [ ] DNS-over-HTTPS (DoH) fallback
- [ ] IPv6 support for all operations

---

## 🔮 **FUTURE ENHANCEMENTS (3+ months)**

### **10. Web3 Ecosystem Integration** 🕸️
- [ ] IPFS content resolution for decentralized websites
- [ ] DID (Decentralized Identity) support
- [ ] zkLogin and self-sovereign identity features
- [ ] Cross-chain bridge integrations
- [ ] NFT metadata resolution

### **11. Advanced Cryptographic Features** 🔐
- [ ] Multi-signature domain ownership
- [ ] Domain transfer and escrow systems
- [ ] Subdomain delegation and management
- [ ] Threshold signature schemes
- [ ] Zero-knowledge proof verification

### **12. Performance & Scalability** ⚡
- [ ] Horizontal scaling with load balancing
- [ ] CDN integration for global resolution
- [ ] Edge computing deployment
- [ ] Advanced caching strategies (Redis, distributed cache)
- [ ] Connection pooling and multiplexing optimization

---

## 📊 **SUCCESS METRICS**

### **Technical Metrics**
- [ ] **Resolution Speed**: <10ms for cached, <100ms for live resolution
- [ ] **Throughput**: 10,000+ resolutions per second
- [ ] **Availability**: 99.9% uptime
- [ ] **Cache Hit Rate**: >85% for production traffic
- [ ] **Memory Usage**: <512MB for production deployment

### **Integration Metrics**
- [ ] **Domain Coverage**: Support for .ghost, .eth, .crypto, .nft, .x, .com
- [ ] **Blockchain Support**: 10+ blockchain networks
- [ ] **Security**: 100% signature verification for cryptographic domains
- [ ] **Ecosystem Integration**: Used by all GhostChain services

### **Production Readiness**
- [ ] **Security Audit**: Complete security review and penetration testing
- [ ] **Performance Testing**: Load testing under realistic conditions
- [ ] **Documentation**: Complete API and integration documentation
- [ ] **Monitoring**: Comprehensive observability and alerting

---

## 🔧 **IMPLEMENTATION NOTES**

### **Dependencies**
- **zcrypto v0.5.0**: Production-ready post-quantum crypto
- **zquic v0.3.0**: QUIC transport with FFI layer
- **TokioZ**: Async runtime for performance
- **SQLite**: Persistent caching backend

### **Integration Points**
- **GhostBridge**: gRPC-over-QUIC for .ghost domain resolution
- **ZWallet**: Domain-based transaction support
- **Wraith Proxy**: DNS-over-QUIC proxy integration
- **CNS System**: Native .zns domain registration and management

### **Breaking Changes**
- HTTP client replacement with QUIC transport
- New ZNS record format with hybrid signatures
- Updated cache schema for persistent storage
- Enhanced error handling and recovery

This TODO represents ZNS evolution from a proof-of-concept to a production-ready component of the GhostChain ecosystem, fully integrated with ZQUIC transport and zcrypto security.


### **INTERNAL NAME SERVICE - ENS + unstoppable domains 

The internal name service. This remains chain-native, and only understands .ghost, .gcc, .key, etc.

    Why: It’s your on-chain registry and contract layer.

    Responsibilities:

        Store and serve native ZNS records

        Issue .ghost/.key/.pin domains

        Optionally mirror verified .eth/.crypto into .ghost aliases (with signature proof)

📁 zns/contracts/zns.zig
📁 zns/lib/zns_utils.zig
📁 zns/handlers/imports/ens_mirror.zig