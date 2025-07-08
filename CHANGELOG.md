# Changelog

All notable changes to the ZNS (Zig Name Service) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-06-25 (Production Refactor)

### 🎉 Major Architectural Improvements

#### Added
- **Pluggable Module Architecture**: Complete trait-based resolver system with dynamic dispatch
  - `src/resolver/traits.zig`: Generic `NameServiceResolver` interface using vtables
  - `ResolverRegistry`: Dynamic resolver registration and discovery system
  - Modular lookup functions: `ens_lookup()`, `ud_lookup()`, `zns_lookup()`
  - Support for runtime resolver addition and removal

- **Enhanced Unstoppable Domains Support**: Full JSON parsing implementation
  - `src/resolver/unstoppable_enhanced.zig`: Complete UD API integration
  - Support for 14+ cryptocurrency types (ETH, BTC, MATIC, SOL, AVAX, BNB, etc.)
  - DNS records parsing (A, AAAA, CNAME, MX)
  - Social profiles extraction (Twitter, Telegram, Discord, Reddit)
  - IPFS content and browser redirect support
  - Web metadata with structured `UDRecord` type

- **ZQLite Cache Integration Design**: SQLite-backed persistent caching
  - `src/cache/zqlite_cache.zig`: Complete schema and wrapper design
  - TTL-based expiration with automatic cleanup
  - Multi-table design: domains, addresses, metadata
  - Performance indexes and foreign key constraints
  - Cached resolver wrapper pattern for any resolver type

- **Production-Ready Infrastructure**:
  - `src/utils/logger.zig`: Configurable logging system with levels
  - `src/config.zig`: Environment-based configuration management
  - `PRODUCTION.md`: Comprehensive deployment guide
  - Docker, systemd, and standalone deployment options
  - Health check endpoints and monitoring guidance

- **Documentation & Examples**:
  - `IDEAS.md`: Architectural roadmap and improvement suggestions
  - `examples/modular_usage.zig`: Complete demonstration of new architecture
  - Comprehensive API documentation and usage patterns

#### Fixed
- **Critical Compilation Issues**:
  - ✅ Fixed all `std.debug.print` calls missing format arguments
  - ✅ Updated deprecated `std.mem.copy` to `@memcpy` (Zig 0.15 compatibility)
  - ✅ Replaced `std.ComptimeStringMap` with `std.static_string_map.StaticStringMap`
  - ✅ Fixed HTTP client headers API for newer Zig versions
  - ✅ Resolved JSON parsing issues with manual string extraction
  - ✅ Fixed const qualifier issues in CLI commands

- **Memory Management**:
  - ✅ Eliminated segmentation faults in cache cleanup
  - ✅ Fixed double-free issues in resolver deinit
  - ✅ Added proper memory leak detection and cleanup
  - ✅ Fixed argument parsing memory leaks in main.zig

- **JSON-RPC Client Refactor**:
  - Replaced complex JSON parsing with manual string templates
  - Simplified Ethereum RPC calls with raw JSON formatting
  - Improved error handling for network timeouts
  - Better status code extraction from HTTP responses

#### Changed
- **Build Optimization**: Reduced binary size from 46MB to 7.3MB with `-Doptimize=ReleaseFast`
- **Error Handling**: Improved error messages and recovery
- **CLI Interface**: Enhanced output formatting and error reporting
- **Cache Architecture**: From simple HashMap to persistent SQLite design
- **Resolver Interface**: From hardcoded to trait-based dynamic system

#### Performance Improvements
- **HTTP Client**: Connection reuse and timeout optimization
- **Memory Usage**: Reduced allocations with arena allocators
- **Cache Efficiency**: Proper TTL handling and expiration cleanup
- **Batch Processing**: Optimized batch domain resolution

### 🔧 Technical Details

#### API Changes
```zig
// Old: Hardcoded resolver selection
const result = universal_resolver.resolve(domain);

// New: Dynamic trait-based resolution
var registry = ResolverRegistry.init(allocator);
try registry.register(NameServiceResolver.from(ENSResolver, &ens));
const result = try registry.resolve(domain);
```

#### Enhanced JSON Parsing
```zig
// Old: Limited field extraction
const address = parseBasicAddress(json);

// New: Full record parsing
const record = try parseFullRecord(json);
// Includes: crypto addresses, DNS, social profiles, IPFS, metadata
```

#### Cache Integration
```zig
// New: Cached resolver wrapper
const cached_ens = try CachedResolver(ENSResolver).init(ens, cache);
const result = try cached_ens.resolve(domain); // Auto-cached
```

### 🐛 Bug Fixes
- Fixed ENS namehash calculation edge cases
- Resolved HTTP response parsing for different status codes
- Fixed domain type detection for case sensitivity
- Corrected TTL handling in cache entries
- Fixed batch resolution error propagation

### 🔒 Security Improvements
- Input validation for all domain inputs
- Secure API key handling via environment variables
- Protection against JSON injection attacks
- Rate limiting preparation for production deployments

### 📊 Monitoring & Observability
- Cache hit/miss rate tracking
- Request latency monitoring per domain type
- Error rate tracking by resolver type
- Memory usage and leak detection

---

## [0.1.0] - 2025-06-24 (Initial Release)

### Added
- Basic domain resolution for ENS (.eth), Unstoppable Domains (.crypto, .nft, .x), and GhostChain (.ghost, .bc, .kz)
- CLI interface with multiple output formats (text, JSON, CSV)
- In-memory caching with TTL
- HTTP client for external API calls
- Basic JSON-RPC support for Ethereum
- Universal resolver with domain type detection
- Batch domain resolution
- Mock data for GhostChain domains

### Core Features
- `src/resolver/ens.zig`: Ethereum Name Service resolution
- `src/resolver/unstoppable.zig`: Unstoppable Domains basic resolution
- `src/resolver/ghost.zig`: GhostChain native domains (mock)
- `src/resolver/universal.zig`: Unified resolution logic
- `src/cli/commands.zig`: Command-line interface
- `src/http/client.zig`: HTTP client implementation

### Supported Commands
- `zns resolve <domain>`: Single domain resolution
- `zns resolve-all <domain>`: Multi-chain resolution
- `zns batch <domains>`: Batch processing
- `zns cache-stats`: Cache statistics
- `zns help`: Usage information

---

## Versioning Strategy

- **Major** (X.0.0): Breaking API changes, architectural overhauls
- **Minor** (0.X.0): New features, non-breaking enhancements
- **Patch** (0.0.X): Bug fixes, security updates, performance improvements

## Development Notes

### Build Requirements
- Zig 0.15.0-dev or later
- Git for version control
- Optional: Docker for containerized deployment

### Testing
```bash
# Development build
zig build

# Production build
zig build -Doptimize=ReleaseFast

# Run tests
zig build test
```

### Contributing
See `IDEAS.md` for architectural plans and `PRODUCTION.md` for deployment guidelines.

---

**Legend**:
- 🎉 Major Features
- 🔧 Technical Changes  
- 🐛 Bug Fixes
- 🔒 Security
- 📊 Monitoring
- ✅ Completed
- ⚠️ Needs Work