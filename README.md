# ZNS - Universal Crypto Domain Resolver

![ENS Compatible](https://img.shields.io/badge/Compatible-ENS-blueviolet)
![Unstoppable Domains](https://img.shields.io/badge/Web3-Unstoppable%20Domains-purple)
![Web3 Native](https://img.shields.io/badge/Web5-Universal%20Resolver-brightgreen)

## 🌐 Universal Crypto Domain Resolution

**ZNS** is the next-generation DNS resolver that bridges Web2 and Web3 by providing universal resolution for **ALL** crypto domains. It supports ENS, Unstoppable Domains, and native GhostChain domains in a single, fast, and secure resolver.

---

## 🌟 Features

### Universal Domain Resolution
- **ENS (.eth)** - Direct Ethereum RPC resolution with namehash calculation
- **Unstoppable Domains** - (.crypto, .nft, .x, .wallet, .bitcoin, .dao, etc.)
- **GhostChain Native** - (.ghost, .bc, .kz, .zkellz) via GhostBridge
- **Traditional DNS** - Fallback for .com, .org, etc.

### Performance & Caching
- **In-memory caching** with TTL-based expiration
- **Parallel resolution** for batch requests
- **Sub-millisecond** resolution for cached entries
- **Configurable cache** management

### Multi-chain Support
- **Ethereum** (ETH, ERC-20 tokens)
- **Bitcoin** (BTC)
- **Polygon** (MATIC)
- **Solana** (SOL)
- **GhostChain** (GCC)
- **Many more** blockchain networks

### ZWallet Integration
- **Domain-based transfers** - Send crypto to alice.eth instead of 0x1234...
- **Multi-chain resolution** - Automatically detect best chain for transfer
- **Transaction validation** - Verify addresses and estimate fees
- **Batch processing** - Resolve multiple domains at once

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ghostkellz/zns
cd zns

# Build the project
zig build

# Install globally (optional)
sudo cp zig-out/bin/zns /usr/local/bin/
```

### Basic Usage

```bash
# Resolve ENS domain
zns resolve alice.eth

# Resolve Unstoppable Domain
zns resolve vault.crypto

# Resolve GhostChain domain
zns resolve ghostkellz.ghost

# Get all crypto addresses for a domain
zns resolve-all alice.crypto

# Batch resolve multiple domains
zns batch alice.eth,vault.crypto,ghostkellz.ghost

# JSON output
zns resolve alice.eth --format json

# CSV output for data processing
zns resolve-all alice.crypto --format csv
```

### Advanced Usage

```bash
# Use custom Ethereum RPC
zns resolve alice.eth --ethereum-rpc https://mainnet.infura.io/v3/YOUR_KEY

# Use Unstoppable Domains API key
zns resolve vault.crypto --unstoppable-key YOUR_API_KEY

# Custom GhostBridge endpoint
zns resolve ghostkellz.ghost --ghostbridge http://localhost:9090

# Cache management
zns cache-stats
zns cache-clear
```

---

## 📚 Library Usage

### Zig Integration

```zig
const std = @import("std");
const zns = @import("zns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize universal resolver
    var resolver = zns.UniversalResolver.init(
        allocator,
        "http://localhost:9090",     // GhostBridge
        "https://eth-mainnet.alchemyapi.io/v2/demo", // Ethereum RPC
        null, // Unstoppable API key
    );
    defer resolver.deinit();
    
    // Resolve domain
    const result = try resolver.resolve("alice.eth");
    defer result.deinit(allocator);
    
    std.debug.print("Domain: {s}\n", .{result.domain});
    std.debug.print("Chain: {s}\n", .{@tagName(result.chain)});
    std.debug.print("Address: {s}\n", .{result.address});
}
```

### ZWallet Integration

```zig
const zns = @import("zns");

// Initialize ZWallet integration
var wallet_integration = zns.zwallet.integration.ZWalletIntegration.init(
    allocator,
    "http://localhost:9090",
    "https://eth-mainnet.alchemyapi.io/v2/demo",
    null,
);
defer wallet_integration.deinit();

// Send to domain instead of address
try zns.zwallet.integration.ZWalletCommands.sendToDomain(
    allocator,
    "alice.eth",      // Domain to resolve
    1.5,              // Amount
    "ETH",            // Token
    &wallet_integration,
);
```

---

## 🏗️ Architecture

### Universal Resolver Flow

```
Domain Input (alice.eth)
    ↓
TLD Detection (.eth)
    ↓
Route to ENS Resolver
    ↓
Ethereum RPC Call
    ↓
Namehash Calculation
    ↓
Contract Query
    ↓
Address Resolution
    ↓
Cache & Return
```

### Supported Domain Types

| Domain Type | TLDs | Resolution Method | Example |
|-------------|------|-------------------|---------|
| ENS | .eth | Ethereum RPC + Namehash | alice.eth |
| Unstoppable | .crypto, .nft, .x, .wallet | HTTPS API | vault.crypto |
| GhostChain | .ghost, .bc, .kz | gRPC GhostBridge | ghostkellz.ghost |
| Traditional | .com, .org, .net | DNS TXT Records | example.com |

### Module Structure

```
zns/
├── resolver/           # Core resolution logic
│   ├── types.zig      # Common types and enums
│   ├── universal.zig  # Universal resolver
│   ├── ens.zig        # ENS resolution
│   ├── unstoppable.zig # Unstoppable Domains
│   └── ghost.zig      # GhostChain native domains
├── http/              # HTTP client utilities
│   └── client.zig     # HTTP/JSON-RPC client
├── cli/               # Command-line interface
│   └── commands.zig   # CLI commands and parsing
└── zwallet/           # ZWallet integration
    └── integration.zig # Domain-based transactions
```

---

## 🧪 Testing

```bash
# Run all tests
zig build test

# Run specific test
zig test src/resolver/ens.zig

# Run with coverage
zig build test --summary all

# Fuzz testing
zig build test --fuzz
```

### Integration Tests

```bash
# Test with live networks (requires internet)
ZNS_LIVE_TEST=1 zig build test

# Test ENS resolution
zns resolve vitalik.eth

# Test Unstoppable Domains
zns resolve brad.crypto

# Test batch resolution
zns batch vitalik.eth,brad.crypto
```

---

## 📊 Performance

### Benchmarks

| Operation | Time | Throughput |
|-----------|------|------------|
| Cached resolution | <1ms | 10,000+ req/s |
| ENS resolution | 50-200ms | 100-500 req/s |
| Unstoppable API | 100-300ms | 50-200 req/s |
| Batch resolution (10 domains) | 200-500ms | 200-500 domains/s |

---

## 🧬 License

MIT License © CK Technology LLC 2025

---

**ZNS - Bridging Web2 and Web3 through Universal Domain Resolution** 🌐✨

