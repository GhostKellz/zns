# ZNS Production Deployment Guide

## Overview
ZNS (Zig Name Service) is a universal crypto domain resolver supporting ENS, Unstoppable Domains, and GhostChain native domains.

## Building for Production

### Prerequisites
- Zig 0.15.0-dev or later
- Git

### Build Commands
```bash
# Development build
zig build

# Release build (optimized)
zig build -Doptimize=ReleaseFast

# Release build with safety checks
zig build -Doptimize=ReleaseSafe

# Smallest binary size
zig build -Doptimize=ReleaseSmall
```

## Configuration

### Environment Variables
```bash
# Ethereum RPC endpoint (required for ENS)
export ZNS_ETHEREUM_RPC="https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY"

# GhostBridge endpoint (required for Ghost domains)
export ZNS_GHOSTBRIDGE_ENDPOINT="http://ghostbridge.example.com:9090"

# Unstoppable Domains API key (optional, improves rate limits)
export ZNS_UNSTOPPABLE_API_KEY="your-api-key"

# Cache configuration
export ZNS_CACHE_SIZE=10000
export ZNS_CACHE_TTL=600  # 10 minutes

# Network timeout
export ZNS_TIMEOUT_MS=30000  # 30 seconds

# Log level (debug, info, warn, error)
export ZNS_LOG_LEVEL=info
```

## Deployment Options

### 1. Standalone Binary
```bash
# Build release binary
zig build -Doptimize=ReleaseFast

# Copy to production location
cp zig-out/bin/zns /usr/local/bin/

# Make executable
chmod +x /usr/local/bin/zns
```

### 2. Docker Container
```dockerfile
FROM alpine:latest

# Install required runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy binary
COPY zig-out/bin/zns /usr/local/bin/zns

# Create non-root user
RUN adduser -D -s /bin/sh zns
USER zns

ENTRYPOINT ["/usr/local/bin/zns"]
```

### 3. Systemd Service
```ini
[Unit]
Description=ZNS Universal Domain Resolver
After=network.target

[Service]
Type=simple
User=zns
Group=zns
ExecStart=/usr/local/bin/zns server
Restart=always
RestartSec=10

# Environment
Environment="ZNS_ETHEREUM_RPC=https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY"
Environment="ZNS_LOG_LEVEL=info"

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

## Performance Tuning

### Cache Settings
- Increase `ZNS_CACHE_SIZE` for high-traffic deployments
- Adjust `ZNS_CACHE_TTL` based on your consistency requirements
- Monitor cache hit rates for optimization

### Network Settings
- Use local Ethereum nodes for better performance
- Deploy GhostBridge close to ZNS for low latency
- Consider using connection pooling for HTTP clients

## Monitoring

### Health Check Endpoint
```bash
# Check service health
zns health

# Expected output:
# {
#   "status": "healthy",
#   "version": "0.1.0",
#   "uptime": 3600,
#   "cache_stats": {
#     "total_entries": 1523,
#     "hit_rate": 0.85
#   }
# }
```

### Metrics
- Request latency per domain type
- Cache hit/miss rates
- Error rates by type
- Upstream service availability

## Security Considerations

1. **API Keys**: Store sensitive keys in environment variables or secure vaults
2. **Network**: Use HTTPS for all external connections
3. **Rate Limiting**: Implement rate limiting for public deployments
4. **Input Validation**: All domain inputs are validated before processing

## Troubleshooting

### Common Issues

1. **Domain Not Found**
   - Check network connectivity to resolver services
   - Verify API keys are correct
   - Ensure domain is registered

2. **Timeout Errors**
   - Increase `ZNS_TIMEOUT_MS`
   - Check upstream service status
   - Verify network latency

3. **Memory Issues**
   - Reduce `ZNS_CACHE_SIZE`
   - Monitor memory usage
   - Consider using external cache (Redis)

## Future Enhancements

1. **gRPC Support**: Native gRPC client for GhostBridge
2. **Batch Processing**: Improved batch resolution performance
3. **Metrics Export**: Prometheus/OpenTelemetry support
4. **Web API**: REST/GraphQL API server mode
5. **Plugin System**: Extensible resolver architecture