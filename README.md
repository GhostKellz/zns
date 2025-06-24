# ZNS — GhostChain On-Chain Name Service

![ENS Compatible](https://img.shields.io/badge/Compatible-ENS-blueviolet)
![Unstoppable Domains](https://img.shields.io/badge/Web3-Unstoppable%20Domains-purple)
![Web3 Native](https://img.shields.io/badge/Web3-Native%20Name%20Service-brightgreen)

## 🌐 Zig Name Service (ZNS)

**ZNS** is the native on-chain name service for [GhostChain](https://ghostchain.io), written entirely in Zig and integrated with the GhostChain ecosystem via `zvm`.

---

### 🔥 Key Features

* 📛 **Web3-Native Identity** — Fully replaces or extends ENS and Unstoppable Domains
* 🔗 **Zig Smart Contracts** — Powered by `zvm`, deployed on GhostChain
* 🌍 **Custom TLDs** — Supports `.ghost`, `.zkellz`, `.kz`, and more
* 🚀 **HTTP/3 + QUIC Ready** — Native IPv6, UDP multiplexing, and TLS 1.3
* 🔐 **Ownership & Identity Resolution** — Signed entries backed by `zsig` and `zwallet`

---

### 🧠 Architecture

* `zns-core.zig` — Registry logic (registration, transfers, ownership)
* `resolver.zig` — Off-chain & on-chain resolver with QUIC/DoQ/HTTP3 interfaces
* `contracts/` — Smart contracts deployed to GhostChain with `zvm`
* `zns-cli.zig` — CLI tool to register and manage names

---

### 📦 Integrated With

* ✅ `zsig` — For domain ownership signature verification
* ✅ `zwallet` — Pay for domain registration, transfers, and renewals
* ✅ `zvm` — Contract execution engine for all resolution and mutation
* ✅ `ghostchain` — Native blockchain and ledger backend

---

### 🔮 Roadmap

* [x] Domain registration and transfer support
* [x] Ownership resolution smart contract
* [x] CLI tooling
* [ ] QUIC + HTTP/3 resolver server
* [ ] DNS-over-QUIC support
* [ ] Browser extension support for `.ghost`, `.kz`, `.zkellz`

---

### 📜 Example

```bash
zns-cli register chris.ghost --wallet ckellz
zns-cli resolve chris.ghost
zns-cli transfer chris.ghost --to wallet123
```

---

### 🧬 License

MIT License © CK Technology LLC 2025

