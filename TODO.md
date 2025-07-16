# 🌐 TODO: Modern Refactor for Ghostchain

> ZNS (Ghost Name Service) is the decentralized identity and resolution layer for Ghostchain.  
> This release refactors ZNS to remove legacy dependencies and align with the new Ghoststack foundations.

---

## 🧱 Core Role

ZNS provides:
- Domain-to-address mappings (name → wallet/pubkey/contract)
- Reverse resolution (address → name/metadata)
- Text record storage
- Token ownership + delegation (optional)
- CLI and API resolution support

---

## 🔥 Dependency Cleanup

| Dependency     | Status           | Replacement / Status            |
|----------------|------------------|---------------------------------|
| `shroud`       | ❌ Removed        | ✅ Replaced with internal logic or `zcrypto` |
| `tokioZ`       | ❌ Removed        | ✅ Replaced by `zsync`           |
| `zqlite`       | ✅ Retained       | No longer requires Shroud       |
| `zcrypto`      | ✅ Optional       | Used for hashing / signing      |
| `zsync`        | ✅ Required       | Used for async fetch / sync     |

---

## 🔧 Refactor Tasks

- [ ] 🔥 Remove all `@import("shroud")` logic (identity, policy, tokens)
- [ ] 🔥 Remove `@import("tokioZ")` and replace with `zsync` primitives
- [ ] ✅ Upgrade `zqlite` to v1.2.0 (dependency-free core)
- [ ] ✅ Replace token delegation with signature verification (via `zcrypto`)
- [ ] 🔁 Refactor identity resolution to raw string-based names or pubkeys

---

## 📦 Module Rework Plan


---

## 🧪 Tests

- [ ] Lookup: domain → address
- [ ] Lookup: address → domain
- [ ] Signature verification for record updates
- [ ] Conflict resolution (overwrite protection)
- [ ] TTL expiration and async refresh
- [ ] ENS compatibility tests (namehash, keccak labels, etc.)

---

## ⚙️ Optional Features

- [ ] Enable `zcrypto` if signature support needed
- [ ] Enable record expiry (auto-prune)
- [ ] Enable ZNS indexing via `zsync` pull model

---

## 🚫 Legacy Logic Removed

- ❌ Shroud identity DIDs
- ❌ Shroud access tokens
- ❌ TokioZ futures/awaits
- ❌ Shroud guardian validation

---

## 🧠 Guiding Principles

> ZNS is lightweight, verifiable, and Ghostchain-native.  
> It serves as the public DNS, identity map, and record index for decentralized identities and contracts.

---

## 🎯 Milestone: ZNS v0.3.0

- [ ] Fully migrated off shroud/tokioZ
- [ ] Working CLI + library mode
- [ ] Deterministic resolver
- [ ] zsync-compatible updates
- [ ] Clean test suite and docs


