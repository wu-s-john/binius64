# SHA-256 Signature Verification Benchmark — Documentation

## Overview

A new example circuit and benchmark were created for **ECDSA signature verification using SHA-256**, modeled after the existing `ethsign` circuit which uses Keccak-256. The ECDSA cryptography (key generation, signing, recovery) is identical — only the hash function used to hash the message and derive the address from the public key was changed from Keccak-256 to SHA-256.

## Motivation

The `ethsign` benchmark is specific to Ethereum's choice of Keccak-256. This new benchmark measures the performance of the same ECDSA signature verification workflow but with SHA-256 as the hash primitive, enabling apples-to-apples comparison of Keccak-256 vs SHA-256 circuit performance in the context of signature verification.

---

## Files created

### 1. `crates/examples/src/circuits/sha256sign.rs` — Circuit definition

This is the core circuit implementing ECDSA signature verification with SHA-256. It exports `Sha256SignExample`, `Params`, and `Instance`.

**Circuit structure (per signature):**

The circuit proves that a given ECDSA signature is valid for a message, where:
- The message is hashed with SHA-256 to produce `z` (the scalar input to ECDSA)
- The public key is recovered via `ecrecover`
- The recovered public key is hashed with SHA-256 to derive a 20-byte address
- The derived address is compared against the claimed address

**Key byte-ordering differences from `ethsign`:**

The SHA-256 and Keccak-256 gadgets use different internal byte orderings for their wire representations, which required three specific adaptations:

| Operation | ethsign (Keccak) | sha256sign (SHA-256) | Why |
|---|---|---|---|
| **Digest → BigUint `z`** | `.rev().map(byteswap)` | `.rev().copied()` | Keccak digest wires are LE-packed (`from_le_bytes`), so `byteswap` converts to match BigUint's LE-limb layout. SHA-256 digest wires are BE-packed (`from_be_bytes`), so simply reversing the word order already produces correct LE-limb BigUint representation. |
| **BigUint limbs → hash message wires** | `.map(byteswap)` | `.map(\|w\| builder.rotl(w, 32))` | BigUint limbs are LE-packed. Keccak message wires are also LE-packed, so a full 8-byte reversal (`byteswap`) converts between them. SHA-256 message wires store two 32-bit BE words per 64-bit wire (`lo_be ^ (hi_be << 32)`), so a 32-bit rotation is the correct conversion from LE-packed limbs. |
| **Digest → ByteVec for address comparison** | Pass `digest` directly | Call `digest_to_le_wires(builder)` first | `ByteVec` expects LE-packed wires. Keccak's digest is already LE-packed. SHA-256's digest is BE-packed, so it must be converted via `digest_to_le_wires()` (which internally calls `swap_bytes` on each wire). |

**Address derivation difference:**

In `ethsign`, the address is derived from the Keccak-256 hash of the public key — this is the standard Ethereum address derivation, and the `ethsign` crate's `public.address()` method computes it natively. In `sha256sign`, the address is derived from the **SHA-256** hash of the public key (bytes 12..32), so we cannot use `public.address()`. Instead, we compute the SHA-256 hash of the public key bytes and extract the address ourselves:

```rust
let pk_hash = sha256_hash(pk_bytes);
let address_bytes: &[u8] = &pk_hash[12..32];
pack_bytes_into_wires_le(w, address, address_bytes);
```

**Native hash helper:**

The `keccak256()` helper function (using `tiny_keccak`) was replaced with:

```rust
fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    NativeSha256::digest(bytes).into()
}
```

This uses the `sha2` crate (already a workspace dependency) for computing reference hashes during witness population.

### 2. `crates/examples/benches/sha256sign.rs` — Benchmark harness

A criterion benchmark following the same pattern as `crates/examples/benches/ethsign.rs`. It uses:
- `SignBenchConfig::from_env(1)` for environment-based configuration (number of signatures, log inverse rate)
- `MESSAGE_MAX_BYTES` env var for message size (default: 320 bytes, chosen to yield 8 SHA-256 compressions per signature)
- The `ExampleBenchmark` trait and `run_cs_benchmark` utility from the shared `crates/examples/benches/utils/` module

**Usage:**
```bash
# Default: 1 signature, 320-byte max message (8 SHA-256 compressions)
cargo bench --bench sha256sign

# Custom: 4 signatures, 256-byte max message
N_SIGNATURES=4 MESSAGE_MAX_BYTES=256 cargo bench --bench sha256sign
```

### 3. `crates/examples/examples/sha256sign.rs` — Example binary

A CLI example for running prove/verify outside the benchmark harness:
```bash
cargo run --example sha256sign -- prove
cargo run --example sha256sign -- prove -n 3 -m 256
```

---

## Files modified

### 4. `crates/examples/src/circuits/mod.rs`

Added `pub mod sha256sign;` to export the new circuit module (line 11).

### 5. `crates/examples/Cargo.toml`

Added a new benchmark target:
```toml
[[bench]]
name = "sha256sign"
harness = false
```

No new dependencies were needed — `sha2`, `ethsign`, `criterion`, and all other dependencies were already present.

---

## Verification

The implementation was verified with:

1. **`cargo check -p binius-examples`** — compiles without errors or warnings
2. **`cargo run --example sha256sign -- prove`** — full prove + verify cycle succeeds, producing a 291 KiB proof for 1 signature with default parameters
