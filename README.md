# OpenMLS WASM E2E Encryption/Decryption

A TypeScript implementation for end-to-end encryption and decryption using the [OpenMLS](https://github.com/openmls/openmls) WASM module — the Rust implementation of the [MLS (Messaging Layer Security)](https://messaginglayersecurity.rocks/) protocol (RFC 9420).

## Overview

This project provides:

1. **Rust WASM Crate** (`crates/openmls-wasm/`) — OpenMLS bindings compiled to WebAssembly with `encrypt` and `decrypt` functions exposed via `wasm-bindgen`.
2. **TypeScript Library** (`ts/src/`) — A high-level wrapper that provides `MlsClient` and `MlsEncryptionGroup` classes for easy encrypt/decrypt operations.
3. **Demo & Tests** — End-to-end examples demonstrating the full flow.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  TypeScript Application                         │
│  (MlsClient, MlsEncryptionGroup)               │
├─────────────────────────────────────────────────┤
│  WASM Bindings (wasm-bindgen)                   │
├─────────────────────────────────────────────────┤
│  OpenMLS Rust Library                           │
│  (MLS Protocol: X25519 + ChaCha20Poly1305 +    │
│   SHA256 + Ed25519)                             │
└─────────────────────────────────────────────────┘
```

## Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [Node.js](https://nodejs.org/) (v18+)
- npm

## Installation

```bash
# Install wasm-pack (if not already installed)
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Install Node.js dependencies
npm install
```

## Building

```bash
# Build the WASM module and TypeScript
npm run build

# Or build separately:
npm run build:wasm   # Compile Rust to WASM
npm run build:ts     # Compile TypeScript
```

## Usage

### Quick Example

```typescript
import { MlsClient, MlsEncryptionGroup, initOpenMls } from "openmls-wasm-e2e";

// Initialize the WASM module
const wasm = await initOpenMls();

// Create two clients
const alice = new MlsClient(wasm, "alice");
const bob = new MlsClient(wasm, "bob");

// Bob generates a key package
const bobKeyPackage = bob.generateKeyPackage();

// Alice creates a group and adds Bob
const aliceGroup = MlsEncryptionGroup.create(alice, "secret-chat");
const { welcome, ratchetTree } = aliceGroup.addMember(bobKeyPackage);

// Bob joins using the welcome message
const bobGroup = MlsEncryptionGroup.join(bob, welcome, ratchetTree, "secret-chat");

// Alice encrypts a message
const ciphertext = aliceGroup.encrypt("Hello Bob! This is encrypted with MLS.");

// Bob decrypts it
const plaintext = bobGroup.decryptToString(ciphertext);
console.log(plaintext); // "Hello Bob! This is encrypted with MLS."

// Bob replies (bidirectional)
const reply = bobGroup.encrypt("Got it, Alice!");
const decryptedReply = aliceGroup.decryptToString(reply);
```

### API Reference

#### `initOpenMls(wasmModulePath?: string): Promise<OpenMlsWasmModule>`
Loads and initializes the WASM module.

#### `MlsClient`
- `constructor(wasm: OpenMlsWasmModule, name: string)` — Create a new MLS client
- `getName(): string` — Get the client's name
- `generateKeyPackage(): Uint8Array` — Generate a key package for group joining
- `free(): void` — Release WASM resources

#### `MlsEncryptionGroup`
- `static create(client: MlsClient, groupId: string): MlsEncryptionGroup` — Create a new group
- `static join(client, welcome, ratchetTree, groupId): MlsEncryptionGroup` — Join an existing group
- `addMember(keyPackageBytes: Uint8Array): { welcome, ratchetTree }` — Add a member
- `encrypt(plaintext: string | Uint8Array): Uint8Array` — Encrypt a message
- `decrypt(ciphertext: Uint8Array): Uint8Array` — Decrypt a message
- `decryptToString(ciphertext: Uint8Array): string` — Decrypt to UTF-8 string
- `free(): void` — Release WASM resources

## Running the Demo

```bash
npm run demo
```

## Testing

```bash
npm test
```

## Security

This implementation uses the MLS protocol with:
- **Key Exchange**: X25519 (DHKEM)
- **Encryption**: ChaCha20-Poly1305 (AEAD)
- **Hash**: SHA-256
- **Signatures**: Ed25519

The MLS protocol provides:
- Forward secrecy
- Post-compromise security
- Scalable group key management
- Authenticated encryption

## Project Structure

```
├── crates/
│   └── openmls-wasm/        # Rust WASM crate
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs        # WASM bindings (encrypt/decrypt)
│           └── utils.rs      # Panic hook utility
├── ts/
│   ├── src/
│   │   ├── index.ts          # Main TypeScript library
│   │   ├── wasm-types.ts     # Type definitions for WASM module
│   │   └── demo.ts           # Demo script
│   ├── tests/
│   │   └── e2e.test.ts       # End-to-end tests
│   └── pkg/                  # Generated WASM package (after build)
├── package.json
├── tsconfig.json
└── jest.config.js
```

## License

MIT