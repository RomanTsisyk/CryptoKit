CryptoKit

Production-grade Android cryptography library built on Android Keystore. Focus on safe defaults, explicit error modeling, and clear security boundaries.

## Problem

Android Keystore APIs are low-level and error-prone. CryptoKit solves specific problems:

- Keystore integration requires understanding multiple APIs with fragmented error handling
- Key lifecycle (generation, storage, invalidation) edge cases are often overlooked
- Authentication state changes and device credential updates can silently break encryption flows
- Developers must write boilerplate code to enforce cryptographic best practices

CryptoKit provides constrained abstractions that remove these footguns without hiding necessary control.

## Design Goals

- Explicit security boundaries and failure modes
- Safe cryptographic defaults (AES-256-GCM, RSA-OAEP, SHA-256)
- Minimal, stable public API
- No exposure of low-level crypto primitives or raw key material
- Sealed exception hierarchy for exhaustive error handling
- Synchronous operations with explicit threading requirements

## Core Capabilities

- Symmetric encryption (AES-256-GCM) and decryption with authenticated encryption
- Asymmetric key operations (RSA-OAEP) and digital signatures (RSA-SHA256)
- Secure key generation, storage, and lifecycle management via Android Keystore
- Biometric and device credential authentication integration
- Key rotation with configurable validity windows
- QR-based key distribution (generation and parsing)
- Sealed error model with typed exceptions for predictable handling

## Architecture

CryptoKit separates public API from Android Keystore implementation details:

- All key material remains in Android Keystore; plaintext keys are never exposed
- Cryptographic operations are performed by hidden, hardened crypto implementations
- Public methods return sealed exceptions only; no raw Java exceptions leak
- Configuration is explicit: every security-relevant parameter is named and typed

## Threading Model

CryptoKit does not manage threading. All cryptographic operations are synchronous and blocking. The caller is responsible for executing operations off the main thread. Long-running operations (key generation, biometric authentication, key rotation) will block the calling thread.

## Error Handling

All failures return sealed subtypes of `CryptoLibException`:
- `CryptoOperationException`: encryption, decryption, signing failures
- `KeyNotFoundException`: requested key does not exist
- `KeyGenerationException`: key creation failed
- `AuthenticationException`: biometric or device credential flow failed

No raw Java exceptions escape the public API. Callers must handle the sealed exception type and pattern-match on subtypes.

## Security Boundaries

CryptoKit is intentionally scoped. It is NOT:

- A TLS or network security library
- A protocol implementation (no OAuth, JWT, etc.)
- A key backup or synchronization solution
- A general-purpose cryptography framework

Key material is managed by Android Keystore only. Encrypted data and keys must be managed by the caller. No automatic secure deletion of plaintext intermediates is guaranteed outside Keystore boundaries.

## Status & Documentation

This library is pre-1.0. API stability is not guaranteed until 1.0 release.

For security policies, threat model, and best practices, see [SECURITY.md](SECURITY.md).
For threading guarantees and blocking behavior, see [CONTRIBUTING.md](CONTRIBUTING.md).

Core API documentation is available in generated Kotlin docs.
