# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-07

### Added
- AES-256-GCM symmetric encryption and decryption
- RSA-OAEP asymmetric encryption and decryption (2048-bit keys)
- Digital signatures (RSA-PSS SHA256, ECDSA P-256)
- Android Keystore key generation, storage, and lifecycle management
- Biometric authentication integration via BiometricPrompt
- Key rotation with configurable validity windows and WorkManager scheduling
- JWT creation and validation with mandatory algorithm pinning
- PBKDF2 key derivation (600,000 iterations, OWASP 2023 compliant)
- Secure random generation (tokens, OTPs, UUIDs, passwords)
- SHA-256/SHA-512 hashing and HMAC generation with constant-time verification
- Certificate validation and certificate pinning with constant-time comparison
- Data integrity envelopes with checksum verification
- QR code generation and scanning with encrypted payloads
- Sealed exception hierarchy for exhaustive error handling
- Encrypted SharedPreferences and file storage
- Comprehensive consumer ProGuard rules for R8 compatibility
- SECURITY.md with vulnerability reporting guidelines
- CI workflow for automated builds and tests

### Security
- All cryptographic comparisons use constant-time operations (MessageDigest.isEqual)
- JWT validation requires explicit algorithm pinning to prevent algorithm confusion attacks
- PBKDF2 iterations set to 600,000 per OWASP 2023 guidelines
- No alpha or unstable dependencies in production artifact
