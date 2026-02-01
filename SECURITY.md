# Security Policy

CryptoKit is a cryptography library, and security is our highest priority. We take all security vulnerabilities seriously and appreciate the community's efforts in responsibly disclosing issues.

## Supported Versions

The following versions of CryptoKit are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

We strongly recommend always using the latest stable release to benefit from the most recent security patches and improvements.

## Reporting a Vulnerability

If you discover a security vulnerability in CryptoKit, please report it responsibly. **Do not disclose security vulnerabilities publicly** until they have been addressed.

### How to Report

1. **GitHub Security Advisories (Preferred)**: Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/RomanTsisyk/CryptoKit/security/advisories/new).

2. **Email**: Send a detailed report to the repository maintainer via GitHub.

### What to Include

When reporting a vulnerability, please provide:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Affected versions
- Potential impact assessment
- Any suggested fixes (optional)

## Response Timeline

| Action                          | Timeline        |
| ------------------------------- | --------------- |
| Initial acknowledgment          | Within 48 hours |
| Preliminary assessment          | Within 7 days   |
| Status update                   | Every 14 days   |
| Security patch release (target) | Within 30 days  |

For critical vulnerabilities affecting core cryptographic functions, we aim to provide patches within 7 days of confirmation.

## Security Best Practices

When using CryptoKit in your applications, follow these guidelines:

### Key Management
- Never hardcode encryption keys in your source code
- Use the Android Keystore for secure key storage
- Implement proper key rotation policies
- Delete keys securely when they are no longer needed

### Cryptographic Operations
- Always use the library's default secure configurations
- Do not implement custom cryptographic algorithms
- Use authenticated encryption (AES-GCM) for data confidentiality and integrity
- Validate all inputs before cryptographic operations

### General Security
- Keep CryptoKit updated to the latest version
- Enable ProGuard/R8 obfuscation in release builds
- Implement certificate pinning for network communications
- Never log sensitive data or cryptographic keys
- Use secure random number generation provided by the library

### Avoid Common Pitfalls
- Do not reuse IVs/nonces with the same key
- Do not use ECB mode for encryption
- Do not ignore cryptographic exceptions
- Do not store encrypted data and keys in the same location

## Responsible Disclosure

We follow a coordinated disclosure process:

1. Reporter submits vulnerability privately
2. We acknowledge receipt and begin investigation
3. We develop and test a fix
4. We release the security patch
5. We publicly disclose the vulnerability after users have had time to update

We request that security researchers:

- Allow reasonable time for us to address the issue before public disclosure
- Make a good faith effort to avoid privacy violations and data destruction
- Do not exploit vulnerabilities beyond what is necessary to demonstrate the issue

We are committed to working with security researchers and will acknowledge contributors in our security advisories (unless anonymity is requested).

## Security Updates

Security updates are announced through:

- GitHub Security Advisories
- Release notes
- Repository changelog

Subscribe to repository notifications to stay informed about security updates.

---

Thank you for helping keep CryptoKit and its users secure.
