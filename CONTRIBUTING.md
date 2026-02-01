# Contributing to CryptoKit

Thank you for your interest in contributing to CryptoKit! This library plays a critical role in securing applications, and we greatly value contributions from the community. Whether you are reporting bugs, suggesting features, improving documentation, or submitting code, your help makes CryptoKit better for everyone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Development Setup](#development-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security Considerations](#security-considerations)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and considerate in all interactions
- Welcome newcomers and help them get started
- Accept constructive criticism gracefully
- Focus on what is best for the community and the project
- Show empathy towards other community members

Unacceptable behavior includes harassment, trolling, personal attacks, and publishing others' private information without permission.

## Reporting Bugs

If you encounter a bug, please report it through [GitHub Issues](https://github.com/RomanTsisyk/CryptoKit/issues).

### Before Submitting a Bug Report

1. Check the existing issues to avoid duplicates
2. Ensure you are using the latest version of CryptoKit
3. Verify the issue is reproducible

### Bug Report Guidelines

Please include the following information:

- **Clear title**: A concise summary of the issue
- **Description**: Detailed explanation of the problem
- **Steps to reproduce**: Numbered steps to recreate the issue
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened
- **Environment**: Android version, device/emulator, CryptoKit version
- **Code samples**: Minimal code to reproduce the issue (if applicable)
- **Stack traces**: Full error messages and stack traces

**Important**: For security vulnerabilities, do NOT use GitHub Issues. Please refer to our [Security Policy](SECURITY.md) for responsible disclosure procedures.

## Suggesting Features

We welcome feature suggestions! To propose a new feature:

1. Open a [GitHub Issue](https://github.com/RomanTsisyk/CryptoKit/issues) with the "Feature Request" label
2. Provide a clear description of the feature
3. Explain the use case and why it would benefit users
4. Include any relevant examples or references
5. Consider the security implications of the proposed feature

Before submitting, please search existing issues to ensure the feature has not already been requested.

## Development Setup

### Prerequisites

- JDK 17 or higher
- Android Studio (latest stable version recommended)
- Android SDK with API level 21 or higher
- Git

### Getting Started

1. **Fork the repository**

   Click the "Fork" button on the [CryptoKit repository](https://github.com/RomanTsisyk/CryptoKit)

2. **Clone your fork**

   ```bash
   git clone https://github.com/YOUR_USERNAME/CryptoKit.git
   cd CryptoKit
   ```

3. **Add upstream remote**

   ```bash
   git remote add upstream https://github.com/RomanTsisyk/CryptoKit.git
   ```

4. **Build the project**

   ```bash
   ./gradlew build
   ```

5. **Run tests**

   ```bash
   ./gradlew test
   ```

6. **Generate documentation**

   ```bash
   ./gradlew dokkaHtml
   ```

### Keeping Your Fork Updated

```bash
git fetch upstream
git checkout master
git merge upstream/master
```

## Code Style Guidelines

CryptoKit follows the official [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html). Please adhere to these guidelines when contributing code.

### Key Points

- **Naming**: Use descriptive names; classes in PascalCase, functions and variables in camelCase
- **Formatting**: Use 4 spaces for indentation (no tabs)
- **Line length**: Maximum 120 characters per line
- **Imports**: No wildcard imports; organize imports alphabetically
- **Documentation**: Use KDoc for all public APIs

### Cryptography-Specific Guidelines

- Use explicit type declarations for cryptographic parameters
- Document all security assumptions and constraints
- Include unit tests for all cryptographic operations
- Never log sensitive data (keys, plaintext, etc.)
- Use secure defaults for all cryptographic parameters

### Example

```kotlin
/**
 * Encrypts the given plaintext using AES-GCM.
 *
 * @param plaintext The data to encrypt
 * @param key The encryption key (must be 256 bits)
 * @return The encrypted ciphertext with prepended IV
 * @throws CryptoException if encryption fails
 */
fun encrypt(plaintext: ByteArray, key: SecretKey): ByteArray {
    // Implementation
}
```

## Pull Request Process

1. **Create a feature branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the code style guidelines
   - Write or update tests as needed
   - Update documentation if applicable

3. **Commit your changes**
   - Write clear, descriptive commit messages
   - Reference related issues (e.g., "Fixes #123")

4. **Push to your fork**

   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request**
   - Provide a clear title and description
   - Link related issues
   - Describe the changes and their purpose
   - Include any testing instructions

### PR Requirements

Before a PR can be merged:

- All existing tests must pass
- New code must include appropriate tests
- Code must follow the style guidelines
- Documentation must be updated if needed
- At least one maintainer must approve the changes
- For cryptographic changes, a security review is required

### Review Process

- Maintainers will review your PR as soon as possible
- Be responsive to feedback and requested changes
- Once approved, a maintainer will merge your PR

## Security Considerations

As a cryptography library, CryptoKit has stringent security requirements. All contributors must understand and follow these guidelines.

### Mandatory Practices

- **Never commit secrets**: Keys, credentials, or sensitive data must never appear in code
- **Use secure defaults**: All cryptographic operations must use secure default parameters
- **Validate inputs**: Always validate and sanitize inputs to cryptographic functions
- **Handle errors securely**: Do not expose sensitive information in error messages
- **Constant-time operations**: Use constant-time comparisons for security-sensitive operations

### Security Review

All changes affecting cryptographic operations require a security review. This includes:

- New encryption/decryption methods
- Key generation or management changes
- Random number generation
- Digital signature operations
- Any changes to existing cryptographic algorithms

### Reporting Security Issues

If you discover a security vulnerability during development, do NOT create a public issue. Follow the [Security Policy](SECURITY.md) for responsible disclosure.

### Resources

- [OWASP Cryptographic Guidelines](https://owasp.org/www-project-cheat-sheets/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Android Keystore Best Practices](https://developer.android.com/training/articles/keystore)
- [Kotlin Security Coding Guidelines](https://kotlinlang.org/docs/security.html)

---

Thank you for contributing to CryptoKit! Your efforts help make cryptography more accessible and secure for developers everywhere.
