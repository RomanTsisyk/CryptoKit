/**
 * Secure Random module for the CryptoKit library.
 *
 * This package provides cryptographically secure random number generation utilities
 * for various cryptographic operations including:
 *
 * - **SecureRandomGenerator**: Core random value generation (bytes, integers, longs, doubles, booleans, UUIDs, shuffling)
 * - **RandomStringGenerator**: Random string generation (alphanumeric, alphabetic, numeric, hex, Base64, passwords)
 * - **IVGenerator**: Initialization Vector and nonce generation for encryption operations
 * - **SaltGenerator**: Salt generation for password hashing and key derivation
 *
 * All random number generation uses `java.security.SecureRandom` to ensure
 * cryptographic strength suitable for security-sensitive operations.
 *
 * ## Example Usage
 *
 * ### Generate Random Bytes
 * ```kotlin
 * val randomBytes = SecureRandomGenerator.generateBytes(32)
 * ```
 *
 * ### Generate Random Password
 * ```kotlin
 * val password = RandomStringGenerator.generatePassword(
 *     length = 16,
 *     includeUppercase = true,
 *     includeLowercase = true,
 *     includeDigits = true,
 *     includeSpecial = true
 * )
 * ```
 *
 * ### Generate IV for AES-GCM
 * ```kotlin
 * val iv = IVGenerator.generateIV() // 12 bytes for GCM
 * val ivCBC = IVGenerator.generateIV16() // 16 bytes for CBC
 * ```
 *
 * ### Generate Salt for Password Hashing
 * ```kotlin
 * val salt = SaltGenerator.generateSalt() // 32 bytes
 * val saltHex = SaltGenerator.generateSaltHex() // Hex string
 * val saltBase64 = SaltGenerator.generateSaltBase64() // Base64 string
 * ```
 *
 * @since 1.0.0
 */
package io.github.romantsisyk.cryptolib.random
