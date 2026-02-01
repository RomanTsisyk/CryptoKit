package io.github.romantsisyk.cryptolib.random

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException

/**
 * Object responsible for generating Initialization Vectors (IVs) and nonces
 * for cryptographic operations. Provides methods for generating IVs of various
 * sizes suitable for different encryption modes (GCM, CBC, etc.).
 */
object IVGenerator {

    /**
     * Default IV size for GCM mode (12 bytes / 96 bits).
     * This is the recommended size for AES-GCM as it provides optimal performance.
     */
    private const val GCM_IV_SIZE = 12

    /**
     * Default IV size for CBC mode (16 bytes / 128 bits).
     * This matches the AES block size.
     */
    private const val CBC_IV_SIZE = 16

    /**
     * Generates a cryptographically secure Initialization Vector (IV) for GCM mode.
     * The default size is 12 bytes (96 bits), which is the recommended size for AES-GCM.
     *
     * @param size The size of the IV in bytes. Default is 12 bytes for GCM mode.
     * @return A random IV byte array of the specified size.
     * @throws CryptoOperationException if the size is less than or equal to 0.
     */
    @JvmStatic
    @JvmOverloads
    fun generateIV(size: Int = GCM_IV_SIZE): ByteArray {
        if (size <= 0) {
            throw CryptoOperationException("IV generation failed: size must be positive")
        }

        return try {
            SecureRandomGenerator.generateBytes(size)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("IV generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure Initialization Vector (IV) for CBC mode.
     * The size is fixed at 16 bytes (128 bits), which matches the AES block size.
     *
     * @return A random IV byte array of 16 bytes.
     */
    @JvmStatic
    fun generateIV16(): ByteArray {
        return try {
            SecureRandomGenerator.generateBytes(CBC_IV_SIZE)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("IV generation failed", e)
        }
    }

    /**
     * Generates a cryptographically secure nonce (number used once).
     * Nonces are similar to IVs but are typically used in different contexts.
     * The default size is 12 bytes (96 bits).
     *
     * @param size The size of the nonce in bytes. Default is 12 bytes.
     * @return A random nonce byte array of the specified size.
     * @throws CryptoOperationException if the size is less than or equal to 0.
     */
    @JvmStatic
    @JvmOverloads
    fun generateNonce(size: Int = GCM_IV_SIZE): ByteArray {
        if (size <= 0) {
            throw CryptoOperationException("Nonce generation failed: size must be positive")
        }

        return try {
            SecureRandomGenerator.generateBytes(size)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Nonce generation failed", e)
        }
    }
}
