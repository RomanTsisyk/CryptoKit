package io.github.romantsisyk.cryptolib.crypto.hashing

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Utility object for performing HMAC (Hash-based Message Authentication Code) operations.
 * HMAC provides message authentication using a secret key and a hash function.
 */
object HMACUtils {

    /**
     * Generates an HMAC for the provided data using the specified key and algorithm.
     *
     * @param data The data to authenticate as a ByteArray.
     * @param key The secret key used for HMAC generation.
     * @param algorithm The hash algorithm to use for HMAC.
     * @return The computed HMAC as a ByteArray.
     * @throws CryptoOperationException if the HMAC generation fails.
     */
    @JvmStatic
    fun generateHMAC(data: ByteArray, key: SecretKey, algorithm: HashAlgorithm): ByteArray {
        if (data.isEmpty()) {
            throw CryptoOperationException("HMAC generation failed: data cannot be empty")
        }

        return try {
            val mac = Mac.getInstance(algorithm.toHmacAlgorithm())
            mac.init(key)
            mac.doFinal(data)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoOperationException(
                "HMAC generation failed: algorithm ${algorithm.toHmacAlgorithm()} not available",
                e
            )
        } catch (e: InvalidKeyException) {
            throw CryptoOperationException("HMAC generation failed: invalid key", e)
        } catch (e: Exception) {
            throw CryptoOperationException("HMAC generation failed: ${e.message}", e)
        }
    }

    /**
     * Generates an HMAC for the provided string data using the specified key and algorithm.
     * Returns the HMAC as a hexadecimal string.
     *
     * @param data The string data to authenticate.
     * @param key The secret key used for HMAC generation.
     * @param algorithm The hash algorithm to use for HMAC.
     * @return The computed HMAC as a hexadecimal string.
     * @throws CryptoOperationException if the HMAC generation fails.
     */
    @JvmStatic
    fun generateHMAC(data: String, key: SecretKey, algorithm: HashAlgorithm): String {
        if (data.isEmpty()) {
            throw CryptoOperationException("HMAC generation failed: data cannot be empty")
        }

        val hmacBytes = generateHMAC(data.toByteArray(Charsets.UTF_8), key, algorithm)
        return HashUtils.bytesToHex(hmacBytes)
    }

    /**
     * Verifies that the HMAC of the provided data matches the expected HMAC value.
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @param data The data to verify.
     * @param mac The expected HMAC value.
     * @param key The secret key used for HMAC verification.
     * @param algorithm The hash algorithm to use for HMAC.
     * @return true if the HMACs match, false otherwise.
     * @throws CryptoOperationException if the HMAC verification fails.
     */
    @JvmStatic
    fun verifyHMAC(data: ByteArray, mac: ByteArray, key: SecretKey, algorithm: HashAlgorithm): Boolean {
        if (data.isEmpty()) {
            throw CryptoOperationException("HMAC verification failed: data cannot be empty")
        }

        if (mac.isEmpty()) {
            throw CryptoOperationException("HMAC verification failed: expected MAC cannot be empty")
        }

        return try {
            val computedMac = generateHMAC(data, key, algorithm)
            MessageDigest.isEqual(computedMac, mac)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("HMAC verification failed: ${e.message}", e)
        }
    }

    /**
     * Verifies that the HMAC of the provided string data matches the expected HMAC hex string.
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @param data The string data to verify.
     * @param macHex The expected HMAC value as a hexadecimal string.
     * @param key The secret key used for HMAC verification.
     * @param algorithm The hash algorithm to use for HMAC.
     * @return true if the HMACs match, false otherwise.
     * @throws CryptoOperationException if the HMAC verification fails.
     */
    @JvmStatic
    fun verifyHMAC(data: String, macHex: String, key: SecretKey, algorithm: HashAlgorithm): Boolean {
        if (data.isEmpty()) {
            throw CryptoOperationException("HMAC verification failed: data cannot be empty")
        }

        if (macHex.isEmpty()) {
            throw CryptoOperationException("HMAC verification failed: expected MAC cannot be empty")
        }

        return try {
            val macBytes = HashUtils.hexToBytes(macHex)
            verifyHMAC(data.toByteArray(Charsets.UTF_8), macBytes, key, algorithm)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("HMAC verification failed: ${e.message}", e)
        }
    }

    /**
     * Generates a new secret key for HMAC operations using the specified algorithm.
     *
     * @param algorithm The hash algorithm to use for HMAC key generation.
     * @return A newly generated SecretKey suitable for HMAC operations.
     * @throws CryptoOperationException if the key generation fails.
     */
    @JvmStatic
    fun generateKey(algorithm: HashAlgorithm): SecretKey {
        return try {
            val keyGenerator = KeyGenerator.getInstance(algorithm.toHmacAlgorithm())
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoOperationException(
                "HMAC key generation failed: algorithm ${algorithm.toHmacAlgorithm()} not available",
                e
            )
        } catch (e: Exception) {
            throw CryptoOperationException("HMAC key generation failed: ${e.message}", e)
        }
    }
}
