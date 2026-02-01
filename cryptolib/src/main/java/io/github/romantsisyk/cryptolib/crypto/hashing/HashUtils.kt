package io.github.romantsisyk.cryptolib.crypto.hashing

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * Utility object for performing hash operations using various algorithms.
 * Provides methods for hashing data, files, and verifying hash values.
 */
object HashUtils {

    private const val BUFFER_SIZE = 8192 // 8KB buffer for file reading

    /**
     * Computes the hash of the provided data using the specified algorithm.
     *
     * @param data The data to hash as a ByteArray.
     * @param algorithm The hash algorithm to use.
     * @return The computed hash as a ByteArray.
     * @throws CryptoOperationException if the hashing operation fails.
     */
    @JvmStatic
    fun hash(data: ByteArray, algorithm: HashAlgorithm): ByteArray {
        if (data.isEmpty()) {
            throw CryptoOperationException("Hash failed: data cannot be empty")
        }

        return try {
            val digest = MessageDigest.getInstance(algorithm.algorithmName)
            digest.digest(data)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoOperationException("Hash failed: algorithm ${algorithm.algorithmName} not available", e)
        } catch (e: Exception) {
            throw CryptoOperationException("Hash failed: ${e.message}", e)
        }
    }

    /**
     * Computes the hash of the provided string data and returns it as a hexadecimal string.
     *
     * @param data The string data to hash.
     * @param algorithm The hash algorithm to use.
     * @return The computed hash as a hexadecimal string.
     * @throws CryptoOperationException if the hashing operation fails.
     */
    @JvmStatic
    fun hash(data: String, algorithm: HashAlgorithm): String {
        if (data.isEmpty()) {
            throw CryptoOperationException("Hash failed: data cannot be empty")
        }

        val hashBytes = hash(data.toByteArray(Charsets.UTF_8), algorithm)
        return bytesToHex(hashBytes)
    }

    /**
     * Computes the hash of a file using the specified algorithm.
     * Reads the file in chunks to handle large files efficiently.
     *
     * @param file The file to hash.
     * @param algorithm The hash algorithm to use.
     * @return The computed hash as a hexadecimal string.
     * @throws CryptoOperationException if the file cannot be read or the hashing operation fails.
     */
    @JvmStatic
    fun hashFile(file: File, algorithm: HashAlgorithm): String {
        if (!file.exists()) {
            throw CryptoOperationException("Hash failed: file does not exist: ${file.absolutePath}")
        }

        if (!file.isFile) {
            throw CryptoOperationException("Hash failed: path is not a file: ${file.absolutePath}")
        }

        if (!file.canRead()) {
            throw CryptoOperationException("Hash failed: file is not readable: ${file.absolutePath}")
        }

        return try {
            val digest = MessageDigest.getInstance(algorithm.algorithmName)

            FileInputStream(file).use { fis ->
                val buffer = ByteArray(BUFFER_SIZE)
                var bytesRead: Int

                while (fis.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }

            bytesToHex(digest.digest())
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoOperationException("Hash failed: algorithm ${algorithm.algorithmName} not available", e)
        } catch (e: IOException) {
            throw CryptoOperationException("Hash failed: error reading file ${file.absolutePath}", e)
        } catch (e: Exception) {
            throw CryptoOperationException("Hash failed: ${e.message}", e)
        }
    }

    /**
     * Verifies that the hash of the provided data matches the expected hash value.
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @param data The data to verify.
     * @param expectedHash The expected hash value.
     * @param algorithm The hash algorithm to use.
     * @return true if the hashes match, false otherwise.
     * @throws CryptoOperationException if the hashing operation fails.
     */
    @JvmStatic
    fun verifyHash(data: ByteArray, expectedHash: ByteArray, algorithm: HashAlgorithm): Boolean {
        if (data.isEmpty()) {
            throw CryptoOperationException("Hash verification failed: data cannot be empty")
        }

        if (expectedHash.isEmpty()) {
            throw CryptoOperationException("Hash verification failed: expected hash cannot be empty")
        }

        return try {
            val computedHash = hash(data, algorithm)
            MessageDigest.isEqual(computedHash, expectedHash)
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Hash verification failed: ${e.message}", e)
        }
    }

    /**
     * Converts a byte array to a hexadecimal string representation.
     *
     * @param bytes The byte array to convert.
     * @return The hexadecimal string representation.
     */
    @JvmStatic
    fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = "0123456789abcdef"[v ushr 4]
            hexChars[i * 2 + 1] = "0123456789abcdef"[v and 0x0F]
        }
        return String(hexChars)
    }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hex The hexadecimal string to convert.
     * @return The byte array representation.
     * @throws CryptoOperationException if the hex string is invalid.
     */
    @JvmStatic
    fun hexToBytes(hex: String): ByteArray {
        if (hex.isEmpty()) {
            throw CryptoOperationException("Hex conversion failed: hex string cannot be empty")
        }

        if (hex.length % 2 != 0) {
            throw CryptoOperationException("Hex conversion failed: hex string must have even length")
        }

        return try {
            val result = ByteArray(hex.length / 2)
            for (i in result.indices) {
                val index = i * 2
                val firstDigit = hex[index].digitToInt(16)
                val secondDigit = hex[index + 1].digitToInt(16)
                result[i] = ((firstDigit shl 4) + secondDigit).toByte()
            }
            result
        } catch (e: NumberFormatException) {
            throw CryptoOperationException("Hex conversion failed: invalid hexadecimal string", e)
        } catch (e: Exception) {
            throw CryptoOperationException("Hex conversion failed: ${e.message}", e)
        }
    }
}
