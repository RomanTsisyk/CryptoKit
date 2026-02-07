package io.github.romantsisyk.cryptolib.integrity

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.CRC32
import java.util.zip.Checksum

/**
 * Utility object providing checksum calculation and verification functionality.
 *
 * This object supports multiple checksum algorithms for data integrity verification,
 * including CRC32, ADLER32, MD5, SHA-256, and SHA-512.
 */
object ChecksumUtils {

    private const val BUFFER_SIZE = 8192 // 8KB buffer for stream processing

    /**
     * Calculates the checksum of a byte array using the specified algorithm.
     *
     * @param data The byte array for which to calculate the checksum.
     * @param algorithm The checksum algorithm to use.
     * @return A hexadecimal string representation of the checksum.
     * @throws CryptoOperationException if the checksum calculation fails.
     */
    @JvmStatic
    fun calculateChecksum(data: ByteArray, algorithm: ChecksumAlgorithm): String {
        if (data.isEmpty()) {
            throw CryptoOperationException("Checksum calculation failed: data cannot be empty")
        }

        return try {
            when (algorithm) {
                ChecksumAlgorithm.CRC32 -> calculateCRC32(data)
                ChecksumAlgorithm.ADLER32 -> calculateAdler32(data)
                ChecksumAlgorithm.MD5, ChecksumAlgorithm.SHA256, ChecksumAlgorithm.SHA512 ->
                    calculateMessageDigest(data, algorithm)
            }
        } catch (e: Exception) {
            throw CryptoOperationException("Checksum calculation failed", e)
        }
    }

    /**
     * Calculates the checksum of a file using the specified algorithm.
     *
     * @param file The file for which to calculate the checksum.
     * @param algorithm The checksum algorithm to use.
     * @return A hexadecimal string representation of the checksum.
     * @throws CryptoOperationException if the file cannot be read or checksum calculation fails.
     */
    @JvmStatic
    fun calculateChecksum(file: File, algorithm: ChecksumAlgorithm): String {
        if (!file.exists()) {
            throw CryptoOperationException("Checksum calculation failed: file does not exist: ${file.absolutePath}")
        }

        if (!file.canRead()) {
            throw CryptoOperationException("Checksum calculation failed: file is not readable: ${file.absolutePath}")
        }

        return try {
            file.inputStream().use { inputStream ->
                calculateChecksum(inputStream, algorithm)
            }
        } catch (e: CryptoOperationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoOperationException("Checksum calculation failed for file: ${file.absolutePath}", e)
        }
    }

    /**
     * Calculates the checksum of data from an input stream using the specified algorithm.
     *
     * @param inputStream The input stream from which to read data.
     * @param algorithm The checksum algorithm to use.
     * @return A hexadecimal string representation of the checksum.
     * @throws CryptoOperationException if reading from the stream or checksum calculation fails.
     */
    @JvmStatic
    fun calculateChecksum(inputStream: InputStream, algorithm: ChecksumAlgorithm): String {
        return try {
            when (algorithm) {
                ChecksumAlgorithm.CRC32 -> calculateCRC32Stream(inputStream)
                ChecksumAlgorithm.ADLER32 -> calculateAdler32Stream(inputStream)
                ChecksumAlgorithm.MD5, ChecksumAlgorithm.SHA256, ChecksumAlgorithm.SHA512 ->
                    calculateMessageDigestStream(inputStream, algorithm)
            }
        } catch (e: Exception) {
            throw CryptoOperationException("Checksum calculation from stream failed", e)
        }
    }

    /**
     * Verifies that the calculated checksum of the data matches the expected checksum.
     *
     * @param data The byte array to verify.
     * @param expectedChecksum The expected checksum value as a hexadecimal string.
     * @param algorithm The checksum algorithm to use for verification.
     * @return True if the calculated checksum matches the expected checksum, false otherwise.
     * @throws CryptoOperationException if the checksum calculation fails.
     */
    @JvmStatic
    fun verifyChecksum(data: ByteArray, expectedChecksum: String, algorithm: ChecksumAlgorithm): Boolean {
        val actualChecksum = calculateChecksum(data, algorithm)
        return MessageDigest.isEqual(
            actualChecksum.lowercase().toByteArray(),
            expectedChecksum.lowercase().toByteArray()
        )
    }

    /**
     * Verifies that the calculated checksum of the file matches the expected checksum.
     *
     * @param file The file to verify.
     * @param expectedChecksum The expected checksum value as a hexadecimal string.
     * @param algorithm The checksum algorithm to use for verification.
     * @return True if the calculated checksum matches the expected checksum, false otherwise.
     * @throws CryptoOperationException if the checksum calculation fails.
     */
    @JvmStatic
    fun verifyChecksum(file: File, expectedChecksum: String, algorithm: ChecksumAlgorithm): Boolean {
        val actualChecksum = calculateChecksum(file, algorithm)
        return MessageDigest.isEqual(
            actualChecksum.lowercase().toByteArray(),
            expectedChecksum.lowercase().toByteArray()
        )
    }

    // Private helper methods

    private fun calculateCRC32(data: ByteArray): String {
        val crc32 = CRC32()
        crc32.update(data)
        return crc32.value.toString(16).padStart(8, '0')
    }

    private fun calculateAdler32(data: ByteArray): String {
        val adler32 = Adler32()
        adler32.update(data)
        return adler32.value.toString(16).padStart(8, '0')
    }

    private fun calculateMessageDigest(data: ByteArray, algorithm: ChecksumAlgorithm): String {
        val digest = MessageDigest.getInstance(algorithm.algorithmName)
        val hash = digest.digest(data)
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun calculateCRC32Stream(inputStream: InputStream): String {
        return calculateChecksumStream(inputStream, CRC32())
    }

    private fun calculateAdler32Stream(inputStream: InputStream): String {
        return calculateChecksumStream(inputStream, Adler32())
    }

    private fun calculateChecksumStream(inputStream: InputStream, checksum: Checksum): String {
        val buffer = ByteArray(BUFFER_SIZE)
        var bytesRead: Int

        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            checksum.update(buffer, 0, bytesRead)
        }

        return checksum.value.toString(16).padStart(8, '0')
    }

    private fun calculateMessageDigestStream(inputStream: InputStream, algorithm: ChecksumAlgorithm): String {
        val digest = MessageDigest.getInstance(algorithm.algorithmName)
        val buffer = ByteArray(BUFFER_SIZE)
        var bytesRead: Int

        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            digest.update(buffer, 0, bytesRead)
        }

        val hash = digest.digest()
        return hash.joinToString("") { "%02x".format(it) }
    }
}
