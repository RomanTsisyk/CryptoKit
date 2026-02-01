package io.github.romantsisyk.cryptolib.storage

import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import java.io.File
import java.io.IOException
import java.security.SecureRandom
import javax.crypto.SecretKey

/**
 * Encrypted file storage utility for secure file persistence.
 * This class provides methods to encrypt data before writing to files and decrypt data when reading.
 * It also supports secure deletion by overwriting file contents before removal.
 *
 * @property keyAlias The alias for the encryption key (default: "SecureStorageKey").
 */
class SecureFileStorage(
    private val keyAlias: String = SecureStorageConfig.DEFAULT_KEY_ALIAS
) {

    private val secretKey: SecretKey by lazy {
        initializeKey()
    }

    private val secureRandom: SecureRandom by lazy {
        try {
            SecureRandom.getInstanceStrong()
        } catch (e: Exception) {
            SecureRandom()
        }
    }

    /**
     * Initializes the encryption key. If the key doesn't exist, it will be created.
     *
     * @return The SecretKey used for encryption and decryption.
     * @throws CryptoOperationException if key initialization fails.
     */
    private fun initializeKey(): SecretKey {
        return try {
            // Try to get existing key
            try {
                KeyHelper.getAESKey(keyAlias)
            } catch (e: Exception) {
                // Key doesn't exist, generate a new one
                KeyHelper.generateAESKey(
                    alias = keyAlias,
                    validityDays = 3650, // 10 years
                    requireUserAuthentication = false
                )
                KeyHelper.getAESKey(keyAlias)
            }
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to initialize encryption key", e)
        }
    }

    /**
     * Encrypts and writes data to a file.
     *
     * @param file The file to write the encrypted data to.
     * @param data The byte array to encrypt and write.
     * @throws CryptoOperationException if encryption or file writing fails.
     * @throws IOException if file operations fail.
     */
    fun writeEncrypted(file: File, data: ByteArray) {
        try {
            // Ensure parent directory exists
            file.parentFile?.let { parent ->
                if (!parent.exists()) {
                    parent.mkdirs()
                }
            }

            val encrypted = AESEncryption.encrypt(data, secretKey)
            file.writeText(encrypted, Charsets.UTF_8)
        } catch (e: IOException) {
            throw IOException("Failed to write encrypted data to file: ${file.absolutePath}", e)
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to encrypt data for file: ${file.absolutePath}", e)
        }
    }

    /**
     * Reads and decrypts data from a file.
     *
     * @param file The file to read and decrypt.
     * @return The decrypted byte array.
     * @throws CryptoOperationException if decryption fails.
     * @throws IOException if file reading fails.
     */
    fun readDecrypted(file: File): ByteArray {
        if (!file.exists()) {
            throw IOException("File does not exist: ${file.absolutePath}")
        }

        return try {
            val encrypted = file.readText(Charsets.UTF_8)
            AESEncryption.decrypt(encrypted, secretKey)
        } catch (e: IOException) {
            throw IOException("Failed to read file: ${file.absolutePath}", e)
        } catch (e: Exception) {
            throw CryptoOperationException("Failed to decrypt data from file: ${file.absolutePath}", e)
        }
    }

    /**
     * Encrypts and writes a string to a file.
     *
     * @param file The file to write the encrypted string to.
     * @param data The string to encrypt and write.
     * @throws CryptoOperationException if encryption or file writing fails.
     * @throws IOException if file operations fail.
     */
    fun writeEncryptedString(file: File, data: String) {
        writeEncrypted(file, data.toByteArray(Charsets.UTF_8))
    }

    /**
     * Reads and decrypts a string from a file.
     *
     * @param file The file to read and decrypt.
     * @return The decrypted string.
     * @throws CryptoOperationException if decryption fails.
     * @throws IOException if file reading fails.
     */
    fun readDecryptedString(file: File): String {
        val decrypted = readDecrypted(file)
        return String(decrypted, Charsets.UTF_8)
    }

    /**
     * Securely deletes a file by overwriting its contents with random data before deletion.
     * This helps prevent data recovery from the file system.
     *
     * @param file The file to securely delete.
     * @param overwritePasses The number of times to overwrite the file (default: 3).
     * @return True if the file was successfully deleted, false otherwise.
     * @throws IOException if file operations fail.
     */
    fun deleteSecurely(file: File, overwritePasses: Int = 3): Boolean {
        if (!file.exists()) {
            return false
        }

        try {
            if (file.isFile) {
                val fileSize = file.length()

                // Overwrite file contents multiple times with random data
                repeat(overwritePasses) {
                    file.outputStream().use { output ->
                        val buffer = ByteArray(8192) // 8KB buffer
                        var remaining = fileSize

                        while (remaining > 0) {
                            val bytesToWrite = minOf(buffer.size.toLong(), remaining).toInt()
                            secureRandom.nextBytes(buffer)
                            output.write(buffer, 0, bytesToWrite)
                            remaining -= bytesToWrite
                        }
                        output.flush()
                    }
                }

                // Truncate file to zero length
                file.writeBytes(ByteArray(0))
            }

            // Finally, delete the file
            return file.delete()
        } catch (e: IOException) {
            throw IOException("Failed to securely delete file: ${file.absolutePath}", e)
        }
    }

    /**
     * Checks if a file exists.
     *
     * @param file The file to check.
     * @return True if the file exists, false otherwise.
     */
    fun exists(file: File): Boolean {
        return file.exists()
    }

    /**
     * Deletes a file without secure overwriting.
     *
     * @param file The file to delete.
     * @return True if the file was successfully deleted, false otherwise.
     */
    fun delete(file: File): Boolean {
        return file.delete()
    }

    /**
     * Gets the size of a file in bytes.
     *
     * @param file The file to get the size of.
     * @return The size of the file in bytes, or -1 if the file doesn't exist.
     */
    fun getFileSize(file: File): Long {
        return if (file.exists()) file.length() else -1
    }
}
