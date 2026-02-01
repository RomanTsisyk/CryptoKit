package io.github.romantsisyk.cryptolib.storage

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException

@RunWith(AndroidJUnit4::class)
class SecureFileStorageTest {

    private lateinit var secureFileStorage: SecureFileStorage
    private lateinit var testDir: File
    private val testKeyAlias = "TestFileStorageKey"

    @Before
    fun setUp() {
        secureFileStorage = SecureFileStorage(testKeyAlias)

        // Create a temporary directory for test files
        testDir = File(System.getProperty("java.io.tmpdir"), "secure_file_storage_test")
        if (!testDir.exists()) {
            testDir.mkdirs()
        }
    }

    @After
    fun tearDown() {
        // Clean up test directory
        testDir.listFiles()?.forEach { it.delete() }
        testDir.delete()

        // Delete test key
        try {
            KeyHelper.deleteKey(testKeyAlias)
        } catch (e: Exception) {
            // Ignore if key doesn't exist
        }
    }

    @Test
    fun `test writeEncrypted and readDecrypted`() {
        val testFile = File(testDir, "test_encrypted.dat")
        val testData = "Test encrypted data".toByteArray()

        secureFileStorage.writeEncrypted(testFile, testData)
        assertTrue(testFile.exists())

        val decrypted = secureFileStorage.readDecrypted(testFile)
        assertArrayEquals(testData, decrypted)
    }

    @Test
    fun `test writeEncryptedString and readDecryptedString`() {
        val testFile = File(testDir, "test_encrypted_string.txt")
        val testString = "Hello, Secure File Storage!"

        secureFileStorage.writeEncryptedString(testFile, testString)
        assertTrue(testFile.exists())

        val decrypted = secureFileStorage.readDecryptedString(testFile)
        assertEquals(testString, decrypted)
    }

    @Test
    fun `test readDecrypted throws IOException when file does not exist`() {
        val nonExistentFile = File(testDir, "non_existent.dat")

        assertThrows(IOException::class.java) {
            secureFileStorage.readDecrypted(nonExistentFile)
        }
    }

    @Test
    fun `test writeEncrypted creates parent directories`() {
        val nestedFile = File(testDir, "nested/dir/test.dat")
        val testData = "Test data".toByteArray()

        assertFalse(nestedFile.parentFile?.exists() ?: false)

        secureFileStorage.writeEncrypted(nestedFile, testData)

        assertTrue(nestedFile.exists())
        assertTrue(nestedFile.parentFile?.exists() ?: false)
    }

    @Test
    fun `test deleteSecurely removes file`() {
        val testFile = File(testDir, "test_secure_delete.dat")
        val testData = "Data to be securely deleted".toByteArray()

        secureFileStorage.writeEncrypted(testFile, testData)
        assertTrue(testFile.exists())

        val deleted = secureFileStorage.deleteSecurely(testFile)

        assertTrue(deleted)
        assertFalse(testFile.exists())
    }

    @Test
    fun `test deleteSecurely returns false for non-existent file`() {
        val nonExistentFile = File(testDir, "non_existent.dat")

        val deleted = secureFileStorage.deleteSecurely(nonExistentFile)

        assertFalse(deleted)
    }

    @Test
    fun `test deleteSecurely with multiple overwrite passes`() {
        val testFile = File(testDir, "test_multiple_overwrites.dat")
        val testData = "Data to be overwritten multiple times".toByteArray()

        secureFileStorage.writeEncrypted(testFile, testData)
        assertTrue(testFile.exists())

        val deleted = secureFileStorage.deleteSecurely(testFile, overwritePasses = 5)

        assertTrue(deleted)
        assertFalse(testFile.exists())
    }

    @Test
    fun `test exists returns true for existing file`() {
        val testFile = File(testDir, "test_exists.dat")
        testFile.writeText("test")

        assertTrue(secureFileStorage.exists(testFile))
    }

    @Test
    fun `test exists returns false for non-existent file`() {
        val nonExistentFile = File(testDir, "non_existent.dat")

        assertFalse(secureFileStorage.exists(nonExistentFile))
    }

    @Test
    fun `test delete removes file without secure overwriting`() {
        val testFile = File(testDir, "test_simple_delete.dat")
        testFile.writeText("test")

        assertTrue(testFile.exists())
        val deleted = secureFileStorage.delete(testFile)

        assertTrue(deleted)
        assertFalse(testFile.exists())
    }

    @Test
    fun `test getFileSize returns correct size`() {
        val testFile = File(testDir, "test_size.dat")
        val testData = "Test data for size check".toByteArray()

        secureFileStorage.writeEncrypted(testFile, testData)

        val size = secureFileStorage.getFileSize(testFile)
        assertTrue(size > 0)
    }

    @Test
    fun `test getFileSize returns -1 for non-existent file`() {
        val nonExistentFile = File(testDir, "non_existent.dat")

        val size = secureFileStorage.getFileSize(nonExistentFile)
        assertEquals(-1, size)
    }

    @Test
    fun `test encrypting and decrypting large data`() {
        val testFile = File(testDir, "test_large_data.dat")
        val largeData = ByteArray(10 * 1024) { it.toByte() } // 10KB

        secureFileStorage.writeEncrypted(testFile, largeData)
        val decrypted = secureFileStorage.readDecrypted(testFile)

        assertArrayEquals(largeData, decrypted)
    }

    @Test
    fun `test encrypting and decrypting empty data`() {
        val testFile = File(testDir, "test_empty_data.dat")
        val emptyData = ByteArray(0)

        assertThrows(CryptoOperationException::class.java) {
            secureFileStorage.writeEncrypted(testFile, emptyData)
        }
    }

    @Test
    fun `test encrypting and decrypting unicode string`() {
        val testFile = File(testDir, "test_unicode.txt")
        val unicodeString = "Unicode test: 你好世界 🌍 مرحبا العالم"

        secureFileStorage.writeEncryptedString(testFile, unicodeString)
        val decrypted = secureFileStorage.readDecryptedString(testFile)

        assertEquals(unicodeString, decrypted)
    }

    @Test
    fun `test overwriting existing encrypted file`() {
        val testFile = File(testDir, "test_overwrite.dat")
        val data1 = "Original data".toByteArray()
        val data2 = "New data".toByteArray()

        secureFileStorage.writeEncrypted(testFile, data1)
        assertArrayEquals(data1, secureFileStorage.readDecrypted(testFile))

        secureFileStorage.writeEncrypted(testFile, data2)
        assertArrayEquals(data2, secureFileStorage.readDecrypted(testFile))
    }

    @Test
    fun `test encrypted data is different from plaintext`() {
        val testFile = File(testDir, "test_encrypted_format.dat")
        val plaintext = "Plaintext data"

        secureFileStorage.writeEncryptedString(testFile, plaintext)

        // Read the raw file content (encrypted)
        val rawContent = testFile.readText(Charsets.UTF_8)

        // The encrypted content should not contain the plaintext
        assertFalse(rawContent.contains(plaintext))
    }

    @Test
    fun `test multiple instances with same key can decrypt each other's data`() {
        val testFile = File(testDir, "test_shared_key.dat")
        val testData = "Shared key test".toByteArray()

        secureFileStorage.writeEncrypted(testFile, testData)

        // Create a new instance with the same key alias
        val anotherInstance = SecureFileStorage(testKeyAlias)
        val decrypted = anotherInstance.readDecrypted(testFile)

        assertArrayEquals(testData, decrypted)
    }

    @Test
    fun `test encrypting binary data`() {
        val testFile = File(testDir, "test_binary.dat")
        val binaryData = ByteArray(256) { it.toByte() }

        secureFileStorage.writeEncrypted(testFile, binaryData)
        val decrypted = secureFileStorage.readDecrypted(testFile)

        assertArrayEquals(binaryData, decrypted)
    }

    @Test
    fun `test handling special characters in filename`() {
        val testFile = File(testDir, "test_file_with-special.chars_123.dat")
        val testData = "Test data".toByteArray()

        secureFileStorage.writeEncrypted(testFile, testData)
        val decrypted = secureFileStorage.readDecrypted(testFile)

        assertArrayEquals(testData, decrypted)
    }
}
