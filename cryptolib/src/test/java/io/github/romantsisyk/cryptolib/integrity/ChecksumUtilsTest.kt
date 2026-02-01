package io.github.romantsisyk.cryptolib.integrity

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.File

class ChecksumUtilsTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val testData = "Hello, World!".toByteArray()

    @Test
    fun `test calculateChecksum with CRC32`() {
        val checksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.CRC32)
        assertNotEquals("", checksum)
        // CRC32 should produce 8 hex characters
        assertEquals(8, checksum.length)
    }

    @Test
    fun `test calculateChecksum with ADLER32`() {
        val checksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.ADLER32)
        assertNotEquals("", checksum)
        // ADLER32 should produce 8 hex characters
        assertEquals(8, checksum.length)
    }

    @Test
    fun `test calculateChecksum with MD5`() {
        val checksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.MD5)
        assertNotEquals("", checksum)
        // MD5 should produce 32 hex characters (128 bits)
        assertEquals(32, checksum.length)
    }

    @Test
    fun `test calculateChecksum with SHA256`() {
        val checksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA256)
        assertNotEquals("", checksum)
        // SHA256 should produce 64 hex characters (256 bits)
        assertEquals(64, checksum.length)
    }

    @Test
    fun `test calculateChecksum with SHA512`() {
        val checksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA512)
        assertNotEquals("", checksum)
        // SHA512 should produce 128 hex characters (512 bits)
        assertEquals(128, checksum.length)
    }

    @Test
    fun `test calculateChecksum with empty data throws exception`() {
        assertThrows(CryptoOperationException::class.java) {
            ChecksumUtils.calculateChecksum(ByteArray(0), ChecksumAlgorithm.SHA256)
        }
    }

    @Test
    fun `test calculateChecksum produces consistent results`() {
        val checksum1 = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA256)
        val checksum2 = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA256)
        assertEquals(checksum1, checksum2)
    }

    @Test
    fun `test calculateChecksum with different data produces different checksums`() {
        val data1 = "Hello, World!".toByteArray()
        val data2 = "Hello, World?".toByteArray()

        val checksum1 = ChecksumUtils.calculateChecksum(data1, ChecksumAlgorithm.SHA256)
        val checksum2 = ChecksumUtils.calculateChecksum(data2, ChecksumAlgorithm.SHA256)

        assertNotEquals(checksum1, checksum2)
    }

    @Test
    fun `test calculateChecksum for file`() {
        val file = tempFolder.newFile("test.txt")
        file.writeBytes(testData)

        val checksum = ChecksumUtils.calculateChecksum(file, ChecksumAlgorithm.SHA256)
        assertNotEquals("", checksum)
        assertEquals(64, checksum.length)
    }

    @Test
    fun `test calculateChecksum for file matches byte array checksum`() {
        val file = tempFolder.newFile("test.txt")
        file.writeBytes(testData)

        val fileChecksum = ChecksumUtils.calculateChecksum(file, ChecksumAlgorithm.SHA256)
        val byteChecksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA256)

        assertEquals(byteChecksum, fileChecksum)
    }

    @Test
    fun `test calculateChecksum for non-existent file throws exception`() {
        val nonExistentFile = File(tempFolder.root, "non_existent.txt")

        assertThrows(CryptoOperationException::class.java) {
            ChecksumUtils.calculateChecksum(nonExistentFile, ChecksumAlgorithm.SHA256)
        }
    }

    @Test
    fun `test calculateChecksum from input stream`() {
        val inputStream = ByteArrayInputStream(testData)
        val checksum = ChecksumUtils.calculateChecksum(inputStream, ChecksumAlgorithm.SHA256)

        assertNotEquals("", checksum)
        assertEquals(64, checksum.length)
    }

    @Test
    fun `test calculateChecksum from input stream matches byte array checksum`() {
        val inputStream = ByteArrayInputStream(testData)
        val streamChecksum = ChecksumUtils.calculateChecksum(inputStream, ChecksumAlgorithm.SHA256)
        val byteChecksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA256)

        assertEquals(byteChecksum, streamChecksum)
    }

    @Test
    fun `test verifyChecksum with valid checksum returns true`() {
        val checksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA256)
        val isValid = ChecksumUtils.verifyChecksum(testData, checksum, ChecksumAlgorithm.SHA256)

        assertTrue(isValid)
    }

    @Test
    fun `test verifyChecksum with invalid checksum returns false`() {
        val invalidChecksum = "0000000000000000000000000000000000000000000000000000000000000000"
        val isValid = ChecksumUtils.verifyChecksum(testData, invalidChecksum, ChecksumAlgorithm.SHA256)

        assertFalse(isValid)
    }

    @Test
    fun `test verifyChecksum is case insensitive`() {
        val checksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA256)
        val uppercaseChecksum = checksum.uppercase()

        assertTrue(ChecksumUtils.verifyChecksum(testData, uppercaseChecksum, ChecksumAlgorithm.SHA256))
    }

    @Test
    fun `test verifyChecksum for file with valid checksum returns true`() {
        val file = tempFolder.newFile("test.txt")
        file.writeBytes(testData)

        val checksum = ChecksumUtils.calculateChecksum(file, ChecksumAlgorithm.SHA256)
        val isValid = ChecksumUtils.verifyChecksum(file, checksum, ChecksumAlgorithm.SHA256)

        assertTrue(isValid)
    }

    @Test
    fun `test verifyChecksum for file with invalid checksum returns false`() {
        val file = tempFolder.newFile("test.txt")
        file.writeBytes(testData)

        val invalidChecksum = "0000000000000000000000000000000000000000000000000000000000000000"
        val isValid = ChecksumUtils.verifyChecksum(file, invalidChecksum, ChecksumAlgorithm.SHA256)

        assertFalse(isValid)
    }

    @Test
    fun `test verifyChecksum after data modification returns false`() {
        val checksum = ChecksumUtils.calculateChecksum(testData, ChecksumAlgorithm.SHA256)
        val modifiedData = "Hello, World?".toByteArray()

        val isValid = ChecksumUtils.verifyChecksum(modifiedData, checksum, ChecksumAlgorithm.SHA256)
        assertFalse(isValid)
    }

    @Test
    fun `test large data checksum calculation`() {
        // Create a large byte array (1MB)
        val largeData = ByteArray(1024 * 1024) { it.toByte() }

        val checksum = ChecksumUtils.calculateChecksum(largeData, ChecksumAlgorithm.SHA256)
        assertNotEquals("", checksum)
        assertEquals(64, checksum.length)

        // Verify it
        assertTrue(ChecksumUtils.verifyChecksum(largeData, checksum, ChecksumAlgorithm.SHA256))
    }

    @Test
    fun `test stream checksum with large data`() {
        // Create a large byte array (1MB)
        val largeData = ByteArray(1024 * 1024) { it.toByte() }
        val inputStream = ByteArrayInputStream(largeData)

        val streamChecksum = ChecksumUtils.calculateChecksum(inputStream, ChecksumAlgorithm.SHA256)
        val byteChecksum = ChecksumUtils.calculateChecksum(largeData, ChecksumAlgorithm.SHA256)

        assertEquals(byteChecksum, streamChecksum)
    }
}
