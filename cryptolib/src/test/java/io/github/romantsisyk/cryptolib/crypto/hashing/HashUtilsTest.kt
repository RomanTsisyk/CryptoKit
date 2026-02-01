package io.github.romantsisyk.cryptolib.crypto.hashing

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class HashUtilsTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `test hash ByteArray with SHA256`() {
        val data = "Hello, World!".toByteArray()
        val hash = HashUtils.hash(data, HashAlgorithm.SHA256)

        // SHA-256 produces 32 bytes (256 bits)
        assertEquals(32, hash.size)
    }

    @Test
    fun `test hash String with SHA256 returns hex`() {
        val data = "Hello, World!"
        val hash = HashUtils.hash(data, HashAlgorithm.SHA256)

        // Verify it's a valid hex string (64 characters for 32 bytes)
        assertEquals(64, hash.length)
        assertTrue(hash.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `test hash with different algorithms produces different hashes`() {
        val data = "Test data".toByteArray()

        val sha256Hash = HashUtils.hash(data, HashAlgorithm.SHA256)
        val sha512Hash = HashUtils.hash(data, HashAlgorithm.SHA512)

        // SHA-256 produces 32 bytes, SHA-512 produces 64 bytes
        assertEquals(32, sha256Hash.size)
        assertEquals(64, sha512Hash.size)
    }

    @Test
    fun `test hash is deterministic`() {
        val data = "Deterministic test".toByteArray()

        val hash1 = HashUtils.hash(data, HashAlgorithm.SHA256)
        val hash2 = HashUtils.hash(data, HashAlgorithm.SHA256)

        assertArrayEquals(hash1, hash2)
    }

    @Test
    fun `test hash empty data throws CryptoOperationException`() {
        val emptyData = ByteArray(0)

        assertThrows(CryptoOperationException::class.java) {
            HashUtils.hash(emptyData, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test hash empty string throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            HashUtils.hash("", HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test SHA256 known test vector`() {
        val data = "abc"
        val expectedHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

        val hash = HashUtils.hash(data, HashAlgorithm.SHA256)

        assertEquals(expectedHash, hash)
    }

    @Test
    fun `test SHA512 known test vector`() {
        val data = "abc"
        val expectedHash = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"

        val hash = HashUtils.hash(data, HashAlgorithm.SHA512)

        assertEquals(expectedHash, hash)
    }

    @Test
    @Suppress("DEPRECATION")
    fun `test MD5 hash produces 128-bit output`() {
        val data = "Test".toByteArray()
        val hash = HashUtils.hash(data, HashAlgorithm.MD5)

        // MD5 produces 16 bytes (128 bits)
        assertEquals(16, hash.size)
    }

    @Test
    fun `test hashFile with valid file`() {
        val testFile = tempFolder.newFile("test.txt")
        testFile.writeText("Hello, File!")

        val hash = HashUtils.hashFile(testFile, HashAlgorithm.SHA256)

        // Verify it's a valid hex string
        assertEquals(64, hash.length)
        assertTrue(hash.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `test hashFile is deterministic`() {
        val testFile = tempFolder.newFile("test.txt")
        testFile.writeText("Consistent content")

        val hash1 = HashUtils.hashFile(testFile, HashAlgorithm.SHA256)
        val hash2 = HashUtils.hashFile(testFile, HashAlgorithm.SHA256)

        assertEquals(hash1, hash2)
    }

    @Test
    fun `test hashFile with large file`() {
        val testFile = tempFolder.newFile("large.txt")
        // Create a file larger than the buffer size (8KB)
        val largeContent = "A".repeat(10000)
        testFile.writeText(largeContent)

        val hash = HashUtils.hashFile(testFile, HashAlgorithm.SHA256)

        // Verify hash was computed successfully
        assertEquals(64, hash.length)
        assertTrue(hash.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `test hashFile with non-existent file throws CryptoOperationException`() {
        val nonExistentFile = File(tempFolder.root, "does-not-exist.txt")

        assertThrows(CryptoOperationException::class.java) {
            HashUtils.hashFile(nonExistentFile, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test hashFile with directory throws CryptoOperationException`() {
        val directory = tempFolder.newFolder("testdir")

        assertThrows(CryptoOperationException::class.java) {
            HashUtils.hashFile(directory, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test verifyHash with matching hashes returns true`() {
        val data = "Test data".toByteArray()
        val hash = HashUtils.hash(data, HashAlgorithm.SHA256)

        val result = HashUtils.verifyHash(data, hash, HashAlgorithm.SHA256)

        assertTrue(result)
    }

    @Test
    fun `test verifyHash with non-matching hashes returns false`() {
        val data = "Test data".toByteArray()
        val wrongData = "Wrong data".toByteArray()
        val hash = HashUtils.hash(data, HashAlgorithm.SHA256)

        val result = HashUtils.verifyHash(wrongData, hash, HashAlgorithm.SHA256)

        assertFalse(result)
    }

    @Test
    fun `test verifyHash with empty data throws CryptoOperationException`() {
        val hash = ByteArray(32) { 0 }

        assertThrows(CryptoOperationException::class.java) {
            HashUtils.verifyHash(ByteArray(0), hash, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test verifyHash with empty hash throws CryptoOperationException`() {
        val data = "Test".toByteArray()

        assertThrows(CryptoOperationException::class.java) {
            HashUtils.verifyHash(data, ByteArray(0), HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test bytesToHex conversion`() {
        val bytes = byteArrayOf(0x12, 0x34, 0xAB.toByte(), 0xCD.toByte())
        val hex = HashUtils.bytesToHex(bytes)

        assertEquals("1234abcd", hex)
    }

    @Test
    fun `test bytesToHex with all zeros`() {
        val bytes = ByteArray(4) { 0 }
        val hex = HashUtils.bytesToHex(bytes)

        assertEquals("00000000", hex)
    }

    @Test
    fun `test bytesToHex with all ones`() {
        val bytes = ByteArray(4) { 0xFF.toByte() }
        val hex = HashUtils.bytesToHex(bytes)

        assertEquals("ffffffff", hex)
    }

    @Test
    fun `test hexToBytes conversion`() {
        val hex = "1234abcd"
        val bytes = HashUtils.hexToBytes(hex)

        assertArrayEquals(byteArrayOf(0x12, 0x34, 0xAB.toByte(), 0xCD.toByte()), bytes)
    }

    @Test
    fun `test hexToBytes with uppercase`() {
        val hex = "1234ABCD"
        val bytes = HashUtils.hexToBytes(hex)

        assertArrayEquals(byteArrayOf(0x12, 0x34, 0xAB.toByte(), 0xCD.toByte()), bytes)
    }

    @Test
    fun `test hexToBytes round trip`() {
        val originalBytes = byteArrayOf(0x01, 0x23, 0x45, 0x67, 0x89.toByte(), 0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        val hex = HashUtils.bytesToHex(originalBytes)
        val resultBytes = HashUtils.hexToBytes(hex)

        assertArrayEquals(originalBytes, resultBytes)
    }

    @Test
    fun `test hexToBytes with empty string throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            HashUtils.hexToBytes("")
        }
    }

    @Test
    fun `test hexToBytes with odd length throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            HashUtils.hexToBytes("123")
        }
    }

    @Test
    fun `test hexToBytes with invalid characters throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            HashUtils.hexToBytes("12ZZ")
        }
    }

    @Test
    fun `test SHA3_256 hash produces correct size`() {
        val data = "SHA3 test".toByteArray()
        val hash = HashUtils.hash(data, HashAlgorithm.SHA3_256)

        // SHA3-256 produces 32 bytes (256 bits)
        assertEquals(32, hash.size)
    }

    @Test
    fun `test SHA3_512 hash produces correct size`() {
        val data = "SHA3 test".toByteArray()
        val hash = HashUtils.hash(data, HashAlgorithm.SHA3_512)

        // SHA3-512 produces 64 bytes (512 bits)
        assertEquals(64, hash.size)
    }

    @Test
    fun `test different data produces different hashes`() {
        val data1 = "Data 1".toByteArray()
        val data2 = "Data 2".toByteArray()

        val hash1 = HashUtils.hash(data1, HashAlgorithm.SHA256)
        val hash2 = HashUtils.hash(data2, HashAlgorithm.SHA256)

        assertFalse(hash1.contentEquals(hash2))
    }

    @Test
    fun `test hash file with empty file`() {
        val testFile = tempFolder.newFile("empty.txt")
        // File is created but empty

        val hash = HashUtils.hashFile(testFile, HashAlgorithm.SHA256)

        // Empty file should produce the hash of empty input
        // SHA-256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
    }
}
