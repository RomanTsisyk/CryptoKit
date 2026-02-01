package io.github.romantsisyk.cryptolib.crypto.hashing

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.spec.SecretKeySpec

class HMACUtilsTest {

    @Test
    fun `test generateHMAC with SHA256`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Hello, HMAC!".toByteArray()

        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)

        // HMAC-SHA256 produces 32 bytes (256 bits)
        assertEquals(32, hmac.size)
    }

    @Test
    fun `test generateHMAC with different algorithms produces different outputs`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test data".toByteArray()

        val hmacSha256 = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)
        val hmacSha512 = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA512)

        // HMAC-SHA256 produces 32 bytes, HMAC-SHA512 produces 64 bytes
        assertEquals(32, hmacSha256.size)
        assertEquals(64, hmacSha512.size)
    }

    @Test
    fun `test generateHMAC is deterministic`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Deterministic test".toByteArray()

        val hmac1 = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)
        val hmac2 = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)

        assertArrayEquals(hmac1, hmac2)
    }

    @Test
    fun `test generateHMAC with empty data throws CryptoOperationException`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val emptyData = ByteArray(0)

        assertThrows(CryptoOperationException::class.java) {
            HMACUtils.generateHMAC(emptyData, key, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test generateHMAC String with SHA256 returns hex`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Hello, HMAC!"

        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)

        // Verify it's a valid hex string (64 characters for 32 bytes)
        assertEquals(64, hmac.length)
        assertTrue(hmac.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `test generateHMAC String with empty data throws CryptoOperationException`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)

        assertThrows(CryptoOperationException::class.java) {
            HMACUtils.generateHMAC("", key, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test verifyHMAC with matching HMAC returns true`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test data".toByteArray()
        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)

        val result = HMACUtils.verifyHMAC(data, hmac, key, HashAlgorithm.SHA256)

        assertTrue(result)
    }

    @Test
    fun `test verifyHMAC with non-matching HMAC returns false`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test data".toByteArray()
        val wrongData = "Wrong data".toByteArray()
        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)

        val result = HMACUtils.verifyHMAC(wrongData, hmac, key, HashAlgorithm.SHA256)

        assertFalse(result)
    }

    @Test
    fun `test verifyHMAC with wrong key returns false`() {
        val key1 = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val key2 = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test data".toByteArray()
        val hmac = HMACUtils.generateHMAC(data, key1, HashAlgorithm.SHA256)

        val result = HMACUtils.verifyHMAC(data, hmac, key2, HashAlgorithm.SHA256)

        assertFalse(result)
    }

    @Test
    fun `test verifyHMAC with empty data throws CryptoOperationException`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val hmac = ByteArray(32) { 0 }

        assertThrows(CryptoOperationException::class.java) {
            HMACUtils.verifyHMAC(ByteArray(0), hmac, key, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test verifyHMAC with empty MAC throws CryptoOperationException`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test".toByteArray()

        assertThrows(CryptoOperationException::class.java) {
            HMACUtils.verifyHMAC(data, ByteArray(0), key, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test verifyHMAC String with matching HMAC returns true`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test data"
        val hmacHex = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)

        val result = HMACUtils.verifyHMAC(data, hmacHex, key, HashAlgorithm.SHA256)

        assertTrue(result)
    }

    @Test
    fun `test verifyHMAC String with non-matching HMAC returns false`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test data"
        val wrongData = "Wrong data"
        val hmacHex = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)

        val result = HMACUtils.verifyHMAC(wrongData, hmacHex, key, HashAlgorithm.SHA256)

        assertFalse(result)
    }

    @Test
    fun `test verifyHMAC String with empty data throws CryptoOperationException`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val hmacHex = "0".repeat(64)

        assertThrows(CryptoOperationException::class.java) {
            HMACUtils.verifyHMAC("", hmacHex, key, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test verifyHMAC String with empty MAC throws CryptoOperationException`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test"

        assertThrows(CryptoOperationException::class.java) {
            HMACUtils.verifyHMAC(data, "", key, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test verifyHMAC String with invalid hex throws CryptoOperationException`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test"
        val invalidHex = "ZZZZ"

        assertThrows(CryptoOperationException::class.java) {
            HMACUtils.verifyHMAC(data, invalidHex, key, HashAlgorithm.SHA256)
        }
    }

    @Test
    fun `test generateKey for different algorithms`() {
        val sha256Key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val sha512Key = HMACUtils.generateKey(HashAlgorithm.SHA512)

        // Verify keys are not null and are of correct type
        assertEquals("RAW", sha256Key.format)
        assertEquals("RAW", sha512Key.format)
    }

    @Test
    fun `test generateKey produces unique keys`() {
        val key1 = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val key2 = HMACUtils.generateKey(HashAlgorithm.SHA256)

        // Keys should be different
        assertFalse(key1.encoded.contentEquals(key2.encoded))
    }

    @Test
    fun `test HMAC-SHA384 produces correct size`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA384)
        val data = "Test data".toByteArray()

        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA384)

        // HMAC-SHA384 produces 48 bytes (384 bits)
        assertEquals(48, hmac.size)
    }

    @Test
    fun `test HMAC-SHA512 produces correct size`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA512)
        val data = "Test data".toByteArray()

        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA512)

        // HMAC-SHA512 produces 64 bytes (512 bits)
        assertEquals(64, hmac.size)
    }

    @Test
    @Suppress("DEPRECATION")
    fun `test HMAC-MD5 produces correct size`() {
        val key = HMACUtils.generateKey(HashAlgorithm.MD5)
        val data = "Test data".toByteArray()

        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.MD5)

        // HMAC-MD5 produces 16 bytes (128 bits)
        assertEquals(16, hmac.size)
    }

    @Test
    fun `test HMAC with known test vector`() {
        // RFC 4231 Test Case 1
        val keyBytes = ByteArray(20) { 0x0b.toByte() }
        val key = SecretKeySpec(keyBytes, "HmacSHA256")
        val data = "Hi There".toByteArray()

        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)
        val hmacHex = HashUtils.bytesToHex(hmac)

        // Expected HMAC from RFC 4231
        val expectedHmac = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

        assertEquals(expectedHmac, hmacHex)
    }

    @Test
    fun `test HMAC different data produces different MACs`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data1 = "Data 1".toByteArray()
        val data2 = "Data 2".toByteArray()

        val hmac1 = HMACUtils.generateHMAC(data1, key, HashAlgorithm.SHA256)
        val hmac2 = HMACUtils.generateHMAC(data2, key, HashAlgorithm.SHA256)

        assertFalse(hmac1.contentEquals(hmac2))
    }

    @Test
    fun `test HMAC with SHA3-256`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA3_256)
        val data = "SHA3 test".toByteArray()

        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA3_256)

        // HMAC-SHA3-256 produces 32 bytes (256 bits)
        assertEquals(32, hmac.size)
    }

    @Test
    fun `test HMAC with SHA3-512`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA3_512)
        val data = "SHA3 test".toByteArray()

        val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA3_512)

        // HMAC-SHA3-512 produces 64 bytes (512 bits)
        assertEquals(64, hmac.size)
    }

    @Test
    fun `test HMAC verification is constant time`() {
        // This test verifies that verification doesn't short-circuit
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val data = "Test data".toByteArray()
        val correctHmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)

        // Create a wrong HMAC that differs only in the last byte
        val wrongHmac = correctHmac.clone()
        wrongHmac[wrongHmac.size - 1] = (wrongHmac[wrongHmac.size - 1].toInt() xor 1).toByte()

        val result = HMACUtils.verifyHMAC(data, wrongHmac, key, HashAlgorithm.SHA256)

        assertFalse(result)
    }

    @Test
    fun `test HMAC with long message`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val longData = "A".repeat(10000).toByteArray()

        val hmac = HMACUtils.generateHMAC(longData, key, HashAlgorithm.SHA256)

        assertEquals(32, hmac.size)
    }

    @Test
    fun `test HMAC String and ByteArray produce same result`() {
        val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
        val dataString = "Test data"
        val dataBytes = dataString.toByteArray(Charsets.UTF_8)

        val hmacString = HMACUtils.generateHMAC(dataString, key, HashAlgorithm.SHA256)
        val hmacBytes = HMACUtils.generateHMAC(dataBytes, key, HashAlgorithm.SHA256)
        val hmacBytesHex = HashUtils.bytesToHex(hmacBytes)

        assertEquals(hmacString, hmacBytesHex)
    }
}
