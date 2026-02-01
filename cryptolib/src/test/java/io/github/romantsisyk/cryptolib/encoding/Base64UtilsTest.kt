package io.github.romantsisyk.cryptolib.encoding

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class Base64UtilsTest {

    @Test
    fun `test encode and decode standard Base64`() {
        val original = "Hello, World!".toByteArray()
        val encoded = Base64Utils.encode(original)
        val decoded = Base64Utils.decode(encoded)

        assertArrayEquals(original, decoded)
    }

    @Test
    fun `test encode produces correct Base64 string`() {
        val data = "test".toByteArray()
        val encoded = Base64Utils.encode(data)

        assertEquals("dGVzdA==", encoded)
    }

    @Test
    fun `test decode produces correct byte array`() {
        val encoded = "dGVzdA=="
        val decoded = Base64Utils.decode(encoded)

        assertArrayEquals("test".toByteArray(), decoded)
    }

    @Test
    fun `test encodeUrlSafe and decodeUrlSafe`() {
        val original = "Hello, World! With special chars: +/=".toByteArray()
        val encoded = Base64Utils.encodeUrlSafe(original)
        val decoded = Base64Utils.decodeUrlSafe(encoded)

        assertArrayEquals(original, decoded)
        // URL-safe encoding should not contain + or / characters
        assertFalse(encoded.contains('+'))
        assertFalse(encoded.contains('/'))
        assertFalse(encoded.contains('=')) // No padding
    }

    @Test
    fun `test encodeUrlSafe produces URL-safe characters`() {
        // This byte array will produce + and / in standard Base64
        val data = byteArrayOf(0x3E.toByte(), 0x3F.toByte(), 0xFE.toByte(), 0xFF.toByte())
        val encoded = Base64Utils.encodeUrlSafe(data)

        assertTrue(encoded.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' })
    }

    @Test
    fun `test decode with empty string throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            Base64Utils.decode("")
        }
    }

    @Test
    fun `test decodeUrlSafe with empty string throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            Base64Utils.decodeUrlSafe("")
        }
    }

    @Test
    fun `test decode with invalid Base64 throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            Base64Utils.decode("!!!invalid@@@")
        }
    }

    @Test
    fun `test decodeUrlSafe with invalid Base64 throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            Base64Utils.decodeUrlSafe("!!!invalid@@@")
        }
    }

    @Test
    fun `test isValidBase64 with valid input returns true`() {
        val validBase64 = Base64Utils.encode("test data".toByteArray())
        assertTrue(Base64Utils.isValidBase64(validBase64))
    }

    @Test
    fun `test isValidBase64 with invalid input returns false`() {
        assertFalse(Base64Utils.isValidBase64("not valid base64!!!"))
    }

    @Test
    fun `test isValidBase64 with empty string returns false`() {
        assertFalse(Base64Utils.isValidBase64(""))
    }

    @Test
    fun `test isValidBase64 with standard test vectors`() {
        assertTrue(Base64Utils.isValidBase64("SGVsbG8gV29ybGQh"))
        assertTrue(Base64Utils.isValidBase64("dGVzdA=="))
        assertFalse(Base64Utils.isValidBase64("invalid@#$"))
    }

    @Test
    fun `test encode and decode with binary data`() {
        val binary = ByteArray(256) { it.toByte() }
        val encoded = Base64Utils.encode(binary)
        val decoded = Base64Utils.decode(encoded)

        assertArrayEquals(binary, decoded)
    }

    @Test
    fun `test encode and decode empty byte array`() {
        val empty = ByteArray(0)
        val encoded = Base64Utils.encode(empty)
        val decoded = Base64Utils.decode(encoded)

        assertEquals("", encoded)
        assertArrayEquals(empty, decoded)
    }

    @Test
    fun `test encodeUrlSafe and decodeUrlSafe with large data`() {
        val largeData = ByteArray(1024) { (it % 256).toByte() }
        val encoded = Base64Utils.encodeUrlSafe(largeData)
        val decoded = Base64Utils.decodeUrlSafe(encoded)

        assertArrayEquals(largeData, decoded)
    }
}
