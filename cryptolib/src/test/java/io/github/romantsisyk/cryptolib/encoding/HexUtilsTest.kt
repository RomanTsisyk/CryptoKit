package io.github.romantsisyk.cryptolib.encoding

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class HexUtilsTest {

    @Test
    fun `test encode and decode hexadecimal`() {
        val original = "Hello, World!".toByteArray()
        val encoded = HexUtils.encode(original)
        val decoded = HexUtils.decode(encoded)

        assertArrayEquals(original, decoded)
    }

    @Test
    fun `test encode produces uppercase hex string`() {
        val data = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val encoded = HexUtils.encode(data)

        assertEquals("DEADBEEF", encoded)
        assertTrue(encoded.all { it in '0'..'9' || it in 'A'..'F' })
    }

    @Test
    fun `test encodeLowerCase produces lowercase hex string`() {
        val data = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val encoded = HexUtils.encodeLowerCase(data)

        assertEquals("deadbeef", encoded)
        assertTrue(encoded.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun `test decode handles both uppercase and lowercase`() {
        val data = byteArrayOf(0xAB.toByte(), 0xCD.toByte())

        val decodedUpper = HexUtils.decode("ABCD")
        val decodedLower = HexUtils.decode("abcd")
        val decodedMixed = HexUtils.decode("AbCd")

        assertArrayEquals(data, decodedUpper)
        assertArrayEquals(data, decodedLower)
        assertArrayEquals(data, decodedMixed)
    }

    @Test
    fun `test decode with empty string throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            HexUtils.decode("")
        }
    }

    @Test
    fun `test decode with odd length throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            HexUtils.decode("ABC")
        }
    }

    @Test
    fun `test decode with invalid hex characters throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            HexUtils.decode("GHIJ")
        }
    }

    @Test
    fun `test isValidHex with valid input returns true`() {
        assertTrue(HexUtils.isValidHex("DEADBEEF"))
        assertTrue(HexUtils.isValidHex("deadbeef"))
        assertTrue(HexUtils.isValidHex("0123456789ABCDEF"))
        assertTrue(HexUtils.isValidHex("0123456789abcdef"))
    }

    @Test
    fun `test isValidHex with invalid input returns false`() {
        assertFalse(HexUtils.isValidHex("GHIJ"))
        assertFalse(HexUtils.isValidHex("not hex"))
        assertFalse(HexUtils.isValidHex(""))
        assertFalse(HexUtils.isValidHex("ABC")) // Odd length
    }

    @Test
    fun `test encode and decode with all byte values`() {
        val allBytes = ByteArray(256) { it.toByte() }
        val encoded = HexUtils.encode(allBytes)
        val decoded = HexUtils.decode(encoded)

        assertArrayEquals(allBytes, decoded)
    }

    @Test
    fun `test encode produces correct length`() {
        val data = ByteArray(10) { it.toByte() }
        val encoded = HexUtils.encode(data)

        assertEquals(data.size * 2, encoded.length)
    }

    @Test
    fun `test encodeLowerCase and decode`() {
        val original = "Test data 123!".toByteArray()
        val encoded = HexUtils.encodeLowerCase(original)
        val decoded = HexUtils.decode(encoded)

        assertArrayEquals(original, decoded)
    }

    @Test
    fun `test encode and decode zero bytes`() {
        val zeros = ByteArray(5) { 0x00 }
        val encoded = HexUtils.encode(zeros)
        val decoded = HexUtils.decode(encoded)

        assertEquals("0000000000", encoded)
        assertArrayEquals(zeros, decoded)
    }

    @Test
    fun `test encode and decode max bytes`() {
        val maxBytes = ByteArray(3) { 0xFF.toByte() }
        val encoded = HexUtils.encode(maxBytes)
        val decoded = HexUtils.decode(encoded)

        assertEquals("FFFFFF", encoded)
        assertArrayEquals(maxBytes, decoded)
    }

    @Test
    fun `test isValidHex with mixed case returns true`() {
        assertTrue(HexUtils.isValidHex("AaBbCc"))
    }

    @Test
    fun `test encode and decode with single byte`() {
        val singleByte = byteArrayOf(0x42)
        val encoded = HexUtils.encode(singleByte)
        val decoded = HexUtils.decode(encoded)

        assertEquals("42", encoded)
        assertArrayEquals(singleByte, decoded)
    }

    @Test
    fun `test encode empty byte array`() {
        val empty = ByteArray(0)
        val encoded = HexUtils.encode(empty)

        assertEquals("", encoded)
    }
}
