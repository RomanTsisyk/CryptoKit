package io.github.romantsisyk.cryptolib.encoding

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.charset.StandardCharsets

class EncodingUtilsTest {

    @Test
    fun `test bytesToString with UTF-8`() {
        val data = "Hello, World!".toByteArray(StandardCharsets.UTF_8)
        val result = EncodingUtils.bytesToString(data)

        assertEquals("Hello, World!", result)
    }

    @Test
    fun `test bytesToString with custom charset`() {
        val data = "Test".toByteArray(StandardCharsets.US_ASCII)
        val result = EncodingUtils.bytesToString(data, StandardCharsets.US_ASCII)

        assertEquals("Test", result)
    }

    @Test
    fun `test stringToBytes with UTF-8`() {
        val str = "Hello, World!"
        val result = EncodingUtils.stringToBytes(str)

        assertArrayEquals(str.toByteArray(StandardCharsets.UTF_8), result)
    }

    @Test
    fun `test stringToBytes with custom charset`() {
        val str = "Test"
        val result = EncodingUtils.stringToBytes(str, StandardCharsets.US_ASCII)

        assertArrayEquals(str.toByteArray(StandardCharsets.US_ASCII), result)
    }

    @Test
    fun `test bytesToString and stringToBytes roundtrip`() {
        val original = "Unicode: こんにちは 世界!"
        val bytes = EncodingUtils.stringToBytes(original)
        val result = EncodingUtils.bytesToString(bytes)

        assertEquals(original, result)
    }

    @Test
    fun `test toBase64 and fromBase64`() {
        val original = "Test data".toByteArray()
        val encoded = EncodingUtils.toBase64(original)
        val decoded = EncodingUtils.fromBase64(encoded)

        assertArrayEquals(original, decoded)
    }

    @Test
    fun `test toBase64 produces correct output`() {
        val data = "test".toByteArray()
        val encoded = EncodingUtils.toBase64(data)

        assertEquals("dGVzdA==", encoded)
    }

    @Test
    fun `test fromBase64 with invalid input throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            EncodingUtils.fromBase64("invalid!!!base64")
        }
    }

    @Test
    fun `test toHex and fromHex`() {
        val original = "Test data".toByteArray()
        val encoded = EncodingUtils.toHex(original)
        val decoded = EncodingUtils.fromHex(encoded)

        assertArrayEquals(original, decoded)
    }

    @Test
    fun `test toHex produces uppercase hex`() {
        val data = byteArrayOf(0xAB.toByte(), 0xCD.toByte())
        val encoded = EncodingUtils.toHex(data)

        assertEquals("ABCD", encoded)
    }

    @Test
    fun `test fromHex with invalid input throws CryptoOperationException`() {
        assertThrows(CryptoOperationException::class.java) {
            EncodingUtils.fromHex("GHIJ")
        }
    }

    @Test
    fun `test all encoding methods with same data`() {
        val original = "Encode me!".toByteArray()

        // Test Base64
        val base64 = EncodingUtils.toBase64(original)
        val fromBase64 = EncodingUtils.fromBase64(base64)
        assertArrayEquals(original, fromBase64)

        // Test Hex
        val hex = EncodingUtils.toHex(original)
        val fromHex = EncodingUtils.fromHex(hex)
        assertArrayEquals(original, fromHex)

        // Test String conversion
        val str = EncodingUtils.bytesToString(original)
        val bytes = EncodingUtils.stringToBytes(str)
        assertArrayEquals(original, bytes)
    }

    @Test
    fun `test bytesToString with empty array`() {
        val empty = ByteArray(0)
        val result = EncodingUtils.bytesToString(empty)

        assertEquals("", result)
    }

    @Test
    fun `test stringToBytes with empty string`() {
        val result = EncodingUtils.stringToBytes("")

        assertArrayEquals(ByteArray(0), result)
    }

    @Test
    fun `test toBase64 with binary data`() {
        val binary = ByteArray(256) { it.toByte() }
        val encoded = EncodingUtils.toBase64(binary)
        val decoded = EncodingUtils.fromBase64(encoded)

        assertArrayEquals(binary, decoded)
    }

    @Test
    fun `test toHex with binary data`() {
        val binary = ByteArray(256) { it.toByte() }
        val encoded = EncodingUtils.toHex(binary)
        val decoded = EncodingUtils.fromHex(encoded)

        assertArrayEquals(binary, decoded)
    }

    @Test
    fun `test stringToBytes with special characters`() {
        val specialChars = "Special: \n\t\r\u0000"
        val bytes = EncodingUtils.stringToBytes(specialChars)
        val result = EncodingUtils.bytesToString(bytes)

        assertEquals(specialChars, result)
    }

    @Test
    fun `test bytesToString with UTF-8 multibyte characters`() {
        val utf8Text = "Emoji: 😀🎉 Japanese: 日本語"
        val bytes = utf8Text.toByteArray(StandardCharsets.UTF_8)
        val result = EncodingUtils.bytesToString(bytes)

        assertEquals(utf8Text, result)
    }
}
