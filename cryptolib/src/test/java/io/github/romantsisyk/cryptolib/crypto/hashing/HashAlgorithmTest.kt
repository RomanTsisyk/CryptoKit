package io.github.romantsisyk.cryptolib.crypto.hashing

import org.junit.Assert.assertEquals
import org.junit.Test

class HashAlgorithmTest {

    @Test
    fun `test SHA256 algorithm name`() {
        assertEquals("SHA-256", HashAlgorithm.SHA256.algorithmName)
    }

    @Test
    fun `test SHA384 algorithm name`() {
        assertEquals("SHA-384", HashAlgorithm.SHA384.algorithmName)
    }

    @Test
    fun `test SHA512 algorithm name`() {
        assertEquals("SHA-512", HashAlgorithm.SHA512.algorithmName)
    }

    @Test
    fun `test SHA3_256 algorithm name`() {
        assertEquals("SHA3-256", HashAlgorithm.SHA3_256.algorithmName)
    }

    @Test
    fun `test SHA3_512 algorithm name`() {
        assertEquals("SHA3-512", HashAlgorithm.SHA3_512.algorithmName)
    }

    @Test
    fun `test MD5 algorithm name`() {
        @Suppress("DEPRECATION")
        assertEquals("MD5", HashAlgorithm.MD5.algorithmName)
    }

    @Test
    fun `test SHA256 HMAC algorithm conversion`() {
        assertEquals("HmacSHA256", HashAlgorithm.SHA256.toHmacAlgorithm())
    }

    @Test
    fun `test SHA384 HMAC algorithm conversion`() {
        assertEquals("HmacSHA384", HashAlgorithm.SHA384.toHmacAlgorithm())
    }

    @Test
    fun `test SHA512 HMAC algorithm conversion`() {
        assertEquals("HmacSHA512", HashAlgorithm.SHA512.toHmacAlgorithm())
    }

    @Test
    fun `test SHA3_256 HMAC algorithm conversion`() {
        assertEquals("HmacSHA3256", HashAlgorithm.SHA3_256.toHmacAlgorithm())
    }

    @Test
    fun `test SHA3_512 HMAC algorithm conversion`() {
        assertEquals("HmacSHA3512", HashAlgorithm.SHA3_512.toHmacAlgorithm())
    }

    @Test
    fun `test MD5 HMAC algorithm conversion`() {
        @Suppress("DEPRECATION")
        assertEquals("HmacMD5", HashAlgorithm.MD5.toHmacAlgorithm())
    }

    @Test
    fun `test all algorithms are unique`() {
        val algorithms = HashAlgorithm.values()
        val uniqueNames = algorithms.map { it.algorithmName }.toSet()
        assertEquals(algorithms.size, uniqueNames.size)
    }
}
