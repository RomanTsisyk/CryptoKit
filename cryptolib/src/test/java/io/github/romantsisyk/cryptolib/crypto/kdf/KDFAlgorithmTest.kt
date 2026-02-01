package io.github.romantsisyk.cryptolib.crypto.kdf

import org.junit.Assert.assertEquals
import org.junit.Test

class KDFAlgorithmTest {

    @Test
    fun `test PBKDF2_SHA256 algorithm name`() {
        assertEquals("PBKDF2WithHmacSHA256", KDFAlgorithm.PBKDF2_SHA256.algorithmName)
    }

    @Test
    fun `test PBKDF2_SHA512 algorithm name`() {
        assertEquals("PBKDF2WithHmacSHA512", KDFAlgorithm.PBKDF2_SHA512.algorithmName)
    }

    @Test
    fun `test all enum values are accessible`() {
        val algorithms = KDFAlgorithm.values()
        assertEquals(2, algorithms.size)
        assert(algorithms.contains(KDFAlgorithm.PBKDF2_SHA256))
        assert(algorithms.contains(KDFAlgorithm.PBKDF2_SHA512))
    }
}
