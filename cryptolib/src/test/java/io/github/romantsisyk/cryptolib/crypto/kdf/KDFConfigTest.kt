package io.github.romantsisyk.cryptolib.crypto.kdf

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class KDFConfigTest {

    @Test
    fun `test default config values`() {
        val config = KDFConfig.Builder().build()

        assertEquals(KDFConfig.DEFAULT_ITERATIONS, config.iterations)
        assertEquals(KDFConfig.DEFAULT_KEY_LENGTH, config.keyLength)
        assertEquals(KDFConfig.DEFAULT_ALGORITHM, config.algorithm)
    }

    @Test
    fun `test getDefault creates valid config`() {
        val config = KDFConfig.getDefault()

        assertEquals(100000, config.iterations)
        assertEquals(256, config.keyLength)
        assertEquals(KDFAlgorithm.PBKDF2_SHA256, config.algorithm)
    }

    @Test
    fun `test builder with custom iterations`() {
        val config = KDFConfig.Builder()
            .iterations(200000)
            .build()

        assertEquals(200000, config.iterations)
    }

    @Test
    fun `test builder with custom key length`() {
        val config = KDFConfig.Builder()
            .keyLength(512)
            .build()

        assertEquals(512, config.keyLength)
    }

    @Test
    fun `test builder with custom algorithm`() {
        val config = KDFConfig.Builder()
            .algorithm(KDFAlgorithm.PBKDF2_SHA512)
            .build()

        assertEquals(KDFAlgorithm.PBKDF2_SHA512, config.algorithm)
    }

    @Test
    fun `test builder with all custom values`() {
        val config = KDFConfig.Builder()
            .iterations(150000)
            .keyLength(384)
            .algorithm(KDFAlgorithm.PBKDF2_SHA512)
            .build()

        assertEquals(150000, config.iterations)
        assertEquals(384, config.keyLength)
        assertEquals(KDFAlgorithm.PBKDF2_SHA512, config.algorithm)
    }

    @Test
    fun `test builder throws on zero iterations`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            KDFConfig.Builder()
                .iterations(0)
                .build()
        }
        assert(exception.message!!.contains("iterations must be greater than 0"))
    }

    @Test
    fun `test builder throws on negative iterations`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            KDFConfig.Builder()
                .iterations(-100)
                .build()
        }
        assert(exception.message!!.contains("iterations must be greater than 0"))
    }

    @Test
    fun `test builder throws on iterations below minimum`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            KDFConfig.Builder()
                .iterations(5000)
                .build()
        }
        assert(exception.message!!.contains("iterations should be at least"))
    }

    @Test
    fun `test builder throws on zero key length`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            KDFConfig.Builder()
                .keyLength(0)
                .build()
        }
        assert(exception.message!!.contains("keyLength must be greater than 0"))
    }

    @Test
    fun `test builder throws on negative key length`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            KDFConfig.Builder()
                .keyLength(-256)
                .build()
        }
        assert(exception.message!!.contains("keyLength must be greater than 0"))
    }

    @Test
    fun `test builder throws on key length not multiple of 8`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            KDFConfig.Builder()
                .keyLength(257)
                .build()
        }
        assert(exception.message!!.contains("keyLength must be a multiple of 8"))
    }

    @Test
    fun `test builder throws on key length below minimum`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            KDFConfig.Builder()
                .keyLength(64)
                .build()
        }
        assert(exception.message!!.contains("keyLength should be at least"))
    }

    @Test
    fun `test builder accepts minimum valid iterations`() {
        val config = KDFConfig.Builder()
            .iterations(KDFConfig.MIN_ITERATIONS)
            .build()

        assertEquals(KDFConfig.MIN_ITERATIONS, config.iterations)
    }

    @Test
    fun `test builder accepts minimum valid key length`() {
        val config = KDFConfig.Builder()
            .keyLength(KDFConfig.MIN_KEY_LENGTH)
            .build()

        assertEquals(KDFConfig.MIN_KEY_LENGTH, config.keyLength)
    }

    @Test
    fun `test builder fluent interface chaining`() {
        val config = KDFConfig.Builder()
            .iterations(120000)
            .keyLength(256)
            .algorithm(KDFAlgorithm.PBKDF2_SHA512)
            .build()

        assertEquals(120000, config.iterations)
        assertEquals(256, config.keyLength)
        assertEquals(KDFAlgorithm.PBKDF2_SHA512, config.algorithm)
    }
}
