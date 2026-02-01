package io.github.romantsisyk.cryptolib.crypto.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoConfigTest {

    // ========== Default Values Tests ==========

    @Test
    fun `test default values are set correctly`() {
        val config = CryptoConfig.Builder("test-key-alias").build()

        assertEquals("test-key-alias", config.keyAlias)
        assertFalse(config.requireUserAuthentication)
        assertEquals(90, config.keyRotationIntervalDays)
        assertEquals(365, config.keyValidityDays)
    }

    @Test
    fun `test default requireUserAuthentication is false`() {
        val config = CryptoConfig.Builder("test-key").build()
        assertFalse(config.requireUserAuthentication)
    }

    @Test
    fun `test default keyRotationIntervalDays is 90`() {
        val config = CryptoConfig.Builder("test-key").build()
        assertEquals(90, config.keyRotationIntervalDays)
    }

    @Test
    fun `test default keyValidityDays is 365`() {
        val config = CryptoConfig.Builder("test-key").build()
        assertEquals(365, config.keyValidityDays)
    }

    // ========== Builder Pattern Tests ==========

    @Test
    fun `test Builder with custom values works`() {
        val config = CryptoConfig.Builder("custom-alias")
            .requireUserAuthentication(true)
            .keyRotationIntervalDays(30)
            .keyValidityDays(180)
            .build()

        assertEquals("custom-alias", config.keyAlias)
        assertTrue(config.requireUserAuthentication)
        assertEquals(30, config.keyRotationIntervalDays)
        assertEquals(180, config.keyValidityDays)
    }

    @Test
    fun `test Builder fluent interface returns same builder instance`() {
        val builder = CryptoConfig.Builder("test-alias")
        val returnedBuilder = builder.requireUserAuthentication(true)

        assertEquals(builder, returnedBuilder)
    }

    @Test
    fun `test Builder chaining works correctly`() {
        val config = CryptoConfig.Builder("chained-alias")
            .requireUserAuthentication(true)
            .keyRotationIntervalDays(45)
            .keyValidityDays(200)
            .build()

        assertEquals("chained-alias", config.keyAlias)
        assertTrue(config.requireUserAuthentication)
        assertEquals(45, config.keyRotationIntervalDays)
        assertEquals(200, config.keyValidityDays)
    }

    @Test
    fun `test Builder can be reused after build`() {
        val builder = CryptoConfig.Builder("reusable-key")
            .requireUserAuthentication(true)
            .keyRotationIntervalDays(30)
            .keyValidityDays(90)

        val config1 = builder.build()
        val config2 = builder.build()

        assertEquals(config1.keyAlias, config2.keyAlias)
        assertEquals(config1.requireUserAuthentication, config2.requireUserAuthentication)
        assertEquals(config1.keyRotationIntervalDays, config2.keyRotationIntervalDays)
        assertEquals(config1.keyValidityDays, config2.keyValidityDays)
    }

    // ========== Key Alias Validation Tests ==========

    @Test
    fun `test empty keyAlias throws IllegalArgumentException`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("").build()
        }
        assertTrue(exception.message!!.contains("keyAlias cannot be empty or blank"))
    }

    @Test
    fun `test blank keyAlias throws IllegalArgumentException`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("   ").build()
        }
        assertTrue(exception.message!!.contains("keyAlias cannot be empty or blank"))
    }

    @Test
    fun `test blank keyAlias with tabs throws IllegalArgumentException`() {
        assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("\t\t").build()
        }
    }

    @Test
    fun `test blank keyAlias with newlines throws IllegalArgumentException`() {
        assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("\n\n").build()
        }
    }

    @Test
    fun `test keyAlias with special characters is accepted`() {
        val config = CryptoConfig.Builder("my-key_alias.123").build()
        assertEquals("my-key_alias.123", config.keyAlias)
    }

    @Test
    fun `test keyAlias with unicode characters is accepted`() {
        val config = CryptoConfig.Builder("key-alias-\u00e9\u00e8").build()
        assertEquals("key-alias-\u00e9\u00e8", config.keyAlias)
    }

    @Test
    fun `test very long keyAlias is accepted`() {
        val longAlias = "a".repeat(1000)
        val config = CryptoConfig.Builder(longAlias).build()
        assertEquals(longAlias, config.keyAlias)
    }

    // ========== Key Rotation Interval Validation Tests ==========

    @Test
    fun `test negative keyRotationIntervalDays throws IllegalArgumentException`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("test-alias")
                .keyRotationIntervalDays(-1)
                .build()
        }
        assertTrue(exception.message!!.contains("keyRotationIntervalDays must be greater than 0"))
        assertTrue(exception.message!!.contains("-1"))
    }

    @Test
    fun `test zero keyRotationIntervalDays throws IllegalArgumentException`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("test-alias")
                .keyRotationIntervalDays(0)
                .build()
        }
        assertTrue(exception.message!!.contains("keyRotationIntervalDays must be greater than 0"))
    }

    @Test
    fun `test minimum valid keyRotationIntervalDays of 1`() {
        val config = CryptoConfig.Builder("test-alias")
            .keyRotationIntervalDays(1)
            .build()
        assertEquals(1, config.keyRotationIntervalDays)
    }

    @Test
    fun `test very large keyRotationIntervalDays is accepted`() {
        val config = CryptoConfig.Builder("test-alias")
            .keyRotationIntervalDays(10000)
            .keyValidityDays(10000)
            .build()
        assertEquals(10000, config.keyRotationIntervalDays)
    }

    // ========== Key Validity Days Validation Tests ==========

    @Test
    fun `test negative keyValidityDays throws IllegalArgumentException`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("test-alias")
                .keyValidityDays(-1)
                .build()
        }
        assertTrue(exception.message!!.contains("keyValidityDays must be greater than 0"))
    }

    @Test
    fun `test zero keyValidityDays throws IllegalArgumentException`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("test-alias")
                .keyValidityDays(0)
                .build()
        }
        assertTrue(exception.message!!.contains("keyValidityDays must be greater than 0"))
    }

    @Test
    fun `test minimum valid keyValidityDays of 1`() {
        val config = CryptoConfig.Builder("test-alias")
            .keyRotationIntervalDays(1)
            .keyValidityDays(1)
            .build()
        assertEquals(1, config.keyValidityDays)
    }

    @Test
    fun `test very large keyValidityDays is accepted`() {
        val config = CryptoConfig.Builder("test-alias")
            .keyValidityDays(100000)
            .build()
        assertEquals(100000, config.keyValidityDays)
    }

    // ========== Rotation Interval vs Validity Relationship Tests ==========

    @Test
    fun `test keyRotationIntervalDays greater than keyValidityDays throws IllegalArgumentException`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("test-alias")
                .keyRotationIntervalDays(100)
                .keyValidityDays(50)
                .build()
        }
        assertTrue(exception.message!!.contains("keyRotationIntervalDays"))
        assertTrue(exception.message!!.contains("must be less than or equal to"))
        assertTrue(exception.message!!.contains("keyValidityDays"))
    }

    @Test
    fun `test keyRotationIntervalDays equal to keyValidityDays is valid`() {
        val config = CryptoConfig.Builder("test-alias")
            .keyRotationIntervalDays(90)
            .keyValidityDays(90)
            .build()
        assertEquals(90, config.keyRotationIntervalDays)
        assertEquals(90, config.keyValidityDays)
    }

    @Test
    fun `test keyRotationIntervalDays less than keyValidityDays is valid`() {
        val config = CryptoConfig.Builder("test-alias")
            .keyRotationIntervalDays(30)
            .keyValidityDays(90)
            .build()
        assertEquals(30, config.keyRotationIntervalDays)
        assertEquals(90, config.keyValidityDays)
    }

    @Test
    fun `test keyRotationIntervalDays one less than keyValidityDays is valid`() {
        val config = CryptoConfig.Builder("test-alias")
            .keyRotationIntervalDays(89)
            .keyValidityDays(90)
            .build()
        assertEquals(89, config.keyRotationIntervalDays)
        assertEquals(90, config.keyValidityDays)
    }

    @Test
    fun `test keyRotationIntervalDays one more than keyValidityDays throws exception`() {
        assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("test-alias")
                .keyRotationIntervalDays(91)
                .keyValidityDays(90)
                .build()
        }
    }

    // ========== User Authentication Tests ==========

    @Test
    fun `test requireUserAuthentication can be set to true`() {
        val config = CryptoConfig.Builder("test-alias")
            .requireUserAuthentication(true)
            .build()
        assertTrue(config.requireUserAuthentication)
    }

    @Test
    fun `test requireUserAuthentication can be set to false`() {
        val config = CryptoConfig.Builder("test-alias")
            .requireUserAuthentication(false)
            .build()
        assertFalse(config.requireUserAuthentication)
    }

    @Test
    fun `test requireUserAuthentication can be toggled multiple times`() {
        val builder = CryptoConfig.Builder("test-alias")
            .requireUserAuthentication(true)
            .requireUserAuthentication(false)
            .requireUserAuthentication(true)

        val config = builder.build()
        assertTrue(config.requireUserAuthentication)
    }

    // ========== Edge Case and Complex Scenario Tests ==========

    @Test
    fun `test valid configuration builds successfully`() {
        val config = CryptoConfig.Builder("valid-key")
            .requireUserAuthentication(false)
            .keyRotationIntervalDays(60)
            .keyValidityDays(120)
            .build()

        assertEquals("valid-key", config.keyAlias)
        assertFalse(config.requireUserAuthentication)
        assertEquals(60, config.keyRotationIntervalDays)
        assertEquals(120, config.keyValidityDays)
    }

    @Test
    fun `test configuration with only keyAlias uses all defaults`() {
        val config = CryptoConfig.Builder("minimal-config").build()

        assertNotNull(config)
        assertEquals("minimal-config", config.keyAlias)
        assertFalse(config.requireUserAuthentication)
        assertEquals(90, config.keyRotationIntervalDays)
        assertEquals(365, config.keyValidityDays)
    }

    @Test
    fun `test configuration with all parameters set to minimum valid values`() {
        val config = CryptoConfig.Builder("min-config")
            .requireUserAuthentication(false)
            .keyRotationIntervalDays(1)
            .keyValidityDays(1)
            .build()

        assertEquals("min-config", config.keyAlias)
        assertFalse(config.requireUserAuthentication)
        assertEquals(1, config.keyRotationIntervalDays)
        assertEquals(1, config.keyValidityDays)
    }

    @Test
    fun `test configuration with typical production values`() {
        val config = CryptoConfig.Builder("production-key")
            .requireUserAuthentication(true)
            .keyRotationIntervalDays(30)
            .keyValidityDays(365)
            .build()

        assertEquals("production-key", config.keyAlias)
        assertTrue(config.requireUserAuthentication)
        assertEquals(30, config.keyRotationIntervalDays)
        assertEquals(365, config.keyValidityDays)
    }

    @Test
    fun `test configuration with weekly rotation`() {
        val config = CryptoConfig.Builder("weekly-rotation-key")
            .keyRotationIntervalDays(7)
            .keyValidityDays(30)
            .build()

        assertEquals(7, config.keyRotationIntervalDays)
        assertEquals(30, config.keyValidityDays)
    }

    @Test
    fun `test configuration with monthly rotation`() {
        val config = CryptoConfig.Builder("monthly-rotation-key")
            .keyRotationIntervalDays(30)
            .keyValidityDays(365)
            .build()

        assertEquals(30, config.keyRotationIntervalDays)
        assertEquals(365, config.keyValidityDays)
    }

    @Test
    fun `test configuration with yearly rotation`() {
        val config = CryptoConfig.Builder("yearly-rotation-key")
            .keyRotationIntervalDays(365)
            .keyValidityDays(730)
            .build()

        assertEquals(365, config.keyRotationIntervalDays)
        assertEquals(730, config.keyValidityDays)
    }

    @Test
    fun `test multiple configurations can be created independently`() {
        val config1 = CryptoConfig.Builder("key1")
            .requireUserAuthentication(true)
            .keyRotationIntervalDays(30)
            .keyValidityDays(90)
            .build()

        val config2 = CryptoConfig.Builder("key2")
            .requireUserAuthentication(false)
            .keyRotationIntervalDays(60)
            .keyValidityDays(180)
            .build()

        assertEquals("key1", config1.keyAlias)
        assertEquals("key2", config2.keyAlias)
        assertTrue(config1.requireUserAuthentication)
        assertFalse(config2.requireUserAuthentication)
        assertEquals(30, config1.keyRotationIntervalDays)
        assertEquals(60, config2.keyRotationIntervalDays)
    }

    @Test
    fun `test partial builder configuration maintains defaults for unset values`() {
        val config = CryptoConfig.Builder("partial-config")
            .keyRotationIntervalDays(45)
            .build()

        assertEquals("partial-config", config.keyAlias)
        assertFalse(config.requireUserAuthentication) // default
        assertEquals(45, config.keyRotationIntervalDays)
        assertEquals(365, config.keyValidityDays) // default
    }

    @Test
    fun `test builder data class copy functionality`() {
        val builder1 = CryptoConfig.Builder("test-key")
        val builder2 = builder1.copy()

        assertEquals(builder1, builder2)
    }

    // ========== Boundary Value Tests ==========

    @Test
    fun `test Integer MAX_VALUE for keyRotationIntervalDays when valid`() {
        val config = CryptoConfig.Builder("max-int-key")
            .keyRotationIntervalDays(Integer.MAX_VALUE)
            .keyValidityDays(Integer.MAX_VALUE)
            .build()

        assertEquals(Integer.MAX_VALUE, config.keyRotationIntervalDays)
        assertEquals(Integer.MAX_VALUE, config.keyValidityDays)
    }

    @Test
    fun `test validation order ensures rotation is checked against validity`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            CryptoConfig.Builder("test")
                .keyRotationIntervalDays(200)
                .keyValidityDays(100)
                .build()
        }
        assertTrue(exception.message!!.contains("less than or equal to"))
    }
}
