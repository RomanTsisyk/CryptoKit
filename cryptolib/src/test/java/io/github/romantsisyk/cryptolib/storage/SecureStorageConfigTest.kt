package io.github.romantsisyk.cryptolib.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureStorageConfigTest {

    @Test
    fun `test builder with default values`() {
        val config = SecureStorageConfig.Builder("TestKeyAlias").build()

        assertEquals("TestKeyAlias", config.keyAlias)
        assertEquals("secure_prefs", config.preferencesName)
        assertFalse(config.enableBackup)
        assertTrue(config.autoCreateKey)
    }

    @Test
    fun `test builder with custom values`() {
        val config = SecureStorageConfig.Builder("CustomKeyAlias")
            .preferencesName("custom_prefs")
            .enableBackup(true)
            .autoCreateKey(false)
            .build()

        assertEquals("CustomKeyAlias", config.keyAlias)
        assertEquals("custom_prefs", config.preferencesName)
        assertTrue(config.enableBackup)
        assertFalse(config.autoCreateKey)
    }

    @Test
    fun `test builder with blank key alias throws exception`() {
        assertThrows(IllegalArgumentException::class.java) {
            SecureStorageConfig.Builder("").build()
        }
    }

    @Test
    fun `test builder with blank preferences name throws exception`() {
        assertThrows(IllegalArgumentException::class.java) {
            SecureStorageConfig.Builder("TestKeyAlias")
                .preferencesName("")
                .build()
        }
    }

    @Test
    fun `test builder fluent chaining`() {
        val config = SecureStorageConfig.Builder("TestKeyAlias")
            .preferencesName("test_prefs")
            .enableBackup(true)
            .autoCreateKey(false)
            .build()

        assertEquals("TestKeyAlias", config.keyAlias)
        assertEquals("test_prefs", config.preferencesName)
        assertTrue(config.enableBackup)
        assertFalse(config.autoCreateKey)
    }

    @Test
    fun `test default constants`() {
        assertEquals("SecureStorageKey", SecureStorageConfig.DEFAULT_KEY_ALIAS)
        assertEquals("secure_prefs", SecureStorageConfig.DEFAULT_PREFERENCES_NAME)
    }
}
