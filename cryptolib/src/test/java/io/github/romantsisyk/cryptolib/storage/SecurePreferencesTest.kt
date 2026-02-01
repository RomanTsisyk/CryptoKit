package io.github.romantsisyk.cryptolib.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SecurePreferencesTest {

    private lateinit var context: Context
    private lateinit var securePreferences: SecurePreferences
    private val testKeyAlias = "TestSecureStorageKey"
    private val testPreferencesName = "test_secure_prefs"

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        securePreferences = SecurePreferences(context, testKeyAlias, testPreferencesName)

        // Clean up any existing test data
        securePreferences.clear()
    }

    @After
    fun tearDown() {
        // Clean up after tests
        securePreferences.clear()

        // Delete test key
        try {
            KeyHelper.deleteKey(testKeyAlias)
        } catch (e: Exception) {
            // Ignore if key doesn't exist
        }

        // Clear SharedPreferences
        context.getSharedPreferences(testPreferencesName, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test
    fun `test putString and getString`() {
        val key = "test_string_key"
        val value = "Hello, Secure World!"

        securePreferences.putString(key, value)
        val retrieved = securePreferences.getString(key)

        assertEquals(value, retrieved)
    }

    @Test
    fun `test getString with default value when key not found`() {
        val defaultValue = "default"
        val retrieved = securePreferences.getString("non_existent_key", defaultValue)

        assertEquals(defaultValue, retrieved)
    }

    @Test
    fun `test getString returns null when key not found and no default`() {
        val retrieved = securePreferences.getString("non_existent_key")

        assertNull(retrieved)
    }

    @Test
    fun `test putInt and getInt`() {
        val key = "test_int_key"
        val value = 42

        securePreferences.putInt(key, value)
        val retrieved = securePreferences.getInt(key)

        assertEquals(value, retrieved)
    }

    @Test
    fun `test getInt with default value when key not found`() {
        val defaultValue = 100
        val retrieved = securePreferences.getInt("non_existent_key", defaultValue)

        assertEquals(defaultValue, retrieved)
    }

    @Test
    fun `test putBoolean and getBoolean`() {
        val key = "test_boolean_key"
        val value = true

        securePreferences.putBoolean(key, value)
        val retrieved = securePreferences.getBoolean(key)

        assertEquals(value, retrieved)
    }

    @Test
    fun `test getBoolean with default value when key not found`() {
        val defaultValue = true
        val retrieved = securePreferences.getBoolean("non_existent_key", defaultValue)

        assertEquals(defaultValue, retrieved)
    }

    @Test
    fun `test putBytes and getBytes`() {
        val key = "test_bytes_key"
        val value = "Binary data test".toByteArray()

        securePreferences.putBytes(key, value)
        val retrieved = securePreferences.getBytes(key)

        assertArrayEquals(value, retrieved)
    }

    @Test
    fun `test getBytes returns null when key not found`() {
        val retrieved = securePreferences.getBytes("non_existent_key")

        assertNull(retrieved)
    }

    @Test
    fun `test remove key`() {
        val key = "test_remove_key"
        val value = "To be removed"

        securePreferences.putString(key, value)
        assertTrue(securePreferences.contains(key))

        securePreferences.remove(key)
        assertFalse(securePreferences.contains(key))
    }

    @Test
    fun `test clear all data`() {
        securePreferences.putString("key1", "value1")
        securePreferences.putInt("key2", 123)
        securePreferences.putBoolean("key3", true)

        assertTrue(securePreferences.contains("key1"))
        assertTrue(securePreferences.contains("key2"))
        assertTrue(securePreferences.contains("key3"))

        securePreferences.clear()

        assertFalse(securePreferences.contains("key1"))
        assertFalse(securePreferences.contains("key2"))
        assertFalse(securePreferences.contains("key3"))
    }

    @Test
    fun `test contains key`() {
        val key = "test_contains_key"
        assertFalse(securePreferences.contains(key))

        securePreferences.putString(key, "value")
        assertTrue(securePreferences.contains(key))
    }

    @Test
    fun `test getAllKeys`() {
        securePreferences.putString("key1", "value1")
        securePreferences.putString("key2", "value2")
        securePreferences.putInt("key3", 123)

        val keys = securePreferences.getAllKeys()

        assertEquals(3, keys.size)
        assertTrue(keys.contains("key1"))
        assertTrue(keys.contains("key2"))
        assertTrue(keys.contains("key3"))
    }

    @Test
    fun `test storing empty string`() {
        val key = "empty_string_key"
        val value = ""

        securePreferences.putString(key, value)
        val retrieved = securePreferences.getString(key)

        assertEquals(value, retrieved)
    }

    @Test
    fun `test storing negative integer`() {
        val key = "negative_int_key"
        val value = -999

        securePreferences.putInt(key, value)
        val retrieved = securePreferences.getInt(key)

        assertEquals(value, retrieved)
    }

    @Test
    fun `test storing large byte array`() {
        val key = "large_bytes_key"
        val value = ByteArray(1024) { it.toByte() }

        securePreferences.putBytes(key, value)
        val retrieved = securePreferences.getBytes(key)

        assertArrayEquals(value, retrieved)
    }

    @Test
    fun `test storing special characters in string`() {
        val key = "special_chars_key"
        val value = "Special chars: !@#$%^&*()_+-=[]{}|;:',.<>?/~`"

        securePreferences.putString(key, value)
        val retrieved = securePreferences.getString(key)

        assertEquals(value, retrieved)
    }

    @Test
    fun `test storing unicode characters`() {
        val key = "unicode_key"
        val value = "Unicode: 你好世界 🌍 مرحبا العالم"

        securePreferences.putString(key, value)
        val retrieved = securePreferences.getString(key)

        assertEquals(value, retrieved)
    }

    @Test
    fun `test multiple instances with same configuration share data`() {
        val key = "shared_key"
        val value = "shared_value"

        securePreferences.putString(key, value)

        // Create a new instance with same configuration
        val anotherInstance = SecurePreferences(context, testKeyAlias, testPreferencesName)
        val retrieved = anotherInstance.getString(key)

        assertEquals(value, retrieved)
    }

    @Test
    fun `test overwriting existing value`() {
        val key = "overwrite_key"
        val value1 = "original value"
        val value2 = "new value"

        securePreferences.putString(key, value1)
        assertEquals(value1, securePreferences.getString(key))

        securePreferences.putString(key, value2)
        assertEquals(value2, securePreferences.getString(key))
    }
}
