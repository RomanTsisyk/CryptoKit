package io.github.romantsisyk.cryptolib.crypto.kdf

import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Arrays

class KeyDerivationTest {

    @Test
    fun `test deriveKey with CharArray produces consistent results`() {
        val password = "TestPassword123!".toCharArray()
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.getDefault()

        val key1 = KeyDerivation.deriveKey(password, salt, config)
        val key2 = KeyDerivation.deriveKey(password, salt, config)

        assertArrayEquals(key1.encoded, key2.encoded)
    }

    @Test
    fun `test deriveKey with String produces consistent results`() {
        val password = "TestPassword123!"
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.getDefault()

        val key1 = KeyDerivation.deriveKey(password, salt, config)
        val key2 = KeyDerivation.deriveKey(password, salt, config)

        assertArrayEquals(key1.encoded, key2.encoded)
    }

    @Test
    fun `test deriveKey CharArray and String produce same result`() {
        val passwordString = "TestPassword123!"
        val passwordChars = passwordString.toCharArray()
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.getDefault()

        val keyFromString = KeyDerivation.deriveKey(passwordString, salt, config)
        val keyFromChars = KeyDerivation.deriveKey(passwordChars, salt, config)

        assertArrayEquals(keyFromString.encoded, keyFromChars.encoded)
    }

    @Test
    fun `test different passwords produce different keys`() {
        val password1 = "Password1".toCharArray()
        val password2 = "Password2".toCharArray()
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.getDefault()

        val key1 = KeyDerivation.deriveKey(password1, salt, config)
        val key2 = KeyDerivation.deriveKey(password2, salt, config)

        assertFalse(Arrays.equals(key1.encoded, key2.encoded))
    }

    @Test
    fun `test different salts produce different keys`() {
        val password = "TestPassword".toCharArray()
        val salt1 = KeyDerivation.generateSalt()
        val salt2 = KeyDerivation.generateSalt()
        val config = KDFConfig.getDefault()

        val key1 = KeyDerivation.deriveKey(password, salt1, config)
        val key2 = KeyDerivation.deriveKey(password, salt2, config)

        assertFalse(Arrays.equals(key1.encoded, key2.encoded))
    }

    @Test
    fun `test different algorithms produce different keys`() {
        val password = "TestPassword".toCharArray()
        val salt = KeyDerivation.generateSalt()

        val config256 = KDFConfig.Builder()
            .algorithm(KDFAlgorithm.PBKDF2_SHA256)
            .build()
        val config512 = KDFConfig.Builder()
            .algorithm(KDFAlgorithm.PBKDF2_SHA512)
            .build()

        val key256 = KeyDerivation.deriveKey(password, salt, config256)
        val key512 = KeyDerivation.deriveKey(password, salt, config512)

        assertFalse(Arrays.equals(key256.encoded, key512.encoded))
    }

    @Test
    fun `test different iterations produce different keys`() {
        val password = "TestPassword".toCharArray()
        val salt = KeyDerivation.generateSalt()

        val config1 = KDFConfig.Builder().iterations(100000).build()
        val config2 = KDFConfig.Builder().iterations(200000).build()

        val key1 = KeyDerivation.deriveKey(password, salt, config1)
        val key2 = KeyDerivation.deriveKey(password, salt, config2)

        assertFalse(Arrays.equals(key1.encoded, key2.encoded))
    }

    @Test
    fun `test derived key has correct length`() {
        val password = "TestPassword".toCharArray()
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.Builder().keyLength(256).build()

        val key = KeyDerivation.deriveKey(password, salt, config)

        assertEquals(32, key.encoded.size) // 256 bits = 32 bytes
    }

    @Test
    fun `test derived key with 512-bit length`() {
        val password = "TestPassword".toCharArray()
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.Builder().keyLength(512).build()

        val key = KeyDerivation.deriveKey(password, salt, config)

        assertEquals(64, key.encoded.size) // 512 bits = 64 bytes
    }

    @Test
    fun `test deriveKey throws on empty password CharArray`() {
        val emptyPassword = charArrayOf()
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.getDefault()

        assertThrows(IllegalArgumentException::class.java) {
            KeyDerivation.deriveKey(emptyPassword, salt, config)
        }
    }

    @Test
    fun `test deriveKey throws on empty password String`() {
        val emptyPassword = ""
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.getDefault()

        assertThrows(IllegalArgumentException::class.java) {
            KeyDerivation.deriveKey(emptyPassword, salt, config)
        }
    }

    @Test
    fun `test deriveKey throws on empty salt`() {
        val password = "TestPassword".toCharArray()
        val emptySalt = ByteArray(0)
        val config = KDFConfig.getDefault()

        assertThrows(IllegalArgumentException::class.java) {
            KeyDerivation.deriveKey(password, emptySalt, config)
        }
    }

    @Test
    fun `test deriveKey throws on salt shorter than 16 bytes`() {
        val password = "TestPassword".toCharArray()
        val shortSalt = ByteArray(15)
        val config = KDFConfig.getDefault()

        val exception = assertThrows(IllegalArgumentException::class.java) {
            KeyDerivation.deriveKey(password, shortSalt, config)
        }
        assert(exception.message!!.contains("Salt should be at least 16 bytes"))
    }

    @Test
    fun `test generateSalt creates salt of correct default length`() {
        val salt = KeyDerivation.generateSalt()

        assertEquals(32, salt.size)
    }

    @Test
    fun `test generateSalt creates salt of custom length`() {
        val salt = KeyDerivation.generateSalt(64)

        assertEquals(64, salt.size)
    }

    @Test
    fun `test generateSalt creates different salts each time`() {
        val salt1 = KeyDerivation.generateSalt()
        val salt2 = KeyDerivation.generateSalt()

        assertFalse(Arrays.equals(salt1, salt2))
    }

    @Test
    fun `test generateSalt throws on length less than 16`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            KeyDerivation.generateSalt(15)
        }
        assert(exception.message!!.contains("Salt length should be at least 16 bytes"))
    }

    @Test
    fun `test generateSalt accepts minimum length of 16`() {
        val salt = KeyDerivation.generateSalt(16)

        assertEquals(16, salt.size)
    }

    @Test
    fun `test deriveKeyWithNewSalt CharArray returns key and salt`() {
        val password = "TestPassword".toCharArray()
        val config = KDFConfig.getDefault()

        val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)

        assertNotNull(key)
        assertNotNull(salt)
        assertEquals(32, salt.size)
        assertEquals(32, key.encoded.size)
    }

    @Test
    fun `test deriveKeyWithNewSalt String returns key and salt`() {
        val password = "TestPassword"
        val config = KDFConfig.getDefault()

        val (key, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)

        assertNotNull(key)
        assertNotNull(salt)
        assertEquals(32, salt.size)
        assertEquals(32, key.encoded.size)
    }

    @Test
    fun `test deriveKeyWithNewSalt creates different salts each time`() {
        val password = "TestPassword".toCharArray()
        val config = KDFConfig.getDefault()

        val (key1, salt1) = KeyDerivation.deriveKeyWithNewSalt(password, config)
        val (key2, salt2) = KeyDerivation.deriveKeyWithNewSalt(password, config)

        assertFalse(Arrays.equals(salt1, salt2))
        assertFalse(Arrays.equals(key1.encoded, key2.encoded))
    }

    @Test
    fun `test deriveKeyWithNewSalt key can be reproduced with same salt`() {
        val password = "TestPassword".toCharArray()
        val config = KDFConfig.getDefault()

        val (originalKey, salt) = KeyDerivation.deriveKeyWithNewSalt(password, config)
        val reproducedKey = KeyDerivation.deriveKey(password, salt, config)

        assertArrayEquals(originalKey.encoded, reproducedKey.encoded)
    }

    @Test
    fun `test derived key algorithm is AES`() {
        val password = "TestPassword".toCharArray()
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.getDefault()

        val key = KeyDerivation.deriveKey(password, salt, config)

        assertEquals("AES", key.algorithm)
    }

    @Test
    fun `test deriveKey works with PBKDF2_SHA512`() {
        val password = "TestPassword".toCharArray()
        val salt = KeyDerivation.generateSalt()
        val config = KDFConfig.Builder()
            .algorithm(KDFAlgorithm.PBKDF2_SHA512)
            .build()

        val key = KeyDerivation.deriveKey(password, salt, config)

        assertNotNull(key)
        assertEquals(32, key.encoded.size)
    }

    @Test
    fun `test deriveKeyWithNewSalt throws on empty password CharArray`() {
        val emptyPassword = charArrayOf()
        val config = KDFConfig.getDefault()

        assertThrows(IllegalArgumentException::class.java) {
            KeyDerivation.deriveKeyWithNewSalt(emptyPassword, config)
        }
    }

    @Test
    fun `test deriveKeyWithNewSalt throws on empty password String`() {
        val emptyPassword = ""
        val config = KDFConfig.getDefault()

        assertThrows(IllegalArgumentException::class.java) {
            KeyDerivation.deriveKeyWithNewSalt(emptyPassword, config)
        }
    }
}
