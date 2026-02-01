package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.security.keystore.KeyInfo
import io.github.romantsisyk.cryptolib.exceptions.CryptoLibException
import io.github.romantsisyk.cryptolib.exceptions.KeyGenerationException
import io.github.romantsisyk.cryptolib.exceptions.KeyNotFoundException
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.SecretKey

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [30])
class KeyHelperTest {

    private val testAlias = "test_key_alias"
    private val testRSAAlias = "test_rsa_key"
    private val testECAlias = "test_ec_key"

    @Before
    fun setUp() {
        // Clean up any existing test keys before each test
        cleanupTestKeys()
    }

    @After
    fun tearDown() {
        // Clean up test keys after each test
        cleanupTestKeys()
    }

    private fun cleanupTestKeys() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        listOf(testAlias, testRSAAlias, testECAlias, "MySecureKeyAlias").forEach { alias ->
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }
    }

    // ==================== AES Key Generation Tests ====================

    @Test
    fun `test generateAESKey creates key successfully`() {
        KeyHelper.generateAESKey(testAlias)

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("Key should exist in keystore", keyStore.containsAlias(testAlias))
    }

    @Test
    fun `test generateAESKey with custom validity days`() {
        val validityDays = 30
        KeyHelper.generateAESKey(testAlias, validityDays = validityDays)

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("Key should exist in keystore", keyStore.containsAlias(testAlias))
    }

    @Test
    fun `test generateAESKey with user authentication required`() {
        KeyHelper.generateAESKey(testAlias, requireUserAuthentication = true)

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("Key should exist in keystore", keyStore.containsAlias(testAlias))
    }

    @Test
    fun `test generateAESKey replaces existing key with same alias`() {
        // Generate first key
        KeyHelper.generateAESKey(testAlias)
        val firstKey = KeyHelper.getAESKey(testAlias)

        // Generate second key with same alias
        KeyHelper.generateAESKey(testAlias)
        val secondKey = KeyHelper.getAESKey(testAlias)

        // Keys should be different (new key replaces old one)
        assertNotEquals("Keys should be different", firstKey, secondKey)
    }

    // ==================== RSA Key Pair Generation Tests ====================

    @Test
    fun `test generateRSAKeyPair creates key pair successfully`() {
        KeyHelper.generateRSAKeyPair(testRSAAlias)

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("RSA key pair should exist in keystore", keyStore.containsAlias(testRSAAlias))
    }

    @Test
    fun `test generateRSAKeyPair creates both private and public keys`() {
        KeyHelper.generateRSAKeyPair(testRSAAlias)

        val privateKey = KeyHelper.getPrivateKey(testRSAAlias)
        val publicKey = KeyHelper.getPublicKey(testRSAAlias)

        assertNotNull("Private key should not be null", privateKey)
        assertNotNull("Public key should not be null", publicKey)
        assertEquals("Private key algorithm should be RSA", "RSA", privateKey?.algorithm)
        assertEquals("Public key algorithm should be RSA", "RSA", publicKey?.algorithm)
    }

    // ==================== EC Key Pair Generation Tests ====================

    @Test
    fun `test generateECKeyPair creates key pair successfully`() {
        KeyHelper.generateECKeyPair(testECAlias)

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("EC key pair should exist in keystore", keyStore.containsAlias(testECAlias))
    }

    @Test
    fun `test generateECKeyPair creates both private and public keys`() {
        KeyHelper.generateECKeyPair(testECAlias)

        val privateKey = KeyHelper.getPrivateKey(testECAlias)
        val publicKey = KeyHelper.getPublicKey(testECAlias)

        assertNotNull("Private key should not be null", privateKey)
        assertNotNull("Public key should not be null", publicKey)
        assertEquals("Private key algorithm should be EC", "EC", privateKey?.algorithm)
        assertEquals("Public key algorithm should be EC", "EC", publicKey?.algorithm)
    }

    // ==================== Key Retrieval Tests ====================

    @Test
    fun `test getAESKey retrieves existing key`() {
        KeyHelper.generateAESKey(testAlias)

        val key = KeyHelper.getAESKey(testAlias)

        assertNotNull("Retrieved key should not be null", key)
        assertTrue("Retrieved object should be SecretKey", key is SecretKey)
    }

    @Test
    fun `test getAESKey throws KeyNotFoundException for non-existent key`() {
        assertThrows(KeyNotFoundException::class.java) {
            KeyHelper.getAESKey("non_existent_alias")
        }
    }

    @Test
    fun `test getPrivateKey retrieves existing private key`() {
        KeyHelper.generateRSAKeyPair(testRSAAlias)

        val privateKey = KeyHelper.getPrivateKey(testRSAAlias)

        assertNotNull("Private key should not be null", privateKey)
        assertTrue("Retrieved object should be PrivateKey", privateKey is PrivateKey)
    }

    @Test
    fun `test getPrivateKey returns null for non-existent key`() {
        val privateKey = KeyHelper.getPrivateKey("non_existent_alias")
        assertNull("Private key should be null for non-existent alias", privateKey)
    }

    @Test
    fun `test getPublicKey retrieves existing public key`() {
        KeyHelper.generateRSAKeyPair(testRSAAlias)

        val publicKey = KeyHelper.getPublicKey(testRSAAlias)

        assertNotNull("Public key should not be null", publicKey)
        assertTrue("Retrieved object should be PublicKey", publicKey is PublicKey)
    }

    @Test
    fun `test getPublicKey returns null for non-existent key`() {
        val publicKey = KeyHelper.getPublicKey("non_existent_alias")
        assertNull("Public key should be null for non-existent alias", publicKey)
    }

    // ==================== Key Listing Tests ====================

    @Test
    fun `test listKeys returns empty list when no keys exist`() {
        val keys = KeyHelper.listKeys()
        assertTrue("Keys list should be empty", keys.isEmpty())
    }

    @Test
    fun `test listKeys returns all stored keys`() {
        KeyHelper.generateAESKey(testAlias)
        KeyHelper.generateRSAKeyPair(testRSAAlias)
        KeyHelper.generateECKeyPair(testECAlias)

        val keys = KeyHelper.listKeys()

        assertEquals("Should have 3 keys", 3, keys.size)
        assertTrue("Should contain test AES key", keys.contains(testAlias))
        assertTrue("Should contain test RSA key", keys.contains(testRSAAlias))
        assertTrue("Should contain test EC key", keys.contains(testECAlias))
    }

    @Test
    fun `test listKeys returns correct count after key deletion`() {
        KeyHelper.generateAESKey(testAlias)
        KeyHelper.generateRSAKeyPair(testRSAAlias)

        var keys = KeyHelper.listKeys()
        assertEquals("Should have 2 keys initially", 2, keys.size)

        KeyHelper.deleteKey(testAlias)

        keys = KeyHelper.listKeys()
        assertEquals("Should have 1 key after deletion", 1, keys.size)
        assertFalse("Should not contain deleted key", keys.contains(testAlias))
    }

    // ==================== Key Deletion Tests ====================

    @Test
    fun `test deleteKey removes existing key`() {
        KeyHelper.generateAESKey(testAlias)
        assertTrue("Key should exist before deletion", KeyHelper.listKeys().contains(testAlias))

        KeyHelper.deleteKey(testAlias)

        assertFalse("Key should not exist after deletion", KeyHelper.listKeys().contains(testAlias))
    }

    @Test
    fun `test deleteKey throws KeyNotFoundException for non-existent key`() {
        assertThrows(KeyNotFoundException::class.java) {
            KeyHelper.deleteKey("non_existent_alias")
        }
    }

    @Test
    fun `test deleteKey removes RSA key pair`() {
        KeyHelper.generateRSAKeyPair(testRSAAlias)
        assertTrue("RSA key pair should exist before deletion", KeyHelper.listKeys().contains(testRSAAlias))

        KeyHelper.deleteKey(testRSAAlias)

        assertFalse("RSA key pair should not exist after deletion", KeyHelper.listKeys().contains(testRSAAlias))
    }

    // ==================== KeyInfo Tests ====================

    @Test
    fun `test getKeyInfo retrieves key information`() {
        KeyHelper.generateAESKey(testAlias)

        val keyInfo = KeyHelper.getKeyInfo(testAlias)

        assertNotNull("KeyInfo should not be null", keyInfo)
        assertTrue("KeyInfo should be instance of KeyInfo", keyInfo is KeyInfo)
    }

    @Test
    fun `test getKeyInfo throws KeyNotFoundException for non-existent key`() {
        assertThrows(KeyNotFoundException::class.java) {
            KeyHelper.getKeyInfo("non_existent_alias")
        }
    }

    @Test
    fun `test getKeyInfo returns correct key size`() {
        KeyHelper.generateAESKey(testAlias)

        val keyInfo = KeyHelper.getKeyInfo(testAlias)

        assertEquals("Key size should be 256 bits", 256, keyInfo.keySize)
    }

    // ==================== getOrCreateSecretKey Tests ====================

    @Test
    fun `test getOrCreateSecretKey creates new key when none exists`() {
        val key = KeyHelper.getOrCreateSecretKey()

        assertNotNull("Key should not be null", key)
        assertTrue("Key should be SecretKey", key is SecretKey)
        assertTrue("Key should exist in keystore", KeyHelper.listKeys().contains("MySecureKeyAlias"))
    }

    @Test
    fun `test getOrCreateSecretKey returns existing key`() {
        val firstKey = KeyHelper.getOrCreateSecretKey()
        val secondKey = KeyHelper.getOrCreateSecretKey()

        assertEquals("Should return same key instance", firstKey, secondKey)
    }

    // ==================== getCipherInstance Tests ====================

    @Test
    fun `test getCipherInstance returns valid Cipher`() {
        val cipher = KeyHelper.getCipherInstance()

        assertNotNull("Cipher should not be null", cipher)
        assertTrue("Cipher should be instance of Cipher", cipher is Cipher)
    }

    @Test
    fun `test getCipherInstance returns AES GCM cipher`() {
        val cipher = KeyHelper.getCipherInstance()

        assertTrue("Cipher algorithm should contain AES", cipher.algorithm.contains("AES"))
        assertTrue("Cipher algorithm should contain GCM", cipher.algorithm.contains("GCM"))
    }

    // ==================== getKey Tests ====================

    @Test
    fun `test getKey retrieves default key alias`() {
        KeyHelper.getOrCreateSecretKey() // Create the default key

        val key = KeyHelper.getKey()

        assertNotNull("Key should not be null", key)
        assertTrue("Key should be SecretKey", key is SecretKey)
    }

    @Test
    fun `test getKey throws KeyNotFoundException when default key does not exist`() {
        assertThrows(KeyNotFoundException::class.java) {
            KeyHelper.getKey()
        }
    }

    // ==================== Edge Cases and Error Handling ====================

    @Test
    fun `test generateAESKey with zero validity days`() {
        // This should still work, just with very short validity
        KeyHelper.generateAESKey(testAlias, validityDays = 0)

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("Key should exist even with 0 validity days", keyStore.containsAlias(testAlias))
    }

    @Test
    fun `test generateAESKey with negative validity days creates key`() {
        // Negative validity should still create a key (end date will be in the past)
        KeyHelper.generateAESKey(testAlias, validityDays = -1)

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("Key should exist even with negative validity days", keyStore.containsAlias(testAlias))
    }

    @Test
    fun `test multiple key types can coexist in keystore`() {
        KeyHelper.generateAESKey(testAlias)
        KeyHelper.generateRSAKeyPair(testRSAAlias)
        KeyHelper.generateECKeyPair(testECAlias)

        val aesKey = KeyHelper.getAESKey(testAlias)
        val rsaPrivate = KeyHelper.getPrivateKey(testRSAAlias)
        val ecPrivate = KeyHelper.getPrivateKey(testECAlias)

        assertNotNull("AES key should exist", aesKey)
        assertNotNull("RSA private key should exist", rsaPrivate)
        assertNotNull("EC private key should exist", ecPrivate)
    }

    @Test
    fun `test key alias with special characters`() {
        val specialAlias = "test_key-123.alias"
        KeyHelper.generateAESKey(specialAlias)

        val key = KeyHelper.getAESKey(specialAlias)
        assertNotNull("Key with special characters in alias should be retrievable", key)

        KeyHelper.deleteKey(specialAlias)
    }

    @Test
    fun `test generateAESKey with very long alias`() {
        val longAlias = "a".repeat(200)
        KeyHelper.generateAESKey(longAlias)

        val key = KeyHelper.getAESKey(longAlias)
        assertNotNull("Key with long alias should be retrievable", key)

        KeyHelper.deleteKey(longAlias)
    }
}
