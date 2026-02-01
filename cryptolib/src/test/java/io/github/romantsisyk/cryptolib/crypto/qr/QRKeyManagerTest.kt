package io.github.romantsisyk.cryptolib.crypto.qr

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkStatic
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.security.Key
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class QRKeyManagerTest {

    private lateinit var mockKeyStore: KeyStore
    private lateinit var mockKeyGenerator: KeyGenerator
    private lateinit var mockSecretKey: SecretKey

    @Before
    fun setUp() {
        mockKeyStore = mockk(relaxed = true)
        mockKeyGenerator = mockk(relaxed = true)
        mockSecretKey = mockk()

        mockkStatic(KeyStore::class)
        mockkStatic(KeyGenerator::class)

        every { KeyStore.getInstance("AndroidKeyStore") } returns mockKeyStore
        every { KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore") } returns mockKeyGenerator
    }

    @After
    fun tearDown() {
        unmockkStatic(KeyStore::class)
        unmockkStatic(KeyGenerator::class)
    }

    // ==================== Tests for generateKey ====================

    @Test
    fun `generateKey should create key with correct alias`() {
        // Arrange
        val keyGenParameterSpecSlot = slot<KeyGenParameterSpec>()
        every { mockKeyGenerator.init(capture(keyGenParameterSpecSlot)) } returns Unit
        every { mockKeyGenerator.generateKey() } returns mockSecretKey

        // Act
        val result = QRKeyManager.generateKey()

        // Assert
        assertNotNull(result)
        assertEquals(mockSecretKey, result)
        assertEquals("CryptoKitQRCodeKey", keyGenParameterSpecSlot.captured.keystoreAlias)
    }

    @Test
    fun `generateKey should create AES key with GCM block mode`() {
        // Arrange
        val keyGenParameterSpecSlot = slot<KeyGenParameterSpec>()
        every { mockKeyGenerator.init(capture(keyGenParameterSpecSlot)) } returns Unit
        every { mockKeyGenerator.generateKey() } returns mockSecretKey

        // Act
        QRKeyManager.generateKey()

        // Assert
        val capturedSpec = keyGenParameterSpecSlot.captured
        assertEquals(KeyProperties.BLOCK_MODE_GCM, capturedSpec.blockModes[0])
        assertEquals(KeyProperties.ENCRYPTION_PADDING_NONE, capturedSpec.encryptionPaddings[0])
        verify { KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore") }
    }

    // ==================== Tests for getKey ====================

    @Test
    fun `getKey should return key when it exists`() {
        // Arrange
        every { mockKeyStore.load(null) } returns Unit
        every { mockKeyStore.getKey("CryptoKitQRCodeKey", null) } returns mockSecretKey

        // Act
        val result = QRKeyManager.getKey()

        // Assert
        assertNotNull(result)
        assertEquals(mockSecretKey, result)
        verify { mockKeyStore.load(null) }
        verify { mockKeyStore.getKey("CryptoKitQRCodeKey", null) }
    }

    @Test
    fun `getKey should throw IllegalStateException when key not found`() {
        // Arrange
        every { mockKeyStore.load(null) } returns Unit
        every { mockKeyStore.getKey("CryptoKitQRCodeKey", null) } returns null

        // Act & Assert
        val exception = assertThrows(IllegalStateException::class.java) {
            QRKeyManager.getKey()
        }
        assertEquals(
            "Key with alias 'CryptoKitQRCodeKey' not found or is not a valid SecretKey",
            exception.message
        )
    }

    @Test
    fun `getKey should throw IllegalStateException for wrong key type`() {
        // Arrange
        val nonSecretKey = mockk<Key>() // A Key that is not a SecretKey
        every { mockKeyStore.load(null) } returns Unit
        every { mockKeyStore.getKey("CryptoKitQRCodeKey", null) } returns nonSecretKey

        // Act & Assert
        val exception = assertThrows(IllegalStateException::class.java) {
            QRKeyManager.getKey()
        }
        assertEquals(
            "Key with alias 'CryptoKitQRCodeKey' not found or is not a valid SecretKey",
            exception.message
        )
    }
}
