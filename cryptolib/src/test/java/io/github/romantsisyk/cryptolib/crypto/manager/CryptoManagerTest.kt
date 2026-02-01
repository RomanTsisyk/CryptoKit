package io.github.romantsisyk.cryptolib.crypto.manager

import android.app.Activity
import androidx.fragment.app.FragmentActivity
import io.github.romantsisyk.cryptolib.biometrics.BiometricHelper
import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import io.github.romantsisyk.cryptolib.crypto.config.CryptoConfig
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationManager
import io.github.romantsisyk.cryptolib.exceptions.AuthenticationException
import io.github.romantsisyk.cryptolib.exceptions.CryptoLibException
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import io.github.romantsisyk.cryptolib.exceptions.KeyGenerationException
import io.github.romantsisyk.cryptolib.exceptions.KeyNotFoundException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.runs
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import javax.crypto.SecretKey

class CryptoManagerTest {

    private val testAlias = "test_key_alias"
    private lateinit var mockFragmentActivity: FragmentActivity
    private lateinit var mockActivity: Activity
    private lateinit var mockSecretKey: SecretKey
    private lateinit var config: CryptoConfig
    private lateinit var configWithAuth: CryptoConfig

    @Before
    fun setUp() {
        mockkObject(KeyHelper)
        mockkObject(AESEncryption)
        mockkObject(KeyRotationManager)
        mockkConstructor(BiometricHelper::class)

        mockFragmentActivity = mockk(relaxed = true)
        mockActivity = mockk(relaxed = true)
        mockSecretKey = mockk()

        config = CryptoConfig.Builder(testAlias)
            .requireUserAuthentication(false)
            .keyValidityDays(365)
            .keyRotationIntervalDays(90)
            .build()

        configWithAuth = CryptoConfig.Builder(testAlias)
            .requireUserAuthentication(true)
            .keyValidityDays(365)
            .keyRotationIntervalDays(90)
            .build()
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // ==================== Tests for encryptData success flow ====================

    @Test
    fun `encryptData should succeed when key exists and no authentication required`() {
        // Arrange
        val plaintext = "Hello, World!".toByteArray()
        val expectedEncryptedData = "encryptedBase64String"
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returns expectedEncryptedData
        every { KeyRotationManager.rotateKeyIfNeeded(testAlias) } just runs

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertEquals(expectedEncryptedData, successResult)
        assertEquals(null, failureResult)
        verify(exactly = 1) { AESEncryption.encrypt(plaintext, mockSecretKey) }
        verify(exactly = 1) { KeyRotationManager.rotateKeyIfNeeded(testAlias) }
    }

    @Test
    fun `encryptData should generate key when key does not exist`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        val expectedEncryptedData = "newEncryptedData"
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns emptyList()
        every { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) } just runs
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returns expectedEncryptedData
        every { KeyRotationManager.rotateKeyIfNeeded(testAlias) } just runs

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertEquals(expectedEncryptedData, successResult)
        assertEquals(null, failureResult)
        verify(exactly = 1) { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) }
    }

    // ==================== Tests for encryptData failure when key generation fails ====================

    @Test
    fun `encryptData should fail when key generation fails`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns emptyList()
        every { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) } throws
                RuntimeException("Key generation failed")

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Failed to generate AES key"))
    }

    @Test
    fun `encryptData should fail when AES encryption throws exception`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } throws
                CryptoOperationException("Encryption failed")

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
    }

    // ==================== Tests for decryptData success flow ====================

    @Test
    fun `decryptData should succeed when key exists and no authentication required`() {
        // Arrange
        val encryptedData = "encryptedBase64String"
        val expectedDecryptedData = "Hello, World!".toByteArray()
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encryptedData, mockSecretKey) } returns expectedDecryptedData

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertTrue(expectedDecryptedData.contentEquals(successResult))
        assertEquals(null, failureResult)
        verify(exactly = 1) { AESEncryption.decrypt(encryptedData, mockSecretKey) }
    }

    @Test
    fun `decryptData should generate key when key does not exist and then decrypt`() {
        // Arrange
        val encryptedData = "encryptedBase64String"
        val expectedDecryptedData = "Decrypted data".toByteArray()
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns emptyList()
        every { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) } just runs
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encryptedData, mockSecretKey) } returns expectedDecryptedData

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertTrue(expectedDecryptedData.contentEquals(successResult))
        assertEquals(null, failureResult)
        verify(exactly = 1) { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) }
    }

    // ==================== Tests for decryptData failure when key not found ====================

    @Test
    fun `decryptData should fail when key retrieval fails`() {
        // Arrange
        val encryptedData = "encryptedBase64String"
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } throws KeyNotFoundException(testAlias)

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is KeyNotFoundException)
    }

    @Test
    fun `decryptData should fail when decryption throws exception`() {
        // Arrange
        val encryptedData = "invalidEncryptedData"
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encryptedData, mockSecretKey) } throws
                CryptoOperationException("Decryption failed")

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
    }

    // ==================== Tests for non-FragmentActivity causing failure ====================

    @Test
    fun `encryptData should fail when activity is not FragmentActivity and auth required`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        // Act
        CryptoManager.encryptData(
            activity = mockActivity, // Regular Activity, not FragmentActivity
            config = configWithAuth, // Config requiring user authentication
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Biometric authentication requires a FragmentActivity"))
    }

    @Test
    fun `decryptData should fail when activity is not FragmentActivity and auth required`() {
        // Arrange
        val encryptedData = "encryptedBase64String"
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        // Act
        CryptoManager.decryptData(
            activity = mockActivity, // Regular Activity, not FragmentActivity
            config = configWithAuth, // Config requiring user authentication
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Biometric authentication requires a FragmentActivity"))
    }

    // ==================== Tests for performAuthenticatedAction ====================

    @Test
    fun `encryptData should call BiometricHelper authenticate when auth is required`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        val expectedEncryptedData = "encryptedResult"
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        val onSuccessSlot = slot<(ByteArray) -> Unit>()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returns expectedEncryptedData
        every { KeyRotationManager.rotateKeyIfNeeded(testAlias) } just runs

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                encryptedData = any(),
                onSuccess = capture(onSuccessSlot),
                onError = any(),
                onAuthenticationError = any()
            )
        } answers {
            // Simulate successful biometric authentication
            onSuccessSlot.captured.invoke(ByteArray(0))
        }

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertEquals(expectedEncryptedData, successResult)
        assertEquals(null, failureResult)
        verify(exactly = 1) {
            anyConstructed<BiometricHelper>().authenticate(
                activity = mockFragmentActivity,
                title = "Encrypt Data",
                description = "Authenticate to encrypt your data",
                encryptedData = any(),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = any()
            )
        }
    }

    @Test
    fun `decryptData should call BiometricHelper authenticate when auth is required`() {
        // Arrange
        val encryptedData = "encryptedBase64String"
        val expectedDecryptedData = "Decrypted!".toByteArray()
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        val onSuccessSlot = slot<(ByteArray) -> Unit>()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encryptedData, mockSecretKey) } returns expectedDecryptedData

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                encryptedData = any(),
                onSuccess = capture(onSuccessSlot),
                onError = any(),
                onAuthenticationError = any()
            )
        } answers {
            // Simulate successful biometric authentication
            onSuccessSlot.captured.invoke(ByteArray(0))
        }

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        // Assert
        assertTrue(expectedDecryptedData.contentEquals(successResult))
        assertEquals(null, failureResult)
        verify(exactly = 1) {
            anyConstructed<BiometricHelper>().authenticate(
                activity = mockFragmentActivity,
                title = "Decrypt Data",
                description = "Authenticate to decrypt your data",
                encryptedData = encryptedData.toByteArray(Charsets.UTF_8),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = any()
            )
        }
    }

    @Test
    fun `performAuthenticatedAction should skip biometric when auth not required`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        val expectedEncryptedData = "encryptedResult"
        var successResult: String? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returns expectedEncryptedData
        every { KeyRotationManager.rotateKeyIfNeeded(testAlias) } just runs

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config, // No authentication required
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { }
        )

        // Assert
        assertEquals(expectedEncryptedData, successResult)
        verify(exactly = 0) {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                encryptedData = any(),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = any()
            )
        }
    }

    // ==================== Edge case tests ====================

    @Test
    fun `encryptData should handle unexpected exception gracefully`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } throws RuntimeException("Unexpected error")

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { },
            onFailure = { failureResult = it }
        )

        // Assert
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Unexpected error during authenticated action"))
    }

    @Test
    fun `decryptData should handle unexpected exception gracefully`() {
        // Arrange
        val encryptedData = "encryptedBase64String"
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } throws RuntimeException("Unexpected error")

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { },
            onFailure = { failureResult = it }
        )

        // Assert
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Unexpected error during authenticated action"))
    }

    // ==================== Additional Authentication Tests ====================

    @Test
    fun `encryptData should handle authentication error callback`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        var failureResult: CryptoLibException? = null
        val onAuthErrorSlot = slot<(Int, CharSequence) -> Unit>()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                encryptedData = any(),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = capture(onAuthErrorSlot)
            )
        } answers {
            // Simulate authentication error
            onAuthErrorSlot.captured.invoke(10, "Too many attempts")
        }

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            plaintext = plaintext,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        // Assert
        assertNotNull(failureResult)
        assertTrue(failureResult is AuthenticationException)
        assertTrue(failureResult!!.message!!.contains("Authentication error [10]"))
        assertTrue(failureResult.message!!.contains("Too many attempts"))
    }

    @Test
    fun `decryptData should handle authentication error callback`() {
        // Arrange
        val encryptedData = "encryptedBase64String"
        var failureResult: CryptoLibException? = null
        val onAuthErrorSlot = slot<(Int, CharSequence) -> Unit>()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                encryptedData = any(),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = capture(onAuthErrorSlot)
            )
        } answers {
            // Simulate authentication error
            onAuthErrorSlot.captured.invoke(5, "Fingerprint not recognized")
        }

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            encryptedData = encryptedData,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        // Assert
        assertNotNull(failureResult)
        assertTrue(failureResult is AuthenticationException)
        assertTrue(failureResult!!.message!!.contains("Authentication error [5]"))
        assertTrue(failureResult.message!!.contains("Fingerprint not recognized"))
    }

    @Test
    fun `encryptData should handle biometric error callback`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        var failureResult: CryptoLibException? = null
        val onErrorSlot = slot<(Exception) -> Unit>()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                encryptedData = any(),
                onSuccess = any(),
                onError = capture(onErrorSlot),
                onAuthenticationError = any()
            )
        } answers {
            // Simulate biometric error
            onErrorSlot.captured.invoke(Exception("Biometric sensor unavailable"))
        }

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            plaintext = plaintext,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        // Assert
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Biometric authentication error"))
        assertTrue(failureResult.message!!.contains("Biometric sensor unavailable"))
    }

    @Test
    fun `decryptData should handle biometric error callback`() {
        // Arrange
        val encryptedData = "encryptedBase64String"
        var failureResult: CryptoLibException? = null
        val onErrorSlot = slot<(Exception) -> Unit>()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                encryptedData = any(),
                onSuccess = any(),
                onError = capture(onErrorSlot),
                onAuthenticationError = any()
            )
        } answers {
            // Simulate biometric error
            onErrorSlot.captured.invoke(Exception("Hardware not available"))
        }

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            encryptedData = encryptedData,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        // Assert
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Biometric authentication error"))
        assertTrue(failureResult.message!!.contains("Hardware not available"))
    }

    // ==================== Integration Tests ====================

    @Test
    fun `encrypt and decrypt round trip without authentication should work`() {
        // Arrange
        val originalData = "Secret message for encryption".toByteArray()
        val encryptedString = "encryptedBase64String"
        var encryptedResult: String? = null
        var decryptedResult: ByteArray? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(originalData, mockSecretKey) } returns encryptedString
        every { AESEncryption.decrypt(encryptedString, mockSecretKey) } returns originalData
        every { KeyRotationManager.rotateKeyIfNeeded(testAlias) } just runs

        // Act - Encrypt
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = originalData,
            onSuccess = { encryptedResult = it },
            onFailure = { fail("Encryption failed: ${it.message}") }
        )

        // Assert - Encryption succeeded
        assertNotNull(encryptedResult)
        assertEquals(encryptedString, encryptedResult)

        // Act - Decrypt
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedResult!!,
            onSuccess = { decryptedResult = it },
            onFailure = { fail("Decryption failed: ${it.message}") }
        )

        // Assert - Decryption succeeded and data matches
        assertNotNull(decryptedResult)
        assertArrayEquals(originalData, decryptedResult)
    }

    @Test
    fun `encrypt and decrypt with authentication should work when auth succeeds`() {
        // Arrange
        val originalData = "Authenticated secret".toByteArray()
        val encryptedString = "authEncryptedData"
        var encryptedResult: String? = null
        var decryptedResult: ByteArray? = null

        val onSuccessSlotEncrypt = slot<(ByteArray) -> Unit>()
        val onSuccessSlotDecrypt = slot<(ByteArray) -> Unit>()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(originalData, mockSecretKey) } returns encryptedString
        every { AESEncryption.decrypt(encryptedString, mockSecretKey) } returns originalData
        every { KeyRotationManager.rotateKeyIfNeeded(testAlias) } just runs

        // Mock successful biometric authentication for encryption
        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = "Encrypt Data",
                description = any(),
                encryptedData = ByteArray(0),
                onSuccess = capture(onSuccessSlotEncrypt),
                onError = any(),
                onAuthenticationError = any()
            )
        } answers {
            onSuccessSlotEncrypt.captured.invoke(ByteArray(0))
        }

        // Act - Encrypt
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            plaintext = originalData,
            onSuccess = { encryptedResult = it },
            onFailure = { fail("Encryption failed: ${it.message}") }
        )

        // Assert - Encryption succeeded
        assertNotNull(encryptedResult)
        assertEquals(encryptedString, encryptedResult)

        // Mock successful biometric authentication for decryption
        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = "Decrypt Data",
                description = any(),
                encryptedData = encryptedString.toByteArray(Charsets.UTF_8),
                onSuccess = capture(onSuccessSlotDecrypt),
                onError = any(),
                onAuthenticationError = any()
            )
        } answers {
            onSuccessSlotDecrypt.captured.invoke(ByteArray(0))
        }

        // Act - Decrypt
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            encryptedData = encryptedResult!!,
            onSuccess = { decryptedResult = it },
            onFailure = { fail("Decryption failed: ${it.message}") }
        )

        // Assert - Decryption succeeded and data matches
        assertNotNull(decryptedResult)
        assertArrayEquals(originalData, decryptedResult)
    }

    // ==================== Multiple Operations Tests ====================

    @Test
    fun `multiple encryptions with same plaintext should all succeed`() {
        // Arrange
        val plaintext = "Repeated message".toByteArray()
        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returnsMany
            listOf("encrypted1", "encrypted2", "encrypted3")
        every { KeyRotationManager.rotateKeyIfNeeded(testAlias) } just runs

        val results = mutableListOf<String>()

        // Act - Perform multiple encryptions
        repeat(3) { index ->
            CryptoManager.encryptData(
                activity = mockFragmentActivity,
                config = config,
                plaintext = plaintext,
                onSuccess = { results.add(it) },
                onFailure = { fail("Encryption $index failed") }
            )
        }

        // Assert
        assertEquals(3, results.size)
        assertEquals("encrypted1", results[0])
        assertEquals("encrypted2", results[1])
        assertEquals("encrypted3", results[2])
        verify(exactly = 3) { AESEncryption.encrypt(plaintext, mockSecretKey) }
        verify(exactly = 3) { KeyRotationManager.rotateKeyIfNeeded(testAlias) }
    }

    @Test
    fun `multiple decryptions with different encrypted data should all succeed`() {
        // Arrange
        val encrypted1 = "encryptedData1"
        val encrypted2 = "encryptedData2"
        val decrypted1 = "Message 1".toByteArray()
        val decrypted2 = "Message 2".toByteArray()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encrypted1, mockSecretKey) } returns decrypted1
        every { AESEncryption.decrypt(encrypted2, mockSecretKey) } returns decrypted2

        val results = mutableListOf<ByteArray>()

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encrypted1,
            onSuccess = { results.add(it) },
            onFailure = { fail("First decryption failed") }
        )

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encrypted2,
            onSuccess = { results.add(it) },
            onFailure = { fail("Second decryption failed") }
        )

        // Assert
        assertEquals(2, results.size)
        assertArrayEquals(decrypted1, results[0])
        assertArrayEquals(decrypted2, results[1])
    }

    // ==================== Config Variations Tests ====================

    @Test
    fun `different configs with different key aliases should use different keys`() {
        // Arrange
        val config1 = CryptoConfig.Builder("key_alias_1").build()
        val config2 = CryptoConfig.Builder("key_alias_2").build()
        val plaintext = "Test data".toByteArray()
        val mockKey1 = mockk<SecretKey>()
        val mockKey2 = mockk<SecretKey>()

        every { KeyHelper.listKeys() } returns listOf("key_alias_1", "key_alias_2")
        every { KeyHelper.getAESKey("key_alias_1") } returns mockKey1
        every { KeyHelper.getAESKey("key_alias_2") } returns mockKey2
        every { AESEncryption.encrypt(plaintext, mockKey1) } returns "encrypted1"
        every { AESEncryption.encrypt(plaintext, mockKey2) } returns "encrypted2"
        every { KeyRotationManager.rotateKeyIfNeeded(any()) } just runs

        var result1: String? = null
        var result2: String? = null

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config1,
            plaintext = plaintext,
            onSuccess = { result1 = it },
            onFailure = { fail("First encryption failed") }
        )

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config2,
            plaintext = plaintext,
            onSuccess = { result2 = it },
            onFailure = { fail("Second encryption failed") }
        )

        // Assert
        assertEquals("encrypted1", result1)
        assertEquals("encrypted2", result2)
        verify { KeyHelper.getAESKey("key_alias_1") }
        verify { KeyHelper.getAESKey("key_alias_2") }
    }

    // ==================== Empty Data Tests ====================

    @Test
    fun `encryptData with empty plaintext should be handled by AESEncryption layer`() {
        // Arrange
        val emptyData = ByteArray(0)
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(emptyData, mockSecretKey) } throws
            CryptoOperationException("Encryption failed: plaintext cannot be empty")

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = emptyData,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        // Assert
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
    }

    // ==================== Key Rotation Tests ====================

    @Test
    fun `encryptData should trigger key rotation after successful encryption`() {
        // Arrange
        val plaintext = "Test data".toByteArray()
        val encryptedData = "encryptedData"

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returns encryptedData
        every { KeyRotationManager.rotateKeyIfNeeded(testAlias) } just runs

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { },
            onFailure = { fail("Should succeed") }
        )

        // Assert
        verify(exactly = 1) { KeyRotationManager.rotateKeyIfNeeded(testAlias) }
    }

    @Test
    fun `encryptData should not trigger key rotation when encryption fails`() {
        // Arrange
        val plaintext = "Test data".toByteArray()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } throws
            CryptoOperationException("Encryption failed")

        // Act
        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { fail("Should not succeed") },
            onFailure = { }
        )

        // Assert
        verify(exactly = 0) { KeyRotationManager.rotateKeyIfNeeded(any()) }
    }

    @Test
    fun `decryptData should not trigger key rotation`() {
        // Arrange
        val encryptedData = "encryptedBase64String"
        val decryptedData = "Decrypted!".toByteArray()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encryptedData, mockSecretKey) } returns decryptedData

        // Act
        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { },
            onFailure = { fail("Should succeed") }
        )

        // Assert
        verify(exactly = 0) { KeyRotationManager.rotateKeyIfNeeded(any()) }
    }
}
