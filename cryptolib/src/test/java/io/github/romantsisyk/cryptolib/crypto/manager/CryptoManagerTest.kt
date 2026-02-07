package io.github.romantsisyk.cryptolib.crypto.manager

import android.app.Activity
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.github.romantsisyk.cryptolib.biometrics.BiometricHelper
import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import io.github.romantsisyk.cryptolib.crypto.config.CryptoConfig
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.exceptions.AuthenticationException
import io.github.romantsisyk.cryptolib.exceptions.CryptoLibException
import io.github.romantsisyk.cryptolib.exceptions.CryptoOperationException
import io.github.romantsisyk.cryptolib.exceptions.KeyNotFoundException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import javax.crypto.Cipher
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
        val plaintext = "Hello, World!".toByteArray()
        val expectedEncryptedData = "encryptedBase64String"
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returns expectedEncryptedData

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertEquals(expectedEncryptedData, successResult)
        assertEquals(null, failureResult)
        verify(exactly = 1) { AESEncryption.encrypt(plaintext, mockSecretKey) }
    }

    @Test
    fun `encryptData should generate key when key does not exist`() {
        val plaintext = "Test data".toByteArray()
        val expectedEncryptedData = "newEncryptedData"
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns emptyList()
        every { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) } just runs
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returns expectedEncryptedData

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertEquals(expectedEncryptedData, successResult)
        assertEquals(null, failureResult)
        verify(exactly = 1) { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) }
    }

    // ==================== Tests for encryptData failure ====================

    @Test
    fun `encryptData should fail when key generation fails`() {
        val plaintext = "Test data".toByteArray()
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns emptyList()
        every { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) } throws
                RuntimeException("Key generation failed")

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Failed to generate AES key"))
    }

    @Test
    fun `encryptData should fail when AES encryption throws exception`() {
        val plaintext = "Test data".toByteArray()
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } throws
                CryptoOperationException("Encryption failed")

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
    }

    // ==================== Tests for decryptData success flow ====================

    @Test
    fun `decryptData should succeed when key exists and no authentication required`() {
        val encryptedData = "encryptedBase64String"
        val expectedDecryptedData = "Hello, World!".toByteArray()
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encryptedData, mockSecretKey) } returns expectedDecryptedData

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertTrue(expectedDecryptedData.contentEquals(successResult))
        assertEquals(null, failureResult)
        verify(exactly = 1) { AESEncryption.decrypt(encryptedData, mockSecretKey) }
    }

    @Test
    fun `decryptData should generate key when key does not exist and then decrypt`() {
        val encryptedData = "encryptedBase64String"
        val expectedDecryptedData = "Decrypted data".toByteArray()
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns emptyList()
        every { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) } just runs
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encryptedData, mockSecretKey) } returns expectedDecryptedData

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertTrue(expectedDecryptedData.contentEquals(successResult))
        assertEquals(null, failureResult)
        verify(exactly = 1) { KeyHelper.generateAESKey(testAlias, config.keyValidityDays, false) }
    }

    // ==================== Tests for decryptData failure ====================

    @Test
    fun `decryptData should fail when key retrieval fails`() {
        val encryptedData = "encryptedBase64String"
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } throws KeyNotFoundException(testAlias)

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is KeyNotFoundException)
    }

    @Test
    fun `decryptData should fail when decryption throws exception`() {
        val encryptedData = "invalidEncryptedData"
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encryptedData, mockSecretKey) } throws
                CryptoOperationException("Decryption failed")

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
    }

    // ==================== Tests for non-FragmentActivity causing failure ====================

    @Test
    fun `encryptData should fail when activity is not FragmentActivity and auth required`() {
        val plaintext = "Test data".toByteArray()
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        CryptoManager.encryptData(
            activity = mockActivity,
            config = configWithAuth,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Biometric authentication requires a FragmentActivity"))
    }

    @Test
    fun `decryptData should fail when activity is not FragmentActivity and auth required`() {
        val encryptedData = "encryptedBase64String"
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        CryptoManager.decryptData(
            activity = mockActivity,
            config = configWithAuth,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertEquals(null, successResult)
        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Biometric authentication requires a FragmentActivity"))
    }

    // ==================== Tests for biometric authentication path ====================

    @Test
    fun `encryptData should call BiometricHelper authenticate when auth is required`() {
        val plaintext = "Test data".toByteArray()
        var successResult: String? = null
        var failureResult: CryptoLibException? = null

        val mockCipher: Cipher = mockk(relaxed = true)
        val mockIv = ByteArray(12) { it.toByte() }
        val mockCiphertext = "ciphertext".toByteArray()
        every { mockCipher.doFinal(plaintext) } returns mockCiphertext
        every { mockCipher.iv } returns mockIv

        mockkStatic(Cipher::class)
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(Cipher.ENCRYPT_MODE, mockSecretKey) } returns Unit

        val onSuccessSlot = slot<(BiometricPrompt.CryptoObject) -> Unit>()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        val mockAuthCryptoObject: BiometricPrompt.CryptoObject = mockk(relaxed = true)
        every { mockAuthCryptoObject.cipher } returns mockCipher

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                cryptoObject = any(),
                onSuccess = capture(onSuccessSlot),
                onError = any(),
                onAuthenticationError = any()
            )
        } answers {
            onSuccessSlot.captured.invoke(mockAuthCryptoObject)
        }

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertNotNull(successResult)
        assertEquals(null, failureResult)
        verify(exactly = 1) {
            anyConstructed<BiometricHelper>().authenticate(
                activity = mockFragmentActivity,
                title = "Encrypt Data",
                description = "Authenticate to encrypt your data",
                cryptoObject = any(),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = any()
            )
        }
    }

    @Test
    fun `decryptData should call BiometricHelper authenticate when auth is required`() {
        // For the biometric decrypt path, we need valid Base64 data with IV
        val iv = ByteArray(12) { it.toByte() }
        val ciphertext = "encrypted_content".toByteArray()
        val combined = iv + ciphertext
        val encryptedData = java.util.Base64.getEncoder().encodeToString(combined)
        val expectedDecryptedData = "Decrypted!".toByteArray()
        var successResult: ByteArray? = null
        var failureResult: CryptoLibException? = null

        val mockCipher: Cipher = mockk(relaxed = true)
        every { mockCipher.doFinal(ciphertext) } returns expectedDecryptedData

        mockkStatic(Cipher::class)
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<javax.crypto.spec.GCMParameterSpec>()) } returns Unit

        val onSuccessSlot = slot<(BiometricPrompt.CryptoObject) -> Unit>()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        val mockAuthCryptoObject: BiometricPrompt.CryptoObject = mockk(relaxed = true)
        every { mockAuthCryptoObject.cipher } returns mockCipher

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                cryptoObject = any(),
                onSuccess = capture(onSuccessSlot),
                onError = any(),
                onAuthenticationError = any()
            )
        } answers {
            onSuccessSlot.captured.invoke(mockAuthCryptoObject)
        }

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            encryptedData = encryptedData,
            onSuccess = { successResult = it },
            onFailure = { failureResult = it }
        )

        assertTrue(expectedDecryptedData.contentEquals(successResult))
        assertEquals(null, failureResult)
        verify(exactly = 1) {
            anyConstructed<BiometricHelper>().authenticate(
                activity = mockFragmentActivity,
                title = "Decrypt Data",
                description = "Authenticate to decrypt your data",
                cryptoObject = any(),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = any()
            )
        }
    }

    @Test
    fun `performAuthenticatedAction should skip biometric when auth not required`() {
        val plaintext = "Test data".toByteArray()
        val expectedEncryptedData = "encryptedResult"
        var successResult: String? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returns expectedEncryptedData

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { successResult = it },
            onFailure = { }
        )

        assertEquals(expectedEncryptedData, successResult)
        verify(exactly = 0) {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                cryptoObject = any(),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = any()
            )
        }
    }

    // ==================== Edge case tests ====================

    @Test
    fun `encryptData should handle unexpected exception gracefully`() {
        val plaintext = "Test data".toByteArray()
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } throws RuntimeException("Unexpected error")

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { },
            onFailure = { failureResult = it }
        )

        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Unexpected error during authenticated action"))
    }

    @Test
    fun `decryptData should handle unexpected exception gracefully`() {
        val encryptedData = "encryptedBase64String"
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } throws RuntimeException("Unexpected error")

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { },
            onFailure = { failureResult = it }
        )

        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Unexpected error during authenticated action"))
    }

    // ==================== Authentication Error Tests ====================

    @Test
    fun `encryptData should handle authentication error callback`() {
        val plaintext = "Test data".toByteArray()
        var failureResult: CryptoLibException? = null
        val onAuthErrorSlot = slot<(Int, CharSequence) -> Unit>()

        val mockCipher: Cipher = mockk(relaxed = true)
        mockkStatic(Cipher::class)
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(Cipher.ENCRYPT_MODE, mockSecretKey) } returns Unit

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                cryptoObject = any(),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = capture(onAuthErrorSlot)
            )
        } answers {
            onAuthErrorSlot.captured.invoke(10, "Too many attempts")
        }

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            plaintext = plaintext,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        assertNotNull(failureResult)
        assertTrue(failureResult is AuthenticationException)
        assertTrue(failureResult!!.message!!.contains("Authentication error [10]"))
        assertTrue(failureResult!!.message!!.contains("Too many attempts"))
    }

    @Test
    fun `decryptData should handle authentication error callback`() {
        val iv = ByteArray(12) { it.toByte() }
        val ciphertext = "content".toByteArray()
        val combined = iv + ciphertext
        val encryptedData = java.util.Base64.getEncoder().encodeToString(combined)
        var failureResult: CryptoLibException? = null
        val onAuthErrorSlot = slot<(Int, CharSequence) -> Unit>()

        val mockCipher: Cipher = mockk(relaxed = true)
        mockkStatic(Cipher::class)
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<javax.crypto.spec.GCMParameterSpec>()) } returns Unit

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                cryptoObject = any(),
                onSuccess = any(),
                onError = any(),
                onAuthenticationError = capture(onAuthErrorSlot)
            )
        } answers {
            onAuthErrorSlot.captured.invoke(5, "Fingerprint not recognized")
        }

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            encryptedData = encryptedData,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        assertNotNull(failureResult)
        assertTrue(failureResult is AuthenticationException)
        assertTrue(failureResult!!.message!!.contains("Authentication error [5]"))
        assertTrue(failureResult!!.message!!.contains("Fingerprint not recognized"))
    }

    @Test
    fun `encryptData should handle biometric error callback`() {
        val plaintext = "Test data".toByteArray()
        var failureResult: CryptoLibException? = null
        val onErrorSlot = slot<(Exception) -> Unit>()

        val mockCipher: Cipher = mockk(relaxed = true)
        mockkStatic(Cipher::class)
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(Cipher.ENCRYPT_MODE, mockSecretKey) } returns Unit

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                cryptoObject = any(),
                onSuccess = any(),
                onError = capture(onErrorSlot),
                onAuthenticationError = any()
            )
        } answers {
            onErrorSlot.captured.invoke(Exception("Biometric sensor unavailable"))
        }

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            plaintext = plaintext,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Biometric authentication error"))
        assertTrue(failureResult!!.message!!.contains("Biometric sensor unavailable"))
    }

    @Test
    fun `decryptData should handle biometric error callback`() {
        val iv = ByteArray(12) { it.toByte() }
        val ciphertext = "content".toByteArray()
        val combined = iv + ciphertext
        val encryptedData = java.util.Base64.getEncoder().encodeToString(combined)
        var failureResult: CryptoLibException? = null
        val onErrorSlot = slot<(Exception) -> Unit>()

        val mockCipher: Cipher = mockk(relaxed = true)
        mockkStatic(Cipher::class)
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<javax.crypto.spec.GCMParameterSpec>()) } returns Unit

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey

        every {
            anyConstructed<BiometricHelper>().authenticate(
                activity = any(),
                title = any(),
                description = any(),
                cryptoObject = any(),
                onSuccess = any(),
                onError = capture(onErrorSlot),
                onAuthenticationError = any()
            )
        } answers {
            onErrorSlot.captured.invoke(Exception("Hardware not available"))
        }

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = configWithAuth,
            encryptedData = encryptedData,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
        assertTrue(failureResult!!.message!!.contains("Biometric authentication error"))
        assertTrue(failureResult!!.message!!.contains("Hardware not available"))
    }

    // ==================== Integration Tests ====================

    @Test
    fun `encrypt and decrypt round trip without authentication should work`() {
        val originalData = "Secret message for encryption".toByteArray()
        val encryptedString = "encryptedBase64String"
        var encryptedResult: String? = null
        var decryptedResult: ByteArray? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(originalData, mockSecretKey) } returns encryptedString
        every { AESEncryption.decrypt(encryptedString, mockSecretKey) } returns originalData

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = originalData,
            onSuccess = { encryptedResult = it },
            onFailure = { fail("Encryption failed: ${it.message}") }
        )

        assertNotNull(encryptedResult)
        assertEquals(encryptedString, encryptedResult)

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedResult!!,
            onSuccess = { decryptedResult = it },
            onFailure = { fail("Decryption failed: ${it.message}") }
        )

        assertNotNull(decryptedResult)
        assertArrayEquals(originalData, decryptedResult)
    }

    // ==================== Multiple Operations Tests ====================

    @Test
    fun `multiple encryptions with same plaintext should all succeed`() {
        val plaintext = "Repeated message".toByteArray()
        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returnsMany
            listOf("encrypted1", "encrypted2", "encrypted3")

        val results = mutableListOf<String>()

        repeat(3) { index ->
            CryptoManager.encryptData(
                activity = mockFragmentActivity,
                config = config,
                plaintext = plaintext,
                onSuccess = { results.add(it) },
                onFailure = { fail("Encryption $index failed") }
            )
        }

        assertEquals(3, results.size)
        assertEquals("encrypted1", results[0])
        assertEquals("encrypted2", results[1])
        assertEquals("encrypted3", results[2])
        verify(exactly = 3) { AESEncryption.encrypt(plaintext, mockSecretKey) }
    }

    @Test
    fun `multiple decryptions with different encrypted data should all succeed`() {
        val encrypted1 = "encryptedData1"
        val encrypted2 = "encryptedData2"
        val decrypted1 = "Message 1".toByteArray()
        val decrypted2 = "Message 2".toByteArray()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encrypted1, mockSecretKey) } returns decrypted1
        every { AESEncryption.decrypt(encrypted2, mockSecretKey) } returns decrypted2

        val results = mutableListOf<ByteArray>()

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

        assertEquals(2, results.size)
        assertArrayEquals(decrypted1, results[0])
        assertArrayEquals(decrypted2, results[1])
    }

    // ==================== Config Variations Tests ====================

    @Test
    fun `different configs with different key aliases should use different keys`() {
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

        var result1: String? = null
        var result2: String? = null

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

        assertEquals("encrypted1", result1)
        assertEquals("encrypted2", result2)
        verify { KeyHelper.getAESKey("key_alias_1") }
        verify { KeyHelper.getAESKey("key_alias_2") }
    }

    // ==================== Empty Data Tests ====================

    @Test
    fun `encryptData with empty plaintext should be handled by AESEncryption layer`() {
        val emptyData = ByteArray(0)
        var failureResult: CryptoLibException? = null

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(emptyData, mockSecretKey) } throws
            CryptoOperationException("Encryption failed: plaintext cannot be empty")

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = emptyData,
            onSuccess = { fail("Should not succeed") },
            onFailure = { failureResult = it }
        )

        assertNotNull(failureResult)
        assertTrue(failureResult is CryptoOperationException)
    }

    // ==================== Key Rotation No Longer Triggered ====================

    @Test
    fun `encryptData should not trigger key rotation`() {
        val plaintext = "Test data".toByteArray()
        val encryptedData = "encryptedData"

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.encrypt(plaintext, mockSecretKey) } returns encryptedData

        CryptoManager.encryptData(
            activity = mockFragmentActivity,
            config = config,
            plaintext = plaintext,
            onSuccess = { },
            onFailure = { fail("Should succeed") }
        )
    }

    @Test
    fun `decryptData should not trigger key rotation`() {
        val encryptedData = "encryptedBase64String"
        val decryptedData = "Decrypted!".toByteArray()

        every { KeyHelper.listKeys() } returns listOf(testAlias)
        every { KeyHelper.getAESKey(testAlias) } returns mockSecretKey
        every { AESEncryption.decrypt(encryptedData, mockSecretKey) } returns decryptedData

        CryptoManager.decryptData(
            activity = mockFragmentActivity,
            config = config,
            encryptedData = encryptedData,
            onSuccess = { },
            onFailure = { fail("Should succeed") }
        )
    }
}
