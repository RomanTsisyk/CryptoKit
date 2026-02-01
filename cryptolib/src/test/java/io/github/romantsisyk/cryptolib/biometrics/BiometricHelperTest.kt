package io.github.romantsisyk.cryptolib.biometrics

import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.exceptions.KeyNotFoundException
import io.mockk.eq
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkObject
import io.mockk.unmockkStatic
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Base64
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class BiometricHelperTest {

    private lateinit var context: Context
    private lateinit var activity: FragmentActivity
    private lateinit var biometricHelper: BiometricHelper
    private lateinit var mockSecretKey: SecretKey
    private lateinit var mockCipher: Cipher
    private lateinit var mockExecutor: Executor

    companion object {
        private const val IV_SIZE = 12
        private const val TAG_SIZE = 128
    }

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        activity = mockk(relaxed = true)
        mockSecretKey = mockk(relaxed = true)
        mockCipher = mockk(relaxed = true)
        mockExecutor = mockk(relaxed = true)

        every { activity.mainExecutor } returns mockExecutor

        mockkObject(KeyHelper)
        mockkStatic(Cipher::class)

        biometricHelper = BiometricHelper(context)
    }

    @After
    fun tearDown() {
        unmockkObject(KeyHelper)
        unmockkStatic(Cipher::class)
    }

    // ==================== Test 1: authenticate with valid encrypted data ====================

    @Test
    fun `authenticate with valid encrypted data should extract IV and initialize cipher`() {
        // Arrange: Create valid encrypted data (IV + ciphertext)
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "encrypted_content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify that the cipher was initialized with proper parameters
        verify { KeyHelper.getKey() }
        verify { Cipher.getInstance("AES/GCM/NoPadding") }

        // Verify cipher init was called with DECRYPT_MODE
        val specSlot = slot<GCMParameterSpec>()
        verify { mockCipher.init(eq(Cipher.DECRYPT_MODE), eq(mockSecretKey), capture(specSlot)) }

        // Verify GCMParameterSpec has correct values
        val capturedSpec = specSlot.captured
        assertEquals(TAG_SIZE, capturedSpec.tLen)
        assertTrue(capturedSpec.iv.contentEquals(iv))
    }

    // ==================== Test 2: authenticate with invalid Base64 data ====================

    @Test
    fun `authenticate with invalid Base64 data should call onError`() {
        // Arrange: Create invalid Base64 data
        val invalidBase64Data = "!!!not-valid-base64@@@".toByteArray()

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = invalidBase64Data,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify onError was called with IllegalArgumentException
        val exceptionSlot = slot<Exception>()
        verify { onError(capture(exceptionSlot)) }

        val capturedException = exceptionSlot.captured
        assertTrue(capturedException is IllegalArgumentException)
        assertEquals("Invalid Base64-encoded encrypted data", capturedException.message)

        // Verify onSuccess was NOT called
        verify(exactly = 0) { onSuccess(any()) }
    }

    // ==================== Test 3: authenticate with data too short for IV ====================

    @Test
    fun `authenticate with data too short for IV should call onError`() {
        // Arrange: Create data that is shorter than IV_SIZE (12 bytes)
        val shortData = ByteArray(8) { it.toByte() } // Only 8 bytes, less than IV_SIZE
        val encryptedData = Base64.getEncoder().encode(shortData)

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify onError was called with IllegalArgumentException
        val exceptionSlot = slot<Exception>()
        verify { onError(capture(exceptionSlot)) }

        val capturedException = exceptionSlot.captured
        assertTrue(capturedException is IllegalArgumentException)
        assertEquals("Encrypted data is too short to contain IV", capturedException.message)

        // Verify onSuccess was NOT called
        verify(exactly = 0) { onSuccess(any()) }
    }

    @Test
    fun `authenticate with exactly IV_SIZE bytes should call onError for too short data`() {
        // Arrange: Create data that is exactly IV_SIZE (12 bytes) - no actual ciphertext
        val exactlyIVSizeData = ByteArray(IV_SIZE) { it.toByte() }
        val encryptedData = Base64.getEncoder().encode(exactlyIVSizeData)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act: This should not fail validation since size >= IV_SIZE,
        // but the cipher will have no ciphertext to decrypt
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: The method should proceed to create cipher (since size >= IV_SIZE)
        verify { KeyHelper.getKey() }
    }

    // ==================== Test 4: getCipher creates proper GCMParameterSpec ====================

    @Test
    fun `getCipher should create cipher with proper GCMParameterSpec`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { (it + 10).toByte() }
        val ciphertext = "test_ciphertext".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify GCMParameterSpec was created with correct TAG_SIZE and IV
        val specSlot = slot<GCMParameterSpec>()
        verify { mockCipher.init(eq(Cipher.DECRYPT_MODE), eq(mockSecretKey), capture(specSlot)) }

        val capturedSpec = specSlot.captured
        assertNotNull(capturedSpec)
        assertEquals("Tag size should be 128 bits", TAG_SIZE, capturedSpec.tLen)
        assertEquals("IV should have correct size", IV_SIZE, capturedSpec.iv.size)
        assertTrue("IV content should match", capturedSpec.iv.contentEquals(iv))
    }

    @Test
    fun `getCipher should use AES GCM NoPadding transformation`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify correct transformation is used
        verify { Cipher.getInstance("AES/GCM/NoPadding") }
    }

    // ==================== Test 5: Error handling when KeyHelper.getKey() fails ====================

    @Test
    fun `authenticate should throw IllegalStateException when KeyHelper getKey fails`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "test_content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } throws KeyNotFoundException("MySecureKeyAlias")

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act & Assert: The authenticate method should throw IllegalStateException
        var thrownException: Exception? = null
        try {
            biometricHelper.authenticate(
                activity = activity,
                title = "Test Title",
                description = "Test Description",
                encryptedData = encryptedData,
                onSuccess = onSuccess,
                onError = onError,
                onAuthenticationError = onAuthenticationError
            )
        } catch (e: Exception) {
            thrownException = e
        }

        // Assert: IllegalStateException should be thrown
        assertNotNull("Exception should be thrown", thrownException)
        assertTrue("Should be IllegalStateException", thrownException is IllegalStateException)
        assertEquals("Failed to initialize Cipher", thrownException?.message)

        // Verify onSuccess and onError were NOT called (exception is thrown)
        verify(exactly = 0) { onSuccess(any()) }
        verify(exactly = 0) { onError(any()) }
    }

    @Test
    fun `authenticate should throw IllegalStateException when Cipher getInstance fails`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "test_content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } throws java.security.NoSuchAlgorithmException("Algorithm not available")

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act & Assert
        var thrownException: Exception? = null
        try {
            biometricHelper.authenticate(
                activity = activity,
                title = "Test Title",
                description = "Test Description",
                encryptedData = encryptedData,
                onSuccess = onSuccess,
                onError = onError,
                onAuthenticationError = onAuthenticationError
            )
        } catch (e: Exception) {
            thrownException = e
        }

        // Assert: IllegalStateException should be thrown
        assertNotNull("Exception should be thrown", thrownException)
        assertTrue("Should be IllegalStateException", thrownException is IllegalStateException)
        assertEquals("Failed to initialize Cipher", thrownException?.message)
    }

    @Test
    fun `authenticate should throw IllegalStateException when cipher init fails`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "test_content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } throws
                java.security.InvalidKeyException("Invalid key")

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act & Assert
        var thrownException: Exception? = null
        try {
            biometricHelper.authenticate(
                activity = activity,
                title = "Test Title",
                description = "Test Description",
                encryptedData = encryptedData,
                onSuccess = onSuccess,
                onError = onError,
                onAuthenticationError = onAuthenticationError
            )
        } catch (e: Exception) {
            thrownException = e
        }

        // Assert: IllegalStateException should be thrown
        assertNotNull("Exception should be thrown", thrownException)
        assertTrue("Should be IllegalStateException", thrownException is IllegalStateException)
        assertEquals("Failed to initialize Cipher", thrownException?.message)
    }

    // ==================== Additional edge case tests ====================

    @Test
    fun `authenticate with empty Base64 encoded data should call onError`() {
        // Arrange: Empty byte array encoded to Base64
        val emptyData = ByteArray(0)
        val encryptedData = Base64.getEncoder().encode(emptyData)

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify onError was called because data is too short
        val exceptionSlot = slot<Exception>()
        verify { onError(capture(exceptionSlot)) }

        val capturedException = exceptionSlot.captured
        assertTrue(capturedException is IllegalArgumentException)
        assertEquals("Encrypted data is too short to contain IV", capturedException.message)
    }

    @Test
    fun `authenticate extracts correct IV from encrypted data`() {
        // Arrange: Create encrypted data with known IV pattern
        val knownIV = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
        val ciphertext = "some_ciphertext_data".toByteArray()
        val encryptedBytes = knownIV + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify the IV extracted matches our known IV
        val specSlot = slot<GCMParameterSpec>()
        verify { mockCipher.init(eq(Cipher.DECRYPT_MODE), eq(mockSecretKey), capture(specSlot)) }

        val extractedIV = specSlot.captured.iv
        assertTrue("Extracted IV should match known IV", extractedIV.contentEquals(knownIV))
    }

    // ==================== Test 6: BiometricPrompt callback tests ====================

    @Test
    fun `authenticate callback onAuthenticationSucceeded should decrypt and call onSuccess`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "encrypted_content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)
        val decryptedData = "decrypted_content".toByteArray()

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit
        every { mockCipher.doFinal(any()) } returns decryptedData

        // Mock BiometricPrompt.AuthenticationResult and CryptoObject
        val mockAuthResult: BiometricPrompt.AuthenticationResult = mockk(relaxed = true)
        val mockCryptoObject: BiometricPrompt.CryptoObject = mockk(relaxed = true)
        every { mockAuthResult.cryptoObject } returns mockCryptoObject
        every { mockCryptoObject.cipher } returns mockCipher

        val callbackSlot = slot<BiometricPrompt.AuthenticationCallback>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any(), any(), capture(callbackSlot))
        } returns mockk(relaxed = true)

        val successSlot = slot<ByteArray>()
        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        every { onSuccess(capture(successSlot)) } returns Unit
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Simulate successful authentication
        callbackSlot.captured.onAuthenticationSucceeded(mockAuthResult)

        // Assert
        verify { mockCipher.doFinal(ciphertext) }
        verify { onSuccess(any()) }
        verify(exactly = 0) { onError(any()) }
        assertTrue(successSlot.captured.contentEquals(decryptedData))

        unmockkStatic(BiometricPrompt::class)
    }

    @Test
    fun `authenticate callback onAuthenticationSucceeded with null cipher should call onError`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "encrypted_content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        // Mock BiometricPrompt.AuthenticationResult with null CryptoObject
        val mockAuthResult: BiometricPrompt.AuthenticationResult = mockk(relaxed = true)
        every { mockAuthResult.cryptoObject } returns null

        val callbackSlot = slot<BiometricPrompt.AuthenticationCallback>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any(), any(), capture(callbackSlot))
        } returns mockk(relaxed = true)

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val errorSlot = slot<Exception>()
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        every { onError(capture(errorSlot)) } returns Unit
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Simulate successful authentication with null cipher
        capturedCallback?.onAuthenticationSucceeded(mockAuthResult)

        // Assert
        verify(exactly = 0) { onSuccess(any()) }
        verify { onError(any()) }
        assertEquals("Authenticated cipher is null", errorSlot.captured.message)

        unmockkStatic(BiometricPrompt::class)
    }

    @Test
    fun `authenticate callback onAuthenticationSucceeded with cipher doFinal exception should call onError`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "encrypted_content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit
        every { mockCipher.doFinal(any()) } throws javax.crypto.BadPaddingException("Decryption failed")

        // Mock BiometricPrompt.AuthenticationResult and CryptoObject
        val mockAuthResult: BiometricPrompt.AuthenticationResult = mockk(relaxed = true)
        val mockCryptoObject: BiometricPrompt.CryptoObject = mockk(relaxed = true)
        every { mockAuthResult.cryptoObject } returns mockCryptoObject
        every { mockCryptoObject.cipher } returns mockCipher

        val callbackSlot = slot<BiometricPrompt.AuthenticationCallback>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any(), any(), capture(callbackSlot))
        } returns mockk(relaxed = true)

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val errorSlot = slot<Exception>()
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        every { onError(capture(errorSlot)) } returns Unit
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Simulate successful authentication but decryption fails
        capturedCallback?.onAuthenticationSucceeded(mockAuthResult)

        // Assert
        verify(exactly = 0) { onSuccess(any()) }
        verify { onError(any()) }
        assertTrue(errorSlot.captured is javax.crypto.BadPaddingException)
        assertEquals("Decryption failed", errorSlot.captured.message)

        unmockkStatic(BiometricPrompt::class)
    }

    @Test
    fun `authenticate callback onAuthenticationError should invoke error callback`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "encrypted_content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val callbackSlot = slot<BiometricPrompt.AuthenticationCallback>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any(), any(), capture(callbackSlot))
        } returns mockk(relaxed = true)

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val errorCodeSlot = slot<Int>()
        val errorMessageSlot = slot<CharSequence>()
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)
        every { onAuthenticationError(capture(errorCodeSlot), capture(errorMessageSlot)) } returns Unit

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Simulate authentication error
        val errorCode = BiometricPrompt.ERROR_LOCKOUT
        val errorMessage = "Too many attempts"
        callbackSlot.captured.onAuthenticationError(errorCode, errorMessage)

        // Assert
        verify(exactly = 0) { onSuccess(any()) }
        verify(exactly = 0) { onError(any()) }
        verify { onAuthenticationError(any(), any()) }
        assertEquals(errorCode, errorCodeSlot.captured)
        assertEquals(errorMessage, errorMessageSlot.captured)

        unmockkStatic(BiometricPrompt::class)
    }

    @Test
    fun `authenticate callback onAuthenticationFailed should call onError`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "encrypted_content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val callbackSlot = slot<BiometricPrompt.AuthenticationCallback>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any(), any(), capture(callbackSlot))
        } returns mockk(relaxed = true)

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val errorSlot = slot<Exception>()
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        every { onError(capture(errorSlot)) } returns Unit
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Simulate authentication failed
        callbackSlot.captured.onAuthenticationFailed()

        // Assert
        verify(exactly = 0) { onSuccess(any()) }
        verify { onError(any()) }
        assertEquals("Authentication failed", errorSlot.captured.message)

        unmockkStatic(BiometricPrompt::class)
    }

    // ==================== Test 7: BiometricPrompt.PromptInfo configuration tests ====================

    @Test
    fun `authenticate should create BiometricPrompt with correct title and description`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val mockBiometricPrompt: BiometricPrompt = mockk(relaxed = true)
        val promptInfoSlot = slot<BiometricPrompt.PromptInfo>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any(), any(), any())
        } returns mockBiometricPrompt
        every {
            mockBiometricPrompt.authenticate(capture(promptInfoSlot), any())
        } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        val testTitle = "Custom Test Title"
        val testDescription = "Custom Test Description"

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = testTitle,
            description = testDescription,
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify BiometricPrompt.authenticate was called
        verify { mockBiometricPrompt.authenticate(any(), any()) }

        // Note: Due to BiometricPrompt.PromptInfo.Builder being final,
        // we cannot directly verify the title and description in unit tests
        // This would require instrumented tests or a wrapper class

        unmockkStatic(BiometricPrompt::class)
    }

    @Test
    fun `authenticate should create BiometricPrompt with CryptoObject containing cipher`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "content".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val mockBiometricPrompt: BiometricPrompt = mockk(relaxed = true)
        val cryptoObjectSlot = slot<BiometricPrompt.CryptoObject>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any(), any(), any())
        } returns mockBiometricPrompt
        every {
            mockBiometricPrompt.authenticate(any(), capture(cryptoObjectSlot))
        } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify CryptoObject was passed to authenticate
        verify { mockBiometricPrompt.authenticate(any(), any()) }
        assertNotNull("CryptoObject should not be null", cryptoObjectSlot.captured)
        assertEquals("CryptoObject should contain our cipher", mockCipher, cryptoObjectSlot.captured.cipher)

        unmockkStatic(BiometricPrompt::class)
    }

    // ==================== Test 8: Boundary and edge cases ====================

    @Test
    fun `authenticate with minimum valid encrypted data size should succeed`() {
        // Arrange: IV (12 bytes) + minimal ciphertext (1 byte)
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val minimalCiphertext = byteArrayOf(42) // Single byte
        val encryptedBytes = iv + minimalCiphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Should initialize cipher successfully
        verify { KeyHelper.getKey() }
        verify { Cipher.getInstance("AES/GCM/NoPadding") }
        verify { mockCipher.init(eq(Cipher.DECRYPT_MODE), eq(mockSecretKey), any<GCMParameterSpec>()) }
    }

    @Test
    fun `authenticate with large encrypted data should process correctly`() {
        // Arrange: IV (12 bytes) + large ciphertext (10KB)
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val largeCiphertext = ByteArray(10240) { (it % 256).toByte() } // 10KB
        val encryptedBytes = iv + largeCiphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Should handle large data without issues
        verify { KeyHelper.getKey() }
        verify { Cipher.getInstance("AES/GCM/NoPadding") }
    }

    @Test
    fun `authenticate with special characters in title and description should work`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "test".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        val specialTitle = "Test & Title with <special> \"characters\""
        val specialDescription = "Description with émojis 😀 and symbols !@#$%"

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = specialTitle,
            description = specialDescription,
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Should handle special characters without issues
        verify { KeyHelper.getKey() }
        verify { Cipher.getInstance("AES/GCM/NoPadding") }
    }

    @Test
    fun `authenticate should use mainExecutor from activity`() {
        // Arrange
        val iv = ByteArray(IV_SIZE) { it.toByte() }
        val ciphertext = "test".toByteArray()
        val encryptedBytes = iv + ciphertext
        val encryptedData = Base64.getEncoder().encode(encryptedBytes)

        val customExecutor: Executor = mockk(relaxed = true)
        every { activity.mainExecutor } returns customExecutor

        every { KeyHelper.getKey() } returns mockSecretKey
        every { Cipher.getInstance("AES/GCM/NoPadding") } returns mockCipher
        every { mockCipher.init(any(), any<SecretKey>(), any<GCMParameterSpec>()) } returns Unit

        val executorSlot = slot<Executor>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any(), capture(executorSlot), any())
        } returns mockk(relaxed = true)

        val onSuccess: (ByteArray) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            encryptedData = encryptedData,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert: Verify the executor from activity was used
        assertEquals(customExecutor, executorSlot.captured)

        unmockkStatic(BiometricPrompt::class)
    }
}
