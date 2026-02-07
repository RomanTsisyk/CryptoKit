package io.github.romantsisyk.cryptolib.biometrics

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkStatic
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.Executor
import javax.crypto.Cipher

class BiometricHelperTest {

    private lateinit var activity: FragmentActivity
    private lateinit var biometricHelper: BiometricHelper
    private lateinit var mockCipher: Cipher
    private lateinit var mockExecutor: Executor
    private lateinit var mockCryptoObject: BiometricPrompt.CryptoObject

    @Before
    fun setUp() {
        activity = mockk(relaxed = true)
        mockCipher = mockk(relaxed = true)
        mockExecutor = mockk(relaxed = true)

        every { activity.mainExecutor } returns mockExecutor

        mockCryptoObject = mockk(relaxed = true)
        every { mockCryptoObject.cipher } returns mockCipher

        biometricHelper = BiometricHelper()
    }

    @After
    fun tearDown() {
        // No static mocks to clean up by default
    }

    // ==================== Test: authenticate passes CryptoObject to BiometricPrompt ====================

    @Test
    fun `authenticate should create BiometricPrompt with provided CryptoObject`() {
        // Arrange
        val mockBiometricPrompt: BiometricPrompt = mockk(relaxed = true)
        val cryptoObjectSlot = slot<BiometricPrompt.CryptoObject>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any<FragmentActivity>(), any(), any())
        } returns mockBiometricPrompt
        every {
            mockBiometricPrompt.authenticate(any(), capture(cryptoObjectSlot))
        } returns Unit

        val onSuccess: (BiometricPrompt.CryptoObject) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            cryptoObject = mockCryptoObject,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert
        verify { mockBiometricPrompt.authenticate(any(), any()) }
        assertEquals(mockCryptoObject, cryptoObjectSlot.captured)

        unmockkStatic(BiometricPrompt::class)
    }

    // ==================== Test: onSuccess returns authenticated CryptoObject ====================

    @Test
    fun `authenticate callback onAuthenticationSucceeded should return authenticated CryptoObject`() {
        // Arrange
        val callbackSlot = slot<BiometricPrompt.AuthenticationCallback>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any<FragmentActivity>(), any(), capture(callbackSlot))
        } returns mockk(relaxed = true)

        val mockAuthResult: BiometricPrompt.AuthenticationResult = mockk(relaxed = true)
        val authenticatedCryptoObject: BiometricPrompt.CryptoObject = mockk(relaxed = true)
        every { mockAuthResult.cryptoObject } returns authenticatedCryptoObject
        every { authenticatedCryptoObject.cipher } returns mockCipher

        val successSlot = slot<BiometricPrompt.CryptoObject>()
        val onSuccess: (BiometricPrompt.CryptoObject) -> Unit = mockk(relaxed = true)
        every { onSuccess(capture(successSlot)) } returns Unit
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            cryptoObject = mockCryptoObject,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Simulate successful authentication
        callbackSlot.captured.onAuthenticationSucceeded(mockAuthResult)

        // Assert
        verify { onSuccess(any()) }
        verify(exactly = 0) { onError(any()) }
        assertEquals(authenticatedCryptoObject, successSlot.captured)

        unmockkStatic(BiometricPrompt::class)
    }

    // ==================== Test: null CryptoObject from result calls onError ====================

    @Test
    fun `authenticate callback onAuthenticationSucceeded with null CryptoObject should call onError`() {
        // Arrange
        val callbackSlot = slot<BiometricPrompt.AuthenticationCallback>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any<FragmentActivity>(), any(), capture(callbackSlot))
        } returns mockk(relaxed = true)

        val mockAuthResult: BiometricPrompt.AuthenticationResult = mockk(relaxed = true)
        every { mockAuthResult.cryptoObject } returns null

        val errorSlot = slot<Exception>()
        val onSuccess: (BiometricPrompt.CryptoObject) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        every { onError(capture(errorSlot)) } returns Unit
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            cryptoObject = mockCryptoObject,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Simulate successful authentication with null CryptoObject
        callbackSlot.captured.onAuthenticationSucceeded(mockAuthResult)

        // Assert
        verify(exactly = 0) { onSuccess(any()) }
        verify { onError(any()) }
        assertEquals("Authenticated CryptoObject is null", errorSlot.captured.message)

        unmockkStatic(BiometricPrompt::class)
    }

    // ==================== Test: onAuthenticationError works correctly ====================

    @Test
    fun `authenticate callback onAuthenticationError should invoke error callback`() {
        // Arrange
        val callbackSlot = slot<BiometricPrompt.AuthenticationCallback>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any<FragmentActivity>(), any(), capture(callbackSlot))
        } returns mockk(relaxed = true)

        val onSuccess: (BiometricPrompt.CryptoObject) -> Unit = mockk(relaxed = true)
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
            cryptoObject = mockCryptoObject,
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

    // ==================== Test: onAuthenticationFailed does NOT call onError (non-terminal) ====================

    @Test
    fun `authenticate callback onAuthenticationFailed should NOT call onError since it is not terminal`() {
        // Arrange
        val callbackSlot = slot<BiometricPrompt.AuthenticationCallback>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any<FragmentActivity>(), any(), capture(callbackSlot))
        } returns mockk(relaxed = true)

        val onSuccess: (BiometricPrompt.CryptoObject) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            cryptoObject = mockCryptoObject,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Simulate a failed attempt (e.g., wet fingerprint) — this is NOT terminal
        callbackSlot.captured.onAuthenticationFailed()

        // Assert: neither onError nor onSuccess should be called — user can retry
        verify(exactly = 0) { onSuccess(any()) }
        verify(exactly = 0) { onError(any()) }
        verify(exactly = 0) { onAuthenticationError(any(), any()) }

        unmockkStatic(BiometricPrompt::class)
    }

    // ==================== Test: uses mainExecutor from activity ====================

    @Test
    fun `authenticate should use mainExecutor from activity`() {
        // Arrange
        val customExecutor: Executor = mockk(relaxed = true)
        every { activity.mainExecutor } returns customExecutor

        val executorSlot = slot<Executor>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any<FragmentActivity>(), capture(executorSlot), any())
        } returns mockk(relaxed = true)

        val onSuccess: (BiometricPrompt.CryptoObject) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = "Test Title",
            description = "Test Description",
            cryptoObject = mockCryptoObject,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert
        assertEquals(customExecutor, executorSlot.captured)

        unmockkStatic(BiometricPrompt::class)
    }

    // ==================== Test: BiometricPrompt.PromptInfo configuration ====================

    @Test
    fun `authenticate should create BiometricPrompt with correct title and description`() {
        // Arrange
        val mockBiometricPrompt: BiometricPrompt = mockk(relaxed = true)
        val promptInfoSlot = slot<BiometricPrompt.PromptInfo>()
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any<FragmentActivity>(), any(), any())
        } returns mockBiometricPrompt
        every {
            mockBiometricPrompt.authenticate(capture(promptInfoSlot), any())
        } returns Unit

        val onSuccess: (BiometricPrompt.CryptoObject) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        val testTitle = "Custom Test Title"
        val testDescription = "Custom Test Description"

        // Act
        biometricHelper.authenticate(
            activity = activity,
            title = testTitle,
            description = testDescription,
            cryptoObject = mockCryptoObject,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert
        verify { mockBiometricPrompt.authenticate(any(), any()) }
        assertNotNull(promptInfoSlot.captured)

        unmockkStatic(BiometricPrompt::class)
    }

    // ==================== Test: special characters in title/description ====================

    @Test
    fun `authenticate with special characters in title and description should work`() {
        // Arrange
        val mockBiometricPrompt: BiometricPrompt = mockk(relaxed = true)
        mockkStatic(BiometricPrompt::class)
        every {
            BiometricPrompt(any<FragmentActivity>(), any(), any())
        } returns mockBiometricPrompt

        val onSuccess: (BiometricPrompt.CryptoObject) -> Unit = mockk(relaxed = true)
        val onError: (Exception) -> Unit = mockk(relaxed = true)
        val onAuthenticationError: (Int, CharSequence) -> Unit = mockk(relaxed = true)

        // Act - should not throw
        biometricHelper.authenticate(
            activity = activity,
            title = "Test & Title with <special> \"characters\"",
            description = "Description with symbols !@#\$%",
            cryptoObject = mockCryptoObject,
            onSuccess = onSuccess,
            onError = onError,
            onAuthenticationError = onAuthenticationError
        )

        // Assert
        verify { mockBiometricPrompt.authenticate(any(), any()) }

        unmockkStatic(BiometricPrompt::class)
    }
}
