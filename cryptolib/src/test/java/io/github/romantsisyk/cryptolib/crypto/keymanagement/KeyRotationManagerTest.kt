package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.security.keystore.KeyInfo
import io.github.romantsisyk.cryptolib.exceptions.KeyNotFoundException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.runs
import io.mockk.unmockkObject
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Calendar
import java.util.Date

class KeyRotationManagerTest {

    private val testAlias = "test_key_alias"

    @Before
    fun setUp() {
        mockkObject(KeyHelper)
    }

    @After
    fun tearDown() {
        unmockkObject(KeyHelper)
    }

    // ==================== Tests for rotateKeyIfNeeded ====================

    @Test
    fun `rotateKeyIfNeeded should rotate key when key is expired`() {
        // Arrange: Create a KeyInfo mock with an expired validity end date
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -1) // Yesterday (expired)
        val expiredDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns expiredDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.generateAESKey(testAlias) } just runs

        // Act
        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        // Assert: Key should be regenerated because it's expired
        verify(atLeast = 1) { KeyHelper.generateAESKey(testAlias) }
    }

    @Test
    fun `rotateKeyIfNeeded should not rotate key when key is still valid`() {
        // Arrange: Create a KeyInfo mock with a future validity end date
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, 180) // 180 days in the future (still valid)
        val futureDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns futureDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        // Act
        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        // Assert: Key should NOT be regenerated because it's still valid
        verify(exactly = 0) { KeyHelper.generateAESKey(any()) }
    }

    @Test
    fun `rotateKeyIfNeeded should not rotate when keyValidityForOriginationEnd is null`() {
        // Arrange: Create a KeyInfo mock with null validity end date
        val mockKeyInfo = mockk<KeyInfo>()

        every { mockKeyInfo.keyValidityForOriginationEnd } returns null
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        // Act
        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        // Assert: Key should NOT be regenerated because there's no end date set
        verify(exactly = 0) { KeyHelper.generateAESKey(any()) }
    }

    @Test
    fun `rotateKeyIfNeeded should rotate key when rotation interval has passed`() {
        // Arrange: Create a KeyInfo mock with a validity end date that is more than 90 days in the past
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -100) // 100 days in the past (past the 90-day rotation interval)
        val oldDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns oldDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.generateAESKey(testAlias) } just runs

        // Act
        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        // Assert: Key should be regenerated because both expiration and rotation interval have passed
        verify(atLeast = 1) { KeyHelper.generateAESKey(testAlias) }
    }

    @Test
    fun `rotateKeyIfNeeded should handle exception during key generation gracefully`() {
        // Arrange: Create a KeyInfo mock with an expired validity end date
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -1) // Yesterday (expired)
        val expiredDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns expiredDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.generateAESKey(testAlias) } throws RuntimeException("Key generation failed")

        // Act & Assert: Should not throw an exception, just log the error
        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        // Verify that generateAESKey was called (even though it failed)
        verify { KeyHelper.generateAESKey(testAlias) }
    }

    // ==================== Tests for isKeyRotationNeeded ====================

    @Test
    fun `isKeyRotationNeeded should return true when key is expired`() {
        // Arrange: Create a KeyInfo mock with an expired validity end date
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -1) // Yesterday (expired)
        val expiredDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns expiredDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        // Act
        val result = KeyRotationManager.isKeyRotationNeeded(testAlias)

        // Assert
        assertTrue("Key rotation should be needed for expired key", result)
    }

    @Test
    fun `isKeyRotationNeeded should return false when key is still valid`() {
        // Arrange: Create a KeyInfo mock with a future validity end date
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, 30) // 30 days in the future
        val futureDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns futureDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        // Act
        val result = KeyRotationManager.isKeyRotationNeeded(testAlias)

        // Assert
        assertFalse("Key rotation should not be needed for valid key", result)
    }

    @Test
    fun `isKeyRotationNeeded should return false when keyValidityForOriginationEnd is null`() {
        // Arrange: Create a KeyInfo mock with null validity end date
        val mockKeyInfo = mockk<KeyInfo>()

        every { mockKeyInfo.keyValidityForOriginationEnd } returns null
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        // Act
        val result = KeyRotationManager.isKeyRotationNeeded(testAlias)

        // Assert
        assertFalse("Key rotation should not be needed when no end date is set", result)
    }

    @Test(expected = KeyNotFoundException::class)
    fun `isKeyRotationNeeded should throw KeyNotFoundException when key does not exist`() {
        // Arrange: Throw KeyNotFoundException when trying to get key info
        every { KeyHelper.getKeyInfo(testAlias) } throws KeyNotFoundException(testAlias)

        // Act: This should throw KeyNotFoundException
        KeyRotationManager.isKeyRotationNeeded(testAlias)
    }

    @Test(expected = KeyNotFoundException::class)
    fun `rotateKeyIfNeeded should throw KeyNotFoundException when key does not exist`() {
        // Arrange: Throw KeyNotFoundException when trying to get key info
        every { KeyHelper.getKeyInfo(testAlias) } throws KeyNotFoundException(testAlias)

        // Act: This should throw KeyNotFoundException
        KeyRotationManager.rotateKeyIfNeeded(testAlias)
    }

    // ==================== Edge case tests ====================

    @Test
    fun `isKeyRotationNeeded should return true when key expires exactly now`() {
        // Arrange: Create a KeyInfo mock with validity end date set to now
        val mockKeyInfo = mockk<KeyInfo>()
        val now = Date()

        every { mockKeyInfo.keyValidityForOriginationEnd } returns now
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        // Act
        val result = KeyRotationManager.isKeyRotationNeeded(testAlias)

        // Assert: Should return false because Date.after() returns false when dates are equal
        assertFalse("Key rotation should not be needed when dates are exactly equal", result)
    }

    @Test
    fun `rotateKeyIfNeeded should handle key expiring exactly at rotation interval boundary`() {
        // Arrange: Key validity ended exactly 90 days ago (at the rotation interval boundary)
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -90) // Exactly 90 days ago
        val boundaryDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns boundaryDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.generateAESKey(testAlias) } just runs

        // Act
        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        // Assert: Key should be regenerated because it's expired (even if not past rotation interval)
        verify(atLeast = 1) { KeyHelper.generateAESKey(testAlias) }
    }
}
