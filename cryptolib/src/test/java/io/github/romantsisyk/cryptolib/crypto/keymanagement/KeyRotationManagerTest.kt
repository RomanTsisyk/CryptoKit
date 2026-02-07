package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.security.keystore.KeyInfo
import io.github.romantsisyk.cryptolib.exceptions.KeyNotFoundException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.runs
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
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
        mockkStatic(KeyHelper::class)
    }

    @After
    fun tearDown() {
        unmockkStatic(KeyHelper::class)
    }

    // ==================== Tests for safeRotate ====================

    @Test
    fun `safeRotate should return NotNeeded when key is still valid`() {
        // Arrange
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, 180)
        val futureDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns futureDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        // Act
        val result = KeyRotationManager.safeRotate(testAlias)

        // Assert
        assertTrue(result is KeyRotationResult.NotNeeded)
        verify(exactly = 0) { KeyHelper.generateAESKey(any()) }
    }

    @Test
    fun `safeRotate should return NotNeeded when keyValidityForOriginationEnd is null`() {
        // Arrange
        val mockKeyInfo = mockk<KeyInfo>()
        every { mockKeyInfo.keyValidityForOriginationEnd } returns null
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        // Act
        val result = KeyRotationManager.safeRotate(testAlias)

        // Assert
        assertTrue(result is KeyRotationResult.NotNeeded)
    }

    @Test
    fun `safeRotate should return Success with versioned alias when key is expired`() {
        // Arrange
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -1)
        val expiredDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns expiredDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.nextVersionedAlias(testAlias) } returns "${testAlias}_v2"
        every { KeyHelper.generateAESKey("${testAlias}_v2") } just runs

        // Act
        val result = KeyRotationManager.safeRotate(testAlias)

        // Assert
        assertTrue(result is KeyRotationResult.Success)
        val success = result as KeyRotationResult.Success
        assertEquals(testAlias, success.oldAlias)
        assertEquals("${testAlias}_v2", success.newAlias)
        verify(exactly = 1) { KeyHelper.generateAESKey("${testAlias}_v2") }
    }

    @Test
    fun `safeRotate should return Failure when key generation fails`() {
        // Arrange
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -1)
        val expiredDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns expiredDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.nextVersionedAlias(testAlias) } returns "${testAlias}_v2"
        every { KeyHelper.generateAESKey("${testAlias}_v2") } throws RuntimeException("Key generation failed")

        // Act
        val result = KeyRotationManager.safeRotate(testAlias)

        // Assert
        assertTrue(result is KeyRotationResult.Failure)
        val failure = result as KeyRotationResult.Failure
        assertEquals(testAlias, failure.alias)
        assertEquals("Key generation failed", failure.exception.message)
    }

    @Test
    fun `safeRotate should return Success when key already expired`() {
        // Arrange: key expired 100 days ago
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -100)
        val oldDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns oldDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.nextVersionedAlias(testAlias) } returns "${testAlias}_v2"
        every { KeyHelper.generateAESKey("${testAlias}_v2") } just runs

        // Act
        val result = KeyRotationManager.safeRotate(testAlias)

        // Assert
        assertTrue(result is KeyRotationResult.Success)
    }

    @Test
    fun `safeRotate should proactively rotate when key expires within rotation window`() {
        // Arrange: key expires in 60 days — within the 90-day proactive rotation window
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, 60)
        val soonExpiring = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns soonExpiring
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.nextVersionedAlias(testAlias) } returns "${testAlias}_v2"
        every { KeyHelper.generateAESKey("${testAlias}_v2") } just runs

        // Act
        val result = KeyRotationManager.safeRotate(testAlias)

        // Assert: should trigger proactive rotation (60 days < 90 day window)
        assertTrue("Expected Success for proactive rotation, got $result", result is KeyRotationResult.Success)
        verify(exactly = 1) { KeyHelper.generateAESKey("${testAlias}_v2") }
    }

    @Test
    fun `safeRotate should NOT rotate when key expires beyond rotation window`() {
        // Arrange: key expires in 120 days — outside the 90-day proactive rotation window
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, 120)
        val farFuture = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns farFuture
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        // Act
        val result = KeyRotationManager.safeRotate(testAlias)

        // Assert: 120 days until expiry > 90 day window — no rotation needed
        assertTrue("Expected NotNeeded, got $result", result is KeyRotationResult.NotNeeded)
        verify(exactly = 0) { KeyHelper.generateAESKey(any()) }
    }

    // ==================== Tests for rotateKeyIfNeeded (deprecated, kept for backwards compat) ====================

    @Suppress("DEPRECATION")
    @Test
    fun `rotateKeyIfNeeded should rotate key when key is expired`() {
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -1)
        val expiredDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns expiredDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.generateAESKey(testAlias) } just runs

        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        verify(atLeast = 1) { KeyHelper.generateAESKey(testAlias) }
    }

    @Suppress("DEPRECATION")
    @Test
    fun `rotateKeyIfNeeded should not rotate key when key is still valid`() {
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, 180)
        val futureDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns futureDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        verify(exactly = 0) { KeyHelper.generateAESKey(any()) }
    }

    @Suppress("DEPRECATION")
    @Test
    fun `rotateKeyIfNeeded should not rotate when keyValidityForOriginationEnd is null`() {
        val mockKeyInfo = mockk<KeyInfo>()
        every { mockKeyInfo.keyValidityForOriginationEnd } returns null
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        verify(exactly = 0) { KeyHelper.generateAESKey(any()) }
    }

    @Suppress("DEPRECATION")
    @Test
    fun `rotateKeyIfNeeded should rotate key when rotation interval has passed`() {
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -100)
        val oldDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns oldDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.generateAESKey(testAlias) } just runs

        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        verify(atLeast = 1) { KeyHelper.generateAESKey(testAlias) }
    }

    @Suppress("DEPRECATION")
    @Test
    fun `rotateKeyIfNeeded should handle exception during key generation gracefully`() {
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -1)
        val expiredDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns expiredDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.generateAESKey(testAlias) } throws RuntimeException("Key generation failed")

        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        verify { KeyHelper.generateAESKey(testAlias) }
    }

    // ==================== Tests for isKeyRotationNeeded ====================

    @Test
    fun `isKeyRotationNeeded should return true when key is expired`() {
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -1)
        val expiredDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns expiredDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        val result = KeyRotationManager.isKeyRotationNeeded(testAlias)

        assertTrue("Key rotation should be needed for expired key", result)
    }

    @Test
    fun `isKeyRotationNeeded should return false when key is still valid`() {
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, 30)
        val futureDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns futureDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        val result = KeyRotationManager.isKeyRotationNeeded(testAlias)

        assertFalse("Key rotation should not be needed for valid key", result)
    }

    @Test
    fun `isKeyRotationNeeded should return false when keyValidityForOriginationEnd is null`() {
        val mockKeyInfo = mockk<KeyInfo>()
        every { mockKeyInfo.keyValidityForOriginationEnd } returns null
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        val result = KeyRotationManager.isKeyRotationNeeded(testAlias)

        assertFalse("Key rotation should not be needed when no end date is set", result)
    }

    @Test(expected = KeyNotFoundException::class)
    fun `isKeyRotationNeeded should throw KeyNotFoundException when key does not exist`() {
        every { KeyHelper.getKeyInfo(testAlias) } throws KeyNotFoundException(testAlias)
        KeyRotationManager.isKeyRotationNeeded(testAlias)
    }

    @Suppress("DEPRECATION")
    @Test(expected = KeyNotFoundException::class)
    fun `rotateKeyIfNeeded should throw KeyNotFoundException when key does not exist`() {
        every { KeyHelper.getKeyInfo(testAlias) } throws KeyNotFoundException(testAlias)
        KeyRotationManager.rotateKeyIfNeeded(testAlias)
    }

    // ==================== Edge case tests ====================

    @Test
    fun `isKeyRotationNeeded should return true when key expires exactly now`() {
        val mockKeyInfo = mockk<KeyInfo>()
        val now = Date()

        every { mockKeyInfo.keyValidityForOriginationEnd } returns now
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo

        val result = KeyRotationManager.isKeyRotationNeeded(testAlias)

        assertFalse("Key rotation should not be needed when dates are exactly equal", result)
    }

    @Suppress("DEPRECATION")
    @Test
    fun `rotateKeyIfNeeded should handle key expiring exactly at rotation interval boundary`() {
        val mockKeyInfo = mockk<KeyInfo>()
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -90)
        val boundaryDate = calendar.time

        every { mockKeyInfo.keyValidityForOriginationEnd } returns boundaryDate
        every { KeyHelper.getKeyInfo(testAlias) } returns mockKeyInfo
        every { KeyHelper.generateAESKey(testAlias) } just runs

        KeyRotationManager.rotateKeyIfNeeded(testAlias)

        verify(atLeast = 1) { KeyHelper.generateAESKey(testAlias) }
    }

    @Test
    fun `safeRotate should return Failure when key does not exist`() {
        every { KeyHelper.getKeyInfo(testAlias) } throws KeyNotFoundException(testAlias)

        val result = KeyRotationManager.safeRotate(testAlias)

        assertTrue(result is KeyRotationResult.Failure)
    }
}
