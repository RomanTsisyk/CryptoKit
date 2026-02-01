package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequest
import androidx.work.WorkManager
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkStatic
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit

class KeyRotationSchedulerTest {

    private lateinit var mockContext: Context
    private lateinit var mockWorkManager: WorkManager

    @Before
    fun setUp() {
        mockContext = mockk(relaxed = true)
        mockWorkManager = mockk(relaxed = true)

        mockkStatic(WorkManager::class)
        every { WorkManager.getInstance(any()) } returns mockWorkManager
    }

    @After
    fun tearDown() {
        unmockkStatic(WorkManager::class)
    }

    @Test
    fun `scheduleKeyRotation should create periodic work request`() {
        // Arrange
        val workRequestSlot = slot<PeriodicWorkRequest>()
        every {
            mockWorkManager.enqueueUniquePeriodicWork(
                any(),
                any(),
                capture(workRequestSlot)
            )
        } returns mockk(relaxed = true)

        // Act
        KeyRotationScheduler.scheduleKeyRotation(mockContext)

        // Assert
        verify(exactly = 1) {
            mockWorkManager.enqueueUniquePeriodicWork(
                any(),
                any(),
                any<PeriodicWorkRequest>()
            )
        }
        assertTrue("Work request should be captured", workRequestSlot.isCaptured)
    }

    @Test
    fun `scheduleKeyRotation should use correct work name`() {
        // Arrange
        val workNameSlot = slot<String>()
        every {
            mockWorkManager.enqueueUniquePeriodicWork(
                capture(workNameSlot),
                any(),
                any<PeriodicWorkRequest>()
            )
        } returns mockk(relaxed = true)

        // Act
        KeyRotationScheduler.scheduleKeyRotation(mockContext)

        // Assert
        assertEquals("KeyRotationWork", workNameSlot.captured)
    }

    @Test
    fun `scheduleKeyRotation should use KEEP policy for existing work`() {
        // Arrange
        val policySlot = slot<ExistingPeriodicWorkPolicy>()
        every {
            mockWorkManager.enqueueUniquePeriodicWork(
                any(),
                capture(policySlot),
                any<PeriodicWorkRequest>()
            )
        } returns mockk(relaxed = true)

        // Act
        KeyRotationScheduler.scheduleKeyRotation(mockContext)

        // Assert
        assertEquals(ExistingPeriodicWorkPolicy.KEEP, policySlot.captured)
    }

    @Test
    fun `scheduleKeyRotation should create work request with correct interval`() {
        // Arrange
        val workRequestSlot = slot<PeriodicWorkRequest>()
        every {
            mockWorkManager.enqueueUniquePeriodicWork(
                any(),
                any(),
                capture(workRequestSlot)
            )
        } returns mockk(relaxed = true)

        // Act
        KeyRotationScheduler.scheduleKeyRotation(mockContext)

        // Assert
        val capturedRequest = workRequestSlot.captured
        val workSpec = capturedRequest.workSpec

        // The implementation uses 7 days interval
        val expectedIntervalMillis = TimeUnit.DAYS.toMillis(7)
        assertEquals(
            "Work request should have 7 day interval",
            expectedIntervalMillis,
            workSpec.intervalDuration
        )
    }

    @Test
    fun `scheduleKeyRotation should set battery not low constraint`() {
        // Arrange
        val workRequestSlot = slot<PeriodicWorkRequest>()
        every {
            mockWorkManager.enqueueUniquePeriodicWork(
                any(),
                any(),
                capture(workRequestSlot)
            )
        } returns mockk(relaxed = true)

        // Act
        KeyRotationScheduler.scheduleKeyRotation(mockContext)

        // Assert
        val capturedRequest = workRequestSlot.captured
        val constraints = capturedRequest.workSpec.constraints

        assertTrue(
            "Work request should have battery not low constraint",
            constraints.requiresBatteryNotLow()
        )
    }

    @Test
    fun `scheduleKeyRotation should get WorkManager instance with provided context`() {
        // Arrange
        every {
            mockWorkManager.enqueueUniquePeriodicWork(
                any(),
                any(),
                any<PeriodicWorkRequest>()
            )
        } returns mockk(relaxed = true)

        // Act
        KeyRotationScheduler.scheduleKeyRotation(mockContext)

        // Assert
        verify(exactly = 1) { WorkManager.getInstance(mockContext) }
    }
}
