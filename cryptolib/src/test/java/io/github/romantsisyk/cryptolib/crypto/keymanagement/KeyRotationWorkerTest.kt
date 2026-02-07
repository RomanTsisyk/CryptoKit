package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.content.Context
import androidx.work.ListenableWorker
import androidx.work.WorkerParameters
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class KeyRotationWorkerTest {

    private lateinit var context: Context
    private lateinit var workerParams: WorkerParameters

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        workerParams = mockk(relaxed = true)
        mockkObject(KeyHelper)
        mockkObject(KeyRotationManager)
    }

    @After
    fun tearDown() {
        unmockkObject(KeyHelper)
        unmockkObject(KeyRotationManager)
    }

    // ==================== Test: doWork returns success when all rotations succeed ====================

    @Test
    fun `doWork should return success when all key rotations succeed`() {
        // Arrange
        val keys = listOf("key1", "key2", "key3")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate("key1") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key2") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key3") } returns KeyRotationResult.NotNeeded

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.success(), result)
        verify(exactly = 1) { KeyHelper.listKeys() }
        verify(exactly = 3) { KeyRotationManager.safeRotate(any()) }
        keys.forEach { alias ->
            verify(exactly = 1) { KeyRotationManager.safeRotate(alias) }
        }
    }

    @Test
    fun `doWork should return success with single key`() {
        // Arrange
        val keys = listOf("single_key")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate("single_key") } returns KeyRotationResult.NotNeeded

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.success(), result)
        verify(exactly = 1) { KeyRotationManager.safeRotate("single_key") }
    }

    @Test
    fun `doWork should return success when rotation produces Success result`() {
        // Arrange
        val keys = listOf("key1")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate("key1") } returns KeyRotationResult.Success("key1", "key1_v2")

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.success(), result)
    }

    // ==================== Test: doWork returns retry when some rotations fail (under 3 attempts) ====================

    @Test
    fun `doWork should return retry when some rotations fail and attempt count is below max`() {
        // Arrange
        val keys = listOf("key1", "key2", "key3")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate("key1") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key2") } returns KeyRotationResult.Failure("key2", RuntimeException("Rotation failed"))
        every { KeyRotationManager.safeRotate("key3") } returns KeyRotationResult.NotNeeded
        every { workerParams.runAttemptCount } returns 0

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.retry(), result)
    }

    @Test
    fun `doWork should return retry when all rotations fail and attempt count is 1`() {
        // Arrange
        val keys = listOf("key1", "key2")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate(any()) } returns KeyRotationResult.Failure("key", RuntimeException("Rotation failed"))
        every { workerParams.runAttemptCount } returns 1

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.retry(), result)
    }

    @Test
    fun `doWork should return retry when some rotations fail and attempt count is 2`() {
        // Arrange
        val keys = listOf("key1", "key2")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate("key1") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key2") } returns KeyRotationResult.Failure("key2", RuntimeException("Rotation failed"))
        every { workerParams.runAttemptCount } returns 2

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.retry(), result)
    }

    // ==================== Test: doWork returns failure after max retries ====================

    @Test
    fun `doWork should return failure when rotations fail and attempt count equals max retries`() {
        // Arrange
        val keys = listOf("key1", "key2")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate("key1") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key2") } returns KeyRotationResult.Failure("key2", RuntimeException("Rotation failed"))
        every { workerParams.runAttemptCount } returns 3

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.failure(), result)
    }

    @Test
    fun `doWork should return failure when rotations fail and attempt count exceeds max retries`() {
        // Arrange
        val keys = listOf("key1")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate(any()) } returns KeyRotationResult.Failure("key1", RuntimeException("Rotation failed"))
        every { workerParams.runAttemptCount } returns 5

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.failure(), result)
    }

    @Test
    fun `doWork should return failure when all rotations fail after max retries`() {
        // Arrange
        val keys = listOf("key1", "key2", "key3")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate(any()) } returns KeyRotationResult.Failure("key", RuntimeException("Rotation failed"))
        every { workerParams.runAttemptCount } returns 4

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.failure(), result)
        verify(exactly = 3) { KeyRotationManager.safeRotate(any()) }
    }

    // ==================== Test: doWork handles empty key list ====================

    @Test
    fun `doWork should return success when key list is empty`() {
        // Arrange
        every { KeyHelper.listKeys() } returns emptyList()

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.success(), result)
        verify(exactly = 1) { KeyHelper.listKeys() }
        verify(exactly = 0) { KeyRotationManager.safeRotate(any()) }
    }

    // ==================== Test: doWork handles exception from KeyHelper.listKeys() ====================

    @Test
    fun `doWork should return retry when KeyHelper listKeys throws exception`() {
        // Arrange
        every { KeyHelper.listKeys() } throws RuntimeException("Failed to access keystore")

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.retry(), result)
        verify(exactly = 1) { KeyHelper.listKeys() }
        verify(exactly = 0) { KeyRotationManager.safeRotate(any()) }
    }

    @Test
    fun `doWork should return retry when KeyHelper listKeys throws SecurityException`() {
        // Arrange
        every { KeyHelper.listKeys() } throws SecurityException("Access denied to keystore")

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.retry(), result)
    }

    @Test
    fun `doWork should return retry when KeyHelper listKeys throws IllegalStateException`() {
        // Arrange
        every { KeyHelper.listKeys() } throws IllegalStateException("Keystore not initialized")

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.retry(), result)
    }

    // ==================== Additional edge case tests ====================

    @Test
    fun `doWork should handle mixed success and failure scenarios correctly`() {
        // Arrange: 2 successes and 2 failures
        val keys = listOf("key1", "key2", "key3", "key4")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate("key1") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key2") } returns KeyRotationResult.Failure("key2", RuntimeException("Failed"))
        every { KeyRotationManager.safeRotate("key3") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key4") } returns KeyRotationResult.Failure("key4", RuntimeException("Failed"))
        every { workerParams.runAttemptCount } returns 1

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.retry(), result)
        verify(exactly = 4) { KeyRotationManager.safeRotate(any()) }
    }

    @Test
    fun `doWork should process all keys even when first key rotation fails`() {
        // Arrange
        val keys = listOf("key1", "key2", "key3")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate("key1") } returns KeyRotationResult.Failure("key1", RuntimeException("Failed"))
        every { KeyRotationManager.safeRotate("key2") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key3") } returns KeyRotationResult.NotNeeded
        every { workerParams.runAttemptCount } returns 0

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.retry(), result)
        // Verify all keys were processed despite first failure
        verify(exactly = 1) { KeyRotationManager.safeRotate("key1") }
        verify(exactly = 1) { KeyRotationManager.safeRotate("key2") }
        verify(exactly = 1) { KeyRotationManager.safeRotate("key3") }
    }

    @Test
    fun `doWork should process all keys even when last key rotation fails`() {
        // Arrange
        val keys = listOf("key1", "key2", "key3")
        every { KeyHelper.listKeys() } returns keys
        every { KeyRotationManager.safeRotate("key1") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key2") } returns KeyRotationResult.NotNeeded
        every { KeyRotationManager.safeRotate("key3") } returns KeyRotationResult.Failure("key3", RuntimeException("Failed"))
        every { workerParams.runAttemptCount } returns 0

        val worker = KeyRotationWorker(context, workerParams)

        // Act
        val result = worker.doWork()

        // Assert
        assertEquals(ListenableWorker.Result.retry(), result)
        verify(exactly = 3) { KeyRotationManager.safeRotate(any()) }
    }
}
