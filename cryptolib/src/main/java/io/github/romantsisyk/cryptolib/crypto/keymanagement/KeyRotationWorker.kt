package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.content.Context
import android.util.Log
import androidx.work.*

/**
 * This worker handles the automatic key rotation process by checking the stored keys
 * and triggering key rotation when needed. It runs periodically to ensure keys are rotated
 * as per the defined schedule.
 */
class KeyRotationWorker(appContext: Context, workerParams: WorkerParameters) :
    Worker(appContext, workerParams) {

    companion object {
        private const val TAG = "KeyRotationWorker"
    }

    /**
     * Performs the key rotation check for each stored key.
     * If a key requires rotation, it will be handled by the KeyRotationManager.
     *
     * @return Result of the work (success, retry, or failure).
     */
    override fun doWork(): Result {
        var failedRotations = 0
        var successfulRotations = 0

        try {
            val keys = KeyHelper.listKeys()
            Log.d(TAG, "Starting key rotation check for ${keys.size} keys")

            keys.forEach { alias ->
                try {
                    KeyRotationManager.rotateKeyIfNeeded(alias)
                    successfulRotations++
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to rotate key '$alias': ${e.message}", e)
                    failedRotations++
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to list keys for rotation: ${e.message}", e)
            return Result.retry()
        }

        return when {
            failedRotations > 0 && runAttemptCount < 3 -> {
                Log.w(TAG, "Key rotation completed with $failedRotations failures, $successfulRotations successes. Scheduling retry.")
                Result.retry()
            }
            failedRotations > 0 -> {
                Log.e(TAG, "Key rotation failed after $runAttemptCount attempts. Failures: $failedRotations, Successes: $successfulRotations")
                Result.failure()
            }
            else -> {
                Log.d(TAG, "Key rotation completed successfully. Rotated $successfulRotations keys.")
                Result.success()
            }
        }
    }
}
