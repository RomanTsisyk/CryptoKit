package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.content.Context
import androidx.work.*

/**
 * This worker handles the automatic key rotation process by checking the stored keys
 * and triggering key rotation when needed. It runs periodically to ensure keys are rotated
 * as per the defined schedule.
 */
class KeyRotationWorker(appContext: Context, workerParams: WorkerParameters) :
    Worker(appContext, workerParams) {

    /**
     * Performs the key rotation check for each stored key.
     * If a key requires rotation, it will be handled by the KeyRotationManager.
     *
     * @return Result of the work (success or failure).
     */
    override fun doWork(): Result {
        val keys = KeyHelper.listKeys()
        keys.forEach { alias ->
            KeyRotationManager.rotateKeyIfNeeded(alias)
        }
        return Result.success()
    }
}
