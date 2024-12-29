package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit


/**
 * This object is responsible for scheduling key rotation tasks using the WorkManager.
 * It ensures key rotation is performed periodically based on the defined schedule.
 */
object KeyRotationScheduler {

    /**
     * Schedules the key rotation task to run periodically every week.
     * The task checks the keys to determine if rotation is necessary.
     *
     * @param context the application context needed to enqueue the work.
     */
    fun scheduleKeyRotation(context: Context) {
        val rotationWork = PeriodicWorkRequestBuilder<KeyRotationWorker>(7, TimeUnit.DAYS) // Check every week
            .setConstraints(
                Constraints.Builder()
                    .setRequiresBatteryNotLow(true) // Only run when the battery is not low
                    .build()
            )
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            "KeyRotationWork",
            ExistingPeriodicWorkPolicy.KEEP,
            rotationWork
        )
    }
}