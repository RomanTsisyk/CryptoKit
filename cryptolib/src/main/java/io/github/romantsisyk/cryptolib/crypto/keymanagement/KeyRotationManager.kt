package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.util.Log
import io.github.romantsisyk.cryptolib.exceptions.KeyGenerationException
import java.util.Calendar
import java.util.Date
import kotlin.concurrent.withLock

/**
 * Result of a safe key rotation attempt.
 */
sealed class KeyRotationResult {
    /** Key does not need rotation yet. */
    object NotNeeded : KeyRotationResult()

    /** Key was successfully rotated to a new versioned alias. */
    data class Success(val oldAlias: String, val newAlias: String) : KeyRotationResult()

    /** Key rotation failed. */
    data class Failure(val alias: String, val exception: Exception) : KeyRotationResult()
}

/**
 * Manages the rotation of cryptographic keys, ensuring they are rotated after a specific interval or when the key is expired.
 * Key rotation helps enhance security by periodically updating encryption keys.
 */
object KeyRotationManager {

    private const val TAG = "KeyRotationManager" // Log tag for debugging and error messages
    private const val ROTATION_INTERVAL_DAYS = 90 // Interval in days for automatic key rotation

    /**
     * Safely rotates the cryptographic key if it has expired or is within the proactive
     * rotation window (90 days before expiry). Generates a new AES key under a versioned
     * alias, keeping the old key intact for decryption of existing data.
     * Returns a result indicating the outcome.
     *
     * @param alias The alias identifying the key to rotate.
     * @return A [KeyRotationResult] indicating the outcome.
     */
    @JvmStatic
    fun safeRotate(alias: String): KeyRotationResult {
        // Lock the alias to prevent two concurrent rotations from computing
        // the same nextVersionedAlias and overwriting each other's key.
        return KeyHelper.lockForAlias(alias).withLock {
            try {
                val keyInfo = KeyHelper.getKeyInfo(alias)
                val keyValidityEndDate = keyInfo.keyValidityForOriginationEnd
                    ?: return@withLock KeyRotationResult.NotNeeded

                val currentDate = Date()

                if (!shouldRotateKey(currentDate, keyValidityEndDate)) {
                    val rotationDate = calculateRotationDate(keyValidityEndDate)
                    if (!shouldRotateKey(currentDate, rotationDate)) {
                        Log.d(TAG, "Key '$alias' does not require rotation yet.")
                        return@withLock KeyRotationResult.NotNeeded
                    }
                }

                val newAlias = KeyHelper.nextVersionedAlias(alias)
                KeyHelper.generateAESKey(newAlias)
                Log.d(TAG, "Key '$alias' rotated successfully to '$newAlias'.")
                KeyRotationResult.Success(oldAlias = alias, newAlias = newAlias)
            } catch (e: Exception) {
                Log.e(TAG, "Key rotation failed for '$alias': ${e.message}", e)
                KeyRotationResult.Failure(alias = alias, exception = e)
            }
        }
    }

    /**
     * Rotates the cryptographic key if it has expired or reached the defined rotation interval.
     * Generates a new AES key and deletes the old one after the rotation.
     * Logs success or failure of the key rotation process.
     *
     * @param alias The alias identifying the key to rotate.
     */
    @Deprecated("Use safeRotate() instead, which preserves the old key and returns a result.", replaceWith = ReplaceWith("safeRotate(alias)"))
    @JvmStatic
    fun rotateKeyIfNeeded(alias: String) {
        KeyHelper.lockForAlias(alias).withLock {
            val keyInfo = KeyHelper.getKeyInfo(alias) // Fetch current key information
            val keyValidityEndDate = keyInfo.keyValidityForOriginationEnd ?: return // No rotation needed if no end date is set
            val currentDate = Date()

            // Check if the key's validity has ended
            if (shouldRotateKey(currentDate, keyValidityEndDate)) {
                performKeyRotation(alias, "Key validity expired")
                return
            }

            // Check if the key should be rotated after a specific interval (e.g., 90 days)
            val rotationDate = calculateRotationDate(keyValidityEndDate)

            // If the key is older than the defined rotation date, rotate it
            if (shouldRotateKey(currentDate, rotationDate)) {
                performKeyRotation(alias, "Rotation interval exceeded")
                return
            }

            Log.d(TAG, "Key '$alias' does not require rotation yet.")
        }
    }

    /**
     * Determines whether the key should be rotated based on the current date and threshold date.
     *
     * @param currentDate The current date.
     * @param thresholdDate The date after which the key should be rotated.
     * @return True if the current date is after the threshold date, false otherwise.
     */
    private fun shouldRotateKey(currentDate: Date, thresholdDate: Date): Boolean {
        return currentDate.after(thresholdDate)
    }

    /**
     * Calculates the proactive rotation date by subtracting the rotation interval
     * from the key validity end date. This triggers rotation BEFORE the key expires,
     * giving time for a smooth transition to the new key.
     *
     * For example, with a 90-day rotation interval and a key expiring on day 365,
     * rotation is triggered on day 275 (365 - 90).
     *
     * @param keyValidityEndDate The key's validity end date.
     * @return The date at which rotation should begin (before expiry).
     */
    private fun calculateRotationDate(keyValidityEndDate: Date): Date {
        val calendar = Calendar.getInstance()
        calendar.time = keyValidityEndDate
        calendar.add(Calendar.DAY_OF_YEAR, -ROTATION_INTERVAL_DAYS)
        return calendar.time
    }

    /**
     * Performs the key rotation by generating a new AES key.
     * Logs success or failure of the key rotation process.
     *
     * @param alias The alias of the key to rotate.
     * @param reason The reason for the rotation (for logging purposes).
     */
    private fun performKeyRotation(alias: String, reason: String) {
        try {
            KeyHelper.generateAESKey(alias)
            Log.d(TAG, "Key '$alias' rotated successfully. Reason: $reason")
        } catch (e: KeyGenerationException) {
            Log.e(TAG, "Key rotation failed for '$alias': ${e.message}", e)
        }
    }

    /**
     * Checks whether a key needs to be rotated based on its expiration date.
     * The key is considered expired if the current date is after its validity end date.
     *
     * @param alias The alias of the key to check.
     * @return True if the key needs to be rotated, false otherwise.
     */
    @JvmStatic
    fun isKeyRotationNeeded(alias: String): Boolean {
        return try {
            val keyInfo = KeyHelper.getKeyInfo(alias)
            val keyValidityEndDate = keyInfo.keyValidityForOriginationEnd ?: return false
            val currentDate = Date()
            currentDate.after(keyValidityEndDate)
        } catch (e: Exception) {
            false
        }
    }
}
