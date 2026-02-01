package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.util.Log
import io.github.romantsisyk.cryptolib.exceptions.KeyGenerationException
import java.util.Calendar
import java.util.Date

/**
 * Manages the rotation of cryptographic keys, ensuring they are rotated after a specific interval or when the key is expired.
 * Key rotation helps enhance security by periodically updating encryption keys.
 */
object KeyRotationManager {

    private const val TAG = "KeyRotationManager" // Log tag for debugging and error messages
    private const val ROTATION_INTERVAL_DAYS = 90 // Interval in days for automatic key rotation

    /**
     * Rotates the cryptographic key if it has expired or reached the defined rotation interval.
     * Generates a new AES key and deletes the old one after the rotation.
     * Logs success or failure of the key rotation process.
     *
     * @param alias The alias identifying the key to rotate.
     */
    @JvmStatic
    fun rotateKeyIfNeeded(alias: String) {
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
     * Calculates the rotation date by adding the rotation interval to the key validity end date.
     *
     * @param keyValidityEndDate The key's validity end date.
     * @return The calculated rotation date.
     */
    private fun calculateRotationDate(keyValidityEndDate: Date): Date {
        val calendar = Calendar.getInstance()
        calendar.time = keyValidityEndDate
        calendar.add(Calendar.DAY_OF_YEAR, ROTATION_INTERVAL_DAYS)
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
        val keyInfo = KeyHelper.getKeyInfo(alias) ?: return false
        val keyValidityEndDate = keyInfo.keyValidityForOriginationEnd ?: return false
        val currentDate = Date()
        return currentDate.after(keyValidityEndDate) // Check if the current date is after the expiration date
    }
}
