package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.util.Log
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
    fun rotateKeyIfNeeded(alias: String) {
        val keyInfo = KeyHelper.getKeyInfo(alias) // Fetch current key information
        val keyValidityEndDate = keyInfo.keyValidityForOriginationEnd ?: return // No rotation needed if no end date is set
        val currentDate = Date()

        // Check if the key's validity has ended
        if (currentDate.after(keyValidityEndDate)) {
            try {
                KeyHelper.generateAESKey(alias) // Generate new key if the current one is expired
                Log.d(TAG, "Key '$alias' rotated successfully.")
            } catch (e: Exception) {
                Log.e(TAG, "Key rotation failed for '$alias': ${e.message}")
            }
        } else {
            Log.d(TAG, "Key '$alias' does not require rotation yet.")
        }

        // Check if the key should be rotated after a specific interval (e.g., 90 days)
        val calendar = Calendar.getInstance()
        calendar.time = keyValidityEndDate
        calendar.add(Calendar.DAY_OF_YEAR, ROTATION_INTERVAL_DAYS)
        val rotationDate = calendar.time

        // If the key is older than the defined rotation date, rotate it
        if (currentDate.after(rotationDate)) {
            try {
                KeyHelper.generateAESKey(alias) // Generate new key if the interval has passed
                Log.d(TAG, "Key '$alias' rotated successfully.")
            } catch (e: Exception) {
                Log.e(TAG, "Key rotation failed for '$alias': ${e.message}")
            }
        } else {
            Log.d(TAG, "Key '$alias' does not require rotation yet.")
        }
    }

    /**
     * Checks whether a key needs to be rotated based on its expiration date.
     * The key is considered expired if the current date is after its validity end date.
     *
     * @param alias The alias of the key to check.
     * @return True if the key needs to be rotated, false otherwise.
     */
    fun isKeyRotationNeeded(alias: String): Boolean {
        val keyInfo = KeyHelper.getKeyInfo(alias) ?: return false
        val keyValidityEndDate = keyInfo.keyValidityForOriginationEnd ?: return false
        val currentDate = Date()
        return currentDate.after(keyValidityEndDate) // Check if the current date is after the expiration date
    }
}
