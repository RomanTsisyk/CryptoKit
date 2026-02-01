package io.github.romantsisyk.cryptolib.biometrics

import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

class BiometricHelper(private val context: Context) {

    companion object {
        private const val IV_SIZE = 12 // IV size for AES-GCM (in bytes)
        private const val TAG_SIZE = 128 // Tag size for GCM mode (in bits)
    }

    /**
     * Authenticates the user using biometric data (e.g., fingerprint) and optionally decrypts encrypted data after successful authentication.
     * Provides success and error callbacks for handling decryption and authentication results.
     *
     * @param activity The activity where the biometric prompt will be displayed.
     * @param encryptedData The Base64-encoded encrypted data (IV prepended) to be decrypted upon successful authentication.
     * @param title The title displayed on the biometric prompt.
     * @param description The description displayed on the biometric prompt.
     * @param onSuccess Callback invoked with decrypted data on successful authentication.
     * @param onError Callback invoked if any error occurs during decryption or authentication.
     * @param onAuthenticationError Callback invoked on authentication errors (e.g., failed fingerprint scan).
     */
    fun authenticate(
        activity: FragmentActivity,
        title: String,
        description: String,
        encryptedData: ByteArray,
        onSuccess: (ByteArray) -> Unit,
        onError: (Exception) -> Unit,
        onAuthenticationError: (Int, CharSequence) -> Unit
    ) {
        // Extract IV from the encrypted data (first 12 bytes after Base64 decoding)
        val encryptedBytes = try {
            Base64.getDecoder().decode(encryptedData)
        } catch (e: Exception) {
            onError(IllegalArgumentException("Invalid Base64-encoded encrypted data", e))
            return
        }

        if (encryptedBytes.size < IV_SIZE) {
            onError(IllegalArgumentException("Encrypted data is too short to contain IV"))
            return
        }

        val iv = encryptedBytes.copyOfRange(0, IV_SIZE)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setDescription(description)
            .setSubtitle("Log in using your biometrics")
            .setNegativeButtonText("Cancel")
            .build()

        val biometricPrompt = BiometricPrompt(
            activity,
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    try {
                        // Get the authenticated cipher from the CryptoObject
                        val cipher = result.cryptoObject?.cipher
                        if (cipher == null) {
                            onError(Exception("Authenticated cipher is null"))
                            return
                        }

                        // Extract the ciphertext (excluding the IV prefix which was already used during cipher initialization)
                        val ciphertext = encryptedBytes.copyOfRange(IV_SIZE, encryptedBytes.size)

                        // Decrypt using the authenticated cipher
                        val decryptedData = cipher.doFinal(ciphertext)
                        onSuccess(decryptedData) // Handle success
                    } catch (e: Exception) {
                        onError(e) // Handle exception
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onAuthenticationError(errorCode, errString) // Handle authentication error
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    onError(Exception("Authentication failed")) // Handle failed authentication
                }
            }
        )

        val cipher = getCipher(iv) // Initialize cipher for decryption with IV
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        biometricPrompt.authenticate(promptInfo, cryptoObject) // Start authentication
    }

    /**
     * Initializes a Cipher object for AES-GCM decryption with the provided IV.
     * The cipher is initialized with the secure key and IV, and is used to decrypt data.
     *
     * @param iv The Initialization Vector (IV) extracted from the encrypted data.
     * @return A Cipher initialized in DECRYPT_MODE with the provided IV.
     * @throws IllegalStateException if initialization fails.
     */
    private fun getCipher(iv: ByteArray): Cipher {
        return try {
            val secretKey = KeyHelper.getKey() // Retrieve the secure key from KeyHelper
            val cipher = Cipher.getInstance("AES/GCM/NoPadding") // AES GCM mode
            val spec = GCMParameterSpec(TAG_SIZE, iv) // Create GCM parameter spec with IV
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec) // Initialize cipher for decryption with IV
            cipher
        } catch (e: Exception) {
            throw IllegalStateException("Failed to initialize Cipher", e) // Handle initialization failure
        }
    }
}