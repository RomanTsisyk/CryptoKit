import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import javax.crypto.Cipher

class BiometricHelper(private val context: Context) {

    /**
     * Authenticates the user using biometric data (e.g., fingerprint) and optionally decrypts encrypted data after successful authentication.
     * Provides success and error callbacks for handling decryption and authentication results.
     *
     * @param activity The activity where the biometric prompt will be displayed.
     * @param encryptedData The encrypted data to be decrypted upon successful authentication.
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
                        // Decrypt the data using the authenticated cipher
                        val decryptedData = result.cryptoObject?.cipher?.let {
                            AESEncryption.decrypt(
                                encryptedData.toString(Charsets.UTF_8),
                                KeyHelper.getKey()
                            )
                        }
                        if (decryptedData != null) {
                            onSuccess(decryptedData) // Handle success
                        } else {
                            onError(Exception("Decryption returned null")) // Handle decryption failure
                        }
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

        val cipher = getCipher() // Initialize cipher for decryption
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        biometricPrompt.authenticate(promptInfo, cryptoObject) // Start authentication
    }

    /**
     * Initializes a Cipher object for AES decryption.
     * The cipher is initialized with the secure key and is used to decrypt data.
     *
     * @return A Cipher initialized in DECRYPT_MODE.
     * @throws IllegalStateException if initialization fails.
     */
    private fun getCipher(): Cipher {
        return try {
            val secretKey = KeyHelper.getKey() // Retrieve the secure key from KeyHelper
            val cipher = Cipher.getInstance("AES/GCM/NoPadding") // AES GCM mode
            cipher.init(Cipher.DECRYPT_MODE, secretKey) // Initialize cipher for decryption
            cipher
        } catch (e: Exception) {
            throw IllegalStateException("Failed to initialize Cipher", e) // Handle initialization failure
        }
    }

    /**
     * Decrypts the provided encrypted data using the specified Cipher.
     * This method is invoked as part of the decryption process after successful authentication.
     *
     * @param cipher The Cipher used for decryption.
     * @param encryptedData The encrypted data to decrypt.
     * @return The decrypted data as a ByteArray.
     */
    private fun decryptData(cipher: Cipher, encryptedData: ByteArray): ByteArray {
        return cipher.doFinal(encryptedData) // Perform decryption
    }
}