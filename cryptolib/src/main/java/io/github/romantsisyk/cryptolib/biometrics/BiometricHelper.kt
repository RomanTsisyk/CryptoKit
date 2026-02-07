package io.github.romantsisyk.cryptolib.biometrics

import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity

/**
 * A pure authentication gateway that delegates biometric prompting.
 * All cipher initialization and crypto operations are the caller's responsibility.
 * BiometricHelper only shows the prompt with the provided CryptoObject and returns
 * the authenticated CryptoObject on success.
 */
class BiometricHelper {

    /**
     * Authenticates the user using biometric data (e.g., fingerprint).
     * The caller provides a pre-initialized CryptoObject; upon successful authentication
     * the authenticated CryptoObject is returned via onSuccess.
     *
     * Note on threading: All callbacks are invoked on the main thread (via [FragmentActivity.getMainExecutor]).
     *
     * @param activity The activity where the biometric prompt will be displayed.
     * @param title The title displayed on the biometric prompt.
     * @param description The description displayed on the biometric prompt.
     * @param cryptoObject The pre-initialized CryptoObject to authenticate with.
     * @param onSuccess Callback invoked with the authenticated CryptoObject on success.
     * @param onError Callback invoked if any error occurs during authentication.
     * @param onAuthenticationError Callback invoked on terminal authentication errors (e.g., lockout, user cancel).
     */
    fun authenticate(
        activity: FragmentActivity,
        title: String,
        description: String,
        cryptoObject: BiometricPrompt.CryptoObject,
        onSuccess: (BiometricPrompt.CryptoObject) -> Unit,
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
                    val authenticatedCryptoObject = result.cryptoObject
                    if (authenticatedCryptoObject == null) {
                        onError(Exception("Authenticated CryptoObject is null"))
                        return
                    }
                    onSuccess(authenticatedCryptoObject)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onAuthenticationError(errorCode, errString)
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    // Do NOT treat this as a terminal error. onAuthenticationFailed() fires
                    // on every individual failed attempt (e.g., wet fingerprint, wrong finger).
                    // The BiometricPrompt handles retries internally and will eventually call
                    // onAuthenticationError() if the user exhausts all attempts or cancels.
                    Log.d("BiometricHelper", "Biometric authentication attempt failed, user can retry")
                }
            }
        )

        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
