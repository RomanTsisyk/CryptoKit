package io.github.romantsisyk.cryptolib.crypto.manager

import android.app.Activity
import android.util.Log
import androidx.fragment.app.FragmentActivity
import io.github.romantsisyk.cryptolib.biometrics.BiometricHelper
import io.github.romantsisyk.cryptolib.crypto.config.CryptoConfig
import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationManager
import io.github.romantsisyk.cryptolib.exceptions.*

object CryptoManager {

    private const val TAG = "CryptoManager"

    /**
     * Encrypts the provided plaintext data after authenticating the user, if required.
     * @param activity The activity context used for user authentication (if enabled).
     * @param config The CryptoConfig object containing encryption configuration.
     * @param plaintext The plaintext data to encrypt.
     * @param onSuccess Callback invoked with the encrypted data (in base64 format) upon success.
     * @param onFailure Callback invoked with an error if encryption fails.
     */
    fun encryptData(
        activity: Activity,
        config: CryptoConfig,
        plaintext: ByteArray,
        onSuccess: (String) -> Unit,
        onFailure: (CryptoLibException) -> Unit
    ) {
        performAuthenticatedAction(
            activity = activity,
            config = config,
            title = "Encrypt Data",
            description = "Authenticate to encrypt your data",
            encryptedData = null,
            onAuthenticated = { secretKey ->
                try {
                    val encryptedData = AESEncryption.encrypt(plaintext, secretKey)
                    onSuccess(encryptedData)

                    // Schedule key rotation if needed
                    KeyRotationManager.rotateKeyIfNeeded(config.keyAlias)
                } catch (e: CryptoOperationException) {
                    onFailure(e)
                }
            },
            onFailure = onFailure
        )
    }

    /**
     * Decrypts the provided encrypted data after authenticating the user, if required.
     * @param activity The activity context used for user authentication (if enabled).
     * @param config The CryptoConfig object containing decryption configuration.
     * @param encryptedData The encrypted data in base64 format to decrypt.
     * @param onSuccess Callback invoked with the decrypted data upon success.
     * @param onFailure Callback invoked with an error if decryption fails.
     */
    fun decryptData(
        activity: Activity,
        config: CryptoConfig,
        encryptedData: String,
        onSuccess: (ByteArray) -> Unit,
        onFailure: (CryptoLibException) -> Unit
    ) {
        performAuthenticatedAction(
            activity = activity,
            config = config,
            title = "Decrypt Data",
            description = "Authenticate to decrypt your data",
            encryptedData = encryptedData.toByteArray(Charsets.UTF_8),
            onAuthenticated = { secretKey ->
                try {
                    val decryptedData = AESEncryption.decrypt(encryptedData, secretKey)
                    onSuccess(decryptedData)
                } catch (e: CryptoOperationException) {
                    onFailure(e)
                }
            },
            onFailure = onFailure
        )
    }

    /**
     * Performs user authentication and retrieves the secret key for encryption or decryption.
     * @param activity The activity context used for user authentication (if enabled).
     * @param config The CryptoConfig object containing key configuration.
     * @param title Title displayed during authentication.
     * @param description Description displayed during authentication.
     * @param encryptedData The encrypted data to be used during biometric authentication (for decryption), or null for encryption operations.
     * @param onAuthenticated Callback invoked with the retrieved secret key after successful authentication.
     * @param onFailure Callback invoked with an error if the operation fails.
     */
    private fun performAuthenticatedAction(
        activity: Activity,
        config: CryptoConfig,
        title: String,
        description: String,
        encryptedData: ByteArray?,
        onAuthenticated: (javax.crypto.SecretKey) -> Unit,
        onFailure: (CryptoLibException) -> Unit
    ) {
        try {
            // Check if key exists, else generate it
            if (!KeyHelper.listKeys().contains(config.keyAlias)) {
                try {
                    KeyHelper.generateAESKey(
                        alias = config.keyAlias,
                        validityDays = config.keyValidityDays,
                        requireUserAuthentication = config.requireUserAuthentication
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to generate AES key: ${e.message}", e)
                    onFailure(CryptoOperationException("Failed to generate AES key", e))
                    return
                }
            }

            val secretKey = try {
                KeyHelper.getAESKey(config.keyAlias)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to retrieve AES key: ${e.message}", e)
                onFailure(KeyNotFoundException("Failed to retrieve key for alias: ${config.keyAlias}", e))
                return
            }

            if (config.requireUserAuthentication) {
                // Perform biometric authentication
                if (activity !is FragmentActivity) {
                    onFailure(
                        CryptoOperationException(
                            "Biometric authentication requires a FragmentActivity. " +
                                "The provided activity is of type ${activity::class.java.name}."
                        )
                    )
                    return
                }
                val dataForAuth = encryptedData ?: ByteArray(0)
                BiometricHelper(context = activity).authenticate(
                    activity = activity,
                    title = title,
                    description = description,
                    onSuccess = {
                        onAuthenticated(secretKey)
                    },
                    encryptedData = dataForAuth,
                    onAuthenticationError = { errorCode, errString ->
                        Log.e(TAG, "Authentication error [$errorCode]: $errString")
                        onFailure(
                            AuthenticationException(
                                "Authentication error [$errorCode]: $errString"
                            )
                        )
                    },
                    onError = { exception ->
                        Log.e(TAG, "Error: ${exception.message}", exception)
                        onFailure(
                            CryptoOperationException(
                                "Biometric authentication error: ${exception.message}",
                                exception
                            )
                        )
                    }
                )
            } else {
                onAuthenticated(secretKey)
            }
        } catch (e: KeyNotFoundException) {
            Log.e(TAG, "Key not found: ${e.message}", e)
            onFailure(e)
        } catch (e: CryptoLibException) {
            Log.e(TAG, "Crypto operation failed: ${e.message}", e)
            onFailure(e)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error: ${e.message}", e)
            onFailure(CryptoOperationException("Unexpected error during authenticated action", e))
        }
    }
}