package io.github.romantsisyk.cryptolib.crypto.manager

import BiometricHelper
import android.app.Activity
import androidx.fragment.app.FragmentActivity
import io.github.romantsisyk.cryptolib.crypto.config.CryptoConfig
import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationManager
import io.github.romantsisyk.cryptolib.exceptions.*

object CryptoManager {

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
            activity,
            config,
            title = "Encrypt Data",
            description = "Authenticate to encrypt your data",
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
            activity,
            config,
            title = "Decrypt Data",
            description = "Authenticate to decrypt your data",
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
     * @param onAuthenticated Callback invoked with the retrieved secret key after successful authentication.
     * @param onFailure Callback invoked with an error if the operation fails.
     */
    private fun performAuthenticatedAction(
        activity: Activity,
        config: CryptoConfig,
        title: String,
        description: String,
        onAuthenticated: (javax.crypto.SecretKey) -> Unit,
        onFailure: (CryptoLibException) -> Unit
    ) {
        try {
            // Check if key exists, else generate it
            if (!KeyHelper.listKeys().contains(config.keyAlias)) {
                KeyHelper.generateAESKey(
                    alias = config.keyAlias,
                    validityDays = config.keyValidityDays,
                    requireUserAuthentication = config.requireUserAuthentication
                )
            }

            val secretKey = KeyHelper.getAESKey(config.keyAlias)

            if (config.requireUserAuthentication) {
                // Perform biometric authentication
                BiometricHelper(context = activity).authenticate(
                    activity = activity as FragmentActivity,
                    title = title,
                    description = description,
                    onSuccess = {
                        onAuthenticated(secretKey)
                    },
                    encryptedData = "testEncryptedData".toByteArray(Charsets.UTF_8),
                    onAuthenticationError = { errorCode, errString ->
                        onFailure(
                            AuthenticationException(
                                "Authentication error [$errorCode]: $errString"
                            )
                        )
                    },
                    onError = { exception -> println("Error: ${exception.message}") }
                )
            } else {
                onAuthenticated(secretKey)
            }
        } catch (e: KeyNotFoundException) {
            onFailure(e)
        } catch (e: CryptoLibException) {
            onFailure(e)
        }
    }
}