package io.github.romantsisyk.cryptolib.crypto.manager

import android.app.Activity
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.github.romantsisyk.cryptolib.biometrics.BiometricHelper
import io.github.romantsisyk.cryptolib.crypto.config.CryptoConfig
import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper
import io.github.romantsisyk.cryptolib.exceptions.*
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.withLock

object CryptoManager {

    private const val TAG = "CryptoManager"
    private const val IV_SIZE = 12
    private const val TAG_SIZE = 128
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

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
        try {
            val secretKey = getOrCreateKey(config, onFailure) ?: return

            if (config.requireUserAuthentication) {
                if (activity !is FragmentActivity) {
                    onFailure(
                        CryptoOperationException(
                            "Biometric authentication requires a FragmentActivity. " +
                                "The provided activity is of type ${activity::class.java.name}."
                        )
                    )
                    return
                }

                val cipher = try {
                    Cipher.getInstance(TRANSFORMATION).apply {
                        init(Cipher.ENCRYPT_MODE, secretKey)
                    }
                } catch (e: Exception) {
                    onFailure(CryptoOperationException("Failed to initialize cipher for encryption", e))
                    return
                }

                val cryptoObject = BiometricPrompt.CryptoObject(cipher)
                BiometricHelper().authenticate(
                    activity = activity,
                    title = "Encrypt Data",
                    description = "Authenticate to encrypt your data",
                    cryptoObject = cryptoObject,
                    onSuccess = { authenticatedCryptoObject ->
                        try {
                            val authenticatedCipher = authenticatedCryptoObject.cipher
                                ?: throw CryptoOperationException("Authenticated cipher is null")
                            val ciphertext = authenticatedCipher.doFinal(plaintext)
                            val iv = authenticatedCipher.iv
                            val combined = iv + ciphertext
                            onSuccess(Base64.getEncoder().encodeToString(combined))
                        } catch (e: CryptoOperationException) {
                            onFailure(e)
                        } catch (e: Exception) {
                            onFailure(CryptoOperationException("Encryption failed after authentication", e))
                        }
                    },
                    onAuthenticationError = { errorCode, errString ->
                        Log.e(TAG, "Authentication error [$errorCode]: $errString")
                        onFailure(AuthenticationException("Authentication error [$errorCode]: $errString"))
                    },
                    onError = { exception ->
                        Log.e(TAG, "Error: ${exception.message}", exception)
                        onFailure(CryptoOperationException("Biometric authentication error: ${exception.message}", exception))
                    }
                )
            } else {
                try {
                    val encryptedData = AESEncryption.encrypt(plaintext, secretKey)
                    onSuccess(encryptedData)
                } catch (e: CryptoOperationException) {
                    onFailure(e)
                }
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
        try {
            val secretKey = getOrCreateKey(config, onFailure) ?: return

            if (config.requireUserAuthentication) {
                if (activity !is FragmentActivity) {
                    onFailure(
                        CryptoOperationException(
                            "Biometric authentication requires a FragmentActivity. " +
                                "The provided activity is of type ${activity::class.java.name}."
                        )
                    )
                    return
                }

                val encryptedBytes = try {
                    Base64.getDecoder().decode(encryptedData)
                } catch (e: Exception) {
                    onFailure(CryptoOperationException("Failed to decode encrypted data", e))
                    return
                }

                if (encryptedBytes.size < IV_SIZE) {
                    onFailure(CryptoOperationException("Encrypted data is too short to contain IV"))
                    return
                }

                val iv = encryptedBytes.copyOfRange(0, IV_SIZE)

                val cipher = try {
                    Cipher.getInstance(TRANSFORMATION).apply {
                        init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_SIZE, iv))
                    }
                } catch (e: Exception) {
                    onFailure(CryptoOperationException("Failed to initialize cipher for decryption", e))
                    return
                }

                val cryptoObject = BiometricPrompt.CryptoObject(cipher)
                BiometricHelper().authenticate(
                    activity = activity,
                    title = "Decrypt Data",
                    description = "Authenticate to decrypt your data",
                    cryptoObject = cryptoObject,
                    onSuccess = { authenticatedCryptoObject ->
                        try {
                            val authenticatedCipher = authenticatedCryptoObject.cipher
                                ?: throw CryptoOperationException("Authenticated cipher is null")
                            val ciphertext = encryptedBytes.copyOfRange(IV_SIZE, encryptedBytes.size)
                            val decryptedData = authenticatedCipher.doFinal(ciphertext)
                            onSuccess(decryptedData)
                        } catch (e: CryptoOperationException) {
                            onFailure(e)
                        } catch (e: Exception) {
                            onFailure(CryptoOperationException("Decryption failed after authentication", e))
                        }
                    },
                    onAuthenticationError = { errorCode, errString ->
                        Log.e(TAG, "Authentication error [$errorCode]: $errString")
                        onFailure(AuthenticationException("Authentication error [$errorCode]: $errString"))
                    },
                    onError = { exception ->
                        Log.e(TAG, "Error: ${exception.message}", exception)
                        onFailure(CryptoOperationException("Biometric authentication error: ${exception.message}", exception))
                    }
                )
            } else {
                try {
                    val decryptedData = AESEncryption.decrypt(encryptedData, secretKey)
                    onSuccess(decryptedData)
                } catch (e: CryptoOperationException) {
                    onFailure(e)
                }
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

    /**
     * Retrieves or creates the AES key for the given config.
     * Returns null if key creation/retrieval fails (onFailure already called).
     *
     * Uses per-alias locking to prevent TOCTOU races where two threads both see
     * the key as missing and both attempt to create it (causing silent overwrite).
     */
    private fun getOrCreateKey(
        config: CryptoConfig,
        onFailure: (CryptoLibException) -> Unit
    ): javax.crypto.SecretKey? {
        return KeyHelper.lockForAlias(config.keyAlias).withLock {
            // Try to get the key first; only create if it doesn't exist
            try {
                KeyHelper.getAESKey(config.keyAlias)
            } catch (e: KeyNotFoundException) {
                // Key does not exist — create it
                try {
                    KeyHelper.generateAESKey(
                        alias = config.keyAlias,
                        validityDays = config.keyValidityDays,
                        requireUserAuthentication = config.requireUserAuthentication
                    )
                    KeyHelper.getAESKey(config.keyAlias)
                } catch (e2: Exception) {
                    Log.e(TAG, "Failed to generate AES key: ${e2.message}", e2)
                    onFailure(CryptoOperationException("Failed to generate AES key", e2))
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to retrieve AES key: ${e.message}", e)
                onFailure(CryptoOperationException("Failed to retrieve key for alias: ${config.keyAlias}", e))
                null
            }
        }
    }
}
