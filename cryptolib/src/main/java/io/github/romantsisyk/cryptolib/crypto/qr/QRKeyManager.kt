package io.github.romantsisyk.cryptolib.crypto.qr

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * QRKeyManager handles key generation and retrieval for QR code encryption using AES.
 * It utilizes the Android Keystore system for secure key storage and management.
 */
object QRKeyManager {
    private const val ALIAS = "CryptoKitQRCodeKey" // Alias used for the key in the Keystore
    private const val TRANSFORMATION = "AES" // Transformation type for encryption

    /**
     * Generates a new encryption key for QR code encryption.
     * The key is stored in the Android Keystore for secure access.
     * @return A SecretKey object for encryption.
     */
    @JvmStatic
    fun generateKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return keyGenerator.generateKey()
    }

    /**
     * Retrieves the encryption key from the Android Keystore.
     * @return The SecretKey stored in the Keystore.
     * @throws IllegalStateException if the key is not found or is not a valid SecretKey.
     */
    @JvmStatic
    fun getKey(): SecretKey {
        val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("Key with alias '$ALIAS' not found or is not a valid SecretKey")
    }
}