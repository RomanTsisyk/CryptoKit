package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.security.keystore.*
import io.github.romantsisyk.cryptolib.exceptions.CryptoLibException
import io.github.romantsisyk.cryptolib.exceptions.KeyGenerationException
import io.github.romantsisyk.cryptolib.exceptions.KeyNotFoundException
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.Calendar
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Helper object for managing cryptographic keys in the Android Keystore.
 * It provides functionality to generate, retrieve, delete, and list keys securely.
 */
object KeyHelper {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "MySecureKeyAlias"
    private const val TRANSFORMATION = "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_GCM}/${KeyProperties.ENCRYPTION_PADDING_NONE}"

    /**
     * Generates an AES symmetric key and stores it securely in the Android Keystore.
     *
     * @param alias the alias used to reference the key.
     * @param validityDays the number of days the key will be valid.
     * @param requireUserAuthentication if set to true, the key requires user authentication to use.
     * @throws KeyGenerationException if key generation fails.
     */
    fun generateAESKey(
        alias: String,
        validityDays: Int = 365,
        requireUserAuthentication: Boolean = false
    ) {
        try {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )

            val calendar = Calendar.getInstance()
            val startDate = calendar.time
            calendar.add(Calendar.DAY_OF_YEAR, validityDays)
            val endDate = calendar.time

            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setKeyValidityStart(startDate)
                .setKeyValidityEnd(endDate)

            if (requireUserAuthentication) {
                builder.setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(-1) // Require authentication for every use
            }

            val keyGenParameterSpec = builder.build()

            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        } catch (e: Exception) {
            throw KeyGenerationException(alias, e)
        }
    }

    /**
     * Generates an RSA key pair and stores it in the Keystore.
     *
     * @param alias the alias used to reference the key pair.
     */
    fun generateRSAKeyPair(alias: String) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE
        )

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA512
            )
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            .setKeySize(2048)
            .build()

        keyPairGenerator.initialize(keyGenParameterSpec)
        keyPairGenerator.generateKeyPair()
    }

    /**
     * Generates an EC key pair and stores it in the Keystore.
     *
     * @param alias the alias used to reference the key pair.
     */
    fun generateECKeyPair(alias: String) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA512
            )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .build()

        keyPairGenerator.initialize(keyGenParameterSpec)
        keyPairGenerator.generateKeyPair()
    }

    /**
     * Retrieves an AES key from the Keystore by its alias.
     *
     * @param alias the alias of the AES key.
     * @return the SecretKey instance.
     * @throws KeyNotFoundException if the key is not found.
     */
    fun getAESKey(alias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key = keyStore.getKey(alias, null) as? SecretKey
            ?: throw KeyNotFoundException(alias)
        return key
    }

    /**
     * Retrieves a PrivateKey from the Keystore using the provided alias.
     *
     * @param alias the alias of the private key to retrieve.
     * @return the PrivateKey if found, or null if the key is not present in the Keystore.
     * @throws KeyNotFoundException if the private key is not found in the Keystore.
     */
    fun getPrivateKey(alias: String): PrivateKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        return entry?.privateKey
    }

    /**
     * Retrieves a PublicKey from the Keystore using the provided alias.
     *
     * @param alias the alias of the public key to retrieve.
     * @return the PublicKey if found, or null if the key is not present in the Keystore.
     * @throws KeyNotFoundException if the public key is not found in the Keystore.
     */
    fun getPublicKey(alias: String): PublicKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        return entry?.certificate?.publicKey
    }

    /**
     * Lists all aliases (keys) stored in the Keystore.
     *
     * @return a list of key aliases stored in the Keystore.
     */
    fun listKeys(): List<String> {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val aliases = keyStore.aliases()
        val keyList = mutableListOf<String>()
        while (aliases.hasMoreElements()) {
            keyList.add(aliases.nextElement())
        }
        return keyList
    }

    /**
     * Deletes a key from the Keystore by its alias.
     *
     * @param alias the alias of the key to be deleted.
     * @throws KeyNotFoundException if the key does not exist in the Keystore.
     */
    fun deleteKey(alias: String) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        } else {
            throw KeyNotFoundException(alias)
        }
    }

    /**
     * Retrieves KeyInfo for a given key alias.
     *
     * @param alias the alias of the key for which KeyInfo is required.
     * @return the KeyInfo associated with the key.
     * @throws KeyNotFoundException if the key does not exist.
     * @throws CryptoLibException if unable to retrieve the KeyInfo.
     */
    fun getKeyInfo(alias: String): KeyInfo {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
            ?: throw KeyNotFoundException(alias)
        val key = entry.secretKey
        val keyFactory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        return keyFactory.getKeySpec(key, KeyInfo::class.java) as? KeyInfo
            ?: throw CryptoLibException("Unable to retrieve KeyInfo for alias '$alias'.")
    }

    /**
     * Retrieves the existing secret key from the Android Keystore or generates a new one if it doesn't exist.
     *
     * @return the existing or newly generated SecretKey.
     * @throws KeyGenerationException if the key generation fails.
     */
    fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        // Check if the key already exists
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return keyStore.getKey(KEY_ALIAS, null) as SecretKey
        }

        // Generate a new secret key
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    /**
     * Retrieves a Cipher instance configured with the appropriate transformation.
     *
     * @return the Cipher instance used for encryption/decryption.
     * @throws IllegalStateException if unable to retrieve the Cipher instance.
     */
    fun getCipherInstance(): Cipher {
        return try {
            Cipher.getInstance(TRANSFORMATION)
        } catch (e: Exception) {
            throw IllegalStateException("Failed to get Cipher instance", e)
        }
    }

    /**
     * Retrieves the SecretKey from the Keystore using the provided alias.
     *
     * @return the SecretKey associated with the provided alias.
     * @throws KeyNotFoundException if the key cannot be found.
     */
    fun getKey(): SecretKey {
        val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey("MySecureKey", null) as SecretKey
    }

}