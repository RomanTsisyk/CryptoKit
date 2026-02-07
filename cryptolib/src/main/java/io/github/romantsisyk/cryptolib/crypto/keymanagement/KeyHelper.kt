package io.github.romantsisyk.cryptolib.crypto.keymanagement

import android.security.keystore.*
import io.github.romantsisyk.cryptolib.exceptions.CryptoLibException
import io.github.romantsisyk.cryptolib.exceptions.KeyGenerationException
import io.github.romantsisyk.cryptolib.exceptions.KeyNotFoundException
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.Calendar
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import kotlin.concurrent.withLock

/**
 * Helper object for managing cryptographic keys in the Android Keystore.
 * It provides functionality to generate, retrieve, delete, and list keys securely.
 */
object KeyHelper {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "MySecureKeyAlias"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    /**
     * Per-alias locks to prevent TOCTOU races during key creation, rotation, and deletion.
     * Using striped locking so that operations on different aliases can proceed concurrently.
     */
    private val aliasLocks = ConcurrentHashMap<String, ReentrantLock>()

    /**
     * Returns the lock for a given alias, creating one if it does not exist.
     */
    internal fun lockForAlias(alias: String): ReentrantLock =
        aliasLocks.computeIfAbsent(alias) { ReentrantLock() }

    /**
     * Loads and returns a KeyStore instance for the Android Keystore.
     * Extracted to a single method so tests can intercept this call via mockkObject.
     */
    @JvmStatic
    internal fun loadKeyStore(): KeyStore {
        return KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /**
     * Generates an AES symmetric key and stores it securely in the Android Keystore.
     *
     * @param alias the alias used to reference the key.
     * @param validityDays the number of days the key will be valid.
     * @param requireUserAuthentication if set to true, the key requires user authentication to use.
     * @throws KeyGenerationException if key generation fails.
     */
    @JvmStatic
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
    @JvmStatic
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
    @JvmStatic
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
    @JvmStatic
    fun getAESKey(alias: String): SecretKey {
        val keyStore = loadKeyStore()
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
    @JvmStatic
    fun getPrivateKey(alias: String): PrivateKey? {
        val keyStore = loadKeyStore()
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
    @JvmStatic
    fun getPublicKey(alias: String): PublicKey? {
        val keyStore = loadKeyStore()
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        return entry?.certificate?.publicKey
    }

    /**
     * Lists all aliases (keys) stored in the Keystore.
     *
     * @return a list of key aliases stored in the Keystore.
     */
    @JvmStatic
    fun listKeys(): List<String> {
        val keyStore = loadKeyStore()
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
    @JvmStatic
    fun deleteKey(alias: String) {
        lockForAlias(alias).withLock {
            val keyStore = loadKeyStore()
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            } else {
                throw KeyNotFoundException(alias)
            }
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
    @JvmStatic
    fun getKeyInfo(alias: String): KeyInfo {
        val keyStore = loadKeyStore()
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
    @JvmStatic
    fun getOrCreateSecretKey(): SecretKey {
        return lockForAlias(KEY_ALIAS).withLock {
            val keyStore = loadKeyStore()

            // Check if the key already exists
            if (keyStore.containsAlias(KEY_ALIAS)) {
                return@withLock keyStore.getKey(KEY_ALIAS, null) as? SecretKey
                    ?: throw KeyNotFoundException(KEY_ALIAS)
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
            keyGenerator.generateKey()
        }
    }

    /**
     * Retrieves a Cipher instance configured with the appropriate transformation.
     *
     * @return the Cipher instance used for encryption/decryption.
     * @throws IllegalStateException if unable to retrieve the Cipher instance.
     */
    @JvmStatic
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
    @Deprecated("Uses hardcoded alias. Use getAESKey(alias) instead.", replaceWith = ReplaceWith("getAESKey(alias)"))
    @JvmStatic
    fun getKey(): SecretKey {
        val keyStore = loadKeyStore()
        return keyStore.getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw KeyNotFoundException(KEY_ALIAS)
    }

    /**
     * Resolves the current (latest versioned) alias for the given base alias.
     * Checks for aliases like `{baseAlias}_v2`, `{baseAlias}_v3`, etc.
     * Returns the highest versioned alias found, or the base alias if none exist.
     *
     * @param baseAlias the base alias to resolve.
     * @return the latest versioned alias.
     */
    @JvmStatic
    fun resolveCurrentAlias(baseAlias: String): String {
        val keyStore = loadKeyStore()
        var currentAlias = baseAlias
        var version = 2
        while (keyStore.containsAlias("${baseAlias}_v$version")) {
            currentAlias = "${baseAlias}_v$version"
            version++
        }
        return currentAlias
    }

    /**
     * Computes the next versioned alias for the given base alias.
     * If no versioned aliases exist, returns `{baseAlias}_v2`.
     * If `{baseAlias}_v2` exists, returns `{baseAlias}_v3`, etc.
     *
     * @param baseAlias the base alias to compute the next version for.
     * @return the next versioned alias.
     */
    @JvmStatic
    fun nextVersionedAlias(baseAlias: String): String {
        // Note: Callers performing rotation must hold lockForAlias(baseAlias)
        // to prevent two concurrent rotations from computing the same next alias.
        val keyStore = loadKeyStore()
        var version = 2
        while (keyStore.containsAlias("${baseAlias}_v$version")) {
            version++
        }
        return "${baseAlias}_v$version"
    }

}