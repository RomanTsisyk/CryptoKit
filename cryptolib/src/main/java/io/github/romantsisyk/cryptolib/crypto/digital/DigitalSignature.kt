package io.github.romantsisyk.cryptolib.crypto.digital

import java.util.Base64
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

object DigitalSignature {

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private const val SIGNATURE_ALGORITHM_RSA = "SHA256withRSA/PSS"
    private const val SIGNATURE_ALGORITHM_ECDSA = "SHA256withECDSA"
    private const val KEY_SIZE_RSA = 2048
    private const val KEY_SIZE_EC = 256

    /**
     * Signs data using RSA or EC private key.
     */
    @JvmStatic
    fun sign(data: ByteArray, privateKey: PrivateKey): String {
        val algorithm = when (privateKey.algorithm) {
            "RSA" -> SIGNATURE_ALGORITHM_RSA
            "EC" -> SIGNATURE_ALGORITHM_ECDSA
            else -> throw UnsupportedOperationException("Unsupported key algorithm")
        }

        val signature = Signature.getInstance(algorithm, "BC") // Use Bouncy Castle
        signature.initSign(privateKey)
        signature.update(data)
        val signedData = signature.sign()
        return Base64.getEncoder().encodeToString(signedData)
    }

    /**
     * Verifies a signature using RSA or EC public key.
     */
    @JvmStatic
    fun verify(data: ByteArray, signatureStr: String, publicKey: PublicKey): Boolean {
        val algorithm = when (publicKey.algorithm) {
            "RSA" -> SIGNATURE_ALGORITHM_RSA
            "EC" -> SIGNATURE_ALGORITHM_ECDSA
            else -> throw UnsupportedOperationException("Unsupported key algorithm")
        }

        val signature = Signature.getInstance(algorithm, "BC") // Use Bouncy Castle
        signature.initVerify(publicKey)
        signature.update(data)
        val signatureBytes = Base64.getDecoder().decode(signatureStr)
        return signature.verify(signatureBytes)
    }

    /**
     * Generates a key pair for RSA or ECDSA signing.
     * Defaults to RSA.
     */
    @JvmStatic
    fun generateKeyPair(algorithm: String = "RSA"): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm)
        val keySize = when (algorithm) {
            "RSA" -> KEY_SIZE_RSA
            "EC" -> KEY_SIZE_EC
            else -> throw UnsupportedOperationException("Unsupported key algorithm")
        }
        keyPairGenerator.initialize(keySize)
        return keyPairGenerator.generateKeyPair()
    }
}