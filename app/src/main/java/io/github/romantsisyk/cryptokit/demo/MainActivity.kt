package io.github.romantsisyk.cryptokit.demo

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import io.github.romantsisyk.cryptokit.demo.databinding.ActivityMainBinding
import io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption
import io.github.romantsisyk.cryptolib.crypto.digital.DigitalSignature
import io.github.romantsisyk.cryptolib.crypto.hashing.HashAlgorithm
import io.github.romantsisyk.cryptolib.crypto.hashing.HashUtils
import io.github.romantsisyk.cryptolib.crypto.hashing.HMACUtils
import io.github.romantsisyk.cryptolib.crypto.kdf.PasswordStrengthChecker
import io.github.romantsisyk.cryptolib.crypto.rsa.RSAEncryption
import io.github.romantsisyk.cryptolib.random.RandomStringGenerator
import io.github.romantsisyk.cryptolib.random.SecureRandomGenerator
import io.github.romantsisyk.cryptolib.tokens.JWTAlgorithm
import io.github.romantsisyk.cryptolib.tokens.JWTBuilder
import io.github.romantsisyk.cryptolib.tokens.JWTValidator
import java.util.Date
import javax.crypto.KeyGenerator

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        binding.recyclerView.layoutManager = LinearLayoutManager(this)
        binding.recyclerView.adapter = DemoAdapter(buildDemoItems())
    }

    private fun buildDemoItems(): List<DemoItem> = listOf(
        DemoItem(
            title = "AES Encryption",
            description = "AES-GCM encrypt/decrypt with a generated key"
        ) {
            val key = AESEncryption.generateKey()
            val plaintext = "Hello, CryptoKit!"
            val encrypted = AESEncryption.encrypt(plaintext.toByteArray(), key)
            val decrypted = AESEncryption.decrypt(encrypted, key)
            buildString {
                appendLine("Plaintext: $plaintext")
                appendLine("Encrypted: ${encrypted.take(60)}...")
                appendLine("Decrypted: ${String(decrypted)}")
            }
        },

        DemoItem(
            title = "RSA Encryption",
            description = "RSA-OAEP encrypt/decrypt with a generated key pair"
        ) {
            val keyPair = RSAEncryption.generateKeyPair()
            val plaintext = "Secret message"
            val encrypted = RSAEncryption.encrypt(plaintext.toByteArray(), keyPair.public)
            val decrypted = RSAEncryption.decrypt(encrypted, keyPair.private)
            buildString {
                appendLine("Plaintext: $plaintext")
                appendLine("Encrypted: ${encrypted.take(60)}...")
                appendLine("Decrypted: ${String(decrypted)}")
            }
        },

        DemoItem(
            title = "Digital Signatures",
            description = "EC sign and verify a message"
        ) {
            val keyPair = DigitalSignature.generateKeyPair("EC")
            val message = "Sign this data"
            val signature = DigitalSignature.sign(message.toByteArray(), keyPair.private)
            val valid = DigitalSignature.verify(message.toByteArray(), signature, keyPair.public)
            buildString {
                appendLine("Message: $message")
                appendLine("Signature: ${signature.take(60)}...")
                appendLine("Valid: $valid")
            }
        },

        DemoItem(
            title = "Hashing",
            description = "SHA-256 and SHA-512 hash of a string"
        ) {
            val input = "Hash me!"
            val sha256 = HashUtils.hash(input, HashAlgorithm.SHA256)
            val sha512 = HashUtils.hash(input, HashAlgorithm.SHA512)
            buildString {
                appendLine("Input: $input")
                appendLine("SHA-256: $sha256")
                appendLine("SHA-512: ${sha512.take(60)}...")
            }
        },

        DemoItem(
            title = "HMAC",
            description = "Generate and verify HMAC-SHA256"
        ) {
            val key = HMACUtils.generateKey(HashAlgorithm.SHA256)
            val data = "Authenticate this"
            val hmac = HMACUtils.generateHMAC(data, key, HashAlgorithm.SHA256)
            val verified = HMACUtils.verifyHMAC(data, hmac, key, HashAlgorithm.SHA256)
            buildString {
                appendLine("Data: $data")
                appendLine("HMAC: $hmac")
                appendLine("Verified: $verified")
            }
        },

        DemoItem(
            title = "JWT Tokens",
            description = "Build and validate a JWT with HMAC-SHA256"
        ) {
            val keyGen = KeyGenerator.getInstance("HmacSHA256")
            keyGen.init(256)
            val key = keyGen.generateKey()
            val token = JWTBuilder()
                .setIssuer("CryptoKit Demo")
                .setSubject("user@example.com")
                .setExpiration(Date(System.currentTimeMillis() + 3600_000))
                .sign(key, JWTAlgorithm.HS256)
            val valid = JWTValidator.validate(token, key, JWTAlgorithm.HS256)
            val claims = JWTValidator.parse(token)
            buildString {
                appendLine("Token: ${token.take(60)}...")
                appendLine("Valid: $valid")
                appendLine("Issuer: ${claims.iss}")
                appendLine("Subject: ${claims.sub}")
            }
        },

        DemoItem(
            title = "Secure Random",
            description = "Generate random strings, passwords, and UUIDs"
        ) {
            val alphanumeric = RandomStringGenerator.generateAlphanumeric(16)
            val password = RandomStringGenerator.generatePassword(20)
            val uuid = SecureRandomGenerator.generateUUID()
            buildString {
                appendLine("Alphanumeric (16): $alphanumeric")
                appendLine("Password (20): $password")
                appendLine("UUID: $uuid")
            }
        },

        DemoItem(
            title = "Password Strength",
            description = "Check strength of various passwords"
        ) {
            val passwords = listOf("abc", "Password1", "C0mpl3x!Pass", "X#9kL!mQ2@vB7&zW")
            buildString {
                passwords.forEach { pw ->
                    val strength = PasswordStrengthChecker.checkStrength(pw)
                    appendLine("\"$pw\" -> $strength")
                }
            }
        }
    )
}
