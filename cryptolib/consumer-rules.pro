# =============================================
# CryptoKit Library - ProGuard Consumer Rules
# =============================================
# These rules are applied to any app that consumes this library.
# They ensure that the public API classes and methods are not
# obfuscated or removed during the minification process.

# =============================================
# External Dependencies
# =============================================
-keep class javax.crypto.** { *; }
-keep class org.bouncycastle.** { *; }
-keep class com.google.zxing.** { *; }

# =============================================
# Exception Classes
# =============================================
-keep class io.github.romantsisyk.cryptolib.exceptions.** { *; }

# =============================================
# CryptoManager - Main encryption/decryption facade
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.manager.CryptoManager {
    public *;
}

# =============================================
# KeyHelper - Key management utilities
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper {
    public *;
}

# =============================================
# AESEncryption - AES-GCM encryption operations
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption {
    public *;
}

# =============================================
# RSAEncryption - RSA encryption operations
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.rsa.RSAEncryption {
    public *;
}

# =============================================
# DigitalSignature - Digital signing and verification
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.digital.DigitalSignature {
    public *;
}

# =============================================
# BiometricHelper - Biometric authentication
# =============================================
-keep class io.github.romantsisyk.cryptolib.biometrics.BiometricHelper {
    public *;
}

# =============================================
# QR Code Classes
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.qr.QRCodeGenerator {
    public *;
}

-keep class io.github.romantsisyk.cryptolib.crypto.qr.QRCodeScanner {
    public *;
}

-keep class io.github.romantsisyk.cryptolib.crypto.qr.QRUtils {
    public *;
}

-keep class io.github.romantsisyk.cryptolib.crypto.qr.QRKeyManager {
    public *;
}

# =============================================
# CryptoConfig and Builder
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.config.CryptoConfig {
    public *;
}

-keep class io.github.romantsisyk.cryptolib.crypto.config.CryptoConfig$Builder {
    public *;
}

# =============================================
# Key Rotation Classes
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationManager {
    public *;
}

-keep class io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationScheduler {
    public *;
}
