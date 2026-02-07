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
# Crypto - AES Encryption
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.aes.AESEncryption { public *; }

# =============================================
# Crypto - RSA Encryption
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.rsa.RSAEncryption { public *; }

# =============================================
# Crypto - Digital Signatures
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.digital.DigitalSignature { public *; }

# =============================================
# Crypto - Config
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.config.CryptoConfig { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.config.CryptoConfig$Builder { public *; }

# =============================================
# Crypto - Manager
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.manager.CryptoManager { public *; }

# =============================================
# Crypto - Hashing
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.hashing.HashUtils { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.hashing.HMACUtils { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.hashing.HashAlgorithm { *; }

# =============================================
# Crypto - KDF (Key Derivation)
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.kdf.KeyDerivation { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.kdf.KDFConfig { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.kdf.KDFConfig$Builder { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.kdf.KDFAlgorithm { *; }
-keep class io.github.romantsisyk.cryptolib.crypto.kdf.PasswordStrengthChecker { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.kdf.PasswordStrength { *; }

# =============================================
# Crypto - Key Management
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyHelper { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationManager { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationResult { *; }
-keep class io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationResult$* { *; }
-keep class io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationScheduler { public *; }
# WorkManager instantiates workers via reflection — this MUST be kept
-keep class io.github.romantsisyk.cryptolib.crypto.keymanagement.KeyRotationWorker { *; }

# =============================================
# Crypto - QR Code
# =============================================
-keep class io.github.romantsisyk.cryptolib.crypto.qr.QRCodeGenerator { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.qr.QRCodeScanner { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.qr.QRUtils { public *; }
-keep class io.github.romantsisyk.cryptolib.crypto.qr.QRKeyManager { public *; }

# =============================================
# Biometrics
# =============================================
-keep class io.github.romantsisyk.cryptolib.biometrics.BiometricHelper { public *; }

# =============================================
# Storage
# =============================================
-keep class io.github.romantsisyk.cryptolib.storage.SecurePreferences { public *; }
-keep class io.github.romantsisyk.cryptolib.storage.SecureFileStorage { public *; }
-keep class io.github.romantsisyk.cryptolib.storage.SecureStorageConfig { public *; }
-keep class io.github.romantsisyk.cryptolib.storage.SecureStorageConfig$Builder { public *; }

# =============================================
# Tokens (JWT)
# =============================================
-keep class io.github.romantsisyk.cryptolib.tokens.JWTBuilder { public *; }
-keep class io.github.romantsisyk.cryptolib.tokens.JWTValidator { public *; }
-keep class io.github.romantsisyk.cryptolib.tokens.JWTAlgorithm { *; }
-keep class io.github.romantsisyk.cryptolib.tokens.JWTHeader { *; }
-keep class io.github.romantsisyk.cryptolib.tokens.JWTPayload { *; }
-keep class io.github.romantsisyk.cryptolib.tokens.SecureTokenGenerator { public *; }

# =============================================
# Encoding
# =============================================
-keep class io.github.romantsisyk.cryptolib.encoding.Base64Utils { public *; }
-keep class io.github.romantsisyk.cryptolib.encoding.HexUtils { public *; }
-keep class io.github.romantsisyk.cryptolib.encoding.EncodingUtils { public *; }
-keep class io.github.romantsisyk.cryptolib.encoding.PEMUtils { public *; }

# =============================================
# Integrity
# =============================================
-keep class io.github.romantsisyk.cryptolib.integrity.ChecksumUtils { public *; }
-keep class io.github.romantsisyk.cryptolib.integrity.ChecksumAlgorithm { *; }
-keep class io.github.romantsisyk.cryptolib.integrity.DataIntegrityManager { public *; }
-keep class io.github.romantsisyk.cryptolib.integrity.IntegrityEnvelope { *; }
-keep class io.github.romantsisyk.cryptolib.integrity.SignedData { *; }

# =============================================
# Random
# =============================================
-keep class io.github.romantsisyk.cryptolib.random.SecureRandomGenerator { public *; }
-keep class io.github.romantsisyk.cryptolib.random.RandomStringGenerator { public *; }
-keep class io.github.romantsisyk.cryptolib.random.SaltGenerator { public *; }
-keep class io.github.romantsisyk.cryptolib.random.IVGenerator { public *; }

# =============================================
# Certificates
# =============================================
-keep class io.github.romantsisyk.cryptolib.certificates.CertificateValidator { public *; }
-keep class io.github.romantsisyk.cryptolib.certificates.CertificatePinning { public *; }
-keep class io.github.romantsisyk.cryptolib.certificates.CertificateUtils { public *; }
-keep class io.github.romantsisyk.cryptolib.certificates.CertificateInfo { *; }
-keep class io.github.romantsisyk.cryptolib.certificates.ValidationResult { *; }
