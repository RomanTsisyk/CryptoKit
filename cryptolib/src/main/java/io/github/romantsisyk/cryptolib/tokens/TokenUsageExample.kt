package io.github.romantsisyk.cryptolib.tokens

import java.security.KeyPairGenerator
import java.util.Date
import javax.crypto.KeyGenerator

/**
 * Example usage of the Token Management module.
 * This file demonstrates how to use JWT and secure token generation features.
 */
object TokenUsageExample {

    /**
     * Example: Create and validate a JWT token using HMAC.
     */
    fun jwtHmacExample() {
        // Generate a secret key for HMAC
        val keyGenerator = KeyGenerator.getInstance("HmacSHA256")
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()

        // Build and sign a JWT
        val token = JWTBuilder()
            .setIssuer("auth-service")
            .setSubject("user123")
            .setAudience("api-gateway")
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + 3600000)) // 1 hour
            .addClaim("role", "admin")
            .addClaim("email", "user@example.com")
            .generateJwtId()
            .sign(secretKey, JWTAlgorithm.HS256)

        // Validate the token
        val isValid = JWTValidator.validate(token, secretKey)
        println("Token is valid: $isValid")

        // Parse and extract claims
        val payload = JWTValidator.parse(token)
        println("Subject: ${payload.sub}")
        println("Role: ${payload.customClaims["role"]}")

        // Check expiration
        val isExpired = JWTValidator.isExpired(token)
        println("Token is expired: $isExpired")
    }

    /**
     * Example: Create and validate a JWT token using RSA.
     */
    fun jwtRsaExample() {
        // Generate RSA key pair
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()

        // Build and sign a JWT with private key
        val token = JWTBuilder()
            .setIssuer("payment-service")
            .setSubject("transaction-456")
            .setExpiration(Date(System.currentTimeMillis() + 300000)) // 5 minutes
            .addClaim("amount", 99.99)
            .addClaim("currency", "USD")
            .sign(keyPair.private, JWTAlgorithm.RS256)

        // Validate the token with public key
        val isValid = JWTValidator.validate(token, keyPair.public)
        println("Token is valid: $isValid")

        // Extract claims
        val amount = JWTValidator.getClaim(token, "amount")
        val currency = JWTValidator.getClaim(token, "currency")
        println("Amount: $amount $currency")
    }

    /**
     * Example: Generate secure tokens for various use cases.
     */
    fun secureTokenExample() {
        // Generate a session ID
        val sessionId = SecureTokenGenerator.generateSessionId()
        println("Session ID: $sessionId")

        // Generate an API key
        val apiKey = SecureTokenGenerator.generateApiKey()
        println("API Key: $apiKey")

        // Generate a refresh token
        val refreshToken = SecureTokenGenerator.generateRefreshToken()
        println("Refresh Token: $refreshToken")

        // Generate a CSRF token
        val csrfToken = SecureTokenGenerator.generateCsrfToken()
        println("CSRF Token: $csrfToken")

        // Generate a 6-digit OTP
        val otp = SecureTokenGenerator.generateNumericOTP(6)
        println("OTP: $otp")

        // Generate a custom alphanumeric token
        val customToken = SecureTokenGenerator.generateAlphanumericToken(32)
        println("Custom Token: $customToken")
    }

    /**
     * Example: Complete authentication flow with access and refresh tokens.
     */
    fun authenticationFlowExample() {
        val keyGenerator = KeyGenerator.getInstance("HmacSHA256")
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()

        val userId = "user789"

        // Step 1: Create access token (short-lived)
        val accessToken = JWTBuilder()
            .setSubject(userId)
            .setIssuer("auth-server")
            .setExpiration(Date(System.currentTimeMillis() + 900000)) // 15 minutes
            .addClaim("type", "access")
            .addClaim("permissions", listOf("read", "write"))
            .sign(secretKey, JWTAlgorithm.HS256)

        // Step 2: Create refresh token (long-lived, opaque)
        val refreshToken = SecureTokenGenerator.generateRefreshToken()

        // Step 3: Store refresh token securely (in database, not shown here)
        println("Access Token: $accessToken")
        println("Refresh Token: $refreshToken")

        // Step 4: Validate access token on API requests
        if (JWTValidator.validateWithExpiry(accessToken, secretKey)) {
            val permissions = JWTValidator.getClaim(accessToken, "permissions")
            println("User has permissions: $permissions")
        }

        // Step 5: When access token expires, use refresh token to get new access token
        // (refresh token validation logic would be implemented in your service)
        val newAccessToken = JWTBuilder()
            .setSubject(userId)
            .setIssuer("auth-server")
            .setExpiration(Date(System.currentTimeMillis() + 900000))
            .addClaim("type", "access")
            .addClaim("permissions", listOf("read", "write"))
            .sign(secretKey, JWTAlgorithm.HS256)

        println("New Access Token: $newAccessToken")
    }

    /**
     * Example: Multi-tenant scenario with different algorithms.
     */
    fun multiTenantExample() {
        // Tenant 1 uses HMAC
        val hmacKey = KeyGenerator.getInstance("HmacSHA256").apply { init(256) }.generateKey()
        val tenant1Token = JWTBuilder()
            .setIssuer("tenant1")
            .setSubject("user1")
            .addClaim("tenant", "tenant1")
            .sign(hmacKey, JWTAlgorithm.HS256)

        // Tenant 2 uses RSA
        val rsaKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val tenant2Token = JWTBuilder()
            .setIssuer("tenant2")
            .setSubject("user2")
            .addClaim("tenant", "tenant2")
            .sign(rsaKeyPair.private, JWTAlgorithm.RS256)

        // Validate based on tenant
        val tenant1Valid = JWTValidator.validate(tenant1Token, hmacKey)
        val tenant2Valid = JWTValidator.validate(tenant2Token, rsaKeyPair.public)

        println("Tenant 1 token valid: $tenant1Valid")
        println("Tenant 2 token valid: $tenant2Valid")

        // Determine algorithm from token header
        val header1 = JWTValidator.parseHeader(tenant1Token)
        val header2 = JWTValidator.parseHeader(tenant2Token)
        println("Tenant 1 algorithm: ${header1.alg.algorithmName}")
        println("Tenant 2 algorithm: ${header2.alg.algorithmName}")
    }

    /**
     * Example: Two-factor authentication with OTP.
     */
    fun twoFactorAuthExample() {
        // Generate a 6-digit OTP
        val otp = SecureTokenGenerator.generateNumericOTP(6)
        println("Your verification code: $otp")

        // In a real scenario, you would:
        // 1. Store the OTP with a timestamp
        // 2. Send it to the user via SMS/Email
        // 3. Verify it when the user submits it
        // 4. Check if it's within the valid time window (e.g., 5 minutes)

        // Generate a backup code (alphanumeric)
        val backupCode = SecureTokenGenerator.generateAlphanumericToken(16)
        println("Backup code: $backupCode")
    }
}
