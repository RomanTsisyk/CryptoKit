# Token Management Module

The Token Management module provides comprehensive JWT (JSON Web Token) handling and secure token generation capabilities for the CryptoKit library.

## Features

### JWT (JSON Web Token) Support

- **Multiple Algorithms**: Support for HMAC (HS256, HS384, HS512) and RSA (RS256, RS384, RS512) signing algorithms
- **Standard Claims**: Full support for standard JWT claims (iss, sub, aud, exp, iat, nbf, jti)
- **Custom Claims**: Add custom claims to JWT payload
- **Token Validation**: Comprehensive validation including signature verification and expiration checking
- **Token Parsing**: Extract and parse JWT headers and payloads

### Secure Token Generation

- **Base64 URL-safe Tokens**: Generate secure random tokens in Base64 URL-safe format
- **Hexadecimal Tokens**: Generate tokens in hexadecimal format
- **Numeric OTP**: Generate secure numeric one-time passwords (4-10 digits)
- **Alphanumeric Tokens**: Generate secure alphanumeric tokens
- **Convenience Methods**: Pre-configured methods for common use cases (session IDs, API keys, refresh tokens, CSRF tokens)

## Components

### JWTAlgorithm

Enum representing supported JWT signing algorithms:

```kotlin
enum class JWTAlgorithm {
    HS256,  // HMAC using SHA-256
    HS384,  // HMAC using SHA-384
    HS512,  // HMAC using SHA-512
    RS256,  // RSA signature using SHA-256
    RS384,  // RSA signature using SHA-384
    RS512   // RSA signature using SHA-512
}
```

### JWTHeader

Data class representing a JWT header with algorithm and type information.

### JWTPayload

Data class representing a JWT payload with standard and custom claims:

- **iss** (issuer): Identifies the principal that issued the JWT
- **sub** (subject): Identifies the principal that is the subject of the JWT
- **aud** (audience): Identifies the recipients that the JWT is intended for
- **exp** (expiration): Identifies the expiration time
- **iat** (issued at): Identifies when the JWT was issued
- **nbf** (not before): Identifies the time before which the JWT must not be accepted
- **jti** (JWT ID): Provides a unique identifier for the JWT
- **customClaims**: Map of custom claims

### JWTBuilder

Fluent builder for creating and signing JWTs:

```kotlin
val token = JWTBuilder()
    .setIssuer("auth-service")
    .setSubject("user123")
    .setAudience("api-gateway")
    .setExpiration(Date(System.currentTimeMillis() + 3600000))
    .addClaim("role", "admin")
    .sign(secretKey, JWTAlgorithm.HS256)
```

### JWTValidator

Object for validating and parsing JWTs:

```kotlin
// Validate signature
val isValid = JWTValidator.validate(token, key)

// Check expiration
val isExpired = JWTValidator.isExpired(token)

// Parse payload
val payload = JWTValidator.parse(token)

// Get specific claim
val role = JWTValidator.getClaim(token, "role")

// Validate with expiry check
JWTValidator.validateWithExpiry(token, key)
```

### SecureTokenGenerator

Object for generating various types of secure tokens:

```kotlin
// Session ID (32 bytes, Base64 URL-safe)
val sessionId = SecureTokenGenerator.generateSessionId()

// API Key (48 bytes, Base64 URL-safe)
val apiKey = SecureTokenGenerator.generateApiKey()

// Refresh Token (64 bytes, hexadecimal)
val refreshToken = SecureTokenGenerator.generateRefreshToken()

// CSRF Token (32 bytes, Base64 URL-safe)
val csrfToken = SecureTokenGenerator.generateCsrfToken()

// Numeric OTP (6 digits)
val otp = SecureTokenGenerator.generateNumericOTP(6)

// Custom tokens
val customToken = SecureTokenGenerator.generateToken(32)
val hexToken = SecureTokenGenerator.generateHexToken(32)
val alphanumeric = SecureTokenGenerator.generateAlphanumericToken(16)
```

## Usage Examples

### Basic JWT with HMAC

```kotlin
// Generate HMAC secret key
val keyGenerator = KeyGenerator.getInstance("HmacSHA256")
keyGenerator.init(256)
val secretKey = keyGenerator.generateKey()

// Create JWT
val token = JWTBuilder()
    .setIssuer("auth-service")
    .setSubject("user123")
    .setExpiration(Date(System.currentTimeMillis() + 3600000))
    .addClaim("role", "admin")
    .generateJwtId()
    .sign(secretKey, JWTAlgorithm.HS256)

// Validate and parse
if (JWTValidator.validate(token, secretKey)) {
    val payload = JWTValidator.parse(token)
    println("User: ${payload.sub}")
    println("Role: ${payload.customClaims["role"]}")
}
```

### JWT with RSA

```kotlin
// Generate RSA key pair
val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
keyPairGenerator.initialize(2048)
val keyPair = keyPairGenerator.generateKeyPair()

// Create JWT with private key
val token = JWTBuilder()
    .setIssuer("service-a")
    .setSubject("transaction-123")
    .setAudience("service-b")
    .addClaim("amount", 99.99)
    .sign(keyPair.private, JWTAlgorithm.RS256)

// Validate with public key
val isValid = JWTValidator.validate(token, keyPair.public)
```

### Authentication Flow

```kotlin
val userId = "user123"

// Create short-lived access token
val accessToken = JWTBuilder()
    .setSubject(userId)
    .setExpiration(Date(System.currentTimeMillis() + 900000)) // 15 min
    .addClaim("type", "access")
    .addClaim("permissions", listOf("read", "write"))
    .sign(secretKey, JWTAlgorithm.HS256)

// Create long-lived refresh token
val refreshToken = SecureTokenGenerator.generateRefreshToken()

// Validate access token on API requests
if (JWTValidator.validateWithExpiry(accessToken, secretKey)) {
    // Token is valid and not expired
    val permissions = JWTValidator.getClaim(accessToken, "permissions")
}
```

### Two-Factor Authentication

```kotlin
// Generate 6-digit OTP
val otp = SecureTokenGenerator.generateNumericOTP(6)
// Send OTP to user via SMS/Email

// Generate backup codes
val backupCodes = (1..10).map {
    SecureTokenGenerator.generateAlphanumericToken(16)
}
```

### API Key Management

```kotlin
// Generate API key for third-party integration
val apiKey = SecureTokenGenerator.generateApiKey()

// Create JWT for API request authentication
val apiToken = JWTBuilder()
    .setIssuer("client-app")
    .setSubject("api-request")
    .setExpiration(Date(System.currentTimeMillis() + 3600000))
    .addClaim("apiKey", apiKey)
    .sign(secretKey, JWTAlgorithm.HS256)
```

### Session Management

```kotlin
// Generate session ID
val sessionId = SecureTokenGenerator.generateSessionId()

// Create session token
val sessionToken = JWTBuilder()
    .setSubject(userId)
    .setExpiration(Date(System.currentTimeMillis() + 86400000)) // 24 hours
    .addClaim("sessionId", sessionId)
    .sign(secretKey, JWTAlgorithm.HS256)
```

## Security Considerations

### JWT Security

1. **Algorithm Selection**: Use RS256 for public key scenarios, HS256 for shared secret scenarios
2. **Key Management**: Store signing keys securely, never expose them
3. **Token Lifetime**: Use short expiration times for access tokens (15 minutes)
4. **Refresh Tokens**: Use long-lived opaque tokens for refresh, store them securely
5. **Signature Validation**: Always validate JWT signatures before trusting the payload
6. **Expiration Checking**: Always check token expiration in addition to signature validation

### Token Generation Security

1. **Cryptographically Secure**: All tokens use `SecureRandom.getInstanceStrong()`
2. **Sufficient Entropy**: Use appropriate token lengths (minimum 32 bytes for session tokens)
3. **Token Storage**: Store sensitive tokens encrypted in secure storage
4. **Token Transmission**: Always transmit tokens over HTTPS
5. **Token Rotation**: Implement token rotation for long-lived tokens

## Exception Handling

The module uses `TokenException` for token-related errors:

```kotlin
try {
    val token = JWTBuilder()
        .setSubject("user")
        .sign(key, JWTAlgorithm.HS256)

    JWTValidator.validateWithExpiry(token, key)
} catch (e: TokenException) {
    // Handle token error (invalid format, expired, invalid signature, etc.)
    Log.e("Auth", "Token error: ${e.message}")
}
```

## Performance

- **JWT Signing**: RSA is slower than HMAC; use HMAC when possible for high-throughput scenarios
- **Token Generation**: All token generation methods are optimized for performance
- **Validation**: JWT validation is fast, but avoid validating the same token multiple times (use caching)

## Testing

The module includes comprehensive unit tests:

- `JWTAlgorithmTest`: Tests for algorithm enumeration
- `JWTHeaderTest`: Tests for JWT header parsing and serialization
- `JWTPayloadTest`: Tests for JWT payload parsing and claim handling
- `JWTBuilderTest`: Tests for JWT building and signing with all algorithms
- `JWTValidatorTest`: Tests for JWT validation and parsing
- `SecureTokenGeneratorTest`: Tests for secure token generation
- `TokenManagementIntegrationTest`: End-to-end integration tests

## Dependencies

This module requires:

- Android SDK (API level 30+)
- Kotlin Standard Library
- org.json (included in Android SDK)

No external dependencies are required for JWT functionality.

## Thread Safety

- `JWTValidator` and `SecureTokenGenerator` are thread-safe (singleton objects)
- `JWTBuilder` instances are not thread-safe (create new instances per thread)
- `JWTPayload` and `JWTHeader` are immutable data classes (thread-safe)

## Best Practices

1. **Use appropriate algorithms**: RS256 for microservices, HS256 for client-server
2. **Set expiration times**: Always set exp claim for JWTs
3. **Validate thoroughly**: Use `validateWithExpiry` for comprehensive validation
4. **Secure key storage**: Use Android Keystore for storing signing keys
5. **Token revocation**: Implement token blacklisting for logout functionality
6. **Audit logging**: Log token creation and validation events for security monitoring
7. **Use standard claims**: Follow JWT RFC 7519 for claim naming and usage

## Migration from Other Libraries

If migrating from other JWT libraries:

- **From jose4j**: Similar builder pattern, compatible claim structure
- **From jjwt**: Similar fluent API, compatible with standard claims
- **From auth0/java-jwt**: Similar validation approach, compatible token format

All JWTs generated by this library are RFC 7519 compliant and interoperable with other JWT libraries.
