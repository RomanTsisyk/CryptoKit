package io.github.romantsisyk.cryptolib.certificates

import io.github.romantsisyk.cryptolib.exceptions.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

/**
 * Object responsible for certificate pinning to prevent man-in-the-middle attacks.
 * Allows applications to pin specific certificates to hostnames using SHA-256 fingerprints.
 *
 * Certificate pinning ensures that only certificates with specific fingerprints are trusted
 * for a given hostname, even if the certificate is otherwise valid.
 */
object CertificatePinning {

    /**
     * Thread-safe map storing hostname to SHA-256 pin mappings.
     * Key: hostname (e.g., "api.example.com")
     * Value: SHA-256 fingerprint of the pinned certificate
     */
    private val pins = ConcurrentHashMap<String, String>()

    /**
     * Adds a certificate pin for a specific host.
     *
     * @param host The hostname to pin (e.g., "api.example.com").
     * @param sha256Pin The SHA-256 fingerprint of the certificate to pin.
     *                  Should be in the format produced by CertificateUtils.getFingerprint()
     *                  (colon-separated hex bytes, e.g., "A1:B2:C3:...").
     * @throws CertificateException if the host or pin is invalid.
     */
    @JvmStatic
    fun addPin(host: String, sha256Pin: String) {
        if (host.isBlank()) {
            throw CertificateException("Host cannot be blank")
        }

        if (sha256Pin.isBlank()) {
            throw CertificateException("SHA-256 pin cannot be blank")
        }

        // Validate pin format (should be hex with colons)
        if (!isValidPinFormat(sha256Pin)) {
            throw CertificateException("Invalid SHA-256 pin format. Expected format: 'A1:B2:C3:...'")
        }

        // Normalize host to lowercase for case-insensitive matching
        val normalizedHost = host.lowercase()
        pins[normalizedHost] = sha256Pin.uppercase()
    }

    /**
     * Removes a certificate pin for a specific host.
     *
     * @param host The hostname whose pin should be removed.
     */
    @JvmStatic
    fun removePin(host: String) {
        if (host.isBlank()) {
            return
        }
        val normalizedHost = host.lowercase()
        pins.remove(normalizedHost)
    }

    /**
     * Verifies that a certificate matches the pin for a specific host.
     *
     * @param host The hostname to verify.
     * @param certificate The X509Certificate to verify against the pin.
     * @return true if the certificate matches the pin, false otherwise.
     * @throws CertificateException if there is an error calculating the certificate fingerprint.
     */
    @JvmStatic
    fun verifyPin(host: String, certificate: X509Certificate): Boolean {
        if (host.isBlank()) {
            throw CertificateException("Host cannot be blank")
        }

        val normalizedHost = host.lowercase()
        val expectedPin = pins[normalizedHost] ?: return false

        // Calculate the SHA-256 fingerprint of the provided certificate
        val actualPin = try {
            CertificateUtils.getFingerprint(certificate, "SHA-256")
        } catch (e: Exception) {
            throw CertificateException("Failed to calculate certificate fingerprint for pin verification", e)
        }

        return expectedPin.equals(actualPin, ignoreCase = true)
    }

    /**
     * Retrieves the pin for a specific host.
     *
     * @param host The hostname whose pin should be retrieved.
     * @return The SHA-256 pin for the host, or null if no pin exists.
     */
    @JvmStatic
    fun getPinForHost(host: String): String? {
        if (host.isBlank()) {
            return null
        }
        val normalizedHost = host.lowercase()
        return pins[normalizedHost]
    }

    /**
     * Clears all certificate pins.
     * Useful for testing or when resetting the application state.
     */
    @JvmStatic
    fun clearAllPins() {
        pins.clear()
    }

    /**
     * Gets all currently configured pins.
     *
     * @return A map of hostname to SHA-256 pin mappings.
     */
    @JvmStatic
    fun getAllPins(): Map<String, String> {
        return pins.toMap()
    }

    /**
     * Validates the format of a SHA-256 pin.
     *
     * @param pin The pin to validate.
     * @return true if the pin format is valid, false otherwise.
     */
    private fun isValidPinFormat(pin: String): Boolean {
        // SHA-256 produces 32 bytes, which when formatted as hex with colons should be:
        // 32 bytes * 2 hex chars + 31 colons = 95 characters
        // Format: XX:XX:XX:...:XX (where X is a hex digit)
        val hexPattern = "^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$".toRegex()
        return hexPattern.matches(pin)
    }
}
