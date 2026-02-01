package io.github.romantsisyk.cryptolib.certificates

import io.github.romantsisyk.cryptolib.exceptions.CertificateException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger

class CertificateUtilsTest {

    private lateinit var testCertificate: X509Certificate
    private lateinit var expiredCertificate: X509Certificate
    private lateinit var notYetValidCertificate: X509Certificate

    @Before
    fun setUp() {
        testCertificate = generateTestCertificate(
            validityDays = 365,
            startDaysAgo = 1
        )

        expiredCertificate = generateTestCertificate(
            validityDays = 1,
            startDaysAgo = 10
        )

        notYetValidCertificate = generateTestCertificate(
            validityDays = 365,
            startDaysAgo = -10
        )
    }

    @Test
    fun `test loadCertificate from InputStream`() {
        val certBytes = testCertificate.encoded
        val inputStream = ByteArrayInputStream(certBytes)

        val loadedCert = CertificateUtils.loadCertificate(inputStream)

        assertNotNull(loadedCert)
        assertEquals(testCertificate.serialNumber, loadedCert.serialNumber)
    }

    @Test
    fun `test loadCertificate from PEM string`() {
        val pemString = certificateToPem(testCertificate)

        val loadedCert = CertificateUtils.loadCertificate(pemString)

        assertNotNull(loadedCert)
        assertEquals(testCertificate.serialNumber, loadedCert.serialNumber)
    }

    @Test
    fun `test loadCertificate from PEM string without headers`() {
        val base64Cert = Base64.getEncoder().encodeToString(testCertificate.encoded)

        val loadedCert = CertificateUtils.loadCertificate(base64Cert)

        assertNotNull(loadedCert)
        assertEquals(testCertificate.serialNumber, loadedCert.serialNumber)
    }

    @Test
    fun `test loadCertificate with empty PEM string throws exception`() {
        assertThrows(CertificateException::class.java) {
            CertificateUtils.loadCertificate("")
        }
    }

    @Test
    fun `test loadCertificate with blank PEM string throws exception`() {
        assertThrows(CertificateException::class.java) {
            CertificateUtils.loadCertificate("   ")
        }
    }

    @Test
    fun `test loadCertificate with invalid Base64 throws exception`() {
        assertThrows(CertificateException::class.java) {
            CertificateUtils.loadCertificate("invalid-base64-string!!!")
        }
    }

    @Test
    fun `test loadCertificateFromFile with valid file`() {
        val tempFile = File.createTempFile("test_cert", ".pem")
        tempFile.deleteOnExit()
        tempFile.writeBytes(testCertificate.encoded)

        val loadedCert = CertificateUtils.loadCertificateFromFile(tempFile)

        assertNotNull(loadedCert)
        assertEquals(testCertificate.serialNumber, loadedCert.serialNumber)
    }

    @Test
    fun `test loadCertificateFromFile with non-existent file throws exception`() {
        val nonExistentFile = File("/non/existent/path/cert.pem")

        assertThrows(CertificateException::class.java) {
            CertificateUtils.loadCertificateFromFile(nonExistentFile)
        }
    }

    @Test
    fun `test getCertificateInfo returns correct information`() {
        val certInfo = CertificateUtils.getCertificateInfo(testCertificate)

        assertNotNull(certInfo)
        assertNotNull(certInfo.subject)
        assertNotNull(certInfo.issuer)
        assertNotNull(certInfo.serialNumber)
        assertNotNull(certInfo.publicKeyAlgorithm)
        assertNotNull(certInfo.signatureAlgorithm)
        assertTrue(certInfo.isValid)
        assertTrue(certInfo.daysUntilExpiry > 0)
    }

    @Test
    fun `test isExpired returns false for valid certificate`() {
        val expired = CertificateUtils.isExpired(testCertificate)
        assertFalse(expired)
    }

    @Test
    fun `test isExpired returns true for expired certificate`() {
        val expired = CertificateUtils.isExpired(expiredCertificate)
        assertTrue(expired)
    }

    @Test
    fun `test isNotYetValid returns false for valid certificate`() {
        val notYetValid = CertificateUtils.isNotYetValid(testCertificate)
        assertFalse(notYetValid)
    }

    @Test
    fun `test isNotYetValid returns true for future certificate`() {
        val notYetValid = CertificateUtils.isNotYetValid(notYetValidCertificate)
        assertTrue(notYetValid)
    }

    @Test
    fun `test getDaysUntilExpiry returns positive for valid certificate`() {
        val days = CertificateUtils.getDaysUntilExpiry(testCertificate)
        assertTrue(days > 0)
        assertTrue(days <= 365)
    }

    @Test
    fun `test getDaysUntilExpiry returns negative for expired certificate`() {
        val days = CertificateUtils.getDaysUntilExpiry(expiredCertificate)
        assertTrue(days < 0)
    }

    @Test
    fun `test getFingerprint with SHA-256`() {
        val fingerprint = CertificateUtils.getFingerprint(testCertificate, "SHA-256")

        assertNotNull(fingerprint)
        assertTrue(fingerprint.contains(":"))
        // SHA-256 produces 32 bytes, formatted as hex with colons: 95 characters
        assertEquals(95, fingerprint.length)
    }

    @Test
    fun `test getFingerprint with SHA-1`() {
        val fingerprint = CertificateUtils.getFingerprint(testCertificate, "SHA-1")

        assertNotNull(fingerprint)
        assertTrue(fingerprint.contains(":"))
        // SHA-1 produces 20 bytes, formatted as hex with colons: 59 characters
        assertEquals(59, fingerprint.length)
    }

    @Test
    fun `test getFingerprint with MD5`() {
        val fingerprint = CertificateUtils.getFingerprint(testCertificate, "MD5")

        assertNotNull(fingerprint)
        assertTrue(fingerprint.contains(":"))
        // MD5 produces 16 bytes, formatted as hex with colons: 47 characters
        assertEquals(47, fingerprint.length)
    }

    @Test
    fun `test getFingerprint with invalid algorithm throws exception`() {
        assertThrows(CertificateException::class.java) {
            CertificateUtils.getFingerprint(testCertificate, "INVALID-ALGORITHM")
        }
    }

    // Helper method to generate a test certificate
    private fun generateTestCertificate(validityDays: Int, startDaysAgo: Int): X509Certificate {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()

        val now = System.currentTimeMillis()
        val startDate = Date(now - (startDaysAgo * 24 * 60 * 60 * 1000L))
        val endDate = Date(startDate.time + (validityDays * 24 * 60 * 60 * 1000L))

        val subject = X500Name("CN=Test Certificate, O=Test Org, C=US")
        val serialNumber = BigInteger.valueOf(System.currentTimeMillis())

        val certBuilder = JcaX509v3CertificateBuilder(
            subject,
            serialNumber,
            startDate,
            endDate,
            subject,
            keyPair.public
        )

        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val certHolder = certBuilder.build(signer)

        return JcaX509CertificateConverter().getCertificate(certHolder)
    }

    // Helper method to convert certificate to PEM format
    private fun certificateToPem(certificate: X509Certificate): String {
        val base64Cert = Base64.getEncoder().encodeToString(certificate.encoded)
        return "-----BEGIN CERTIFICATE-----\n$base64Cert\n-----END CERTIFICATE-----"
    }
}
