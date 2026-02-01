package io.github.romantsisyk.cryptolib.certificates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

class CertificateValidatorTest {

    private lateinit var validCertificate: X509Certificate
    private lateinit var expiredCertificate: X509Certificate
    private lateinit var notYetValidCertificate: X509Certificate
    private lateinit var expiringSoonCertificate: X509Certificate

    @Before
    fun setUp() {
        validCertificate = generateTestCertificate(
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

        expiringSoonCertificate = generateTestCertificate(
            validityDays = 20,
            startDaysAgo = 1
        )
    }

    @Test
    fun `test validateCertificate with valid certificate`() {
        val result = CertificateValidator.validateCertificate(validCertificate)

        assertTrue(result.isValid)
        assertTrue(result.errors.isEmpty())
    }

    @Test
    fun `test validateCertificate with expired certificate`() {
        val result = CertificateValidator.validateCertificate(expiredCertificate)

        assertFalse(result.isValid)
        assertFalse(result.errors.isEmpty())
        assertTrue(result.errors.any { it.contains("expired") })
    }

    @Test
    fun `test validateCertificate with not yet valid certificate`() {
        val result = CertificateValidator.validateCertificate(notYetValidCertificate)

        assertFalse(result.isValid)
        assertFalse(result.errors.isEmpty())
        assertTrue(result.errors.any { it.contains("not yet valid") })
    }

    @Test
    fun `test validateCertificate with expiring soon certificate shows warning`() {
        val result = CertificateValidator.validateCertificate(expiringSoonCertificate)

        assertTrue(result.isValid)
        assertTrue(result.errors.isEmpty())
        assertFalse(result.warnings.isEmpty())
        assertTrue(result.warnings.any { it.contains("will expire") })
    }

    @Test
    fun `test validateChain with empty chain`() {
        val result = CertificateValidator.validateChain(emptyList())

        assertFalse(result.isValid)
        assertTrue(result.errors.any { it.contains("empty") })
    }

    @Test
    fun `test validateChain with single certificate`() {
        val result = CertificateValidator.validateChain(listOf(validCertificate))

        assertTrue(result.isValid)
        assertTrue(result.errors.isEmpty())
    }

    @Test
    fun `test validateChain with valid chain`() {
        val (rootCert, intermediateCert, leafCert) = generateCertificateChain()

        val result = CertificateValidator.validateChain(listOf(leafCert, intermediateCert, rootCert))

        assertTrue(result.isValid)
        assertTrue(result.errors.isEmpty())
    }

    @Test
    fun `test validateChain with invalid chain order`() {
        val (rootCert, intermediateCert, leafCert) = generateCertificateChain()

        // Wrong order: root first instead of leaf first
        val result = CertificateValidator.validateChain(listOf(rootCert, intermediateCert, leafCert))

        assertFalse(result.isValid)
        assertFalse(result.errors.isEmpty())
    }

    @Test
    fun `test validateChain with expired certificate in chain`() {
        val (rootCert, intermediateCert, _) = generateCertificateChain()

        val result = CertificateValidator.validateChain(
            listOf(expiredCertificate, intermediateCert, rootCert)
        )

        assertFalse(result.isValid)
        assertTrue(result.errors.any { it.contains("expired") })
    }

    @Test
    fun `test verifyCertificateSignature with valid signature`() {
        val (rootCert, intermediateCert, _) = generateCertificateChain()

        val isValid = CertificateValidator.verifyCertificateSignature(
            intermediateCert,
            rootCert.publicKey
        )

        assertTrue(isValid)
    }

    @Test
    fun `test verifyCertificateSignature with invalid signature`() {
        val (_, intermediateCert, leafCert) = generateCertificateChain()

        // Try to verify intermediate cert with leaf's public key (wrong)
        val isValid = CertificateValidator.verifyCertificateSignature(
            intermediateCert,
            leafCert.publicKey
        )

        assertFalse(isValid)
    }

    @Test
    fun `test verifyCertificateSignature with self-signed certificate`() {
        val (rootCert, _, _) = generateCertificateChain()

        // Root certificate should be self-signed
        val isValid = CertificateValidator.verifyCertificateSignature(
            rootCert,
            rootCert.publicKey
        )

        assertTrue(isValid)
    }

    @Test
    fun `test checkRevocation returns false as placeholder`() {
        val isRevoked = CertificateValidator.checkRevocation(validCertificate)

        // Placeholder implementation should return false
        assertFalse(isRevoked)
    }

    @Test
    fun `test ValidationResult success factory method`() {
        val result = ValidationResult.success()

        assertTrue(result.isValid)
        assertTrue(result.errors.isEmpty())
        assertTrue(result.warnings.isEmpty())
    }

    @Test
    fun `test ValidationResult success with warnings`() {
        val warnings = listOf("Warning 1", "Warning 2")
        val result = ValidationResult.success(warnings)

        assertTrue(result.isValid)
        assertTrue(result.errors.isEmpty())
        assertEquals(warnings, result.warnings)
    }

    @Test
    fun `test ValidationResult failure factory method`() {
        val errors = listOf("Error 1", "Error 2")
        val result = ValidationResult.failure(errors)

        assertFalse(result.isValid)
        assertEquals(errors, result.errors)
        assertTrue(result.warnings.isEmpty())
    }

    @Test
    fun `test ValidationResult failure with warnings`() {
        val errors = listOf("Error 1")
        val warnings = listOf("Warning 1")
        val result = ValidationResult.failure(errors, warnings)

        assertFalse(result.isValid)
        assertEquals(errors, result.errors)
        assertEquals(warnings, result.warnings)
    }

    // Helper method to generate a test certificate
    private fun generateTestCertificate(
        validityDays: Int,
        startDaysAgo: Int,
        isCA: Boolean = false
    ): X509Certificate {
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

        if (isCA) {
            certBuilder.addExtension(
                Extension.basicConstraints,
                true,
                BasicConstraints(true)
            )
        }

        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val certHolder = certBuilder.build(signer)

        return JcaX509CertificateConverter().getCertificate(certHolder)
    }

    // Helper method to generate a certificate chain (root -> intermediate -> leaf)
    private fun generateCertificateChain(): Triple<X509Certificate, X509Certificate, X509Certificate> {
        // Generate root CA
        val rootKeyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        val now = System.currentTimeMillis()
        val startDate = Date(now - (24 * 60 * 60 * 1000L))
        val endDate = Date(startDate.time + (365 * 24 * 60 * 60 * 1000L))

        val rootSubject = X500Name("CN=Root CA, O=Test Org, C=US")
        val rootSerial = BigInteger.valueOf(System.currentTimeMillis())

        val rootBuilder = JcaX509v3CertificateBuilder(
            rootSubject,
            rootSerial,
            startDate,
            endDate,
            rootSubject,
            rootKeyPair.public
        )
        rootBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))

        val rootSigner = JcaContentSignerBuilder("SHA256withRSA").build(rootKeyPair.private)
        val rootCert = JcaX509CertificateConverter().getCertificate(rootBuilder.build(rootSigner))

        // Generate intermediate CA
        val intermediateKeyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        val intermediateSubject = X500Name("CN=Intermediate CA, O=Test Org, C=US")
        val intermediateSerial = BigInteger.valueOf(System.currentTimeMillis() + 1)

        val intermediateBuilder = JcaX509v3CertificateBuilder(
            rootSubject,
            intermediateSerial,
            startDate,
            endDate,
            intermediateSubject,
            intermediateKeyPair.public
        )
        intermediateBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))

        val intermediateSigner = JcaContentSignerBuilder("SHA256withRSA").build(rootKeyPair.private)
        val intermediateCert = JcaX509CertificateConverter()
            .getCertificate(intermediateBuilder.build(intermediateSigner))

        // Generate leaf certificate
        val leafKeyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        val leafSubject = X500Name("CN=Leaf Certificate, O=Test Org, C=US")
        val leafSerial = BigInteger.valueOf(System.currentTimeMillis() + 2)

        val leafBuilder = JcaX509v3CertificateBuilder(
            intermediateSubject,
            leafSerial,
            startDate,
            endDate,
            leafSubject,
            leafKeyPair.public
        )

        val leafSigner = JcaContentSignerBuilder("SHA256withRSA").build(intermediateKeyPair.private)
        val leafCert = JcaX509CertificateConverter().getCertificate(leafBuilder.build(leafSigner))

        return Triple(rootCert, intermediateCert, leafCert)
    }
}
