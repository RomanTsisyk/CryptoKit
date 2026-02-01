package io.github.romantsisyk.cryptolib.certificates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

class CertificateInfoTest {

    @Test
    fun `test CertificateInfo data class creation`() {
        val subject = "CN=Test Subject, O=Test Org, C=US"
        val issuer = "CN=Test Issuer, O=Test Org, C=US"
        val serialNumber = "1234567890ABCDEF"
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L)
        val publicKeyAlgorithm = "RSA"
        val signatureAlgorithm = "SHA256withRSA"
        val isValid = true
        val daysUntilExpiry = 365L

        val certInfo = CertificateInfo(
            subject = subject,
            issuer = issuer,
            serialNumber = serialNumber,
            notBefore = notBefore,
            notAfter = notAfter,
            publicKeyAlgorithm = publicKeyAlgorithm,
            signatureAlgorithm = signatureAlgorithm,
            isValid = isValid,
            daysUntilExpiry = daysUntilExpiry
        )

        assertNotNull(certInfo)
        assertEquals(subject, certInfo.subject)
        assertEquals(issuer, certInfo.issuer)
        assertEquals(serialNumber, certInfo.serialNumber)
        assertEquals(notBefore, certInfo.notBefore)
        assertEquals(notAfter, certInfo.notAfter)
        assertEquals(publicKeyAlgorithm, certInfo.publicKeyAlgorithm)
        assertEquals(signatureAlgorithm, certInfo.signatureAlgorithm)
        assertTrue(certInfo.isValid)
        assertEquals(daysUntilExpiry, certInfo.daysUntilExpiry)
    }

    @Test
    fun `test CertificateInfo for expired certificate`() {
        val certInfo = CertificateInfo(
            subject = "CN=Expired",
            issuer = "CN=Issuer",
            serialNumber = "123",
            notBefore = Date(System.currentTimeMillis() - 400 * 24 * 60 * 60 * 1000L),
            notAfter = Date(System.currentTimeMillis() - 10 * 24 * 60 * 60 * 1000L),
            publicKeyAlgorithm = "RSA",
            signatureAlgorithm = "SHA256withRSA",
            isValid = false,
            daysUntilExpiry = -10L
        )

        assertFalse(certInfo.isValid)
        assertTrue(certInfo.daysUntilExpiry < 0)
    }

    @Test
    fun `test CertificateInfo equality`() {
        val date1 = Date()
        val date2 = Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L)

        val certInfo1 = CertificateInfo(
            subject = "CN=Test",
            issuer = "CN=Issuer",
            serialNumber = "123",
            notBefore = date1,
            notAfter = date2,
            publicKeyAlgorithm = "RSA",
            signatureAlgorithm = "SHA256withRSA",
            isValid = true,
            daysUntilExpiry = 365L
        )

        val certInfo2 = CertificateInfo(
            subject = "CN=Test",
            issuer = "CN=Issuer",
            serialNumber = "123",
            notBefore = date1,
            notAfter = date2,
            publicKeyAlgorithm = "RSA",
            signatureAlgorithm = "SHA256withRSA",
            isValid = true,
            daysUntilExpiry = 365L
        )

        assertEquals(certInfo1, certInfo2)
        assertEquals(certInfo1.hashCode(), certInfo2.hashCode())
    }

    @Test
    fun `test CertificateInfo copy method`() {
        val original = CertificateInfo(
            subject = "CN=Original",
            issuer = "CN=Issuer",
            serialNumber = "123",
            notBefore = Date(),
            notAfter = Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L),
            publicKeyAlgorithm = "RSA",
            signatureAlgorithm = "SHA256withRSA",
            isValid = true,
            daysUntilExpiry = 365L
        )

        val modified = original.copy(subject = "CN=Modified")

        assertEquals("CN=Modified", modified.subject)
        assertEquals(original.issuer, modified.issuer)
        assertEquals(original.serialNumber, modified.serialNumber)
    }

    @Test
    fun `test CertificateInfo toString contains all fields`() {
        val certInfo = CertificateInfo(
            subject = "CN=Test",
            issuer = "CN=Issuer",
            serialNumber = "123",
            notBefore = Date(),
            notAfter = Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L),
            publicKeyAlgorithm = "RSA",
            signatureAlgorithm = "SHA256withRSA",
            isValid = true,
            daysUntilExpiry = 365L
        )

        val toString = certInfo.toString()

        assertTrue(toString.contains("CN=Test"))
        assertTrue(toString.contains("CN=Issuer"))
        assertTrue(toString.contains("123"))
        assertTrue(toString.contains("RSA"))
        assertTrue(toString.contains("SHA256withRSA"))
        assertTrue(toString.contains("365"))
    }
}
