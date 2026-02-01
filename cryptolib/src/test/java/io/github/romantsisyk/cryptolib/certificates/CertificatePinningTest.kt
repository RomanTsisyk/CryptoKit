package io.github.romantsisyk.cryptolib.certificates

import io.github.romantsisyk.cryptolib.exceptions.CertificateException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

class CertificatePinningTest {

    private lateinit var testCertificate1: X509Certificate
    private lateinit var testCertificate2: X509Certificate
    private lateinit var testPin1: String
    private lateinit var testPin2: String

    @Before
    fun setUp() {
        // Clear all pins before each test
        CertificatePinning.clearAllPins()

        // Generate test certificates
        testCertificate1 = generateTestCertificate("CN=Test 1")
        testCertificate2 = generateTestCertificate("CN=Test 2")

        // Calculate pins
        testPin1 = CertificateUtils.getFingerprint(testCertificate1, "SHA-256")
        testPin2 = CertificateUtils.getFingerprint(testCertificate2, "SHA-256")
    }

    @After
    fun tearDown() {
        // Clean up after each test
        CertificatePinning.clearAllPins()
    }

    @Test
    fun `test addPin with valid host and pin`() {
        CertificatePinning.addPin("api.example.com", testPin1)

        val retrievedPin = CertificatePinning.getPinForHost("api.example.com")
        assertEquals(testPin1.uppercase(), retrievedPin)
    }

    @Test
    fun `test addPin with blank host throws exception`() {
        assertThrows(CertificateException::class.java) {
            CertificatePinning.addPin("", testPin1)
        }
    }

    @Test
    fun `test addPin with blank pin throws exception`() {
        assertThrows(CertificateException::class.java) {
            CertificatePinning.addPin("api.example.com", "")
        }
    }

    @Test
    fun `test addPin with invalid pin format throws exception`() {
        assertThrows(CertificateException::class.java) {
            CertificatePinning.addPin("api.example.com", "invalid-pin-format")
        }
    }

    @Test
    fun `test addPin with short pin throws exception`() {
        assertThrows(CertificateException::class.java) {
            CertificatePinning.addPin("api.example.com", "AA:BB:CC")
        }
    }

    @Test
    fun `test addPin normalizes host to lowercase`() {
        CertificatePinning.addPin("API.EXAMPLE.COM", testPin1)

        val retrievedPin = CertificatePinning.getPinForHost("api.example.com")
        assertNotNull(retrievedPin)
        assertEquals(testPin1.uppercase(), retrievedPin)
    }

    @Test
    fun `test removePin removes existing pin`() {
        CertificatePinning.addPin("api.example.com", testPin1)
        assertNotNull(CertificatePinning.getPinForHost("api.example.com"))

        CertificatePinning.removePin("api.example.com")

        assertNull(CertificatePinning.getPinForHost("api.example.com"))
    }

    @Test
    fun `test removePin with blank host does not throw`() {
        // Should not throw exception
        CertificatePinning.removePin("")
    }

    @Test
    fun `test removePin with non-existent host does not throw`() {
        // Should not throw exception
        CertificatePinning.removePin("non.existent.com")
    }

    @Test
    fun `test verifyPin with matching certificate returns true`() {
        CertificatePinning.addPin("api.example.com", testPin1)

        val isValid = CertificatePinning.verifyPin("api.example.com", testCertificate1)

        assertTrue(isValid)
    }

    @Test
    fun `test verifyPin with non-matching certificate returns false`() {
        CertificatePinning.addPin("api.example.com", testPin1)

        val isValid = CertificatePinning.verifyPin("api.example.com", testCertificate2)

        assertFalse(isValid)
    }

    @Test
    fun `test verifyPin with no pin configured returns false`() {
        val isValid = CertificatePinning.verifyPin("api.example.com", testCertificate1)

        assertFalse(isValid)
    }

    @Test
    fun `test verifyPin with blank host throws exception`() {
        assertThrows(CertificateException::class.java) {
            CertificatePinning.verifyPin("", testCertificate1)
        }
    }

    @Test
    fun `test verifyPin is case-insensitive for host`() {
        CertificatePinning.addPin("api.example.com", testPin1)

        assertTrue(CertificatePinning.verifyPin("API.EXAMPLE.COM", testCertificate1))
        assertTrue(CertificatePinning.verifyPin("Api.Example.Com", testCertificate1))
    }

    @Test
    fun `test getPinForHost returns correct pin`() {
        CertificatePinning.addPin("api.example.com", testPin1)

        val retrievedPin = CertificatePinning.getPinForHost("api.example.com")

        assertEquals(testPin1.uppercase(), retrievedPin)
    }

    @Test
    fun `test getPinForHost with non-existent host returns null`() {
        val retrievedPin = CertificatePinning.getPinForHost("non.existent.com")

        assertNull(retrievedPin)
    }

    @Test
    fun `test getPinForHost with blank host returns null`() {
        val retrievedPin = CertificatePinning.getPinForHost("")

        assertNull(retrievedPin)
    }

    @Test
    fun `test clearAllPins removes all pins`() {
        CertificatePinning.addPin("api1.example.com", testPin1)
        CertificatePinning.addPin("api2.example.com", testPin2)

        CertificatePinning.clearAllPins()

        assertNull(CertificatePinning.getPinForHost("api1.example.com"))
        assertNull(CertificatePinning.getPinForHost("api2.example.com"))
        assertTrue(CertificatePinning.getAllPins().isEmpty())
    }

    @Test
    fun `test getAllPins returns all configured pins`() {
        CertificatePinning.addPin("api1.example.com", testPin1)
        CertificatePinning.addPin("api2.example.com", testPin2)

        val allPins = CertificatePinning.getAllPins()

        assertEquals(2, allPins.size)
        assertTrue(allPins.containsKey("api1.example.com"))
        assertTrue(allPins.containsKey("api2.example.com"))
        assertEquals(testPin1.uppercase(), allPins["api1.example.com"])
        assertEquals(testPin2.uppercase(), allPins["api2.example.com"])
    }

    @Test
    fun `test getAllPins returns empty map when no pins configured`() {
        val allPins = CertificatePinning.getAllPins()

        assertTrue(allPins.isEmpty())
    }

    @Test
    fun `test multiple pins for different hosts`() {
        CertificatePinning.addPin("api1.example.com", testPin1)
        CertificatePinning.addPin("api2.example.com", testPin2)

        assertTrue(CertificatePinning.verifyPin("api1.example.com", testCertificate1))
        assertTrue(CertificatePinning.verifyPin("api2.example.com", testCertificate2))
        assertFalse(CertificatePinning.verifyPin("api1.example.com", testCertificate2))
        assertFalse(CertificatePinning.verifyPin("api2.example.com", testCertificate1))
    }

    @Test
    fun `test updating pin for existing host`() {
        CertificatePinning.addPin("api.example.com", testPin1)
        assertTrue(CertificatePinning.verifyPin("api.example.com", testCertificate1))

        // Update with new pin
        CertificatePinning.addPin("api.example.com", testPin2)
        assertFalse(CertificatePinning.verifyPin("api.example.com", testCertificate1))
        assertTrue(CertificatePinning.verifyPin("api.example.com", testCertificate2))
    }

    @Test
    fun `test pin format validation accepts valid SHA-256 format`() {
        val validPin = "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:" +
                      "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"

        // Should not throw exception
        CertificatePinning.addPin("api.example.com", validPin)
    }

    @Test
    fun `test pin format validation rejects pin without colons`() {
        val invalidPin = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"

        assertThrows(CertificateException::class.java) {
            CertificatePinning.addPin("api.example.com", invalidPin)
        }
    }

    @Test
    fun `test pin format validation rejects pin with wrong length`() {
        val invalidPin = "AB:CD:EF:12:34:56"

        assertThrows(CertificateException::class.java) {
            CertificatePinning.addPin("api.example.com", invalidPin)
        }
    }

    @Test
    fun `test pin format validation rejects pin with invalid characters`() {
        val invalidPin = "GH:IJ:KL:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:" +
                        "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"

        assertThrows(CertificateException::class.java) {
            CertificatePinning.addPin("api.example.com", invalidPin)
        }
    }

    // Helper method to generate a test certificate
    private fun generateTestCertificate(subject: String): X509Certificate {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()

        val now = System.currentTimeMillis()
        val startDate = Date(now - (24 * 60 * 60 * 1000L))
        val endDate = Date(startDate.time + (365 * 24 * 60 * 60 * 1000L))

        val x500Subject = X500Name(subject)
        val serialNumber = BigInteger.valueOf(System.currentTimeMillis())

        val certBuilder = JcaX509v3CertificateBuilder(
            x500Subject,
            serialNumber,
            startDate,
            endDate,
            x500Subject,
            keyPair.public
        )

        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val certHolder = certBuilder.build(signer)

        return JcaX509CertificateConverter().getCertificate(certHolder)
    }
}
