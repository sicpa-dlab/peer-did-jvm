package org.didcommx.peerdid

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class TestCreateNumalgo2 {
    val VALID_X25519_KEY = VerificationMaterialAgreement(
        value = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
        type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019, format = VerificationMaterialFormatPeerDID.BASE58
    )

    val VALID_ED25519_KEY_1 = VerificationMaterialAuthentication(
        value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
    )
    val VALID_ED25519_KEY_2 = VerificationMaterialAuthentication(
        value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
        type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
    )

    val VALID_SERVICE =
        """
        {
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"],
            "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
        }
        """

    @Test
    fun testCreateNumalgo2Positive() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = """[
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint",
                "routingKeys": ["did:example:somemediator#somekey"]
            },
            {
                "type": "example",
                "serviceEndpoint": "https://example.com/endpoint2",
                "routingKeys": ["did:example:somemediator#somekey2"],
                "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
            }
            ]
            """

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )
        assertEquals(
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" +
                ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfV0",
            peerDIDAlgo2
        )
        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2PositiveServiceNotArray() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service =
            """
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint",
                "routingKeys": ["did:example:somemediator#somekey"]
            }
            """

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )

        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2PositiveServiceMinimalFields() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service =
            """
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint"
            }
            """

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )

        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2PositiveServiceArrayOf1Element() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = """
        [
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint",
                "routingKeys": ["did:example:somemediator#somekey"]
            }       
        ]
        """

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )

        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2PositiveServiceIsNull() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = null

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )

        assertEquals(
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg",
            peerDIDAlgo2
        )
        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2WithoutEncryptionKeys() {
        val encryptionKeys = listOf<VerificationMaterialAgreement>()
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = VALID_SERVICE

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )
        assertEquals(
            "did:peer:2" +
                ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" +
                ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
            peerDIDAlgo2
        )
        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2EmptySigningKeys() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf<VerificationMaterialAuthentication>()
        val service = VALID_SERVICE

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )
        assertEquals(
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
            peerDIDAlgo2
        )
        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2WrongEncryptionKey() {
        val encryptionKeys = listOf(
            VerificationMaterialAgreement(
                value = "...",
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = VALID_SERVICE

        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }

    @Test
    fun testCreateNumalgo2WrongSigningKey() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VerificationMaterialAuthentication(
                value = "....",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
            ),
            VerificationMaterialAuthentication(
                value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val service = VALID_SERVICE

        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }

    @Test
    fun testCreateNumalgo2WrongService() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = """..."""
        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }

    @Test
    fun testCreateNumalgo2EncryptionKeysAndSigningAreMoreThan1ElementArray() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY,
            VerificationMaterialAgreement(
                value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = VALID_SERVICE

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )
        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2ServiceHasMoreFieldsThanInConversionTable() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY,
            VerificationMaterialAgreement(
                value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = """{
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"],
        "example1": "myExample1",
        "example2": "myExample2"
        }
        """

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )
        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2ServiceIsNotdidcommmessaging() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = """{
        "type": "example1",
        "serviceEndpoint": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"]
        }
        """

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )
        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2ServiceIsEmptyString() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = """"""

        assert(
            isPeerDID(
                createPeerDIDNumalgo2(
                    encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                    service = service
                )
            )
        )
    }

    @Test
    fun testCreateNumalgo2MalformedEncryptionKeyNotBase58Encoded() {
        val encryptionKeys = listOf(
            VerificationMaterialAgreement(
                value = "JhNWeSVLMYcc0k7iopQW4guaSJTojqpMEELgSLhKwRr",
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = VALID_SERVICE

        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }

    @Test
    fun testCreateNumalgo2MalformedSigningKeyNotBase58Encoded() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VerificationMaterialAuthentication(
                value = "ByHnpUCFb1vA0h9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
            ),
            VerificationMaterialAuthentication(
                value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val service = VALID_SERVICE

        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }

    @Test
    fun testCreateNumalgo2MalformedLongEncryptionKey() {
        val encryptionKeys = listOf(
            VerificationMaterialAgreement(
                value = "JhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWe",
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = VALID_SERVICE

        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }

    @Test
    fun testCreateNumalgo2MalformedShortEncryptionKey() {
        val encryptionKeys = listOf(
            VerificationMaterialAgreement(
                value = "JhNWeSV",
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = VALID_SERVICE

        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }

    @Test
    fun testCreateNumalgo2MalformedLongSigningKey() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VerificationMaterialAuthentication(
                value = "JhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWe",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
            ),
            VerificationMaterialAuthentication(
                value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val service = VALID_SERVICE

        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }

    @Test
    fun testCreateNumalgo2MalformedShortSigningKey() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf(
            VerificationMaterialAuthentication(
                value = "JhNWeSV",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
            ),
            VerificationMaterialAuthentication(
                value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018, format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val service = VALID_SERVICE

        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }
}
