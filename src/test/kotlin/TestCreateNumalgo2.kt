import org.dif.model.EncodingType
import org.dif.model.PublicKeyAgreement
import org.dif.model.PublicKeyAuthentication
import org.dif.model.PublicKeyTypeAgreement
import org.dif.model.PublicKeyTypeAuthentication
import org.dif.peerdid.createPeerDIDNumalgo2
import org.dif.peerdid.isPeerDID
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class TestCreateNumalgo2 {
    val VALID_X25519_KEY = PublicKeyAgreement(
        encodedValue = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
        type = PublicKeyTypeAgreement.X25519, encodingType = EncodingType.BASE58
    )

    val VALID_ED25519_KEY_1 = PublicKeyAuthentication(
        encodedValue = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
    )
    val VALID_ED25519_KEY_2 = PublicKeyAuthentication(
        encodedValue = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
        type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
    )

    val VALID_SERVICE =
        """[
        {
            "type": "didcommmessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
        },
        {
            "type": "didcommmessaging",
            "serviceEndpoint": "https://example.com/endpoint2",
            "routingKeys": ["did:example:somemediator#somekey2"]
        }
        ]
        """

    val VALID_SERVICE_NOT_ARRAY =
        """
        {
            "type": "didcommmessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"]
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
        val service = VALID_SERVICE

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )
        assert(
            peerDIDAlgo2 == "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" +
                ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlO" +
                "nNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9p" +
                "bnQyIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTIiXX1d"
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
        val service = VALID_SERVICE_NOT_ARRAY

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
                "type": "didcommmessaging",
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
    fun testCreateNumalgo2WithoutEncryptionKeys() {
        val encryptionKeys = listOf<PublicKeyAgreement>()
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = VALID_SERVICE

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )
        assert(
            peerDIDAlgo2 == "did:peer:2" +
                ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" +
                ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlO" +
                "nNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9p" +
                "bnQyIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTIiXX1d"
        )
        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2EmptySigningKeys() {
        val encryptionKeys = listOf(
            VALID_X25519_KEY
        )
        val signingKeys = listOf<PublicKeyAuthentication>()
        val service = VALID_SERVICE

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )
        assert(
            peerDIDAlgo2 == "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlO" +
                "nNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9p" +
                "bnQyIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTIiXX1d"
        )
        assert(isPeerDID(peerDIDAlgo2))
    }

    @Test
    fun testCreateNumalgo2WrongEncryptionKey() {
        val encryptionKeys = listOf(
            PublicKeyAgreement(
                encodedValue = "...",
                type = PublicKeyTypeAgreement.X25519, encodingType = EncodingType.BASE58
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
            PublicKeyAuthentication(
                encodedValue = "....",
                type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
            ),
            PublicKeyAuthentication(
                encodedValue = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
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
            PublicKeyAgreement(
                encodedValue = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                type = PublicKeyTypeAgreement.X25519, encodingType = EncodingType.BASE58
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
            PublicKeyAgreement(
                encodedValue = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                type = PublicKeyTypeAgreement.X25519, encodingType = EncodingType.BASE58
            )
        )
        val signingKeys = listOf(
            VALID_ED25519_KEY_1, VALID_ED25519_KEY_2
        )
        val service = """{
        "type": "didcommmessaging",
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

        assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
    }

    @Test
    fun testCreateNumalgo2MalformedEncryptionKeyNotBase58Encoded() {
        val encryptionKeys = listOf(
            PublicKeyAgreement(
                encodedValue = "JhNWeSVLMYcc0k7iopQW4guaSJTojqpMEELgSLhKwRr",
                type = PublicKeyTypeAgreement.X25519, encodingType = EncodingType.BASE58
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
            PublicKeyAuthentication(
                encodedValue = "ByHnpUCFb1vA0h9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
            ),
            PublicKeyAuthentication(
                encodedValue = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
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
            PublicKeyAgreement(
                encodedValue = "JhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWe",
                type = PublicKeyTypeAgreement.X25519, encodingType = EncodingType.BASE58
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
            PublicKeyAgreement(
                encodedValue = "JhNWeSV",
                type = PublicKeyTypeAgreement.X25519, encodingType = EncodingType.BASE58
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
            PublicKeyAuthentication(
                encodedValue = "JhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWe",
                type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
            ),
            PublicKeyAuthentication(
                encodedValue = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
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
            PublicKeyAuthentication(
                encodedValue = "JhNWeSV",
                type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
            ),
            PublicKeyAuthentication(
                encodedValue = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = PublicKeyTypeAuthentication.ED25519, encodingType = EncodingType.BASE58
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
