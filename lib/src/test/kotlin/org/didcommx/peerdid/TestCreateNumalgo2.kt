package org.didcommx.peerdid

import org.didcommx.peerdid.core.toJson
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TestCreateNumalgo2 {

    data class TestData(
        val signingKeys: List<VerificationMaterialAuthentication>,
        val encKeys: List<VerificationMaterialAgreement>
    )

    companion object {

        val VALID_X25519_KEY_BASE58 = VerificationMaterialAgreement(
            value = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
            type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format = VerificationMaterialFormatPeerDID.BASE58
        )

        val VALID_X25519_KEY_MULTIBASE = VerificationMaterialAgreement(
            value = "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
            format = VerificationMaterialFormatPeerDID.MULTIBASE
        )

        val VALID_X25519_KEY_JWK_DICT = VerificationMaterialAgreement(
            value = mapOf(
                "kty" to "OKP",
                "crv" to "X25519",
                "x" to "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
            ),
            type = VerificationMethodTypeAgreement.JSON_WEB_KEY_2020, format = VerificationMaterialFormatPeerDID.JWK
        )

        val VALID_X25519_KEY_JWK_JSON = VerificationMaterialAgreement(
            value = toJson(
                mapOf(
                    "kty" to "OKP",
                    "crv" to "X25519",
                    "x" to "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
                )
            ),
            type = VerificationMethodTypeAgreement.JSON_WEB_KEY_2020, format = VerificationMaterialFormatPeerDID.JWK
        )

        val VALID_ED25519_KEY_1_BASE58 = VerificationMaterialAuthentication(
            value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format = VerificationMaterialFormatPeerDID.BASE58
        )
        val VALID_ED25519_KEY_1_MULTIBASE = VerificationMaterialAuthentication(
            value = "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
            format = VerificationMaterialFormatPeerDID.MULTIBASE
        )
        val VALID_ED25519_KEY_1_JWK = VerificationMaterialAuthentication(
            value = mapOf(
                "kty" to "OKP",
                "crv" to "Ed25519",
                "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
            ),
            type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
            format = VerificationMaterialFormatPeerDID.JWK
        )

        val VALID_ED25519_KEY_2_BASE58 = VerificationMaterialAuthentication(
            value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
            type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format = VerificationMaterialFormatPeerDID.BASE58
        )
        val VALID_ED25519_KEY_2_MULTIBASE = VerificationMaterialAuthentication(
            value = "z6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg",
            type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
            format = VerificationMaterialFormatPeerDID.MULTIBASE
        )
        val VALID_ED25519_KEY_2_JWK = VerificationMaterialAuthentication(
            value = mapOf(
                "kty" to "OKP",
                "crv" to "Ed25519",
                "x" to "Itv8B__b1-Jos3LCpUe8EdTFGTCa_Dza6_3848P3R70",
            ),
            type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
            format = VerificationMaterialFormatPeerDID.JWK
        )

        const val VALID_SERVICE =
            """
        {
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint",
            "routingKeys": ["did:example:somemediator#somekey"],
            "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
        }
        """

        @JvmStatic
        fun validKeys(): Stream<TestData> =
            Stream.of(
                TestData(
                    listOf(VALID_ED25519_KEY_1_BASE58, VALID_ED25519_KEY_2_BASE58),
                    listOf(VALID_X25519_KEY_BASE58)
                ),
                TestData(
                    listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE),
                    listOf(VALID_X25519_KEY_MULTIBASE)
                ),
                TestData(
                    listOf(VALID_ED25519_KEY_1_JWK, VALID_ED25519_KEY_2_JWK),
                    listOf(VALID_X25519_KEY_JWK_DICT)
                ),
                TestData(
                    listOf(VALID_ED25519_KEY_1_JWK, VALID_ED25519_KEY_2_JWK),
                    listOf(VALID_X25519_KEY_JWK_JSON)
                )
            )
    }

    @ParameterizedTest
    @MethodSource("validKeys")
    fun testCreateNumalgo2Positive(keys: TestData) {
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
            encryptionKeys = keys.encKeys, signingKeys = keys.signingKeys,
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
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)
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
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)

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
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)

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
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)

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
        val encryptionKeys = emptyList<VerificationMaterialAgreement>()
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)

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
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = emptyList<VerificationMaterialAuthentication>()
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
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)
        val service = VALID_SERVICE

        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key: Invalid base58 encoding.*")))
    }

    @Test
    fun testCreateNumalgo2WrongSigningKey() {
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(
            VerificationMaterialAuthentication(
                value = "....",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format = VerificationMaterialFormatPeerDID.BASE58
            ),
            VerificationMaterialAuthentication(
                value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val service = VALID_SERVICE

        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key: Invalid base58 encoding.*")))
    }

    @Test
    fun testCreateNumalgo2WrongService() {
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)
        val service = """..."""
        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid JSON.*")))
    }

    @Test
    fun testCreateNumalgo2EncryptionKeysAndSigningAreMoreThan1ElementArray() {
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE, VALID_X25519_KEY_JWK_DICT, VALID_X25519_KEY_BASE58)
        val signingKeys = listOf(
            VALID_ED25519_KEY_1_MULTIBASE,
            VALID_ED25519_KEY_2_MULTIBASE,
            VALID_ED25519_KEY_1_BASE58,
            VALID_ED25519_KEY_2_JWK
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
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)

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
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)

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
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)

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
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)

        val service = VALID_SERVICE

        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key: Invalid base58 encoding.*")))
    }

    @Test
    fun testCreateNumalgo2MalformedSigningKeyNotBase58Encoded() {
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(
            VerificationMaterialAuthentication(
                value = "ByHnpUCFb1vA0h9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format = VerificationMaterialFormatPeerDID.BASE58
            ),
            VerificationMaterialAuthentication(
                value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val service = VALID_SERVICE

        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key: Invalid base58 encoding.*")))
    }

    @Test
    fun testCreateNumalgo2MalformedLongEncryptionKey() {
        val encryptionKeys = listOf(
            VerificationMaterialAgreement(
                value = "JhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWe",
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)

        val service = VALID_SERVICE

        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key.*")))
    }

    @Test
    fun testCreateNumalgo2MalformedShortEncryptionKey() {
        val encryptionKeys = listOf(
            VerificationMaterialAgreement(
                value = "JhNWeSV",
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE, VALID_ED25519_KEY_2_MULTIBASE)
        val service = VALID_SERVICE

        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key.*")))
    }

    @Test
    fun testCreateNumalgo2MalformedLongSigningKey() {
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(
            VerificationMaterialAuthentication(
                value = "JhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWeSVJhNWe",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format = VerificationMaterialFormatPeerDID.BASE58
            ),
            VerificationMaterialAuthentication(
                value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val service = VALID_SERVICE

        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key.*")))
    }

    @Test
    fun testCreateNumalgo2MalformedShortSigningKey() {
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(
            VerificationMaterialAuthentication(
                value = "JhNWeSV",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format = VerificationMaterialFormatPeerDID.BASE58
            ),
            VerificationMaterialAuthentication(
                value = "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J",
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format = VerificationMaterialFormatPeerDID.BASE58
            )
        )
        val service = VALID_SERVICE

        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo2(
                encryptionKeys = encryptionKeys, signingKeys = signingKeys,
                service = service
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key.*")))
    }
}
