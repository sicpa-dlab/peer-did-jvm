package org.didcommx.peerdid

import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TestDIDDocFromJson {

    data class TestData(
        val didDoc: JSON,
        val expectedFormat: VerificationMaterialFormatPeerDID,
        val expectedType: VerificationMethodType,
        val expectedField: PublicKeyField
    )

    companion object {

        @JvmStatic
        fun didDocNumalgo0(): Stream<TestData> =
            Stream.of(
                TestData(
                    DID_DOC_NUMALGO_O_BASE58,
                    VerificationMaterialFormatPeerDID.BASE58,
                    VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                    PublicKeyField.BASE58
                ),
                TestData(
                    DID_DOC_NUMALGO_O_MULTIBASE,
                    VerificationMaterialFormatPeerDID.MULTIBASE,
                    VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    PublicKeyField.MULTIBASE
                ),
                TestData(
                    DID_DOC_NUMALGO_O_JWK,
                    VerificationMaterialFormatPeerDID.JWK,
                    VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    PublicKeyField.JWK
                ),
            )

    }

    @ParameterizedTest
    @MethodSource("didDocNumalgo0")
    fun testDidDocFromJsonNumalgo0(testData: TestData) {
        val didDoc = DIDDocPeerDID.fromJson(testData.didDoc)

        assertEquals(PEER_DID_NUMALGO_0, didDoc.did)

        assertTrue(didDoc.keyAgreement.isEmpty())
        assertNull(didDoc.service)
        assertEquals(1, didDoc.authentication.size)

        val auth = didDoc.authentication[0]
        val expectedAuth = (fromJson(testData.didDoc)["authentication"] as List<Map<String, Any>>)[0]
        assertEquals(expectedAuth["id"], auth.id)
        assertEquals(PEER_DID_NUMALGO_0, auth.controller)
        assertEquals(testData.expectedFormat, auth.verMaterial.format)
        assertEquals(testData.expectedType, auth.verMaterial.type)
        assertEquals(expectedAuth[testData.expectedField.value], auth.verMaterial.value)

        assertEquals(
            listOf("did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"),
            didDoc.authKids()
        )
        assertTrue(didDoc.agreemenrtKids().isEmpty())
    }
}