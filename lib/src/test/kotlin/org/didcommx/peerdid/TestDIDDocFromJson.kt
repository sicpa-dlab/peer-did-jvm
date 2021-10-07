package org.didcommx.peerdid

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TestDIDDocFromJson {

    data class TestData(
        val didDoc: JSON,
        val expectedFormat: VerificationMaterialFormatPeerDID,
        val expectedAuthType: VerificationMethodType,
        val expectedAgreemType: VerificationMethodType,
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
                    VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                    PublicKeyField.BASE58
                ),
                TestData(
                    DID_DOC_NUMALGO_O_MULTIBASE,
                    VerificationMaterialFormatPeerDID.MULTIBASE,
                    VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                    PublicKeyField.MULTIBASE
                ),
                TestData(
                    DID_DOC_NUMALGO_O_JWK,
                    VerificationMaterialFormatPeerDID.JWK,
                    VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
                    PublicKeyField.JWK
                ),
            )


        @JvmStatic
        fun didDocNumalgo2(): Stream<TestData> =
            Stream.of(
                TestData(
                    DID_DOC_NUMALGO_2_BASE58,
                    VerificationMaterialFormatPeerDID.BASE58,
                    VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                    VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                    PublicKeyField.BASE58
                ),
                TestData(
                    DID_DOC_NUMALGO_2_MULTIBASE,
                    VerificationMaterialFormatPeerDID.MULTIBASE,
                    VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                    PublicKeyField.MULTIBASE
                ),
                TestData(
                    DID_DOC_NUMALGO_2_JWK,
                    VerificationMaterialFormatPeerDID.JWK,
                    VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
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
        assertEquals(testData.expectedAuthType, auth.verMaterial.type)
        assertEquals(expectedAuth[testData.expectedField.value], auth.verMaterial.value)

        assertEquals(listOf(expectedAuth["id"]), didDoc.authKids())
        assertTrue(didDoc.agreemenrtKids().isEmpty())
    }

    @ParameterizedTest
    @MethodSource("didDocNumalgo2")
    fun testDidDocFromJsonNumalgo2(testData: TestData) {
        val didDoc = DIDDocPeerDID.fromJson(testData.didDoc)

        assertEquals(PEER_DID_NUMALGO_2, didDoc.did)

        assertEquals(2, didDoc.authentication.size)
        assertEquals(1, didDoc.keyAgreement.size)
        assertNotNull(didDoc.service)
        assertEquals(1, didDoc.service?.size)

        val auth1 = didDoc.authentication[0]
        val expectedAuth1 = (fromJson(testData.didDoc)["authentication"] as List<Map<String, Any>>)[0]
        assertEquals(expectedAuth1["id"], auth1.id)
        assertEquals(PEER_DID_NUMALGO_2, auth1.controller)
        assertEquals(testData.expectedFormat, auth1.verMaterial.format)
        assertEquals(testData.expectedAuthType, auth1.verMaterial.type)
        assertEquals(expectedAuth1[testData.expectedField.value], auth1.verMaterial.value)

        val auth2 = didDoc.authentication[1]
        val expectedAuth2 = (fromJson(testData.didDoc)["authentication"] as List<Map<String, Any>>)[1]
        assertEquals(expectedAuth2["id"], auth2.id)
        assertEquals(PEER_DID_NUMALGO_2, auth2.controller)
        assertEquals(testData.expectedFormat, auth2.verMaterial.format)
        assertEquals(testData.expectedAuthType, auth2.verMaterial.type)
        assertEquals(expectedAuth2[testData.expectedField.value], auth2.verMaterial.value)

        val agreem = didDoc.keyAgreement[0]
        val expectedAgreem = (fromJson(testData.didDoc)["keyAgreement"] as List<Map<String, Any>>)[0]
        assertEquals(expectedAgreem["id"], agreem.id)
        assertEquals(PEER_DID_NUMALGO_2, agreem.controller)
        assertEquals(testData.expectedFormat, agreem.verMaterial.format)
        assertEquals(testData.expectedAgreemType, agreem.verMaterial.type)
        assertEquals(expectedAgreem[testData.expectedField.value], agreem.verMaterial.value)

        val service = didDoc.service!![0]
        val expectedService = (fromJson(testData.didDoc)["service"] as List<Map<String, Any>>)[0]
        assertTrue(service is DIDCommServicePeerDID)
        assertEquals(expectedService["id"], service.id)
        assertEquals(expectedService["serviceEndpoint"], service.serviceEndpoint)
        assertEquals(expectedService["type"], service.type)
        assertEquals(expectedService["routingKeys"], service.routingKeys)
        assertEquals(expectedService["accept"], service.accept)

        assertEquals(listOf(expectedAuth1["id"], expectedAuth2["id"]), didDoc.authKids())
        assertEquals(listOf(expectedAgreem["id"]), didDoc.agreemenrtKids())
    }

    @Test
    fun testDidDocFromJsonNumalgo2Service2Elements() {
        val didDoc = DIDDocPeerDID.fromJson(DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES)

        assertEquals(PEER_DID_NUMALGO_2_2_SERVICES, didDoc.did)

        assertNotNull(didDoc.service)
        assertEquals(2, didDoc.service?.size)


        val service1 = didDoc.service!![0]
        val expectedService1 =
            (fromJson(DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES)["service"] as List<Map<String, Any>>)[0]
        assertTrue(service1 is DIDCommServicePeerDID)
        assertEquals(expectedService1["id"], service1.id)
        assertEquals(expectedService1["serviceEndpoint"], service1.serviceEndpoint)
        assertEquals(expectedService1["type"], service1.type)
        assertEquals(expectedService1["routingKeys"], service1.routingKeys)
        assertEquals(expectedService1["accept"], service1.accept)

        val service2 = didDoc.service!![1]
        val expectedService2 =
            (fromJson(DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES)["service"] as List<Map<String, Any>>)[1]
        assertTrue(service2 is OtherService)
        assertEquals(expectedService2, service2.data)
    }

    @Test
    fun testDidDocFromJsonNumalgo2NoService() {
        val didDoc = DIDDocPeerDID.fromJson(DID_DOC_NUMALGO_2_MULTIBASE_NO_SERVICES)
        assertEquals(PEER_DID_NUMALGO_2_NO_SERVICES, didDoc.did)
        assertNull(didDoc.service)
        assertEquals(1, didDoc.authentication.size)
        assertEquals(1, didDoc.keyAgreement.size)
    }

    @Test
    fun testDidDocFromJsonNumalgo2MinimalService() {
        val didDoc = DIDDocPeerDID.fromJson(DID_DOC_NUMALGO_2_MULTIBASE_MINIMAL_SERVICES)
        assertEquals(PEER_DID_NUMALGO_2_MINIMAL_SERVICES, didDoc.did)

        assertEquals(2, didDoc.authentication.size)
        assertEquals(1, didDoc.keyAgreement.size)

        val service = didDoc.service!![0]
        assertTrue(service is DIDCommServicePeerDID)
        assertEquals(
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9#didcommmessaging-0",
            service.id
        )
        assertEquals("https://example.com/endpoint", service.serviceEndpoint)
        assertEquals("DIDCommMessaging", service.type)
        assertNull(service.routingKeys)
        assertNull(service.accept)
    }

    @Test
    fun testDidDocFromJsonInvalidJson() {
        assertThrows<MalformedPeerDIDDOcException> {
            DIDDocPeerDID.fromJson("sdfasdfsf{sdfsdfasdf...")
        }
    }

    @Test
    fun testDidDocIdFieldOnly() {
        val didDoc = DIDDocPeerDID.fromJson(
            """
   {
       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
   }
            """
        )
        assertEquals("did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V", didDoc.did)
    }

    @Test
    fun testDidDocInvalidJsonNoId() {
        assertThrows<MalformedPeerDIDDOcException> {
            DIDDocPeerDID.fromJson(
                """
                   {
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Ed25519VerificationKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyMultibase": "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
                           }
                       ]
                   }
            """
            )
        }
    }

    @Test
    fun testDidDocInvalidJsonVerMethodNoId() {
        assertThrows<MalformedPeerDIDDOcException> {
            DIDDocPeerDID.fromJson(
                """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "type": "Ed25519VerificationKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyMultibase": "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
                           }
                       ]
                   }
            """
            )
        }
    }

    @Test
    fun testDidDocInvalidJsonVerMethodNoType() {
        assertThrows<MalformedPeerDIDDOcException> {
            DIDDocPeerDID.fromJson(
                """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyMultibase": "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
                           }
                       ]
                   }
            """
            )
        }
    }

    @Test
    fun testDidDocInvalidJsonVerMethodNoController() {
        assertThrows<MalformedPeerDIDDOcException> {
            DIDDocPeerDID.fromJson(
                """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Ed25519VerificationKey2020",
                               "publicKeyMultibase": "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
                           }
                       ]
                   }
            """
            )
        }
    }

    @Test
    fun testDidDocInvalidJsonVerMethodNoValue() {
        assertThrows<MalformedPeerDIDDOcException> {
            DIDDocPeerDID.fromJson(
                """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Ed25519VerificationKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
                           }
                       ]
                   }
            """
            )
        }
    }

    @Test
    fun testDidDocInvalidJsonVerMethodInvalidType() {
        assertThrows<MalformedPeerDIDDOcException> {
            DIDDocPeerDID.fromJson(
                """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Unkknown",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyMultibase": "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
                           }
                       ]
                   }
            """
            )
        }
    }

    @Test
    fun testDidDocInvalidJsonVerMethodInvalidField() {
        assertThrows<MalformedPeerDIDDOcException> {
            DIDDocPeerDID.fromJson(
                """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "Ed25519VerificationKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyJwk": "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
                           }
                       ]
                   }
            """
            )
        }
    }

    @Test
    fun testDidDocInvalidJsonVerMethodInvalidValueJwk() {
        assertThrows<MalformedPeerDIDDOcException> {
            DIDDocPeerDID.fromJson(
                """
                   {
                       "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                       "authentication": [
                           {
                               "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "type": "JsonWebKey2020",
                               "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                               "publicKeyJwk": "sdfsdf{sfsdfdf"
                           }
                       ]
                   }
            """
            )
        }
    }

}