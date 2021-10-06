package org.didcommx.peerdid

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class TestResolveNumalgo0 {

    @Test
    fun testResolvePositiveDefault() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_0)
        assertEquals(fromJson(DID_DOC_NUMALGO_O_MULTIBASE), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveBase58() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_0, VerificationMaterialFormatPeerDID.BASE58)
        assertEquals(fromJson(DID_DOC_NUMALGO_O_BASE58), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveMultibase() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_0, VerificationMaterialFormatPeerDID.MULTIBASE)
        assertEquals(fromJson(DID_DOC_NUMALGO_O_MULTIBASE), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveJWK() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_0, VerificationMaterialFormatPeerDID.JWK)
        assertEquals(fromJson(DID_DOC_NUMALGO_O_JWK), fromJson(realValue))
    }

    @Test
    fun testResolveUnsupportedDIDMethod() {
        assertThrows<MalformedPeerDIDException> { resolvePeerDID("did:key:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveInvalidPeerDID() {
        assertThrows<MalformedPeerDIDException> { resolvePeerDID("did:peer:0z6MkqRYqQiSBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveUnsupportedNumalgoCode() {
        assertThrows<MalformedPeerDIDException> { resolvePeerDID("did:key:1z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveMalformedBase58Encoding() {
        assertThrows<MalformedPeerDIDException> { resolvePeerDID("did:peer:0z6MkqRYqQiSgvZQd0Bytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveUnsupportedTransformCode() {
        assertThrows<MalformedPeerDIDException> { resolvePeerDID("did:peer:0a6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveMalformedMulticodecEncoding() {
        assertThrows<MalformedPeerDIDException> { resolvePeerDID("did:peer:0z6666RYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveInvalidKeyType() {
        assertThrows<MalformedPeerDIDException> { resolvePeerDID("did:peer:0z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc") }
    }
}
