package org.dif.peerdid

import org.dif.peerdid.core.DIDDocVerMaterialFormat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class TestResolveNumalgo2 {

    @Test
    fun testResolvePositiveDefault() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_MULTIBASE), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveBase58() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2, DIDDocVerMaterialFormat.BASE58)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_BASE58), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveMultibase() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2, DIDDocVerMaterialFormat.MULTIBASE)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_MULTIBASE), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveJWK() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2, DIDDocVerMaterialFormat.JWK)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_JWK), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveServiceIs2ElementsArray() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2_2_SERVICES)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveNoService() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2_NO_SERVICES)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_MULTIBASE_NO_SERVICES), fromJson(realValue))
    }

    @Test
    fun testResolveUnsupportedNumalgoCode() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:1.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                    ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
    }

    @Test
    fun testResolveSigningMalformedBase58Encoding() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                    ".Vz6MkqRYqQi0gvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
    }

    @Test
    fun testResolveEncryptionMalformedBase58Encoding() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSpSrLxbAh02SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                    ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
    }

    @Test
    fun testResolveUnsupportedTransformCode() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:2.Ea6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                    ".Va6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
    }

    @Test
    fun testResolveMalformedSigningMulticodecEncoding() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                    ".Vz6666kqYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
    }

    @Test
    fun testResolveMalformedEncryptionMulticodecEncoding() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:2.Ez6666SrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                    ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
    }

    @Test
    fun testResolveInvalidVerificationKeyType() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:2.Vz6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                    ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
            )
        }
    }

    @Test
    fun testResolveInvalidEncryptionKeyType() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                    ".Ez6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
            )
        }
    }

    @Test
    fun testResolveMalformedServiceEncoding() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                    ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9\\\\GxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
            )
        }
    }

    @Test
    fun testResolveInvalidPrefix() {
        assertThrows<IllegalArgumentException> {
            resolvePeerDID(
                "did:peer:2" +
                    ".Cz6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                    ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                    ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" +
                    ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0="
            )
        }
    }
}
