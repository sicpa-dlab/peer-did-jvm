package org.didcommx.peerdid

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TestResolveNumalgo2 {

    @Test
    fun testResolvePositiveDefault() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_MULTIBASE), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveBase58() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2, VerificationMaterialFormatPeerDID.BASE58)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_BASE58), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveMultibase() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2, VerificationMaterialFormatPeerDID.MULTIBASE)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_MULTIBASE), fromJson(realValue))
    }

    @Test
    fun testResolvePositiveJWK() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2, VerificationMaterialFormatPeerDID.JWK)
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
    fun testResolvePositiveMinimalService() {
        val realValue = resolvePeerDID(PEER_DID_NUMALGO_2_MINIMAL_SERVICES)
        assertEquals(fromJson(DID_DOC_NUMALGO_2_MULTIBASE_MINIMAL_SERVICES), fromJson(realValue))
    }

    @Test
    fun testResolveUnsupportedNumalgoCode() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:1.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }

    @Test
    fun testResolveSigningMalformedBase58Encoding() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                        ".Vz6MkqRYqQi0gvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }

    @Test
    fun testResolveEncryptionMalformedBase58Encoding() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSpSrLxbAh02SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }

    @Test
    fun testResolveUnsupportedTransformCode() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2.Ea6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                        ".Va6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }

    @Test
    fun testResolveMalformedSigningMulticodecEncoding() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                        ".Vz7MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Invalid key.*")))
    }

    @Test
    fun testResolveMalformedEncryptionMulticodecEncoding() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2.Ez6666SrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfV0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Invalid key.*")))
    }

    @Test
    fun testResolveInvalidVerificationKeyType() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2.Vz6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Invalid key.*")))
    }

    @Test
    fun testResolveInvalidEncryptionKeyType() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                        ".Ez6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Invalid key.*")))
    }

    @Test
    fun testResolveMalformedServiceEncoding() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9\\\\GxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXX0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }

    @Test
    fun testResolveMalformedService() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".SeyJ0IjoiZG0iLCJzIjo"
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Invalid service.*")))
    }

    @Test
    fun testResolveInvalidPrefix() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2" +
                        ".Cz6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" +
                        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0="
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }

    @Test
    fun testResolveShortSigningKey() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2" +
                        ".Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFp" +
                        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }

    @Test
    fun testResolveLongSigningKey() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2" +
                        ".Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V77777" +
                        ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" +
                        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }

    @Test
    fun testResolveShortEncryptionKey() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2" +
                        ".Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" +
                        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }

    @Test
    fun testResolveLongEncryptionKey() {
        val ex = assertThrows<MalformedPeerDIDException> {
            resolvePeerDID(
                "did:peer:2" +
                        ".Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCccccc" +
                        ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
                        ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" +
                        ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
            )
        }
        assertTrue(ex.message!!.matches(Regex("Invalid peer DID provided.*Does not match peer DID regexp.*")))
    }
}
