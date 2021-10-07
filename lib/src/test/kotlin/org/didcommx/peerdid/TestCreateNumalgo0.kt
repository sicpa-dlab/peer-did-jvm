package org.didcommx.peerdid

import org.didcommx.peerdid.core.toJson
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TestCreateNumalgo0 {

    companion object {

        @JvmStatic
        fun validKeys(): Stream<VerificationMaterialAuthentication> {
            return Stream.of(
                VerificationMaterialAuthentication(
                    value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                    format = VerificationMaterialFormatPeerDID.BASE58,
                ),
                VerificationMaterialAuthentication(
                    value = "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.MULTIBASE,
                ),
                VerificationMaterialAuthentication(
                    value = mapOf(
                        "kty" to "OKP",
                        "crv" to "Ed25519",
                        "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                    ),
                    type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.JWK,
                ),
                VerificationMaterialAuthentication(
                    value = toJson(
                        mapOf(
                            "kty" to "OKP",
                            "crv" to "Ed25519",
                            "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                        )
                    ),
                    type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.JWK,
                )
            )
        }

        @JvmStatic
        fun notBase58Keys(): Stream<VerificationMaterialAuthentication> {
            return Stream.of(
                VerificationMaterialAuthentication(
                    value = "x8xB2pv7cw8q1Pd0DacS",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                    format = VerificationMaterialFormatPeerDID.BASE58,
                ),
                VerificationMaterialAuthentication(
                    value = "zx8xB2pv7cw8q1Pd0DacS",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.MULTIBASE,
                ),
            )
        }

        @JvmStatic
        fun shortKeys(): Stream<VerificationMaterialAuthentication> {
            return Stream.of(
                VerificationMaterialAuthentication(
                    value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                    format = VerificationMaterialFormatPeerDID.BASE58,
                ),
                VerificationMaterialAuthentication(
                    value = "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.MULTIBASE,
                ),
                VerificationMaterialAuthentication(
                    value = mapOf(
                        "kty" to "OKP",
                        "crv" to "Ed25519",
                        "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_Ygm",
                    ),
                    type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.JWK,
                ),
                VerificationMaterialAuthentication(
                    value = toJson(
                        mapOf(
                            "kty" to "OKP",
                            "crv" to "Ed25519",
                            "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_Ygm",
                        )
                    ),
                    type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.JWK,
                )
            )
        }

        @JvmStatic
        fun longKeys(): Stream<VerificationMaterialAuthentication> {
            return Stream.of(
                VerificationMaterialAuthentication(
                    value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L77",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                    format = VerificationMaterialFormatPeerDID.BASE58,
                ),
                VerificationMaterialAuthentication(
                    value = "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L77",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.MULTIBASE,
                ),
                VerificationMaterialAuthentication(
                    value = mapOf(
                        "kty" to "OKP",
                        "crv" to "Ed25519",
                        "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA7",
                    ),
                    type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.JWK,
                ),
                VerificationMaterialAuthentication(
                    value = toJson(
                        mapOf(
                            "kty" to "OKP",
                            "crv" to "Ed25519",
                            "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA7",
                        )
                    ),
                    type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.JWK,
                )
            )
        }

        @JvmStatic
        fun emptyKeys(): Stream<VerificationMaterialAuthentication> {
            return Stream.of(
                VerificationMaterialAuthentication(
                    value = "",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                    format = VerificationMaterialFormatPeerDID.BASE58,
                ),
                VerificationMaterialAuthentication(
                    value = "",
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.MULTIBASE,
                ),
                VerificationMaterialAuthentication(
                    value = mapOf(
                        "kty" to "OKP",
                        "crv" to "Ed25519",
                        "x" to "",
                    ),
                    type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.JWK,
                ),
                VerificationMaterialAuthentication(
                    value = toJson(
                        mapOf(
                            "kty" to "OKP",
                            "crv" to "Ed25519",
                            "x" to "",
                        )
                    ),
                    type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    format = VerificationMaterialFormatPeerDID.JWK,
                )
            )
        }
    }

    @ParameterizedTest
    @MethodSource("validKeys")
    fun testCreateNumalgo0Positive(key: VerificationMaterialAuthentication) {
        val peerDIDAlgo0 = createPeerDIDNumalgo0(key)
        assertEquals(
            "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            peerDIDAlgo0
        )
        assert(isPeerDID(peerDIDAlgo0))
    }

    @ParameterizedTest
    @MethodSource("notBase58Keys")
    fun testCreateNumalgo0MalformedInceptionKeyNotBase58Encoded(key: VerificationMaterialAuthentication) {
        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo0(key)
        }
        assertTrue(ex.message!!.matches(Regex("Invalid base58 encoding.*")))
    }

    @ParameterizedTest
    @MethodSource("shortKeys")
    fun testCreateNumalgo0MalformedShortInceptionKey(key: VerificationMaterialAuthentication) {
        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo0(key)
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key.*")))
    }

    @ParameterizedTest
    @MethodSource("longKeys")
    fun testCreateNumalgo0MalformedLongInceptionKey(key: VerificationMaterialAuthentication) {
        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo0(key)
        }
        assertTrue(ex.message!!.matches(Regex("Invalid key.*")))
    }

    @ParameterizedTest
    @MethodSource("emptyKeys")
    fun testCreateNumalgo0MalformedEmptyInceptionKey(key: VerificationMaterialAuthentication) {
        val ex = assertThrows<IllegalArgumentException> {
            createPeerDIDNumalgo0(key)
        }
        val expectedError = when (key.format) {
            VerificationMaterialFormatPeerDID.BASE58 -> "Invalid base58 encoding.*"
            VerificationMaterialFormatPeerDID.MULTIBASE -> "No transform part in multibase encoding.*"
            VerificationMaterialFormatPeerDID.JWK -> "Invalid key.*"
        }
        assertTrue(ex.message!!.matches(Regex(expectedError)))
    }
}
