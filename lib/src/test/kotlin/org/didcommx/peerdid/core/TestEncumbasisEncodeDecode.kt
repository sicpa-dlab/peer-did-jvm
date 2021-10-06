package org.didcommx.peerdid.core

import org.didcommx.peerdid.*
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals

internal data class DecodeEncumbasisTestData(
    val inputMultibase: String,
    val format: VerificationMaterialFormatPeerDID,
    val expected: VerificationMaterial<out VerificationMethodType>
)

internal class TestEncumbasisEncodeDecode {

    companion object {

        @JvmStatic
        fun decodeEncumbasisData(): Stream<DecodeEncumbasisTestData> {
            return Stream.of(
                DecodeEncumbasisTestData(
                    "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                    VerificationMaterialFormatPeerDID.BASE58,
                    VerificationMaterialAuthentication(
                        format = VerificationMaterialFormatPeerDID.BASE58,
                        type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                        value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                    )
                ),
                DecodeEncumbasisTestData(
                    "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                    VerificationMaterialFormatPeerDID.BASE58,
                    VerificationMaterialAgreement(
                        format = VerificationMaterialFormatPeerDID.BASE58,
                        type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                        value = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                    ),
                ),
                DecodeEncumbasisTestData(
                    "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                    VerificationMaterialFormatPeerDID.MULTIBASE,
                    VerificationMaterialAuthentication(
                        format = VerificationMaterialFormatPeerDID.MULTIBASE,
                        type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                        value = "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                    ),
                ),
                DecodeEncumbasisTestData(
                    "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                    VerificationMaterialFormatPeerDID.MULTIBASE,
                    VerificationMaterialAgreement(
                        format = VerificationMaterialFormatPeerDID.MULTIBASE,
                        type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                        value = "zJhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                    ),
                ),
                DecodeEncumbasisTestData(
                    "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                    VerificationMaterialFormatPeerDID.JWK,
                    VerificationMaterialAuthentication(
                        format = VerificationMaterialFormatPeerDID.JWK,
                        type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                        value = mapOf(
                            "kty" to "OKP",
                            "crv" to "Ed25519",
                            "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                        )
                    ),
                ),
                DecodeEncumbasisTestData(
                    "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                    VerificationMaterialFormatPeerDID.JWK,
                    VerificationMaterialAgreement(
                        format = VerificationMaterialFormatPeerDID.JWK,
                        type = VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
                        value = mapOf(
                            "kty" to "OKP",
                            "crv" to "X25519",
                            "x" to "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
                        ),
                    ),
                ),
            )
        }
    }

    @ParameterizedTest
    @MethodSource("decodeEncumbasisData")
    fun testDecodeEncumbasis(data: DecodeEncumbasisTestData) {
        assertEquals(
            data.expected,
            decodeMultibaseEncnumbasis(data.inputMultibase, data.format).verMaterial
        )
    }
}
