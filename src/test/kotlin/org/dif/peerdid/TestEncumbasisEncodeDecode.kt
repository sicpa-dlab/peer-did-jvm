package org.dif.peerdid

import org.dif.peerdid.core.*
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals

data class DecodeEncumbasisTestData(
    val inputMultibase: String,
    val format: DIDDocVerMaterialFormat,
    val expected: VerificationMaterial
)


class TestEncumbasisEncodeDecode {

    companion object {

        @JvmStatic
        fun decodeEncumbasisData(): Stream<DecodeEncumbasisTestData> {
            return Stream.of(
                DecodeEncumbasisTestData(
                    "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                    DIDDocVerMaterialFormat.BASE58,
                    VerificationMaterial(
                        field = PublicKeyField.BASE58,
                        type = VerificationMaterialTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                        value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                        encnumbasis = "6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                    )
                ),
                DecodeEncumbasisTestData(
                    "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                    DIDDocVerMaterialFormat.BASE58,
                    VerificationMaterial(
                        field = PublicKeyField.BASE58,
                        type = VerificationMaterialTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                        value = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                        encnumbasis = "6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                    ),
                ),
                DecodeEncumbasisTestData(
                    "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                    DIDDocVerMaterialFormat.MULTIBASE,
                    VerificationMaterial(
                        field = PublicKeyField.MULTIBASE,
                        type = VerificationMaterialTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                        value = "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                        encnumbasis = "6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                    ),
                ),
                DecodeEncumbasisTestData(
                    "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                    DIDDocVerMaterialFormat.MULTIBASE,
                    VerificationMaterial(
                        field = PublicKeyField.MULTIBASE,
                        type = VerificationMaterialTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                        value = "zJhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                        encnumbasis = "6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                    ),
                ),
                DecodeEncumbasisTestData(
                    "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                    DIDDocVerMaterialFormat.JWK,
                    VerificationMaterial(
                        field = PublicKeyField.JWK,
                        type = VerificationMaterialTypeAuthentication.JSON_WEB_KEY_2020,
                        value = mapOf(
                            "kty" to "OKP",
                            "crv" to "Ed25519",
                            "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
                        ),
                        encnumbasis = "6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                    ),
                ),
                DecodeEncumbasisTestData(
                    "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                    DIDDocVerMaterialFormat.JWK,
                    VerificationMaterial(
                        field = PublicKeyField.JWK,
                        type = VerificationMaterialTypeAgreement.JSON_WEB_KEY_2020,
                        value = mapOf(
                            "kty" to "OKP",
                            "crv" to "X25519",
                            "x" to "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
                        ),
                        encnumbasis = "6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
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
            decodeMultibaseEncnumbasis(data.inputMultibase, data.format)
        )

    }
}