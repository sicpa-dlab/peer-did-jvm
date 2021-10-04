package org.didcommx.peerdid.core

import io.ipfs.multibase.binary.Base64

internal data class DIDDoc(
    val did: String,
    val authentication: List<VerificationMethod>,
    val keyAgreement: List<VerificationMethod> = emptyList(),
    val service: List<Map<String, Any>>? = null
) {
    fun toDict(): Map<String, Any> {
        val res = mutableMapOf(
            "id" to did,
            "authentication" to authentication.map { it.toDict() },
        )
        if (keyAgreement.isNotEmpty()) {
            res["keyAgreement"] = keyAgreement.map { it.toDict() }
        }
        service?.let {
            res["service"] = service
        }
        return res
    }
}

internal data class VerificationMethod(
    val verMaterial: VerificationMaterial,
    val did: String
) {
    fun toDict() = mapOf(
        "id" to did + "#" + verMaterial.encnumbasis,
        "type" to verMaterial.type.value,
        "controller" to did,
        verMaterial.field.value to verMaterial.value,
    )
}

internal data class VerificationMaterial(
    val field: PublicKeyField,
    val type: VerificationMaterialType,
    val value: Any,
    val encnumbasis: String
)

internal enum class PublicKeyField(val value: String) {
    BASE58("publicKeyBase58"),
    MULTIBASE("publicKeyMultibase"),
    JWK("publicKeyJwk");
}

internal sealed class VerificationMaterialType(val value: String)

internal sealed class VerificationMaterialTypeAgreement(value: String) : VerificationMaterialType(value) {
    object JSON_WEB_KEY_2020 : VerificationMaterialTypeAgreement("JsonWebKey2020")
    object X25519_KEY_AGREEMENT_KEY_2019 : VerificationMaterialTypeAgreement("X25519KeyAgreementKey2019")
    object X25519_KEY_AGREEMENT_KEY_2020 : VerificationMaterialTypeAgreement("X25519KeyAgreementKey2020")
}

internal sealed class VerificationMaterialTypeAuthentication(value: String) : VerificationMaterialType(value) {
    object JSON_WEB_KEY_2020 : VerificationMaterialTypeAuthentication("JsonWebKey2020")
    object ED25519_VERIFICATION_KEY_2018 : VerificationMaterialTypeAuthentication("Ed25519VerificationKey2018")
    object ED25519_VERIFICATION_KEY_2020 : VerificationMaterialTypeAuthentication("Ed25519VerificationKey2020")
}

internal class JWK_OKP(
    private val verMaterialType: VerificationMaterialType,
    private val value: ByteArray
) {
    fun toDict(): Map<String, Any> {
        val x = Base64.encodeBase64URLSafe(value).decodeToString()
        val crv = when (verMaterialType) {
            VerificationMaterialTypeAuthentication.JSON_WEB_KEY_2020 -> "Ed25519"
            VerificationMaterialTypeAgreement.JSON_WEB_KEY_2020 -> "X25519"
            else -> throw IllegalArgumentException("Unsupported JWK type ${verMaterialType.value}")
        }
        return mapOf(
            "kty" to "OKP",
            "crv" to crv,
            "x" to x,
        )
    }
}
