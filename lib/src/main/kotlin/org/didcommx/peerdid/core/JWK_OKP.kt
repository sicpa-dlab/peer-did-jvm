package org.didcommx.peerdid.core

import io.ipfs.multibase.binary.Base64
import org.didcommx.peerdid.VerificationMaterialPeerDID
import org.didcommx.peerdid.VerificationMethodTypeAgreement
import org.didcommx.peerdid.VerificationMethodTypeAuthentication
import org.didcommx.peerdid.VerificationMethodTypePeerDID

fun toJwk(publicKey: ByteArray, verMethodType: VerificationMethodTypePeerDID): Map<String, String> {
    val x = Base64.encodeBase64URLSafe(publicKey).decodeToString()
    val crv = when (verMethodType) {
        VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020 -> "Ed25519"
        VerificationMethodTypeAgreement.JSON_WEB_KEY_2020 -> "X25519"
        else -> throw IllegalArgumentException("Unsupported JWK type ${verMethodType.value}")
    }
    return mapOf(
        "kty" to "OKP",
        "crv" to crv,
        "x" to x,
    )
}

fun fromJwk(verMaterial: VerificationMaterialPeerDID<out VerificationMethodTypePeerDID>): ByteArray {
    val jwkDict = if (verMaterial.value is Map<*, *>) verMaterial.value else fromJsonToMap(verMaterial.value.toString())

    if (!jwkDict.containsKey("crv"))
        throw IllegalArgumentException("Invalid JWK key - no 'crv' fields: ${verMaterial.value}")
    if (!jwkDict.containsKey("x"))
        throw IllegalArgumentException("Invalid JWK key - no 'x' fields: ${verMaterial.value}")

    val crv = jwkDict["crv"]
    if (verMaterial.type is VerificationMethodTypeAuthentication && crv != "Ed25519")
        throw IllegalArgumentException("Invalid JWK key type - authentication expected: ${verMaterial.value}")
    if (verMaterial.type is VerificationMethodTypeAgreement && crv != "X25519")
        throw IllegalArgumentException("Invalid JWK key type - key agreement expected: ${verMaterial.value}")

    val value = jwkDict["x"].toString()
    return Base64.decodeBase64(value)
}
