package org.didcommx.peerdid

import com.google.gson.GsonBuilder


data class DIDDocPeerDID(
    val did: String,
    val authentication: List<VerificationMethodPeerDID>,
    val keyAgreement: List<VerificationMethodPeerDID> = emptyList(),
    val service: List<Map<String, Any>>? = null
) {

    companion object {

        fun fromJson() {

        }
    }

    fun authKids() = authentication.map { it.id }

    fun agreemenrtKids() = keyAgreement.map { it.id }

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

    fun toJson() =
        GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(toDict())


}

data class VerificationMethodPeerDID(
    val id: String,
    val controller: String,
    val verMaterial: VerificationMaterial<out VerificationMethodType>
) {

    private fun publicKeyField() =
        when (verMaterial.format) {
            VerificationMaterialFormatPeerDID.BASE58 -> PublicKeyField.BASE58
            VerificationMaterialFormatPeerDID.JWK -> PublicKeyField.JWK
            VerificationMaterialFormatPeerDID.MULTIBASE -> PublicKeyField.MULTIBASE
        }

//    private fun publicKeyField() =
//        if (verMaterial.format == VerificationMaterialFormatPeerDID.JWK)
//

    fun toDict() = mapOf(
        "id" to id,
        "type" to verMaterial.type.value,
        "controller" to controller,
        publicKeyField().value to verMaterial.value,
    )
}

enum class PublicKeyField(val value: String) {
    BASE58("publicKeyBase58"),
    MULTIBASE("publicKeyMultibase"),
    JWK("publicKeyJwk");
}

const val SERVICE_ID = "id"
const val SERVICE_TYPE = "type"
const val SERVICE_ENDPOINT = "serviceEndpoint"
const val SERVICE_DIDCOMM_MESSAGING = "DIDCommMessaging"
const val SERVICE_ROUTING_KEYS = "routingKeys"
const val SERVICE_ACCEPT = "accept"
