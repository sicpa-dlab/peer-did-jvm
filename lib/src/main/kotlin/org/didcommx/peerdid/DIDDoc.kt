package org.didcommx.peerdid

import com.google.gson.GsonBuilder
import com.google.gson.JsonDeserializer
import org.didcommx.peerdid.core.didDocFromJson

data class DIDDocPeerDID(
    val did: String,
    val authentication: List<VerificationMethodPeerDID>,
    val keyAgreement: List<VerificationMethodPeerDID> = emptyList(),
    val service: List<Service>? = null
) {

    companion object {

        /**
         * Creates a new instance of DIDDocPeerDID from the given DID Doc JSON.
         *
         * @param value DID Doc JSON
         * @throws MalformedPeerDIDDOcException if the input DID Doc JSON is not a valid peerdid DID Doc
         * @return [DIDDocPeerDID] instance
         */
        fun fromJson(value: JSON): DIDDocPeerDID {
            val deserializer =
                JsonDeserializer { json, typeOfT, context ->
                    val jsonObject = json?.asJsonObject
                        ?: throw IllegalArgumentException("Invalid JSON")
                    didDocFromJson(jsonObject)
                }

            try {
                return GsonBuilder()
                    .registerTypeAdapter(DIDDocPeerDID::class.java, deserializer)
                    .create()
                    .fromJson(value, DIDDocPeerDID::class.java)
            } catch (e: Exception) {
                throw MalformedPeerDIDDOcException(e)
            }
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
            res["service"] = service.map {
                when (it) {
                    is OtherService -> it.data
                    is DIDCommServicePeerDID -> it.toDict()
                }
            }
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

    fun toDict() = mapOf(
        "id" to id,
        "type" to verMaterial.type.value,
        "controller" to controller,
        publicKeyField().value to verMaterial.value,
    )
}

sealed interface Service

data class OtherService(val data: Map<String, Any>) : Service

data class DIDCommServicePeerDID(
    val id: String,
    val type: String,
    val serviceEndpoint: String?,
    val routingKeys: List<String>?,
    val accept: List<String>?
) : Service {

    fun toDict(): MutableMap<String, Any> {
        val res = mutableMapOf<String, Any>(
            SERVICE_ID to id,
            SERVICE_TYPE to type,
        )
        serviceEndpoint?.let { res[SERVICE_ENDPOINT] = it }
        routingKeys?.let { res[SERVICE_ROUTING_KEYS] = it }
        accept?.let { res[SERVICE_ACCEPT] = it }
        return res
    }
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
