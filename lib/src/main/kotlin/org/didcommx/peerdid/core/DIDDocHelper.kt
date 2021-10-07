package org.didcommx.peerdid.core

import com.google.gson.JsonObject
import org.didcommx.peerdid.*

private val verTypeToField = mapOf(
    VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019 to PublicKeyField.BASE58,
    VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020 to PublicKeyField.MULTIBASE,
    VerificationMethodTypeAgreement.JSON_WEB_KEY_2020 to PublicKeyField.JWK,
    VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018 to PublicKeyField.BASE58,
    VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020 to PublicKeyField.MULTIBASE,
    VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020 to PublicKeyField.JWK,
)

private val verTypeToFormat = mapOf(
    VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019 to VerificationMaterialFormatPeerDID.BASE58,
    VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020 to VerificationMaterialFormatPeerDID.MULTIBASE,
    VerificationMethodTypeAgreement.JSON_WEB_KEY_2020 to VerificationMaterialFormatPeerDID.JWK,
    VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018 to VerificationMaterialFormatPeerDID.BASE58,
    VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020 to VerificationMaterialFormatPeerDID.MULTIBASE,
    VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020 to VerificationMaterialFormatPeerDID.JWK,
)

internal fun didDocFromJson(jsonObject: JsonObject): DIDDocPeerDID {
    val did = jsonObject.get("id")?.asString
        ?: throw IllegalArgumentException("No 'id' field")
    val authentication = jsonObject.get("authentication")
        ?.asJsonArray
        ?.map { verificationMethodFromJson(it.asJsonObject) }
        ?: emptyList()
    val keyAgreement = jsonObject.get("keyAgreement")
        ?.asJsonArray
        ?.map { verificationMethodFromJson(it.asJsonObject) }
        ?: emptyList()
    val service = jsonObject.get("service")
        ?.asJsonArray
        ?.map { serviceFromJson(it.asJsonObject)}
    return DIDDocPeerDID(
        did = did,
        authentication = authentication,
        keyAgreement = keyAgreement,
        service = service
    )
}

internal fun verificationMethodFromJson(jsonObject: JsonObject): VerificationMethodPeerDID {
    val id = jsonObject.get("id")?.asString
        ?: throw IllegalArgumentException("No 'id' field in method ${jsonObject.asString}")
    val controller = jsonObject.get("controller")?.asString
        ?: throw IllegalArgumentException("No 'controller' field in method ${jsonObject.asString}")
    val type = jsonObject.get("type")?.asString
        ?: throw IllegalArgumentException("No 'type' field in method ${jsonObject.asString}")

    val verMaterialType = verMaterialFromType(type, jsonObject)
    val field = verTypeToField.getValue(verMaterialType)
    val format = verTypeToFormat.getValue(verMaterialType)
    val value = if (verMaterialType is VerificationMethodTypeAgreement.JSON_WEB_KEY_2020 ||
        verMaterialType is VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020
    ) {
        val jwkJson = jsonObject.get(field.value)?.asJsonObject?.toString()
            ?: throw IllegalArgumentException("No 'field' field in method ${jsonObject.asString}")
        fromJsonToMap(jwkJson)
    } else {
        jsonObject.get(field.value)?.asString
            ?: throw IllegalArgumentException("No 'field' field in method ${jsonObject.asString}")

    }

    return VerificationMethodPeerDID(
        id = id, controller = controller,
        verMaterial = VerificationMaterial(
            format = format,
            type = verMaterialType,
            value = value
        )
    )
}

internal fun serviceFromJson(jsonObject: JsonObject): Service {
    val serviceMap = fromJsonToMap(jsonObject.toString())

    val id = jsonObject.get(SERVICE_ID)?.asString
        ?: throw IllegalArgumentException("No 'id' field in service ${jsonObject.asString}")
    val type = jsonObject.get(SERVICE_TYPE)?.asString
        ?: throw IllegalArgumentException("No 'type' field in service ${jsonObject.asString}")

    if (type != SERVICE_DIDCOMM_MESSAGING)
        return OtherService(serviceMap)

    val endpoint = jsonObject.get(SERVICE_ENDPOINT)?.asString
    val routingKeys = jsonObject.get(SERVICE_ROUTING_KEYS)?.asJsonArray?.map { it.asString }
    val accept = jsonObject.get(SERVICE_ACCEPT)?.asJsonArray?.map { it.asString }

    return DIDCommServicePeerDID(
        id = id,
        type = type,
        serviceEndpoint = endpoint,
        routingKeys = routingKeys,
        accept = accept
    )
}

private fun verMaterialFromType(type: String, jsonObject: JsonObject) =
    when (type) {
        VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019.value
        -> VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019

        VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020.value
        -> VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020

        VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018.value
        -> VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018

        VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020.value
        -> VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020

        VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020.value -> {
            val v = jsonObject.get(PublicKeyField.JWK.value)?.asJsonObject
                ?: throw IllegalArgumentException("No 'field' field in method ${jsonObject.asString}")
            val crv = v.get("crv")?.asString
                ?: throw IllegalArgumentException("No 'crv' field in method ${jsonObject.asString}")
            if (crv == "X25519") VerificationMethodTypeAgreement.JSON_WEB_KEY_2020 else VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020
        }

        else ->
            throw IllegalArgumentException("Unknown verification method type ${type}")
    }