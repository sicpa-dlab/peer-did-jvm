package org.didcommx.peerdid.core

import com.google.gson.JsonObject
import org.didcommx.peerdid.DIDCommServicePeerDID
import org.didcommx.peerdid.DIDDocPeerDID
import org.didcommx.peerdid.OtherService
import org.didcommx.peerdid.PublicKeyField
import org.didcommx.peerdid.SERVICE_DIDCOMM_MESSAGING
import org.didcommx.peerdid.SERVICE_ENDPOINT
import org.didcommx.peerdid.SERVICE_ID
import org.didcommx.peerdid.SERVICE_TYPE
import org.didcommx.peerdid.Service
import org.didcommx.peerdid.ServiceEndpoint
import org.didcommx.peerdid.VerificationMaterialFormatPeerDID
import org.didcommx.peerdid.VerificationMaterialPeerDID
import org.didcommx.peerdid.VerificationMethodPeerDID
import org.didcommx.peerdid.VerificationMethodTypeAgreement
import org.didcommx.peerdid.VerificationMethodTypeAuthentication
import org.didcommx.peerdid.VerificationMethodTypePeerDID

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
        ?.map { serviceFromJson(it.asJsonObject) }
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

    val verMaterialType = getVerMethodType(jsonObject)
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
        verMaterial = VerificationMaterialPeerDID(
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

    val serviceEndpointObject = jsonObject.getAsJsonObject(SERVICE_ENDPOINT)
    val uri = serviceEndpointObject?.get("uri")?.asString ?: ""
    val routingKeys = serviceEndpointObject?.getAsJsonArray("routingKeys")?.map { it.asString } ?: emptyList()
    val accept = serviceEndpointObject?.getAsJsonArray("accept")?.map { it.asString } ?: emptyList()

    val serviceEndpoint = ServiceEndpoint(
        uri = uri,
        routingKeys = routingKeys,
        accept = accept
    )

    return DIDCommServicePeerDID(
        id = id,
        type = type,
        serviceEndpoint = serviceEndpoint
    )
}

private fun getVerMethodType(jsonObject: JsonObject): VerificationMethodTypePeerDID {
    val type = jsonObject.get("type")?.asString
        ?: throw IllegalArgumentException("No 'type' field in method ${jsonObject.asString}")
    return when (type) {
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
            throw IllegalArgumentException("Unknown verification method type $type")
    }
}
