@file:JvmName("PeerDIDUtils")

package org.didcommx.peerdid.core

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonSyntaxException
import io.ipfs.multibase.binary.Base64
import org.didcommx.peerdid.JSON
import org.didcommx.peerdid.OtherService
import org.didcommx.peerdid.PeerDID
import org.didcommx.peerdid.SERVICE_ACCEPT
import org.didcommx.peerdid.SERVICE_DIDCOMM_MESSAGING
import org.didcommx.peerdid.SERVICE_ENDPOINT
import org.didcommx.peerdid.SERVICE_ROUTING_KEYS
import org.didcommx.peerdid.SERVICE_TYPE
import org.didcommx.peerdid.SERVICE_URI
import org.didcommx.peerdid.Service
import org.didcommx.peerdid.VerificationMaterialAgreement
import org.didcommx.peerdid.VerificationMaterialAuthentication
import org.didcommx.peerdid.VerificationMaterialFormatPeerDID
import org.didcommx.peerdid.VerificationMaterialPeerDID
import org.didcommx.peerdid.VerificationMethodPeerDID
import org.didcommx.peerdid.VerificationMethodTypeAgreement
import org.didcommx.peerdid.VerificationMethodTypeAuthentication
import org.didcommx.peerdid.VerificationMethodTypePeerDID
internal enum class Numalgo2Prefix(val prefix: Char) {
    AUTHENTICATION('V'),
    KEY_AGREEMENT('E'),
    SERVICE('S');
}

private val ServicePrefix = mapOf(
    SERVICE_TYPE to "t",
    SERVICE_ENDPOINT to "s",
    SERVICE_DIDCOMM_MESSAGING to "dm",
    SERVICE_ROUTING_KEYS to "r",
    SERVICE_ACCEPT to "a",
    SERVICE_URI to "uri",
)

/**
 * Encodes [service] according to the second algorithm.
 * For this type of algorithm DIDDoc can be obtained from PeerDID
 * @see <a href="https://identity.foundation/peer-did-method-spec/index.html#generation-method">Specification</a>
 * @param [service] service to encode
 * @return encoded [service]
 */
internal fun encodeService(service: JSON): String {
    validateJson(service)
    val trimmedService = service.trim()
    val gson = Gson()
    return when {
        trimmedService.startsWith("[") -> {
            /**
             * Process each service object individually if 'serviceEndpoint' is a JsonObject
             * @see section To encode a service: https://identity.foundation/peer-did-method-spec/#method-2-multiple-inception-key-without-doc
             */
            val jsonArray = Gson().fromJson(trimmedService, JsonArray::class.java)
            val firstElement = jsonArray.firstOrNull() as? JsonObject
            val isServiceEndpointObject = firstElement?.get("serviceEndpoint") is JsonObject

            if (isServiceEndpointObject) { // New Peer Did Spec
                jsonArray.joinToString(separator = "") { jsonElement ->
                    encodeIndividualService(jsonElement.toString())
                }
            } else {
                // Old approach combine service encoded
                encodeIndividualService(trimmedService)
            }
        }
        trimmedService.startsWith("{") -> {
            encodeIndividualService(trimmedService)
        }
        else -> throw IllegalArgumentException("Invalid JSON format")
    }
}

fun encodeIndividualService(service: JSON): String {
    val serviceToEncode = service.replace(Regex("[\n\t\\s]*"), "")
        .replace(SERVICE_TYPE, ServicePrefix.getValue(SERVICE_TYPE))
        .replace(SERVICE_ENDPOINT, ServicePrefix.getValue(SERVICE_ENDPOINT))
        .replace(SERVICE_DIDCOMM_MESSAGING, ServicePrefix.getValue(SERVICE_DIDCOMM_MESSAGING))
        .replace(SERVICE_ROUTING_KEYS, ServicePrefix.getValue(SERVICE_ROUTING_KEYS))
        .replace(SERVICE_ACCEPT, ServicePrefix.getValue(SERVICE_ACCEPT))

    val encodedService = Base64.encodeBase64URLSafe(serviceToEncode.toByteArray()).decodeToString()
    return ".${Numalgo2Prefix.SERVICE.prefix}$encodedService"
}

/**
 * Decodes [encodedService] according to PeerDID spec
 * @see
 * <a href="https://identity.foundation/peer-did-method-spec/index.html#example-2-abnf-for-peer-dids">Specification</a>
 * @param [encodedService] service to decode
 * @param [peerDID] PeerDID which will be used as an ID
 * @throws IllegalArgumentException if service is not correctly decoded
 * @return decoded service
 */
internal fun decodeService(encodedServices: List<JSON>, peerDID: PeerDID): List<Service>? {

    if (encodedServices.isEmpty())
        return null

    val decodedServices = encodedServices.map { encodedService ->
        Base64.decodeBase64(encodedService).decodeToString()
    }

    val decodedServicesJson = if (decodedServices.size == 1) {
        decodedServices[0]
    } else {
        decodedServices.joinToString(separator = ",", prefix = "[", postfix = "]")
    }

    val serviceMapList = try {
        fromJsonToList(decodedServicesJson)
    } catch (e: JsonSyntaxException) {
        try {
            listOf(fromJsonToMap(decodedServicesJson))
        } catch (e: JsonSyntaxException) {
            throw IllegalArgumentException("Invalid JSON $decodedServices")
        }
    }

    return serviceMapList.mapIndexed { serviceNumber, serviceMap ->
        if (!serviceMap.containsKey(ServicePrefix.getValue(SERVICE_TYPE)))
            throw IllegalArgumentException("service doesn't contain a type")

        val serviceType = serviceMap.getValue(ServicePrefix.getValue(SERVICE_TYPE)).toString()
            .replace(ServicePrefix.getValue(SERVICE_DIDCOMM_MESSAGING), SERVICE_DIDCOMM_MESSAGING)
        val serviceId = if (serviceMapList.size > 1) {
            if (serviceNumber == 0) "#service" else "#service-$serviceNumber"
        } else "#service"

        val serviceEndpointMap = mutableMapOf<String, Any>()
        when (val serviceEndpointValue = serviceMap[ServicePrefix.getValue(SERVICE_ENDPOINT)]) {
            is String -> {
                serviceMap[ServicePrefix.getValue(SERVICE_ENDPOINT)]?.let { serviceEndpointMap.put(SERVICE_URI, it) }
                serviceMap[ServicePrefix.getValue(SERVICE_ROUTING_KEYS)]?.let { serviceEndpointMap.put(SERVICE_ROUTING_KEYS, it) }
                serviceMap[ServicePrefix.getValue(SERVICE_ACCEPT)]?.let { serviceEndpointMap.put(SERVICE_ACCEPT, it) }
            }
            is Map<*, *> -> {
                serviceEndpointValue[ServicePrefix.getValue(SERVICE_URI)]?.let { serviceEndpointMap.put(SERVICE_URI, it) }
                serviceEndpointValue[ServicePrefix.getValue(SERVICE_ROUTING_KEYS)]?.let { serviceEndpointMap.put(SERVICE_ROUTING_KEYS, it) }
                serviceEndpointValue[ServicePrefix.getValue(SERVICE_ACCEPT)]?.let { serviceEndpointMap.put(SERVICE_ACCEPT, it) }
            }
            else -> {
                throw IllegalArgumentException("Service doesn't contain a valid Endpoint")
            }
        }
        val service = mutableMapOf<String, Any>(
            "id" to serviceId,
            "type" to serviceType,
            "serviceEndpoint" to serviceEndpointMap
        )
        OtherService(service)
    }.toList()
}

/**
 * Creates multibased encnumbasis according to PeerDID spec
 * @see
 * <a href="https://identity.foundation/peer-did-method-spec/index.html#method-specific-identifier">Specification</a>
 * @param [key] public key
 * @throws IllegalArgumentException if key is invalid
 * @return transform+encnumbasis
 */
internal fun createMultibaseEncnumbasis(key: VerificationMaterialPeerDID<out VerificationMethodTypePeerDID>): String {
    val decodedKey = when (key.format) {
        VerificationMaterialFormatPeerDID.BASE58 -> fromBase58(key.value.toString())
        VerificationMaterialFormatPeerDID.MULTIBASE -> fromMulticodec(fromBase58Multibase(key.value.toString()).second).second
        VerificationMaterialFormatPeerDID.JWK -> fromJwk(key)
    }
    validateRawKeyLength(decodedKey)
    return toBase58Multibase(toMulticodec(decodedKey, key.type))
}

internal data class DecodedEncumbasis(
    val encnumbasis: String,
    val verMaterial: VerificationMaterialPeerDID<out VerificationMethodTypePeerDID>
)

/**
 * Decodes multibased encnumbasis to a verification material for DID DOC
 * @param [multibase] transform+encnumbasis to decode
 * @param [format] the format of public keys in the DID DOC
 * @throws IllegalArgumentException if key is invalid
 * @return decoded encnumbasis as verification material for DID DOC
 */
internal fun decodeMultibaseEncnumbasis(
    multibase: String,
    format: VerificationMaterialFormatPeerDID
): DecodedEncumbasis {
    val (encnumbasis, decodedEncnumbasis) = fromBase58Multibase(multibase)
    val (codec, decodedEncnumbasisWithoutPrefix) = fromMulticodec(decodedEncnumbasis)
    validateRawKeyLength(decodedEncnumbasisWithoutPrefix)

    val verMaterial = when (format) {
        VerificationMaterialFormatPeerDID.BASE58 ->
            when (codec) {
                Codec.X25519 -> VerificationMaterialAgreement(
                    format = format,
                    type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                    value = toBase58(decodedEncnumbasisWithoutPrefix)
                )
                Codec.ED25519 -> VerificationMaterialAuthentication(
                    format = format,
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                    value = toBase58(decodedEncnumbasisWithoutPrefix)
                )
            }
        VerificationMaterialFormatPeerDID.MULTIBASE ->
            when (codec) {
                Codec.X25519 -> VerificationMaterialAgreement(
                    format = format,
                    type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
                    value = toBase58Multibase(
                        toMulticodec(
                            decodedEncnumbasisWithoutPrefix,
                            VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020
                        )
                    )
                )
                Codec.ED25519 -> VerificationMaterialAuthentication(
                    format = format,
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    value = toBase58Multibase(
                        toMulticodec(
                            decodedEncnumbasisWithoutPrefix,
                            VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020
                        )
                    )
                )
            }
        VerificationMaterialFormatPeerDID.JWK ->
            when (codec) {
                Codec.X25519 -> VerificationMaterialAgreement(
                    format = format,
                    type = VerificationMethodTypeAgreement.JSON_WEB_KEY_2020,
                    value = toJwk(decodedEncnumbasisWithoutPrefix, VerificationMethodTypeAgreement.JSON_WEB_KEY_2020)
                )
                Codec.ED25519 -> VerificationMaterialAuthentication(
                    format = format,
                    type = VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020,
                    value = toJwk(
                        decodedEncnumbasisWithoutPrefix,
                        VerificationMethodTypeAuthentication.JSON_WEB_KEY_2020
                    )
                )
            }
    }

    return DecodedEncumbasis(encnumbasis, verMaterial)
}

internal fun getVerificationMethod(keyId: Int, did: String, decodedEncumbasis: DecodedEncumbasis) =
    VerificationMethodPeerDID(
        id = "$did#key-$keyId",
        controller = did,
        verMaterial = decodedEncumbasis.verMaterial
    )
