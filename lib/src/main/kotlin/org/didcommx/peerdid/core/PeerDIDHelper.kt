@file:JvmName("PeerDIDUtils")

package org.didcommx.peerdid.core

import com.google.gson.JsonSyntaxException
import io.ipfs.multibase.binary.Base64
import org.didcommx.peerdid.*

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
internal fun decodeService(encodedService: JSON, peerDID: PeerDID): List<Map<String, Any>>? {
    if (encodedService.isEmpty())
        return null
    val decodedService = Base64.decodeBase64(encodedService).decodeToString()

    val serviceMapList = try {
        fromJsonToList(decodedService)
    } catch (e: JsonSyntaxException) {
        try {
            listOf(fromJsonToMap(decodedService))
        } catch (e: JsonSyntaxException) {
            throw IllegalArgumentException("Invalid JSON $decodedService")
        }
    }

    return serviceMapList.mapIndexed { serviceNumber, serviceMap ->
        if (!serviceMap.containsKey(ServicePrefix.getValue(SERVICE_TYPE)))
            throw IllegalArgumentException("service doesn't contain a type")

        val serviceType = serviceMap.getValue(ServicePrefix.getValue(SERVICE_TYPE)).toString()
            .replace(ServicePrefix.getValue(SERVICE_DIDCOMM_MESSAGING), SERVICE_DIDCOMM_MESSAGING)
        val service = mutableMapOf<String, Any>(
            "id" to "$peerDID#${serviceType.lowercase()}-$serviceNumber",
            "type" to serviceType
        )
        serviceMap[ServicePrefix.getValue(SERVICE_ENDPOINT)]?.let { service.put(SERVICE_ENDPOINT, it) }
        serviceMap[ServicePrefix.getValue(SERVICE_ROUTING_KEYS)]?.let { service.put(SERVICE_ROUTING_KEYS, it) }
        serviceMap[ServicePrefix.getValue(SERVICE_ACCEPT)]?.let { service.put(SERVICE_ACCEPT, it) }

        service
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
internal fun createMultibaseEncnumbasis(key: VerificationMaterial<out VerificationMethodType>): String {
    val decodedKey = when (key.format) {
        VerificationMaterialFormatPeerDID.BASE58 -> fromBase58(key.value.toString())
        VerificationMaterialFormatPeerDID.MULTIBASE -> fromBase58Multibase(key.value.toString()).second
        VerificationMaterialFormatPeerDID.JWK -> fromJwk(key)
    }
    validateRawKeyLength(decodedKey)
    return toBase58Multibase(toMulticodec(decodedKey, key.type))
}

internal data class DecodedEncumbasis(
    val encnumbasis: String,
    val verMaterial: VerificationMaterial<out VerificationMethodType>
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
                    value = toBase58Multibase(decodedEncnumbasisWithoutPrefix)
                )
                Codec.ED25519 -> VerificationMaterialAuthentication(
                    format = format,
                    type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
                    value = toBase58Multibase(decodedEncnumbasisWithoutPrefix)
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

internal fun getVerificationMethod(did: String, decodedEncumbasis: DecodedEncumbasis) =
    VerificationMethodPeerDID(
        id = "${did}#${decodedEncumbasis.encnumbasis}",
        controller = did,
        verMaterial = decodedEncumbasis.verMaterial
    )
