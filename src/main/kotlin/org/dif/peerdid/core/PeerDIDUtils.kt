@file:JvmName("PeerDIDUtils")

package org.dif.peerdid.core

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonSyntaxException
import com.google.gson.reflect.TypeToken
import com.zman.varint.VarInt
import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
import io.ipfs.multibase.binary.Base64
import java.nio.ByteBuffer

internal enum class Numalgo2Prefix(val prefix: Char) {
    AUTHENTICATION('V'),
    KEY_AGREEMENT('E'),
    SERVICE('S');
}

internal enum class MultibasePrefix(val prefix: Char) {
    BASE58('z');
}

internal enum class MulticodecPrefix(val prefix: Int) {
    X25519(0xEC),
    ED25519(0xED);

    fun toPublicKey() =
        when (this) {
            X25519 -> PublicKeyTypeAgreement.X25519
            ED25519 -> PublicKeyTypeAuthentication.ED25519
        }

    companion object {
        fun fromPrefix(prefix: Int) =
            values().find { it.prefix == prefix }
                ?: throw IllegalArgumentException("Prefix $prefix not supported")

        fun fromPublicKey(publicKey: PublicKeyType) =
            when (publicKey) {
                PublicKeyTypeAgreement.X25519 -> X25519
                PublicKeyTypeAuthentication.ED25519 -> ED25519
            }
    }
}

internal fun isInEncodingTypes(encodingAlgorithm: Char): Boolean {
    return EncodingType.values().any { type -> type.type == encodingAlgorithm }
}

/**
 * Checks [json] to be valid JSON
 * @param [json] JSON to check
 * @return true if [json] is valid, otherwise false
 */
internal fun isJSONValid(json: String): Boolean {
    val gson = Gson()
    return try {
        if (!json.contains("{")) return false
        gson.fromJson(json, Any::class.java)
        true
    } catch (ex: JsonSyntaxException) {
        false
    }
}

/**
 * Checks if [key] correctly encoded (base58)
 * @param [key] public key
 * @param [encodingType] encoding type of [key]
 * @return true if [key] correctly encoded, otherwise false
 */
internal fun checkKeyCorrectlyEncoded(key: String, encodingType: EncodingType): Boolean {
    if (encodingType != EncodingType.BASE58) {
        return false
    }
    val alphabet = Regex("[1-9a-km-zA-HJ-NP-Z]+")
    val byteLengths = listOf(32)
    return try {
        val b58len = Base58.decode(key).size
        alphabet.matches(key) && byteLengths.contains(b58len)
    } catch (ex: IllegalStateException) {
        false
    }
}

/**
 * Encodes [service] according to the second algorithm.
 * For this type of algorithm DIDDoc can be obtained from PeerDID
 * @see <a href="https://identity.foundation/peer-did-method-spec/index.html#generation-method">Specification</a>
 * @param [service] service to encode
 * @throws IllegalArgumentException if [service] is not JSON
 * @return encoded [service]
 */
internal fun encodeService(service: JSON): String {
    if (!isJSONValid(service)) throw IllegalArgumentException("Service is not JSON")

    val serviceToEncode = service.replace(Regex("[\n\t\\s]*"), "")
        .replace("type", "t")
        .replace("serviceEndpoint", "s")
        .replace("DIDCommMessaging", "dm")
        .replace("routingKeys", "r")
        .replace("accept", "a")

    val encodedService = Base64.encodeBase64URLSafe(serviceToEncode.toByteArray()).decodeToString()
    return ".${Numalgo2Prefix.SERVICE.prefix}$encodedService"
}

/**
 * Decodes [encodedService] according to PeerDID spec
 * @see
 * <a href="https://identity.foundation/peer-did-method-spec/index.html#example-2-abnf-for-peer-dids">Specification</a>
 * @param [encodedService] service to decode
 * @param [peerDID] PeerDID which will be used as an ID
 * @return decoded service
 */
internal fun decodeService(encodedService: JSON, peerDID: PeerDID): List<Map<String, Any>>? {
    if (encodedService.isEmpty())
        return null
    val decodedService = Base64.decodeBase64(encodedService).decodeToString()

    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
    val serviceMapList = try {
        gson.fromJson(decodedService, object : TypeToken<List<HashMap<String, Any>>>() {}.type)
    } catch (e: JsonSyntaxException) {
        listOf(gson.fromJson(decodedService, HashMap::class.java))
    }

    return serviceMapList.mapIndexed { serviceNumber, serviceMap ->
        val serviceType = serviceMap.remove("t").toString().replace("dm", "DIDCommMessaging")
        val service = mutableMapOf<String, Any>(
            "id" to "$peerDID#${serviceType.lowercase()}-$serviceNumber",
            "type" to serviceType
        )
        serviceMap.remove("s")?.let { service.put("serviceEndpoint", it) }
        serviceMap.remove("r")?.let { service.put("routingKeys", it) }
        serviceMap.remove("a")?.let { service.put("accept", it) }

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
internal fun createMultibaseEncnumbasis(key: PublicKey<out PublicKeyType>): String {
    val decodedKey = decodeKey(key)
    return toBase58Multibase(addPrefix(key.type, decodedKey))
}

/**
 * Decodes multibased encnumbasis to a verification material for DID DOC
 * @param [multibase] transform+encnumbasis to decode
 * @param [format] the format of public keys in the DID DOC
 * @throws IllegalArgumentException if key is invalid
 * @return decoded encnumbasis as verification material for DID DOC
 */
internal fun decodeMultibaseEncnumbasis(multibase: String, format: DIDDocVerMaterialFormat): VerificationMaterial {
    val transform = multibase[0]
    if (transform != MultibasePrefix.BASE58.prefix)
        throw IllegalArgumentException("Prefix $transform not supported")
    val encnumbasis = multibase.drop(1)
    val decodedEncnumbasis = Base58.decode(encnumbasis)
    val decodedEncnumbasisWithoutPrefix = removePrefix(decodedEncnumbasis)

    return when (format) {
        DIDDocVerMaterialFormat.BASE58 -> VerificationMaterial(
            field = PublicKeyField.BASE58,
            type = when (getPublicKeyType(decodedEncnumbasis)) {
                PublicKeyTypeAgreement.X25519 -> VerificationMaterialTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019
                PublicKeyTypeAuthentication.ED25519 -> VerificationMaterialTypeAuthentication.ED25519_VERIFICATION_KEY_2018
            },
            value = Base58.encode(decodedEncnumbasisWithoutPrefix.toByteArray()),
            encnumbasis = encnumbasis
        )
        DIDDocVerMaterialFormat.MULTIBASE -> VerificationMaterial(
            field = PublicKeyField.MULTIBASE,
            type = when (getPublicKeyType(decodedEncnumbasis)) {
                PublicKeyTypeAgreement.X25519 -> VerificationMaterialTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020
                PublicKeyTypeAuthentication.ED25519 -> VerificationMaterialTypeAuthentication.ED25519_VERIFICATION_KEY_2020
            },
            value = toBase58Multibase(decodedEncnumbasisWithoutPrefix.toByteArray()),
            encnumbasis = encnumbasis
        )
        DIDDocVerMaterialFormat.JWK -> {
            val verMaterialType = when (getPublicKeyType(decodedEncnumbasis)) {
                PublicKeyTypeAgreement.X25519 -> VerificationMaterialTypeAgreement.JSON_WEB_KEY_2020
                PublicKeyTypeAuthentication.ED25519 -> VerificationMaterialTypeAuthentication.JSON_WEB_KEY_2020
            }
            VerificationMaterial(
                field = PublicKeyField.JWK,
                type = verMaterialType,
                value = JWK_OKP(verMaterialType, decodedEncnumbasisWithoutPrefix.toByteArray()).toDict(),
                encnumbasis = encnumbasis
            )
        }
    }
}

private fun getPublicKeyType(data: ByteArray) =
    extractPrefix(data).toPublicKey()

private fun extractPrefix(data: ByteArray) =
    MulticodecPrefix.fromPrefix(VarInt.readVarint(ByteBuffer.wrap(data)))

private fun removePrefix(data: ByteArray): List<Byte> {
    val prefix = extractPrefix(data)
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(prefix.prefix, byteBuffer)
    return data.drop(byteBuffer.array().size)
}

private fun addPrefix(keyType: PublicKeyType, decodedKey: ByteArray): ByteArray {
    val prefix = MulticodecPrefix.fromPublicKey(keyType).prefix
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(prefix, byteBuffer)
    return byteBuffer.array().plus(decodedKey)
}

private fun decodeKey(key: PublicKey<out PublicKeyType>): ByteArray {
    try {
        when (key.encodingType) {
            EncodingType.BASE58 -> return Base58.decode(key.encodedValue)
        }
    } catch (e: IllegalStateException) {
        throw IllegalArgumentException("Key: $key is not correctly encoded", e)
    }
}

private fun toBase58Multibase(value: ByteArray): String {
    return Multibase.encode(Multibase.Base.Base58BTC, value)
}
