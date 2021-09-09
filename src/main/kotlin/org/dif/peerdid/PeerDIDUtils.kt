@file:JvmName("PeerDIDUtils")

package org.dif.peerdid

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonSyntaxException
import com.google.gson.internal.LinkedTreeMap
import com.zman.varint.VarInt
import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
import io.ipfs.multibase.binary.Base64
import org.dif.model.EncodingType
import org.dif.model.JSON
import org.dif.model.PeerDID
import org.dif.model.PublicKey
import org.dif.model.PublicKeyType
import org.dif.model.PublicKeyTypeAgreement
import org.dif.model.PublicKeyTypeAuthentication
import java.nio.ByteBuffer
import kotlin.collections.HashMap

/** Helper method to create DIDDoc according to numalgo 0
 * @param [peerDID] PeerDID to resolve
 * @throws IllegalArgumentException
 * - if PeerDID contains unsupported encoding algorithm of key
 * - if inception key type is invalid
 * @return DIDDoc
 */
internal fun buildDIDDocNumalgo0(peerDID: PeerDID): String {
    val inceptionKey = peerDID.substring(10)
    val encodingAlgorithm = peerDID[10]

    if (!isInEncodingTypes(encodingAlgorithm))
        throw IllegalArgumentException("Unsupported encoding algorithm of key: $encodingAlgorithm")

    val decodedEncnumbasis = decodeEncnumbasis(inceptionKey)

    if (decodedEncnumbasis.type !is PublicKeyTypeAuthentication)
        throw IllegalArgumentException("Invalid type of key $inceptionKey")
    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
    val authentication = mapOf(
        "id" to peerDID.plus("#${inceptionKey.drop(1)}"),
        "type" to decodedEncnumbasis.type.toString(),
        "controller" to peerDID,
        "publicKeyBase58" to decodedEncnumbasis.encodedValue
    )
    val diddoc = mapOf(
        "id" to peerDID,
        "authentication" to gson.toJsonTree(authentication)
    )

    return gson.toJson(diddoc)
}

/** Helper method to create DIDDoc according to numalgo 2
 * @param [peerDID] PeerDID to resolve
 * @throws IllegalArgumentException
 * - if PeerDID contains unsupported transform part
 * - if PeerDID contatins keys with invalid types:
 * @return DIDDoc
 */
internal fun buildDIDDocNumalgo2(peerDID: PeerDID): String {
    val keys = peerDID.drop(11)
    val keysList = keys.split(".")
    var service = ""
    val keysWithoutPurposeCode = mutableListOf<String>()
    for (key in keysList) {
        if (key[0] != 'S') {
            val transform = key[1]
            if (!isInEncodingTypes(transform))
                throw IllegalArgumentException("Unsupported transform part of PeerDID: $transform")

            keysWithoutPurposeCode.add(key.drop(1))
        } else service = key.drop(1)
    }
    val authentication = mutableListOf<Map<String, String>>()
    val keyAgreement = mutableListOf<Map<String, String>>()
    for (i in keysWithoutPurposeCode.indices) {
        val key = keysWithoutPurposeCode[i]
        val decodedEncnumbasis = decodeEncnumbasis(key)
        val DIDDocSection = mapOf(
            "id" to peerDID.plus('#').plus(key.drop(1)),
            "type" to decodedEncnumbasis.type.toString(),
            "controller" to peerDID,
            "publicKeyBase58" to decodedEncnumbasis.encodedValue
        )
        if (decodedEncnumbasis.type is PublicKeyTypeAuthentication && keysList[i][0] == 'V')
            authentication.add(DIDDocSection)
        else if (decodedEncnumbasis.type is PublicKeyTypeAgreement && keysList[i][0] == 'E')
            keyAgreement.add(DIDDocSection)
        else
            throw IllegalArgumentException("Invalid key type of: ${keysList[i]}")
    }
    val decodedService = decodeService(service, peerDID)

    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
    val diddoc = mapOf(
        "id" to peerDID,
        "authentication" to gson.toJsonTree(authentication),
        "keyAgreement" to gson.toJsonTree(keyAgreement),
        "service" to gson.toJsonTree(decodedService)
    )
    return gson.toJson(diddoc)
}

/**
 * Checks if [encodingAlgorithm] is supported
 * @param [encodingAlgorithm] encoding algorithm to check
 * @return true if supported, otherwise false
 */
private fun isInEncodingTypes(encodingAlgorithm: Char): Boolean {
    return EncodingType.values().any { type -> type.type == encodingAlgorithm }
}

/**
 * Decodes [encodedService] according to PeerDID spec
 * @see
 * <a href="https://identity.foundation/peer-did-method-spec/index.html#example-2-abnf-for-peer-dids">Specification</a>
 * @param [encodedService] service to decode
 * @param [peerDID] PeerDID which will be used as an ID
 * @return decoded service
 */
private fun decodeService(encodedService: JSON, peerDID: PeerDID): List<Map<String, String>> {
    val decodedService = Base64.decodeBase64(encodedService).decodeToString()
    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
    val serviceMapList = try {
        gson.fromJson(decodedService, List::class.java) as List<LinkedTreeMap<String, String>>
    } catch (e: JsonSyntaxException) {
        listOf(gson.fromJson(decodedService, HashMap::class.java))
    }
    var serviceNumber = 0
    return serviceMapList.map { serviceMap ->
        val serviceType = serviceMap.remove("t").toString().replace("dm", "didcommmessaging")
        val service = mapOf(
            "id" to peerDID.plus("#$serviceType").plus("-$serviceNumber"),
            "type" to serviceType,
            "serviceEndpoint" to serviceMap.remove("s").toString(),
            "routingKeys" to serviceMap.remove("r").toString()
        )
        serviceNumber++
        service
    }
}

/**
 * Decodes [encnumbasis]
 * @param [encnumbasis] encnumbasis to decode
 * @return decoded encnumbasis
 */
private fun decodeEncnumbasis(encnumbasis: String): PublicKey<PublicKeyType> {
    val encodingChar = encnumbasis[0]
    val encodedValue = encnumbasis.drop(1)
    val encodingType = getEncodingTypeByChar(encodingChar)
    val decodedEncnumbasis = Base58.decode(encodedValue)
    val codec = getCodec(decodedEncnumbasis)
    val decodedEncnumbasisWithoutPrefix = removePrefix(decodedEncnumbasis)
    val publicKey = Base58.encode(decodedEncnumbasisWithoutPrefix.toByteArray())
    return PublicKey(
        encodedValue = publicKey,
        type = codec,
        encodingType = encodingType,
    )
}

/** Gets encoding type by [encodingChar]
 * @throws IllegalArgumentException if [encodingChar] is not supported
 * @return encoding type
 */
private fun getEncodingTypeByChar(encodingChar: Char): EncodingType {
    when (encodingChar) {
        'z' -> return EncodingType.BASE58
        else -> throw IllegalArgumentException("Invalid encodingType: $encodingChar")
    }
}

/** Gets codec from [data]
 *  @param [data] prefixed data
 *  @throws IllegalArgumentException if prefix is not supported
 *  @return codec type
 */
private fun getCodec(data: ByteArray): PublicKeyType {
    val prefix = extractPrefix(data)
    return PublicKeyTypeAgreement.values().find { it.prefix() == prefix }
        ?: PublicKeyTypeAuthentication.values().find { it.prefix() == prefix }
        ?: throw IllegalArgumentException("Prefix $prefix not supported")
}

/** Extracts prefix from [data]
 *  @param [data] prefixed data
 *  @return prefix
 */
private fun extractPrefix(data: ByteArray): Int {
    return VarInt.readVarint(ByteBuffer.wrap(data))
}

/** Removes prefix from [data]
 *  @param [data] prefixed data
 *  @return [data] without prefix
 */
private fun removePrefix(data: ByteArray): List<Byte> {
    val prefixInt = extractPrefix(data)
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(prefixInt, byteBuffer)
    return data.drop(byteBuffer.array().size)
}

/**
 * Creates encnumbasis according to PeerDID spec
 * @see
 * <a href="https://identity.foundation/peer-did-method-spec/index.html#method-specific-identifier">Specification</a>
 * @param [key] public key
 * @throws IllegalArgumentException if key is invalid
 * @return encnumbasis
 */
internal fun createEncnumbasis(key: PublicKey<out PublicKeyType>): String {
    val decodedKey = decodeKey(key)
    val prefixedDecodedKey = addPrefix(key.type, decodedKey)
    val encnumbasis = Multibase.encode(Multibase.Base.Base58BTC, prefixedDecodedKey)
    if (encnumbasis.length < 47 || encnumbasis.length > 48) {
        throw IllegalArgumentException("Invalid key: $key")
    }
    return encnumbasis
}

/**
 * Decodes [key]
 * @param [key] public key
 * @throws IllegalArgumentException if [key] is not correctly encoded
 * @return decoded [key]
 */
private fun decodeKey(key: PublicKey<out PublicKeyType>): ByteArray {
    try {
        when (key.encodingType) {
            EncodingType.BASE58 -> return Base58.decode(key.encodedValue)
        }
    } catch (e: IllegalStateException) {
        throw IllegalArgumentException("Key: $key is not correctly encoded", e)
    }
}

/** Adds prefix to [decodedKey]
 *  @param [decodedKey] key to be prefixed
 *  @param [keyType] type of key
 *  @return [decodedKey] with prefix
 */
private fun addPrefix(keyType: PublicKeyType, decodedKey: ByteArray): ByteArray {
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(keyType.prefix(), byteBuffer)
    return byteBuffer.array().plus(decodedKey)
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
    val serviceToEncode = (
        service.replace(Regex("[\n\t\\s]*"), "")
            .replace("type", "t")
            .replace("serviceEndpoint", "s")
            .replace("didcommmessaging", "dm")
            .replace("routingKeys", "r")
        )
    return ".S" + Base64.encodeBase64(serviceToEncode.toByteArray()).decodeToString()
}

/**
 * Checks [json] to be valid JSON
 * @param [json] JSON to check
 * @return true if [json] is valid, otherwise false
 */
fun isJSONValid(json: String): Boolean {
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
 * Checks if [key] correctly encoded
 * @param [key] public key
 * @param [encodingType] encoding type of [key]
 * @return true if [key] correctly encoded, otherwise false
 */
internal fun checkKeyCorrectlyEncoded(key: String, encodingType: EncodingType): Boolean {
    if (encodingType != EncodingType.BASE58) {
        return false
    }
    val alphabet = Regex("[1-9a-km-zA-HJ-NP-Z]+")
    val byteLengths = mutableListOf(32)
    return try {
        val b58len = Base58.decode(key).size
        alphabet.matches(key) && byteLengths.contains(b58len)
    } catch (ex: IllegalStateException) {
        false
    }
}
