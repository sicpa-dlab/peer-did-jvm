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

internal fun buildDIDDocNumalgo0(peerDID: PeerDID): String {
    val inceptionKey = peerDID.substring(10)
    val encodingAlgorithm = peerDID[10]

    if (!isInEncodingTypes(encodingAlgorithm))
        throw IllegalArgumentException("Unsupported encoding algorithm of key: $encodingAlgorithm")

    val decodedEncnumbasis = decodeEncnumbasis(inceptionKey)
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
    for (key in keysWithoutPurposeCode) {
        val decodedEncnumbasis = decodeEncnumbasis(key)
        val DIDDocSection = mapOf(
            "id" to peerDID.plus('#').plus(key.drop(1)),
            "type" to decodedEncnumbasis.type.toString(),
            "controller" to peerDID,
            "publicKeyBase58" to decodedEncnumbasis.encodedValue
        )
        when (decodedEncnumbasis.type) {
            is PublicKeyTypeAuthentication -> authentication.add(DIDDocSection)
            is PublicKeyTypeAgreement -> keyAgreement.add(DIDDocSection)
        }
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

private fun isInEncodingTypes(encodingAlgorithm: Char): Boolean {
    return EncodingType.values().any { type -> type.type == encodingAlgorithm }
}

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
            "id" to peerDID.plus("#$serviceType").plus("#$serviceNumber"),
            "type" to serviceType,
            "serviceEndpoint" to serviceMap.remove("s").toString(),
            "routingKeys" to serviceMap.remove("r").toString()
        )
        serviceNumber++
        service
    }
}

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

private fun getEncodingTypeByChar(encodingChar: Char): EncodingType {
    when (encodingChar) {
        'z' -> return EncodingType.BASE58
        else -> throw IllegalArgumentException("Invalid encodingType: $encodingChar")
    }
}

private fun getCodec(data: ByteArray): PublicKeyType {
    val prefix = extractPrefix(data)
    PublicKeyTypeAgreement.values().forEach { type -> if (type.prefix() == prefix) return type }
    PublicKeyTypeAuthentication.values().forEach { type -> if (type.prefix() == prefix) return type }
    throw IllegalArgumentException("Prefix $prefix not supported")
}

private fun extractPrefix(data: ByteArray): Int {
    return VarInt.readVarint(ByteBuffer.wrap(data))
}

private fun removePrefix(data: ByteArray): List<Byte> {
    val prefixInt = extractPrefix(data)
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(prefixInt, byteBuffer)
    return data.drop(byteBuffer.array().size)
}

internal fun createEncnumbasis(key: PublicKey<out PublicKeyType>): String {
    val decodedKey = decodeKey(key)
    val prefixedDecodedKey = addPrefix(key.type, decodedKey)
    val encnumbasis = Multibase.encode(Multibase.Base.Base58BTC, prefixedDecodedKey)
    if (encnumbasis.length < 47 || encnumbasis.length > 48) {
        throw IllegalArgumentException("Invalid key: $key")
    }
    return encnumbasis
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

private fun addPrefix(keyType: PublicKeyType, decodedKey: ByteArray): ByteArray {
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(keyType.prefix(), byteBuffer)
    return byteBuffer.array().plus(decodedKey)
}

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

fun isJSONValid(jsonInString: String): Boolean {
    val gson = Gson()
    return try {
        if (!jsonInString.contains("{")) return false
        gson.fromJson(jsonInString, Any::class.java)
        true
    } catch (ex: JsonSyntaxException) {
        false
    }
}
