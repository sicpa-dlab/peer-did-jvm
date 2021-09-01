@file:JvmName("PeerDIDUtils")

package org.dif.peerdid

import com.google.gson.GsonBuilder
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
import java.util.HashMap

internal fun buildDIDDocNumalgo0(peerDID: PeerDID): String {
    val inceptionKey = peerDID.substring(11)
    val encodingAlgorithm = peerDID[10]

    if (!isInEncodingTypes(encodingAlgorithm))
        throw IllegalArgumentException("Unsupported encoding algorithm of key: $encodingAlgorithm")

    val decodedEncnumbasis = decodeEncnumbasis(inceptionKey, peerDID)
    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
    val diddoc = mapOf(
        "id" to peerDID,
        "authentication" to gson.toJsonTree(decodedEncnumbasis)
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

            keysWithoutPurposeCode.add(key.drop(2))
        } else service = key.drop(1)
    }
    val decodedEncnumbasises = keysWithoutPurposeCode.map { key -> decodeEncnumbasis(key, peerDID) }
    val decodedService = decodeService(service, peerDID)

    val authentication = mutableListOf<Map<String, String>>()
    val keyAgreement = mutableListOf<Map<String, String>>()

    for (i in decodedEncnumbasises.indices) {
        if (PublicKeyTypeAuthentication.values().any { value -> value.name == decodedEncnumbasises[i]["type"] })
            authentication.add(decodedEncnumbasises[i])
        else if (PublicKeyTypeAgreement.values().any { value -> value.name == decodedEncnumbasises[i]["type"] })
            keyAgreement.add(decodedEncnumbasises[i])
        else
            throw IllegalArgumentException("Invalid key type of: ${keysList[i]}")
    }

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

private fun decodeService(encodedService: JSON, peerDID: PeerDID): Map<String, String> {
    val decodedService = Base64.decodeBase64(encodedService).decodeToString()
    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
    val serviceMap = gson.fromJson(decodedService, HashMap::class.java)
    val serviceType = serviceMap.remove("t").toString().replace("dm", "didcommmessaging")

    return mapOf(
        "id" to peerDID.plus('#').plus(serviceType),
        "type" to serviceType,
        "serviceEndpoint" to serviceMap.remove("s").toString(),
        "routingKeys" to serviceMap.remove("r").toString()
    )
}

private fun decodeEncnumbasis(encnumbasis: String, peerDID: PeerDID): Map<String, String> {
    val decodedEncnumbasis = Base58.decode(encnumbasis)
    val codec = getCodec(decodedEncnumbasis)
    val decodedEncnumbasisWithoutPrefix = removePrefix(decodedEncnumbasis)
    val publicKey = Base58.encode(decodedEncnumbasisWithoutPrefix.toByteArray())
    return mapOf(
        "id" to peerDID.plus('#').plus(encnumbasis),
        "type" to codec,
        "controller" to peerDID,
        "publicKeyBase58" to publicKey
    )
}

private fun getCodec(data: ByteArray): String {
    val prefix = extractPrefix(data)
    PublicKeyTypeAgreement.values().forEach { type -> if (type.prefix() == prefix) return type.name }
    PublicKeyTypeAuthentication.values().forEach { type -> if (type.prefix() == prefix) return type.name }
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
    val decodedKey = Base58.decode(key.encodedValue)
    val prefixedDecodedKey = addPrefix(key.type, decodedKey)
    val encnumbasis = Multibase.encode(Multibase.Base.Base58BTC, prefixedDecodedKey)
    if (encnumbasis.length < 47 || encnumbasis.length > 48) {
        throw IllegalArgumentException("Invalid key: $key")
    }
    return encnumbasis
}

private fun addPrefix(keyType: PublicKeyType, decodedKey: ByteArray): ByteArray {
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(keyType.prefix(), byteBuffer)
    return byteBuffer.array().plus(decodedKey)
}

internal fun encodeService(service: JSON): String {
    val serviceToEncode = (
        service.replace(Regex("[\n\t\\s]*"), "")
            .replace("type", "t")
            .replace("serviceEndpoint", "s")
            .replace("didcommmessaging", "dm")
            .replace("routingKeys", "r")
        )
    return ".S" + Base64.encodeBase64(serviceToEncode.toByteArray()).decodeToString()
}
