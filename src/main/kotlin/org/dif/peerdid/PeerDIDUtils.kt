@file:JvmName("PeerDIDUtils")

package org.dif.peerdid

import com.zman.varint.VarInt
import io.ipfs.multibase.Multibase
import org.dif.model.JSON
import org.dif.model.PublicKey
import org.dif.model.PublicKeyType
import java.nio.ByteBuffer
import java.util.Base64

fun isPeerDID(peerDID: String): Boolean {
    val regex =
        (
            "^did:peer:(([0](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))" +
                "|(2((.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))+(.(S)[0-9a-zA-Z=]*)?)))$"
            ).toRegex()
    return regex.matches(peerDID)
}

internal fun createEncnumbasis(key: PublicKey<out PublicKeyType>): String {
    val decodedKey = Multibase.decode(key.encodedValue)
    val prefixedDecodedKey = addPrefix(key.type, decodedKey)
    val encnumbasis = Multibase.encode(Multibase.Base.Base58BTC, prefixedDecodedKey)
    return encnumbasis
}

private fun addPrefix(keyType: PublicKeyType, decodedKey: ByteArray): ByteArray {
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(keyType.prefix(), byteBuffer)
    return byteBuffer.array().plus(decodedKey)
}

internal fun encodeService(service: JSON): String {
    val serviceToEncode = (
        service.replace("[\n\t]*", "")
            .replace("type", "t")
            .replace("serviceEndpoint", "s")
            .replace("didcommmessaging", "dm")
            .replace("routingKeys", "r")
        )
    return ".S" + Base64.getEncoder().encodeToString(serviceToEncode.toByteArray())
}
