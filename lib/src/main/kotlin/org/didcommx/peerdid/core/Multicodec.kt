package org.didcommx.peerdid.core

import com.zman.varint.VarInt
import org.didcommx.peerdid.VerificationMethodType
import org.didcommx.peerdid.VerificationMethodTypeAgreement
import org.didcommx.peerdid.VerificationMethodTypeAuthentication
import java.nio.ByteBuffer

enum class Codec(val prefix: Int) {
    X25519(0xEC),
    ED25519(0xED);
}

fun toMulticodec(value: ByteArray, keyType: VerificationMethodType): ByteArray {
    val prefix = getCodec(keyType).prefix
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(prefix, byteBuffer)
    return byteBuffer.array().plus(value)
}

fun fromMulticodec(value: ByteArray): Pair<Codec, ByteArray> {
    val prefix = VarInt.readVarint(ByteBuffer.wrap(value))
    val codec = getCodec(prefix)
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(prefix, byteBuffer)
    return Pair(codec, value.drop(byteBuffer.array().size).toByteArray())
}

private fun getCodec(keyType: VerificationMethodType) =
    when (keyType) {
        is VerificationMethodTypeAuthentication -> Codec.ED25519
        is VerificationMethodTypeAgreement -> Codec.X25519
    }

private fun getCodec(prefix: Int) =
    Codec.values().find { it.prefix == prefix }
        ?: throw IllegalArgumentException("Prefix $prefix not supported")

