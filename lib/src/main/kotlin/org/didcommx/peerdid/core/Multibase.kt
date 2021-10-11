package org.didcommx.peerdid.core

import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase

private enum class MultibasePrefix(val prefix: Char) {
    BASE58('z');
}

fun toBase58Multibase(value: ByteArray) =
    Multibase.encode(Multibase.Base.Base58BTC, value)

fun toBase58(value: ByteArray) =
    Base58.encode(value)

fun fromBase58Multibase(multibase: String): Pair<String, ByteArray> {
    if (multibase.isEmpty())
        throw IllegalArgumentException("Invalid key: No transform part in multibase encoding")
    val transform = multibase[0]
    if (transform != MultibasePrefix.BASE58.prefix)
        throw IllegalArgumentException("Invalid key: Prefix $transform not supported")
    val encnumbasis = multibase.drop(1)
    val decodedEncnumbasis = fromBase58(encnumbasis)
    return Pair(encnumbasis, decodedEncnumbasis)
}

fun fromBase58(value: String): ByteArray {
    if (!isBase58(value))
        throw IllegalArgumentException("Invalid key: Invalid base58 encoding: $value")
    return Base58.decode(value)
}

fun isBase58(value: String): Boolean {
    val alphabet = Regex("[1-9a-km-zA-HJ-NP-Z]+")
    return alphabet.matches(value)
}
