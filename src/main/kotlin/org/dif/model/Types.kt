package org.dif.model

interface PublicKeyType {
    fun prefix(): Int
}

enum class PublicKeyTypeAgreement(private val prefix: Int) : PublicKeyType {
    X25519(0xEC);

    override fun prefix(): Int {
        return prefix
    }
}

enum class PublicKeyTypeAuthentication(private val prefix: Int) : PublicKeyType {
    ED25519(0xED),
    SECP256K1(0xE7);

    override fun prefix(): Int {
        return prefix
    }
}

enum class EncodingType(val type: Char) {
    BASE58('z')
}

typealias JSON = String
typealias DIDDoc = String
typealias PeerDID = String
