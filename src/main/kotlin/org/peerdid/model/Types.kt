package org.peerdid.model

enum class PublicKeyTypeAgreement(val prefix: Int) {
    X25519(0xEC)
}

enum class PublicKeyTypeAuthentication(val prefix: Int) {
    ED25519(0xED),
    SECP256K1(0xE7)
}

enum class EncodingType(val type: Char) {
    BASE58('z')
}

enum class Numalgo(val number: Int) {
    ZERO(0),
    SECOND(2)
}

typealias JSON = String
