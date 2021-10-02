package org.didcommx.peerdid.core

sealed class PublicKeyType

sealed class PublicKeyTypeAgreement : PublicKeyType() {
    object X25519 : PublicKeyTypeAgreement()
}

sealed class PublicKeyTypeAuthentication : PublicKeyType() {
    object ED25519 : PublicKeyTypeAuthentication()
}

data class PublicKey<T : PublicKeyType>(
    val encodingType: EncodingType,
    val encodedValue: String,
    val type: T
)

typealias PublicKeyAgreement = PublicKey<PublicKeyTypeAgreement>
typealias PublicKeyAuthentication = PublicKey<PublicKeyTypeAuthentication>

enum class EncodingType(val type: Char) {
    BASE58('z')
}

enum class DIDDocVerMaterialFormat {
    JWK,
    BASE58,
    MULTIBASE;
}

typealias JSON = String
typealias PeerDID = String
