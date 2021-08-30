package org.dif.model

interface PublicKey<T : PublicKeyType> {
    val encodingType: EncodingType
    val encodedValue: String
    val type: T
}

typealias PublicKeyAgreement = PublicKey<PublicKeyTypeAgreement>
typealias PublicKeyAuthentication = PublicKey<PublicKeyTypeAuthentication>
