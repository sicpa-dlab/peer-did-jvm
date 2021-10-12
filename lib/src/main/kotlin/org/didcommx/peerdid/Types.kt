package org.didcommx.peerdid

enum class VerificationMaterialFormatPeerDID {
    JWK,
    BASE58,
    MULTIBASE;
}

sealed class VerificationMethodTypePeerDID(val value: String)

sealed class VerificationMethodTypeAgreement(value: String) : VerificationMethodTypePeerDID(value) {
    object JSON_WEB_KEY_2020 : VerificationMethodTypeAgreement("JsonWebKey2020")
    object X25519_KEY_AGREEMENT_KEY_2019 : VerificationMethodTypeAgreement("X25519KeyAgreementKey2019")
    object X25519_KEY_AGREEMENT_KEY_2020 : VerificationMethodTypeAgreement("X25519KeyAgreementKey2020")
}

sealed class VerificationMethodTypeAuthentication(value: String) : VerificationMethodTypePeerDID(value) {
    object JSON_WEB_KEY_2020 : VerificationMethodTypeAuthentication("JsonWebKey2020")
    object ED25519_VERIFICATION_KEY_2018 : VerificationMethodTypeAuthentication("Ed25519VerificationKey2018")
    object ED25519_VERIFICATION_KEY_2020 : VerificationMethodTypeAuthentication("Ed25519VerificationKey2020")
}

data class VerificationMaterialPeerDID<T : VerificationMethodTypePeerDID>(
    val format: VerificationMaterialFormatPeerDID,
    val value: Any,
    val type: T
)

typealias VerificationMaterialAgreement = VerificationMaterialPeerDID<VerificationMethodTypeAgreement>
typealias VerificationMaterialAuthentication = VerificationMaterialPeerDID<VerificationMethodTypeAuthentication>

typealias JSON = String
typealias PeerDID = String
