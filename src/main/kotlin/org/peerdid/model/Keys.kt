package org.peerdid.model

data class PublicKeyAgreement(
    val encoding_type: EncodingType,
    val encoded_value: String,
    val type: PublicKeyTypeAgreement
)

data class PublicKeyAuthentication(
    val encoding_type: EncodingType,
    val encoded_value: String,
    val type: PublicKeyTypeAuthentication
)
