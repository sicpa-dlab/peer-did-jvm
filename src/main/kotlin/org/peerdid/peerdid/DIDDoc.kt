package org.peerdid.peerdid

import org.peerdid.model.PublicKeyAgreement
import org.peerdid.model.PublicKeyAuthentication

class DIDDoc(
    val peerDID: String?,
    val encryptionKeys: Set<PublicKeyAgreement>?,
    val signingKeys: Set<PublicKeyAuthentication>?,
    val service: Set<Service>?
) {
    private constructor(builder: Builder) : this(
        builder.peerDID, builder.encryptionKeys,
        builder.signingKeys, builder.service
    )

    data class Builder(
        var peerDID: String?,
        var encryptionKeys: Set<PublicKeyAgreement>?,
        var signingKeys: Set<PublicKeyAuthentication>?,
        var service: Set<Service>?
    ) {

        fun peerDID(peerDID: String) = apply { this.peerDID = peerDID }
        fun encryptionKeys(encryptionKeys: Set<PublicKeyAgreement>) = apply { this.encryptionKeys = encryptionKeys }
        fun signingKeys(signingKeys: Set<PublicKeyAuthentication>) = apply { this.signingKeys = signingKeys }
        fun service(service: Set<Service>) = apply { this.service = service }
        fun build() = DIDDoc(this)
    }
}

data class Service(
    val peerDID: String,
    val type: String,
    val serviceEndpoint: String,
    val routingKeys: Set<String>
)
