package org.peerdid.peerdid

import org.peerdid.model.EncodingType
import org.peerdid.model.Numalgo

class PeerDIDNumalgo2(
    override val numalgo: Numalgo = Numalgo.SECOND,
    override val transform: EncodingType,
    val encryptionKeys: Set<String>?,
    val signingKeys: Set<String>?,
    val service: Set<String>?
) : PeerDID {
    private constructor(builder: Builder) : this(
        builder.numalgo, builder.transform,
        builder.encryptionKeys, builder.signingKeys, builder.service
    )

    data class Builder(
        var numalgo: Numalgo = Numalgo.SECOND,
        var transform: EncodingType,
        var encryptionKeys: Set<String>?,
        var signingKeys: Set<String>?,
        var service: Set<String>?
    ) {

        fun transform(transform: EncodingType) = apply { this.transform = transform }
        fun encryptionKeys(encryptionKeys: Set<String>) = apply { this.encryptionKeys = encryptionKeys }
        fun signingKeys(signingKeys: Set<String>) = apply { this.signingKeys = signingKeys }
        fun service(service: Set<String>) = apply { this.service = service }
        fun build(): PeerDIDNumalgo2 {
            return PeerDIDNumalgo2(this)
        }
    }

    override fun create(): String {
        TODO("Not yet implemented")
    }

    override fun resolve(): DIDDoc {
        TODO("Not yet implemented")
    }
}
