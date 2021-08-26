package org.peerdid.peerdid

import org.peerdid.model.EncodingType
import org.peerdid.model.Numalgo

class PeerDIDNumalgo0(
    override val numalgo: Numalgo = Numalgo.ZERO,
    override val transform: EncodingType,
    val inceptionKey: String,
) : PeerDID {
    override fun create(): String {
        TODO("Not yet implemented")
    }

    override fun resolve(): DIDDoc {
        TODO("Not yet implemented")
    }
}
