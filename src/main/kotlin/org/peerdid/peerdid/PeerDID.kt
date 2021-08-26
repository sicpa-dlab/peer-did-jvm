package org.peerdid.peerdid

import org.peerdid.model.EncodingType
import org.peerdid.model.Numalgo

interface PeerDID {
    val numalgo: Numalgo
    val transform: EncodingType
    fun create(): String
    fun resolve(): DIDDoc
}
