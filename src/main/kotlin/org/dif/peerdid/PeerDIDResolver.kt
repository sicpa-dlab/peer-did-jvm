@file:JvmName("PeerDIDResolver")

package org.dif.peerdid

import org.dif.model.DIDDoc
import org.dif.model.PeerDID

/** Resolves [PeerDID] to [DIDDoc]*/
fun resolvePeerDID(peerDID: PeerDID, versionId: Int? = null): DIDDoc {
    if (!isPeerDID(peerDID)) {
        throw IllegalArgumentException("Invalid Peer DID: $peerDID")
    }
    if (peerDID[9] == '0') {
        return buildDIDDocNumalgo0(peerDID)
    } else if (peerDID[9] == '2') {
        return buildDIDDocNumalgo2(peerDID)
    }
    throw IllegalArgumentException("Invalid numalgo of Peer DID: $peerDID")
}
