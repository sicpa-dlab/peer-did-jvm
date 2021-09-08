@file:JvmName("PeerDIDResolver")

package org.dif.peerdid

import org.dif.model.DIDDoc
import org.dif.model.PeerDID

/** Resolves [DIDDoc] from [PeerDID]
 * @param [peerDID] PeerDID to resolve
 * @param [versionId] a specific version of a [DIDDoc].
 *  If value is default, version of [DIDDoc] will be latest.
 *  [versionId] is not used for now, as we support only static layer where [DIDDoc] never changes
 * @throws IllegalArgumentException if [peerDID] parameter does not match [peerDID] spec
 * @return resolved [DIDDoc] as JSON string
 */
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
