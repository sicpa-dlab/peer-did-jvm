@file:JvmName("PeerDIDCreator")

package org.dif.peerdid

import org.dif.model.JSON
import org.dif.model.PeerDID
import org.dif.model.PublicKeyAgreement
import org.dif.model.PublicKeyAuthentication

/** Creates [PeerDID] according to zero algorithm using [inceptionKey]*/
fun createPeerDIDNumalgo0(inceptionKey: PublicKeyAuthentication): PeerDID {
    return "did:peer:0z".plus(createEncnumbasis(inceptionKey))
}

/** Creates [PeerDID] according to the second algorithm using [encryptionKeys], [signingKeys], [service]*/
fun createPeerDIDNumalgo2(
    encryptionKeys: List<PublicKeyAgreement>,
    signingKeys: List<PublicKeyAuthentication>,
    service: JSON
): PeerDID {
    val encryptionKeysStr = encryptionKeys.joinToString(".Ez", ".Ez")
    val signingKeysStr = signingKeys.joinToString(".Ez", ".Ez")
    val encodedService = encodeService(service)

    val peerdid = "did:peer:2".plus(encryptionKeysStr).plus(signingKeysStr).plus(encodedService)
    return peerdid
}
