@file:JvmName("PeerDIDCreator")

package org.dif.peerdid

import org.dif.model.JSON
import org.dif.model.PeerDID
import org.dif.model.PublicKeyAgreement
import org.dif.model.PublicKeyAuthentication

fun isPeerDID(peerDID: String): Boolean {
    val regex =
        (
            "^did:peer:(([0](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))" +
                "|(2((.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))+(.(S)[0-9a-zA-Z=]*)?)))$"
            ).toRegex()
    return regex.matches(peerDID)
}

/** Creates [PeerDID] according to zero algorithm using [inceptionKey]*/
fun createPeerDIDNumalgo0(inceptionKey: PublicKeyAuthentication): PeerDID {
    return "did:peer:0".plus(createEncnumbasis(inceptionKey))
}

/** Creates [PeerDID] according to the second algorithm using [encryptionKeys], [signingKeys], [service]*/
fun createPeerDIDNumalgo2(
    encryptionKeys: List<PublicKeyAgreement>,
    signingKeys: List<PublicKeyAuthentication>,
    service: JSON
): PeerDID {
    val encodedEncryptionKeys = encryptionKeys.map { publicKey -> createEncnumbasis(publicKey) }
    val encodedSigningKeys = signingKeys.map { publicKey -> createEncnumbasis(publicKey) }
    val encryptionKeysStr = encodedEncryptionKeys.joinToString(".E", ".E")
    val signingKeysStr = encodedSigningKeys.joinToString(".V", ".V")
    val encodedService = encodeService(service)

    val peerdid = "did:peer:2".plus(encryptionKeysStr).plus(signingKeysStr).plus(encodedService)
    return peerdid
}
