@file:JvmName("PeerDIDCreator")

package org.dif.peerdid

import org.dif.model.JSON
import org.dif.model.PeerDID
import org.dif.model.PublicKeyAgreement
import org.dif.model.PublicKeyAuthentication

/**
 * Checks if [peerDID] param matches PeerDID spec
 * @param [peerDID] PeerDID to check
 * @return true if [peerDID] matches spec, otherwise false
 */
fun isPeerDID(peerDID: String): Boolean {
    val regex =
        (
            "^did:peer:(([0](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))" +
                "|(2((.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))+(.(S)[0-9a-zA-Z=]*)?)))$"
            ).toRegex()
    return regex.matches(peerDID)
}

/**
 * Generates PeerDID according to the zero algorithm
 * For this type of algorithm DIDDoc can be obtained from PeerDID
 * @param [inceptionKey] the key that creates the DID and authenticates when exchanging it with the first peer
 * @throws IllegalArgumentException if the [inceptionKey] is not correctly encoded
 * @return generated PeerDID
 */
fun createPeerDIDNumalgo0(inceptionKey: PublicKeyAuthentication): PeerDID {
    if (!checkKeyCorrectlyEncoded(inceptionKey.encodedValue, inceptionKey.encodingType))
        throw IllegalArgumentException("Inception key $inceptionKey is not correctly encoded")
    return "did:peer:0".plus(createEncnumbasis(inceptionKey))
}

/**
 * Generates PeerDID according to the second algorithm
 * For this type of algorithm DIDDoc can be obtained from PeerDID
 * @param [encryptionKeys] list of encryption keys
 * @param [signingKeys] list of signing keys
 * @param [service] JSON string conforming to the DID specification
 * @throws IllegalArgumentException if at least one of keys is not properly encoded
 * @return generated PeerDID
 */
fun createPeerDIDNumalgo2(
    encryptionKeys: List<PublicKeyAgreement>,
    signingKeys: List<PublicKeyAuthentication>,
    service: JSON
): PeerDID {
    val encodedEncryptionKeys = encryptionKeys.map { publicKey ->
        if (!checkKeyCorrectlyEncoded(publicKey.encodedValue, publicKey.encodingType))
            throw IllegalArgumentException("Encryption key $publicKey is not correctly encoded")
        createEncnumbasis(publicKey)
    }
    val encodedSigningKeys = signingKeys.map { publicKey ->
        if (!checkKeyCorrectlyEncoded(publicKey.encodedValue, publicKey.encodingType))
            throw IllegalArgumentException("Signing key $publicKey is not correctly encoded")
        createEncnumbasis(publicKey)
    }
    val encryptionKeysStr = if (encryptionKeys.isEmpty()) "" else encodedEncryptionKeys.joinToString(".E", ".E")
    val signingKeysStr = if (signingKeys.isEmpty()) "" else encodedSigningKeys.joinToString(".V", ".V")
    val encodedService = if (service.isEmpty()) "" else encodeService(service)

    val peerdid = "did:peer:2".plus(encryptionKeysStr).plus(signingKeysStr).plus(encodedService)
    return peerdid
}
