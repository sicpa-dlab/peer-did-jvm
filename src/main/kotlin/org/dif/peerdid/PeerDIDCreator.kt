@file:JvmName("PeerDIDCreator")

package org.dif.peerdid

import org.dif.peerdid.core.JSON
import org.dif.peerdid.core.Numalgo2Prefix
import org.dif.peerdid.core.PeerDID
import org.dif.peerdid.core.PublicKeyAgreement
import org.dif.peerdid.core.PublicKeyAuthentication
import org.dif.peerdid.core.checkKeyCorrectlyEncoded
import org.dif.peerdid.core.createMultibaseEncnumbasis
import org.dif.peerdid.core.encodeService

/**
 * Checks if [peerDID] param matches PeerDID spec
 * @see
 * <a href="https://identity.foundation/peer-did-method-spec/index.html#matching-regex">Specification</a>
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
 * @see
 * <a href="https://identity.foundation/peer-did-method-spec/index.html#generation-method">Specification</a>
 * @param [inceptionKey] the key that creates the DID and authenticates when exchanging it with the first peer
 * @throws IllegalArgumentException if the [inceptionKey] is not correctly encoded
 * @return generated PeerDID
 */
fun createPeerDIDNumalgo0(inceptionKey: PublicKeyAuthentication): PeerDID {
    if (!checkKeyCorrectlyEncoded(inceptionKey.encodedValue, inceptionKey.encodingType))
        throw IllegalArgumentException("Inception key $inceptionKey is not correctly encoded")
    return "did:peer:0${createMultibaseEncnumbasis(inceptionKey)}"
}

/**
 * Generates PeerDID according to the second algorithm
 * For this type of algorithm DIDDoc can be obtained from PeerDID
 * @see
 * <a href="https://identity.foundation/peer-did-method-spec/index.html#generation-method">Specification</a>
 * @param [encryptionKeys] list of encryption keys
 * @param [signingKeys] list of signing keys
 * @param [service] JSON string conforming to the DID specification
 * @throws IllegalArgumentException
 * - if at least one of keys is not properly encoded
 * - if service is not a valid JSON
 * @return generated PeerDID
 */
fun createPeerDIDNumalgo2(
    encryptionKeys: List<PublicKeyAgreement>,
    signingKeys: List<PublicKeyAuthentication>,
    service: JSON?
): PeerDID {
    val encodedEncryptionKeys = encryptionKeys.map { publicKey ->
        if (!checkKeyCorrectlyEncoded(publicKey.encodedValue, publicKey.encodingType))
            throw IllegalArgumentException("Encryption key $publicKey is not correctly encoded")
        createMultibaseEncnumbasis(publicKey)
    }
    val encodedSigningKeys = signingKeys.map { publicKey ->
        if (!checkKeyCorrectlyEncoded(publicKey.encodedValue, publicKey.encodingType))
            throw IllegalArgumentException("Signing key $publicKey is not correctly encoded")
        createMultibaseEncnumbasis(publicKey)
    }

    val encryptionKeysStr = if (encryptionKeys.isEmpty())
        ""
    else
        encodedEncryptionKeys.joinToString(
            ".${Numalgo2Prefix.KEY_AGREEMENT.prefix}",
            ".${Numalgo2Prefix.KEY_AGREEMENT.prefix}"
        )

    val signingKeysStr = if (signingKeys.isEmpty())
        ""
    else
        encodedSigningKeys.joinToString(
            ".${Numalgo2Prefix.AUTHENTICATION.prefix}",
            ".${Numalgo2Prefix.AUTHENTICATION.prefix}"
        )

    val encodedService = if (service.isNullOrEmpty()) "" else encodeService(service)

    return "did:peer:2$encryptionKeysStr$signingKeysStr$encodedService"
}
