@file:JvmName("PeerDIDCreator")

package org.didcommx.peerdid

import org.didcommx.peerdid.core.Numalgo2Prefix
import org.didcommx.peerdid.core.createMultibaseEncnumbasis
import org.didcommx.peerdid.core.encodeService
import org.didcommx.peerdid.core.validateAgreementMaterialType
import org.didcommx.peerdid.core.validateAuthenticationMaterialType

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
fun createPeerDIDNumalgo0(inceptionKey: VerificationMaterialAuthentication): PeerDID {
    validateAuthenticationMaterialType(inceptionKey)
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
    encryptionKeys: List<VerificationMaterialAgreement>,
    signingKeys: List<VerificationMaterialAuthentication>,
    service: JSON?
): PeerDID {
    encryptionKeys.forEach { validateAgreementMaterialType(it) }
    signingKeys.forEach { validateAuthenticationMaterialType(it) }

    val encodedEncryptionKeysStr = encryptionKeys
        .map { createMultibaseEncnumbasis(it) }
        .map { ".${Numalgo2Prefix.KEY_AGREEMENT.prefix}$it" }
        .joinToString("")
    val encodedSigningKeysStr = signingKeys
        .map { createMultibaseEncnumbasis(it) }
        .map { ".${Numalgo2Prefix.AUTHENTICATION.prefix}$it" }
        .joinToString("")
    val encodedService = if (service.isNullOrEmpty()) "" else encodeService(service)

    return "did:peer:2$encodedEncryptionKeysStr$encodedSigningKeysStr$encodedService"
}
