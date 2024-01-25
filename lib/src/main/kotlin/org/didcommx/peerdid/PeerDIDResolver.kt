@file:JvmName("PeerDIDResolver")

package org.didcommx.peerdid

import org.didcommx.peerdid.core.DecodedEncumbasis
import org.didcommx.peerdid.core.Numalgo2Prefix
import org.didcommx.peerdid.core.decodeMultibaseEncnumbasis
import org.didcommx.peerdid.core.decodeService
import org.didcommx.peerdid.core.getVerificationMethod
import org.didcommx.peerdid.core.validateAgreementMaterialType
import org.didcommx.peerdid.core.validateAuthenticationMaterialType

/** Resolves [DIDDocPeerDID] from [PeerDID]
 * @param [peerDID] PeerDID to resolve
 * @param [format] The format of public keys in the DID DOC. Default format is multibase.
 * @throws MalformedPeerDIDException
 * - if [peerDID] parameter does not match [peerDID] spec
 * - if a valid DIDDoc cannot be produced from the [peerDID]
 * @return resolved [DIDDocPeerDID] as JSON string
 */
fun resolvePeerDID(
    peerDID: PeerDID,
    format: VerificationMaterialFormatPeerDID = VerificationMaterialFormatPeerDID.MULTIBASE
): String {
    if (!isPeerDID(peerDID)) {
        throw MalformedPeerDIDException("Does not match peer DID regexp: $peerDID")
    }
    val didDoc = when (peerDID[9]) {
        '0' -> buildDIDDocNumalgo0(peerDID, format)
        '2' -> buildDIDDocNumalgo2(peerDID, format)
        else -> throw IllegalArgumentException("Invalid numalgo of Peer DID: $peerDID")
    }
    return didDoc.toJson()
}

private fun buildDIDDocNumalgo0(peerDID: PeerDID, format: VerificationMaterialFormatPeerDID): DIDDocPeerDID {
    val inceptionKey = peerDID.substring(10)
    val decodedEncumbasis = decodeMultibaseEncnumbasisAuth(inceptionKey, format)
    return DIDDocPeerDID(
        did = peerDID,
        authentication = listOf(getVerificationMethod(1, peerDID, decodedEncumbasis))
    )
}

private fun buildDIDDocNumalgo2(peerDID: PeerDID, format: VerificationMaterialFormatPeerDID): DIDDocPeerDID {
    val keys = peerDID.drop(11)

    val encodedServicesJson = mutableListOf<JSON>()
    val authentications = mutableListOf<VerificationMethodPeerDID>()
    val keyAgreement = mutableListOf<VerificationMethodPeerDID>()

    keys.split(".").withIndex().forEach { (index, keyIt) ->
        val prefix = keyIt[0]
        val value = keyIt.drop(1)

        when (prefix) {
            Numalgo2Prefix.SERVICE.prefix -> {
                encodedServicesJson.add(value)
            }
            Numalgo2Prefix.AUTHENTICATION.prefix -> {
                val decodedEncumbasis = decodeMultibaseEncnumbasisAuth(value, format)
                authentications.add(getVerificationMethod(index + 1, peerDID, decodedEncumbasis))
            }

            Numalgo2Prefix.KEY_AGREEMENT.prefix -> {
                val decodedEncumbasis = decodeMultibaseEncnumbasisAgreement(value, format)
                keyAgreement.add(getVerificationMethod(index + 1, peerDID, decodedEncumbasis))
            }

            else -> throw IllegalArgumentException("Unsupported transform part of PeerDID: $prefix")
        }
    }

    val decodedService = doDecodeService(encodedServicesJson, peerDID)

    return DIDDocPeerDID(
        did = peerDID,
        authentication = authentications,
        keyAgreement = keyAgreement,
        service = decodedService
    )
}

private fun decodeMultibaseEncnumbasisAuth(
    multibase: String,
    format: VerificationMaterialFormatPeerDID
): DecodedEncumbasis {
    try {
        val decodedEncumbasis = decodeMultibaseEncnumbasis(multibase, format)
        validateAuthenticationMaterialType(decodedEncumbasis.verMaterial)
        return decodedEncumbasis
    } catch (e: IllegalArgumentException) {
        throw MalformedPeerDIDException("Invalid key $multibase", e)
    }
}

private fun decodeMultibaseEncnumbasisAgreement(
    multibase: String,
    format: VerificationMaterialFormatPeerDID
): DecodedEncumbasis {
    try {
        val decodedEncumbasis = decodeMultibaseEncnumbasis(multibase, format)
        validateAgreementMaterialType(decodedEncumbasis.verMaterial)
        return decodedEncumbasis
    } catch (e: IllegalArgumentException) {
        throw MalformedPeerDIDException("Invalid key $multibase", e)
    }
}

private fun doDecodeService(service: List<JSON>, peerDID: String): List<Service>? {
    try {
        return decodeService(service, peerDID)
    } catch (e: IllegalArgumentException) {
        throw MalformedPeerDIDException("Invalid service", e)
    }
}
