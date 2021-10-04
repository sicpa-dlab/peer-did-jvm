@file:JvmName("PeerDIDResolver")

package org.didcommx.peerdid

import com.google.gson.GsonBuilder
import org.didcommx.peerdid.core.DIDDoc
import org.didcommx.peerdid.core.DIDDocVerMaterialFormat
import org.didcommx.peerdid.core.Numalgo2Prefix
import org.didcommx.peerdid.core.PeerDID
import org.didcommx.peerdid.core.VerificationMaterialTypeAgreement
import org.didcommx.peerdid.core.VerificationMaterialTypeAuthentication
import org.didcommx.peerdid.core.VerificationMethod
import org.didcommx.peerdid.core.decodeMultibaseEncnumbasis
import org.didcommx.peerdid.core.decodeService
import org.didcommx.peerdid.core.isInEncodingTypes

/** Resolves [DIDDoc] from [PeerDID]
 * @param [peerDID] PeerDID to resolve
 * @param [format] The format of public keys in the DID DOC. Default format is multibase.
 * @throws IllegalArgumentException
 * - if [peerDID] parameter does not match [peerDID] spec
 * - if a valid DIDDoc cannot be produced from the [peerDID]
 * @return resolved [DIDDoc] as JSON string
 */
fun resolvePeerDID(peerDID: PeerDID, format: DIDDocVerMaterialFormat = DIDDocVerMaterialFormat.MULTIBASE): String {
    if (!isPeerDID(peerDID)) {
        throw IllegalArgumentException("Invalid Peer DID: $peerDID")
    }
    val didDoc = when (peerDID[9]) {
        '0' -> buildDIDDocNumalgo0(peerDID, format)
        '2' -> buildDIDDocNumalgo2(peerDID, format)
        else -> throw IllegalArgumentException("Invalid numalgo of Peer DID: $peerDID")
    }

    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
    return gson.toJson(didDoc.toDict())
}

private fun buildDIDDocNumalgo0(peerDID: PeerDID, format: DIDDocVerMaterialFormat): DIDDoc {
    val inceptionKey = peerDID.substring(10)
    val encodingAlgorithm = peerDID[10]

    if (!isInEncodingTypes(encodingAlgorithm))
        throw IllegalArgumentException("Unsupported encoding algorithm of key: $encodingAlgorithm")

    val verificationMaterial = decodeMultibaseEncnumbasis(inceptionKey, format)

    if (verificationMaterial.type !is VerificationMaterialTypeAuthentication)
        throw IllegalArgumentException("Invalid type of key $inceptionKey. Key agreement instead of authentication.")

    return DIDDoc(
        did = peerDID,
        authentication = listOf(
            VerificationMethod(verificationMaterial, peerDID)
        )
    )
}

private fun buildDIDDocNumalgo2(peerDID: PeerDID, format: DIDDocVerMaterialFormat): DIDDoc {
    val keys = peerDID.drop(11)

    var service = ""
    val authentications = mutableListOf<VerificationMethod>()
    val keyAgreement = mutableListOf<VerificationMethod>()

    keys.split(".").forEach {
        val prefix = it[0]
        val value = it.drop(1)

        when (prefix) {
            Numalgo2Prefix.SERVICE.prefix -> service = value

            Numalgo2Prefix.AUTHENTICATION.prefix -> {
                val verificationMaterial = decodeMultibaseEncnumbasis(value, format)
                if (verificationMaterial.type !is VerificationMaterialTypeAuthentication)
                    throw IllegalArgumentException("Invalid type of key $value. Key agreement instead of authentication.")
                authentications.add(VerificationMethod(verificationMaterial, peerDID))
            }

            Numalgo2Prefix.KEY_AGREEMENT.prefix -> {
                val verificationMaterial = decodeMultibaseEncnumbasis(value, format)
                if (verificationMaterial.type !is VerificationMaterialTypeAgreement)
                    throw IllegalArgumentException("Invalid type of key $value. Authentication instead of key agreement.")
                keyAgreement.add(VerificationMethod(verificationMaterial, peerDID))
            }

            else -> throw IllegalArgumentException("Unsupported transform part of PeerDID: $prefix")
        }
    }

    val decodedService = decodeService(service, peerDID)

    return DIDDoc(
        did = peerDID,
        authentication = authentications,
        keyAgreement = keyAgreement,
        service = decodedService
    )
}
