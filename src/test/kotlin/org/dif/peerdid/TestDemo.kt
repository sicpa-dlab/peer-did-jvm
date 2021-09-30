package org.dif.peerdid

import org.dif.peerdid.core.*
import org.junit.jupiter.api.Test

class TestDemo {
    @Test
    fun testCreateResolvePeerDID() {
        val encryptionKeys = listOf(
            PublicKeyAgreement(
                type = PublicKeyTypeAgreement.X25519,
                encodingType = EncodingType.BASE58,
                encodedValue = "DmgBSHMqaZiYqwNMEJJuxWzsGGC8jUYADrfSdBrC6L8s",
            )
        )
        val signingKeys = listOf(
            PublicKeyAuthentication(
                type = PublicKeyTypeAuthentication.ED25519,
                encodingType = EncodingType.BASE58,
                encodedValue = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
            )
        )
        val service =
            """
                {
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": "https://example.com/endpoint1",
                    "routingKeys": ["did:example:somemediator#somekey1"],
                    "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
                }
            """

        val peerDIDAlgo0 = createPeerDIDNumalgo0(signingKeys[0])
        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys, signingKeys, service
        )

        println("PeerDID algo 0:$peerDIDAlgo0")
        println("==================================")
        println("PeerDID algo 2:$peerDIDAlgo2")
        println("==================================")

        val DIDDocAlgo0 = resolvePeerDID(peerDIDAlgo0)
        val DIDDocAlgo2 = resolvePeerDID(peerDIDAlgo2)
        println("DIDDoc algo 0:$DIDDocAlgo0")
        println("==================================")
        print("DIDDoc algo 2:$DIDDocAlgo2")
    }
}
