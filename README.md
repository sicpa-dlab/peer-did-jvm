# Peer DID Kotlin library

This is an implementation of the [Peer DID method specification](https://identity.foundation/peer-did-method-spec/).

This version of API implements
only [static layers of support (1, 2a, 2b)](https://identity.foundation/peer-did-method-spec/#layers-of-support).

## Example

Example code:

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
                "type": "didcommmessaging",
                "serviceEndpoint": "https://example.com/endpoint1",
                "routingKeys": ["did:example:somemediator#somekey1"]
            }
        """

    val peerDIDAlgo0 = createPeerDIDNumalgo0(signingKeys[0])
    val peerDIDAlgo2 = createPeerDIDNumalgo2(
        encryptionKeys, signingKeys, service
    )

    val DIDDocAlgo0 = resolvePeerDID(peerDIDAlgo0)
    val DIDDocAlgo2 = resolvePeerDID(peerDIDAlgo2)

Example of DID documents:

    # DIDDoc algo 0:
    {
        "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        "authentication": {
            "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            "type": "ED25519",
            "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            "publicKeyBase58": "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
        }
    }

    # DIDDoc algo 2:
    {
        "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdfQ==",
        "authentication": [
            {
                "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdfQ==#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                "type": "ED25519",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdfQ==",
                "publicKeyBase58": "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
            }
        ],
        "keyAgreement": [
            {
                "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdfQ==#6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud",
                "type": "X25519",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdfQ==",
                "publicKeyBase58": "DmgBSHMqaZiYqwNMEJJuxWzsGGC8jUYADrfSdBrC6L8s"
            }
        ],
        "service": [
            {
                "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdfQ==#didcommmessaging#0",
                "type": "didcommmessaging",
                "serviceEndpoint": "https://example.com/endpoint1",
                "routingKeys": "[did:example:somemediator#somekey1]"
            }
        ]
    }

## How to contribute

Pull requests are welcome!

Pull requests should have a descriptive name, include the summary of all changes made in the pull
request description, and include unit tests that provide good coverage of the feature or fix. A Continuous Integration (
CI)
pipeline is executed on all PRs before review and contributors are expected to address all CI issues identified.

### A Continuous Integration (CI) pipeline does the following jobs:

- Executes all unit tests from the pull request.
- Analyzes code style using ktlint.