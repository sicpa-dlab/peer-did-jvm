# Peer DID JVM

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Unit Tests](https://github.com/sicpa-dlab/peer-did-jvm/workflows/verify/badge.svg)](https://github.com/sicpa-dlab/peer-did-jvm/actions/workflows/verify.yml)


Implementation of the [Peer DID method specification](https://identity.foundation/peer-did-method-spec/) 
in Java/Kotlin and Android.

Implements [static layers of support (1, 2a, 2b)](https://identity.foundation/peer-did-method-spec/#layers-of-support) only.

## Installation
Available from Maven Central.

Gradle:
```
dependencies {
  implementation 'org.didcommx:peerdid:0.2.0'
}
```


Maven:
```
<dependency>
  <groupId>org.didcommx</groupId>
  <artifactId>peerdid</artifactId>
  <version>0.2.0</version>
</dependency>
```

## Example

Example code:

    val encryptionKeys = listOf(
        VerificationMaterialAgreement(
            type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format = VerificationMaterialFormatPeerDID.BASE58,
            value = "DmgBSHMqaZiYqwNMEJJuxWzsGGC8jUYADrfSdBrC6L8s",
        )
    )
    val signingKeys = listOf(
        VerificationMaterialAuthentication(
            type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format = VerificationMaterialFormatPeerDID.BASE58,
            value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
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

    val didDocAlgo0Json = resolvePeerDID(peerDIDAlgo0)
    val didDocAlgo2Json = resolvePeerDID(peerDIDAlgo2)

    val didDocAlgo0 = DIDDocPeerDID.fromJson(didDocAlgo0Json)
    val didDocAlgo2 = DIDDocPeerDID.fromJson(didDocAlgo2Json)

Example of DID documents:
# DIDDoc algo 0:

    {
        "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        "authentication": [
            {
                "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            }
        ]
    }

    # did_doc_algo_2
    {
        "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19",
        "authentication": [
            {
                "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19#key-2",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19",
                "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            }
        ],
        "keyAgreement": [
            {
                "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19#key-1",
                "type": "X25519KeyAgreementKey2020",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19",
                "publicKeyMultibase": "z6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud"
            }
        ],
        "service": [
            {
                "id": "#service",
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "https://example.com/endpoint1",
                    "routingKeys": [
                        "did:example:somemediator#somekey1"
                    ],
                    "accept": [
                        "didcomm/v2", "didcomm/aip2;env=rfc587"
                    ]
                }
            }
        ]
    }


Example code:
    Based the new PeerDid Spec https://identity.foundation/peer-did-method-spec/

    val encryptionKeys = listOf(
        VerificationMaterialAgreement(
            type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format = VerificationMaterialFormatPeerDID.BASE58,
            value = "DmgBSHMqaZiYqwNMEJJuxWzsGGC8jUYADrfSdBrC6L8s",
        )
    )
    val signingKeys = listOf(
        VerificationMaterialAuthentication(
            type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format = VerificationMaterialFormatPeerDID.BASE58,
            value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        )
    )
    val service =
        """
            {
              "type": "DIDCommMessaging",
              "serviceEndpoint": {
                "uri": "https://example.com/endpoint1",
                "routingKeys": [
                  "did:example:somemediator#somekey1"
                ],
                "accept": [
                  "didcomm/v2",
                  "didcomm/aip2;env=rfc587"
                ]
              }
            }
        """

    val peerDIDAlgo0 = createPeerDIDNumalgo0(signingKeys[0])
    val peerDIDAlgo2 = createPeerDIDNumalgo2(
        encryptionKeys, signingKeys, service
    )

    val didDocAlgo0Json = resolvePeerDID(peerDIDAlgo0)
    val didDocAlgo2Json = resolvePeerDID(peerDIDAlgo2)

    val didDocAlgo0 = DIDDocPeerDID.fromJson(didDocAlgo0Json)
    val didDocAlgo2 = DIDDocPeerDID.fromJson(didDocAlgo2Json)

Example of DID documents:

    # DIDDoc algo 0:
    {
        "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        "authentication": [
            {
              "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#key-1",
              "type": "Ed25519VerificationKey2020",
              "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
              "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            }
        ]
    }

    # did_doc_algo_2
    {
        "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19",
        "authentication": [
            {
                "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19#key-2",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19",
                "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            }
        ],
        "keyAgreement": [
            {
                "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19#key-1",
                "type": "X25519KeyAgreementKey2020",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQxIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTEiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX19",
                "publicKeyMultibase": "z6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud"
            }
        ],
        "service": [
            {
                "id": "#service",
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "https://example.com/endpoint1",
                    "routingKeys": [
                        "did:example:somemediator#somekey1"
                    ],
                    "accept": [
                        "didcomm/v2", "didcomm/aip2;env=rfc587"
                    ]
                }
            }
        ]
    }

## Assumptions and limitations
- Only static layers [1, 2a, 2b](https://identity.foundation/peer-did-method-spec/#layers-of-support) are supported
- Only `X25519` keys are support for key agreement
- Only `Ed25519` keys are support for authentication
- Supported verification materials (input and in the resolved DID DOC):
    - [Default] 2020 verification materials (`Ed25519VerificationKey2020` and `X25519KeyAgreementKey2020`) with multibase base58 (`publicKeyMultibase`) public key encoding.
    - JWK (`JsonWebKey2020`) using JWK (`publicKeyJwk`) public key encoding
    - 2018/2019 verification materials (`Ed25519VerificationKey2018` and `X25519KeyAgreementKey2019`) using base58 (`publicKeyBase58`) public key encoding.



## How to contribute

Pull requests are welcome!

Pull requests should have a descriptive name, include the summary of all changes made in the pull
request description, and include unit tests that provide good coverage of the feature or fix. A Continuous Integration (
CI)
pipeline is executed on all PRs before review and contributors are expected to address all CI issues identified.

### A Continuous Integration (CI) pipeline does the following jobs:

- Executes all unit tests from the pull request.
- Analyzes code style using ktlint.