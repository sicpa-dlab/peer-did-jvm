package org.didcommx.peerdid.core

import org.didcommx.peerdid.OtherService
import org.didcommx.peerdid.PEER_DID_NUMALGO_2
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class TestServiceEncodeDecode {

    @Test
    fun testEncodeService() {
        assertEquals(
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
            encodeService(
                """
                        {
                            "type": "DIDCommMessaging",
                            "serviceEndpoint": "https://example.com/endpoint",
                            "routingKeys": ["did:example:somemediator#somekey"],
                            "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
                        }
                        """
            )
        )
    }

    @Test
    fun testDecodeService() {
        val expected = listOf(
            OtherService(
                mapOf(
                    "id" to "#service",
                    "type" to "DIDCommMessaging",
                    "serviceEndpoint" to mapOf(
                        "uri" to "https://example.com/endpoint",
                        "routingKeys" to listOf("did:example:somemediator#somekey"),
                        "accept" to listOf("didcomm/v2", "didcomm/aip2;env=rfc587"),
                    )
                )
            )

        )
        val service = decodeService(
            listOf("eyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"),
            PEER_DID_NUMALGO_2
        )
        assertEquals(expected, service)
    }

    @Test
    fun testEncodeServiceEndpointFields() {
        assertEquals(
            ".SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ",
            encodeService(
                """
                        {
                          "type": "DIDCommMessaging",
                          "serviceEndpoint": {
                            "uri": "http://example.com/didcomm",
                            "accept": [
                              "didcomm/v2"
                            ],
                            "routingKeys": [
                              "did:example:123456789abcdefghi#key-1"
                            ]
                          }
                        }
                        """
            )
        )
    }

    @Test
    fun testEncodeServiceMinimalFields() {
        assertEquals(
            ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
            encodeService(
                """
                        {
                            "type": "DIDCommMessaging",
                            "serviceEndpoint": "https://example.com/endpoint"
                        }
                        """
            )
        )
    }
    @Test
    fun testDecodeServiceMinimalFields() {
        val expected = listOf(
            OtherService(
                mapOf(
                    "id" to "#service",
                    "type" to "DIDCommMessaging",
                    "serviceEndpoint" to mapOf(
                        "uri" to "https://example.com/endpoint",
                    )
                )
            )
        )
        val service = decodeService(
            listOf("eyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9"),
            PEER_DID_NUMALGO_2
        )
        assertEquals(expected, service)
    }

    @Test
    fun testEncodeServiceMultipleEntries() {
        assertEquals(
            ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il0sImEiOlsiZGlkY29tbS92MiIsImRpZGNvbW0vYWlwMjtlbnY9cmZjNTg3Il19LHsidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQyIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTIiXX1d",
            encodeService(
                """
                        [
                            {
                                "type": "DIDCommMessaging",
                                "serviceEndpoint": "https://example.com/endpoint",
                                "routingKeys": ["did:example:somemediator#somekey"],
                                "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
                            },
                            {
                                "type": "DIDCommMessaging",
                                "serviceEndpoint": "https://example.com/endpoint2",
                                "routingKeys": ["did:example:somemediator#somekey2"]
                            }
                        ]
                        """
            )
        )
    }

    @Test
    fun testDecodeServiceMultipleEntries() {
        val expected = listOf(
            OtherService(
                mapOf(
                    "id" to "#service",
                    "type" to "DIDCommMessaging",
                    "serviceEndpoint" to mapOf(
                        "uri" to "https://example.com/endpoint",
                        "routingKeys" to listOf("did:example:somemediator#somekey"),
                        "accept" to listOf("didcomm/v2", "didcomm/aip2;env=rfc587")
                    )
                )
            ),
            OtherService(
                mapOf(
                    "id" to "#service-1",
                    "type" to "DIDCommMessaging",
                    "serviceEndpoint" to mapOf(
                        "uri" to "https://example.com/endpoint2",
                        "routingKeys" to listOf("did:example:somemediator#somekey2"),
                    )
                )
            )
        )
        val service = decodeService(
            listOf("W3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il0sImEiOlsiZGlkY29tbS92MiIsImRpZGNvbW0vYWlwMjtlbnY9cmZjNTg3Il19LHsidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQyIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTIiXX1d"),
            PEER_DID_NUMALGO_2
        )
        assertEquals(expected, service)
    }
    @Test
    fun testDecodeServiceMultipleEntriesIndividualEncoded() {
        val expected = listOf(
            OtherService(
                mapOf(
                    "id" to "#service",
                    "type" to "DIDCommMessaging",
                    "serviceEndpoint" to mapOf(
                        "uri" to "https://example.com/endpoint",
                        "routingKeys" to listOf("did:example:somemediator#somekey"),
                        "accept" to listOf("didcomm/v2", "didcomm/aip2;env=rfc587")
                    )
                )
            ),
            OtherService(
                mapOf(
                    "id" to "#service-1",
                    "type" to "DIDCommMessaging",
                    "serviceEndpoint" to mapOf(
                        "uri" to "https://example.com/endpoint2",
                        "routingKeys" to listOf("did:example:somemediator#somekey2"),
                    )
                )
            )
        )
        val service = decodeService(
            listOf(
                "eyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "eyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdfQ"
            ),
            PEER_DID_NUMALGO_2
        )
        assertEquals(expected, service)
    }
}
