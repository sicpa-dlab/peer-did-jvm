package org.dif.peerdid.core

import org.dif.peerdid.PEER_DID_NUMALGO_2
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
            mapOf(
                "id" to PEER_DID_NUMALGO_2 + "#didcommmessaging-0",
                "type" to "DIDCommMessaging",
                "serviceEndpoint" to "https://example.com/endpoint",
                "routingKeys" to listOf("did:example:somemediator#somekey"),
                "accept" to listOf("didcomm/v2", "didcomm/aip2;env=rfc587"),
            )
        )
        val service = decodeService(
            "eyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
            PEER_DID_NUMALGO_2
        )
        assertEquals(expected, service)
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
            mapOf(
                "id" to PEER_DID_NUMALGO_2 + "#didcommmessaging-0",
                "type" to "DIDCommMessaging",
                "serviceEndpoint" to "https://example.com/endpoint"
            )
        )
        val service = decodeService(
            "eyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
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
            mapOf(
                "id" to PEER_DID_NUMALGO_2 + "#didcommmessaging-0",
                "type" to "DIDCommMessaging",
                "serviceEndpoint" to "https://example.com/endpoint",
                "routingKeys" to listOf("did:example:somemediator#somekey"),
                "accept" to listOf("didcomm/v2", "didcomm/aip2;env=rfc587")
            ),
            mapOf(
                "id" to PEER_DID_NUMALGO_2 + "#didcommmessaging-1",
                "type" to "DIDCommMessaging",
                "serviceEndpoint" to "https://example.com/endpoint2",
                "routingKeys" to listOf("did:example:somemediator#somekey2")
            )
        )
        val service = decodeService(
            "W3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il0sImEiOlsiZGlkY29tbS92MiIsImRpZGNvbW0vYWlwMjtlbnY9cmZjNTg3Il19LHsidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQyIiwiciI6WyJkaWQ6ZXhhbXBsZTpzb21lbWVkaWF0b3Ijc29tZWtleTIiXX1d",
            PEER_DID_NUMALGO_2
        )
        assertEquals(expected, service)
    }
}
