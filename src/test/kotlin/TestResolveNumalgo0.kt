
import com.google.gson.GsonBuilder
import org.dif.peerdid.resolvePeerDID
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class TestResolveNumalgo0 {
    val GSON = GsonBuilder().create()

    @Test
    fun testResolvePositive() {
        val expectedValue = GSON.fromJson(
            """{
            "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            "authentication": {
                "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                "type": "ED25519",
                "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                "publicKeyBase58": "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
            }
        }""",
            Map::class.java
        )
        val realValue = GSON.fromJson(
            resolvePeerDID("did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"),
            Map::class.java
        )
        assert(realValue.equals(expectedValue))
    }

    @Test
    fun testResolveUnsupportedDIDMethod() {
        assertThrows<IllegalArgumentException> { resolvePeerDID("did:key:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveInvalidPeerDID() {
        assertThrows<IllegalArgumentException> { resolvePeerDID("did:peer:0z6MkqRYqQiSBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveUnsupportedNumalgoCode() {
        assertThrows<IllegalArgumentException> { resolvePeerDID("did:key:1z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveMalformedBase58Encoding() {
        assertThrows<IllegalArgumentException> { resolvePeerDID("did:peer:0z6MkqRYqQiSgvZQd0Bytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveUnsupportedTransformCode() {
        assertThrows<IllegalArgumentException> { resolvePeerDID("did:peer:0a6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveMalformedMulticodecEncoding() {
        assertThrows<IllegalArgumentException> { resolvePeerDID("did:peer:0z6666RYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V") }
    }

    @Test
    fun testResolveInvalidKeyType() {
        assertThrows<IllegalArgumentException> { resolvePeerDID("did:peer:0z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc") }
    }
}
