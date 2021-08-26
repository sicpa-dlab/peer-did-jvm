package org.peerdid.peerdid

class PeerDIDUtils {
    fun isPeerDID(peerDID: String): Boolean {
        val regex =
            (
                "^did:peer:(([0](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))" +
                    "|(2((.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))+(.(S)[0-9a-zA-Z=]*)?)))$"
                ).toRegex()
        return regex.matches(peerDID)
    }
}
