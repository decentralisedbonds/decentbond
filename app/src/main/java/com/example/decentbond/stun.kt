import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import kotlin.experimental.xor

object StunClient {
    private const val TAG = "StunClient"
    private const val MAGIC_COOKIE = 0x2112A442
    private const val BINDING_REQUEST = 0x0001
    private const val BINDING_RESPONSE = 0x0101
    private const val MAPPED_ADDRESS = 0x0001
    private const val XOR_MAPPED_ADDRESS = 0x0020
    private const val STUN_HEADER_SIZE = 20

    private val rand = SecureRandom()

    /** Public helper: returns the external IP/port or null on failure */
    suspend fun getExternalAddress(
        stunHost: String = "stun.l.google.com",
        stunPort: Int = 19302
    ): Pair<String, Int>? = withContext(Dispatchers.IO) {
        try {
            val socket = DatagramSocket()          // OS will bind to an available port
            socket.soTimeout = 3000                // 3‑second timeout

            val transactionId = ByteArray(12)
            rand.nextBytes(transactionId)

            val request = buildBindingRequest(transactionId)
            val address = InetAddress.getByName(stunHost)
            val packet = DatagramPacket(request, request.size, address, stunPort)

            socket.send(packet)

            val buf = ByteArray(1024)
            val resp = DatagramPacket(buf, buf.size)
            socket.receive(resp)

            parseBindingResponse(resp.data, resp.length)
        } catch (e: Exception) {
            Log.e(TAG, "STUN error", e)
            null
        }
    }

    /** Builds a 20‑byte STUN binding request */
    private fun buildBindingRequest(txId: ByteArray): ByteArray {
        val bb = ByteBuffer.allocate(STUN_HEADER_SIZE)
        bb.putShort(BINDING_REQUEST.toShort())         // Message type
        bb.putShort(0)                                 // Message length (no attributes)
        bb.putInt(MAGIC_COOKIE)                        // Magic cookie
        bb.put(txId)                                   // Transaction ID
        return bb.array()
    }

    /** Parses the response and extracts the mapped IP/port */
    private fun parseBindingResponse(data: ByteArray, len: Int): Pair<String, Int>? {
        if (len < STUN_HEADER_SIZE) return null

        val bb = ByteBuffer.wrap(data, 0, len)
        val msgType = bb.short
        val msgLen  = bb.short
        val cookie  = bb.int
        val txId    = ByteArray(12)
        bb.get(txId)

        if (msgType.toInt() != BINDING_RESPONSE || cookie != MAGIC_COOKIE) return null

        var offset = STUN_HEADER_SIZE
        while (offset + 4 <= len) {
            val attrType = ByteBuffer.wrap(data, offset, 2).short.toInt()
            val attrLen  = ByteBuffer.wrap(data, offset + 2, 2).short.toInt()
            offset += 4
            if (offset + attrLen > len) break

            when (attrType) {
                MAPPED_ADDRESS -> {
                    // RFC 5389 recommends XOR‑MAPPED‑ADDRESS, but many servers still send MAPPED‑ADDRESS
                    val family = data[offset + 1]
                    val port = ((data[offset + 2].toInt() and 0xFF) shl 8) or
                            (data[offset + 3].toInt() and 0xFF)
                    val ipBytes = data.copyOfRange(offset + 4, offset + 8)
                    return Pair(ipBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }, port)
                }
                XOR_MAPPED_ADDRESS -> {
                    // RFC 5389: XOR the port with the magic cookie, XOR the IP with the cookie
                    val family = data[offset + 1]
                    val port = ((data[offset + 2].toInt() and 0xFF) shl 8) or
                            (data[offset + 3].toInt() and 0xFF)
                    val xorPort = port xor (MAGIC_COOKIE shr 16)

                    val ipBytes = ByteArray(4)
                    for (i in 0 until 4) {
                        ipBytes[i] = (data[offset + 4 + i] xor ((MAGIC_COOKIE ushr (24 - i * 8)) and 0xFF).toByte())
                    }
                    val ip = ipBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
                    return Pair(ip, xorPort)
                }
            }
            offset += attrLen
            // Attributes are padded to 4‑byte boundaries
            if (attrLen % 4 != 0) offset += 4 - (attrLen % 4)
        }

        return null
    }
}