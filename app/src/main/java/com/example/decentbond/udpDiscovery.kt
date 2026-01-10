import android.content.Context
import android.util.Log
import com.example.decentbond.KeyUtils
import com.example.decentbond.getLocalIpAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

private const val DISCOVERY_PORT = 5051          // UDP port used for discovery
private const val DISCOVERY_MSG  = "DISCOVER_REQUEST" // marker string
private const val DISCOVERY_TIMEOUT_MS = 2000L      // wait for 2 s for replies
private const val TAG = "LanDiscovery"

/**
 * Listens for UDP broadcast packets on [DISCOVERY_PORT] and replies
 * with a JSON payload containing the device’s public key and IP.
 * Runs forever (or until the coroutine scope is cancelled).
 *
 * The responder now ignores any packet that originates from this device
 * itself (loopback or same local IP) so that the app will only reply to
 * other devices on the LAN.
 */
fun startDiscoveryResponder(scope: CoroutineScope, context: Context) {
    scope.launch(Dispatchers.IO) {
        // Create a socket that listens on the discovery port
        val socket = DatagramSocket(DISCOVERY_PORT).apply {
            reuseAddress = true
        }

        // Resolve the local IP once so we can quickly compare incoming packets
        val localIpStr = getLocalIpAddress(context) ?: "0.0.0.0"
        val localIp = try {
            InetAddress.getByName(localIpStr)
        } catch (e: Exception) {
            // Fallback to an address that will never match
            InetAddress.getByName("0.0.0.0")
        }

        Log.i(TAG, "UDP discovery responder listening on $DISCOVERY_PORT")

        val buf = ByteArray(1024)

        while (isActive) {
            Log.i(TAG, "UDP discovery responder active")
            try {
                val packet = DatagramPacket(buf, buf.size)
                socket.receive(packet)

                // Skip packets that originated from this device
                val srcAddr = packet.address
                if (srcAddr.hostAddress == localIp.hostAddress || srcAddr.isLoopbackAddress) {
                    Log.d(TAG, "Ignoring packet from self (${srcAddr.hostAddress})")
                    continue
                }

                val msg = String(packet.data, 0, packet.length, Charsets.UTF_8)
                if (msg != DISCOVERY_MSG) continue   // ignore unrelated packets

                // Build JSON reply
                val json = JSONObject().apply {
                    put("public_key", KeyUtils.getPublicKeyPemBase64Url())
                    put("ip", getLocalIpAddress(context) ?: "0.0.0.0")
                }
                val reply = json.toString().toByteArray(Charsets.UTF_8)

                // Echo back to the sender
                val replyPacket = DatagramPacket(
                    reply, reply.size,
                    packet.address, packet.port
                )
                Log.i(TAG, "sent reply to ${packet.address.hostAddress}:${packet.port}")
                socket.send(replyPacket)

            } catch (e: IOException) {
                // Socket closed, or a read error – just log and continue
                Log.w(TAG, "Discovery responder error", e)
            }
        }
        socket.close()
    }
}
