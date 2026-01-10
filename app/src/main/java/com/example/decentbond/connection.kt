package com.example.decentbond

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Base64
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.LinkProperties

private const val TAG = "HolePunch"

private val httpClient = OkHttpClient.Builder()
    .retryOnConnectionFailure(true)
    .build()

/**
 * 1️⃣  Store a connection request on the server
 */
suspend fun postConnectionRequest(
    context: Context,
    targetPublicKey: String
): Result<Unit> = withContext(Dispatchers.IO) {
    try {
        val reqBody = JSONObject()
            .put("target_public_key", targetPublicKey)
            .put("requester_public_key", KeyUtils.getPublicKeyPemBase64Url())
            .toString()
            .toRequestBody("application/json".toMediaTypeOrNull())

        val resp = httpClient.newCall(
            Request.Builder()
                .url("http://${serverIp.value}:8080/storeConnectionRequest")
                .post(reqBody)
                .build()
        ).execute()

        if (!resp.isSuccessful) {
            return@withContext Result.failure(
                Exception("Server rejected request: ${resp.code}")
            )
        }
        Result.success(Unit)
    } catch (e: Exception) {
        Result.failure(e)
    }
}

/**
 * 2️⃣  Retrieve & consume a pending request for *this* device
 */
suspend fun getConnectionRequest(
    context: Context
): Result<String> = withContext(Dispatchers.IO) {
    try {
        val pk = KeyUtils.getPublicKeyPemBase64Url()
        val resp = httpClient.newCall(
            Request.Builder()
                .url("http://${serverIp.value}:8080/getConnectionRequest?public_key=$pk")
                .get()
                .build()
        ).execute()

        if (!resp.isSuccessful) {
            return@withContext Result.failure(
                Exception("Server returned ${resp.code}")
            )
        }

        val body = resp.body?.string() ?: ""
        val json = JSONObject(body)
        val requesterPk = json.getString("requester_public_key")
        Result.success(requesterPk)
    } catch (e: Exception) {
        Result.failure(e)
    }
}

/**
 * 3️⃣  Lookup a public key → IP/port mapping
 */
suspend fun lookupIP(
    context: Context,
    publicKey: String
): Result<InetSocketAddress> = withContext(Dispatchers.IO) {
    try {
        val resp = httpClient.newCall(
            Request.Builder()
                .url("http://${serverIp.value}:8080/lookup?public_key=$publicKey")
                .get()
                .build()
        ).execute()

        if (!resp.isSuccessful) {
            return@withContext Result.failure(
                Exception("Lookup failed: ${resp.code}")
            )
        }

        val body = resp.body?.string() ?: ""
        val json = JSONObject(body)
        val ip = json.getString("ip")           // e.g. "203.0.113.42:45678"
        val addr = InetSocketAddress.createUnresolved(ip, 0) // will resolve later
        Result.success(addr)
    } catch (e: Exception) {
        Result.failure(e)
    }
}

/**
 * 4️⃣  Send a one‑byte UDP packet to the remote endpoint
 *      – this is the classic “hole punching” trick.
 */
suspend fun sendHolePunchPacket(
    remoteAddr: InetSocketAddress,
    localPort: Int = 0   // 0 = OS chooses random port
) {
    withContext(Dispatchers.IO) {
        try {
            val socket = DatagramSocket(localPort)
            val packet = DatagramPacket(
                byteArrayOf(0x01),          // payload can be anything
                1,
                InetAddress.getByName(remoteAddr.hostString),
                remoteAddr.port
            )
            socket.send(packet)
            socket.close()
            Log.i(TAG, "Sent hole‑punch packet to ${remoteAddr.hostString}:${remoteAddr.port}")
        } catch (e: Exception) {
            Log.w(TAG, "Hole‑punch failed: ${e.message}")
        }
    }
}

/**
 * 5️⃣  Determine whether two IP addresses are on the same LAN
 *      (simple /24 subnet check).  If yes we’ll punch locally instead.
 */
private fun onSameSubnet(localIp: String, remoteIp: String): Boolean {
    // Convert dotted‑quad to ints
    val local = localIp.split(".").map { it.toInt() }
    val remote = remoteIp.split(".").map { it.toInt() }
    return local.take(3) == remote.take(3)
}

/**
 * 6️⃣  Public helper – starts a long‑running coroutine that
 *      polls the server for incoming requests and punches holes.
 *
 *      Call this once from BondSyncService.onCreate().
 */
fun startHolePunchingService(
    context: Context,
    job: Job,
    intervalMs: Long = 5_000L   // 5 s
) {
    val scope = CoroutineScope(Dispatchers.IO + job)

    scope.launch {
        while (isActive) {
            try {
                // 1️⃣  Ask the server for a pending request
                val result = getConnectionRequest(context)
                if (result.isSuccess) {
                    val requesterPk = result.getOrThrow()
                    Log.i(TAG, "Got request from $requesterPk")

                    // 2️⃣  Resolve requester's external IP/port
                    val lookup = lookupIP(context, requesterPk)
                    if (lookup.isFailure) {
                        Log.w(TAG, "Could not look up IP: ${lookup.exceptionOrNull()}")
                        continue
                    }
                    val remoteAddr = lookup.getOrThrow()

                    // 3️⃣  If we are on the same LAN, punch locally
                    val localIp = getLocalIpAddress(context)?: "0.0.0.0"
                    val remoteIp = remoteAddr.hostString
                    val punchAddr = if (onSameSubnet(localIp, remoteIp)) {
                        InetSocketAddress.createUnresolved(localIp, remoteAddr.port)
                    } else remoteAddr

                    // 4️⃣  Send the UDP packet
                    sendHolePunchPacket(punchAddr)

                    // 5️⃣  (Optional) open a TCP socket / start a listener here
                    //      For a demo we stop after the first request – in a real
                    //      app you would keep the connection alive.
                }
            } catch (e: Exception) {
                Log.w(TAG, "Hole‑punch loop error: ${e.message}")
            }

            delay(intervalMs)
        }
    }
}

/**
 * Utility: fetch the device’s current Wi‑Fi IP address
 */

fun getHotspotIp(context: Context): String? {
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val network = cm.activeNetwork ?: return null
    val linkProps = cm.getLinkProperties(network) ?: return null

    // Usually the hotspot interface is the only one with a link local IPv4 address
    for (addr in linkProps.linkAddresses) {
        if (addr.address is java.net.Inet4Address && !addr.address.isLoopbackAddress) {
            return addr.address.hostAddress
        }
    }
    return null
}
fun getLocalIpAddress(context: Context): String? {
    // First try Wi‑Fi connection info (client mode)
    val wifi = context.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    val ipInt = wifi?.connectionInfo?.ipAddress ?: 0
    if (ipInt != 0) {
        val ip = (ipInt and 0xFF) or ((ipInt shr 8) and 0xFF shl 8) or
                ((ipInt shr 16) and 0xFF shl 16) or ((ipInt shr 24) and 0xFF shl 24)
        return InetAddress.getByAddress(byteArrayOf(
            (ip and 0xFF).toByte(),
            ((ip shr 8) and 0xFF).toByte(),
            ((ip shr 16) and 0xFF).toByte(),
            ((ip shr 24) and 0xFF).toByte()
        )).hostAddress
    }

    // If that fails, try enumerating interfaces
    return getHotspotIp(context) // or any of the other helpers above
}