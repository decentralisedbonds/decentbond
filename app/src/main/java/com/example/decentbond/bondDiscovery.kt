package com.example.decentbond

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import java.net.DatagramSocket

private const val TAG = "BondDiscovery"

private const val DISCOVERY_PORT = 5051          // UDP port used for discovery
private const val DISCOVERY_MSG  = "DISCOVER_REQUEST" // marker string
private const val DISCOVERY_TIMEOUT_MS = 2000L      // wait for 2 s for replies

/**
 * Tries to find a device that hosts a `SimpleHttpServer` and
 * whose public key equals [publicKey].
 *
 * The search is performed on the local LAN: the function iterates over the
 * addresses in the same /24 subnet and performs an HTTP GET to
 * http://<ip>:5050/discover.
 *
 * @return the first matching InetSocketAddress or `null` if no match was found.
 */
private val deviceCache = ConcurrentHashMap<String, InetSocketAddress>()

suspend fun discoverDeviceByPublicKey(
    publicKey: String,
    context: Context
): InetSocketAddress? = withContext(Dispatchers.IO) {

    // 1️⃣  Return cached entry first
    deviceCache[publicKey]?.let { return@withContext it }

    // 2️⃣  Build the broadcast address (e.g. 192.168.1.255)
    val localIp = getLocalIpAddress(context) ?: return@withContext null
    val subnet = localIp.substringBeforeLast('.')
    val broadcastIp = "$subnet.255"

    val socket = DatagramSocket().apply {
        soTimeout = DISCOVERY_TIMEOUT_MS.toInt()
        broadcast = true
        reuseAddress = true
    }

    // 3️⃣  Broadcast the discovery request
    val msg = DISCOVERY_MSG.toByteArray(Charsets.UTF_8)
    val packet = DatagramPacket(msg, msg.size,
        InetAddress.getByName(broadcastIp), DISCOVERY_PORT)
    socket.send(packet)

    // 4️⃣  Listen for replies for DISCOVERY_TIMEOUT_MS
    val buf = ByteArray(1024)
    val start = System.currentTimeMillis()

    try {
        while (System.currentTimeMillis() - start < DISCOVERY_TIMEOUT_MS) {
            val replyPacket = DatagramPacket(buf, buf.size)
            socket.receive(replyPacket)

            val body = String(replyPacket.data, 0, replyPacket.length, Charsets.UTF_8)
            val json = JSONObject(body)

            val pk = json.getString("public_key")
            val ip = json.getString("ip")

            if (pk == publicKey) {
                val addr = InetAddress.getByName(ip)
                val result = InetSocketAddress(addr, 5050)   // HTTP port
                deviceCache[publicKey] = result            // cache it
                Log.i(TAG, "Discovered $publicKey at $ip")
                return@withContext result
            }
        }
    } catch (e: SocketTimeoutException) {
        // No more packets – normal exit
    } catch (e: IOException) {
        Log.w(TAG, "UDP discovery error", e)
    } finally {
        socket.close()
    }

    Log.w(TAG, "No device with public key $publicKey found on the LAN")
    try {
        val lookupResult = lookupIP(context, publicKey).getOrNull()
        if (lookupResult != null) {
            // 1️⃣  Send a hole‑punch packet to open the NAT
            sendHolePunchPacket(lookupResult)

            // 2️⃣  Assume the device hosts its HTTP server on port 5050
            val httpAddr = InetSocketAddress(
                InetAddress.getByName(lookupResult.hostString),
                5050
            )
            deviceCache[publicKey] = httpAddr
            Log.i(TAG, "Discovered $publicKey via NAT traversal at ${httpAddr.hostString}")
            return@withContext httpAddr
        }
    } catch (e: Exception) {
        Log.w(TAG, "NAT traversal lookup failed", e)
    }

    // If we still haven’t found it, give up
    null
}

/**
 * Pulls all bond files from the remote device whose address was found
 * by [discoverDeviceByPublicKey] and stores them into a local
 * `analysis/` folder.
 *
 * @throws IOException if the download or file write fails.
 */
suspend fun pullRemoteBonds(
    publicKey: String,
    context: Context
) = withContext(Dispatchers.IO) {
    val remoteAddr = discoverDeviceByPublicKey(publicKey, context)
        ?: throw IOException("No device with public key $publicKey found")

    val url = "http://${remoteAddr.hostString}:5050/bonds"
    val client = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(3, TimeUnit.SECONDS)
        .build()

    val request = Request.Builder().url(url).get().build()
    client.newCall(request).execute().use { resp ->
        if (!resp.isSuccessful) {
            throw IOException("Failed to download bonds – ${resp.code}")
        }

        val body = resp.body?.string()
            ?: throw IOException("Empty body from $url")

        val array = JSONArray(body)
        val analysisDir = File(context.filesDir, "analysis").apply { mkdirs() }

        repeat(array.length()) { idx ->
            val bondStr = array.getString(idx)
            val json = JSONObject(bondStr)
            val nonce = json.getString("nonce")
            val file = File(analysisDir, nonce)
            file.writeText(bondStr)
        }
    }
}
