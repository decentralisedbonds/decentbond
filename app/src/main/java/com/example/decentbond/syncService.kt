package com.example.decentbond

import android.app.*
import android.content.*
import android.os.*
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import okhttp3.*
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.Base64
import java.security.PublicKey

/**
 * Foreground service that periodically pulls bonds from the remote server
 * and writes them to the local file system.
 */
class BondSyncService : Service() {

    /* ------------------------------------------------------------------ */
    /*  Companion object – “one‑off” sync that can be called from any     */
    /*  Activity / Fragment (e.g. MainActivity)                          */
    /* ------------------------------------------------------------------ */
    companion object {
        private const val TAG = "BondSyncService"
        private val client = OkHttpClient.Builder()
            .retryOnConnectionFailure(true)
            .build()
        private const val CHANNEL_ID = "bond_sync_channel"
        private const val NOTIFICATION_ID = 1
        private const val POLL_INTERVAL_MS = 1_000L          // 30 s, change if you want
        private const val MAX_RETRY_DELAY_MS = 60*5_000L    // 5 min max back‑off
        /**
         * Run the same logic that `startPolling()` runs – but **once**.
         *
         * @param context  The context needed to write the bond files.
         */
        suspend fun pollOnce(context: Context) {
            try {
                Log.d(TAG, "Polling server for bonds…")
                val bonds = fetchBondsFromServer()
                if (bonds.isNotEmpty()) {
                    Log.i(TAG, "Received ${bonds.size} bond(s), writing to disk")
                    bonds.forEach { bondJson -> writeBondToDisk(context, bondJson) }
                } else {
                    Log.d(TAG, "No bonds currently available")
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to poll bonds – ${e.message}")
            }
        }

        /* ------------------------------------------------------------------ */
        /*  Server communication – identical to the Service implementation   */
        /* ------------------------------------------------------------------ */
        private suspend fun fetchBondsFromServer(): List<String> {
            // 1️⃣  Get a fresh nonce
            val challengeUrl =
                "http://${serverIp.value}:8080/challenge?public_key=${KeyUtils.getPublicKeyPemBase64Url()}"
            val challengeResp = client.newCall(
                Request.Builder()
                    .url(challengeUrl)
                    .get()
                    .build()
            ).execute()

            if (!challengeResp.isSuccessful) {
                throw IOException("Challenge endpoint returned ${challengeResp.code}")
            }

            val challengeBody = challengeResp.body?.string()
                ?: throw IOException("Challenge response had no body")
            val nonceB64 = JSONObject(challengeBody).getString("nonce")
            val nonce = Base64.getUrlDecoder().decode(nonceB64)

            // 2️⃣  Sign the nonce with our private key
            val sig = KeyUtils.signData(nonce)          // returns raw bytes
            val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)

            // 3️⃣  Call /bonds with signature
            val bondsUrl = "http://${serverIp.value}:8080/bonds" +
                    "?public_key=${KeyUtils.getPublicKeyPemBase64Url()}" +
                    "&signature=${sigB64}"

            val bondsResp = client.newCall(
                Request.Builder()
                    .url(bondsUrl)
                    .get()
                    .build()
            ).execute()

            if (!bondsResp.isSuccessful) {
                throw IOException("Bonds endpoint returned ${bondsResp.code}")
            }

            val body = bondsResp.body?.string()
                ?: throw IOException("Bonds response had no body")

            // The server returns a JSON array of bond strings
            return JSONArray(body).let { array ->
                List(array.length()) { idx -> array.getString(idx) }
            }
        }

        /* ------------------------------------------------------------------ */
        /*  Persistence – write each bond to <nonce>.json                     */
        /* ------------------------------------------------------------------ */
        private fun writeBondToDisk(context: Context, bondJson: String) {
            // Parse the bond so we can grab the nonce field
            val json = JSONObject(bondJson)
            val nonce = json.optString("nonce")
                ?: throw IllegalArgumentException("Bond JSON missing nonce field")

            val checksumB64 = json.optString("checksum") ?: run {
                Log.w(TAG, "Bond $nonce missing checksum – skipping")
                return
            }

            val senderKeyB64 = json.optString("sender") ?: run {
                Log.w(TAG, "Bond $nonce missing sender key – skipping")
                return
            }

            // Build the payload that was signed by the sender
            val payload = JSONObject().apply {
                put("amount", json.getLong("amount"))
                put("currency", json.getString("currency"))
                put("timedate", json.getString("timedate"))
                put("sender", json.getString("sender"))
                put("receiver", json.getString("receiver"))
                put("nonce", json.getString("nonce"))
            }

            val payloadBytes = payload.toString().toByteArray(Charsets.UTF_8)
            val signatureBytes = Base64.getUrlDecoder().decode(checksumB64)

            val publicKey: PublicKey = try {
                KeyUtils.publicKeyFromBase64Url(senderKeyB64)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to reconstruct sender's public key for bond $nonce", e)
                return
            }

            val verified: Boolean = try {
                KeyUtils.verifySignatureWithPublicKey(payloadBytes, signatureBytes, publicKey)
            } catch (e: Exception) {
                Log.e(TAG, "Signature verification failed for bond $nonce", e)
                false
            }

            if (!verified) {
                Log.w(TAG, "Signature check failed – bond $nonce discarded")
                return
            }

            val folder = bondsFolder(context)
            val file = File(folder, nonce)
            file.writeText(bondJson)
        }
    }

    /* ------------------------------------------------------------------ */
    /*  Service life‑cycle – unchanged – only kept for reference          */
    /* ------------------------------------------------------------------ */

    private val job = Job()
    private val scope = CoroutineScope(Dispatchers.IO + job)
    private val client = OkHttpClient.Builder()
        .retryOnConnectionFailure(true)
        .build()

    /* ------------------------------------------------------------------ */
    /*  Lifecycle -------------------------------------------------------- */
    /* ------------------------------------------------------------------ */

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Service created – starting poll loop")
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        startPolling()
        // NEW: start the NAT‑traversal loop
        startHolePunchingService(this, job)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // We are already running – just keep going
        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "Service destroyed – canceling coroutines")
        job.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /* ------------------------------------------------------------------ */
    /*  Notification helpers --------------------------------------------- */
    /* ------------------------------------------------------------------ */

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Bond sync service",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Background sync of bonds from the central server"
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Bond sync")
            .setContentText("Synchronising bonds in the background")
            .setSmallIcon(R.drawable.icon)   // replace with an icon you have
            .setOngoing(true)
            .build()
    }

    /* ------------------------------------------------------------------ */
    /*  Poll loop -------------------------------------------------------- */
    /* ------------------------------------------------------------------ */

    private fun startPolling() {
        scope.launch {
            var retryDelay = POLL_INTERVAL_MS

            while (isActive) {
                try {
                    Log.d(TAG, "Polling server for bonds…")
                    val bonds = fetchBondsFromServer()
                    if (bonds.isNotEmpty()) {
                        Log.i(TAG, "Received ${bonds.size} bond(s), writing to disk")
                        bonds.forEach { writeBondToDisk(it) }
                        // reset back‑off on success
                        retryDelay = POLL_INTERVAL_MS
                    } else {
                        Log.d(TAG, "No bonds currently available")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to poll bonds – ${e.message}")
                    // exponential back‑off, capped at MAX_RETRY_DELAY_MS
                    retryDelay = (retryDelay * 2).coerceAtMost(MAX_RETRY_DELAY_MS)
                }

                delay(retryDelay)
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /*  Server communication -------------------------------------------- */
    /* ------------------------------------------------------------------ */

    private suspend fun fetchBondsFromServer(): List<String> {
        // 1️⃣  Get a fresh nonce
        val challengeUrl = "http://${serverIp.value}:8080/challenge?public_key=${KeyUtils.getPublicKeyPemBase64Url()}"
        val challengeResp = client.newCall(
            Request.Builder()
                .url(challengeUrl)
                .get()
                .build()
        ).execute()

        if (!challengeResp.isSuccessful) {
            throw IOException("Challenge endpoint returned ${challengeResp.code}")
        }

        val challengeBody = challengeResp.body?.string()
            ?: throw IOException("Challenge response had no body")
        val nonceB64 = JSONObject(challengeBody).getString("nonce")
        val nonce = Base64.getUrlDecoder().decode(nonceB64)

        // 2️⃣  Sign the nonce with our private key
        val sig = KeyUtils.signData(nonce)          // returns raw bytes
        val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)

        // 3️⃣  Call /bonds with signature
        val bondsUrl = "http://${serverIp.value}:8080/bonds" +
                "?public_key=${KeyUtils.getPublicKeyPemBase64Url()}" +
                "&signature=${sigB64}"

        val bondsResp = client.newCall(
            Request.Builder()
                .url(bondsUrl)
                .get()
                .build()
        ).execute()

        if (!bondsResp.isSuccessful) {
            throw IOException("Bonds endpoint returned ${bondsResp.code}")
        }

        val body = bondsResp.body?.string()
            ?: throw IOException("Bonds response had no body")

        // The server returns a JSON array of bond strings
        return JSONArray(body).let { array ->
            List(array.length()) { idx -> array.getString(idx) }
        }
    }

    /* ------------------------------------------------------------------ */
    /*  Persistence – write each bond to <nonce>.json ------------------ */
    /* ------------------------------------------------------------------ */

    private fun writeBondToDisk(bondJson: String) {
        // Parse the bond so we can grab the nonce field
        val json = JSONObject(bondJson)
        val nonce = json.optString("nonce")
            ?: throw IllegalArgumentException("Bond JSON missing nonce field")

        val checksumB64 = json.optString("checksum") ?: run {
            Log.w(TAG, "Bond $nonce missing checksum – skipping")
            return
        }

        val senderKeyB64 = json.optString("sender") ?: run {
            Log.w(TAG, "Bond $nonce missing sender key – skipping")
            return
        }

        val payload = JSONObject().apply {
            put("amount", json.getLong("amount"))
            put("currency", json.getString("currency"))
            put("timedate", json.getString("timedate"))
            put("sender", json.getString("sender"))
            put("receiver", json.getString("receiver"))
            put("nonce", json.getString("nonce"))
        }

        val payloadBytes = payload.toString().toByteArray(Charsets.UTF_8)
        val signatureBytes = Base64.getUrlDecoder().decode(checksumB64)

        val publicKey: PublicKey
        try {
            publicKey = KeyUtils.publicKeyFromBase64Url(senderKeyB64)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to reconstruct sender's public key for bond $nonce", e)
            return
        }

        val verified: Boolean = try {
            KeyUtils.verifySignatureWithPublicKey(payloadBytes, signatureBytes, publicKey)
        } catch (e: Exception) {
            Log.e(TAG, "Signature verification failed for bond $nonce", e)
            false
        }

        if (!verified) {
            Log.w(TAG, "Signature check failed – bond $nonce discarded")
            return
        }

        val folder = bondsFolder(this)
        val file = File(folder, nonce)
        file.writeText(bondJson)
    }
}