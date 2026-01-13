// ──────────────────────────────────────────────────────────────────────
//  ServerApi – a thin HTTP wrapper around the RSA‑2048 HTTPS server
//  (written in the “pasted” style – one coroutine, plain OkHttp, no Result)
// ──────────────────────────────────────────────────────────────────────
package com.example.decentbond

import android.util.Log
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.security.PublicKey
import java.util.Base64
import kotlinx.coroutines.flow.first

private const val TAG = "ServerApi"

/**
 * Sign a byte array with the local private key (raw RSA‑SHA256) and
 * return a URL‑safe Base64 string (no padding).
 */
private fun signData(bytes: ByteArray): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(KeyUtils.signData(bytes))

/**
 * Retrieve the challenge nonce from the server, decode it to bytes
 * and sign it.  Returns the raw nonce string and its signature.
 */
private suspend fun fetchAndSignNonce(): Pair<String, String> =
    withContext(Dispatchers.IO) {
        // 1️⃣ GET /challenge
        val challengeRequest = Request.Builder()
            .url("https://${serverIp.value}:443/challenge?public_key=${KeyUtils.getPublicKeyPemBase64Url()}")
            .get()
            .build()

        client.newCall(challengeRequest).execute().use { resp ->
            if (!resp.isSuccessful) {
                throw IOException("Challenge request failed: ${resp.code}")
            }
            val body = resp.body?.string()
                ?: throw IOException("Empty challenge body")
            val nonceB64 = JSONObject(body).getString("nonce")
            val nonceBytes = Base64.getUrlDecoder().decode(nonceB64)
            val signature = signData(nonceBytes)
            Pair(nonceB64, signature)
        }
    }

/**
 * A single OkHttp client reused across all requests.
 */
private val client = OkHttpClient.Builder()
    .retryOnConnectionFailure(true)
    .build()

// ──────────────────────────────────────────────────────────────────────
//  Public API – one function per endpoint
// ──────────────────────────────────────────────────────────────────────

/** 1️⃣  GET /challenge?public_key=…   */
suspend fun getChallenge(): String =
    fetchAndSignNonce().first

/** ---------------------------------------------------------------------
//  /gdprAccepted – POST – requires pk, name, datetime, contact, client_pk,
//  signature
// --------------------------------------------------------------------- */
suspend fun gdprAccepted(name: String, datetime: String, contact: String): Boolean =
    withContext(Dispatchers.IO) {
        try {
            val (_, signature) = fetchAndSignNonce()
            val body = JSONObject()
                .put("public_key", KeyUtils.getPublicKeyPemBase64Url())
                .put("name", name)
                .put("datetime", datetime)
                .put("contact", contact)
                .put("signature", signature)

            val request = Request.Builder()
                .url("https://${serverIp.value}:443/gdprAccepted")
                .post(body.toString().toRequestBody("application/json".toMediaTypeOrNull()))
                .build()

            client.newCall(request).execute().use { resp ->
                val bodyStr = resp.body?.string()
                if (!resp.isSuccessful || bodyStr == null) throw IOException("HTTP ${resp.code}")
                val respJson = JSONObject(bodyStr)
                respJson.optBoolean("ok", false)
            }
        } catch (e: Exception) {
            Log.e(TAG, "gdprAccepted failed: ${e.message}", e)
            false
        }
    }

/** ---------------------------------------------------------------------
//  /gdprDelete – POST – requires target_pk, client_pk, signature
// --------------------------------------------------------------------- */
suspend fun gdprDelete(): Boolean =
    withContext(Dispatchers.IO) {
        try {
            val (_, signature) = fetchAndSignNonce()
            val body = JSONObject()
                .put("public_key", KeyUtils.getPublicKeyPemBase64Url())
                .put("signature", signature)

            val request = Request.Builder()
                .url("https://${serverIp.value}:443/gdprDelete")
                .post(body.toString().toRequestBody("application/json".toMediaTypeOrNull()))
                .build()

            client.newCall(request).execute().use { resp ->
                val bodyStr = resp.body?.string()
                if (!resp.isSuccessful || bodyStr == null) throw IOException("HTTP ${resp.code}")
                val respJson = JSONObject(bodyStr)
                respJson.optBoolean("ok", false)
            }
        } catch (e: Exception) {
            Log.e(TAG, "gdprDelete failed: ${e.message}", e)
            false
        }
    }

/** ---------------------------------------------------------------------
//  /register – POST – authenticated, requires client_pk, signature
// --------------------------------------------------------------------- */
suspend fun registerUser( username: String, info: String): Boolean =
    withContext(Dispatchers.IO) {
        try {
            val (_, signature) = fetchAndSignNonce()
            val body = JSONObject()
                .put("public_key", KeyUtils.getPublicKeyPemBase64Url())
                .put("username", username)
                .put("info", info)
                .put("signature", signature)

            val request = Request.Builder()
                .url("https://${serverIp.value}:443/register")
                .post(body.toString().toRequestBody("application/json".toMediaTypeOrNull()))
                .build()

            client.newCall(request).execute().use { resp ->
                val bodyStr = resp.body?.string()
                if (!resp.isSuccessful || bodyStr == null) throw IOException("HTTP ${resp.code}")
                val respJson = JSONObject(bodyStr)
                respJson.optBoolean("ok", false)
            }
        } catch (e: Exception) {
            Log.e(TAG, "registerUser failed: ${e.message}", e)
            false
        }
    }

/** ---------------------------------------------------------------------
//  /lookup – GET – authenticated, requires client_pk, signature
// --------------------------------------------------------------------- */
suspend fun lookupUser(targetPublicKey: String): UserLookup? =
    withContext(Dispatchers.IO) {
        try {
            val (_, signature) = fetchAndSignNonce()
            val url = "https://${serverIp.value}:443/lookup?" +
                    "target_public_key=${targetPublicKey}" +
                    "&public_key=${KeyUtils.getPublicKeyPemBase64Url()}" +
                    "&signature=${signature}"

            val request = Request.Builder()
                .url(url)
                .get()
                .build()

            client.newCall(request).execute().use { resp ->
                val bodyStr = resp.body?.string()
                if (!resp.isSuccessful || bodyStr == null) throw IOException("HTTP ${resp.code}")
                val obj = JSONObject(bodyStr)
                UserLookup(
                    username = obj.optString("username"),
                    info = obj.optString("info")
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "lookupUser failed: ${e.message}", e)
            null
        }
    }

suspend fun lookupContact(publicKey: String): Contact? =
    lookupUser( publicKey)?.let { user ->
        Contact(publicKey, user.username, user.info)
    }

/** ---------------------------------------------------------------------
//  /bonds – GET (retrieve & keep until /clearBonds)
// --------------------------------------------------------------------- */
suspend fun fetchBonds(): List<String> =
    withContext(Dispatchers.IO) {
        try {
            val (_, signature) = fetchAndSignNonce()
            val url = "https://${serverIp.value}:443/bonds?" +
                    "public_key=${KeyUtils.getPublicKeyPemBase64Url()}" +
                    "&signature=${signature}"

            val request = Request.Builder()
                .url(url)
                .get()
                .build()

            client.newCall(request).execute().use { resp ->
                val bodyStr = resp.body?.string()
                if (!resp.isSuccessful || bodyStr == null) throw IOException("HTTP ${resp.code}")
                JSONArray(bodyStr).let { array ->
                    List(array.length()) { i -> array.getString(i) }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "fetchBonds failed: ${e.message}", e)
            emptyList()
        }
    }

/** ---------------------------------------------------------------------
//  /createBond – POST – authenticated, requires client_pk, signature
// --------------------------------------------------------------------- */
suspend fun createBond(bondJson: JSONObject, receiverPk: String): Boolean =
    withContext(Dispatchers.IO) {
        try {
            val (_, signature) = fetchAndSignNonce()
            val body = JSONObject()
                .put("target_public_key", receiverPk)
                .put("bond", bondJson.toString())
                .put("public_key", KeyUtils.getPublicKeyPemBase64Url())
                .put("signature", signature)

            val request = Request.Builder()
                .url("https://${serverIp.value}:443/createBond")
                .post(body.toString().toRequestBody("application/json".toMediaTypeOrNull()))
                .build()

            client.newCall(request).execute().use { resp ->
                val bodyStr = resp.body?.string()
                if (!resp.isSuccessful || bodyStr == null) throw IOException("HTTP ${resp.code}")
                val respJson = JSONObject(bodyStr)
                respJson.optBoolean("ok", false)
            }
        } catch (e: Exception) {
            Log.e(TAG, "createBond failed: ${e.message}", e)
            false
        }
    }

/** ---------------------------------------------------------------------
//  /setAnalysisBonds – POST – authenticated, requires client_pk, signature
// --------------------------------------------------------------------- */
suspend fun setAnalysisBonds( bonds: List<JSONObject>): Boolean =
    withContext(Dispatchers.IO) {
        try {
            val (_, signature) = fetchAndSignNonce()
            val body = JSONObject()
                .put("public_key", KeyUtils.getPublicKeyPemBase64Url())
                .put("analysis_bonds", JSONArray(bonds).toString())
                .put("signature", signature)

            val request = Request.Builder()
                .url("https://$serverIp:443/setAnalysisBonds")
                .post(body.toString().toRequestBody("application/json".toMediaTypeOrNull()))
                .build()

            client.newCall(request).execute().use { resp ->
                val bodyStr = resp.body?.string()
                if (!resp.isSuccessful || bodyStr == null) throw IOException("HTTP ${resp.code}")
                val respJson = JSONObject(bodyStr)
                respJson.optBoolean("ok", false)
            }
        } catch (e: Exception) {
            Log.e(TAG, "setAnalysisBonds failed: ${e.message}", e)
            false
        }
    }

/** ---------------------------------------------------------------------
//  /getAnalysisBonds – POST – public read (no auth)
// --------------------------------------------------------------------- */
suspend fun fetchAnalysisBonds(targetPk: String): List<String> =
    withContext(Dispatchers.IO) {
        try {
            val (_, signature) = fetchAndSignNonce()
            val body = JSONObject()
                .put("public_key", KeyUtils.getPublicKeyPemBase64Url())
                .put("signature", signature)

            val request = Request.Builder()
                .url("https://${serverIp.value}443/getAnalysisBonds?public_key=${targetPk}")
                .post(body.toString().toRequestBody("application/json".toMediaTypeOrNull()))
                .build()

            client.newCall(request).execute().use { resp ->
                val bodyStr = resp.body?.string()
                if (!resp.isSuccessful || bodyStr == null) throw IOException("HTTP ${resp.code}")
                JSONArray(bodyStr).let { array ->
                    List(array.length()) { i -> array.getString(i) }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "fetchAnalysisBonds failed: ${e.message}", e)
            emptyList()
        }
    }

// ──────────────────────────────────────────────────────────────────────
//  Convenience wrappers used by the UI
// ──────────────────────────────────────────────────────────────────────

suspend fun syncAnalysisBonds(serverIp: String, bonds: List<Bond>) =
    setAnalysisBonds(bonds.map { it.toJsonObject() })

suspend fun pushBond(bond: Bond) =
    createBond( bond.toJsonObject(), bond.receiver)

// ──────────────────────────────────────────────────────────────────────
//  Helper to register the local user via the “pasted” style
// ──────────────────────────────────────────────────────────────────────

suspend fun registerToServer(context: Context): String {
    // Load the current profile once
    val storedProfile = UserProfileRepository.userProfileFlow(context).first()

    return withContext(Dispatchers.IO) {
        try {
            /* ---------- 1️⃣  Ask for a challenge ---------- */
            val challengeCall = client.newCall(
                Request.Builder()
                    .url("https://${serverIp.value}:443/challenge?public_key=${KeyUtils.getPublicKeyPemBase64Url()}")
                    .get()
                    .build()
            )
            val challengeResp = challengeCall.execute()
            if (!challengeResp.isSuccessful) {
                return@withContext "Challenge request failed: ${challengeResp.code}"
            }

            val challengeBody = challengeResp.body?.string()
            if (challengeBody == null) {
                return@withContext "Challenge response has no body"
            }

            val challengeJson = JSONObject(challengeBody)
            val nonceB64 = challengeJson.getString("nonce")
            val nonce = Base64.getUrlDecoder().decode(nonceB64)

            /* ---------- 2️⃣  Sign the nonce ---------- */
            val sigBytes = KeyUtils.signData(nonce)

            /* ---------- 3️⃣  Get external IP/port ---------- */
            /*val external = StunClient.getExternalAddress()
            val (ip, port) = external ?: run {
                Log.e("MainActivity", "STUN failed")
                return@withContext "STUN failed"
            }*/
            val ip = "0.0.0.0"
            val port = "443"

            /* ---------- 4️⃣  Send registration ---------- */
            val req = RegistrationRequest(
                publickey = KeyUtils.getPublicKeyPemBase64Url(),
                ip = "$ip:$port",
                nonce = nonceB64,
                signature = Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes),
                username = storedProfile.username,
                info = storedProfile.info
            )

            val reqBody = req.toJsonString()

            val regResp = client.newCall(
                Request.Builder()
                    .url("https://${serverIp.value}:443/register")
                    .post(reqBody.toRequestBody("application/json".toMediaTypeOrNull()))
                    .build()
            ).execute()

            if (regResp.isSuccessful) {
                "Registration succeeded"
            } else {
                val body = regResp.body?.string()
                "Registration failed: ${regResp.code}" +
                        (if (body.isNullOrBlank()) "" else ": $body")
            }
        } catch (e: Exception) {
            val msg = e.localizedMessage ?: e::class.simpleName ?: "Unknown error"
            "Error: $msg"
        }
    }
}