package com.example.decentbond

import android.content.Context
import android.util.Log
import fi.iki.elonen.NanoHTTPD
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

private const val TAG = "SimpleHttpServer"

class SimpleHttpServer(
    host: String,
    port: Int,
    private val context: Context          // <-- added
) : NanoHTTPD(host, port) {

    override fun serve(session: IHTTPSession): Response {
        val uri = session.uri
        return when {
            uri == "/discover" && session.method == Method.GET -> handleDiscover()
            uri == "/bonds" && session.method == Method.GET -> handleBonds()
            else -> newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "Not Found")
        }
    }

    /** Returns JSON: { "public_key": "...", "ip": "<local_ip>" } */
    private fun handleDiscover(): Response {
        val pk = KeyUtils.getPublicKeyPemBase64Url()
        val ip = getLocalIpAddress(context) ?: "0.0.0.0"
        val json = JSONObject().apply {
            put("public_key", pk)
            put("ip", ip)
        }
        Log.i(TAG, "Responding to /discover from $ip")
        return newFixedLengthResponse(Response.Status.OK, "application/json", json.toString())
    }

    /** Returns a JSON array of all bond JSON strings stored locally */
    private fun handleBonds(): Response {
        val folder = bondsFolder(context)
        val array = JSONArray()
        if (folder.isDirectory) {
            folder.listFiles()?.forEach { f ->
                try {
                    array.put(f.readText())
                } catch (e: Exception) {
                    Log.w(TAG, "Could not read bond ${f.name}", e)
                }
            }
        }
        return newFixedLengthResponse(Response.Status.OK, "application/json", array.toString())
    }
}