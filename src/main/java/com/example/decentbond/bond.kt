package com.example.decentbond

import org.json.JSONObject
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Locale

data class Bond(
    val amount: ULong,
    val currency: String,
    val timedate: String,
    val sender: String,
    val receiver: String,
    val nonce: String,
    val checksum: String
) {
    /** Convert a *Bond* into a JSON object – exactly what the server expects. */
    fun toJsonObject(): JSONObject = JSONObject().apply {
        put("amount", amount.toLong())
        put("currency", currency)
        put("timedate", timedate)
        put("sender", sender)
        put("receiver", receiver)
        put("nonce", nonce)
        put("checksum", checksum)
    }

    /** Helper for the UI.  Only the raw bond string is needed for the graph. */
    fun toJsonString(): String = toJsonObject().toString()

    companion object
}
fun Bond.Companion.fromJsonString(bondStr: String) = try {
    val obj = JSONObject(bondStr)
    Bond(
        amount = obj.getLong("amount").toULong(),
        currency = obj.getString("currency"),
        timedate = obj.getString("timedate"),
        sender = obj.getString("sender"),
        receiver = obj.getString("receiver"),
        nonce = obj.getString("nonce"),
        checksum = obj.getString("checksum")
    )
} catch (e: Exception) {
    null
}