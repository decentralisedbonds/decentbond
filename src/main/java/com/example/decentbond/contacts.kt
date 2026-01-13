package com.example.decentbond

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.collections.plus

private const val KEYS_FILE = "contacts.json"

data class Contact(
    val publicKey: String,
    var username: String? = null,
    var info: String? = null
){
    /** Convert the request to a JSON string – no serialization library needed. */
    fun toJsonString(): String {
        val json = JSONObject()
        json.put("publickey", publicKey)
        json.put("username", username)
        json.put("info", info)
        return json.toString()
    }
    companion object {
        fun fromJsonObject(obj: JSONObject): Contact {
            val publicKey = obj.getString("publickey")
            val username =
                if (obj.has("username") && !obj.isNull("username")) obj.getString("username") else null
            val info = if (obj.has("info") && !obj.isNull("info")) obj.getString("info") else null
            return Contact(publicKey, username, info)
        }
    }
}

// -----------------------------------------------------------------------------
// 2️⃣  Persistence helpers
// -----------------------------------------------------------------------------
fun loadContacts(context: Context): MutableList<Contact> {
    val file = File(context.filesDir, KEYS_FILE)

    if (!file.exists()) {
        return mutableListOf()
    }

    return try {
        val jsonText = file.readText()
        val jsonArray = JSONArray(jsonText)
        val result = mutableListOf<Contact>()

        for (i in 0 until jsonArray.length()) {
            val obj = jsonArray.getJSONObject(i)
            result.add(Contact.fromJsonObject(obj))
        }

        result
    } catch (e: Exception) {
        // Any parsing error → return an empty list (you could also log the error)
        mutableListOf()
    }
}

fun saveContacts(context: Context, contacts: List<Contact>) {
    val file = File(context.filesDir, KEYS_FILE)

    var i = 1
    file.delete()
    file.writeText("[")
    for(contact in contacts) {
        if(i>1){
            file.appendText(",")
        }
        file.appendText(contact.toJsonString())
        i += 1
    }
    file.appendText("]")
}

fun lookupUsername(publickey: String, context: Context): String?{
    val contacts = loadContacts(context)
    for(contact in contacts){
        if(contact.publicKey==publickey){
            return contact.username.toString()
        }
    }
    return null
}

suspend fun newContact(context: Context, publickey: String) {
    val contacts = loadContacts(context)
    val newContact = lookupContact(publickey)   // ← new helper
    if (newContact != null){
        saveContacts(context, contacts + newContact)
    }

}