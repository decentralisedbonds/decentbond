package com.example.decentbond

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.compose.runtime.*
import com.google.firebase.crashlytics.buildtools.reloc.org.apache.http.client.methods.RequestBuilder.put
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.json.JSONObject
import org.json.JSONArray

/**
 * 1️⃣  A tiny data‑class that holds what we want to persist.
 */
data class UserProfile(
    val username: String = "",
    val info: String = ""
)

/**
 * 2️⃣  DataStore instance – one per app.
 */
private val Context.userProfileDataStore by preferencesDataStore(name = "user_profile")

/**
 * 3️⃣  Repository that talks to DataStore.
 */
object UserProfileRepository {

    private val USERNAME_KEY = stringPreferencesKey("username")
    private val INFO_KEY = stringPreferencesKey("info")

    /** Exposes the profile as a Flow that Compose can observe. */
    fun userProfileFlow(context: Context): Flow<UserProfile> =
        context.userProfileDataStore.data
            .map { prefs ->
                UserProfile(
                    username = prefs[USERNAME_KEY] ?: "",
                    info = prefs[INFO_KEY] ?: ""
                )
            }

    /** Persist a new profile. */
    suspend fun saveProfile(
        context: Context,
        username: String,
        info: String
    ) {
        context.userProfileDataStore.edit { prefs ->
            prefs[USERNAME_KEY] = username
            prefs[INFO_KEY] = info
        }
    }
}