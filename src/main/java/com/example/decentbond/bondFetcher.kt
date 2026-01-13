package com.example.decentbond

import android.content.Context
import kotlinx.coroutines.withContext
import java.io.File

object BondFetcher {

    suspend fun fetchAndPersistBonds(context: Context) {
        val bonds = fetchBonds()
        bonds.forEach { bondStr ->
            val bond = Bond.fromJsonString(bondStr) ?: return@forEach
            writeBond(context, bond)
        }
    }

    private fun writeBond(ctx: Context, bond: Bond) {
        val file = File(bondsFolder(ctx), bond.nonce)
        file.writeText(bond.toJsonString())
    }
}