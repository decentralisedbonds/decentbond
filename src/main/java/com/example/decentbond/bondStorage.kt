package com.example.decentbond

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

private const val BONDS_DIR = "bonds"
private const val ANALYSIS_DIR = "analysis"

fun bondsFolder(ctx: Context) = File(ctx.filesDir, BONDS_DIR).apply { if (!exists()) mkdirs() }
fun analysisFolder(ctx: Context) = File(ctx.filesDir, ANALYSIS_DIR).apply { if (!exists()) mkdirs() }

fun loadBonds(ctx: Context): List<Bond> {
    val folder = bondsFolder(ctx)
    if (!folder.isDirectory) return emptyList()
    return folder.listFiles()
        ?.mapNotNull { Bond.fromJsonString(it.readText()) }
        ?: emptyList()
}

fun loadJsonBonds(ctx: Context): List<JSONObject> {
    val folder = bondsFolder(ctx)
    if (!folder.isDirectory) return emptyList()
    return folder.listFiles()
        ?.mapNotNull { Bond.fromJsonString(it.readText())?.toJsonObject() }
        ?: emptyList()
}