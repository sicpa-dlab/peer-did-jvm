package org.didcommx.peerdid.core

import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken

fun toJson(value: Any?) =
    GsonBuilder().create().toJson(value)

fun fromJsonToList(value: String): List<Map<String, Any>> =
    GsonBuilder().create().fromJson(value, object : TypeToken<List<Map<String, Any>>>() {}.type)

fun fromJsonToMap(value: String): Map<String, Any> =
    GsonBuilder().create().fromJson(value, object : TypeToken<Map<String, Any>>() {}.type)