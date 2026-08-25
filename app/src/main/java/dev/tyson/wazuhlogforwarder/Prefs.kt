package dev.tyson.wazuhlogforwarder

import android.content.Context

/**
 * Thin wrapper around SharedPreferences holding the Wazuh manager destination
 * and user choices. Nothing here is secret-grade; if you need auth beyond
 * network-level trust, put the manager behind a VPN/TLS-terminating proxy.
 */
object Prefs {
    private const val FILE = "wazuh_forwarder_prefs"
    private const val KEY_HOST = "host"
    private const val KEY_PORT = "port"
    private const val KEY_PROTOCOL = "protocol" // "UDP" or "TCP"
    private const val KEY_AUTOSTART = "autostart"
    private const val KEY_RUNNING = "running"

    const val DEFAULT_PORT = 514

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun getHost(ctx: Context): String = prefs(ctx).getString(KEY_HOST, "") ?: ""
    fun setHost(ctx: Context, value: String) = prefs(ctx).edit().putString(KEY_HOST, value).apply()

    fun getPort(ctx: Context): Int = prefs(ctx).getInt(KEY_PORT, DEFAULT_PORT)
    fun setPort(ctx: Context, value: Int) = prefs(ctx).edit().putInt(KEY_PORT, value).apply()

    fun getProtocol(ctx: Context): String = prefs(ctx).getString(KEY_PROTOCOL, "UDP") ?: "UDP"
    fun setProtocol(ctx: Context, value: String) = prefs(ctx).edit().putString(KEY_PROTOCOL, value).apply()

    fun getAutostart(ctx: Context): Boolean = prefs(ctx).getBoolean(KEY_AUTOSTART, false)
    fun setAutostart(ctx: Context, value: Boolean) = prefs(ctx).edit().putBoolean(KEY_AUTOSTART, value).apply()

    fun getRunning(ctx: Context): Boolean = prefs(ctx).getBoolean(KEY_RUNNING, false)
    fun setRunning(ctx: Context, value: Boolean) = prefs(ctx).edit().putBoolean(KEY_RUNNING, value).apply()
}
