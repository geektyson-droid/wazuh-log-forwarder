package dev.tyson.wazuhlogforwarder

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

/**
 * Foreground service: tails `logcat`, converts each line to an RFC 3164
 * syslog message, and streams it to the configured Wazuh manager over
 * UDP or TCP. Runs until the user stops it or the OS kills the process.
 */
class LogForwarderService : android.app.Service() {

    companion object {
        private const val TAG = "LogForwarderService"
        private const val CHANNEL_ID = "wazuh_forwarder"
        private const val NOTIFICATION_ID = 1
        const val ACTION_SEND_TEST = "dev.tyson.wazuhlogforwarder.SEND_TEST"
        const val EXTRA_STATUS_BROADCAST = "dev.tyson.wazuhlogforwarder.STATUS"

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private val serviceJob = Job()
    private val scope = CoroutineScope(Dispatchers.IO + serviceJob)
    private var logcatProcess: Process? = null
    private var udpSocket: DatagramSocket? = null
    private var tcpSocket: Socket? = null
    private lateinit var hostname: String

    override fun onCreate() {
        super.onCreate()
        hostname = deviceHostname()
        createNotificationChannel()
        scope.launch { LogFileStore.pruneOldLogs(this@LogForwarderService) }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_SEND_TEST) {
            scope.launch {
                val msg = SyslogFormatter.format(hostname, testLine())
                LogBus.push(msg)
                LogFileStore.appendLine(this@LogForwarderService, msg)
                sendOne(msg)
            }
            return START_STICKY
        }

        if (!isRunning) {
            startForegroundWithNotification()
            isRunning = true
            Prefs.setRunning(this, true)
            scope.launch { runLogcatLoop() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        isRunning = false
        Prefs.setRunning(this, false)
        serviceJob.cancel()
        logcatProcess?.destroy()
        closeSockets()
        LogFileStore.closeWriter()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ---- logcat capture -----------------------------------------------------

    private suspend fun runLogcatLoop() {
        var backoffMs = 2000L
        while (scope.isActive) {
            try {
                openTransport()
                tailLogcatOnce()
                backoffMs = 2000L // reset after a clean run
            } catch (e: Exception) {
                Log.w(TAG, "logcat/transport loop error, retrying in ${backoffMs}ms", e)
            }
            if (!scope.isActive) break
            delay(backoffMs)
            backoffMs = (backoffMs * 2).coerceAtMost(60_000L)
        }
    }

    private fun tailLogcatOnce() {
        // -v threadtime gives level + tag in a stable, parseable position.
        // We do NOT pass -d, so this blocks and streams continuously.
        val process = ProcessBuilder("logcat", "-v", "threadtime")
            .redirectErrorStream(true)
            .start()
        logcatProcess = process

        BufferedReader(InputStreamReader(process.inputStream, StandardCharsets.UTF_8)).use { reader ->
            var line: String?
            while (scope.isActive) {
                line = reader.readLine() ?: break
                val msg = SyslogFormatter.format(hostname, line)
                LogBus.push(msg)
                LogFileStore.appendLine(this@LogForwarderService, msg)
                try {
                    sendOne(msg)
                } catch (e: IOException) {
                    Log.w(TAG, "send failed, reopening transport", e)
                    closeSockets()
                    openTransport()
                }
            }
        }
        process.destroy()
    }

    // ---- transport ------------------------------------------------------------

    private fun openTransport() {
        closeSockets()
        val host = Prefs.getHost(this)
        val port = Prefs.getPort(this)
        if (host.isBlank()) throw IllegalStateException("No Wazuh manager host configured")

        when (Prefs.getProtocol(this)) {
            "TCP" -> {
                val s = Socket()
                s.connect(InetSocketAddress(host, port), 5000)
                tcpSocket = s
            }
            else -> {
                udpSocket = DatagramSocket()
            }
        }
    }

    @Throws(IOException::class)
    private fun sendOne(message: String) {
        val host = Prefs.getHost(this)
        val port = Prefs.getPort(this)
        if (host.isBlank()) return
        val bytes = message.toByteArray(StandardCharsets.UTF_8)

        when (Prefs.getProtocol(this)) {
            "TCP" -> {
                val socket = tcpSocket ?: throw IOException("TCP socket not open")
                val out = socket.getOutputStream()
                out.write(bytes)
                out.write('\n'.code)
                out.flush()
            }
            else -> {
                val socket = udpSocket ?: throw IOException("UDP socket not open")
                val packet = DatagramPacket(bytes, bytes.size, InetSocketAddress(host, port))
                socket.send(packet)
            }
        }
    }

    private fun closeSockets() {
        try { udpSocket?.close() } catch (_: Exception) {}
        try { tcpSocket?.close() } catch (_: Exception) {}
        udpSocket = null
        tcpSocket = null
    }

    // ---- misc -----------------------------------------------------------------

    private fun deviceHostname(): String {
        val id = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"
        val model = Build.MODEL?.replace(Regex("\\s+"), "-") ?: "android"
        return "$model-$id".take(63)
    }

    private fun testLine(): String =
        "08-22 00:00:00.000  9999  9999 I WazuhLogForwarder: test message from $hostname"

    private fun createNotificationChannel() {
        val mgr = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        )
        mgr.createNotificationChannel(channel)
    }

    private fun startForegroundWithNotification() {
        val openIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_running))
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }
}
