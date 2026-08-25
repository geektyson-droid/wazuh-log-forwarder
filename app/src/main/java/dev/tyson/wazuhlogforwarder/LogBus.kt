package dev.tyson.wazuhlogforwarder

import android.os.Handler
import android.os.Looper
import java.util.concurrent.CopyOnWriteArrayList

/**
 * In-process pub/sub feeding the live-log screen. Every syslog line the
 * service forwards (successfully or not — this is independent of network
 * delivery) is pushed here, bounded to the most recent [MAX_LINES] so a
 * long-running capture can't grow memory without bound. Listeners are
 * always notified on the main thread, so UI code can update views directly.
 */
object LogBus {
    private const val MAX_LINES = 1000

    private val buffer = ArrayDeque<String>()
    private val listeners = CopyOnWriteArrayList<(String) -> Unit>()
    private val mainHandler = Handler(Looper.getMainLooper())

    @Synchronized
    fun push(line: String) {
        buffer.addLast(line)
        if (buffer.size > MAX_LINES) buffer.removeFirst()
        mainHandler.post { listeners.forEach { it(line) } }
    }

    @Synchronized
    fun snapshot(): List<String> = buffer.toList()

    fun addListener(listener: (String) -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: (String) -> Unit) {
        listeners.remove(listener)
    }
}
