package dev.tyson.wazuhlogforwarder

import android.content.Context
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Writes every forwarded syslog line to a rotating set of local log files
 * under app-private external storage (no storage permission needed on any
 * supported API level, and it's cleaned up automatically on uninstall), and
 * can bundle the current set into a single zip for the user to save
 * wherever they like via Storage Access Framework.
 *
 * This is independent of whether delivery to the Wazuh manager succeeded —
 * it's a local record of what the app tried to send.
 */
object LogFileStore {
    private const val MAX_FILE_BYTES = 5L * 1024 * 1024 // rotate a file at 5MB
    private const val MAX_TOTAL_BYTES = 200L * 1024 * 1024 // prune oldest beyond 200MB total
    private const val RETENTION_DAYS = 7L

    private var writer: BufferedWriter? = null
    private var writerFile: File? = null
    private var writtenBytes: Long = 0
    private var linesSinceFlush = 0

    private val fileNameFormat = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)

    fun logsDir(context: Context): File {
        val base = context.getExternalFilesDir(null) ?: context.filesDir
        val dir = File(base, "logs")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    @Synchronized
    fun appendLine(context: Context, line: String) {
        ensureWriter(context)
        val w = writer ?: return
        w.write(line)
        w.newLine()
        writtenBytes += line.toByteArray(Charsets.UTF_8).size + 1
        linesSinceFlush++
        if (linesSinceFlush >= 50) {
            w.flush()
            linesSinceFlush = 0
        }
        if (writtenBytes >= MAX_FILE_BYTES) {
            closeWriter()
        }
    }

    @Synchronized
    fun closeWriter() {
        try {
            writer?.flush()
            writer?.close()
        } catch (_: Exception) {
        }
        writer = null
        writerFile = null
        writtenBytes = 0
        linesSinceFlush = 0
    }

    private fun ensureWriter(context: Context) {
        if (writer != null) return
        val dir = logsDir(context)
        val file = File(dir, "logcat-${fileNameFormat.format(System.currentTimeMillis())}.log")
        writer = BufferedWriter(FileWriter(file, true))
        writerFile = file
        writtenBytes = file.length()
    }

    fun listLogFiles(context: Context): List<File> =
        logsDir(context).listFiles { f -> f.isFile && f.name.endsWith(".log") }
            ?.sortedBy { it.name } ?: emptyList()

    /** Zips every current log file into [out]. Flushes the active writer first so nothing is missed. */
    @Synchronized
    fun zipLogFiles(context: Context, out: OutputStream) {
        writer?.flush()
        ZipOutputStream(out).use { zos ->
            for (file in listLogFiles(context)) {
                zos.putNextEntry(ZipEntry(file.name))
                file.inputStream().use { it.copyTo(zos) }
                zos.closeEntry()
            }
        }
    }

    /** Deletes log files older than [RETENTION_DAYS] days, then trims oldest-first if still over budget. */
    fun pruneOldLogs(context: Context) {
        val cutoff = System.currentTimeMillis() - RETENTION_DAYS * 24 * 60 * 60 * 1000
        val files = listLogFiles(context).filter { it != writerFile }.toMutableList()

        files.removeAll { file ->
            (file.lastModified() < cutoff).also { expired -> if (expired) file.delete() }
        }

        var total = files.sumOf { it.length() }
        var idx = 0
        while (total > MAX_TOTAL_BYTES && idx < files.size) {
            val f = files[idx]
            total -= f.length()
            f.delete()
            idx++
        }
    }
}
