package dev.tyson.wazuhlogforwarder

import java.text.SimpleDateFormat
import java.util.Locale

/**
 * Formats Android logcat lines as legacy BSD syslog (RFC 3164) messages so a
 * stock Wazuh manager `<remote>` syslog listener can parse them without any
 * extra decoder work. RFC 3164 (rather than 5424) is used because Wazuh's
 * bundled decoders assume the classic "<PRI>Mon dd HH:mm:ss host tag: msg"
 * shape.
 */
object SyslogFormatter {

    private const val FACILITY_LOCAL0 = 16

    // logcat -v threadtime lines start with "MM-dd HH:mm:ss.SSS  PID  TID L tag: message"
    // where L is one of V,D,I,W,E,F,S. We only need the level char to pick a severity.
    private val LEVEL_REGEX = Regex("""^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\d+\s+\d+\s+([VDIWEF])\s""")

    private val monthDayFormat = SimpleDateFormat("MMM", Locale.US)
    private val dayFormat = SimpleDateFormat("d", Locale.US)
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

    /** RFC 3164 timestamp: "Mon" + space-padded day + " HH:mm:ss", e.g. "Jan  5 08:03:11". */
    private fun rfc3164Timestamp(): String {
        val now = System.currentTimeMillis()
        val month = monthDayFormat.format(now)
        val day = dayFormat.format(now).padStart(2, ' ')
        val time = timeFormat.format(now)
        return "$month $day $time"
    }

    private fun severityFor(level: Char?): Int = when (level) {
        'F' -> 2 // Critical
        'E' -> 3 // Error
        'W' -> 4 // Warning
        'I' -> 6 // Informational
        'D', 'V' -> 7 // Debug
        else -> 6
    }

    /**
     * @param hostname stable device identifier used as the syslog HOSTNAME field
     * @param line a raw line of `logcat -v threadtime` output
     */
    fun format(hostname: String, line: String): String {
        val level = LEVEL_REGEX.find(line)?.groupValues?.get(1)?.firstOrNull()
        val severity = severityFor(level)
        val pri = FACILITY_LOCAL0 * 8 + severity

        val ts = rfc3164Timestamp()

        // Truncate to keep well under typical 2KB UDP-safe payloads; Wazuh/rsyslog
        // style listeners commonly cap single-line messages around 1024-2048 bytes.
        val safeLine = if (line.length > 1800) line.take(1800) + "...(truncated)" else line

        return "<$pri>$ts $hostname android-logcat: $safeLine"
    }
}
