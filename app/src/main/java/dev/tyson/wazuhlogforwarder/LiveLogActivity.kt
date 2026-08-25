package dev.tyson.wazuhlogforwarder

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.addTextChangedListener
import dev.tyson.wazuhlogforwarder.databinding.ActivityLiveLogBinding

/**
 * Shows the syslog lines the forwarder service is (or was) sending, live,
 * as they arrive — sourced from [LogBus], which the service pushes every
 * line into regardless of whether delivery to Wazuh succeeded. Supports a
 * simple substring filter, pause/resume, and clearing the view.
 */
class LiveLogActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLiveLogBinding
    private var paused = false
    private var filter: String = ""
    private val displayed = ArrayDeque<String>()
    private val maxDisplayed = 1000

    private val busListener: (String) -> Unit = { line ->
        if (!paused && matchesFilter(line)) appendLine(line)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLiveLogBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnClose.setOnClickListener { finish() }

        binding.btnClear.setOnClickListener {
            displayed.clear()
            binding.textLog.text = ""
        }

        binding.btnPause.setOnClickListener {
            paused = !paused
            binding.btnPause.text = getString(if (paused) R.string.btn_resume else R.string.btn_pause)
        }

        binding.editFilter.addTextChangedListener { text ->
            filter = text?.toString().orEmpty()
            rebuildFromSnapshot()
        }

        rebuildFromSnapshot()
    }

    override fun onStart() {
        super.onStart()
        LogBus.addListener(busListener)
    }

    override fun onStop() {
        super.onStop()
        LogBus.removeListener(busListener)
    }

    private fun matchesFilter(line: String): Boolean =
        filter.isBlank() || line.contains(filter, ignoreCase = true)

    private fun rebuildFromSnapshot() {
        displayed.clear()
        LogBus.snapshot().filter { matchesFilter(it) }.takeLast(maxDisplayed).forEach { displayed.addLast(it) }
        binding.textLog.text = displayed.joinToString("\n")
        scrollToBottom()
    }

    private fun appendLine(line: String) {
        displayed.addLast(line)
        if (displayed.size > maxDisplayed) displayed.removeFirst()
        val prefix = if (binding.textLog.text.isNullOrEmpty()) "" else "\n"
        binding.textLog.append("$prefix$line")
        scrollToBottom()
    }

    private fun scrollToBottom() {
        binding.scrollLog.post { binding.scrollLog.fullScroll(View.FOCUS_DOWN) }
    }
}
