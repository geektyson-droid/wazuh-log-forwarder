package dev.tyson.wazuhlogforwarder

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import dev.tyson.wazuhlogforwarder.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* no-op */ }

    private val createZipLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
            if (uri != null) saveLogsToZip(uri)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        loadPrefsIntoUi()
        refreshStatus()
        maybeRequestNotificationPermission()

        binding.btnStart.setOnClickListener {
            savePrefsFromUi()
            val intent = Intent(this, LogForwarderService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
            refreshStatus()
        }

        binding.btnStop.setOnClickListener {
            stopService(Intent(this, LogForwarderService::class.java))
            refreshStatus()
        }

        binding.btnTest.setOnClickListener {
            savePrefsFromUi()
            val intent = Intent(this, LogForwarderService::class.java).apply {
                action = LogForwarderService.ACTION_SEND_TEST
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        }

        binding.btnViewLive.setOnClickListener {
            startActivity(Intent(this, LiveLogActivity::class.java))
        }

        binding.btnSaveZip.setOnClickListener {
            if (LogFileStore.listLogFiles(this).isEmpty()) {
                Toast.makeText(this, R.string.toast_zip_empty, Toast.LENGTH_SHORT).show()
            } else {
                val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                createZipLauncher.launch("wazuh-logs-$ts.zip")
            }
        }

        binding.btnBattery.setOnClickListener { requestIgnoreBatteryOptimizations() }
        binding.btnGrantHelp.setOnClickListener { showGrantHelpDialog() }

        binding.switchAutostart.setOnCheckedChangeListener { _, checked ->
            Prefs.setAutostart(this, checked)
        }
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    private fun loadPrefsIntoUi() {
        binding.editHost.setText(Prefs.getHost(this))
        binding.editPort.setText(Prefs.getPort(this).toString())
        if (Prefs.getProtocol(this) == "TCP") {
            binding.radioTcp.isChecked = true
        } else {
            binding.radioUdp.isChecked = true
        }
        binding.switchAutostart.isChecked = Prefs.getAutostart(this)
    }

    private fun savePrefsFromUi() {
        Prefs.setHost(this, binding.editHost.text?.toString()?.trim().orEmpty())
        val port = binding.editPort.text?.toString()?.trim()?.toIntOrNull() ?: Prefs.DEFAULT_PORT
        Prefs.setPort(this, port)
        Prefs.setProtocol(this, if (binding.radioTcp.isChecked) "TCP" else "UDP")
    }

    private fun refreshStatus() {
        val running = LogForwarderService.isRunning
        binding.textStatus.text = if (running) {
            "Status: forwarding to ${Prefs.getHost(this)}:${Prefs.getPort(this)} (${Prefs.getProtocol(this)})"
        } else {
            getString(R.string.status_stopped)
        }

        val hasReadLogs = ContextCompat.checkSelfPermission(
            this, Manifest.permission.READ_LOGS
        ) == PackageManager.PERMISSION_GRANTED
        binding.textLogAccess.text = if (hasReadLogs) {
            "Full system logcat access: granted"
        } else {
            "Full system logcat access: NOT granted (currently forwarding only this app's own log lines) — tap the button below"
        }
    }

    private fun maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun requestIgnoreBatteryOptimizations() {
        val pm = getSystemService(PowerManager::class.java)
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        val intent = Intent(
            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
            Uri.parse("package:$packageName")
        )
        startActivity(intent)
    }

    private fun saveLogsToZip(uri: Uri) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                contentResolver.openOutputStream(uri)?.use { out ->
                    LogFileStore.zipLogFiles(this@MainActivity, out)
                } ?: throw IllegalStateException("Could not open destination for writing")
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, R.string.toast_zip_saved, Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@MainActivity,
                        getString(R.string.toast_zip_failed, e.message ?: e.toString()),
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun showGrantHelpDialog() {
        val adbCommand = "adb shell pm grant $packageName android.permission.READ_LOGS"
        AlertDialog.Builder(this)
            .setTitle("Grant full logcat access")
            .setMessage(
                "Android sandboxes each app's log output. To forward the WHOLE " +
                "device system log instead of just this app's own lines, connect " +
                "the device over ADB (USB debugging must be enabled) and run:\n\n" +
                "$adbCommand\n\n" +
                "This grant persists until the app is uninstalled. No root required."
            )
            .setPositiveButton("OK", null)
            .show()
    }
}
