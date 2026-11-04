package com.ai.relay.arpl

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var enrollment: EditText
    private val prefs by lazy { getSharedPreferences(ArplService.PREFS, MODE_PRIVATE) }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        status = TextView(this)
        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1001)
        }
        enrollment = EditText(this).apply {
            hint = "Paste signed enrollment payload or open an arpl://enroll link"
            minLines = 3
        }
        handleIntent(intent)

        val binary = EditText(this).apply {
            hint = "ARPL binary path (optional; bundled runtime is automatic)"
            setText(prefs.getString(ArplService.KEY_BINARY_PATH, ""))
        }
        val config = EditText(this).apply {
            hint = "ARPL settings path"
            setText(prefs.getString(ArplService.KEY_CONFIG_PATH, ""))
        }
        val start = Button(this).apply {
            text = "Start ARPL connectivity"
            setOnClickListener {
                prefs.edit().putString(ArplService.KEY_BINARY_PATH, binary.text.toString().trim())
                    .putString(ArplService.KEY_CONFIG_PATH, config.text.toString().trim()).apply()
                startService(ArplService.ACTION_START)
                renderStatus()
            }
        }
        val stop = Button(this).apply {
            text = "Stop / force disconnect"
            setOnClickListener { startService(ArplService.ACTION_STOP); renderStatus() }
        }
        val import = Button(this).apply {
            text = "Import enrollment payload"
            setOnClickListener {
                val payload = enrollment.text.toString().trim()
                if (payload.isNotEmpty() && payload.length <= 64 * 1024) {
                    prefs.edit().putString(ArplService.KEY_PENDING_ENROLLMENT, payload).apply()
                    enrollment.setText("")
                    status.text = "Enrollment payload imported (public signed material only)."
                } else {
                    status.text = "Enrollment payload is empty or too large."
                }
            }
        }
        val battery = Button(this).apply {
            text = "Battery optimization guidance"
            setOnClickListener {
                val pm = getSystemService(PowerManager::class.java)
                if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                    startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
                } else {
                    status.text = "Battery optimization is already disabled for ARPL Companion."
                }
            }
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
            addView(status)
            addView(binary, ViewGroup.LayoutParams(-1, ViewGroup.LayoutParams.WRAP_CONTENT))
            addView(config, ViewGroup.LayoutParams(-1, ViewGroup.LayoutParams.WRAP_CONTENT))
            addView(enrollment, ViewGroup.LayoutParams(-1, ViewGroup.LayoutParams.WRAP_CONTENT))
            addView(import)
            addView(start)
            addView(stop)
            addView(battery)
        }
        setContentView(root)
        renderStatus()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent != null) handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        val payload = intent.getStringExtra("enrollment_payload")
            ?: intent.data?.takeIf { it.scheme == "arpl" && it.host == "enroll" }
                ?.getQueryParameter("payload")
        if (!payload.isNullOrBlank() && payload.length <= 64 * 1024) enrollment.setText(payload)
    }

    private fun renderStatus() {
        val state = prefs.getString(ArplService.KEY_STATUS, "stopped") ?: "stopped"
        val detail = prefs.getString(ArplService.KEY_STATUS_DETAIL, "ARPL is stopped") ?: "ARPL is stopped"
        val fleet = prefs.getString(ArplService.KEY_FLEET_SUMMARY, "fleet unavailable") ?: "fleet unavailable"
        val pending = if (prefs.contains(ArplService.KEY_PENDING_ENROLLMENT)) " Enrollment payload pending import." else ""
        status.text = "ARPL Companion\nService: $state\n$detail\nPeers/fleet: $fleet$pending\nPrivate keys and secrets are never displayed."
    }

    private fun startService(action: String) {
        val intent = Intent(this, ArplService::class.java).setAction(action)
        if (android.os.Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }

}
