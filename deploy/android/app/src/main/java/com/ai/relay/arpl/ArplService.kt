package com.ai.relay.arpl

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import java.io.File
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit

/** Owns exactly one native ARPL resident process. No shell is involved. */
class ArplService : Service() {
    private val executor = Executors.newSingleThreadExecutor()
    private val lock = Any()
    private var child: Process? = null
    private var supervisorRunning = false
    private var supervisorGeneration = 0L
    private var stopping = false
    private var networkAvailable = true
    private var wakeLock: PowerManager.WakeLock? = null
    private var network: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val retrySignal = Semaphore(0)
    private val prefs by lazy { getSharedPreferences(PREFS, Context.MODE_PRIVATE) }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForegroundCompat(notification("stopped", "ARPL is stopped"))
        network = getSystemService(ConnectivityManager::class.java)
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                synchronized(lock) { networkAvailable = true }
                retrySignal.release()
                updateNotification("reconnecting", "NETWORK_AVAILABLE; opening a fresh ARPL path")
                startSupervisor()
            }
            override fun onLost(network: Network) {
                val staleChild = synchronized(lock) {
                    networkAvailable = false
                    child
                }
                retrySignal.release()
                staleChild?.destroy()
                updateNotification("reconnecting", "NETWORK_LOST; stale ARPL transport closed")
            }
        }
        networkCallback?.let { network?.registerDefaultNetworkCallback(it) }
        if (enabled()) startSupervisor()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                prefs.edit().putBoolean(KEY_ENABLED, false).putBoolean(KEY_FORCE_DISCONNECT, true).apply()
                stopSupervisor("stopped")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelfResult(startId)
            }
            ACTION_START, ACTION_RECONNECT, null -> {
                if (intent?.action == ACTION_START) {
                    synchronized(lock) { stopping = false }
                    prefs.edit().putBoolean(KEY_ENABLED, true).putBoolean(KEY_FORCE_DISCONNECT, false).apply()
                }
                startSupervisor()
            }
        }
        return START_STICKY
    }

    private fun enabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false) &&
        !prefs.getBoolean(KEY_FORCE_DISCONNECT, false)

    private fun startSupervisor() {
        val generation: Long
        synchronized(lock) {
            if (stopping || !enabled() || supervisorRunning) return
            supervisorRunning = true
            supervisorGeneration++
            generation = supervisorGeneration
            acquireWakeLockLocked()
            executor.execute { supervise(generation) }
        }
        updateNotification("reconnecting", "Starting ARPL resident supervisor")
    }

    private fun supervise(generation: Long) {
        var backoff = 1000L
        while (active(generation)) {
            if (!networkReady()) {
                updateNotification("reconnecting", "NETWORK_LOST; waiting for network")
                waitForRetry(60_000L)
                continue
            }
            val command = validatedCommand()
            if (command == null) {
                updateNotification("stopped", "Configure a valid ARPL binary and settings file")
                break
            }
            if (!consumePendingEnrollment(command[0], command[4], generation)) break
            val process = try {
                processBuilder(command).start()
            } catch (_: Exception) {
                null
            }
            if (process == null) {
                updateNotification("reconnecting", "ARPL could not start; RETRY_SCHEDULED in ${backoff / 1000}s")
                waitForRetry(backoff)
                backoff = (backoff * 2).coerceAtMost(60_000L)
                continue
            }
            val startedAt = System.nanoTime()
            var shouldStop = false
            synchronized(lock) {
                shouldStop = !activeLocked(generation)
                if (!shouldStop) child = process
            }
            if (shouldStop) {
                process.destroy()
                break
            }
            updateNotification("connected", "CONNECTED; ARPL resident supervisor is running")
            // Drain output without displaying it; diagnostics belong in the
            // configured local log, never in a notification or UI.
            Thread { process.inputStream.bufferedReader().use { it.forEachLine { } } }.start()
            try { process.waitFor() } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            synchronized(lock) { if (child === process) child = null }
            if (!active(generation)) break

            // A connectivity callback deliberately destroys a possibly half-open
            // native child. Do not impose crash backoff when the network itself
            // disappeared; onAvailable() wakes this loop for an immediate redial.
            if (!networkReady()) {
                backoff = 1000L
                continue
            }

            val ranForMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)
            if (ranForMillis >= 30_000L) backoff = 1000L
            updateNotification("reconnecting", "DISCONNECTED; RETRY_SCHEDULED in ${backoff / 1000}s")
            waitForRetry(backoff)
            backoff = (backoff * 2).coerceAtMost(60_000L)
        }
        synchronized(lock) {
            if (supervisorGeneration == generation) {
                child = null
                supervisorRunning = false
                releaseWakeLockLocked()
            }
        }
        val stillCurrent = synchronized(lock) { supervisorGeneration == generation }
        if (stillCurrent && !active(generation)) updateNotification("stopped", "ARPL is stopped")
    }

    private fun active(generation: Long): Boolean = synchronized(lock) { activeLocked(generation) }

    private fun networkReady(): Boolean = synchronized(lock) { networkAvailable }

    private fun activeLocked(generation: Long): Boolean =
        !stopping && supervisorGeneration == generation && enabled()

    private fun consumePendingEnrollment(binary: String, config: String, generation: Long): Boolean {
        val payload = prefs.getString(KEY_PENDING_ENROLLMENT, "")?.trim().orEmpty()
        if (payload.isEmpty()) return true
        if (!active(generation)) return false

        val payloadFile = File(filesDir, "pending-enrollment.payload")
        return try {
            payloadFile.writeText(payload)
            payloadFile.setReadable(false, false)
            payloadFile.setWritable(false, false)
            payloadFile.setExecutable(false, false)
            payloadFile.setReadable(true, true)
            payloadFile.setWritable(true, true)

            val process = processBuilder(
                listOf(binary, "enroll", "consume", "--payload-file", payloadFile.absolutePath, "--settings-file", config)
            ).start()
            Thread { process.inputStream.bufferedReader().use { it.forEachLine { } } }.start()
            val finished = try { process.waitFor(30, TimeUnit.SECONDS) } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                false
            }
            if (!finished) process.destroyForcibly()
            if (!finished || process.exitValue() != 0) {
                updateNotification("stopped", "ARPL enrollment import failed; review the payload and settings")
                false
            } else {
                prefs.edit().remove(KEY_PENDING_ENROLLMENT).apply()
                true
            }
        } catch (_: Exception) {
            updateNotification("stopped", "ARPL enrollment import could not start")
            false
        } finally {
            payloadFile.delete()
        }
    }

    internal fun commandFor(binary: String, config: String): List<String> =
        listOf(binary, "client", "connect", "--settings-file", config)

    private fun validatedCommand(): List<String>? {
        val configured = prefs.getString(KEY_BINARY_PATH, "")?.trim().orEmpty()
        val termux = prefs.getString(KEY_TERMUX_BINARY_PATH, DEFAULT_TERMUX_BINARY)?.trim().orEmpty()
        val binary = listOf(configured, bundledBinaryPath(), termux, defaultBinaryPath())
            .firstOrNull { validExecutable(it) } ?: return null
        val config = prefs.getString(KEY_CONFIG_PATH, "")?.trim().orEmpty().ifEmpty { defaultConfigPath() }
        if (!ensureRuntimeInitialized(binary, config)) return null
        return commandFor(binary, config)
    }

    private fun ensureRuntimeInitialized(binary: String, config: String): Boolean {
        if (!validRegularFile(config)) {
            File(config).parentFile?.mkdirs()
            if (!runNative(listOf(binary, "settings", "init", "--file", config))) {
                updateNotification("stopped", "ARPL settings initialization failed")
                return false
            }
        }
        val identity = File(filesDir, "ai-relay/arpl/identity.json")
        if (!identity.isFile) {
            identity.parentFile?.mkdirs()
            if (!runNative(listOf(binary, "key", "rotate", "--key-file", identity.absolutePath))) {
                updateNotification("stopped", "ARPL identity initialization failed")
                return false
            }
        }
        return validRegularFile(config) && identity.isFile
    }

    private fun runNative(command: List<String>): Boolean {
        val process = try { processBuilder(command).start() } catch (_: Exception) { return false }
        Thread { process.inputStream.bufferedReader().use { it.forEachLine { } } }.start()
        val finished = try { process.waitFor(30, TimeUnit.SECONDS) } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!finished) process.destroyForcibly()
        return finished && process.exitValue() == 0
    }

    private fun processBuilder(command: List<String>): ProcessBuilder =
        ProcessBuilder(command).redirectErrorStream(true).also {
            it.environment()["HOME"] = filesDir.absolutePath
            it.environment()["XDG_CONFIG_HOME"] = filesDir.absolutePath
        }

    private fun validRegularFile(path: String): Boolean = path.isNotEmpty() && File(path).isFile && File(path).canRead()
    private fun validExecutable(path: String): Boolean = validRegularFile(path) && File(path).canExecute()
    private fun defaultConfigPath(): String = File(filesDir, "settings.json").absolutePath
    private fun defaultBinaryPath(): String = File(filesDir, "arpl").absolutePath
    private fun bundledBinaryPath(): String = File(applicationInfo.nativeLibraryDir, "libai_relay_arpl.so").absolutePath

    private fun stopSupervisor(state: String) {
        synchronized(lock) {
            stopping = true
            supervisorGeneration++
            child?.destroy()
            child = null
            supervisorRunning = false
            releaseWakeLockLocked()
        }
        retrySignal.release()
        updateNotification(state, "ARPL is stopped")
    }

    private fun acquireWakeLockLocked() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "ai-relay:arpl-connectivity").also {
            it.setReferenceCounted(false)
            it.acquire()
        }
    }

    private fun releaseWakeLockLocked() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    private fun waitForRetry(millis: Long) {
        try {
            retrySignal.tryAcquire(millis, TimeUnit.MILLISECONDS)
            retrySignal.drainPermits()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "ARPL connectivity", NotificationManager.IMPORTANCE_LOW)
        )
    }

    private fun notification(state: String, detail: String): Notification =
        Notification.Builder(this, CHANNEL)
            .setContentTitle("ARPL $state")
            .setContentText(detail)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(state != "stopped")
            .build()

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(state: String, detail: String) {
        if (Build.VERSION.SDK_INT < 33 ||
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(state, detail))
        }
        prefs.edit().putString(KEY_STATUS, state).putString(KEY_STATUS_DETAIL, detail)
            .putString(KEY_FLEET_SUMMARY, fleetSummary()).apply()
    }

    private fun fleetSummary(): String {
        val config = prefs.getString(KEY_CONFIG_PATH, "")?.trim().orEmpty().ifEmpty { defaultConfigPath() }
        val file = File(File(config).parentFile ?: filesDir, "fleet.json")
        return try {
            val objectValue = JSONObject(file.readText())
            var online = 0
            val keys = objectValue.keys()
            while (keys.hasNext()) {
                if (objectValue.optJSONObject(keys.next())?.optBoolean("connected", false) == true) online++
            }
            "${objectValue.length()} peers, $online online"
        } catch (_: Exception) { "fleet unavailable" }
    }

    override fun onDestroy() {
        synchronized(lock) { stopping = true; child?.destroy(); child = null; supervisorRunning = false; releaseWakeLockLocked() }
        retrySignal.release()
        networkCallback?.let { network?.unregisterNetworkCallback(it) }
        executor.shutdownNow()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val ACTION_START = "com.ai.relay.arpl.START"
        const val ACTION_STOP = "com.ai.relay.arpl.STOP"
        const val ACTION_RECONNECT = "com.ai.relay.arpl.RECONNECT"
        const val PREFS = "arpl_companion"
        const val KEY_ENABLED = "enabled"
        const val KEY_FORCE_DISCONNECT = "force_disconnect"
        const val KEY_BINARY_PATH = "binary_path"
        const val KEY_TERMUX_BINARY_PATH = "termux_binary_path"
        const val KEY_CONFIG_PATH = "config_path"
        const val KEY_STATUS = "status"
        const val KEY_STATUS_DETAIL = "status_detail"
        const val KEY_FLEET_SUMMARY = "fleet_summary"
        const val KEY_PENDING_ENROLLMENT = "pending_enrollment"
        const val DEFAULT_TERMUX_BINARY = "/data/data/com.termux/files/usr/bin/arpl"
        private const val CHANNEL = "arpl"
        private const val NOTIFICATION_ID = 7
    }
}
