package com.ai.relay.arpl

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = context.getSharedPreferences(ArplService.PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(ArplService.KEY_ENABLED, false) ||
            prefs.getBoolean(ArplService.KEY_FORCE_DISCONNECT, false)) return
        val serviceIntent = Intent(context, ArplService::class.java).setAction(ArplService.ACTION_RECONNECT)
        if (android.os.Build.VERSION.SDK_INT >= 26) context.startForegroundService(serviceIntent)
        else context.startService(serviceIntent)
    }
}
