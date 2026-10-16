package com.smartable.wallet

import android.os.SystemClock
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * Milliseconds since the device booted, sleep included.
 *
 * **The one clock on the phone its owner cannot set.** `System.currentTimeMillis`
 * is a setting — Settings › Date & time, or a phone with no network taking the
 * time from nothing — and a lockout measured by it is a lockout that ends
 * whenever somebody holding the phone decides it has. See `UnlockThrottle` in
 * Dart, which is the only caller and the reason this exists.
 *
 * `elapsedRealtime` rather than `uptimeMillis`: the second one stops while the
 * device is in deep sleep, so a phone put face-down in a drawer would serve its
 * wait in far less real time than it looks. This one keeps counting.
 *
 * It resets on reboot, and the caller in Dart treats a reading lower than the
 * one it stored as the lockout beginning again.
 */
object DeviceUptime {
    const val CHANNEL = "com.smartable.wallet/uptime"

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        if (call.method != "sinceBoot") {
            result.notImplemented()
            return
        }
        result.success(SystemClock.elapsedRealtime())
    }
}
