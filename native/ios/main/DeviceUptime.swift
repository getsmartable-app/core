import Flutter
import Foundation

/// Milliseconds since the device booted, sleep included.
///
/// **The one clock on the phone its owner cannot set.** `Date()` is a setting,
/// and a lockout measured by it is a lockout that ends whenever whoever is
/// holding the phone decides it has. See `UnlockThrottle` in Dart, which is the
/// only caller and the reason this exists.
///
/// `mach_continuous_time` rather than `ProcessInfo.systemUptime`: the second
/// one is `CLOCK_MONOTONIC`, which on Darwin stops while the device sleeps, so
/// a phone left face-down in a drawer would serve its wait in far less real
/// time than it appears to. This one keeps counting, which is what Android's
/// `elapsedRealtime` does and what makes the two platforms the same rule.
///
/// It resets on reboot, and the caller treats a reading lower than the one it
/// stored as the lockout beginning again.
enum DeviceUptime {
  static let channel = "com.smartable.wallet/uptime"

  static func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard call.method == "sinceBoot" else {
      result(FlutterMethodNotImplemented)
      return
    }
    var timebase = mach_timebase_info_data_t()
    guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom != 0 else {
      // No reading rather than a wrong one: Dart falls back to the wall clock
      // bounded by the tier, and says so in its own comment.
      result(nil)
      return
    }
    // Nanoseconds, in 64 bits, divided down before the multiply would overflow
    // it: the ticks alone pass 2^63 after a few centuries, but `numer` on the
    // simulator is 125 and multiplying first does not survive that long.
    let ticks = mach_continuous_time()
    let nanoseconds =
      ticks / UInt64(timebase.denom) * UInt64(timebase.numer)
      + ticks % UInt64(timebase.denom) * UInt64(timebase.numer) / UInt64(timebase.denom)
    result(Int64(nanoseconds / 1_000_000))
  }
}
