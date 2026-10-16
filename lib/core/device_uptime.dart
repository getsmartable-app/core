import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Milliseconds since the device booted, sleep included.
///
/// **A clock the person holding the phone cannot set.** Everything else this
/// wallet measures time with is the wall clock, which is a setting: Settings →
/// Date & time, or a SIM-less phone taking the time from nothing at all. That
/// is fine for showing a date and wrong for holding somebody to a wait, because
/// the wait is the only thing standing between a stolen phone and an unlimited
/// run at the PIN — see `UnlockThrottle`.
///
/// Android answers with `SystemClock.elapsedRealtime`, iOS with
/// `mach_continuous_time`. Both count from boot and both keep counting while
/// the device sleeps, which is the property that matters: a lockout must not be
/// waited out by putting the phone down, and must not be skipped by moving the
/// clock.
///
/// **It resets on reboot, and that is the one thing a caller must handle.** A
/// value lower than one recorded earlier does not mean time ran backwards; it
/// means the device restarted and this counter began again. What to do about
/// that is the caller's decision, not this file's.
///
/// Null means the platform did not answer — a test, a desktop host, a channel
/// that is not registered. A caller gets no reading rather than a wrong one.
abstract final class DeviceUptime {
  static const MethodChannel _channel =
      MethodChannel('com.smartable.wallet/uptime');

  /// Replaces the platform call in tests. Null restores it.
  @visibleForTesting
  static Future<int?> Function()? override;

  static Future<int?> sinceBoot() async {
    final stub = override;
    if (stub != null) return stub();
    try {
      final value = await _channel.invokeMethod<int>('sinceBoot');
      // A negative reading is not a reading. Neither is one from a platform
      // that answered the wrong type, which `invokeMethod` turns into null.
      if (value == null || value < 0) return null;
      return value;
    } catch (_) {
      return null;
    }
  }
}
