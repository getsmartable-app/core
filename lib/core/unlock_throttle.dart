import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'device_uptime.dart';
import 'secure_storage.dart';

/// Rate-limits password guesses against a locked wallet.
///
/// Until this existed the only thing standing between someone holding the
/// phone and the seed was `password.length >= 8` at creation time: the unlock
/// screen accepted guesses as fast as they could be typed, forever, and a
/// four-digit-shaped password would fall in minutes.
///
/// PBKDF2 at 600k iterations already makes an *offline* attack expensive — a
/// thief who dumps `encrypted_seed` and `salt` pays that cost per guess on
/// their own hardware, and nothing here changes that. What this defends is the
/// on-device path, where the attacker has the running app and no such cost.
///
/// **The wallet is never wiped.** Auto-destroying after N failures turns a
/// curious child, a pocket-dialled screen or a hostile flatmate into permanent
/// loss of funds, and it hands anyone holding the phone a way to destroy money
/// they cannot steal. MetaMask and Trust Wallet both decline to do it, and so
/// does this: the answer to a forgotten password is the recovery phrase.
///
/// **The clock is not the wall clock, because the wall clock is a setting.**
/// A deadline stored as `DateTime.now()` is one Settings → Date & time away
/// from being over: move the phone forward an hour and the hour-long tier is
/// spent, every time, at the speed of typing. This file used to say that was
/// bounded because the attempt count keeps rising — it is not, because the top
/// tier is an hour and an hour is one tap away.
///
/// So a lockout is anchored to [DeviceUptime] as well: milliseconds since boot,
/// which keeps counting while the device sleeps and which nobody can set. The
/// wall deadline stays beside it, and **the longer of the two is what is
/// served**, so moving the clock forward shortens nothing and moving it back —
/// a phone whose battery died and came up in 1970 — cannot extend a wait past
/// the tier it came from.
///
/// **A reboot resets that counter, and is treated as the lockout beginning
/// again.** The alternative is to believe the wall clock across a restart,
/// which is the hole this closes; the cost is that somebody who restarts their
/// phone during a lockout waits it out once more, and the longest that can be
/// is an hour.
class UnlockThrottle {
  /// The count and the deadline, as one record.
  ///
  /// **Two keys were two writes, and they could disagree.** `recordFailure`
  /// wrote the count and then the deadline; an interruption between them left a
  /// higher count with no wait behind it. The order was the safe one — a lost
  /// pause is paid for by a longer next one — but a security control with a
  /// window in it is a window somebody eventually aims at.
  ///
  /// **Still the ordinary storage class, and deliberately.** An encrypted-only
  /// write is *skipped* when the keystore refuses, and a skipped write here is
  /// an attempt that was never counted — free guesses, which is the opposite of
  /// what this exists for. Weak and durable beats strong and absent for a
  /// throttle, and app data is neither backed up nor device-transferred; see
  /// `data_extraction_rules.xml` and `test/storage_class_inventory_test.dart`.
  ///
  /// What was wrong was never the write. It was the *read*: see [_state].
  static const _recordKey = 'unlock_throttle';

  /// The shape before the record above. Read once, on the way past.
  static const _attemptsKey = 'failed_unlock_attempts';
  static const _lockedUntilKey = 'unlock_locked_until';

  /// The two clocks, replaceable in tests and nowhere else.
  @visibleForTesting
  static DateTime Function() clock = DateTime.now;
  @visibleForTesting
  static Future<int?> Function() uptime = DeviceUptime.sinceBoot;

  /// Failures allowed before any wait. Four is room for a fat-fingered
  /// password and a wrong keyboard layout, which is what genuine failures
  /// usually are, without being room for a search.
  static const int freeAttempts = 4;

  /// How long the wallet stays shut after [attempts] consecutive failures.
  ///
  /// Pure, so the schedule can be read and tested without touching storage or
  /// a clock. Escalating rather than fixed: a flat delay is a throughput limit
  /// an attacker simply waits out, while doubling turns a few hundred guesses
  /// into days.
  static Duration lockoutFor(int attempts) {
    if (attempts <= freeAttempts) return Duration.zero;
    return switch (attempts - freeAttempts) {
      1 => const Duration(seconds: 30),
      2 => const Duration(minutes: 2),
      3 => const Duration(minutes: 10),
      4 => const Duration(minutes: 30),
      _ => const Duration(hours: 1),
    };
  }

  /// What the store says, and whether it said anything at all.
  ///
  /// **`blind` is the third answer, and this file was the last place in the
  /// wallet without one.** `readSecret` throws rather than return null so a
  /// caller can tell an absent secret from an unreadable one, and
  /// `encryptedRecordExists` exists to carry the same distinction for a store
  /// that will not decrypt. A guess limiter needs it more than either: see the
  /// comment on the probe below for what the missing answer cost.
  static Future<({int attempts, int? until, int? boot, int? wait, bool blind})>
      _state() async {
    String? raw;
    try {
      raw = await SecureStorage.read(_recordKey);
    } catch (_) {
      raw = null;
    }

    if (raw != null && raw.isNotEmpty) {
      try {
        final decoded = jsonDecode(raw);
        if (decoded is Map && decoded['attempts'] is int) {
          final until = decoded['until'];
          final boot = decoded['boot'];
          final wait = decoded['wait'];
          return (
            attempts: decoded['attempts'] as int,
            until: until is int ? until : null,
            // Absent in every record written before the uptime anchor existed.
            // Such a record is served by the wall clock alone, bounded by its
            // own tier — the old hole, but only until the next failure.
            boot: boot is int ? boot : null,
            wait: wait is int ? wait : null,
            blind: false,
          );
        }
      } catch (_) {
        // Falls through: a record that is there and will not parse is one this
        // session could not read, which is not the same as an empty one.
      }
      return (attempts: 0, until: null, boot: null, wait: null, blind: true);
    }

    // **Null is "nothing here" and "could not look" wearing the same face, and
    // this is where the limiter used to remove itself.**
    //
    // `SecureStorage.read` answers a keystore exception by falling through to
    // preferences, and with nothing there it returns null — which
    // `int.tryParse(null) ?? 0` read as "no failed attempts". So the one
    // control between somebody holding the phone and an unlimited on-device
    // password search switched itself off on exactly the device state an
    // attacker can provoke.
    //
    // `containsKey` is what tells the two apart, and **only `false` means
    // there is no record**: `true` is an entry that exists and would not
    // decrypt, `null` is a store that would not even say. To a guess limiter
    // those are the same answer, and it is not "start from zero".
    final exists = await SecureStorage.encryptedRecordExists(_recordKey);
    if (exists != false) {
      return (attempts: 0, until: null, boot: null, wait: null, blind: true);
    }

    // The two-key shape, for a wallet written before the record above. Read
    // and not migrated: the next failure writes the new record, and the next
    // success deletes both.
    final legacy = int.tryParse(await SecureStorage.read(_attemptsKey) ?? '');
    if (legacy == null) {
      return (attempts: 0, until: null, boot: null, wait: null, blind: false);
    }
    return (
      attempts: legacy,
      until: int.tryParse(await SecureStorage.read(_lockedUntilKey) ?? ''),
      boot: null,
      wait: null,
      blind: false,
    );
  }

  /// The wait a session that cannot read its own record is held to.
  ///
  /// **The first tier, not the longest, and the choice is deliberate.** Zero is
  /// what this did before and it is an unlimited search. An hour is the other
  /// end, and it would meet a legitimate owner whose keystore hiccupped with a
  /// wallet that will not open until they wait — punishing the common case to
  /// harden the rare one.
  ///
  /// Thirty seconds a guess ends brute force just as completely as an hour
  /// does: a million six-digit PINs at that rate is most of a year. And it
  /// costs somebody who did nothing wrong half a minute.
  static Duration get _blindLockout => lockoutFor(freeAttempts + 1);

  static Future<int> attempts() async => (await _state()).attempts;

  /// Writes the record, anchored to both clocks.
  ///
  /// `wait` is the tier this lockout came from and never changes while it runs:
  /// it is what bounds a wall deadline that has become nonsense, and what a
  /// reboot restarts.
  static Future<void> _arm({
    required int attempts,
    required Duration wait,
    int? boot,
  }) async {
    await SecureStorage.write(
      _recordKey,
      jsonEncode({
        'attempts': attempts,
        if (wait != Duration.zero) ...{
          'until': clock().add(wait).millisecondsSinceEpoch,
          'wait': wait.inMilliseconds,
          if (boot != null) 'boot': boot,
        },
      }),
    );
  }

  /// How much of [state]'s lockout is left, by whichever clock says more.
  static Future<Duration?> _left(
      ({int attempts, int? until, int? boot, int? wait, bool blind}) state) async {
    final wait = state.wait ?? lockoutFor(state.attempts).inMilliseconds;
    if (wait <= 0) return null;
    if (state.until == null && state.boot == null) return null;

    final boot = state.boot;
    if (boot != null) {
      final now = await uptime();
      if (now != null) {
        if (now < boot) {
          // **The device restarted, so this counter began again and nothing
          // here knows how long that took.** Believing the wall clock across a
          // restart is the hole being closed, so the lockout is re-anchored and
          // runs once more — at most an hour, and only for somebody who
          // rebooted mid-lockout.
          await _arm(
            attempts: state.attempts,
            wait: Duration(milliseconds: wait),
            boot: now,
          );
          return Duration(milliseconds: wait);
        }
        // **Authoritative where it exists, rather than one vote of two.** The
        // first version of this served whichever clock said more, and a phone
        // whose battery died and came up in 1970 then reported a deadline
        // decades away that the reading below could never talk down — the
        // wallet would have stayed shut for ever on a flat battery.
        final left = wait - (now - boot);
        return left <= 0 ? null : Duration(milliseconds: left);
      }
    }

    // No reading: the wall deadline is all there is. **Bounded by the tier it
    // came from**, so a clock that has gone backwards cannot lock a wallet for
    // longer than the wait somebody actually earned.
    if (state.until == null) return null;
    final left = state.until! - clock().millisecondsSinceEpoch;
    if (left <= 0) return null;
    return Duration(milliseconds: left > wait ? wait : left);
  }

  /// How much of the current lockout is left, or null when the wallet is open
  /// to guesses.
  ///
  /// Read from a stored deadline rather than a countdown held in memory: a
  /// countdown dies with the process, and force-stopping the app is the first
  /// thing anyone tries.
  static Future<Duration?> remaining() async {
    final state = await _state();
    if (state.blind) {
      // **Repaired, not just reported, because a blind state does not expire.**
      //
      // Returning the wait and stopping there was a lock with no key: this is
      // read *before* an attempt is counted, so `recordFailure` never runs, so
      // nothing ever replaces the record that could not be read — and the
      // wallet stays shut for ever on a corrupted throttle. Somebody whose
      // storage hiccupped once would have lost their wallet to the thing
      // guarding it.
      //
      // Writing a real deadline over it turns the blind state into an ordinary
      // lockout that ends. It starts at the first tier rather than at zero, so
      // the guess this call is standing in front of still costs thirty seconds,
      // and every guess after it is counted normally.
      await _arm(
        attempts: freeAttempts + 1,
        wait: _blindLockout,
        boot: await uptime(),
      );
      return _blindLockout;
    }

    return _left(state);
  }

  /// Records one wrong password and returns the wait it earned, if any.
  ///
  /// **One write, so the count and the deadline cannot disagree.**
  static Future<Duration?> recordFailure() async {
    final state = await _state();
    final next = state.attempts + 1;
    final lockout = lockoutFor(next);

    await _arm(attempts: next, wait: lockout, boot: await uptime());

    // A session that could not read the record is held to a wait whatever the
    // count says — stricter than a success, which is the direction it has to be.
    if (state.blind) return _blindLockout;
    if (lockout == Duration.zero) return null;
    return lockout;
  }

  /// Clears the count and any deadline. Only a correct password gets here —
  /// which is what makes the escalation above hold across restarts.
  ///
  /// Both shapes, because a wallet that has not failed since the record
  /// replaced the pair still has the pair.
  static Future<void> recordSuccess() async {
    await SecureStorage.delete(_recordKey);
    await SecureStorage.delete(_attemptsKey);
    await SecureStorage.delete(_lockedUntilKey);
  }

  /// "in 2 minutes" / "in 45 seconds", for the message on the lock screen.
  ///
  /// Rounded up, never to "in 0 seconds": a wait the person is told has ended
  /// while it has not is worse than a second of over-statement.
  static String describe(Duration d) {
    if (d.inMinutes >= 60) {
      final hours = (d.inMinutes / 60).ceil();
      return hours == 1 ? '1 hour' : '$hours hours';
    }
    if (d.inSeconds >= 60) {
      final minutes = (d.inSeconds / 60).ceil();
      return minutes == 1 ? '1 minute' : '$minutes minutes';
    }
    final seconds = d.inSeconds < 1 ? 1 : d.inSeconds;
    return seconds == 1 ? '1 second' : '$seconds seconds';
  }
}
