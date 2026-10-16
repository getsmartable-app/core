import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smartable_wallet_core/core/device_uptime.dart';
import 'package:smartable_wallet_core/core/secure_storage.dart';
import 'package:smartable_wallet_core/core/unlock_throttle.dart';

/// Before this existed, the only barrier between someone holding the phone and
/// the seed was `password.length >= 8` at creation. These tests are about the
/// properties that make the barrier real: that it escalates, that it survives a
/// restart, and that it never punishes the owner for something other than a
/// wrong password.
void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    // The throttle is encrypted-only now, so a test that mocks only
    // preferences would be testing a store that refuses every write.
    FlutterSecureStorage.setMockInitialValues({});
    UnlockThrottle.clock = DateTime.now;
    UnlockThrottle.uptime = () async => null;
  });

  tearDown(() {
    UnlockThrottle.clock = DateTime.now;
    UnlockThrottle.uptime = DeviceUptime.sinceBoot;
  });

  group('the schedule', () {
    test('the first four failures cost nothing', () {
      for (var i = 0; i <= UnlockThrottle.freeAttempts; i++) {
        expect(UnlockThrottle.lockoutFor(i), Duration.zero,
            reason: 'attempt $i should still be free');
      }
    });

    test('every failure after that waits strictly longer than the last', () {
      var previous = Duration.zero;
      for (var i = UnlockThrottle.freeAttempts + 1;
          i <= UnlockThrottle.freeAttempts + 4;
          i++) {
        final lockout = UnlockThrottle.lockoutFor(i);
        expect(lockout, greaterThan(previous),
            reason: 'a flat delay is a throughput limit, not a barrier');
        previous = lockout;
      }
    });

    test('it caps rather than growing without bound', () {
      // An unbounded schedule locks the owner out of their own funds for a
      // week over a forgotten keyboard layout.
      final capped = UnlockThrottle.lockoutFor(50);
      expect(capped, const Duration(hours: 1));
      expect(UnlockThrottle.lockoutFor(500), capped);
    });

    test('a hundred guesses cost more than a day', () {
      // The number that matters: this is what makes a weak password survive
      // someone with the phone in their hand.
      final total = List.generate(100, (i) => UnlockThrottle.lockoutFor(i + 1))
          .fold(Duration.zero, (a, b) => a + b);
      expect(total.inHours, greaterThan(24));
    });
  });

  group('counting', () {
    test('a failure is recorded and survives being read back', () async {
      await UnlockThrottle.recordFailure();
      await UnlockThrottle.recordFailure();
      expect(await UnlockThrottle.attempts(), 2);
    });

    test('early failures impose no wait', () async {
      for (var i = 0; i < UnlockThrottle.freeAttempts; i++) {
        expect(await UnlockThrottle.recordFailure(), isNull);
      }
      expect(await UnlockThrottle.remaining(), isNull);
    });

    test('the next failure locks, and the lock is readable', () async {
      for (var i = 0; i < UnlockThrottle.freeAttempts; i++) {
        await UnlockThrottle.recordFailure();
      }
      final lockout = await UnlockThrottle.recordFailure();
      expect(lockout, isNotNull);

      final left = await UnlockThrottle.remaining();
      expect(left, isNotNull);
      expect(left!.inSeconds, greaterThan(0));
      expect(left, lessThanOrEqualTo(lockout!));
    });

    test('only a correct password clears it', () async {
      for (var i = 0; i < UnlockThrottle.freeAttempts + 1; i++) {
        await UnlockThrottle.recordFailure();
      }
      expect(await UnlockThrottle.remaining(), isNotNull);

      await UnlockThrottle.recordSuccess();
      expect(await UnlockThrottle.attempts(), 0);
      expect(await UnlockThrottle.remaining(), isNull);
    });

    test('the count is not reset by waiting out a lockout', () async {
      // The clock can be moved forward to skip a wait. What must not be
      // skippable is the escalation: the next failure has to land in a longer
      // tier than the last, or the whole schedule is one 30-second delay.
      for (var i = 0; i < UnlockThrottle.freeAttempts + 1; i++) {
        await UnlockThrottle.recordFailure();
      }
      final first = UnlockThrottle.lockoutFor(await UnlockThrottle.attempts());

      final second = await UnlockThrottle.recordFailure();
      expect(second, greaterThan(first));
    });
  });

  group('what the person is told', () {
    test('never reports a wait that has not ended as over', () {
      expect(UnlockThrottle.describe(const Duration(milliseconds: 400)),
          '1 second');
      expect(UnlockThrottle.describe(const Duration(seconds: 61)), '2 minutes');
    });

    test('reads as a sentence, singular and plural', () {
      expect(UnlockThrottle.describe(const Duration(seconds: 30)), '30 seconds');
      expect(UnlockThrottle.describe(const Duration(minutes: 1)), '1 minute');
      expect(UnlockThrottle.describe(const Duration(minutes: 10)), '10 minutes');
      expect(UnlockThrottle.describe(const Duration(hours: 1)), '1 hour');
    });
  });

  /// **The one control in this wallet that used to open when storage failed.**
  ///
  /// Every read went through `SecureStorage.read`, which answers a keystore
  /// exception with null, and `int.tryParse(null) ?? 0` turned "I could not
  /// look" into "there were no failed attempts". The limit standing between
  /// somebody holding the phone and an unlimited on-device password search
  /// removed itself on exactly the device state an attacker can provoke.
  group('a store that will not answer', () {
    test('a record that will not parse is a lockout, not a clean slate',
        () async {
      await SecureStorage.writeEncryptedOnly('unlock_throttle', 'not json');
      final waiting = await UnlockThrottle.remaining();
      expect(waiting, isNotNull,
          reason: 'an unreadable limiter must not read as an unused one');
      expect(waiting, UnlockThrottle.lockoutFor(UnlockThrottle.freeAttempts + 1),
          reason: 'the first tier, not the longest: thirty seconds a guess '
              'ends a search, and costs an owner whose keystore hiccupped '
              'half a minute rather than an hour');
    });

    test('and a failure recorded against it stays shut', () async {
      await SecureStorage.writeEncryptedOnly('unlock_throttle', 'not json');
      expect(await UnlockThrottle.recordFailure(), isNotNull);
    });

    test('an empty device is open, because nothing has been guessed', () async {
      expect(await UnlockThrottle.remaining(), isNull);
      expect(await UnlockThrottle.attempts(), 0);
    });

    test('and the lockout it imposes ends, rather than shutting for ever',
        () async {
      // **The defect the repair above exists to avoid.** `remaining()` is read
      // before an attempt is counted, so `recordFailure` never runs on a
      // blocked wallet — and a blind state that only ever reported itself
      // would never be replaced. Somebody whose storage hiccupped once would
      // have lost their wallet to the thing guarding it.
      await SecureStorage.writeEncryptedOnly('unlock_throttle', 'not json');
      expect(await UnlockThrottle.remaining(), isNotNull);

      final raw = await SecureStorage.readEncryptedOnly('unlock_throttle');
      final decoded = jsonDecode(raw!) as Map<String, dynamic>;
      expect(decoded['until'], isA<int>(),
          reason: 'the blind state is replaced by a deadline that passes');
      expect(decoded['attempts'], UnlockThrottle.freeAttempts + 1);

      // And a correct password still clears it, like any other lockout.
      await UnlockThrottle.recordSuccess();
      expect(await UnlockThrottle.remaining(), isNull);
    });
  });

  group('the record, which used to be two of them', () {
    test('the count and the deadline are written together', () async {
      for (var i = 0; i <= UnlockThrottle.freeAttempts; i++) {
        await UnlockThrottle.recordFailure();
      }
      final raw = await SecureStorage.readEncryptedOnly('unlock_throttle');
      expect(raw, isNotNull);
      final decoded = jsonDecode(raw!) as Map<String, dynamic>;
      expect(decoded['attempts'], UnlockThrottle.freeAttempts + 1);
      expect(decoded['until'], isA<int>(),
          reason: 'one write, so an interruption cannot leave a raised count '
              'with no wait behind it');
    });

    test('it prefers the encrypted copy and leaves no plain one beside it',
        () async {
      // **Not "never in preferences", which would be the wrong rule here.**
      // The throttle is deliberately on the ordinary storage class: an
      // encrypted-only write is skipped when the keystore refuses, and a
      // skipped write is an attempt that was never counted. Durability wins
      // for a limiter. What must not happen is a readable duplicate sitting
      // beside a perfectly good encrypted one.
      await UnlockThrottle.recordFailure();
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getKeys().where((k) => k.contains('unlock')), isEmpty,
          reason: 'the encrypted write succeeded, so the plain copy goes');
      expect(await SecureStorage.read('unlock_throttle'), isNotNull);
    });

    test('a wallet written under the old two keys is still held to them',
        () async {
      // Read on the way past rather than migrated: the next failure writes the
      // new record and the next success deletes both.
      SharedPreferences.setMockInitialValues({
        'failed_unlock_attempts': '${UnlockThrottle.freeAttempts + 2}',
        'unlock_locked_until':
            '${DateTime.now().add(const Duration(minutes: 5)).millisecondsSinceEpoch}',
      });
      expect(await UnlockThrottle.attempts(), UnlockThrottle.freeAttempts + 2);
      expect(await UnlockThrottle.remaining(), isNotNull);

      await UnlockThrottle.recordSuccess();
      expect(await UnlockThrottle.remaining(), isNull);
      expect(await UnlockThrottle.attempts(), 0);
    });
  });

  group('the clock somebody holding the phone can set', () {
    /// **The wall clock is a setting, and this used to be the whole lock.**
    /// Settings → Date & time, move forward an hour, and the longest tier this
    /// schedule has was spent. The lockout is anchored to time since boot as
    /// well, and that anchor is authoritative wherever the platform gives one;
    /// the wall deadline is the fallback, capped by the tier it came from.
    Future<void> failUntilLocked() async {
      for (var i = 0; i <= UnlockThrottle.freeAttempts; i++) {
        await UnlockThrottle.recordFailure();
      }
    }

    test('moving the clock forward does not end a lockout', () async {
      var boot = 1000000;
      UnlockThrottle.uptime = () async => boot;
      await failUntilLocked();
      expect(await UnlockThrottle.remaining(), isNotNull);

      // A day forward on the wall, one second by the clock that counts.
      UnlockThrottle.clock = () => DateTime.now().add(const Duration(days: 1));
      boot += 1000;
      expect(await UnlockThrottle.remaining(), isNotNull,
          reason: 'the wait was skipped by changing a setting');
      expect((await UnlockThrottle.remaining())!.inSeconds, greaterThan(20));
    });

    test('and the wait still ends when the time is actually served', () async {
      var boot = 1000000;
      UnlockThrottle.uptime = () async => boot;
      await failUntilLocked();

      // Thirty seconds of real device time, wall clock untouched.
      boot += const Duration(seconds: 31).inMilliseconds;
      UnlockThrottle.clock = () =>
          DateTime.now().add(const Duration(seconds: 31));
      expect(await UnlockThrottle.remaining(), isNull);
    });

    test('a reboot restarts the lockout rather than trusting the wall',
        () async {
      var boot = 5000000;
      UnlockThrottle.uptime = () async => boot;
      await failUntilLocked();

      // The counter begins again, and the wall says the wait is long over.
      boot = 200;
      UnlockThrottle.clock = () => DateTime.now().add(const Duration(days: 2));
      final left = await UnlockThrottle.remaining();
      expect(left, isNotNull);
      expect(left!.inSeconds, greaterThan(25),
          reason: 'a restart is the lockout beginning again, not ending');

      // And it is re-anchored, so it now runs down against the new counter
      // instead of re-arming on every read.
      boot += const Duration(seconds: 31).inMilliseconds;
      expect(await UnlockThrottle.remaining(), isNull);
    });

    test('a clock that fell back to 1970 cannot lock the wallet for decades',
        () async {
      var boot = 9000000;
      UnlockThrottle.uptime = () async => boot;
      await failUntilLocked();

      // The battery died; the phone came up at the epoch. The deadline is now
      // decades in the future, and the wait it earned was thirty seconds.
      UnlockThrottle.clock = () => DateTime.fromMillisecondsSinceEpoch(0);
      final left = await UnlockThrottle.remaining();
      expect(left, isNotNull);
      expect(left!, lessThanOrEqualTo(const Duration(seconds: 30)));

      boot += const Duration(seconds: 31).inMilliseconds;
      expect(await UnlockThrottle.remaining(), isNull);
    });

    test('a device that will not say how long it has been up still locks',
        () async {
      // A platform with no channel registered answers null. The wall clock is
      // then all there is — bounded by the tier, which is what it always
      // should have been.
      UnlockThrottle.uptime = () async => null;
      await failUntilLocked();
      expect(await UnlockThrottle.remaining(), isNotNull);

      UnlockThrottle.clock = () => DateTime.now().add(const Duration(days: 1));
      expect(await UnlockThrottle.remaining(), isNull,
          reason: 'without a monotonic reading there is nothing else to use');
    });

    test('a record written before the anchor existed is bounded by its tier',
        () async {
      // Written by an older build: a deadline, no anchor, no tier.
      await SecureStorage.write(
        'unlock_throttle',
        jsonEncode({
          'attempts': UnlockThrottle.freeAttempts + 1,
          'until': DateTime.now()
              .add(const Duration(days: 365))
              .millisecondsSinceEpoch,
        }),
      );
      final left = await UnlockThrottle.remaining();
      expect(left, isNotNull);
      expect(left!, lessThanOrEqualTo(const Duration(seconds: 30)),
          reason: 'the tier is 30 seconds however far the deadline says');
    });
  });
}
