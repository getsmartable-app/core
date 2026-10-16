
import 'wallet_doors.dart';
import 'package:flutter/services.dart';

import 'key_backing.dart';

/// The phone's own key store, as far as this app is concerned.
///
/// It holds a copy of the vault key — the random 256 bits the recovery phrase
/// is sealed under — inside hardware that will use it and never hand it back.
/// The app can ask for something to be wrapped or unwrapped; it cannot ask for
/// the key. On a device with a secure element the key never enters the
/// operating system's memory at all, so a stolen storage file is worth nothing
/// without the phone, and this door does not open a stolen phone without the
/// person's biometric — the password and the PIN remain doors of their own.
///
/// **Only on hardware that has one.** Which kind of hardware is holding it —
/// a separate chip, the phone's secure processor, or nothing — is measured by
/// [describe], and a screen that says anything about it reads that answer.
///
/// **This is an addition, never a replacement.** The password wraps the same
/// vault key and always will. Hardware keys die for ordinary reasons — a new
/// fingerprint, a removed screen lock, a restored backup, a new phone — and a
/// wallet whose only key can die is a wallet that eats somebody's money on an
/// ordinary Tuesday.
abstract final class HardwareKey {
  static const MethodChannel _channel =
      MethodChannel('com.smartable.wallet/hardware_key');

  /// Overridable so tests can answer for the platform without one.
  static MethodChannel channel = _channel;

  /// Whether this device can hold the key.
  ///
  /// False is a normal answer, not a failure: an old phone, no screen lock
  /// set, or a keystore that refuses. The app must say so plainly rather than
  /// quietly falling back — silently protecting less than the user was told is
  /// worse than protecting less.
  static Future<bool> isSupported() async {
    try {
      return await channel.invokeMethod<bool>('isSupported') ?? false;
    } on PlatformException {
      return false;
    } on MissingPluginException {
      // A platform where this is not built. Android and iOS both have it.
      return false;
    }
  }

  /// What is holding this key, for the screen that reports it.
  static Future<KeyStoreReport> describe() => keystoreDescribe(channel);

  /// [bytes] sealed by the device key, ready to store.
  static Future<Uint8List> wrap(Uint8List bytes) async {
    final wrapped = await _invoke('wrap', bytes);
    if (wrapped == null) throw const HardwareKeyUnavailable();
    return wrapped;
  }

  /// The bytes back, once the person has proved who they are.
  static Future<Uint8List> unwrap(Uint8List blob) async {
    final plain = await _invoke('unwrap', blob);
    if (plain == null) throw const HardwareKeyUnavailable();
    return plain;
  }

  /// Drops the device key. The password path is unaffected — that is the whole
  /// reason this can be dropped at all.
  static Future<void> forget() async {
    try {
      await channel.invokeMethod<void>('forget');
    } on PlatformException {
      // Nothing to forget is the same outcome as having forgotten it.
    } on MissingPluginException {
      // ignore
    }
  }

  static Future<Uint8List?> _invoke(String method, Uint8List bytes) =>
      keystoreInvoke(channel, method, bytes);
}

/// Both keys the wallet may hold, as the platform reports them.
///
/// What any screen claiming something about hardware protection reads — the
/// security screen, and the rooted-phone warning.
Future<SecurityKeyReport> describeWalletKeys() async => SecurityKeyReport(
      unlockKey: await HardwareKey.describe(),
      pinKey: await DeviceKey.describe(),
    );

/// Which of the PIN's two keys sealed a blob (audit M2).
enum DeviceKeyKind {
  /// Bound to the phone and usable whether it is locked or not. Every PIN on a
  /// phone below Android 15, and every PIN armed before the second key existed.
  anyTime,

  /// Bound to the phone and refused by the keystore while the phone is locked
  /// — `setUnlockedDeviceRequired`, Android 15 and later.
  unlockedOnly,
}

/// The other key in the store: bound to this phone, gated by nothing.
///
/// It exists for the PIN, and the reason is worth stating where the code is.
/// Six digits cannot protect anything by being hard to guess — a million
/// combinations fall in milliseconds against a file somebody has copied. What
/// makes them worth more is that the file cannot be attacked away from this
/// phone without first asking this key to open it, and the running app asks
/// once per guess, against a throttle that escalates to an hour.
///
/// So this key asks for nothing. Requiring a fingerprint would mean the PIN
/// could only be typed by somebody who had already passed the gate the PIN is
/// there to replace, and a new fingerprint would silently kill it — a PIN that
/// stops working for a reason nobody would connect to it.
///
/// **The honest limit, stated exactly (audit M2).** The throttle belongs to the
/// app, not to this key. Whoever can make one call to the key — root, an
/// instrumented process, a forensic tool — takes the outer layer off in that
/// one call, and what is under it is six digits behind PBKDF2 at 600,000
/// rounds: a million guesses, minutes on one graphics card, with no throttle
/// anywhere. On Android 15 and later the PIN is sealed under the
/// [DeviceKeyKind.unlockedOnly] key instead, and that one call fails while the
/// phone is locked — a seized, locked phone gives nothing to work on without
/// its own lock screen code. An unlocked, rooted phone still does, on every
/// version; there the password and the phrase are what stand behind the PIN.
/// The same is true of Trust Wallet's passcode and MetaMask's, and it is not
/// improved by pretending otherwise.
abstract final class DeviceKey {
  static const MethodChannel _channel =
      MethodChannel('com.smartable.wallet/device_key');
  static const MethodChannel _unlockedChannel =
      MethodChannel('com.smartable.wallet/device_key_unlocked');

  /// Overridable so tests can answer for the platform without one.
  static MethodChannel channel = _channel;

  /// The [DeviceKeyKind.unlockedOnly] key. The platform answers "not
  /// supported" below Android 15, and so does a missing handler.
  static MethodChannel unlockedChannel = _unlockedChannel;

  static MethodChannel _of(DeviceKeyKind kind) => switch (kind) {
        DeviceKeyKind.anyTime => channel,
        DeviceKeyKind.unlockedOnly => unlockedChannel,
      };

  static Future<bool> _supported(MethodChannel channel) async {
    try {
      return await channel.invokeMethod<bool>('isSupported') ?? false;
    } on PlatformException {
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  /// The key a new PIN is sealed under: the one that refuses while the phone
  /// is locked where this phone can hold it, the other one where it cannot,
  /// and null where it can hold neither.
  ///
  /// Asked in that order on purpose. The platform answers "supported" by
  /// making the key, so asking about the any-time key on a phone that will use
  /// the other would leave a key behind that nothing needs.
  static Future<DeviceKeyKind?> strongest() async {
    if (await _supported(unlockedChannel)) return DeviceKeyKind.unlockedOnly;
    if (await _supported(channel)) return DeviceKeyKind.anyTime;
    return null;
  }

  /// Whether this phone can hold either key. False means no PIN can be
  /// offered: there would be nothing making the six digits worth more than
  /// six digits.
  static Future<bool> isSupported() async => await strongest() != null;

  /// What is holding the PIN's key, for the screen that reports it — the
  /// unlocked-only key where one exists, the any-time key otherwise.
  static Future<KeyStoreReport> describe() async {
    final unlocked = await keystoreDescribe(unlockedChannel);
    return unlocked.exists ? unlocked : await keystoreDescribe(channel);
  }

  /// [bytes] sealed to this device under [kind], ready to store.
  static Future<Uint8List> seal(Uint8List bytes,
      {required DeviceKeyKind kind}) async {
    final sealed = await keystoreInvoke(_of(kind), 'wrap', bytes);
    if (sealed == null) throw const HardwareKeyUnavailable();
    return sealed;
  }

  /// The bytes back from the [kind] key. No prompt: this key is not the gate,
  /// the PIN is.
  static Future<Uint8List> open(Uint8List blob,
      {required DeviceKeyKind kind}) async {
    final plain = await keystoreInvoke(_of(kind), 'unwrap', blob);
    if (plain == null) throw const HardwareKeyUnavailable();
    return plain;
  }

  /// Drops the [kind] key, or both when [kind] is null, and with it every PIN
  /// blob sealed under what was dropped.
  static Future<void> forget({DeviceKeyKind? kind}) async {
    for (final each in kind == null ? DeviceKeyKind.values : [kind]) {
      try {
        await _of(each).invokeMethod<void>('forget');
      } on PlatformException {
        // Nothing to forget is the same outcome as having forgotten it.
      } on MissingPluginException {
        // ignore
      }
    }
  }
}

/// The keyed function every PIN guess goes through: an HMAC in the Android
/// keystore, a Diffie–Hellman agreement in the Secure Enclave — see
/// `PinPepperKey.kt` and `PinPepperKey.swift`.
///
/// **Why the PIN needs it** (3 October 2026). [DeviceKey] seals the PIN's
/// wrapper, so a guess cannot be made off this phone — until one call to that
/// key takes the seal off on a compromised, unlocked phone. Under it the
/// million PINs were PBKDF2 alone: 2.4 hours on the eight cores of an Apple M3
/// laptop, measured that day, and less on a graphics card. A memory-hard
/// function would have doubled it (Argon2id at 64 MiB: 0.13 s a guess against
/// 0.068, measured beside it) and left the work portable. With this in the
/// derivation every guess is an operation of this phone's key store, made here,
/// one at a time — the work can no longer be carried away.
///
/// **A function of the key**, so a lost key is not a wrong PIN: [of] answers
/// [HardwareKeyGone] when there is no key and never makes one. Only [prepare],
/// when a PIN is armed, does.
abstract final class PinPepper {
  static const MethodChannel _channel =
      MethodChannel('com.smartable.wallet/pin_pepper');

  /// Overridable so tests can answer for the platform without one.
  static MethodChannel channel = _channel;

  /// Whether this phone can hold the key. Leaves none behind.
  static Future<bool> isSupported() async {
    try {
      return await channel.invokeMethod<bool>('isSupported') ?? false;
    } on PlatformException {
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  /// The key, made if there is none. False where the phone cannot hold one.
  static Future<bool> prepare() async {
    try {
      return await channel.invokeMethod<bool>('prepare') ?? false;
    } on PlatformException {
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  /// The keyed answer for [input], 32 bytes. Throws [HardwareKeyGone] when
  /// the key is not there, and never makes one: a new key would give a right
  /// PIN a different answer, and the person would be throttled for it.
  static Future<Uint8List> of(Uint8List input) async {
    final answer = await keystoreInvoke(channel, 'mac', input);
    if (answer == null || answer.length != 32) {
      throw const HardwareKeyUnavailable();
    }
    return answer;
  }

  /// Drops the key, and with it every PIN sealed through it.
  static Future<void> forget() async {
    try {
      await channel.invokeMethod<void>('forget');
    } on PlatformException {
      // Nothing to forget is the same outcome as having forgotten it.
    } on MissingPluginException {
      // ignore
    }
  }
}

/// Asks a key what is holding it.
///
/// **Every failure is [KeyStoreReport.unknown], and that is the point.** This
/// answers a question a screen prints as a claim about somebody's money, so
/// there is exactly one direction it may be wrong in: silence. A platform that
/// throws, a build with no handler, an older app on the other side of the
/// channel — all of them mean "not answered", never "software" and certainly
/// never "hardware".
Future<KeyStoreReport> keystoreDescribe(MethodChannel channel) async {
  try {
    final raw = await channel.invokeMethod<Map<Object?, Object?>>('describe');
    return KeyStoreReport.fromPlatform(raw);
  } on PlatformException {
    return const KeyStoreReport.unknown();
  } on MissingPluginException {
    return const KeyStoreReport.unknown();
  }
}

/// Shared plumbing for both keys above.
///
/// The words the system's own fingerprint sheet shows.
///
/// **Android draws that sheet, not this app, so the only way it speaks the
/// reader's language is for us to hand it the words.** They were three
/// constants in `HardwareVaultKey.kt` — the one surface of this wallet that
/// stayed English in all thirteen languages, and the first thing a person sees
/// on opening the app. Reported by the owner on 13 September 2026.
///
/// Carried rather than looked up, because the key is unwrapped from
/// `WalletProvider`, which is pure of `BuildContext` and should stay that way.
/// Null until the app has resolved a language — the native side then keeps its
/// own English, which is the right answer for a prompt raised before there is
/// a widget tree to ask.
class UnlockPromptWords {
  const UnlockPromptWords({
    required this.title,
    required this.subtitle,
    required this.cancel,
    required this.cancelToPassword,
  });

  /// What the fingerprint is for. Names the product, which is not translated.
  final String title;

  /// Which sensor the system is about to read.
  final String subtitle;

  /// The way out when a PIN is armed, and it means *this wallet's* PIN rather
  /// than the phone's — which this wallet does not accept as a door at all.
  final String cancel;

  /// The way out when no PIN is armed.
  ///
  /// **The sheet used to say "Use PIN instead" on a wallet with no PIN.**
  /// Owner's report, 21 September 2026: with the PIN switched off, unlocking
  /// raised the fingerprint sheet with a button offering a door that did not
  /// exist — and pressing it closed the sheet and asked for the password,
  /// which is what it should have said in the first place. The label was
  /// passed unconditionally from `main.dart`, where whether a PIN exists is
  /// not knowable, so it named the more common case and was wrong for the
  /// rest.
  ///
  /// This is not cosmetic. That button is the only thing on a system sheet
  /// this app writes, the sheet is the first thing somebody sees on opening
  /// the wallet, and a wallet that offers a credential it does not accept is
  /// teaching people to look for the wrong one — the phone's PIN is a door
  /// this wallet refuses by design, and "Use PIN instead" on a phone that has
  /// one reads exactly like an offer to use it.
  final String cancelToPassword;

  Map<String, String> get asArguments => {
        'promptTitle': title,
        'promptSubtitle': subtitle,
        'promptCancel': pinArmedAsObserved ? cancel : cancelToPassword,
      };
}

// Which door the sheet offers on the way out is `pinArmedAsObserved` — see
// `wallet_doors.dart` for why the answer is remembered rather than awaited.

/// Set by the app each time its language resolves. See `main.dart`.
UnlockPromptWords? unlockPromptWords;

/// One copy rather than two, because the interesting part is the error mapping
/// and two copies of that would drift — the difference between these keys is
/// which alias they speak for and whether the chip asks for a person, not how
/// a `PlatformException` is read.
Future<Uint8List?> keystoreInvoke(
    MethodChannel channel, String method, Uint8List bytes) async {
  try {
    return await channel.invokeMethod<Uint8List>(method, {
      'bytes': bytes,
      // Absent before a language is resolved, and the native side then keeps
      // its own English rather than showing a sheet with empty rows.
      ...?unlockPromptWords?.asArguments,
    });
  } on PlatformException catch (e) {
    throw switch (e.code) {
      'auth_required' => const HardwareKeyNeedsAuth(),
      'key_gone' => const HardwareKeyGone(),
      // **The prompt happened and did not authorise the key.** Cancelled,
      // locked out, or a phone with no strong biometric at all: one class,
      // because the app does the same thing with all three — this door did not
      // open, and its own PIN or password is the way in — and three [Declined]
      // values, because they do not say the same thing to a person.
      //
      // Distinct from `HardwareKeyUnavailable`, which says the device cannot
      // hold a key at all; telling somebody their phone is incapable because
      // they pressed Cancel is a different and wrong sentence.
      'auth_cancelled' => const HardwareKeyDeclined(Declined.cancelled),
      'auth_lockout' => const HardwareKeyDeclined(Declined.lockout),
      'auth_unavailable' => const HardwareKeyDeclined(Declined.unavailable),
      _ => const HardwareKeyUnavailable(),
    };
  } on MissingPluginException {
    throw const HardwareKeyUnavailable();
  }
}

/// Base for the three answers that are not "here are your bytes", kept
/// distinct because the app does something different with each.
sealed class HardwareKeyException implements Exception {
  const HardwareKeyException();
  String get message;

  @override
  String toString() => message;
}

/// Which of the three ways the prompt ended without authorising the key.
///
/// **Kept apart because they need different sentences and the app has no
/// other way to tell them apart.** The platform sends three codes and they
/// used to collapse into one exception here, which left the screens reading
/// `BiometricAuth.lastError` to recover what had been thrown away — a value
/// belonging to some earlier `local_auth` call, and on the paths that no
/// longer make one, stale or null.
enum Declined {
  /// "Use PIN instead", the back gesture, or the system taking the sheet away.
  cancelled,

  /// Too many failed fingers. The sensor is shut, for a while or until the
  /// phone is unlocked its own way.
  lockout,

  /// Nothing enrolled, or a Class 2 sensor — which cannot back a keystore key
  /// on any Android version. This phone does not get this door at all.
  unavailable,
}

/// The biometric did not authorise the key: cancelled, locked out, or this
/// phone has no strong biometric to offer.
///
/// The key is intact and the wallet's own doors are open — this is the one
/// refusal that is not a fault of any kind.
class HardwareKeyDeclined extends HardwareKeyException {
  const HardwareKeyDeclined(this.reason);

  final Declined reason;

  /// Each says what happened and names the way in that still works. None of
  /// them says the wallet is broken, because none of these mean that.
  @override
  String get message => switch (reason) {
        Declined.cancelled =>
          'Quick unlock was cancelled. Your PIN and password still open this '
              'wallet.',
        Declined.lockout =>
          'Too many attempts, so the fingerprint sensor is closed for now. '
              'Your PIN and password still open this wallet.',
        Declined.unavailable =>
          'This phone has no fingerprint the wallet can use. Your PIN and '
              'password open it.',
      };
}

/// This device will not hold a key. Use the password and say so.
class HardwareKeyUnavailable extends HardwareKeyException {
  const HardwareKeyUnavailable();

  @override
  String get message => 'This device cannot store the key in hardware.';
}

/// Prove it is you, then try again. The one case worth retrying.
class HardwareKeyNeedsAuth extends HardwareKeyException {
  const HardwareKeyNeedsAuth();

  @override
  String get message => 'Confirm it is you to continue.';
}

/// The key is gone for good: a new fingerprint enrolled, the screen lock
/// removed, the phone restored from a backup.
///
/// Not an error to retry and not a reason to panic. The password still opens
/// the wallet, and quick unlock can be armed again afterwards — but the app has
/// to say which of those happened, because "confirm it is you" repeated
/// forever is how somebody concludes their wallet is broken.
class HardwareKeyGone extends HardwareKeyException {
  const HardwareKeyGone();

  @override
  String get message =>
      'Your device key was reset. Unlock with your password once to restore it.';
}
