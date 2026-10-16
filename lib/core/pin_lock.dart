import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/foundation.dart' show listEquals;

import 'crypto_utils.dart';
import 'hardware_key.dart';

/// Six digits, made worth more than six digits.
///
/// **Why this is not simply a short password.** A password is defensible
/// because guessing it is expensive: PBKDF2 at 600k rounds means an attacker
/// who copies the storage file pays that cost per attempt on their own
/// hardware. Six digits have a million combinations, so that same attacker
/// pays a million times a fraction of a second and is through. Deriving a key
/// from a PIN and calling it done would be replacing the wallet's strength
/// with a number, quietly — which is exactly why an app PIN was refused here
/// for months.
///
/// What changes it is [DeviceKey]. The PIN's wrapper is sealed a second time by
/// a key that lives in the phone's key store and cannot be extracted, so the
/// stored blob is not a thing anybody can take away and work on. Through the
/// app, every guess is made on this phone against a throttle that reaches an
/// hour a try — a million of those is over a century.
///
/// The PBKDF2 pass is kept anyway. It buys nothing against the phone and
/// everything against the one case where the device key leaks: without it, a
/// leaked device key would hand over the wallet instantly rather than after a
/// million derivations.
///
/// **What it does not do, exactly (audit M2).** The throttle is the app's, not
/// the key store's. Whoever can make one call to the device key — root, an
/// instrumented process, a forensic tool — removes the outer seal in that one
/// call. On Android 15 and later the seal is made by the key that refuses
/// while the phone is locked ([DeviceKeyKind.unlockedOnly]), so that call
/// fails on a locked phone; on an unlocked, rooted phone it does not, on any
/// version.
///
/// **What is under the seal since 3 October 2026 ([version] 2).** Under it the
/// million PINs used to be PBKDF2 alone, work that could be carried off the
/// phone: 2.4 hours on the eight cores of an Apple M3 laptop, measured that
/// day, less on a graphics card. A memory-hard function was the obvious change
/// and was measured instead of assumed — Argon2id at 64 MiB costs 0.13 s a
/// guess against PBKDF2's 0.068, twice, and the work stays portable. So the
/// PIN now goes through [PinPepper] first, a keyed function of this phone's
/// key store, and every guess is a key-store operation made here, one at a
/// time, while the phone stays unlocked and compromised. That is a change in
/// where the work can happen, not a promise that it cannot: the password and
/// the phrase are still what stand behind the PIN on such a phone, as they are
/// behind Trust Wallet's passcode and MetaMask's.
abstract final class PinLock {
  static final _random = Random.secure();

  /// Six, and fixed. A variable length turns "is this my PIN" into "how long
  /// was my PIN", which people answer wrong under stress at exactly the moment
  /// they most need to get in.
  static const int digits = 6;

  static bool isValidShape(String pin) =>
      pin.length == digits && RegExp(r'^\d+$').hasMatch(pin);

  /// Whether a PIN can be offered at all on this phone.
  ///
  /// False is a real answer on a device whose key store refuses. Offering the
  /// PIN anyway would mean six digits protecting a file that could be carried
  /// off and opened at leisure — the app would be advertising a lock it does
  /// not have. Both keys, the seal and the pepper.
  static Future<bool> isAvailable() async =>
      await DeviceKey.isSupported() && await PinPepper.isSupported();

  /// The format a new PIN is sealed in: 2, with [PinPepper] in the
  /// derivation. A payload with no version is 1 — PBKDF2 alone — and is still
  /// opened, and moved to 2 by [openAndUpgrade] the next time it opens.
  static const int version = 2;

  /// What [PinPepper] is asked for a PIN: a domain, the salt, the digits.
  static Uint8List _pepperInput(List<int> salt, String pin) => Uint8List.fromList(
      [...utf8.encode('smartable-pin-v2|'), ...salt, ...utf8.encode('|$pin')]);

  /// What [PinPepper] is asked to name its key: an answer stored inside the
  /// seal, so a key that was replaced is told apart from a wrong PIN. Without
  /// it a lost key would read as every PIN being wrong, and the person would
  /// be locked out by the throttle for typing the right one.
  static final Uint8List _keyCheckInput =
      Uint8List.fromList(utf8.encode('smartable-pin-v2|key-check'));

  /// What PBKDF2 is given in place of the bare digits.
  static String _peppered(Uint8List pepper, String pin) =>
      '${pepper.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}:$pin';

  /// Marks a blob sealed by the [DeviceKeyKind.unlockedOnly] key. Not a
  /// character base64 uses, so a blob from before this — no mark — can never
  /// be read as one with it, and which key opens a blob is read, not guessed
  /// by trying both.
  static const _unlockedMark = 'unlocked:';

  /// Which device key sealed [blob].
  static DeviceKeyKind kindOf(String blob) => blob.startsWith(_unlockedMark)
      ? DeviceKeyKind.unlockedOnly
      : DeviceKeyKind.anyTime;

  static String _stored(Uint8List sealed, DeviceKeyKind kind) => switch (kind) {
        DeviceKeyKind.anyTime => base64Encode(sealed),
        DeviceKeyKind.unlockedOnly => '$_unlockedMark${base64Encode(sealed)}',
      };

  static Uint8List _sealedPart(String blob) => base64Decode(
      kindOf(blob) == DeviceKeyKind.unlockedOnly
          ? blob.substring(_unlockedMark.length)
          : blob);

  /// [secret] sealed under [pin] and this device, ready to store.
  static Future<String> seal(Uint8List secret, String pin) async {
    if (!isValidShape(pin)) {
      throw ArgumentError('A PIN is $digits digits.');
    }
    if (!await PinPepper.prepare()) throw const HardwareKeyUnavailable();
    final salt = List<int>.generate(16, (_) => _random.nextInt(256));
    final pepper = await PinPepper.of(_pepperInput(salt, pin));
    final keyCheck = await PinPepper.of(_keyCheckInput);
    final derived = await CryptoUtils.deriveKey(_peppered(pepper, pin), salt);

    // Wrapped, then sealed. The order matters: sealing first would leave the
    // PIN wrapping something the device key had already made opaque, and a
    // wrong PIN would be indistinguishable from a dead device key.
    final payload = jsonEncode({
      'v': version,
      'salt': base64Encode(salt),
      'key': CryptoUtils.wrapKey(secret, derived),
      'check': base64Encode(keyCheck),
    });
    final kind = await DeviceKey.strongest();
    if (kind == null) throw const HardwareKeyUnavailable();
    final sealed = await DeviceKey.seal(
        Uint8List.fromList(utf8.encode(payload)),
        kind: kind);
    return _stored(sealed, kind);
  }

  /// [blob] sealed again under the key that refuses while the phone is locked,
  /// or null when there is nothing to move — it is there already, or this
  /// phone cannot hold that key (below Android 15).
  ///
  /// **No PIN, and no secret.** Only the outer seal changes: what comes out of
  /// the old key is the PIN's own wrapper, which this never opens, so a PIN
  /// armed before the second key existed moves on the next unlock by any door
  /// without anybody typing it.
  ///
  /// **Read back before it is handed over.** A seal the new key cannot open
  /// would replace a working PIN with a dead one; this opens what it made and
  /// compares, and throws [HardwareKeyUnavailable] rather than return it.
  static Future<String?> upgrade(String blob) async {
    if (kindOf(blob) == DeviceKeyKind.unlockedOnly) return null;
    if (await DeviceKey.strongest() != DeviceKeyKind.unlockedOnly) return null;
    final wrapper =
        await DeviceKey.open(_sealedPart(blob), kind: DeviceKeyKind.anyTime);
    final sealed =
        await DeviceKey.seal(wrapper, kind: DeviceKeyKind.unlockedOnly);
    final back =
        await DeviceKey.open(sealed, kind: DeviceKeyKind.unlockedOnly);
    if (!listEquals(back, wrapper)) throw const HardwareKeyUnavailable();
    return _stored(sealed, DeviceKeyKind.unlockedOnly);
  }

  /// The secret back, or [WrongPin].
  ///
  /// Throws [HardwareKeyUnavailable] when the device key itself is gone, which
  /// is a different sentence on screen: the PIN was right and there is nothing
  /// left for it to open, so the way in is the password. So is a [PinPepper]
  /// key that is not the one the PIN was sealed through — [HardwareKeyGone],
  /// never [WrongPin].
  static Future<Uint8List> open(String blob, String pin) async =>
      (await openAndUpgrade(blob, pin, upgrade: false)).secret;

  /// [open], and where [blob] is in format 1 and this phone can hold the
  /// pepper, the same secret sealed again in format 2 under the same PIN —
  /// which only an open can do, since the PIN goes into the new derivation.
  /// [upgraded] is null when there is nothing to move or it could not be made;
  /// the caller stores it only over the blob it was made from.
  static Future<({Uint8List secret, String? upgraded})> openAndUpgrade(
    String blob,
    String pin, {
    bool upgrade = true,
  }) async {
    final plain = await DeviceKey.open(_sealedPart(blob), kind: kindOf(blob));

    final Map<String, dynamic> payload;
    try {
      payload = jsonDecode(utf8.decode(plain)) as Map<String, dynamic>;
    } catch (_) {
      // The device key opened it and it is not ours. Nothing a PIN can fix.
      throw const HardwareKeyUnavailable();
    }
    final salt = base64Decode(payload['salt'] as String);
    final format = payload['v'] ?? 1;

    final String derivedFrom;
    if (format == version) {
      final stored = payload['check'];
      final check = await PinPepper.of(_keyCheckInput);
      if (stored is! String || !listEquals(base64Decode(stored), check)) {
        // Another key than the one this PIN was sealed through. The PIN may
        // well be right; there is nothing left for it to open.
        throw const HardwareKeyGone();
      }
      derivedFrom = _peppered(await PinPepper.of(_pepperInput(salt, pin)), pin);
    } else if (format == 1) {
      derivedFrom = pin;
    } else {
      // A format this build does not know: never guessed at, never counted.
      throw const HardwareKeyUnavailable();
    }

    final derived = await CryptoUtils.deriveKey(derivedFrom, salt);
    final Uint8List secret;
    try {
      secret = CryptoUtils.unwrapKey(payload['key'] as String, derived);
    } catch (_) {
      // AES-GCM's tag failed, which is the only way a wrong PIN shows up. The
      // count of these belongs to the caller, beside the password's — see
      // UnlockThrottle, and note that both share one counter on purpose so
      // that alternating between the two does not reset it.
      throw const WrongPin();
    }

    String? upgraded;
    if (upgrade && format == 1) {
      try {
        final candidate = await seal(secret, pin);
        // **Opened before it is handed over**, as [upgrade] reads its seal
        // back: a blob that would not open again would replace a working PIN
        // with a dead one.
        final back = await openAndUpgrade(candidate, pin, upgrade: false);
        if (listEquals(back.secret, secret)) upgraded = candidate;
      } catch (_) {
        // The PIN keeps the format it has; the next unlock tries again.
        upgraded = null;
      }
    }
    return (secret: secret, upgraded: upgraded);
  }
}

/// The PIN did not open it. Distinct from every hardware answer because the
/// screen does something different: it counts this one.
class WrongPin implements Exception {
  const WrongPin();

  @override
  String toString() => 'That PIN is not right.';
}
