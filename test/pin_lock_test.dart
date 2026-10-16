import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smartable_wallet_core/core/crypto_utils.dart';
import 'package:smartable_wallet_core/core/hardware_key.dart';
import 'package:smartable_wallet_core/core/pin_lock.dart';

import 'support/fake_pin_pepper.dart';

/// Six digits holding a wallet key, and the reason that is allowed.
///
/// A PIN was refused here for months on an argument that was correct: a million
/// combinations against a stored blob is not protection, whatever the
/// derivation costs. What answers it is that the blob is sealed to the phone
/// first, so there is no "against a stored blob" — the guesses have to be made
/// here, one at a time, through the throttle. These tests hold both halves: the
/// PIN really is what opens it, and the device really is what makes that worth
/// anything.
void main() {
  final pepper = useFakePinPepper();
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('test.device_key');
  DeviceKey.channel = channel;

  const pin = '135790';
  final secret = Uint8List.fromList(List<int>.generate(32, (i) => i * 7 % 256));

  /// A stand-in for the phone's key store: it seals by prefixing a byte that
  /// only it knows how to strip, and refuses in the ways the real one refuses.
  String? refuseWith;
  var deviceKeyAlive = true;
  final wrapped = <Uint8List>[];

  setUp(() {
    refuseWith = null;
    deviceKeyAlive = true;
    wrapped.clear();

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      if (refuseWith != null) throw PlatformException(code: refuseWith!);
      final bytes = call.arguments?['bytes'] as Uint8List?;
      switch (call.method) {
        case 'isSupported':
          return true;
        case 'wrap':
          wrapped.add(bytes!);
          return Uint8List.fromList([42, ...bytes]);
        case 'unwrap':
          if (!deviceKeyAlive) {
            throw PlatformException(code: 'key_gone');
          }
          return Uint8List.fromList(bytes!.sublist(1));
        case 'forget':
          deviceKeyAlive = false;
          return null;
      }
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('the right PIN gives the secret back', () async {
    final blob = await PinLock.seal(secret, pin);
    expect(await PinLock.open(blob, pin), secret);
  });

  test('a wrong PIN does not, and says which kind of wrong it is', () async {
    final blob = await PinLock.seal(secret, pin);
    // WrongPin rather than a bare failure: the screen counts this one against
    // the throttle, and must not count a dead device key the same way.
    expect(() => PinLock.open(blob, '135791'), throwsA(isA<WrongPin>()));
  });

  test('every neighbouring PIN is wrong, not just an obviously different one',
      () async {
    // A million combinations is only a defence if they are all actually
    // distinct. A derivation that ignored a digit would pass the test above.
    final blob = await PinLock.seal(secret, pin);
    for (final wrong in ['035790', '135700', '135799', '235790', '135780']) {
      expect(() => PinLock.open(blob, wrong), throwsA(isA<WrongPin>()),
          reason: '$wrong opened a blob sealed with $pin');
    }
  });

  test('two seals of the same secret and PIN are different blobs', () async {
    // Fresh salt each time. Without it, two wallets with the same PIN share a
    // derivation, and one cracked PIN is every wallet that chose it.
    expect(await PinLock.seal(secret, pin), isNot(await PinLock.seal(secret, pin)));
  });

  test('nothing is stored that the device key has not sealed', () async {
    // The one property the whole design rests on, and the only part of it this
    // layer can be held to: what goes to storage is the key store's output, not
    // ours. The stub above seals by prefixing a byte — a real key store
    // encrypts — so asserting the *content* is unreadable here would be
    // testing the stub. What is ours to get right is that the sealing happens
    // at all, and that the PIN's wrapper is what goes into it.
    final blob = await PinLock.seal(secret, pin);

    expect(wrapped, hasLength(1), reason: 'the device key was not asked once');
    expect(base64Decode(blob), Uint8List.fromList([42, ...wrapped.single]),
        reason: 'the stored blob must be what the key store handed back');
  });

  test('the secret is already unreadable before the device sees it', () async {
    // Belt and braces, and this half *is* ours: if the device key ever leaks,
    // what it was hiding must still be a wrapped key rather than the key. So
    // the payload handed to the key store must not contain the secret.
    await PinLock.seal(secret, pin);
    final payload = jsonDecode(utf8.decode(wrapped.single)) as Map;

    expect(payload['salt'], isNotNull);
    expect(base64Decode(payload['key'] as String),
        isNot(containsAllInOrder(secret)),
        reason: 'a leaked device key would then be the whole wallet, with no '
            'million derivations in the way');
  });

  test('a dead device key is not reported as a wrong PIN', () async {
    // The difference decides what the screen says. "That PIN is not right" sent
    // to somebody whose PIN *is* right, over and over, is how a person concludes
    // the wallet ate their money — the answer here is the password.
    final blob = await PinLock.seal(secret, pin);
    await DeviceKey.forget();

    expect(() => PinLock.open(blob, pin), throwsA(isA<HardwareKeyGone>()));
  });

  test('a phone that cannot hold the key says so before a PIN is offered',
      () async {
    refuseWith = 'unavailable';
    expect(await PinLock.isAvailable(), isFalse,
        reason: 'six digits over a file anybody could carry off is a lock the '
            'app would be advertising and not have');
  });

  group('format 2: every guess goes through the phone\'s key', () {
    /// What an attacker holds after one call to the device key: the payload
    /// under the seal — the stub's seal is a prefixed byte.
    Map<String, dynamic> underTheSeal(String blob) =>
        jsonDecode(utf8.decode(base64Decode(blob).sublist(1)))
            as Map<String, dynamic>;

    test('the payload says format 2 and names the key it was sealed through',
        () async {
      final payload = underTheSeal(await PinLock.seal(secret, pin));
      expect(payload['v'], PinLock.version);
      expect(payload['check'], isA<String>());
    });

    test('the seal off is no longer enough: the digits alone open nothing',
        () async {
      // **The point of the format.** With the outer seal taken off — the one
      // call a compromised, unlocked phone allows — format 1 was PBKDF2 over
      // the digits, a million guesses to run anywhere. Format 2 is not: the
      // right PIN itself, without the phone's key, opens nothing.
      final payload = underTheSeal(await PinLock.seal(secret, pin));
      final salt = base64Decode(payload['salt'] as String);
      final derived = await CryptoUtils.deriveKey(pin, salt);
      expect(() => CryptoUtils.unwrapKey(payload['key'] as String, derived),
          throwsA(anything));
    });

    test('each guess asks the key, with the salt and the digits in it',
        () async {
      final blob = await PinLock.seal(secret, pin);
      final salt = base64Decode(underTheSeal(blob)['salt'] as String);
      pepper.asked.clear();
      await expectLater(PinLock.open(blob, '000000'), throwsA(isA<WrongPin>()));
      expect(
          pepper.asked
              .map((a) => utf8.decode(a, allowMalformed: true))
              .any((a) => a.startsWith('smartable-pin-v2|') &&
                  a.endsWith('|000000')),
          isTrue);
      expect(
          pepper.asked.any((a) => _containsRun(a, salt)), isTrue,
          reason: 'the salt is in the keyed input, so one answer serves one '
              'blob');
    });

    test('a lost key is not a wrong PIN, and no key is made by trying',
        () async {
      final blob = await PinLock.seal(secret, pin);
      pepper.lose();
      await expectLater(
          PinLock.open(blob, pin), throwsA(isA<HardwareKeyGone>()));
      expect(pepper.hasKey, isFalse);
    });

    test('nor is a key that was replaced: the check inside the seal says so',
        () async {
      // Without the check, a new key would answer every PIN differently and
      // the right one would read as wrong — counted, throttled, locked out.
      final blob = await PinLock.seal(secret, pin);
      pepper.replace();
      await expectLater(
          PinLock.open(blob, pin), throwsA(isA<HardwareKeyGone>()));
    });

    test('no PIN is offered where the key store will not hold the key',
        () async {
      pepper.unsupported = true;
      expect(await PinLock.isAvailable(), isFalse);
      await expectLater(
          PinLock.seal(secret, pin), throwsA(isA<HardwareKeyUnavailable>()));
    });

    test('a format the build does not know is refused, never counted',
        () async {
      final payload = underTheSeal(await PinLock.seal(secret, pin))..['v'] = 3;
      final blob =
          base64Encode([42, ...utf8.encode(jsonEncode(payload))]);
      await expectLater(
          PinLock.open(blob, pin), throwsA(isA<HardwareKeyUnavailable>()));
    });
  });

  group('format 1, from before', () {
    /// A PIN sealed the way it was until 3 October 2026: PBKDF2 over the
    /// digits, no pepper, no version.
    Future<String> formatOne(String pin) async {
      final salt = List<int>.generate(16, (i) => i * 11 % 256);
      final derived = await CryptoUtils.deriveKey(pin, salt);
      final payload = jsonEncode({
        'salt': base64Encode(salt),
        'key': CryptoUtils.wrapKey(secret, derived),
      });
      return base64Encode([42, ...utf8.encode(payload)]);
    }

    test('still opens, and a wrong PIN is still wrong', () async {
      final old = await formatOne(pin);
      expect(await PinLock.open(old, pin), secret);
      await expectLater(PinLock.open(old, '135791'), throwsA(isA<WrongPin>()));
    });

    test('and moves to format 2 the next time it opens, under the same PIN',
        () async {
      final old = await formatOne(pin);
      final opened = await PinLock.openAndUpgrade(old, pin);
      expect(opened.secret, secret);
      final upgraded = opened.upgraded!;
      expect(jsonDecode(utf8.decode(base64Decode(upgraded).sublist(1)))['v'],
          PinLock.version);
      expect(await PinLock.open(upgraded, pin), secret);
      await expectLater(
          PinLock.open(upgraded, '135791'), throwsA(isA<WrongPin>()));
    });

    test('but a wrong PIN moves nothing, and a phone without the key keeps '
        'format 1', () async {
      final old = await formatOne(pin);
      await expectLater(
          PinLock.openAndUpgrade(old, '135791'), throwsA(isA<WrongPin>()));
      pepper.unsupported = true;
      final opened = await PinLock.openAndUpgrade(old, pin);
      expect(opened.secret, secret);
      expect(opened.upgraded, isNull);
    });
  });

  test('sealing refuses anything that is not six digits', () async {
    for (final bad in ['12345', '1234567', '12a456', '', 'abcdef']) {
      expect(() => PinLock.seal(secret, bad), throwsA(isA<ArgumentError>()),
          reason: '"$bad" was accepted as a PIN');
    }
  });
}

bool _containsRun(List<int> haystack, List<int> needle) {
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    var all = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        all = false;
        break;
      }
    }
    if (all) return true;
  }
  return false;
}
