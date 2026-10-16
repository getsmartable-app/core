
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smartable_wallet_core/core/hardware_key.dart';

/// What the app does with each answer the phone's key store can give.
///
/// Three of them are not bytes, and the difference between them is the whole
/// value of this layer: "prove it is you" is worth retrying, "this device
/// cannot" is worth saying out loud once, and "the key is gone" is neither —
/// it means the password is the only way in until quick unlock is set up
/// again. Collapsing them into one failure is how a wallet ends up asking for
/// a fingerprint forever on a phone whose key died last Tuesday.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('test.hardware_key');
  HardwareKey.channel = channel;

  void answer(Object? Function(MethodCall call) handler) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async => handler(call));
  }

  void fail(String code) {
    answer((_) => throw PlatformException(code: code));
  }

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('wrapping returns what the platform sealed', () async {
    answer((call) {
      expect(call.method, 'wrap');
      return Uint8List.fromList([9, 9, 9]);
    });

    expect(await HardwareKey.wrap(Uint8List.fromList([1, 2])),
        Uint8List.fromList([9, 9, 9]));
  });

  test('a device without the hardware answers no, and does not throw', () async {
    fail('unavailable');
    expect(await HardwareKey.isSupported(), isFalse);
  });

  test('a platform with nothing built for it answers no', () async {
    // iOS today. The app must treat this as "use the password", not as a bug.
    answer((_) => throw MissingPluginException());
    expect(await HardwareKey.isSupported(), isFalse);
    expect(() => HardwareKey.wrap(Uint8List(1)),
        throwsA(isA<HardwareKeyUnavailable>()));
  });

  test('"prove it is you" is its own answer, because it is retryable',
      () async {
    fail('auth_required');
    expect(() => HardwareKey.unwrap(Uint8List(20)),
        throwsA(isA<HardwareKeyNeedsAuth>()));
  });

  test('a key that has been invalidated says so, and is not retryable',
      () async {
    // A new fingerprint, a removed screen lock, a restored backup. Asking for
    // a fingerprint again would loop forever; the password is the way in.
    fail('key_gone');
    expect(() => HardwareKey.unwrap(Uint8List(20)),
        throwsA(isA<HardwareKeyGone>()));
  });

  test('every failure names what to do next', () async {
    for (final e in <HardwareKeyException>[
      const HardwareKeyUnavailable(),
      const HardwareKeyNeedsAuth(),
      const HardwareKeyGone(),
    ]) {
      expect(e.message, isNotEmpty);
      expect(e.message, isNot(contains('Exception')),
          reason: 'this text is read by somebody holding their money, not by '
              'a developer reading a stack trace');
    }
  });

  test('forgetting a key that is not there is not a failure', () async {
    fail('unavailable');
    await HardwareKey.forget();
  });
}
