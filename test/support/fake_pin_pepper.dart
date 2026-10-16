import 'dart:math';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart';
import 'package:smartable_wallet_core/core/hardware_key.dart';

/// The PIN's keyed function, answered in Dart the way `PinPepperKey` answers
/// on a phone: an HMAC-SHA256 under a key the test holds and the code under
/// test never sees, made only by `prepare`, never by `mac`, and `key_gone`
/// when there is none.
class FakePinPepper {
  static const MethodChannel channel = MethodChannel('test.pin_pepper');

  Uint8List? _key;

  /// Every input the app asked to be keyed, in order.
  final List<Uint8List> asked = [];

  /// When set, `isSupported` and `prepare` answer false: a phone whose key
  /// store will not hold an HMAC key.
  bool unsupported = false;

  bool get hasKey => _key != null;

  /// The key is gone — the app's data cleared, the key store reset.
  void lose() => _key = null;

  /// Another key under the same name, as a reset key store would leave.
  void replace() => _key = _fresh();

  static Uint8List _fresh() {
    final random = Random.secure();
    return Uint8List.fromList(List<int>.generate(32, (_) => random.nextInt(256)));
  }

  Uint8List _mac(Uint8List input) {
    final hmac = HMac(SHA256Digest(), 64)..init(KeyParameter(_key!));
    return hmac.process(input);
  }

  Future<Object?> _handle(MethodCall call) async {
    switch (call.method) {
      case 'isSupported':
        return !unsupported;
      case 'prepare':
        if (unsupported) return false;
        _key ??= _fresh();
        return true;
      case 'mac':
        final bytes = call.arguments?['bytes'] as Uint8List?;
        if (bytes == null || bytes.isEmpty || bytes.length > 128) {
          throw PlatformException(code: 'bad_argument');
        }
        if (_key == null) throw PlatformException(code: 'key_gone');
        asked.add(bytes);
        return _mac(bytes);
      case 'forget':
        _key = null;
        return null;
    }
    return null;
  }
}

/// Installs a [FakePinPepper] for every test in the file it is called from,
/// fresh for each, and hands it back.
FakePinPepper useFakePinPepper() {
  final pepper = FakePinPepper();
  setUp(() {
    pepper
      .._key = null
      ..unsupported = false
      ..asked.clear();
    PinPepper.channel = FakePinPepper.channel;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(FakePinPepper.channel, pepper._handle);
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(FakePinPepper.channel, null);
  });
  return pepper;
}
