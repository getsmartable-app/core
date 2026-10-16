import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';

/// A keystore that will not answer at all — the locked-since-reboot shape.
///
/// **The happy-path mock proves the wrong half.** `setMockInitialValues`
/// installs an in-memory store that always works, which shows the app calls the
/// right API and shows nothing about the branch the refusal exists for. This is
/// the other half: every call throws, the way an Android Keystore does before
/// the device has been unlocked once, so "there is nothing here" and "I could
/// not look" arrive as the same silence unless the code keeps them apart.
///
/// **Still not a Keychain.** Nothing here touches Android Keystore, StrongBox
/// or iOS Keychain; it does not model `KeyPermanentlyInvalidatedException`, a
/// locked device, an entitlement error, or restore-after-reinstall. Those need
/// a physical device and are listed as pending in the finding record.
class SilentKeystore extends FlutterSecureStoragePlatform {
  static const _refusal = 'keystore unavailable';

  static PlatformException _no() =>
      PlatformException(code: 'Keystore', message: _refusal);

  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async =>
      throw _no();

  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) async =>
      throw _no();

  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async =>
      throw _no();

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) async =>
      throw _no();

  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) async =>
      throw _no();

  @override
  Future<void> deleteAll({required Map<String, String> options}) async =>
      throw _no();
}

/// A keystore that works, except that it will not decrypt one entry it holds.
///
/// **The one-sided failure a read-then-write has to survive.** A keystore can
/// refuse to decrypt an entry and still accept a new one, so a merge that took
/// the refusal for "nothing stored" would replace the entry with whatever its
/// writer held. This refuses exactly one read and hands everything else to the
/// mock already installed — `containsKey` included, which asks about presence
/// without decrypting, unless [saysWhetherHeld] is false and it refuses that
/// too.
///
/// Construct it *after* `setMockInitialValues`, handing it
/// `FlutterSecureStoragePlatform.instance`.
class OneKeyUnreadable extends FlutterSecureStoragePlatform {
  OneKeyUnreadable({
    required this.inner,
    required this.refusedKey,
    this.saysWhetherHeld = true,
  });

  final FlutterSecureStoragePlatform inner;
  final String refusedKey;
  final bool saysWhetherHeld;

  static Future<T> _no<T>() =>
      Future.error(PlatformException(code: 'Keystore', message: 'unavailable'));

  @override
  Future<String?> read(
          {required String key, required Map<String, String> options}) =>
      key == refusedKey ? _no() : inner.read(key: key, options: options);

  @override
  Future<bool> containsKey(
          {required String key, required Map<String, String> options}) =>
      key == refusedKey && !saysWhetherHeld
          ? _no()
          : inner.containsKey(key: key, options: options);

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) =>
      inner.write(key: key, value: value, options: options);

  @override
  Future<Map<String, String>> readAll({required Map<String, String> options}) =>
      inner.readAll(options: options);

  @override
  Future<void> delete(
          {required String key, required Map<String, String> options}) =>
      inner.delete(key: key, options: options);

  @override
  Future<void> deleteAll({required Map<String, String> options}) =>
      inner.deleteAll(options: options);
}

/// A keystore that works, except for one key it will not delete.
///
/// **Narrower than [SilentKeystore], and the narrowness is the point.** A
/// blanket failure stops whatever is asked *first*, so a test about going on
/// past one refusal would never reach the keys after it. This wraps the mock
/// that is already installed and refuses exactly one deletion, so the failure
/// lands where the rule under test lives.
///
/// Construct it *after* `setMockInitialValues`, handing it
/// `FlutterSecureStoragePlatform.instance`.
class OneKeyUndeletable extends FlutterSecureStoragePlatform {
  OneKeyUndeletable({required this.inner, required this.refusedKey});

  final FlutterSecureStoragePlatform inner;
  final String refusedKey;

  @override
  Future<void> delete(
          {required String key, required Map<String, String> options}) =>
      key == refusedKey
          ? Future.error(
              PlatformException(code: 'Keystore', message: 'unavailable'))
          : inner.delete(key: key, options: options);

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) =>
      inner.write(key: key, value: value, options: options);

  @override
  Future<String?> read(
          {required String key, required Map<String, String> options}) =>
      inner.read(key: key, options: options);

  @override
  Future<Map<String, String>> readAll({required Map<String, String> options}) =>
      inner.readAll(options: options);

  @override
  Future<bool> containsKey(
          {required String key, required Map<String, String> options}) =>
      inner.containsKey(key: key, options: options);

  @override
  Future<void> deleteAll({required Map<String, String> options}) =>
      inner.deleteAll(options: options);
}
