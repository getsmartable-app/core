import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smartable_wallet_core/core/quick_unlock.dart';
import 'package:smartable_wallet_core/core/secure_storage.dart';

/// Whether the unlock screen draws a fingerprint button.
///
/// The bug this file exists for shipped and was invisible: the screen asked
/// whether an older build's stored password was present, and the same release
/// deleted that copy as soon as it armed a device key in its place. So turning
/// quick unlock on, then unlocking once with the password, removed the button —
/// while Settings still showed the switch as on. Nothing failed; the feature
/// simply stopped being reachable.
void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  test('not offered when the switch is off', () async {
    await SecureStorage.saveDeviceKeyBlob('sealed');
    expect(await QuickUnlock.isOffered(), isFalse);
  });

  test('not offered when the switch is on but nothing is armed', () async {
    // A button that always fails is worse than no button: it teaches the user
    // that the wallet's fingerprint is unreliable.
    await SecureStorage.saveBiometricEnabled(true);
    expect(await QuickUnlock.isOffered(), isFalse);
  });

  test('offered on the device key alone', () async {
    // The case the shipped condition got wrong.
    await SecureStorage.saveBiometricEnabled(true);
    await SecureStorage.saveDeviceKeyBlob('sealed');
    expect(await QuickUnlock.isOffered(), isTrue);
  });

  test('offered on what an older build left behind', () async {
    // A wallet upgrading from a build that kept the password behind the
    // fingerprint still opens by fingerprint the first time; that unlock arms a
    // real key and deletes this.
    await SecureStorage.saveBiometricEnabled(true);
    await SecureStorage.write('biometric_password', 'the old copy');
    expect(await QuickUnlock.isOffered(), isTrue);
  });

  test('not offered once quick unlock is switched off', () async {
    await SecureStorage.saveBiometricEnabled(true);
    await SecureStorage.saveDeviceKeyBlob('sealed');
    await SecureStorage.saveDeviceKeyBlob(null);
    await SecureStorage.saveBiometricEnabled(false);
    expect(await QuickUnlock.isOffered(), isFalse);
  });
}
