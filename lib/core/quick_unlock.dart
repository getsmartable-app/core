import 'secure_storage.dart';

/// Whether the wallet can be opened without typing the password, and why.
///
/// A single sentence of policy that used to live inline on the unlock path,
/// where it went wrong quietly: the screen asked whether an older build's
/// stored password existed, and this build deletes that copy the moment a
/// device key replaces it. Everybody the feature had just been fixed for lost
/// the button, with the switch in Settings still showing as on.
///
/// The switch alone is not the answer either — it survives a password change
/// on purpose, while the key it stood for does not — so a wallet that asked
/// only the flag would draw a fingerprint button that always failed.
abstract final class QuickUnlock {
  /// True when there is something a fingerprint can actually open.
  ///
  /// Two shapes, both current. The device key blob is what this build arms:
  /// the keys themselves, sealed by hardware that will not act without the
  /// person. The legacy password is what builds up to 2026-08-04 left behind,
  /// and it is read so an upgrading wallet still opens by fingerprint the
  /// first time — after that the password unlock arms a real key and deletes
  /// it.
  static Future<bool> isOffered() async {
    if (!await SecureStorage.getBiometricEnabled()) return false;
    if ((await SecureStorage.getDeviceKeyBlob())?.isNotEmpty == true) {
      return true;
    }
    return (await SecureStorage.getBiometricPassword())?.isNotEmpty == true;
  }
}
