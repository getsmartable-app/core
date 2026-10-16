import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// A key the app can use and cannot read — the iPhone half of
/// `android/app/src/main/kotlin/com/smartable/wallet/HardwareVaultKey.kt`.
///
/// Same contract, same two aliases, same four methods, and the same three
/// error codes on the Dart side, because `lib/core/hardware_key.dart` speaks to
/// both and must not learn which platform it is on. What differs is the
/// primitive underneath, and the difference is not cosmetic:
///
/// **The Secure Enclave holds elliptic-curve keys, not AES ones.** Android's
/// keystore will hold an AES-GCM key and encrypt with it directly; the Enclave
/// will only hold a P-256 private key. So wrapping here is ECIES — the system
/// generates an ephemeral key pair, agrees a shared secret with our public key,
/// derives an AES-GCM key from it and encrypts. Unwrapping runs the same
/// agreement with the private key, which never leaves the Enclave and cannot
/// be exported even by this app. The result is the property the Kotlin file
/// describes in its own terms: the blob is worthless without this phone.
final class HardwareVaultKey {
  /// The copy behind quick unlock: released only to Face ID or Touch ID, never
  /// to the device passcode — see `createKey`.
  static let vaultChannel = "com.smartable.wallet/hardware_key"
  static let vaultTag = "com.smartable.wallet.vault.key"

  /// The copy behind the PIN: bound to this phone, gated by nothing. See the
  /// Kotlin file and `lib/core/pin_lock.dart` — six digits are safe exactly
  /// because the blob cannot be attacked away from the device, and requiring a
  /// biometric here would mean the PIN could only be typed by somebody who had
  /// already passed the gate the PIN exists to replace.
  static let deviceChannel = "com.smartable.wallet/device_key"
  static let deviceTag = "com.smartable.wallet.device.key"

  private let tag: Data
  private let requireAuth: Bool
  private let enclave: Bool

  /// ECIES with a variable IV. The fixed-IV variant reuses the nonce across
  /// messages sealed with the same ephemeral key, which is the one mistake
  /// AES-GCM does not survive.
  private let algorithm: SecKeyAlgorithm =
    .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

  /// [enclave] is whether this device has a Secure Enclave at all, and it is
  /// a parameter only so `RunnerTests` can reach the fallback on a simulator
  /// that has one. Nothing in the app passes it.
  init(tag: String, requireAuth: Bool, enclave: Bool = SecureEnclave.isAvailable) {
    self.tag = Data(tag.utf8)
    self.requireAuth = requireAuth
    self.enclave = enclave
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "isSupported":
      result(isSupported())
    case "describe":
      result(describe())
    case "wrap":
      wrap(call, result)
    case "unwrap":
      unwrap(call, result)
    case "forget":
      forget()
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  /// Answered by trying, not by reading a device model.
  ///
  /// A phone with no face or finger enrolled cannot hold the auth-bound key at
  /// all, and reporting it as capable would mean telling somebody their wallet
  /// is behind Face ID while nothing is stored. Same reasoning as the Kotlin.
  private func isSupported() -> Bool {
    if loadKey() != nil { return true }
    return (try? createKey()) != nil
  }

  private func createKey() throws -> SecKey {
    // **A key that opens to a face or a finger is not made where neither is
    // enrolled.** It could never be opened, and `isSupported` answering yes
    // would arm quick unlock on a phone that has only a passcode — which the
    // key below deliberately refuses. The question used to be asked by the
    // Enclave probe, where it decided the wrong thing: where the PIN's key
    // lived. Asked here it decides only this key, and asked explicitly rather
    // than left to the Enclave: the simulator refuses an Enclave key under
    // every user-presence flag, enrolled or not, and what a phone does with
    // `.biometryCurrentSet` and nothing enrolled is not measured here.
    if requireAuth && !biometryEnrolled() {
      throw KeyError.unavailable
    }

    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if requireAuth {
      // **Face ID or Touch ID, and nothing else.** `.biometryCurrentSet` is
      // biometry alone, invalidated when a biometric is enrolled or removed —
      // the iOS equivalent of setInvalidatedByBiometricEnrollment(true):
      // somebody who can add their own face to an unlocked phone would
      // otherwise inherit the wallet.
      //
      // **`.userPresence` used to sit beside it and had to go.** That flag
      // means "biometry *or* the device passcode", which is the same door
      // `AUTH_DEVICE_CREDENTIAL` opened on Android — a phone code, known to
      // anyone who has watched it typed, standing in for a fingerprint. The
      // wallet's own PIN and password are the fallback, and they are ours to
      // rate-limit and ours to forget.
      flags.insert(.biometryCurrentSet)
    }

    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil,
      // ThisDeviceOnly: never carried to a new phone by an encrypted backup.
      // A key that can be restored elsewhere is not a device-bound key.
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      flags,
      &accessError
    ) else {
      throw (accessError?.takeRetainedValue() as Error?) ?? KeyError.unavailable
    }

    var attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: access,
      ],
    ]
    // **The Enclave wherever the device has one, whatever is enrolled.** This
    // was asked of biometry — `canEvaluatePolicy(.deviceOwnerAuthentication
    // WithBiometrics)` — so on a phone with a passcode and no face or finger
    // enrolled, the PIN's key, which asks for neither, was made in software
    // beside an Enclave that would have held it. Audit finding M9. Enrolment
    // is a question about the quick-unlock key, and it is asked there, above.
    //
    // **Never a fallback from a refused Enclave.** A device that has one and
    // refuses this key gets no key: silently protecting less than the person
    // was told is worse than protecting less. Software only where there is no
    // Enclave at all — a simulator on a Mac that lends it none; every iPhone
    // that runs iOS 13.1 has one.
    //
    // **Software is software.** A Keychain-held key is bound to this phone —
    // `ThisDeviceOnly`, never in a backup — but its private half is not
    // sealed from this process: `SecKeyCopyExternalRepresentation` hands it
    // back, 97 bytes, where an Enclave key answers -4. Measured on the iOS
    // 26.5 simulator, 18 September 2026; this comment used to say the opposite.
    if enclave {
      attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }

    var createError: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &createError) else {
      let error = createError?.takeRetainedValue()
      NSLog("SmartableKey: key generation refused: %@", String(describing: error))
      throw (error as Error?) ?? KeyError.unavailable
    }
    return key
  }

  /// A face or a finger is enrolled — not merely a passcode set.
  /// `.deviceOwnerAuthentication` answers yes to a passcode alone, which is
  /// exactly the phone the quick-unlock key cannot serve.
  private func biometryEnrolled() -> Bool {
    var error: NSError?
    return LAContext().canEvaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics, error: &error)
  }

  /// What is actually holding this key, for the screen that reports it.
  ///
  /// The same contract as the Kotlin, and it never creates a key either: a
  /// report that arms one by being read would be describing its own footprint.
  ///
  /// **It asks the key, not the device.** Whether the device has an Enclave
  /// answers what a key created *now* would get; a key created on an earlier
  /// build may not have got it. `kSecAttrTokenID` on the key itself is the only
  /// statement about the key in front of us.
  ///
  /// The Keychain fallback reports `software`, and that is exact: its private
  /// half can be read out by this process (see `createKey`).
  private func describe() -> [String: Any] {
    guard let key = loadKey() else {
      return ["exists": false, "backing": "unknown", "precise": false]
    }
    let attributes = SecKeyCopyAttributes(key) as? [String: Any]
    let token = attributes?[kSecAttrTokenID as String] as? String
    let inEnclave = token == (kSecAttrTokenIDSecureEnclave as String)
    return [
      "exists": true,
      "backing": inEnclave ? "strongbox" : "software",
      "precise": true,
    ]
  }

  private func loadKey() -> SecKey? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
      return nil
    }
    return (item as! SecKey?)
  }

  private func wrap(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
    guard let arguments = call.arguments as? [String: Any],
          let plain = (arguments["bytes"] as? FlutterStandardTypedData)?.data else {
      result(FlutterError(code: "bad_argument", message: "Nothing to wrap.", details: nil))
      return
    }

    let key: SecKey
    if let existing = loadKey() {
      key = existing
    } else if let created = try? createKey() {
      key = created
    } else {
      result(FlutterError(code: "unavailable", message: "Keystore refused.", details: nil))
      return
    }

    // The *public* half, so sealing never asks for a face. Only opening does,
    // which is the whole point: the app can put something away at any moment
    // and can only take it out with the person present.
    guard let publicKey = SecKeyCopyPublicKey(key) else {
      result(FlutterError(code: "unavailable", message: "Keystore refused.", details: nil))
      return
    }

    var error: Unmanaged<CFError>?
    guard let sealed = SecKeyCreateEncryptedData(
      publicKey, algorithm, plain as CFData, &error
    ) as Data? else {
      NSLog("SmartableKey: wrap refused: %@",
            String(describing: error?.takeRetainedValue()))
      result(FlutterError(code: "unavailable", message: "Keystore refused.", details: nil))
      return
    }
    result(FlutterStandardTypedData(bytes: sealed))
  }

  private func unwrap(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
    guard let arguments = call.arguments as? [String: Any],
          let blob = (arguments["bytes"] as? FlutterStandardTypedData)?.data,
          !blob.isEmpty else {
      result(FlutterError(code: "bad_argument", message: "Nothing to unwrap.", details: nil))
      return
    }

    guard let key = loadKey() else {
      // Gone for good: a new face enrolled, the passcode removed, the app's
      // data cleared. Not an error to swallow — it means the password is the
      // only way in now, and the app has to say which of the two happened.
      result(FlutterError(code: "key_gone",
                          message: "The device key is no longer available.",
                          details: nil))
      return
    }

    // Off the platform thread: decrypting with an auth-bound key puts Face ID
    // on screen and blocks until the person answers, and doing that on the
    // main thread freezes the UI it is drawn over.
    DispatchQueue.global(qos: .userInitiated).async {
      var error: Unmanaged<CFError>?
      let plain = SecKeyCreateDecryptedData(
        key, self.algorithm, blob as CFData, &error
      ) as Data?

      let failure = error?.takeRetainedValue()
      DispatchQueue.main.async {
        if let plain = plain {
          result(FlutterStandardTypedData(bytes: plain))
          return
        }
        result(self.errorFor(failure))
      }
    }
  }

  /// Four answers, because the app does something different with each — see
  /// `HardwareKeyException` in `lib/core/hardware_key.dart`.
  private func errorFor(_ failure: CFError?) -> FlutterError {
    let code = failure.map { CFErrorGetCode($0) } ?? 0
    switch OSStatus(code) {
    case errSecUserCanceled:
      // **A cancel is the person choosing the wallet's own door**, as
      // `ERROR_USER_CANCELED` is on Android: the key stays, and the PIN and
      // the password are the way in. It answered "confirm it's you" until
      // 6 October 2026 — a fault's sentence for a choice, and an invitation to
      // the same prompt again.
      return FlutterError(code: "auth_cancelled",
                          message: "Cancelled.", details: nil)
    case errSecAuthFailed, errSecInteractionNotAllowed:
      // Prove it is you, then try again. The one case worth retrying.
      return FlutterError(code: "auth_required",
                          message: "Authentication required.", details: nil)
    case errSecItemNotFound, errSecInvalidKeyRef:
      return FlutterError(code: "key_gone",
                          message: "The device key was invalidated.", details: nil)
    default:
      NSLog("SmartableKey: unwrap refused: %@", String(describing: failure))
      return FlutterError(code: "unavailable",
                          message: "Keystore refused.", details: nil)
    }
  }

  private func forget() {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
    ]
    // Nothing to delete is the same outcome as having deleted it.
    SecItemDelete(query as CFDictionary)
  }

  private enum KeyError: Error { case unavailable }
}
