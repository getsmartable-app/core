import CryptoKit
import Foundation
import Security

/// A key in the Secure Enclave that every PIN guess has to go through — the
/// iPhone half of `android/app/src/main/kotlin/com/smartable/wallet/PinPepperKey.kt`.
///
/// Same contract and same channel methods; what differs is the primitive. The
/// Enclave holds P-256 keys and computes Diffie–Hellman with them, and nothing
/// else — no HMAC. So the keyed function here is an agreement: the input is
/// hashed to a point `Q` on the curve whose discrete logarithm nobody knows,
/// and the Enclave multiplies it by its private key `d`. SHA-256 of the
/// x-coordinate of `d·Q` is returned — the "2HashDH" construction. Computing
/// `d·Q` from `Q` and the key's public half `d·G` is the computational
/// Diffie–Hellman problem, so every answer needs the Enclave.
///
/// **`Q` is never `s·G` for an `s` anybody can compute** (found 6 October
/// 2026). The first version hashed the input to a scalar `s` and asked the
/// Enclave for `d·(s·G)` — which is `s·(d·G)`, computable from the public key
/// alone, and the public key is one call away from any process that holds the
/// key. With the outer seal off, the million PINs could then be worked on any
/// machine: the property this file exists for did not hold. The regression
/// test (`testTheAnswerCannotBeMadeFromThePublicKey`) is that attack, and
/// `tool/pin_pepper_construction_check.py` reproduces both constructions off
/// the phone — keep its domain string this file's.
///
/// **Why it exists** is the Kotlin file's argument: the PIN's outer seal comes
/// off in one call to the device key on a compromised, unlocked phone, and the
/// million PINs under it were PBKDF2 alone, work that could be carried off the
/// phone. Through this key every guess is an Enclave operation on this phone.
///
/// **Never made by a guess**: `mac` uses the key that exists and answers
/// `key_gone` when there is none; only `prepare`, at arming, makes one.
final class PinPepperKey {
  static let channel = "com.smartable.wallet/pin_pepper"
  static let tag = "com.smartable.wallet.pin.pepper"

  /// The most a caller may ask to be keyed — see the Kotlin file.
  static let maxInput = 128

  private let tag: Data
  private let enclave: Bool

  /// [enclave] is a parameter only so `RunnerTests` can reach the software
  /// key a device without an Enclave gets. Nothing in the app passes it.
  init(tag: String = PinPepperKey.tag, enclave: Bool = SecureEnclave.isAvailable) {
    self.tag = Data(tag.utf8)
    self.enclave = enclave
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "isSupported":
      result(loadKey() != nil || canCreate())
    case "prepare":
      result(prepare())
    case "mac":
      guard let arguments = call.arguments as? [String: Any],
            let input = (arguments["bytes"] as? FlutterStandardTypedData)?.data,
            !input.isEmpty, input.count <= PinPepperKey.maxInput else {
        result(FlutterError(code: "bad_argument", message: "Nothing to key.", details: nil))
        return
      }
      DispatchQueue.global(qos: .userInitiated).async {
        let answer = self.mac(input)
        DispatchQueue.main.async { result(answer) }
      }
    case "forget":
      forget()
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  /// The keyed answer for [input], or the error the Dart side expects.
  func mac(_ input: Data) -> Any {
    guard let key = loadKey() else {
      return FlutterError(code: "key_gone",
                          message: "The PIN's device key is no longer available.",
                          details: nil)
    }
    guard let peer = PinPepperKey.publicPoint(for: input) else {
      return FlutterError(code: "unavailable", message: "No point for that input.", details: nil)
    }
    var error: Unmanaged<CFError>?
    guard let shared = SecKeyCopyKeyExchangeResult(
      key, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, &error
    ) as Data? else {
      NSLog("SmartableKey: pin pepper refused: %@",
            String(describing: error?.takeRetainedValue()))
      return FlutterError(code: "unavailable", message: "Keystore refused.", details: nil)
    }
    return FlutterStandardTypedData(bytes: Data(SHA256.hash(data: shared)))
  }

  /// The point on P-256 for [input], as a public key the Enclave will agree
  /// with: an x-coordinate from SHA-256 and the curve's own point at it
  /// ("try and increment"). About half of all x are on the curve; the rest are
  /// hashed again with the next counter, so the mapping stays a function and
  /// fails for an input with probability 2⁻²⁵⁶. Nobody knows the point's
  /// discrete logarithm, which is the whole of its job — see the type's note.
  /// `compactRepresentation` is the x-coordinate alone (CryptoKit, iOS 13), the
  /// y it recovers fixed by the curve, so the same input is always the same
  /// point.
  static func publicPoint(for input: Data) -> SecKey? {
    for counter in UInt8(0)...UInt8(255) {
      var material = Data("smartable-pin-pepper-curve-point".utf8)
      material.append(counter)
      material.append(input)
      let x = Data(SHA256.hash(data: material))
      guard let point = try? P256.KeyAgreement.PublicKey(compactRepresentation: x)
      else { continue }
      let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256,
      ]
      return SecKeyCreateWithData(
        point.x963Representation as CFData, attributes as CFDictionary, nil)
    }
    return nil
  }

  private func canCreate() -> Bool {
    guard prepare() else { return false }
    forget()
    return true
  }

  /// The key, made if there is none — in the Enclave wherever the device has
  /// one, never a software fallback from a refused Enclave (the rule
  /// `HardwareVaultKey.createKey` keeps for the PIN's device key).
  func prepare() -> Bool {
    if loadKey() != nil { return true }
    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &accessError
    ) else { return false }
    var attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: access,
      ],
    ]
    if enclave {
      attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }
    var createError: Unmanaged<CFError>?
    guard SecKeyCreateRandomKey(attributes as CFDictionary, &createError) != nil else {
      NSLog("SmartableKey: pin pepper generation refused: %@",
            String(describing: createError?.takeRetainedValue()))
      return false
    }
    return loadKey() != nil
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

  func forget() {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
    ]
    SecItemDelete(query as CFDictionary)
  }
}
