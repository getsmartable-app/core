import CryptoKit
import Flutter
import LocalAuthentication
import Security
import XCTest

@testable import Runner

/// The two device keys, driven through the same `handle` the method channels
/// call. Run on a simulator by `tool/ios_native_check.sh`, once with Face ID
/// enrolled and once without, because the finding these hold (M9) was a key
/// whose home depended on enrolment.
///
/// **What a simulator can answer, measured on 18 September 2026** (iOS 26.5,
/// Apple Silicon): it has a Secure Enclave and holds a plain Enclave key, with
/// a private half that cannot be exported; it refuses an Enclave key under
/// every user-presence flag — `.biometryCurrentSet`, `.biometryAny`,
/// `.userPresence`, `.devicePasscode` — with Face ID enrolled or not (-25293);
/// and it enforces no biometric access control on the Keychain at all: an item
/// under `.biometryCurrentSet` is read with interaction forbidden. So the PIN's
/// key is tested here for real, and the quick-unlock key only for the rules
/// that do not need a face: never software beside an Enclave, never made with
/// nothing enrolled. Whether Face ID opens it is a phone's to say.
final class HardwareVaultKeyTests: XCTestCase {
  private var tags: [String] = []

  override func tearDown() {
    for tag in tags {
      SecItemDelete([
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: Data(tag.utf8),
      ] as CFDictionary)
    }
    tags = []
    super.tearDown()
  }

  /// A key under a tag of its own, so no test touches the app's two.
  private func makeKey(requireAuth: Bool, enclave: Bool? = nil) -> (HardwareVaultKey, String) {
    let tag = "com.smartable.wallet.test.\(UUID().uuidString)"
    tags.append(tag)
    let key = enclave.map { HardwareVaultKey(tag: tag, requireAuth: requireAuth, enclave: $0) }
      ?? HardwareVaultKey(tag: tag, requireAuth: requireAuth)
    return (key, tag)
  }

  private func call(_ key: HardwareVaultKey, _ method: String, _ arguments: Any? = nil) -> Any? {
    let answered = expectation(description: method)
    var answer: Any?
    key.handle(FlutterMethodCall(methodName: method, arguments: arguments)) { value in
      answer = value
      answered.fulfill()
    }
    wait(for: [answered], timeout: 10)
    return answer
  }

  private func describe(_ key: HardwareVaultKey) -> [String: Any] {
    call(key, "describe") as? [String: Any] ?? [:]
  }

  /// The stored key, loaded the way the app loads it — not the object
  /// `SecKeyCreateRandomKey` handed back, which holds a software key's bytes
  /// in memory whatever the Keychain would say.
  private func stored(_ tag: String) -> SecKey? {
    var item: CFTypeRef?
    let status = SecItemCopyMatching([
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(tag.utf8),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ] as CFDictionary, &item)
    guard status == errSecSuccess, let item = item else { return nil }
    return (item as! SecKey)
  }

  private var biometryEnrolled: Bool {
    var error: NSError?
    return LAContext().canEvaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics, error: &error)
  }

  // MARK: The PIN's key

  func testThePinKeyIsHeldByTheEnclaveWhateverIsEnrolled() throws {
    try XCTSkipUnless(SecureEnclave.isAvailable, "this simulator host has no Enclave")
    let (key, tag) = makeKey(requireAuth: false)

    XCTAssertEqual(call(key, "isSupported") as? Bool, true)
    let report = describe(key)
    XCTAssertEqual(report["exists"] as? Bool, true)
    XCTAssertEqual(report["backing"] as? String, "strongbox",
                   "Face ID enrolled: \(biometryEnrolled) — the Enclave must not depend on it")
    XCTAssertEqual(report["precise"] as? Bool, true)

    let loaded = try XCTUnwrap(stored(tag))
    var error: Unmanaged<CFError>?
    XCTAssertNil(SecKeyCopyExternalRepresentation(loaded, &error),
                 "an Enclave key's private half never leaves it")
    error?.release()
  }

  func testThePinKeySealsAndOpensWithNoPrompt() throws {
    let (key, _) = makeKey(requireAuth: false)
    let plain = Data((0..<32).map { UInt8($0) })

    let sealed = try XCTUnwrap(
      call(key, "wrap", ["bytes": FlutterStandardTypedData(bytes: plain)])
        as? FlutterStandardTypedData)
    XCTAssertNotEqual(sealed.data, plain)
    let opened = try XCTUnwrap(
      call(key, "unwrap", ["bytes": sealed]) as? FlutterStandardTypedData)
    XCTAssertEqual(opened.data, plain)
  }

  func testWithoutAnEnclaveTheKeyIsSoftwareAndSaysSo() throws {
    // The fallback's comment used to say this process could not export the
    // key. It can, and the report calling it "software" is exact.
    let (key, tag) = makeKey(requireAuth: false, enclave: false)

    XCTAssertEqual(call(key, "isSupported") as? Bool, true)
    XCTAssertEqual(describe(key)["backing"] as? String, "software")

    let loaded = try XCTUnwrap(stored(tag))
    let bytes = SecKeyCopyExternalRepresentation(loaded, nil) as Data?
    XCTAssertEqual(bytes?.count, 97, "0x04, X, Y and the private scalar")
  }

  func testAKeyThatIsGoneSaysSo() throws {
    let (key, _) = makeKey(requireAuth: false)
    _ = call(key, "forget")

    let answer = call(key, "unwrap", ["bytes": FlutterStandardTypedData(bytes: Data([1]))])
    XCTAssertEqual((answer as? FlutterError)?.code, "key_gone")
    XCTAssertEqual(describe(key)["exists"] as? Bool, false)
  }

  // MARK: The quick-unlock key

  func testTheQuickUnlockKeyIsNeverSoftwareBesideAnEnclave() throws {
    try XCTSkipUnless(SecureEnclave.isAvailable, "this simulator host has no Enclave")
    let (key, _) = makeKey(requireAuth: true)

    let supported = call(key, "isSupported") as? Bool
    let report = describe(key)
    if supported == true {
      XCTAssertEqual(report["backing"] as? String, "strongbox")
    } else {
      // The simulator's answer, enrolled or not: it will not make an Enclave
      // key that asks for a face, and nothing weaker is made in its place.
      XCTAssertEqual(report["exists"] as? Bool, false)
    }
  }

  func testTheQuickUnlockKeyIsNotMadeWithNothingEnrolled() throws {
    try XCTSkipIf(biometryEnrolled, "runs with Face ID not enrolled")
    // Software, so the Enclave's own refusal cannot be what answers.
    let (key, _) = makeKey(requireAuth: true, enclave: false)

    XCTAssertEqual(call(key, "isSupported") as? Bool, false)
    let sealed = call(key, "wrap", ["bytes": FlutterStandardTypedData(bytes: Data([1]))])
    XCTAssertEqual((sealed as? FlutterError)?.code, "unavailable")
    XCTAssertEqual(describe(key)["exists"] as? Bool, false)
  }

  func testTheQuickUnlockKeyIsMadeWhereAFaceIsEnrolled() throws {
    try XCTSkipUnless(biometryEnrolled, "runs with Face ID enrolled")
    // The gate above is not a gate that is always shut.
    let (key, _) = makeKey(requireAuth: true, enclave: false)

    XCTAssertEqual(call(key, "isSupported") as? Bool, true)
    XCTAssertEqual(describe(key)["backing"] as? String, "software")
  }
}
