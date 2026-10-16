import CryptoKit
import Flutter
import Security
import XCTest

@testable import Runner

/// The PIN's keyed function in the Secure Enclave, driven through the same
/// `handle` the method channel calls. Run on a simulator by
/// `tool/ios_native_check.sh`; a simulator holds a plain Enclave key (measured
/// 18 September 2026, see `HardwareVaultKeyTests`), which is all this key is.
///
/// What it has to be: a **function** — the same input gives the same answer
/// for as long as the key lives, or a right PIN stops opening the wallet; a
/// function of the input — six neighbouring PINs give six answers; a function
/// of the key — a new key gives new answers, and no key gives `key_gone`
/// rather than a key made on the spot, which would turn a right PIN into a
/// throttled wrong one.
final class PinPepperKeyTests: XCTestCase {
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

  private func makeKey(enclave: Bool? = nil) -> PinPepperKey {
    let tag = "com.smartable.wallet.test.pepper.\(UUID().uuidString)"
    tags.append(tag)
    return enclave.map { PinPepperKey(tag: tag, enclave: $0) } ?? PinPepperKey(tag: tag)
  }

  private func call(_ key: PinPepperKey, _ method: String, _ bytes: Data? = nil) -> Any? {
    let answered = expectation(description: method)
    var answer: Any?
    let arguments: Any? = bytes.map { ["bytes": FlutterStandardTypedData(bytes: $0)] }
    key.handle(FlutterMethodCall(methodName: method, arguments: arguments)) { value in
      answer = value
      answered.fulfill()
    }
    wait(for: [answered], timeout: 10)
    return answer
  }

  private func mac(_ key: PinPepperKey, _ pin: String) -> Data? {
    (call(key, "mac", Data("smartable-pin-v2|salt|\(pin)".utf8)) as? FlutterStandardTypedData)?.data
  }

  func testTheSameInputGivesTheSameAnswer() {
    let key = makeKey()
    XCTAssertEqual(call(key, "prepare") as? Bool, true)
    let first = mac(key, "135790")
    XCTAssertEqual(first?.count, 32)
    XCTAssertEqual(mac(key, "135790"), first)
  }

  func testNeighbouringPinsGiveDifferentAnswers() {
    let key = makeKey()
    XCTAssertEqual(call(key, "prepare") as? Bool, true)
    let answers = Set(["135790", "135791", "135780", "035790", "135709", "000000"]
      .compactMap { mac(key, $0) })
    XCTAssertEqual(answers.count, 6)
  }

  func testAnotherKeyGivesAnotherAnswer() {
    let one = makeKey()
    let two = makeKey()
    XCTAssertEqual(call(one, "prepare") as? Bool, true)
    XCTAssertEqual(call(two, "prepare") as? Bool, true)
    XCTAssertNotEqual(mac(one, "135790"), mac(two, "135790"))
  }

  func testNoKeyIsKeyGoneAndMakesNone() {
    let key = makeKey()
    let answer = call(key, "mac", Data("smartable-pin-v2|salt|135790".utf8))
    XCTAssertEqual((answer as? FlutterError)?.code, "key_gone")
    // Still none: a guess must never make the key it is checked against.
    let again = call(key, "mac", Data("smartable-pin-v2|salt|135790".utf8))
    XCTAssertEqual((again as? FlutterError)?.code, "key_gone")
  }

  func testForgetMakesTheOldAnswersUnreachable() {
    let key = makeKey()
    XCTAssertEqual(call(key, "prepare") as? Bool, true)
    let before = mac(key, "135790")
    _ = call(key, "forget")
    XCTAssertEqual((call(key, "mac", Data("x".utf8)) as? FlutterError)?.code, "key_gone")
    XCTAssertEqual(call(key, "prepare") as? Bool, true)
    XCTAssertNotEqual(mac(key, "135790"), before)
  }

  func testIsSupportedLeavesNoKeyBehind() {
    let key = makeKey()
    XCTAssertEqual(call(key, "isSupported") as? Bool, true)
    XCTAssertEqual((call(key, "mac", Data("x".utf8)) as? FlutterError)?.code, "key_gone")
  }

  func testAnOversizedInputIsRefused() {
    let key = makeKey()
    XCTAssertEqual(call(key, "prepare") as? Bool, true)
    let answer = call(key, "mac", Data(repeating: 1, count: PinPepperKey.maxInput + 1))
    XCTAssertEqual((answer as? FlutterError)?.code, "bad_argument")
  }

  /// **The answer cannot be made from the key's public half** (6 October
  /// 2026). The first construction asked the Enclave for `d·(s·G)` with `s` a
  /// hash of the input, and that is `s·(d·G)`: anybody holding the public key —
  /// which any process holding the key can read — could work every PIN off the
  /// phone. This is that attack, run against the answer the key gives.
  func testTheAnswerCannotBeMadeFromThePublicKey() throws {
    let key = makeKey()
    XCTAssertEqual(call(key, "prepare") as? Bool, true)
    let input = Data("smartable-pin-v2|salt|135790".utf8)
    let answer = try XCTUnwrap((call(key, "mac", input) as? FlutterStandardTypedData)?.data)

    // The key's public half, read the way any process holding the key can.
    let tag = try XCTUnwrap(tags.last)
    var item: CFTypeRef?
    let status = SecItemCopyMatching([
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(tag.utf8),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ] as CFDictionary, &item)
    XCTAssertEqual(status, errSecSuccess)
    let privateKey = try XCTUnwrap(item as! SecKey?)
    let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
    let x963 = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil) as Data?)
    let published = try P256.KeyAgreement.PublicKey(x963Representation: x963)

    // Every scalar the first construction could have derived for this input,
    // multiplied into the public key in software: none may be the answer.
    for counter in UInt8(0)...UInt8(3) {
      var material = Data("smartable-pin-pepper-point".utf8)
      material.append(counter)
      material.append(input)
      let scalar = Data(SHA256.hash(data: material))
      guard let s = try? P256.KeyAgreement.PrivateKey(rawRepresentation: scalar) else { continue }
      let shared = try s.sharedSecretFromKeyAgreement(with: published)
      let forged = shared.withUnsafeBytes { Data(SHA256.hash(data: Data($0))) }
      XCTAssertNotEqual(forged, answer)
    }
  }

  func testTheKeyIsInTheEnclaveWhereThereIsOne() {
    guard SecureEnclave.isAvailable else { return }
    let tag = "com.smartable.wallet.test.pepper.\(UUID().uuidString)"
    tags.append(tag)
    let key = PinPepperKey(tag: tag)
    XCTAssertEqual(call(key, "prepare") as? Bool, true)
    var item: CFTypeRef?
    let status = SecItemCopyMatching([
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(tag.utf8),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnAttributes as String: true,
    ] as CFDictionary, &item)
    XCTAssertEqual(status, errSecSuccess)
    let attributes = item as? [String: Any]
    XCTAssertEqual(attributes?[kSecAttrTokenID as String] as? String,
                   kSecAttrTokenIDSecureEnclave as String)
  }
}
