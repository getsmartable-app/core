import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show SecretKey;
import 'package:cryptography/dart.dart' show DartArgon2id;
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:smartable_wallet_core/core/crypto_utils.dart';

/// The Argon2id that seals a split backup's shares
/// (`CryptoUtils.deriveKeyArgon2id`, `ShareKdf`).
///
/// **Held to two outside answers, not to itself.** RFC 9106's own test vector
/// checks the implementation the app names; a second, independent
/// implementation (pointycastle's, a port of Bouncy Castle) checks that the
/// app hands it the password, the salt and the three numbers the way the
/// standard means them. A key derivation that agreed only with itself would
/// pass every round trip and open nothing a correct implementation sealed.
void main() {
  String hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  test('the implementation named is RFC 9106\'s Argon2id (§5.3 test vector)',
      () async {
    final algorithm = DartArgon2id(
        parallelism: 4, memory: 32, iterations: 3, hashLength: 32);
    final key = await algorithm.deriveKey(
      secretKey: SecretKey(List<int>.filled(32, 1)),
      nonce: List<int>.filled(16, 2),
      optionalSecret: List<int>.filled(8, 3),
      associatedData: List<int>.filled(12, 4),
    );
    expect(hex(await key.extractBytes()),
        '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  });

  test('and the app\'s derivation agrees with an independent implementation',
      () async {
    const password = 'correct horse battery staple';
    final salt = Uint8List.fromList(List<int>.generate(32, (i) => i * 7 % 256));
    // Small numbers so the second implementation, which has no isolates, is
    // quick; the arguments are the same ones `ShareKdf` passes.
    final ours = await CryptoUtils.deriveKeyArgon2id(password, salt,
        memoryKiB: 8192, iterations: 2, parallelism: 4);

    final theirs = Uint8List(32);
    (pc.Argon2BytesGenerator()
          ..init(pc.Argon2Parameters(pc.Argon2Parameters.ARGON2_id, salt,
              iterations: 2,
              lanes: 4,
              memory: 8192,
              desiredKeyLength: 32,
              version: pc.Argon2Parameters.ARGON2_VERSION_13)))
        .deriveKey(Uint8List.fromList(utf8.encode(password)), 0, theirs, 0);

    expect(ours, theirs);
  });

  test('a password is one key however its accents were typed', () async {
    // `canonicalSecretBytes`, as for PBKDF2: U+00E9 and e + U+0301 are one
    // character on every screen and must be one key.
    final salt = List<int>.filled(32, 9);
    final composed = await CryptoUtils.deriveKeyArgon2id('café au lait', salt,
        memoryKiB: 8192, iterations: 1, parallelism: 1);
    final decomposed = await CryptoUtils.deriveKeyArgon2id(
        'café au lait', salt,
        memoryKiB: 8192, iterations: 1, parallelism: 1);
    expect(composed, decomposed);
  });

  test('every one of the three numbers changes the key', () async {
    final salt = List<int>.filled(32, 5);
    Future<String> key(int m, int t, int p) async => hex(
        await CryptoUtils.deriveKeyArgon2id('correct horse battery', salt,
            memoryKiB: m, iterations: t, parallelism: p));
    final base = await key(8192, 1, 1);
    expect(await key(16384, 1, 1), isNot(base));
    expect(await key(8192, 2, 1), isNot(base));
    expect(await key(8192, 1, 2), isNot(base));
  });
}
