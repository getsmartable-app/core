// Shares are sealed with Argon2id at 64 MiB since 12 October 2026 (audit S1),
// the real cost and not a test setting: about 0.6 s to seal and 0.4 s to open
// on the development Mac alone, many times that in a full parallel run, where
// tests that seal and open several shares passed the default thirty seconds.
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:smartable_wallet_core/core/crypto_utils.dart';
import 'package:smartable_wallet_core/core/sealed_share.dart';
import 'package:smartable_wallet_core/core/share_store.dart';
import 'package:smartable_wallet_core/core/slip39.dart';

/// Sealing a share, and counting what a set of stores adds up to.
///
/// **The screen these feed is the one that tells somebody whether their money
/// is recoverable**, so every assertion here is about the ways that screen
/// could say yes when the answer is no.
void main() {
  // **Copied from SatoshiLabs' vectors, not written by hand.** The first
  // version of this file invented plausible-looking shares, which is the exact
  // failure this project keeps recording: they parsed as words and were not
  // shares, and the test failed for a reason that had nothing to do with what
  // it was asserting.
  //
  // Vector 4, "Basic sharing 2-of-3 (128 bits)". Two of these three recover
  // `b43ceb7e57a0ea8766221624d01b0864`.
  const shareA =
      'shadow pistol academic always adequate wildlife fancy gross oasis '
      'cylinder mustang wrist rescue view short owner flip making coding armed';
  const shareB =
      'shadow pistol academic acid actress prayer class unknown daughter '
      'sweater depict flip twice unkind craft early superior advocate guest '
      'smoking';

  // A share from a *different* backup — vector 43 — so "two backups do not
  // pool their shares" is tested against a real second identifier.
  const otherSetShare =
      'enemy favorite academic acid cowboy phrase havoc level response walnut '
      'budget painting inside trash adjust froth kitchen learn tidy punish';

  const password = 'correct horse battery staple';

  // The passphrase the vector file was generated with — see slip39_test.dart.
  const trezor = [84, 82, 69, 90, 79, 82];

  group('sealing', () {
    test('a share survives the round trip', () async {
      final sealed = await SealedShare.seal(mnemonic: shareA, password: password, shareCount: 3);
      expect(await sealed.open(password), shareA);
    });

    test('the labels come from the share, not from the caller', () async {
      // Filling these from what the caller believed is how a share ends up
      // filed under the wrong backup and then refuses to combine with its own
      // siblings.
      final share = decodeShare(shareA);
      final sealed = await SealedShare.seal(mnemonic: shareA, password: password, shareCount: 3);
      expect(sealed.setId, share.identifier.toRadixString(16).padLeft(4, '0'));
      expect(sealed.memberIndex, share.memberIndex);
      expect(sealed.groupIndex, share.groupIndex);
    });

    test('a damaged share is refused before it is stored, not after', () async {
      // A backup that turns out to be unreadable is discovered at the worst
      // possible moment, so the check happens on the way in.
      expect(
        () => SealedShare.seal(mnemonic: '$shareA extra', password: password, shareCount: 3),
        throwsA(isA<Slip39Exception>()),
      );
    });

    test('two seals of one share are different bytes', () async {
      // A fresh salt and a fresh nonce each time. Identical ciphertexts would
      // mean one key sealing every copy — crack one, crack all three.
      final a = await SealedShare.seal(mnemonic: shareA, password: password, shareCount: 3);
      final b = await SealedShare.seal(mnemonic: shareA, password: password, shareCount: 3);
      expect(a.ciphertext, isNot(b.ciphertext));
      expect(a.salt, isNot(b.salt));
      expect(a.isSameShareAs(b), isTrue,
          reason: 'identity is the set and the indices, never the bytes');
    });

    test('a wrong password is refused', () async {
      final sealed = await SealedShare.seal(mnemonic: shareA, password: password, shareCount: 3);
      expect(() => sealed.open('wrong'), throwsA(isA<Slip39Exception>()));
    });

    test('and the three ways a sealed share fails are three types', () async {
      // **Not three sentences.** `ShareBackup.restore` collects failures from
      // three stores and has to tell "type it again" from "this copy is gone"
      // from "somebody edited this" — which it did by looking for the words
      // "Wrong password" in a `toString()`. AES-GCM cannot distinguish a wrong
      // key from a corrupted tag, so the wallet reports the more likely and
      // more actionable of the two; what it must not do is lose the
      // distinctions it *can* make.
      final sealed = await SealedShare.seal(mnemonic: shareA, password: password, shareCount: 3);

      await expectLater(
          sealed.open('wrong'), throwsA(isA<Slip39WrongPassword>()));

      final tampered = SealedShare.fromJson({
        ...sealed.toJson(),
        'm': sealed.memberIndex + 1,
      })!;
      await expectLater(
          tampered.open(password), throwsA(isA<Slip39Altered>()));

      final unsalted =
          SealedShare.fromJson({...sealed.toJson(), 'salt': '!not base64!'})!;
      await expectLater(
          unsalted.open(password), throwsA(isA<Slip39Damaged>()));

      // All three are still the base type, so `on Slip39Exception` on the
      // restore screen keeps catching every one of them.
      for (final e in [
        const Slip39WrongPassword(),
        const Slip39Altered(),
        const Slip39Damaged(),
        const Slip39Invalid('x'),
      ]) {
        expect(e, isA<Slip39Exception>());
        expect(e.message, isNotEmpty);
      }
    });

    test('edited plaintext labels are caught by the sealed share', () async {
      // The labels are readable, so they are editable. A share filed under
      // another backup's identifier would be counted towards a threshold it is
      // not part of, and the combination would then fail with nothing to say
      // why.
      final sealed = await SealedShare.seal(mnemonic: shareA, password: password, shareCount: 3);
      final tampered = SealedShare.fromJson({
        ...sealed.toJson(),
        'm': sealed.memberIndex + 1,
      })!;
      expect(() => tampered.open(password), throwsA(isA<Slip39Exception>()));
    });

    test('a body from another format version is refused whole', () {
      final json = {'v': SealedShare.version + 1, 'set': '0001'};
      expect(SealedShare.fromJson(json), isNull);
    });

    test('a backup with no readable date is still a backup', () {
      // Losing the label must not lose the share.
      final json = {
        'v': SealedShare.version,
        'set': '0001',
        'g': 0,
        'm': 1,
        'salt': base64Encode(List<int>.filled(32, 0)),
        'ct': base64Encode(List<int>.filled(40, 0)),
        'at': 'not a date',
      };
      expect(SealedShare.fromJson(json), isNotNull);
    });
  });

  group('the key derivation (Argon2id since 11 October 2026)', () {
    // A share sealed the way every share was before: PBKDF2, version 1.
    Future<Map<String, dynamic>> pbkdf2Body(String mnemonic) async {
      final share = decodeShare(mnemonic);
      final salt = CryptoUtils.randomKey();
      final key = await CryptoUtils.deriveKey(password, salt);
      return {
        'v': SealedShare.version,
        'set': share.setIdHex,
        'g': share.groupIndex,
        'm': share.memberIndex,
        'salt': base64Encode(salt),
        'ct': base64Encode(CryptoUtils.encrypt(mnemonic, key)),
        'at': '2026-09-01T00:00:00.000Z',
      };
    }

    test('a new share is Argon2id, version 4, its numbers in the body',
        () async {
      final sealed = await SealedShare.seal(
          mnemonic: shareA, password: password, shareCount: 3);
      final json = sealed.toJson();
      expect(json['v'], SealedShare.labelBoundVersion);
      expect(json['kdf'],
          {'alg': 'argon2id', 'm': 65536, 't': 3, 'p': 4},
          reason: 'RFC 9106\'s second recommended setting, written out');
      final back = SealedShare.fromJson(jsonDecode(jsonEncode(json)))!;
      expect(back.kdf.isArgon2id, isTrue);
      expect(await back.open(password), shareA);
    });

    test('a share sealed with PBKDF2 before still opens', () async {
      final legacy = SealedShare.fromJson(await pbkdf2Body(shareA))!;
      expect(legacy.kdf.isArgon2id, isFalse);
      expect(await legacy.open(password), shareA);
      expect(legacy.toJson().containsKey('kdf'), isFalse,
          reason: 'a PBKDF2 share is written back exactly as it was read');
    });

    test('the derivation the body names is the one used', () async {
      // An Argon2id share relabelled as PBKDF2 derives a different key, and
      // the tag refuses it: the label chooses the function, it cannot choose
      // the result.
      final sealed = await SealedShare.seal(
          mnemonic: shareA, password: password, shareCount: 3);
      final relabelled = Map<String, dynamic>.from(sealed.toJson())
        ..['v'] = SealedShare.version
        ..remove('kdf');
      final asPbkdf2 = SealedShare.fromJson(relabelled)!;
      expect(asPbkdf2.kdf.isArgon2id, isFalse);
      await expectLater(asPbkdf2.open(password),
          throwsA(isA<Slip39WrongPassword>()));

      final weaker = Map<String, dynamic>.from(sealed.toJson())
        ..['kdf'] = {'alg': 'argon2id', 'm': 8192, 't': 1, 'p': 1};
      await expectLater(SealedShare.fromJson(weaker)!.open(password),
          throwsA(isA<Slip39WrongPassword>()),
          reason: 'lowering the numbers in the file buys nothing');
    });

    test('Argon2id numbers a later build may choose are read', () async {
      final share = decodeShare(shareA);
      final salt = CryptoUtils.randomKey();
      const kdf = ShareKdf.argon2id(
          memoryKiB: 131072, iterations: 4, parallelism: 4);
      final key = await kdf.derive(password, salt);
      final body = {
        'v': SealedShare.argon2idVersion,
        'set': share.setIdHex,
        'g': share.groupIndex,
        'm': share.memberIndex,
        't': 2,
        'n': 3,
        'salt': base64Encode(salt),
        'kdf': kdf.toJson(),
        'ct': base64Encode(CryptoUtils.encrypt(shareA, key)),
        'at': '2026-10-11T00:00:00.000Z',
      };
      expect(await SealedShare.fromJson(body)!.open(password), shareA);
    });

    test('a version 3 body is refused whole when its derivation is not one',
        () async {
      final good = (await SealedShare.seal(
              mnemonic: shareA, password: password, shareCount: 3))
          .toJson();
      Map<String, dynamic> withKdf(Object? kdf) =>
          Map<String, dynamic>.from(good)..['kdf'] = kdf;
      for (final (kdf, why) in [
        (null, 'no derivation named'),
        ({'alg': 'scrypt', 'm': 65536, 't': 3, 'p': 4}, 'another function'),
        ({'alg': 'argon2id', 'm': 1048576, 't': 3, 'p': 4},
            'a gigabyte, which a phone may not have'),
        ({'alg': 'argon2id', 'm': 4096, 't': 3, 'p': 4}, 'below the floor'),
        ({'alg': 'argon2id', 'm': 65536, 't': 0, 'p': 4}, 'no passes'),
        ({'alg': 'argon2id', 'm': 65536, 't': 17, 'p': 4}, 'too many passes'),
        ({'alg': 'argon2id', 'm': 65536, 't': 3, 'p': 0}, 'no lanes'),
        ({'alg': 'argon2id', 'm': 65536, 't': 3, 'p': 9}, 'too many lanes'),
        ({'alg': 'argon2id', 'm': '65536', 't': 3, 'p': 4}, 'a string'),
      ]) {
        expect(SealedShare.fromJson(withKdf(kdf)), isNull, reason: why);
      }
      // And the other way round: a PBKDF2 version naming a derivation.
      final legacy = await pbkdf2Body(shareA);
      legacy['kdf'] = {'alg': 'argon2id', 'm': 65536, 't': 3, 'p': 4};
      expect(SealedShare.fromJson(legacy), isNull,
          reason: 'version 1 never carried one, so one there was not written '
              'by this app');
    });
  });

  group('what the stores add up to', () {
    Future<SealedShare> sealed(String m) =>
        SealedShare.seal(mnemonic: m, password: password, shareCount: 3);

    test('two copies of one share are not two shares', () async {
      // **The way a threshold gets satisfied by nothing.** The same share
      // synced into two clouds looks like two entries and is one.
      final a = await sealed(shareA);
      final again = await sealed(shareA);
      final status = BackupStatus.from(
        byStore: {'device': [ShareRecord.of(a)], 'google': [ShareRecord.of(again)]},
        unreachable: const [],
      ).single;
      expect(status.distinctShares, 1);
      expect(status.isRecoverable, isFalse);
    });

    test('two different shares meet a threshold of two', () async {
      final status = BackupStatus.from(
        byStore: {
          'device': [ShareRecord.of(await sealed(shareA))],
          'google': [ShareRecord.of(await sealed(shareB))],
        },
        unreachable: const [],
      ).single;
      expect(status.distinctShares, 2);
      expect(status.isRecoverable, isTrue);
      expect(status.isOneAwayFromLost, isTrue,
          reason: 'losing either leaves one share and no wallet');
    });

    test('a store that did not answer never counts as recoverable', () async {
      // A maybe reported as a yes is how somebody deletes their last copy.
      final status = BackupStatus.from(
        byStore: {'device': [ShareRecord.of(await sealed(shareA))]},
        unreachable: const ['google'],
      ).single;
      expect(status.isRecoverable, isFalse);
      expect(status.unreachable, ['google']);
    });

    test('shares of different backups are counted separately', () async {
      // Two backups on one device must never pool their shares into one
      // apparently-safe total.
      final other = await SealedShare.seal(
        mnemonic: otherSetShare,
        password: password,
        shareCount: 3,
      );
      final mine = await sealed(shareA);
      final statuses = BackupStatus.from(
        byStore: {
          'device': [ShareRecord.of(mine)],
          'google': [ShareRecord.of(other)],
        },
        unreachable: const [],
      );
      expect(mine.setId, isNot(other.setId),
          reason: 'the vectors were chosen to be two different backups');
      expect(statuses, hasLength(2));
      for (final s in statuses) {
        expect(s.isRecoverable, isFalse,
            reason: 'one share each is one share each');
      }
    });

    test('sealing does not change what the shares reconstruct', () async {
      // **The end-to-end assertion, and the only one that proves the sealing
      // did not quietly alter what is stored.** Seal both shares, open them,
      // and require the reconstruction to be the secret the *standard* names
      // for this pair — not merely what our own plain mnemonics give, which
      // would be the round trip agreeing with itself.
      final opened = [
        await (await sealed(shareA)).open(password),
        await (await sealed(shareB)).open(password),
      ];
      final secret = recoverSecret(opened, passphrase: trezor);
      expect(
        secret.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        'b43ceb7e57a0ea8766221624d01b0864',
      );
    });

  });

  group('the labels a share cannot vouch for, sealed beside it (version 4)', () {
    // How many shares there were, which backup, and when: readable because
    // the restore screens need them before any password, and since
    // 13 October 2026 sealed with the share too, so an edit is caught when
    // the share is opened — as an altered file, not as a wrong password.
    Future<Map<String, dynamic>> sealedBody() async => (await SealedShare.seal(
          mnemonic: shareA,
          password: password,
          shareCount: 3,
          backupId: SealedShare.newBackupId(),
          now: DateTime.utc(2026, 10, 13, 9, 30),
        ))
            .toJson();

    Future<String> openBody(Map<String, dynamic> body) =>
        SealedShare.fromJson(jsonDecode(jsonEncode(body)))!.open(password);

    test('an untouched body opens with the right password', () async {
      final body = await sealedBody();
      expect(body['v'], SealedShare.labelBoundVersion);
      expect(await openBody(body), shareA);
    });

    test('an edit to any of the three is an altered file', () async {
      final body = await sealedBody();
      for (final (edit, why) in [
        (({...body, 'n': 5}), 'two of five where it was two of three'),
        (({...body, 'bid': SealedShare.newBackupId()}), 'another backup\'s name'),
        (({...body}..remove('bid')), 'the backup\'s name taken away'),
        (({...body, 'at': '2025-01-01T00:00:00.000Z'}), 'another date'),
        (({...body, 'at': 'yesterday'}), 'a date nobody can read'),
      ]) {
        await expectLater(openBody(edit), throwsA(isA<Slip39Altered>()),
            reason: why);
      }
    });

    test('a wrong password is still a wrong password', () async {
      final body = await sealedBody();
      await expectLater(
          SealedShare.fromJson(body)!.open('not the password at all'),
          throwsA(isA<Slip39WrongPassword>()));
    });

    test('relabelled down to version 3, it is not read as a share', () async {
      // The check cannot be dropped by lowering the number: what version 3
      // decrypts is then not a share's words.
      final body = await sealedBody();
      await expectLater(openBody({...body, 'v': SealedShare.argon2idVersion}),
          throwsA(isA<Slip39Exception>()));
    });

    test('a version 3 share relabelled up to 4 is damage', () async {
      final share = decodeShare(shareA);
      final salt = CryptoUtils.randomKey();
      final key = await ShareKdf.current.derive(password, salt);
      final body = {
        'v': SealedShare.labelBoundVersion,
        'set': share.setIdHex,
        'g': share.groupIndex,
        'm': share.memberIndex,
        't': 2,
        'n': 3,
        'salt': base64Encode(salt),
        'kdf': ShareKdf.current.toJson(),
        'ct': base64Encode(CryptoUtils.encrypt(shareA, key)),
        'at': '2026-10-11T00:00:00.000Z',
      };
      await expectLater(openBody(body), throwsA(isA<Slip39Damaged>()));
      // And the same body under its own number opens, labels unchecked.
      expect(await openBody({...body, 'v': SealedShare.argon2idVersion}),
          shareA);
    });
  });

  group('a test may seal cheaper, and only a test', () {
    // Ten test files about stores, backups and screens seal under
    // `ShareKdf.cheapestReadable` (12 October 2026: Argon2id's isolates,
    // left running by a timed-out test, failed whole files in a full run).
    // These hold that the shortcut cannot reach a shipped app.
    final source = File('lib/core/sealed_share.dart').readAsStringSync();

    test('it is read only in a debug build', () {
      expect(source,
          contains('(_debugBuild ? debugSealingKdf : null) ?? ShareKdf.current'));
      expect(
          source,
          contains("static const bool _debugBuild = "
              "!bool.fromEnvironment('dart.vm.product') &&\n"
              "      !bool.fromEnvironment('dart.vm.profile');"),
          reason: 'the gate must be a compile-time constant false in release');
    });

    test('nothing under lib/ sets it', () {
      final setters = <String>[];
      for (final file in Directory('lib').listSync(recursive: true)) {
        if (file is! File || !file.path.endsWith('.dart')) continue;
        if (file.path.endsWith('core/sealed_share.dart')) continue;
        if (file.readAsStringSync().contains('debugSealingKdf')) {
          setters.add(file.path);
        }
      }
      expect(setters, isEmpty);
    });

    test('unset, a share is sealed under the real setting', () async {
      expect(SealedShare.debugSealingKdf, isNull);
      final sealed = await SealedShare.seal(
          mnemonic: shareA, password: password, shareCount: 3);
      expect(sealed.toJson()['kdf'], ShareKdf.current.toJson());
    });

    test('and the cheap one is still a setting a share may state', () async {
      expect(ShareKdf.fromJson(ShareKdf.cheapestReadable.toJson()), isNotNull);
      SealedShare.debugSealingKdf = ShareKdf.cheapestReadable;
      addTearDown(() => SealedShare.debugSealingKdf = null);
      final sealed = await SealedShare.seal(
          mnemonic: shareA, password: password, shareCount: 3);
      expect(sealed.toJson()['kdf'], {'alg': 'argon2id', 'm': 8192, 't': 1, 'p': 1});
      final back = SealedShare.fromJson(jsonDecode(jsonEncode(sealed.toJson())))!;
      expect(await back.open(password), shareA);
    });
  });
}
