import 'dart:convert';
import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smartable_wallet_core/core/paper_share_store.dart';
import 'package:smartable_wallet_core/core/sealed_share.dart';
import 'package:smartable_wallet_core/core/share_store.dart';

/// The share somebody wrote down, and the counting that has to include it.
///
/// **A status screen that could not see paper would understate the backup**,
/// and understating sends somebody to fix a thing that is not broken — which
/// ends with them replacing a working backup and losing the one they had.
void main() {
  // Where shares go, not how hard their key is to guess: sealed under the
  // cheapest Argon2id setting a share may state (`SealedShare.debugSealingKdf`
  // says why). `sealed_share_test` keeps the real one.
  setUpAll(() => SealedShare.debugSealingKdf = ShareKdf.cheapestReadable);
  tearDownAll(() => SealedShare.debugSealingKdf = null);

  const shareA =
      'shadow pistol academic always adequate wildlife fancy gross oasis '
      'cylinder mustang wrist rescue view short owner flip making coding armed';
  const shareB =
      'shadow pistol academic acid actress prayer class unknown daughter '
      'sweater depict flip twice unkind craft early superior advocate guest '
      'smoking';
  const password = 'correct horse battery staple';

  test('it is always available, and says what it is', () async {
    // **Available unconditionally, unlike every other store.** Paper needs no
    // account, no network and no platform support, which is exactly why it is
    // the answer for somebody with one cloud — and why the flow must be able
    // to offer it when the others report false.
    const store = PaperShareStore();
    expect(await store.isAvailable(), isTrue);
    expect(store.id, 'paper');
    // Named for what the person did, not for what we stored: "Written down" is
    // a claim about their card, and this store holds nothing else.
    expect(store.displayName, 'Written down');
  });

  test('it stores a note and never the share', () {
    // **The whole point of paper is that it is not on the phone.** Twenty words
    // kept beside the device they are meant to outlive protect against
    // nothing, so this is a scan: the failure would be invisible on screen and
    // perfect in every behavioural test.
    final source = File('lib/core/paper_share_store.dart').readAsStringSync();
    final put = source.substring(source.indexOf('Future<bool> put('));
    final body = put.substring(0, put.indexOf('\n  }'));
    expect(body.contains('ciphertext'), isFalse);
    expect(body.contains('sealed:'), isFalse,
        reason: 'a paper share kept on the device is not a paper share');
  });

  test('what it reports cannot be opened here', () async {
    // "Fetch your paper" and "this copy is gone" are opposite instructions, so
    // a caller must branch on the type rather than call and catch.
    final record = ShareRecord(
      setId: '0abc',
      groupIndex: 0,
      memberIndex: 2,
      createdAt: DateTime.utc(2026, 8, 15),
    );
    expect(record.isReadable, isFalse);
    expect(record.sealed, isNull);
  });

  group('counting', () {
    Future<ShareRecord> readable(String m) async =>
        ShareRecord.of(await SealedShare.seal(mnemonic: m, password: password, shareCount: 3));

    ShareRecord onPaper(ShareRecord of) => ShareRecord(
          setId: of.setId,
          groupIndex: of.groupIndex,
          memberIndex: of.memberIndex,
          createdAt: of.createdAt,
        );

    test('paper counts towards the backup and not towards restoring here',
        () async {
      // **Two true things that must not be collapsed.** The backup is complete;
      // this device still cannot restore it on its own. Saying only the first
      // would tell somebody they can recover without their card, and saying
      // only the second would tell them they are one share short.
      final device = await readable(shareA);
      final paper = onPaper(await readable(shareB));
      final status = BackupStatus.from(
        byStore: {'device': [device], 'paper': [paper]},
        unreachable: const [],
      ).single;

      expect(status.distinctShares, 2, reason: 'the backup is complete');
      expect(status.isRecoverable, isTrue);
      expect(status.readableShares, 1);
      expect(status.isRestorableHere, isFalse,
          reason: 'the words are on a card, not on the phone');
    });

    test('two readable shares restore here', () async {
      final status = BackupStatus.from(
        byStore: {
          'device': [await readable(shareA)],
          'google': [await readable(shareB)],
        },
        unreachable: const [],
      ).single;
      expect(status.isRestorableHere, isTrue);
    });

    test('a paper note of a share already held is still one share', () async {
      // Writing down the share that is also on the device does not raise the
      // threshold; it is one share in two places.
      final device = await readable(shareA);
      final status = BackupStatus.from(
        byStore: {'device': [device], 'paper': [onPaper(device)]},
        unreachable: const [],
      ).single;
      expect(status.distinctShares, 1);
      expect(status.isRecoverable, isFalse);
    });
  });

  group('how the backup was divided', () {
    setUp(() {
      TestWidgetsFlutterBinding.ensureInitialized();
      SharedPreferences.setMockInitialValues({});
    });

    test('a note keeps how the backup was divided', () async {
      // **Paper holds no share, so its label is the one nothing can check.** A
      // note from a three-of-five backup read back as two of three would give
      // a restore on a phone with no sealed share left one fewer to ask for.
      FlutterSecureStorage.setMockInitialValues({});
      const store = PaperShareStore();
      final share = SealedShare(
        setId: '0abc',
        instanceId: 'c' * 32,
        groupIndex: 0,
        memberIndex: 4,
        threshold: 3,
        shareCount: 5,
        salt: 'c2FsdA==',
        ciphertext: 'Y2lwaGVy',
        createdAt: DateTime.utc(2026, 9, 11),
      );
      expect(await store.put(share), isTrue);

      final note = (await store.list()).single;
      expect(note.threshold, 3);
      expect(note.shareCount, 5);
      expect(note.isReadable, isFalse, reason: 'still a note, not the share');
    });

    test('a note from before the numbers is two of three', () async {
      FlutterSecureStorage.setMockInitialValues({
        'wallet_shares_paper': jsonEncode([
          {'set': '0abc', 'g': 0, 'm': 2, 'at': '2026-08-15T00:00:00.000Z'},
        ]),
      });
      final note = (await const PaperShareStore().list()).single;
      expect(note.threshold, 2);
      expect(note.shareCount, 3);
    });

    test('a note with numbers it cannot mean is not counted', () async {
      FlutterSecureStorage.setMockInitialValues({
        'wallet_shares_paper': jsonEncode([
          {'set': '0abc', 'g': 0, 'm': 2, 't': 4, 'n': 3, 'at': '2026-09-11T00:00:00.000Z'},
        ]),
      });
      expect(await const PaperShareStore().list(), isEmpty);
    });
  });
}
