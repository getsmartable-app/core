// The shares kept on this phone are one encrypted record, rewritten whole by
// every backup made or removed here. A share this build cannot read — a newer
// format, or a damaged entry — is carried through every write unchanged, and a
// record that is there and could not be read this moment is never written over
// as though it were empty: either would delete shares with nothing said.
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smartable_wallet_core/core/paper_share_store.dart';
import 'package:smartable_wallet_core/core/sealed_share.dart';
import 'package:smartable_wallet_core/core/secure_storage.dart';
import 'package:smartable_wallet_core/core/share_store.dart';

const _key = 'wallet_shares';

SealedShare _share(String backupId, {int member = 0}) => SealedShare(
      setId: '1a2b',
      instanceId: backupId,
      groupIndex: 0,
      memberIndex: member,
      salt: 'c2FsdA==',
      ciphertext: 'Y2lwaGVydGV4dA==',
      createdAt: DateTime.utc(2026, 10, 6),
    );

const _a = '0123456789abcdef0123456789abcdef';
const _b = 'fedcba9876543210fedcba9876543210';

/// A share from a build that seals with a backup passphrase (format 3).
const Map<String, Object?> _newer = {
  'v': 3,
  'set': '7f00',
  'bid': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'g': 0,
  'm': 1,
  'sealed': 'AAEC',
};

Future<List<Object?>> _stored() async =>
    jsonDecode((await SecureStorage.readEncryptedOnly(_key))!) as List<Object?>;

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    FlutterSecureStorage.setMockInitialValues({});
  });

  const store = DeviceShareStore();

  test('a backup made here keeps a share this build cannot read', () async {
    await SecureStorage.writeEncryptedOnly(_key, jsonEncode([_share(_a).toJson(), _newer]));
    expect(await store.put(_share(_b)), isTrue);
    final after = await _stored();
    expect(after, contains(equals(_newer)), reason: 'a newer build’s share survives');
    expect((await store.list()).map((r) => r.backupId), unorderedEquals([_a, _b]));
  });

  test('removing a backup removes its shares, and keeps one it cannot read', () async {
    await SecureStorage.writeEncryptedOnly(
        _key, jsonEncode([_share(_a).toJson(), _share(_b).toJson(), _newer]));
    expect(await store.removeBackup(_a), isTrue);
    expect((await store.list()).map((r) => r.backupId), [_b]);
    expect(await _stored(), contains(equals(_newer)));
  });

  test('an unreadable entry that names the backup being removed goes with it', () async {
    await SecureStorage.writeEncryptedOnly(_key, jsonEncode([_share(_b).toJson(), _newer]));
    expect(await store.removeBackup(_newer['bid']! as String), isTrue);
    expect(await _stored(), isNot(contains(equals(_newer))));
    expect((await store.list()).map((r) => r.backupId), [_b]);
  });

  test('a record that is there and will not read is not written over', () async {
    await SecureStorage.writeEncryptedOnly(_key, 'not json {');
    expect(await store.put(_share(_b)), isFalse);
    expect(await store.removeBackup(_a), isFalse);
    expect(await SecureStorage.readEncryptedOnly(_key), 'not json {');
  });

  test('with nothing stored, a share is stored', () async {
    expect(await store.put(_share(_a)), isTrue);
    expect((await store.list()).map((r) => r.backupId), [_a]);
    expect(await store.put(_share(_a, member: 1)), isTrue);
    expect((await store.list()).single.memberIndex, 1,
        reason: 'a backup made again replaces its own share');
  });

  group('the notes of shares written down', () {
    const paper = PaperShareStore();
    const paperKey = 'wallet_shares_paper';
    Future<List<Object?>> notes() async =>
        jsonDecode((await SecureStorage.readEncryptedOnly(paperKey))!) as List<Object?>;

    test('a note this build cannot read is kept, and still counted by a newer one',
        () async {
      const newer = {'set': '7f00', 'bid': _b, 'g': 0, 'm': 2, 't': 2, 'n': 17};
      expect(await paper.put(_share(_a)), isTrue);
      await SecureStorage.writeEncryptedOnly(paperKey, jsonEncode([...await notes(), newer]));
      expect(await paper.put(_share(_a, member: 1)), isTrue);
      expect(await notes(), contains(equals(newer)));
      expect(await paper.removeBackup(_a), isTrue);
      expect(await notes(), contains(equals(newer)));
      expect(await paper.removeBackup(_b), isTrue, reason: 'and goes with its own backup');
      expect(await notes(), isEmpty);
    });

    test('a record that will not read is not written over', () async {
      await SecureStorage.writeEncryptedOnly(paperKey, '{');
      expect(await paper.put(_share(_a)), isFalse);
      expect(await paper.removeBackup(_a), isFalse);
      expect(await SecureStorage.readEncryptedOnly(paperKey), '{');
    });
  });
}
