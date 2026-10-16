// A vault entry this build cannot read is kept, never written over.
//
// The record of sealed phrases is one list, rewritten whole by every change —
// a name, a backup mark, a password change, another wallet. An entry this
// build could not parse (a newer build's shape after a downgrade, or damage)
// was dropped on read and then gone at the next write, taking an encrypted
// recovery phrase with it: the store deleting on its own, which nothing in it
// may do. Such an entry is now carried through every write unchanged, a record
// holding nothing else readable says so instead of "no wallet", and erasing
// the wallet still erases it.
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smartable_wallet_core/core/secure_storage.dart';
import 'package:smartable_wallet_core/core/seed_vault.dart';
import 'package:smartable_wallet_core/core/vault_keeper.dart';

const _phrase = 'abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon abandon abandon about';
const _password = 'correct horse 1';

/// An entry from a build that writes vaults differently.
const Map<String, Object?> _future = {
  'id': 'vault-from-a-newer-build',
  'sealed': {'v': 3, 'cipher': 'AAEC'},
  'accounts': 2,
};

class _Host implements VaultHost {
  bool open = false;

  @override
  Future<void> opened(SeedVault vault, String mnemonic) async => open = true;

  @override
  Future<void> switched(SeedVault vault, String mnemonic) async => open = true;

  @override
  void forget() => open = false;

  @override
  bool get phraseOpen => open;

  @override
  bool get phraseAccountSelected => true;
}

Future<List<Object?>> _stored() async =>
    jsonDecode((await SecureStorage.getSeedVaults())!) as List<Object?>;

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    FlutterSecureStorage.setMockInitialValues({});
  });

  group('the record', () {
    test('an entry that cannot be read is kept, as it was', () {
      final good = SeedVault(id: 'primary', encryptedSeed: 'c2VlZA==', salt: 'c2FsdA==');
      final raw = jsonEncode([good.toJson(), _future, 'not a vault at all']);
      final record = SeedVault.read(raw);
      expect(record.vaults.map((v) => v.id), ['primary']);
      expect(record.dropped, 2);
      expect(record.unparsed, [_future, 'not a vault at all']);
      expect(jsonDecode(SeedVault.encode(record.vaults, keep: record.unparsed)),
          jsonDecode(raw));
    });

    test('a record with nothing unreadable is written exactly as before', () {
      final good = SeedVault(id: 'primary', encryptedSeed: 'c2VlZA==', salt: 'c2FsdA==');
      expect(SeedVault.encode([good], keep: const []), SeedVault.encode([good]));
      expect(SeedVault.read(SeedVault.encode([good])).unparsed, isEmpty);
    });
  });

  group('the keeper', () {
    Future<VaultKeeper> sealed() async {
      final keeper = VaultKeeper(_Host());
      await keeper.saveSeed(_phrase, _password,
          accountSpan: 1, derivedCount: 1, backedUp: true);
      // A newer build wrote a second wallet this one cannot read.
      await SecureStorage.saveSeedVaults(jsonEncode([...await _stored(), _future]));
      return keeper;
    }

    test('a change to a wallet it can read keeps the one it cannot', () async {
      final keeper = await sealed();
      expect(await keeper.loadSeed(_password), _phrase);
      await keeper.updateVault('primary', (v) => v.copyWith(label: 'Savings'));
      final after = await _stored();
      expect(after, contains(equals(_future)), reason: 'the unread phrase survives the write');
      expect(after, hasLength(2));
    });

    test('so does a password change, which rewrites every wallet', () async {
      final keeper = await sealed();
      await keeper.loadSeed(_password);
      await keeper.changePassword(_password, 'another password 2');
      expect(await _stored(), contains(equals(_future)));
      keeper.lock();
      expect(await keeper.loadSeed('another password 2'), _phrase);
    });

    test('a record holding nothing readable is said to be unreadable, not empty',
        () async {
      await SecureStorage.saveSeedVaults(jsonEncode([_future]));
      final keeper = VaultKeeper(_Host());
      await expectLater(keeper.loadSeed(_password), throwsA(isA<VaultRecordUnreadable>()));
      expect(await _stored(), [_future], reason: 'and nothing was written over it');
    });

    test('a lock forgets it, so a wallet erased since is not brought back', () async {
      final keeper = await sealed();
      await keeper.loadSeed(_password);
      keeper.lock();
      await SecureStorage.saveSeedVaults('[]');
      await keeper.saveSeed(_phrase, _password,
          accountSpan: 1, derivedCount: 1, backedUp: true);
      expect(await _stored(), hasLength(1));
      expect(await _stored(), isNot(contains(equals(_future))));
    });
  });
}
