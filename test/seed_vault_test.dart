import 'package:flutter_test/flutter_test.dart';
import 'package:smartable_wallet_core/core/seed_vault.dart';

/// This record is the wallet. A vault that cannot be read back is a recovery
/// phrase the user no longer has, so the tests below are less about features
/// than about the two ways reading can go wrong: losing a good record, and
/// accepting a broken one.
void main() {
  const vault = SeedVault(
    id: 'primary',
    encryptedSeed: 'Y2lwaGVydGV4dA==',
    salt: 'c2FsdA==',
    accountCount: 3,
    backedUp: true,
    label: 'Main',
  );

  test('survives a round trip intact', () {
    final back = SeedVault.decode(SeedVault.encode([vault])).single;
    expect(back.id, vault.id);
    expect(back.encryptedSeed, vault.encryptedSeed);
    expect(back.salt, vault.salt);
    expect(back.accountCount, vault.accountCount);
    expect(back.backedUp, isTrue);
    expect(back.label, 'Main');
  });

  test('keeps several phrases in order', () {
    final list = [vault, vault.copyWith(label: 'Second')];
    final back = SeedVault.decode(SeedVault.encode(list));
    expect(back, hasLength(2));
    expect(back.last.label, 'Second');
  });

  group('refuses a record it cannot read in full', () {
    test('missing ciphertext or salt', () {
      // Carrying a half-read vault forward surfaces later as a failed
      // decryption, which looks exactly like a wrong password — and sends the
      // user to reset a wallet that was never lost.
      expect(SeedVault.fromJson({'id': 'a', 'salt': 's'}), isNull);
      expect(SeedVault.fromJson({'id': 'a', 'seed': 'c'}), isNull);
      expect(SeedVault.fromJson({'seed': 'c', 'salt': 's'}), isNull);
    });

    test('empty strings, which are not values', () {
      expect(SeedVault.fromJson({'id': '', 'seed': 'c', 'salt': 's'}), isNull);
      expect(SeedVault.fromJson({'id': 'a', 'seed': '', 'salt': 's'}), isNull);
    });

    test('something that is not a record at all', () {
      expect(SeedVault.fromJson('nonsense'), isNull);
      expect(SeedVault.fromJson(null), isNull);
    });
  });

  group('does not lose good records', () {
    test('one corrupt entry does not hide the others', () {
      const json = '[{"id":"a","seed":"c","salt":"s"},'
          '{"broken":true},'
          '{"id":"b","seed":"c2","salt":"s2"}]';
      final back = SeedVault.decode(json);
      expect(back.map((v) => v.id), ['a', 'b'],
          reason: 'a single bad record must not hide recoverable phrases');
    });

    test('malformed json yields nothing rather than throwing', () {
      // Throwing here would take the unlock screen down with it, turning a
      // storage problem into an unopenable wallet.
      expect(SeedVault.decode('{not json'), isEmpty);
      expect(SeedVault.decode('{"not":"a list"}'), isEmpty);
      expect(SeedVault.decode(null), isEmpty);
      expect(SeedVault.decode(''), isEmpty);
    });

    test('an account count of zero reads as one', () {
      // A wallet always has a first account; older builds could store zero,
      // and restoring none would present an unlocked wallet with no addresses.
      final back = SeedVault.fromJson(
          {'id': 'a', 'seed': 'c', 'salt': 's', 'accounts': 0});
      expect(back!.accountCount, 1);
    });
  });

  test('backedUp defaults to false when absent', () {
    // Fails closed, like the gate it feeds: an unreadable answer must not read
    // as "already backed up".
    final back = SeedVault.fromJson({'id': 'a', 'seed': 'c', 'salt': 's'});
    expect(back!.backedUp, isFalse);
  });

  group('removed accounts', () {
    test('survive the round trip', () {
      final withHidden = vault.copyWith(accountCount: 4, hiddenAccounts: [1, 2]);
      final back = SeedVault.decode(SeedVault.encode([withHidden])).single;
      expect(back.hiddenAccounts, [1, 2]);
      expect(back.accountCount, 4,
          reason: 'the span has to outlive the removal, or the gap closes');
    });

    test('are absent from the file when there are none', () {
      // Most wallets have never removed one, and an empty list in every record
      // is noise in a file read on every unlock.
      expect(SeedVault.encode([vault]), isNot(contains('hidden')));
    });

    test('a vault written before this existed has none', () {
      final back = SeedVault.fromJson({'id': 'a', 'seed': 'c', 'salt': 's'});
      expect(back!.hiddenAccounts, isEmpty);
    });

    test('an unreadable entry is dropped, not the vault', () {
      // The worst a bad entry can do is show an account that was meant to be
      // hidden. Refusing the whole record over one would lose the phrase.
      final back = SeedVault.fromJson({
        'id': 'a',
        'seed': 'c',
        'salt': 's',
        'hidden': [1, 'two', -3, 4],
      });
      expect(back!.hiddenAccounts, [1, 4]);
      expect(back.encryptedSeed, 'c');
    });
  });

  test('copyWith leaves the secret and its salt alone', () {
    final renamed = vault.copyWith(label: 'Renamed', backedUp: false);
    expect(renamed.encryptedSeed, vault.encryptedSeed);
    expect(renamed.salt, vault.salt);
    expect(renamed.id, vault.id);
  });
}
