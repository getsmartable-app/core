import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smartable_wallet_core/core/secure_storage.dart';

import 'support/keystores.dart';

/// What happens when the keystore says no.
///
/// **The happy-path mock proves the wrong half.** `setMockInitialValues`
/// installs an in-memory store that always works, which shows the app calls the
/// right API and shows nothing at all about the branch this change exists for.
/// The security review of 23 August 2026 asked for the other half, and it is
/// the half that carries the guarantee: a refusal must stop the operation and
/// must not leave the secret somewhere readable.
///
/// **Still not a Keychain.** Nothing here touches Android Keystore, StrongBox
/// or iOS Keychain; it does not model `KeyPermanentlyInvalidatedException`, a
/// locked device, an entitlement error, or restore-after-reinstall. Those need
/// a physical device and are listed as pending in the finding record.
class _RefusingKeystore extends FlutterSecureStoragePlatform {
  final Map<String, String> _store = {};

  /// Reads are allowed on purpose: the interesting failures are one-sided —
  /// a device that can read what it has and cannot write anything new.
  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async =>
      _store[key];

  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) async =>
      _store.containsKey(key);

  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async =>
      Map.of(_store);

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) async {
    throw PlatformException(code: 'Keystore', message: 'unavailable');
  }

  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) async =>
      _store.remove(key);

  @override
  Future<void> deleteAll({required Map<String, String> options}) async =>
      _store.clear();
}

void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    FlutterSecureStoragePlatform.instance = _RefusingKeystore();
  });

  tearDown(() => FlutterSecureStorage.setMockInitialValues({}));

  group('a keystore that will not write', () {
    test('refuses the secret rather than putting it somewhere readable',
        () async {
      await expectLater(
        SecureStorage.saveSeedVaults('[{"id":"primary"}]'),
        throwsA(isA<SecretStorageUnavailable>()),
      );

      // The assertion that matters. An exception with the value written anyway
      // would be the old behaviour wearing a new error.
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('seed_vaults'), isNull);
    });

    test('and the same for every other secret', () async {
      final prefs = await SharedPreferences.getInstance();
      for (final write in <(String, Future<void> Function())>[
        ('pin_blob', () => SecureStorage.savePinBlob('sealed')),
        ('device_key_blob', () => SecureStorage.saveDeviceKeyBlob('wrapped')),
        ('imported_keys', () => SecureStorage.saveImportedKeys('cipher')),
        ('account_key', () => SecureStorage.saveAccountKeyRecord('{"k":1}')),
        ('encrypted_seed',
            () => SecureStorage.saveEncryptedSeed('cipher', 'salt')),
      ]) {
        await expectLater(write.$2(), throwsA(isA<SecretStorageUnavailable>()),
            reason: write.$1);
        expect(prefs.getString(write.$1), isNull, reason: write.$1);
      }
      expect(prefs.getString('salt'), isNull);
    });

    test('a network added by hand is not written weakly either', () async {
      // Its RPC URL usually carries a paid provider key in the path, the
      // reason Settings → RPC endpoints is encrypted-only. "Add network" wrote
      // the same URL through the ordinary path, which fell back to plaintext.
      expect(
          await SecureStorage.saveCustomNetworks(
              '[{"rpcUrl":"https://eth.example/v2/KEY"}]'),
          isFalse);
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('custom_networks'), isNull);
    });

    test('an ordinary preference still falls back, and that is the point',
        () async {
      // Without this the rule is "encrypt everything or fail", which would
      // stop a wallet from starting because it could not save a theme.
      await SecureStorage.saveThemeMode(true);
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('theme_mode'), 'dark');
    });

    test('the message says nothing was written anywhere weaker', () async {
      try {
        await SecureStorage.savePinBlob('sealed');
        fail('should have thrown');
      } on SecretStorageUnavailable catch (error) {
        expect(error.toString(), contains('Nothing was written anywhere less safe'));
      }
    });
  });

  group('migrating a wallet written by an older build', () {
    test('a hand-added network left in preferences is moved on first read',
        () async {
      FlutterSecureStorage.setMockInitialValues({});
      const list = '[{"rpcUrl":"https://eth.example/v2/KEY"}]';
      SharedPreferences.setMockInitialValues({'custom_networks': list});

      expect(await SecureStorage.getCustomNetworks(), list);
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('custom_networks'), isNull);
      expect(await SecureStorage.getCustomNetworks(), list,
          reason: 'and it is still there, now from the keystore');
    });

    test('a legacy secret is readable, moved, and then gone from preferences',
        () async {
      FlutterSecureStorage.setMockInitialValues({});
      SharedPreferences.setMockInitialValues({'seed_vaults': '[{"id":"old"}]'});

      expect(await SecureStorage.getSeedVaults(), '[{"id":"old"}]',
          reason: 'the old shape has to keep opening');

      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('seed_vaults'), isNull,
          reason: 'reading it is what moves it — not the next write, which '
              'may be months away or never');
    });

    test('a failed migration leaves it readable and writes no new plaintext',
        () async {
      SharedPreferences.setMockInitialValues({'seed_vaults': '[{"id":"old"}]'});
      FlutterSecureStoragePlatform.instance = _RefusingKeystore();

      expect(await SecureStorage.getSeedVaults(), '[{"id":"old"}]');
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('seed_vaults'), '[{"id":"old"}]',
          reason: 'deleting it would strand a wallet that still opens');

      // Read twice: a migration that half-succeeded must not compound.
      expect(await SecureStorage.getSeedVaults(), '[{"id":"old"}]');
    });

    test('the secure copy wins over a stale readable one, which is removed',
        () async {
      FlutterSecureStorage.setMockInitialValues({'seed_vaults': '[{"id":"new"}]'});
      SharedPreferences.setMockInitialValues({'seed_vaults': '[{"id":"old"}]'});

      expect(await SecureStorage.getSeedVaults(), '[{"id":"new"}]');
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('seed_vaults'), isNull);
    });
  });

  group('a keystore that will not answer', () {
    setUp(() {
      SharedPreferences.setMockInitialValues({});
      FlutterSecureStoragePlatform.instance = SilentKeystore();
    });

    test('a read that failed is not the answer "there is no wallet"', () async {
      // The P0 of the third review round. Returning null here is what offered
      // onboarding over the top of somebody's funds.
      await expectLater(
        SecureStorage.getSeedVaults(),
        throwsA(isA<SecretStorageUnavailable>()),
      );
    });

    test('every secret read carries the same distinction', () async {
      for (final read in <(String, Future<String?> Function())>[
        ('pin_blob', SecureStorage.getPinBlob),
        ('device_key_blob', SecureStorage.getDeviceKeyBlob),
        ('imported_keys', SecureStorage.getImportedKeys),
        ('account_key', SecureStorage.getAccountKeyRecord),
        ('encrypted_seed', SecureStorage.getEncryptedSeed),
        ('salt', SecureStorage.getSalt),
      ]) {
        await expectLater(read.$2(), throwsA(isA<SecretStorageUnavailable>()),
            reason: read.$1);
      }
    });

    test('a legacy copy still opens the wallet, and stays where it is',
        () async {
      // Checked before the failure is raised, on purpose: a readable copy
      // opens the wallet whatever the keystore is doing, and deleting it
      // because the migration could not run would strand exactly the person
      // the migration is for.
      SharedPreferences.setMockInitialValues({'seed_vaults': '[{"id":"old"}]'});

      expect(await SecureStorage.getSeedVaults(), '[{"id":"old"}]');

      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('seed_vaults'), '[{"id":"old"}]',
          reason: 'the migration failed, so nothing about it may be claimed');
    });

    test('hasStoredWallet throws rather than answering false', () async {
      // False is the value the launcher turns into "create a wallet". There is
      // no reading of this store that may produce it.
      await expectLater(
        SecureStorage.hasStoredWallet(),
        throwsA(isA<SecretStorageUnavailable>()),
      );
    });

    test('hasStoredWallet says yes from the readable copy alone', () async {
      SharedPreferences.setMockInitialValues({'seed_vaults': '[{"id":"old"}]'});
      expect(await SecureStorage.hasStoredWallet(), isTrue);
    });

    test('an empty vault list is not a wallet', () async {
      SharedPreferences.setMockInitialValues({'seed_vaults': '[]'});
      // Both reads have to be reached for this to be answerable, and the
      // second one is the loose legacy pair, which this store cannot serve.
      await expectLater(
        SecureStorage.hasStoredWallet(),
        throwsA(isA<SecretStorageUnavailable>()),
      );
    });

    test('an ordinary read still falls back and still answers null', () async {
      // The other half of the distinction: `read` is for records whose absence
      // costs nothing, and it must not start throwing at every call site that
      // asks for a theme.
      expect(await SecureStorage.getThemeModeIsDark(), isTrue);
      expect(await SecureStorage.getCurrency(), isNull);
    });
  });

  group('an erasure that cannot confirm its half', () {
    setUp(() {
      SharedPreferences.setMockInitialValues({'seed_vaults': '[{"id":"a"}]'});
      FlutterSecureStoragePlatform.instance = SilentKeystore();
    });

    test('the readable half goes anyway, and the failure is reported',
        () async {
      await expectLater(
        SecureStorage.eraseEverything(),
        throwsA(isA<SecretStorageDeletionIncomplete>()),
      );

      // The rule the erasure order exists for: a device is left with less on
      // it than before, never more. Stopping at the keystore failure would
      // have skipped this wipe.
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('seed_vaults'), isNull);
    });

    test('it is not the same failure as a refused write', () async {
      // Two exceptions rather than one because the screens above say opposite
      // things: nothing was written, versus something may still be here.
      await expectLater(
        SecureStorage.eraseEverything(),
        throwsA(isNot(isA<SecretStorageUnavailable>())),
      );
    });

    test('the message tells somebody not to hand the device on', () async {
      try {
        await SecureStorage.eraseEverything();
        fail('should have thrown');
      } on SecretStorageDeletionIncomplete catch (error) {
        expect(error.toString(), contains('Do not sell, give away or hand'));
      }
    });
  });

  group('the test harness itself', () {
    // **Infrastructure regression, asked for by the review.** The global mock
    // is reset per test rather than per file; without that, one test's wallet
    // is the next test's starting state and the cause is invisible months
    // later.
    test('A writes a secret', () async {
      FlutterSecureStorage.setMockInitialValues({});
      await SecureStorage.saveSeedVaults('[{"id":"from-test-A"}]');
      expect(await SecureStorage.getSeedVaults(), contains('from-test-A'));
    });

    test('B starts with nothing of A', () async {
      FlutterSecureStorage.setMockInitialValues({});
      expect(await SecureStorage.getSeedVaults(), isNull);
    });
  });
}
