import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smartable_wallet_core/core/crypto_utils.dart';
import 'package:smartable_wallet_core/core/hardware_key.dart';
import 'package:smartable_wallet_core/core/password_recovery.dart';
import 'package:smartable_wallet_core/core/pin_lock.dart';
import 'package:smartable_wallet_core/core/secure_storage.dart';
import 'package:smartable_wallet_core/core/seed_vault.dart';
import 'package:smartable_wallet_core/core/vault_keeper.dart';
import 'package:smartable_wallet_core/core/wallet_doors.dart';

import 'support/fake_pin_pepper.dart';

/// The keeper on its own, with no wallet in front of it.
///
/// **Why a file of its own when the wallet's tests already go through it.**
/// Those tests reach the keeper through `WalletProvider`, which the published
/// core does not carry — so in the core they do not exist, and the code that
/// seals a phrase would be published with nothing there running it. These are
/// the same properties asked of the keeper directly, through a host that does
/// nothing but record what it was told.
void main() {
  useFakePinPepper();
  TestWidgetsFlutterBinding.ensureInitialized();

  const phrase = 'abandon abandon abandon abandon abandon abandon abandon '
      'abandon abandon abandon abandon about';
  const otherPhrase =
      'legal winner thank year wave sausage worth useful legal winner thank '
      'yellow';
  const password = 'correct horse battery';
  const next = 'a different long password';
  const pin = '246813';

  const deviceChannel = MethodChannel('test.vault_keeper_device_key');
  DeviceKey.channel = deviceChannel;

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    resetWalletDoorsForTest();
    var alive = true;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(deviceChannel, (call) async {
      final bytes = call.arguments?['bytes'] as Uint8List?;
      switch (call.method) {
        case 'isSupported':
          return true;
        case 'wrap':
          return Uint8List.fromList([9, ...bytes!]);
        case 'unwrap':
          if (!alive) throw PlatformException(code: 'key_gone');
          return Uint8List.fromList(bytes!.sublist(1));
        case 'forget':
          alive = false;
          return null;
      }
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(deviceChannel, null);
  });

  Future<SeedVault> storedVault() async =>
      SeedVault.decode(await SecureStorage.getSeedVaults()).single;

  /// A wallet saved under [password] and then dropped from memory, which is
  /// how the create flow leaves it.
  Future<void> sealed() async {
    final host = _Host()..phrase = phrase;
    await VaultKeeper(host).saveSeed(phrase, password,
        accountSpan: 1, derivedCount: 1, backedUp: false);
  }

  /// [sealed], then opened by the password, as an unlock leaves it.
  Future<(VaultKeeper, _Host)> opened() async {
    await sealed();
    final host = _Host();
    final keeper = VaultKeeper(host);
    await keeper.loadSeed(password);
    return (keeper, host);
  }

  group('a phrase is sealed under a key nobody typed', () {
    test('the password unwraps that key, and opens nothing by itself', () async {
      await sealed();
      final vault = await storedVault();
      final derived =
          await CryptoUtils.deriveKey(password, base64Decode(vault.salt));

      expect(vault.wrappedKey, isNotNull);
      expect(
          () => CryptoUtils.decrypt(base64Decode(vault.encryptedSeed), derived),
          throwsA(anything),
          reason: 'a phrase under the password is a phrase guessable offline');
      final vaultKey = CryptoUtils.unwrapKey(vault.wrappedKey!, derived);
      expect(CryptoUtils.decrypt(base64Decode(vault.encryptedSeed), vaultKey),
          phrase);
      expect(await SecureStorage.getEncryptedSeed(), isNull,
          reason: 'no copy is kept under the password for an older build');
    });

    test('saving drops the keys and what the wallet derived', () async {
      final host = _Host()..phrase = phrase;
      final keeper = VaultKeeper(host);
      await keeper.saveSeed(phrase, password,
          accountSpan: 1, derivedCount: 1, backedUp: false);

      expect(host.forgets, 1);
      expect(host.phrase, isNull);
      expect(keeper.holdsAccountKey, isFalse);
      expect(keeper.canArmQuickUnlock, isFalse);
      expect(keeper.vaults, hasLength(1),
          reason: 'the records stay; only what they open goes');
    });

    test('a password too short is refused before anything is stored',
        () async {
      expect(() => VaultKeeper.requireSealablePassword('short'),
          throwsException);
      await expectLater(
          VaultKeeper(_Host()..phrase = phrase).saveSeed(phrase, 'short',
              accountSpan: 1, derivedCount: 1, backedUp: false),
          throwsException);
      expect(await SecureStorage.getSeedVaults(), isNull);
    });
  });

  group('the password opens it, and nothing else does', () {
    test('the right one opens the phrase and hands it to the wallet', () async {
      final (keeper, host) = await opened();

      expect(host.openedOn.single, ('primary', phrase));
      expect(keeper.activeVaultId, 'primary');
      expect(keeper.holdsAccountKey, isTrue);
      expect(await keeper.verifyPassword(password), isTrue);
      expect(await keeper.verifyPassword('not the password'), isFalse);
    });

    test('a wrong one is WrongPassword, and the wallet is told nothing',
        () async {
      await sealed();
      final host = _Host();
      await expectLater(VaultKeeper(host).loadSeed('not the password'),
          throwsA(isA<WrongPassword>()));
      expect(host.openedOn, isEmpty);
    });
  });

  group('changing the password', () {
    test('re-wraps the vault key and never touches the phrase', () async {
      final (keeper, _) = await opened();
      final before = await storedVault();

      await keeper.changePassword(password, next);
      final after = await storedVault();

      expect(after.encryptedSeed, before.encryptedSeed,
          reason: 'the vault key is kept; only its wrapper changes');
      expect(after.salt, isNot(before.salt));
      await expectLater(VaultKeeper(_Host()).loadSeed(password),
          throwsA(isA<WrongPassword>()));
      expect(await VaultKeeper(_Host()).loadSeed(next), phrase);
    });

    test('a wrong current password is counted as one and writes nothing',
        () async {
      final (keeper, _) = await opened();
      final before = await SecureStorage.getSeedVaults();

      await expectLater(keeper.changePassword('not the password', next),
          throwsA(isA<WrongPassword>()));
      expect(await SecureStorage.getSeedVaults(), before);
    });

    test('the account key survives it, so imported keys still open', () async {
      final (keeper, _) = await opened();
      final imported = keeper.encryptWithAccountKey('imported keys');

      await keeper.changePassword(password, next);
      final again = VaultKeeper(_Host());
      await again.loadSeed(next);

      expect(again.decryptWithAccountKey(imported), 'imported keys');
    });
  });

  group('several phrases, one password', () {
    test('every phrase opens with it, and switching asks for nothing',
        () async {
      final (keeper, host) = await opened();
      final second = await keeper.addVault(otherPhrase, password);

      await keeper.switchVault(second.id);
      expect(host.switchedTo.single, (second.id, otherPhrase));

      // The next unlock opens on the wallet used last, and the other is a
      // switch away.
      final nextHost = _Host();
      final nextKeeper = VaultKeeper(nextHost);
      expect(await nextKeeper.loadSeed(password), otherPhrase);
      await nextKeeper.switchVault('primary');
      expect(nextHost.switchedTo.single, ('primary', phrase));
    });

    test('the same phrase twice is refused', () async {
      final (keeper, _) = await opened();
      await expectLater(keeper.addVault(phrase, password), throwsException);
      expect(keeper.vaults, hasLength(1));
    });

    test('removing the open one lands on another, and the last one stays',
        () async {
      final (keeper, host) = await opened();
      final second = await keeper.addVault(otherPhrase, password);

      await keeper.removeVault('primary');
      expect(keeper.vaults.map((v) => v.id), [second.id]);
      expect(host.switchedTo.single, (second.id, otherPhrase));

      await expectLater(keeper.removeVault(second.id), throwsException);
      expect(keeper.vaults, hasLength(1));
    });
  });

  group('the PIN', () {
    test('seals the two keys and never the phrase', () async {
      final (keeper, _) = await opened();
      expect(await keeper.armPinUnlock(pin), isTrue);
      expect(pinArmedAsObserved, isTrue);

      final plain = utf8.decode(
          await PinLock.open((await SecureStorage.getPinBlob())!, pin));
      final payload = jsonDecode(plain) as Map<String, dynamic>;
      expect(payload.keys.toSet(), {'vault', 'key', 'enc'});
      expect(payload['vault'], 'primary');
      expect(plain, isNot(contains('abandon')));
    });

    test('opens the same wallet the password opens, imported keys and all',
        () async {
      final (keeper, _) = await opened();
      final imported = keeper.encryptWithAccountKey('imported keys');
      await keeper.armPinUnlock(pin);

      final host = _Host();
      final byPin = VaultKeeper(host);
      expect(await byPin.unlockWithPin(pin), phrase);
      expect(host.openedOn.single, ('primary', phrase));
      expect(byPin.decryptWithAccountKey(imported), 'imported keys');
      await expectLater(VaultKeeper(_Host()).unlockWithPin('000000'),
          throwsA(isA<WrongPin>()));
    });

    test('opens one wallet, not every wallet', () async {
      final (keeper, _) = await opened();
      final second = await keeper.addVault(otherPhrase, password);
      await keeper.armPinUnlock(pin);

      final host = _Host();
      final byPin = VaultKeeper(host);
      await byPin.unlockWithPin(pin);

      await expectLater(
          byPin.switchVault(second.id), throwsA(isA<VaultLocked>()));
      await expectLater(byPin.openVaultWithPassword(second.id, 'nope'),
          throwsA(isA<WrongPassword>()));
      await byPin.openVaultWithPassword(second.id, password);
      expect(host.switchedTo.single, (second.id, otherPhrase));
    });

    test('disarmed, it opens nothing', () async {
      final (keeper, _) = await opened();
      await keeper.armPinUnlock(pin);

      await keeper.disarmPinUnlock();
      expect(await keeper.hasPin(), isFalse);
      expect(pinArmedAsObserved, isFalse);
      await expectLater(VaultKeeper(_Host()).unlockWithPin(pin),
          throwsA(isA<HardwareKeyUnavailable>()));
    });
  });

  group('a forgotten password, replaced by the PIN', () {
    test('is offered only when this device can finish the job', () async {
      final (keeper, host) = await opened();
      await keeper.addVault(otherPhrase, password);
      expect(await keeper.passwordRecoveryOffer(), PasswordRecoveryOffer.none,
          reason: 'no quick unlock to prove anything with');

      await keeper.armPinUnlock(pin);
      expect(await keeper.passwordRecoveryOffer(),
          PasswordRecoveryOffer.available);

      host.phraseAccount = false;
      expect(await keeper.passwordRecoveryOffer(), PasswordRecoveryOffer.none,
          reason: 'a watched or imported account is not the phrase');

      // After a PIN unlock only that wallet's phrase is open.
      final byPin = VaultKeeper(_Host());
      await byPin.unlockWithPin(pin);
      expect(await byPin.passwordRecoveryOffer(),
          PasswordRecoveryOffer.otherWalletsClosed);
    });

    test('is bound to the wallet the PIN opens', () async {
      final (keeper, _) = await opened();
      final second = await keeper.addVault(otherPhrase, password);
      await keeper.armPinUnlock(pin);

      await keeper.switchVault(second.id);
      await expectLater(
          keeper.resetPasswordWithPin(pin, next),
          throwsA(predicate((e) => '$e'.contains('different wallet'))),
          reason: 'six digits armed on one wallet must not reseal another');

      await keeper.switchVault('primary');
      await keeper.resetPasswordWithPin(pin, next);
      expect(await VaultKeeper(_Host()).loadSeed(next), phrase);
    });
  });

  group('a wallet with no password yet', () {
    test('is opened by the PIN until it is given one', () async {
      final host = _Host()..phrase = phrase;
      final keeper = VaultKeeper(host);
      await keeper.saveSeedWithoutPassword(phrase,
          accountSpan: 1, derivedCount: 1, backedUp: false);

      expect(keeper.hasPassword, isFalse);
      expect(await VaultKeeper.storedWalletHasPassword(), isFalse);
      expect(await keeper.armPinUnlock(pin), isTrue);

      await keeper.setPassword(password);
      expect(await VaultKeeper.storedWalletHasPassword(), isTrue);
      expect(await VaultKeeper(_Host()).loadSeed(password), phrase);
      expect(await VaultKeeper(_Host()).unlockWithPin(pin), phrase);
    });
  });

  group('records', () {
    test('a change to a record may not touch its seal', () async {
      final (keeper, _) = await opened();
      final before = await SecureStorage.getSeedVaults();

      await expectLater(
          keeper.updateVault('primary', (v) => v.copyWith(salt: 'AAAA')),
          throwsArgumentError);
      expect(await SecureStorage.getSeedVaults(), before);

      await keeper.updateVault('primary', (v) => v.copyWith(label: 'Savings'));
      expect((await storedVault()).label, 'Savings');
    });
  });

  group('locking', () {
    test('forgets every key, every phrase and which vaults exist', () async {
      final (keeper, host) = await opened();

      keeper.lock();

      expect(keeper.vaults, isEmpty);
      expect(keeper.activeVaultId, isNull);
      expect(keeper.holdsAccountKey, isFalse);
      expect(keeper.canArmQuickUnlock, isFalse);
      expect(host.forgets, 1);
      expect(await keeper.armPinUnlock(pin), isFalse,
          reason: 'nothing is held to seal');
    });
  });
}

/// A wallet that holds what it is told and records it.
class _Host implements VaultHost {
  String? phrase;
  bool phraseAccount = true;
  int forgets = 0;
  final List<(String, String)> openedOn = [];
  final List<(String, String)> switchedTo = [];

  @override
  Future<void> opened(SeedVault vault, String mnemonic) async {
    phrase = mnemonic;
    openedOn.add((vault.id, mnemonic));
  }

  @override
  Future<void> switched(SeedVault vault, String mnemonic) async {
    phrase = mnemonic;
    switchedTo.add((vault.id, mnemonic));
  }

  @override
  void forget() {
    phrase = null;
    forgets++;
  }

  @override
  bool get phraseOpen => phrase != null;

  @override
  bool get phraseAccountSelected => phraseAccount;
}
