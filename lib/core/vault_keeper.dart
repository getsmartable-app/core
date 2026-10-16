import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'crypto_utils.dart';
import 'hardware_key.dart';
import 'password_policy.dart';
import 'password_recovery.dart';
import 'pin_lock.dart';
import 'secure_storage.dart';
import 'seed_vault.dart';
import 'wallet_doors.dart';

final _secureRandom = Random.secure();

/// What a [VaultKeeper] needs from the wallet built on the phrase it opens.
///
/// **The keeper seals and opens phrases; it derives nothing.** Accounts,
/// addresses and signers belong to the wallet, and exist only while a phrase
/// is open — so the keeper says when one has been opened or switched to and
/// when its keys are dropped, and asks the two things about the wallet that
/// decide whether a password may be replaced. In the app this is
/// `WalletProvider`.
abstract interface class VaultHost {
  /// Builds the wallet on [mnemonic], the phrase of [vault], just opened by
  /// the password, the PIN or the device key. The account key is already held
  /// when this is called.
  Future<void> opened(SeedVault vault, String mnemonic);

  /// The same, for a switch to another phrase already open in this session.
  Future<void> switched(SeedVault vault, String mnemonic);

  /// Drops everything derived from the phrase, in the same breath as the
  /// keeper drops its keys.
  void forget();

  /// Whether a recovery phrase is open in the wallet at all — one opened here,
  /// or one being made or typed in that is not stored yet.
  bool get phraseOpen;

  /// Whether the selected account is one the open phrase derives: not a
  /// watched address, an imported key or a hardware account.
  bool get phraseAccountSelected;
}

/// The recovery phrases on this device: how each is sealed, and every door
/// that opens one.
///
/// **What keeps the wallet non-custodial, in one place.** A phrase is written
/// encrypted under a vault key of its own, random, which nobody ever types —
/// [_vaultKey] reads the older shape too, converted at the next password
/// change. The password wraps that key through [CryptoUtils.deriveKey]; the PIN
/// and the device key each seal a copy of it, together with the account key
/// that imported private keys are encrypted under. Nothing here reaches a
/// network: what is written goes to [SecureStorage], and what is opened is
/// handed to the wallet in memory and dropped with it.
///
/// Part of `WalletProvider` until 6 October 2026, and moved out without a
/// change in behaviour so that the published core could carry it: the files
/// that turn a password into a key and hold keys in the key store were
/// published, and the code that seals a phrase under them was not.
///
/// One wallet holds one keeper and builds its accounts on what the keeper
/// opens — see [VaultHost].
class VaultKeeper {
  VaultKeeper(this._host);

  final VaultHost _host;

  /// The key imported private keys are encrypted under, held while unlocked.
  ///
  /// **Random, and no longer derived from the password.** It used to be
  /// PBKDF2 of the password and the active vault's salt, which tied every
  /// imported account to a secret that changes: a password change replaced it,
  /// so the keys had to be re-encrypted in the same breath, and the PIN and
  /// device blobs — which carry this key — had to be thrown away. Wrapped like
  /// a vault key instead, a password change touches 32 bytes and nothing else
  /// notices.
  Uint8List? _encryptionKey;

  /// Every open vault's own key, by vault id.
  ///
  /// Kept because the wrapper can only be opened by the password that was
  /// typed, and the app needs the key itself afterwards — to hand to the PIN
  /// and the device store, and to re-wrap on a password change without
  /// touching a single phrase.
  ///
  /// It also fixes a real bug: arming quick unlock *after switching wallets*
  /// used to unwrap the new vault's key with the old vault's derived key,
  /// because those two are only ever the same before a switch. Salts are per
  /// vault, so that could never have worked.
  final Map<String, Uint8List> _vaultKeys = {};

  /// Whether the account key is held: from an unlock, or the saving of a new
  /// wallet, until the keys are dropped.
  bool get holdsAccountKey => _encryptionKey != null;

  /// Encrypts [plain] — the wallet's imported private keys — under the account
  /// key, for storage. Only while [holdsAccountKey].
  String encryptWithAccountKey(String plain) =>
      base64Encode(CryptoUtils.encrypt(plain, _encryptionKey!));

  /// Opens what [encryptWithAccountKey] wrote. Throws when the account key held
  /// is not the one it was written under.
  String decryptWithAccountKey(String sealed) =>
      CryptoUtils.decrypt(base64Decode(sealed), _encryptionKey!);

  /// Changes one stored vault's record and writes the list.
  ///
  /// For what the wallet keeps beside a sealed phrase: the account span and the
  /// hidden accounts, a name, whether the phrase was written down, its split
  /// backup. [change] answers null to leave the record as it is, and then
  /// nothing is written; an unknown or null [vaultId] changes nothing.
  ///
  /// **Never the seal.** How a phrase is encrypted, under which salt and
  /// wrapped key, and whether a password opens it are changed only by the
  /// methods that re-seal — [setPassword], [changePassword] and the resets by
  /// PIN or device key — and a change that touches any of them is refused
  /// before anything is written.
  Future<void> updateVault(
      String? vaultId, SeedVault? Function(SeedVault vault) change) async {
    if (vaultId == null) return;
    final i = _vaults.indexWhere((v) => v.id == vaultId);
    if (i < 0) return;
    final vault = _vaults[i];
    final changed = change(vault);
    if (changed == null) return;
    if (changed.encryptedSeed != vault.encryptedSeed ||
        changed.salt != vault.salt ||
        changed.wrappedKey != vault.wrappedKey ||
        changed.hasPassword != vault.hasPassword) {
      throw ArgumentError.value(
          vaultId, 'vaultId', 'A record change may not touch its seal');
    }
    _vaults[i] = changed;
    await _writeVaults();
  }

  /// The one rule every new password is held to — [saveSeed], [setPassword]
  /// and a change or reset ([_reseal]) — which is [PasswordPolicy]'s.
  ///
  /// Static so the wallet can ask it before it derives anything for the phrase
  /// being saved: a password refused changes nothing, not even the account
  /// list in memory. **One rule in one place**: until 11 October 2026 the
  /// three each wrote out "eight characters" for themselves.
  static void requireSealablePassword(String password) =>
      PasswordPolicy.require(password);

  /// Checks [password] against the stored wallet without unlocking it, by
  /// attempting to open a vault with it. Used to gate destructive actions.
  ///
  /// Asks the vault list first and the loose legacy pair only as a fallback.
  /// It used to ask only the loose pair, which stopped being equivalent the
  /// day a vault's phrase was sealed under its own random key instead of
  /// under the password: the check would have gone on succeeding against a
  /// copy that no longer opens anything.
  Future<bool> verifyPassword(String password) async {
    final stored = await _readVaults();
    if (stored.isNotEmpty) {
      final vault = stored.firstWhere((v) => v.id == _activeVaultId,
          orElse: () => stored.first);
      // Nothing to check against. Answering "yes" would let a screen gated on
      // this — export, remove wallet — open on a password nobody set.
      if (!vault.hasPassword) return false;
      try {
        final derived =
            await CryptoUtils.deriveKey(password, base64Decode(vault.salt));
        CryptoUtils.decrypt(
            base64Decode(vault.encryptedSeed), _vaultKey(vault, derived));
        return true;
      } catch (_) {
        return false;
      }
    }

    final encryptedBase64 = await SecureStorage.getEncryptedSeed();
    final saltBase64 = await SecureStorage.getSalt();
    if (encryptedBase64 == null || saltBase64 == null) return false;
    try {
      final key =
          await CryptoUtils.deriveKey(password, base64Decode(saltBase64));
      CryptoUtils.decrypt(base64Decode(encryptedBase64), key);
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Whether a password opens this wallet at all.
  ///
  /// False between creation and the first backup, export or send — see
  /// [SeedVault.hasPassword]. Every screen that offers the password has to ask
  /// this first, or it offers a way in that does not exist.
  bool get hasPassword =>
      _vaults.isEmpty || _vaults.every((v) => v.hasPassword);

  /// Whether the wallet on this device has a password, read from storage.
  ///
  /// The instance getter above answers for an *open* wallet and is no use to
  /// the unlock screen, which runs before anything is open. That screen has to
  /// know, because a wallet created behind a PIN has no password to offer and
  /// a button leading to a field that can never work is worse than no button.
  static Future<bool> storedWalletHasPassword() async {
    final stored = SeedVault.decode(await SecureStorage.getSeedVaults());
    if (stored.isEmpty) return true;
    final lastId = await SecureStorage.getActiveVaultId();
    final vault =
        stored.firstWhere((v) => v.id == lastId, orElse: () => stored.first);
    return vault.hasPassword;
  }

  /// Stores the phrase with **no password at all**, opened only by the PIN.
  ///
  /// The caller must arm a PIN immediately afterwards — see [armPinUnlock] —
  /// and must undo this if that fails, because between the two there is
  /// nothing on the device that can open the wallet. That ordering is why this
  /// is separate from [saveSeed] rather than a null argument to it: a
  /// half-finished passwordless wallet is a wallet whose only copy is the
  /// recovery phrase, and the create flow is the one place that can hold both
  /// halves and undo the first.
  ///
  /// The salt is written now even though nothing derives from it yet. It is
  /// what [setPassword] will wrap against, and generating it here keeps the
  /// stored shape identical whether a password ever arrives or not.
  ///
  /// [accountSpan] and [derivedCount] are the wallet's: one past the
  /// highest account index this phrase has allocated, and how many accounts
  /// it shows. [backedUp] is whether the phrase has been written down.
  Future<void> saveSeedWithoutPassword(
    String mnemonic, {
    required int accountSpan,
    required int derivedCount,
    required bool backedUp,
  }) async {
    final vaultKey = CryptoUtils.randomKey();
    final vault = SeedVault(
      id: 'primary',
      encryptedSeed: base64Encode(CryptoUtils.encrypt(mnemonic, vaultKey)),
      salt: base64Encode(
          List<int>.generate(16, (i) => _secureRandom.nextInt(256))),
      accountCount: max(1, accountSpan),
      backedUp: backedUp,
      hasPassword: false,
    );

    _vaults
      ..clear()
      ..add(vault);
    _vaultKeys
      ..clear()
      ..[vault.id] = vaultKey;
    _activeVaultId = vault.id;
    _encryptionKey ??= CryptoUtils.randomKey();

    await _writeVaults();
    // **Finish, then report.** `clearLegacySeed` throws when the keystore will
    // not confirm the deletion, and the wallet in front of it has already been
    // written correctly — failing the whole operation would answer a leftover
    // copy by leaving the person with no wallet at all. The same shape
    // `removeWalletFromDevice` uses, and for the same reason.
    Object? incomplete;
    try {
      await SecureStorage.clearLegacySeed();
    } on SecretStorageDeletionIncomplete catch (error) {
      incomplete = error;
    }
    await SecureStorage.saveAccountCount(derivedCount);
    if (incomplete != null) throw incomplete;
    // Deliberately *not* cleared here, unlike saveSeed: the caller still has to
    // arm the PIN, and that needs the keys this holds.
  }

  /// Undoes [saveSeedWithoutPassword] when the PIN could not be armed.
  ///
  /// Leaving the vault behind would leave a wallet nothing on the phone can
  /// open — and it would answer "yes" to `hasStoredWallet`, so the app would
  /// meet the person with an unlock screen instead of the create flow they
  /// were halfway through.
  Future<void> discardUnprotectedWallet() async {
    _vaults.clear();
    _vaultKeys.clear();
    _activeVaultId = null;
    await SecureStorage.saveSeedVaults('[]');
  }

  /// Gives a passwordless wallet its password, for the first time.
  ///
  /// Not [changePassword]: there is nothing to check against, nothing to
  /// re-encrypt, and nothing to invalidate. Every vault key is already in
  /// memory, so this wraps each one and writes the account key's record —
  /// which is the whole of what a password *is* in this design.
  Future<void> setPassword(String password) async {
    if (_vaults.isEmpty || _vaultKeys.isEmpty) {
      throw Exception('Unlock the wallet before setting a password.');
    }
    if (hasPassword) {
      throw Exception('This wallet already has a password.');
    }
    requireSealablePassword(password);

    final rebuilt = <SeedVault>[];
    for (final vault in _vaults) {
      final vaultKey = _vaultKeys[vault.id];
      if (vaultKey == null) {
        throw Exception(
            'One of your recovery phrases is not open. Nothing was changed.');
      }
      final salt = List<int>.generate(16, (i) => _secureRandom.nextInt(256));
      final derived = await CryptoUtils.deriveKey(password, salt);
      rebuilt.add(vault.copyWith(
        salt: base64Encode(salt),
        wrappedKey: CryptoUtils.wrapKey(vaultKey, derived),
        hasPassword: true,
      ));
    }

    _vaults
      ..clear()
      ..addAll(rebuilt);
    await _writeVaults();

    _encryptionKey ??= CryptoUtils.randomKey();
    // Every vault was just rebuilt under this password, so every vault gets a
    // copy and the record is rewritten whole.
    await _storeAccountKey(
        [for (final v in _vaults) v.id], password, _encryptionKey!,
        replace: true);
  }

  /// Seals [mnemonic] under [password] as this device's wallet, then drops
  /// the keys and the phrase from memory — the records stay; see
  /// [_clearSensitiveData].
  ///
  /// [accountSpan], [derivedCount] and [backedUp] are as in
  /// [saveSeedWithoutPassword].
  Future<void> saveSeed(
    String mnemonic,
    String password, {
    required int accountSpan,
    required int derivedCount,
    required bool backedUp,
  }) async {
    requireSealablePassword(password);
    final salt = List<int>.generate(16, (i) => _secureRandom.nextInt(256));
    final derived = await CryptoUtils.deriveKey(password, salt);
    // The phrase is sealed under a key that was never typed by anybody.
    final vaultKey = CryptoUtils.randomKey();
    final encryptedBase64 =
        base64Encode(CryptoUtils.encrypt(mnemonic, vaultKey));
    final saltBase64 = base64Encode(salt);

    final vault = SeedVault(
      id: 'primary',
      encryptedSeed: encryptedBase64,
      salt: saltBase64,
      wrappedKey: CryptoUtils.wrapKey(vaultKey, derived),
      accountCount: max(1, accountSpan),
      backedUp: backedUp,
    );
    _vaults
      ..clear()
      ..add(vault);
    _vaultKeys
      ..clear()
      ..[vault.id] = vaultKey;
    _activeVaultId = vault.id;
    await _writeVaults();

    // Its own random key for imported accounts, from the first moment, so this
    // wallet never has to be converted later. See _resolveAccountKey.
    _encryptionKey ??= CryptoUtils.randomKey();
    await _storeAccountKey([vault.id], password, _encryptionKey!,
        replace: true);

    // The loose legacy pair is deliberately *not* written for a wrapped
    // vault. It exists so a build predating vaults could still open the
    // wallet, and that build knows only one shape: a phrase encrypted under
    // the password. Keeping such a copy would mean the password-derived
    // envelope survives beside the wrapped one — the exact offline-guessable
    // copy this change exists to remove. Downgrading to an APK from before
    // vaults now means restoring from the recovery phrase, which is what the
    // phrase is for.
    // **Finish, then report.** `clearLegacySeed` throws when the keystore will
    // not confirm the deletion, and the wallet in front of it has already been
    // written correctly — failing the whole operation would answer a leftover
    // copy by leaving the person with no wallet at all. The same shape
    // `removeWalletFromDevice` uses, and for the same reason.
    Object? incomplete;
    try {
      await SecureStorage.clearLegacySeed();
    } on SecretStorageDeletionIncomplete catch (error) {
      incomplete = error;
    }
    await SecureStorage.saveAccountCount(derivedCount);
    _clearSensitiveData();
    if (incomplete != null) throw incomplete;
  }

  /// Every recovery phrase this wallet holds, newest last. Empty until unlock.
  final List<SeedVault> _vaults = [];

  List<SeedVault> get vaults => List.unmodifiable(_vaults);

  /// Which vault the current accounts were derived from.
  String? _activeVaultId;

  /// Decrypted phrases by vault id, held only while unlocked. Cleared with
  /// everything else in [_clearSensitiveData].
  final Map<String, String> _vaultMnemonics = {};

  String? get activeVaultId => _activeVaultId;

  SeedVault? get activeVault {
    final id = _activeVaultId;
    if (id == null) return null;
    for (final v in _vaults) {
      if (v.id == id) return v;
    }
    return null;
  }

  /// True when the stored vault record exists and this build could not read it.
  ///
  /// Held from the last [_readVaults] so the unlock path can say which of two
  /// things happened without reading the record a second time.
  bool _vaultRecordUnreadable = false;

  /// The stored entries the last [_readVaults] could not parse, written back
  /// unchanged by every [_writeVaults] — see [VaultRecord.unparsed]. Forgotten
  /// by [lock], which erasing the wallet goes through, so an erased record is
  /// never brought back.
  List<Object?> _unparsed = const [];

  /// Reads the stored vaults, converting a pre-multi-vault wallet on the way.
  ///
  /// Migration is additive and never destructive. The old `encrypted_seed` and
  /// `salt` keys are read and left exactly where they are: if a later version
  /// of this code has a bug, the original wallet is still sitting there in the
  /// format the previous build understands. Deleting them would buy tidiness
  /// with the one thing that must not be risked.
  ///
  /// The old global backup flag carries onto the migrated vault, so someone who
  /// wrote their phrase down is not asked again — and, more to the point, is
  /// not locked out of sending by a rule that just became per-vault.
  Future<List<SeedVault>> _readVaults() async {
    final record = SeedVault.read(await SecureStorage.getSeedVaults());
    _vaultRecordUnreadable = record.unreadable;
    _unparsed = record.unparsed;
    final stored = record.vaults;
    if (stored.isNotEmpty) return stored;

    final legacySeed = await SecureStorage.getEncryptedSeed();
    final legacySalt = await SecureStorage.getSalt();
    if (legacySeed == null || legacySalt == null) {
      // Entries stored and none of them readable is a record this build cannot
      // read — never "no wallet", which is a wallet to create over it.
      if (record.unparsed.isNotEmpty) _vaultRecordUnreadable = true;
      return const [];
    }
    // A legacy pair opens the wallet whatever the vault list said, so a record
    // that could not be read costs nothing here.
    _vaultRecordUnreadable = false;

    return [
      SeedVault(
        id: 'primary',
        encryptedSeed: legacySeed,
        salt: legacySalt,
        accountCount: max(1, await SecureStorage.getAccountCount() ?? 1),
        backedUp: await SecureStorage.getSeedBackedUp(),
      ),
    ];
  }

  Future<void> _writeVaults() async =>
      SecureStorage.saveSeedVaults(SeedVault.encode(_vaults, keep: _unparsed));

  /// Re-encrypts every stored phrase under a new password.
  ///
  /// The wallet must already be unlocked, so the phrases are in memory and no
  /// decryption is needed here — only re-encryption. [current] is still
  /// required and still checked, because "unlocked" can mean "someone else
  /// picked up the phone", and this is the operation that would lock the owner
  /// out of their own wallet.
  ///
  /// **Written in one go, deliberately.** Every vault is re-encrypted into a
  /// new list in memory and only then persisted, because `_writeVaults` stores
  /// the whole list as a single value. Re-encrypting them one at a time and
  /// saving after each would leave a wallet whose first phrase opens with the
  /// new password and whose second still wants the old one — half-openable,
  /// with no way for the person to know which half.
  ///
  /// Each vault gets a **fresh salt** rather than keeping its old one. Reusing
  /// it would mean the same phrase under two passwords shared a derivation
  /// input, which is the property salts exist to prevent.
  ///
  /// Throws before touching storage if [current] is wrong or [next] is too
  /// short, so a failed attempt changes nothing.
  ///
  /// **A wrong [current] throws [WrongPassword], which is what puts this door
  /// on the same counter as every other one.** It threw a plain `Exception`
  /// with a hand-written sentence until 17 September 2026 — refusing correctly
  /// and counting nothing, so an unlocked phone was an unlimited password
  /// search on the Change password screen. The screen runs the call through
  /// `revealWithSecret`, which reads the type.
  Future<void> changePassword(String current, String next) async {
    if (_vaults.isEmpty || _vaultMnemonics.isEmpty) {
      throw Exception('Unlock the wallet before changing its password.');
    }
    if (!await verifyPassword(current)) {
      throw const WrongPassword('That is not your current password.');
    }
    if (next == current) {
      throw Exception('That is already your password.');
    }
    await _reseal(next, legacyKeyFrom: current);
  }

  /// Re-seals every phrase under [next]. **Authorisation happens above this.**
  ///
  /// Split out when a second way in arrived: a password is the ordinary proof,
  /// and a freshly opened quick-unlock blob is the other one — see
  /// [resetPasswordWithPin]. Both end here, so there is one place that decides
  /// what re-sealing means and no chance of two of them drifting apart.
  ///
  /// [legacyKeyFrom] is the old password, and only a wallet written before
  /// imported keys were wrapped needs it: such a wallet's account key *is* the
  /// key derived from that password. Every wallet opened by a quick unlock has
  /// the account key already, because the sealed blob carries it — so the
  /// recovery path passes nothing and is refused outright if that turns out to
  /// be untrue, rather than writing a wallet whose imported accounts nothing
  /// can open.
  Future<void> _reseal(String next, {String? legacyKeyFrom}) async {
    requireSealablePassword(next);

    // Built entirely before anything is written.
    final rebuilt = <SeedVault>[];
    final rebuiltKeys = <String, Uint8List>{};
    for (final vault in _vaults) {
      final mnemonic = _vaultMnemonics[vault.id];
      if (mnemonic == null) {
        // A phrase that did not open under the old password cannot be
        // re-sealed under the new one, and writing the rest without it would
        // strand it permanently.
        throw Exception(
            'One of your recovery phrases could not be opened. Nothing was changed.');
      }
      final salt = List<int>.generate(16, (i) => _secureRandom.nextInt(256));
      final derived = await CryptoUtils.deriveKey(next, salt);

      // **The vault key is kept, not replaced.** This is what wrapping was for:
      // a password change re-wraps 32 bytes and never touches the phrase, which
      // is why the PIN and the device store — both of which hold this key —
      // keep working across it. Replacing it meant re-encrypting every phrase
      // and throwing both away.
      //
      // A vault written before wrapping has no key of its own, and converts
      // here: it is the one moment that costs nothing, because such a vault's
      // key *is* the old derived key and re-sealing it under a random one is a
      // single AES pass over a phrase already in memory.
      final existing = _vaultKeys[vault.id];
      final vaultKey = existing ?? CryptoUtils.randomKey();
      rebuiltKeys[vault.id] = vaultKey;
      rebuilt.add(vault.copyWith(
        encryptedSeed: existing != null
            ? vault.encryptedSeed
            : base64Encode(CryptoUtils.encrypt(mnemonic, vaultKey)),
        salt: base64Encode(salt),
        wrappedKey: CryptoUtils.wrapKey(vaultKey, derived),
      ));
    }

    _vaults
      ..clear()
      ..addAll(rebuilt);
    _vaultKeys
      ..clear()
      ..addAll(rebuiltKeys);
    await _writeVaults();

    // Every vault is wrapped after this, so the loose legacy pair can only be
    // a copy under the *old* password — an older build would open the wallet
    // with a password this one no longer accepts. It goes.
    //
    // **Finish, then report**, like every other removal of a leftover here:
    // the password has already been changed and the vaults rewritten, so
    // throwing now would leave somebody believing the change failed when it
    // did not. Both leftovers are attempted; the first refusal is raised at
    // the end.
    Object? incomplete;
    try {
      await SecureStorage.clearLegacySeed();
    } on SecretStorageDeletionIncomplete catch (error) {
      incomplete = error;
    }

    // **Imported private keys are not in any vault, and this is where they used
    // to die.** They were encrypted under the key derived from the password,
    // which this replaces, and the loader that fails to open them says nothing
    // by design so that one unreadable blob cannot block an unlock. Together
    // that made every imported account disappear at the next unlock, silently,
    // with no recovery phrase behind them to restore from.
    //
    // Now the key is random and only its *wrapper* is password-derived, so this
    // rewrites 32 bytes and the ciphertext is not touched at all. A wallet that
    // has no record yet converts here, taking the old derived key — which is
    // what its imported keys are actually encrypted under — as the key to wrap.
    if (_encryptionKey == null) {
      if (legacyKeyFrom == null) {
        // Unreachable from the quick-unlock path, which carries this key in
        // the blob it just opened — and a throw rather than a guess, because
        // the alternative is a wallet whose imported accounts silently stop
        // opening at the next unlock.
        throw Exception(
            'This wallet cannot be re-sealed without its password.');
      }
      _encryptionKey = await CryptoUtils.deriveKey(
          legacyKeyFrom, base64Decode(_vaults.first.salt));
    }
    await _storeAccountKey(
        [for (final v in _vaults) v.id], next, _encryptionKey!,
        replace: true);

    // Nothing else has to be dropped. The PIN and the device store hold the
    // vault key and the account key, and both survived this untouched — which
    // is the whole point of wrapping them rather than deriving them. Before
    // that, a password change silently disarmed both.
    // An older build kept the password itself behind the fingerprint. That copy
    // is the *old* password now — useless, and still readable. It goes.
    try {
      await SecureStorage.clearLegacyBiometricPassword();
    } on SecretStorageDeletionIncomplete catch (error) {
      incomplete ??= error;
    }

    if (incomplete != null) throw incomplete;
  }

  /// Whether a forgotten password can be replaced from here, and why not.
  ///
  /// **The dead end this exists to end.** A wallet with a password nobody
  /// remembers, opened by PIN or fingerprint, could neither change that
  /// password nor read its recovery phrase — both doors ask for the thing that
  /// was forgotten — so the person could watch their money and never write
  /// down the one thing that would survive the phone.
  ///
  /// The conditions are about this device holding enough to finish the job,
  /// not about who is asking:
  ///
  ///  * the wallet is open, so the phrases are in memory, and there is a
  ///    password to replace at all;
  ///  * the selected account is one this phrase derives. A watched address, an
  ///    imported key and a hardware account are not the phrase, and re-sealing
  ///    it from one of them is an act aimed at something else;
  ///  * a quick unlock exists to be proved;
  ///  * and **every** phrase is open, because one password covers all of them.
  ///    Re-sealing the list while another is closed would seal it around a
  ///    phrase nothing could open again — so that case is
  ///    [PasswordRecoveryOffer.otherWalletsClosed] rather than a silent no, and
  ///    the screen says which way through it is.
  ///
  /// This answers whether to *offer* the way out. Whether it is really this
  /// wallet's door is settled by opening the blob — see [resetPasswordWithPin].
  Future<PasswordRecoveryOffer> passwordRecoveryOffer() async {
    if (_vaults.isEmpty || !_host.phraseOpen || _activeVaultId == null) {
      return PasswordRecoveryOffer.none;
    }
    if (!hasPassword) return PasswordRecoveryOffer.none;
    if (!_host.phraseAccountSelected) return PasswordRecoveryOffer.none;
    if (_encryptionKey == null) return PasswordRecoveryOffer.none;
    if (!await hasPin() && !await hasDeviceUnlock()) {
      return PasswordRecoveryOffer.none;
    }
    if (_vaults.any((v) => _vaultMnemonics[v.id] == null)) {
      return PasswordRecoveryOffer.otherWalletsClosed;
    }
    return PasswordRecoveryOffer.available;
  }

  /// Replaces the password, authorised by six digits that open **this** wallet.
  ///
  /// **The authorisation is the decryption, not a flag.** A wrong PIN cannot
  /// open the sealed blob at all, and a blob sealed for another wallet names
  /// that wallet inside itself — so neither a mistyped PIN nor another
  /// wallet's door can reach this, and no caller can assert its way past by
  /// passing a boolean. That is the same rule [_openFromPayload] already
  /// relies on to decide which vault a quick unlock opens.
  ///
  /// Throws [WrongPin] for a wrong PIN, [HardwareKeyUnavailable] when no PIN is
  /// armed, and refuses in this wallet's own words when the blob turns out to
  /// belong to a different one. Nothing is written on any of those paths.
  Future<void> resetPasswordWithPin(String pin, String next) async {
    final stored = await SecureStorage.getPinBlob();
    if (stored == null || stored.isEmpty) {
      throw const HardwareKeyUnavailable();
    }
    final plain = await PinLock.open(stored, pin);
    await _resetWithQuickUnlock(utf8.decode(plain), next);
  }

  /// The same, proved by the device key instead. See [resetPasswordWithPin].
  ///
  /// The prompt is the freshness: unwrapping is a per-use operation and shows
  /// the system's own biometric dialog, so an open session is not the proof —
  /// the person in front of the phone is.
  Future<void> resetPasswordWithDeviceKey(String next) async {
    final stored = await SecureStorage.getDeviceKeyBlob();
    if (stored == null || stored.isEmpty) {
      throw const HardwareKeyUnavailable();
    }
    final plain = await HardwareKey.unwrap(base64Decode(stored));
    await _resetWithQuickUnlock(utf8.decode(plain), next);
  }

  /// Checks that the blob just opened belongs to the wallet in front of the
  /// person, then re-seals.
  ///
  /// **The binding check is the whole security of this path.** Without it, six
  /// digits armed on one wallet would set the password of whichever wallet
  /// happened to be active — and since one password covers every phrase, that
  /// is every wallet on the device.
  Future<void> _resetWithQuickUnlock(String json, String next) async {
    final payload = jsonDecode(json) as Map<String, dynamic>;
    if (payload['vault'] != _activeVaultId) {
      throw Exception('That quick unlock opens a different wallet.');
    }
    if (await passwordRecoveryOffer() != PasswordRecoveryOffer.available) {
      throw Exception(
          'This wallet cannot be re-sealed from here. Open every wallet with '
          'its password first.');
    }
    await _reseal(next);
  }

  /// Adds an existing recovery phrase alongside the ones already held.
  ///
  /// [normalised] arrives checked. The wallet in front of this keeper
  /// normalises the words and holds them to BIP-39, refuses a name another
  /// wallet carries and refuses on a modified phone, all before calling
  /// this — see `WalletProvider.addVault`.
  ///
  /// Encrypted under the same password as the rest — one password opens the
  /// wallet, several phrases live inside it, which is how MetaMask and Trust
  /// Wallet both work. A password per phrase would mean a wallet that can be
  /// half-open, and a user who has to remember which one they are typing.
  ///
  /// Its own salt, never the active vault's: that is what stops two phrases
  /// under one password from deriving the same key.
  ///
  /// [backedUp] defaults to true because a phrase typed in from somewhere else
  /// is, by definition, written down already — the nag exists for a phrase this
  /// app generated and the user has never seen.
  ///
  /// [isAgentVault] marks the phrase as an Agent Wallet, kept for showing an
  /// AI and connected to nothing. **False is the Primary Wallet and false is
  /// the default**; see `SeedVault.isAgentVault` for why the two misreadings
  /// are not equally bad. It can only be set here, at creation: a vault is an Agent
  /// Wallet from birth or never, and `copyWith` deliberately offers no way to
  /// move it — the conversion worth worrying about is the one that promotes the
  /// Primary Wallet.
  ///
  /// [splitBackupId] names the split backup [mnemonic] was just rebuilt from,
  /// when it was. **Only then** — the same rule as
  /// `WalletProvider.linkSplitBackup`: a backup
  /// proven by reconstruction, never one merely lying in a cloud. A wallet
  /// added from shares was left with no link at all, so its status screen
  /// could not say which backup was its own.
  Future<SeedVault> addVault(
    String normalised,
    String password, {
    String? label,
    bool backedUp = true,
    bool isAgentVault = false,
    String? splitBackupId,
  }) async {
    if (_vaultMnemonics.values.contains(normalised)) {
      // Silently adding a duplicate produces two wallets showing the same
      // balance, which reads as the money having doubled.
      throw Exception('This recovery phrase is already in this wallet.');
    }
    // **The Agent Wallet cap, here rather than in a screen.** The limit of one
    // that stood until now was not a decision: it was a `firstOrNull` in
    // `_openAgentWallet` that opened the existing wallet instead of making a
    // second, and nothing anywhere refused one. A product rule enforced by a
    // branch in one call site is a rule the next call site does not have.
    if (isAgentVault &&
        _vaults.where((v) => v.isAgentVault).length >=
            SeedVault.agentWalletLimit) {
      throw Exception(
          'This device already has ${SeedVault.agentWalletLimit} Agent '
          'Wallets. Remove one before making another.');
    }

    final salt = List<int>.generate(16, (i) => _secureRandom.nextInt(256));
    final derived = await CryptoUtils.deriveKey(password, salt);
    final vaultKey = CryptoUtils.randomKey();
    final vault = SeedVault(
      // Time-based rather than positional, so deleting one never makes a later
      // id collide with an earlier account's reference to it.
      id: 'vault-${DateTime.now().microsecondsSinceEpoch}',
      encryptedSeed: base64Encode(CryptoUtils.encrypt(normalised, vaultKey)),
      salt: base64Encode(salt),
      wrappedKey: CryptoUtils.wrapKey(vaultKey, derived),
      backedUp: backedUp,
      label: label,
      isAgentVault: isAgentVault,
      splitBackupId: splitBackupId,
    );

    _vaults.add(vault);
    _vaultKeys[vault.id] = vaultKey;
    _vaultMnemonics[vault.id] = normalised;
    try {
      await _writeVaults();
    } catch (_) {
      // **A vault that was not written is not a vault.** Left in memory it is
      // a wallet somebody can fund for one session and never see again — and
      // the phrase behind it was shown once, on a screen that is now closed.
      // Rolling back makes the failure the caller is told about the whole
      // truth rather than half of it.
      _vaults.remove(vault);
      _vaultKeys.remove(vault.id);
      _vaultMnemonics.remove(vault.id);
      rethrow;
    }

    // **A copy of the account key this wallet can open, and without it the new
    // wallet destroys the old one's imported keys.**
    //
    // `imported_keys` is one blob for the whole device, wrapped by the account
    // key. The record holding that key used to carry a single copy under a
    // single password — so adding a wallet under its *own* password produced a
    // session that could not unwrap it, fell back to a key that opens nothing,
    // loaded no imported accounts, and then rewrote the blob from that empty
    // list. The keys a recovery phrase cannot restore were the keys being lost,
    // and nothing on any screen said so.
    //
    // After this the new password opens the same account key as every other,
    // which is what makes the imported accounts simply *be there*. The refusal
    // in `WalletProvider._persistImportedKeys` stays as the backstop for the
    // wallets already written without an entry.
    final accountKey = _encryptionKey;
    if (accountKey != null) {
      await _storeAccountKey([vault.id], password, accountKey);
    }
    return vault;
  }

  /// Whether [vaultId] can be opened with a password at all.
  ///
  /// **The question that decides whether a quick unlock may be moved off it.**
  /// A wallet created by the current flow has a PIN and no password until its
  /// first backup or export, so taking its PIN away and giving it to another
  /// wallet would leave it with no door at all — recoverable only by importing
  /// the phrase again. [hasPassword] answers for the whole list and cannot see
  /// that; this answers for one.
  bool vaultHasPassword(String vaultId) =>
      _vaults.any((v) => v.id == vaultId && v.hasPassword);

  /// Removes one recovery phrase from this device, leaving the others alone.
  ///
  /// **"Remove wallet" used to remove every wallet**, which is a different act
  /// wearing the same words: somebody with two phrases who wanted to drop the
  /// second lost the first as well, and the dialog's own sentence — "including
  /// your list of accounts" — read as though it were describing the one on
  /// screen. Erasing the device is still available and still needed; it is
  /// `removeWalletFromDevice`, reached by its own row and its own wording.
  ///
  /// **The last one is refused here rather than falling through to an erase.**
  /// Removing the only wallet leaves a device with vault records for nothing,
  /// the PIN blob still armed, and `hasStoredWallet` answering yes — the exact
  /// shape of the defect this project shipped once, where the screen said the
  /// wallet was gone and the PIN went on opening it. That case has to be the
  /// full erasure, and making the caller ask for it by name is what stops the
  /// two being confused again.
  ///
  /// **Nothing is touched until there is somewhere to land.** If the phrase
  /// being removed is the active one and the survivor has not been opened,
  /// this throws [VaultLocked] *before* any mutation, so the screen can ask
  /// for the password and try again. Removing first and switching afterwards
  /// would leave a wallet with no active vault and the removed one's accounts
  /// still on screen if the person dismissed that prompt.
  ///
  /// **The PIN and quick unlock are switched off, every time.** Both seal a
  /// payload naming *one* vault, and neither can be read back without the
  /// secret that opens it — so there is no way to ask whether the blob points
  /// at the phrase being removed. Left in place when it does, the PIN opens
  /// onto a vault that is gone: [_openFromPayload] falls back to the first
  /// stored vault and decrypts it with the wrong key, which surfaces as a
  /// wallet that will not open rather than as a door that was dropped. Every
  /// wallet holding more than one phrase has a password by construction —
  /// [addVault] requires one — so switching these off always leaves a way in.
  Future<void> removeVault(String vaultId) async {
    if (_vaults.length <= 1) {
      throw Exception(
          'This is the only wallet on this device. Use "Remove all wallets" '
          'to erase it.');
    }
    final i = _vaults.indexWhere((v) => v.id == vaultId);
    if (i < 0) throw Exception('No such recovery phrase in this wallet.');

    final wasActive = _activeVaultId == vaultId;
    final next = _vaults.firstWhere((v) => v.id != vaultId);
    if (wasActive && _vaultMnemonics[next.id] == null) {
      throw VaultLocked(next.id);
    }

    // **Only the doors that opened *this* wallet.**
    //
    // An unlock payload names one vault: the key it carries opens that phrase
    // and no other. Removing a different phrase leaves it perfectly valid — so
    // switching it off is not caution, it is taking away a working PIN and
    // fingerprint because something unrelated was deleted. Reported 22 August
    // 2026: a second wallet was created, left empty, removed, and the first
    // wallet then asked for a password with both PIN and biometrics found
    // switched off in Settings. Nothing warned that this was the cause, which
    // is what makes it read as the app having lost them.
    //
    // The blob cannot be asked which vault it holds — it is sealed under six
    // digits or the secure element — so the id is recorded beside it when it is
    // armed. See [SecureStorage.savePinVaultId].
    //
    // **Doors before records**, where a door is actually being closed. A
    // process that dies between these two leaves a wallet with its PIN
    // switched off and every phrase intact, which the password recovers. The
    // other order leaves a PIN armed for a vault that no longer exists, which
    // nothing recovers.
    if (await pinOpensVault(vaultId)) await disarmPinUnlock();
    if (await deviceOpensVault(vaultId)) {
      await disarmDeviceUnlock();
      await SecureStorage.clearBiometricPassword();
    }

    _vaults.removeAt(i);
    _vaultKeys.remove(vaultId);
    _vaultMnemonics.remove(vaultId);
    await _writeVaults();

    if (wasActive) {
      _activeVaultId = null;
      await switchVault(next.id);
    }
  }

  /// Switches the wallet onto another stored phrase, one already open in
  /// this session, and has the wallet rebuilt on it — see
  /// [VaultHost.switched].
  ///
  /// Throws [VaultLocked] for a phrase that is stored and not open; the way
  /// through is [openVaultWithPassword].
  Future<void> switchVault(String vaultId) async {
    if (vaultId == _activeVaultId) return;
    final vault = _vaults.firstWhere(
      (v) => v.id == vaultId,
      orElse: () => throw Exception('No such recovery phrase in this wallet.'),
    );
    final mnemonic = _vaultMnemonics[vaultId];
    if (mnemonic == null) {
      // **A type, because the wallet is fine and the sentence said it was
      // not.** Reported 18 August 2026: a phrase imported perfectly well, and
      // tapping it answered *"That recovery phrase could not be opened."* —
      // which reads as a lost wallet and is the most alarming thing this app
      // can say. It was true only in the narrowest sense: a PIN or device-key
      // unlock assembles one vault's key and no other, so every *other* stored
      // phrase is sealed and unread until the password is given.
      //
      // Nothing was wrong with the phrase, nothing was lost, and there was no
      // way forward from that message. [VaultLocked] lets the screen ask for
      // the password and open it — see [openVaultWithPassword].
      throw VaultLocked(vaultId);
    }

    _activeVaultId = vault.id;
    await SecureStorage.saveActiveVaultId(vault.id);
    await _host.switched(vault, mnemonic);
  }

  /// Opens one stored phrase with the password, then switches onto it.
  ///
  /// **The way out of [VaultLocked].** A PIN unlock holds the key to the vault
  /// it was armed for and to no other, which is correct — six digits should
  /// not open every phrase on the device — but it left the other wallets
  /// reachable only by locking and unlocking with the password, which nothing
  /// on screen said.
  ///
  /// **It opens the one vault asked for, not all of them.** Widening it to
  /// every phrase would quietly turn one password prompt into unlocking the
  /// lot, which is a bigger act than the person is performing.
  Future<void> openVaultWithPassword(String vaultId, String password) async {
    final vault = _vaults.firstWhere(
      (v) => v.id == vaultId,
      orElse: () => throw Exception('No such recovery phrase in this wallet.'),
    );

    final String mnemonic;
    final Uint8List key;
    try {
      final derived =
          await CryptoUtils.deriveKey(password, base64Decode(vault.salt));
      key = _vaultKey(vault, derived);
      mnemonic = CryptoUtils.decrypt(base64Decode(vault.encryptedSeed), key);
    } catch (_) {
      // **The password, not the phrase.** Saying anything about the phrase
      // here is the defect this whole change exists to fix.
      throw const WrongPassword();
    }

    _vaultKeys[vaultId] = key;
    _vaultMnemonics[vaultId] = mnemonic;
    await switchVault(vaultId);
  }

  /// The key a vault's phrase is actually encrypted with.
  ///
  /// Two shapes, and both are current. A vault written since key wrapping
  /// carries its own random key, sealed under the password — that one is
  /// unwrapped here. A vault written before it has no wrapped key, and for it
  /// the derived key *is* the vault key, exactly as it always was. Nothing is
  /// migrated on unlock: a wallet is the wrong place to rewrite storage
  /// nobody asked to have rewritten, and the two shapes cost the same to
  /// read. They converge the next time the password changes, which rewrites
  /// every vault anyway.
  static Uint8List _vaultKey(SeedVault vault, Uint8List derivedKey) {
    final wrapped = vault.wrappedKey;
    if (wrapped == null) return derivedKey;
    return CryptoUtils.unwrapKey(wrapped, derivedKey);
  }

  /// Opens the wallet with [password]: every vault it opens goes into memory.
  ///
  /// **A refusal changes nothing in memory.** This is also the password check
  /// of an open wallet — revealing the phrase, making a split backup, creating
  /// an agent wallet, adding a wallet — and it used to empty the phrases and
  /// keys before it knew whether the password opened anything. One typo there
  /// left the wallet on screen with nothing behind it, and Change password
  /// answered "Unlock the wallet before changing its password" to somebody
  /// looking at their open wallet (the owner's device report of 14 October
  /// 2026). Everything is read and opened into locals; the fields are written
  /// only once the vault being opened has opened.
  Future<String> loadSeed(String password) async {
    final stored = await _readVaults();
    if (stored.isEmpty) {
      // **Two different sentences, and they were one.** A device with no
      // wallet and a device whose vault record will not parse both arrived
      // here with an empty list, and both were told there was no stored seed —
      // which on the second is a wallet saying somebody's phrase is gone when
      // it is merely unreadable, and points them at creating a new one over
      // the top of it.
      if (_vaultRecordUnreadable) throw const VaultRecordUnreadable();
      throw Exception('No stored seed');
    }
    // Whichever was open last, falling back to the first. The others are
    // available to switch to without asking for the password again, since they
    // are all encrypted under it.
    //
    // The stored id is checked against what actually exists: a wallet removed
    // on another install, or a storage entry that outlived its vault, must not
    // leave the app unable to open at all.
    final lastId = await SecureStorage.getActiveVaultId();
    final vault = stored.firstWhere(
      (v) => v.id == lastId,
      orElse: () => stored.first,
    );

    // Said plainly rather than left to fail as a wrong password. A wallet
    // created since the PIN has no password yet, and "wrong password" to
    // somebody who never set one sends them to the recovery flow for a
    // problem they do not have.
    if (!vault.hasPassword) {
      throw Exception('This wallet has no password yet. Unlock it with your '
          'PIN, and set a password when it asks.');
    }

    // Every vault is opened here, not just the active one, so switching later
    // costs nothing and never asks for the password again.
    //
    // In parallel on purpose: the key derivation is 600k PBKDF2 rounds, and
    // running three of them one after another would triple the wait on the one
    // screen where the user is already typing a password and waiting.
    //
    // The exposure is worth naming: an unlocked wallet now holds every phrase
    // in memory rather than one. That is a difference of degree — it already
    // held a phrase, and _clearSensitiveData drops all of them together — and
    // the alternative is either keeping the password around, which is worse,
    // or asking for it on every switch, which teaches people to type it often.
    final opened = await Future.wait(stored.map((v) async {
      try {
        final derived =
            await CryptoUtils.deriveKey(password, base64Decode(v.salt));
        final key = _vaultKey(v, derived);
        return MapEntry(v.id,
            (CryptoUtils.decrypt(base64Decode(v.encryptedSeed), key), key));
      } catch (_) {
        // One vault written under a different password, or corrupt, must not
        // stop the others opening. It simply cannot be switched to.
        return MapEntry(v.id, null);
      }
    }));

    final mnemonic = opened.firstWhere((e) => e.key == vault.id).value?.$1;
    if (mnemonic == null) {
      // The first vault failing is a wrong password, which is what the caller
      // and the unlock screen expect to hear.
      throw const WrongPassword();
    }

    _vaults
      ..clear()
      ..addAll(stored);
    _activeVaultId = vault.id;
    _vaultKeys
      ..clear()
      ..addEntries(opened
          .where((e) => e.value != null)
          .map((e) => MapEntry(e.key, e.value!.$2)));
    _vaultMnemonics
      ..clear()
      ..addEntries(opened
          .where((e) => e.value != null)
          .map((e) => MapEntry(e.key, e.value!.$1)));

    final derived =
        await CryptoUtils.deriveKey(password, base64Decode(vault.salt));
    await _openWith(
      vault: vault,
      mnemonic: mnemonic,
      encryptionKey: await _resolveAccountKey(vault.id, password, derived),
    );
    return mnemonic;
  }

  /// The key imported private keys sit under, whichever shape this wallet is in.
  ///
  /// Three now, and all three are current.
  ///
  /// * **A copy per vault** — `{"vaults": {"vault-1": {salt, key}, …}}`, each
  ///   entry the one device-wide account key wrapped under PBKDF2 of *that
  ///   vault's* password. This is what a wallet written since 14 September
  ///   2026 carries.
  /// * **One flat `{salt, key}`** — every wallet written before it. Read here
  ///   unchanged and converted on the next password change, for the same
  ///   reason a pre-wrapping vault is not migrated on unlock: a wallet is the
  ///   wrong place to rewrite storage nobody asked to have rewritten.
  /// * **No record at all** — older still, and for it the password-derived key
  ///   *is* the account key, exactly as it always was.
  ///
  /// **The per-vault copy is the correction, and it was a real loss.** The
  /// record held one salt wrapped under one password, while `imported_keys` is
  /// a single blob for the whole device. So a second wallet added under its own
  /// password could not unwrap the record, fell through to the line below, and
  /// got a key that opens nothing — every imported account vanished from the
  /// list, and the next write rewrote the blob without them. The accounts a
  /// recovery phrase cannot restore were the accounts being destroyed.
  ///
  /// Wrapping a copy per vault costs 32 bytes each and needs no new password
  /// handling: whichever wallet is opened, with whatever password, the key that
  /// comes back is the same one.
  Future<Uint8List> _resolveAccountKey(
      String vaultId, String password, Uint8List derived) async {
    final stored = await SecureStorage.getAccountKeyRecord();
    if (stored == null || stored.isEmpty) return derived;

    Future<Uint8List?> open(Object? entry) async {
      if (entry is! Map) return null;
      final salt = entry['salt'];
      final key = entry['key'];
      if (salt is! String || key is! String) return null;
      try {
        final wrapping =
            await CryptoUtils.deriveKey(password, base64Decode(salt));
        return CryptoUtils.unwrapKey(key, wrapping);
      } catch (_) {
        return null;
      }
    }

    try {
      final record = jsonDecode(stored) as Map<String, dynamic>;
      final perVault = record['vaults'];
      if (perVault is Map) {
        // **This vault's own copy, and no other's.** The entries are wrapped
        // under different passwords; trying them all would be a password guess
        // against our own storage, and succeeding would mean two wallets share
        // a password, which tells us nothing worth having.
        if (await open(perVault[vaultId]) case final key?) return key;
      }
      if (await open(record) case final key?) return key;
    } catch (_) {
      // A record that will not parse is the same answer as no record: the
      // phrase still opens, which is what an unlock must not lose.
    }

    // Unreadable under this password. Falling back to the derived key keeps the
    // phrase openable — the imported accounts go missing, and the wallet's
    // `importedKeysUnreadable` is what says so. What no longer happens is the
    // write that made the loss permanent; see the wallet's
    // `_persistImportedKeys`.
    return derived;
  }

  /// Writes [accountKey] wrapped under [password], one copy per vault in
  /// [vaultIds].
  ///
  /// **[replace] is the difference between the two kinds of caller, and it is
  /// not a tidiness flag.**
  ///
  /// `setPassword` and `changePassword` rebuild *every* vault under the new
  /// password, so after them one password opens the whole device: they pass
  /// every vault id and `replace: true`, and the record is rewritten whole.
  /// That is also what prunes entries belonging to wallets that have since been
  /// removed.
  ///
  /// `addVault` is the opposite case — one new wallet under a password of its
  /// own, beside wallets whose passwords this call does not have. It merges,
  /// and **keeps any flat legacy record it finds**: that record is the only
  /// thing standing between the wallets already on this device and their
  /// imported keys, and dropping it while writing an entry for the newcomer
  /// would lock out exactly the accounts this whole shape exists to protect.
  static Future<void> _storeAccountKey(
    Iterable<String> vaultIds,
    String password,
    Uint8List accountKey, {
    bool replace = false,
  }) async {
    final out = <String, dynamic>{};
    final vaults = <String, dynamic>{};

    if (!replace) {
      final stored = await SecureStorage.getAccountKeyRecord();
      if (stored != null && stored.isNotEmpty) {
        try {
          final record = jsonDecode(stored);
          if (record is Map) {
            if (record['vaults'] is Map) {
              vaults.addAll((record['vaults'] as Map).cast<String, dynamic>());
            }
            // The flat shape, carried forward verbatim. See above.
            if (record['salt'] is String && record['key'] is String) {
              out['salt'] = record['salt'];
              out['key'] = record['key'];
            }
          }
        } catch (_) {
          // An unparseable record opens nothing. Carrying it forward would
          // leave the flat branch of [_resolveAccountKey] reading rubbish for
          // ever, so it is the one thing not preserved.
        }
      }
    }

    // One salt per vault rather than one for the batch: a shared salt would
    // make two entries the same PBKDF2 work, and the cost of another is a few
    // hundred milliseconds on a screen nobody is waiting on twice.
    for (final id in vaultIds) {
      final salt = List<int>.generate(16, (_) => _secureRandom.nextInt(256));
      final wrapping = await CryptoUtils.deriveKey(password, salt);
      vaults[id] = {
        'salt': base64Encode(salt),
        'key': CryptoUtils.wrapKey(accountKey, wrapping),
      };
    }

    out['vaults'] = vaults;
    await SecureStorage.saveAccountKeyRecord(jsonEncode(out));
  }

  /// Holds the account key, then has the wallet built on the phrase just
  /// opened — see [VaultHost.opened].
  ///
  /// Shared by the password path and the device-key path below, which is the
  /// point: two ways in that assemble the wallet differently would be two
  /// wallets, and the difference would show up as an account missing from one
  /// of them rather than as an error.
  Future<void> _openWith({
    required SeedVault vault,
    required String mnemonic,
    required Uint8List encryptionKey,
  }) async {
    _encryptionKey = encryptionKey;
    await _host.opened(vault, mnemonic);
  }

  /// Hands the device key a copy of what this unlock is holding.
  ///
  /// Two keys go in, not one: the vault key that opens the phrase, and the
  /// key the imported private keys are encrypted under. Wrapping only the
  /// first would give a device unlock that opens the wallet and silently
  /// leaves every imported account behind — a wallet that shows less money
  /// depending on how you came in.
  ///
  /// Best effort by construction. A device that cannot hold a key is a normal
  /// device, and the wallet must not refuse to unlock over it.
  Future<bool> armDeviceUnlock() async {
    final payload = _unlockPayload();
    if (payload == null) return false;

    try {
      final wrapped =
          await HardwareKey.wrap(Uint8List.fromList(utf8.encode(payload)));
      await SecureStorage.saveDeviceKeyBlob(base64Encode(wrapped));
      // Which wallet this opens, in the clear beside it — see
      // [SecureStorage.saveDeviceVaultId]. The blob itself names the vault and
      // cannot be asked without the person present.
      await SecureStorage.saveDeviceVaultId(_activeVaultId);
      return true;
    } on HardwareKeyDeclined {
      // **Not the same answer as "this phone cannot", so not the same value.**
      // Sealing is a per-use operation now: it shows the prompt itself, and a
      // person who cancels it lands here. Collapsed into `false` that reads as
      // a phone that will not hold a key, and every caller answers a phone
      // like that by putting the switch back off — so one press of Cancel
      // turned quick unlock off for good. The callers tell the two apart.
      rethrow;
    } on HardwareKeyException {
      return false;
    } on SecretStorageUnavailable {
      // **A failed arm, not a crash.** Quick unlock is an offer; a device that
      // will not store the blob simply does not get it, and the password still
      // opens the wallet. The caller already draws "not enabled" for false.
      return false;
    }
  }

  /// The same, sealed under six digits instead of the system gate.
  ///
  /// Shares [_unlockPayload] with the hardware path deliberately: two ways in
  /// that assemble different payloads would be two wallets, and the difference
  /// would surface as an account missing from one of them rather than as an
  /// error. See [PinLock] for why six digits are enough here and would not be
  /// on their own.
  Future<bool> armPinUnlock(String pin) async {
    final payload = _unlockPayload();
    if (payload == null) return false;

    try {
      final sealed =
          await PinLock.seal(Uint8List.fromList(utf8.encode(payload)), pin);
      await SecureStorage.savePinBlob(sealed);
      await SecureStorage.savePinVaultId(_activeVaultId);
      // The other half of [disarmPinUnlock]'s line: the sheet may offer a PIN
      // from the moment there is one.
      pinArmedAsObserved = true;
      return true;
    } on HardwareKeyException {
      return false;
    } on SecretStorageUnavailable {
      return false;
    }
  }

  /// What an unlock needs, as bytes: which wallet, the key that opens its
  /// phrase, and the key its imported private keys sit under.
  ///
  /// Null when the wallet is not open, which is the only state this cannot be
  /// built from — it exists to be captured at the one moment the app holds
  /// these in the clear.
  String? _unlockPayload() {
    final vaultId = _activeVaultId;
    final encryptionKey = _encryptionKey;
    if (vaultId == null || !_host.phraseOpen || encryptionKey == null) {
      return null;
    }
    // Only the id and the two keys go into the payload — the vault record
    // itself is read back from storage at unlock, so looking it up here was
    // dead weight, and its `orElse: _vaults.first` would have thrown on an
    // empty list for a value nothing read.
    final vaultKey = _vaultKeys[vaultId];
    if (vaultKey == null) return null;

    return jsonEncode({
      'vault': vaultId,
      'key': base64Encode(vaultKey),
      'enc': base64Encode(encryptionKey),
    });
  }

  /// Opens the wallet with the key the phone is holding, no password typed.
  ///
  /// Throws [HardwareKeyNeedsAuth] when the person has to prove who they are
  /// first, and [HardwareKeyGone] when the key has been invalidated — a new
  /// fingerprint, a removed lock screen, a restored backup. Both are ordinary
  /// and neither means the wallet is lost: the password opens it and arms this
  /// again.
  Future<String> unlockWithDeviceKey() async {
    final stored = await SecureStorage.getDeviceKeyBlob();
    if (stored == null || stored.isEmpty) {
      throw const HardwareKeyUnavailable();
    }

    final plain = await HardwareKey.unwrap(base64Decode(stored));
    return _openFromPayload(utf8.decode(plain));
  }

  /// Opens the wallet with six digits, no password and no system gate.
  ///
  /// Throws [WrongPin] for a wrong PIN — which the caller counts, on the same
  /// throttle as the password — and [HardwareKeyUnavailable] when the device
  /// key is gone, which is not the person's fault and needs a different
  /// sentence on screen.
  Future<String> unlockWithPin(String pin) async {
    final stored = await SecureStorage.getPinBlob();
    if (stored == null || stored.isEmpty) {
      throw const HardwareKeyUnavailable();
    }

    final opened = await PinLock.openAndUpgrade(stored, pin);
    final vault = await _openFromPayload(utf8.decode(opened.secret));
    await _storeUpgradedPin(stored, opened.upgraded);
    return vault;
  }

  /// A PIN sealed in format 1 moved to format 2 ([PinLock.version]) by the
  /// unlock that just typed it — the only moment the PIN is in hand.
  ///
  /// Written only over the blob it was made from, so a PIN changed meanwhile
  /// is left alone; the old blob opens until the new one is stored, so a
  /// failure anywhere loses nothing and the next unlock tries again. Nothing
  /// here can fail an unlock that has already succeeded.
  Future<void> _storeUpgradedPin(String from, String? upgraded) async {
    if (upgraded == null) return;
    try {
      if (await SecureStorage.getPinBlob() != from) return;
      await SecureStorage.savePinBlob(upgraded);
    } catch (_) {
      // The PIN keeps the format it has.
    }
  }

  /// Moves the PIN onto the key that refuses while the phone is locked, where
  /// this phone has one (audit M2, Android 15 and later).
  ///
  /// Called after every unlock, by any door, and needs no PIN: only the outer
  /// seal changes — see [PinLock.upgrade]. Every step that could lose the PIN
  /// is ordered so that it cannot:
  ///
  /// - written only over the blob it was made from, so a PIN changed in the
  ///   meantime is newer than this and is left alone;
  /// - the old key is dropped only once the new blob is read back from
  ///   storage — before that it is the only key that opens anything;
  /// - a failure anywhere leaves the old blob and the old key as they were,
  ///   and the next unlock tries again.
  ///
  /// A blob already moved still drops the old key, so a crash between the
  /// write and the drop does not leave it behind for good.
  Future<void> upgradePinKey() async {
    try {
      final stored = await SecureStorage.getPinBlob();
      if (stored == null || stored.isEmpty) return;
      if (PinLock.kindOf(stored) == DeviceKeyKind.unlockedOnly) {
        await DeviceKey.forget(kind: DeviceKeyKind.anyTime);
        return;
      }
      final moved = await PinLock.upgrade(stored);
      if (moved == null) return;
      if (await SecureStorage.getPinBlob() != stored) return;
      await SecureStorage.savePinBlob(moved);
      if (await SecureStorage.getPinBlob() != moved) return;
      await DeviceKey.forget(kind: DeviceKeyKind.anyTime);
    } catch (_) {
      // The PIN keeps the key it has. Nothing is lost by trying again later,
      // and an unlock that has already succeeded must not fail over this.
    }
  }

  /// Drops the PIN. The password path is untouched, which is the whole reason
  /// this can be dropped at all.
  ///
  /// **The PIN's two keys go as well**, so a sealed copy the keystore would not
  /// delete opens nothing: the blob needs [DeviceKey] to unseal and
  /// [PinPepper] for every guess, and both are the PIN's alone. A new PIN makes
  /// new ones. Then the refusal is reported — finish, then report, like every
  /// other removal of a secret here.
  ///
  /// Throws [SecretStorageDeletionIncomplete] when the blob was not confirmed
  /// deleted.
  Future<void> disarmPinUnlock() async {
    Object? incomplete;
    try {
      await SecureStorage.savePinBlob(null);
    } on SecretStorageDeletionIncomplete catch (error) {
      incomplete = error;
    }
    await SecureStorage.savePinVaultId(null);
    await PinPepper.forget();
    await DeviceKey.forget();
    // Outright rather than at the next [hasPin]: the sheet must stop offering
    // a PIN from the moment there is not one.
    pinArmedAsObserved = false;
    if (incomplete != null) throw incomplete;
  }

  /// Whether six digits will open this wallet.
  ///
  /// **Every call refreshes what the fingerprint sheet will offer.** That
  /// sheet's one button is written in `main.dart`, where this cannot be
  /// awaited, so it reads [pinArmedAsObserved] instead — and the lock
  /// screen asks this question immediately before raising the prompt, which
  /// is what keeps the two in step. See [UnlockPromptWords.cancelToPassword].
  Future<bool> hasPin() async {
    final armed = (await SecureStorage.getPinBlob())?.isNotEmpty == true;
    pinArmedAsObserved = armed;
    return armed;
  }

  /// Whether there is anything here to seal a quick unlock from.
  ///
  /// **The precondition for moving the door onto this wallet.** Arming captures
  /// the open vault's key and the imported-key encryption key; a wallet that is
  /// locked, or one whose active vault was never opened with its password, has
  /// neither — and offering to move quick unlock there would be offering
  /// something that can only fail. Same three values [_unlockPayload] needs,
  /// asked without building it, so nothing assembles key material to answer a
  /// question about whether it could.
  bool get canArmQuickUnlock =>
      _activeVaultId != null && _host.phraseOpen && _encryptionKey != null;

  /// Whether a device key is armed at all, for any wallet.
  ///
  /// The counterpart to [hasPin]; [deviceOpensVault] answers the narrower
  /// question of *which* wallet it opens.
  Future<bool> hasDeviceUnlock() async =>
      (await SecureStorage.getDeviceKeyBlob())?.isNotEmpty == true;

  /// Whether the armed PIN opens [vaultId] specifically.
  ///
  /// **Null answers true, deliberately.** A blob armed before the id was
  /// recorded cannot say which phrase it belongs to, and the two mistakes are
  /// not equal: disarming a PIN that would still have worked costs somebody one
  /// password and a re-arm, while leaving one armed for a vault that no longer
  /// exists is a door onto nothing, with no way back to closing it properly.
  Future<bool> pinOpensVault(String vaultId) async {
    if (!await hasPin()) return false;
    final armed = await SecureStorage.getPinVaultId();
    return armed == null || armed == vaultId;
  }

  /// The same question for the device key. See [pinOpensVault].
  Future<bool> deviceOpensVault(String vaultId) async {
    if ((await SecureStorage.getDeviceKeyBlob())?.isNotEmpty != true) {
      return false;
    }
    final armed = await SecureStorage.getDeviceVaultId();
    return armed == null || armed == vaultId;
  }

  /// Proves the person is here, using the device key and opening nothing.
  ///
  /// **The biometric counterpart to [verifyPin].** Unwrapping is a per-use
  /// operation: it shows the system's own prompt and fails without an answer,
  /// so the fact that it returned is the proof. Nothing is opened, no key is
  /// kept, and the wallet is left exactly as it was — this exists to be called
  /// on an already-open wallet, where an open session is precisely what must
  /// not count as confirmation.
  ///
  /// False when no device key is armed. [HardwareKeyDeclined] reaches the
  /// caller, because a cancelled prompt is an answer and not a broken phone.
  Future<bool> confirmWithDeviceKey() async {
    final stored = await SecureStorage.getDeviceKeyBlob();
    if (stored == null || stored.isEmpty) return false;
    await HardwareKey.unwrap(base64Decode(stored));
    return true;
  }

  /// Checks a PIN without opening anything, the counterpart to
  /// [verifyPassword].
  ///
  /// **A passwordless wallet is the ordinary shape now, not an edge case.**
  /// Creation is PIN → confirm → wallet, and the password arrives later at the
  /// first backup or export. `verifyPassword` answers false for such a wallet
  /// *by design* — there is nothing to check against — so every screen gated on
  /// it was a screen a PIN-only wallet could not reach. Remove wallet was one:
  /// the dialog said "Wrong password" whatever was typed, and there was no way
  /// to delete the wallet at all.
  ///
  /// Unlike [unlockWithPin] this assembles nothing and leaves no key in memory,
  /// so it is safe to call on an already-open wallet purely to confirm an act.
  Future<bool> verifyPin(String pin) async {
    final stored = await SecureStorage.getPinBlob();
    if (stored == null || stored.isEmpty) return false;
    try {
      await PinLock.open(stored, pin);
      return true;
    } on WrongPin {
      return false;
    }
  }

  Future<String> _openFromPayload(String json) async {
    final payload = jsonDecode(json) as Map<String, dynamic>;
    final vaultKey = base64Decode(payload['key'] as String);
    final encryptionKey = base64Decode(payload['enc'] as String);

    _vaults
      ..clear()
      ..addAll(await _readVaults());
    if (_vaults.isEmpty) throw Exception('No stored seed');

    final vault = _vaults.firstWhere((v) => v.id == payload['vault'],
        orElse: () => _vaults.first);
    final mnemonic =
        CryptoUtils.decrypt(base64Decode(vault.encryptedSeed), vaultKey);

    _activeVaultId = vault.id;
    _vaultKeys
      ..clear()
      ..[vault.id] = vaultKey;
    // Only the vault this key belongs to. The others need their own keys, and
    // asking for the password to reach them is correct — it is the same rule
    // as switching wallets, not a limitation of this path.
    _vaultMnemonics
      ..clear()
      ..[vault.id] = mnemonic;

    await _openWith(
      vault: vault,
      mnemonic: mnemonic,
      encryptionKey: encryptionKey,
    );
    return mnemonic;
  }

  /// Drops the device key and what it was holding. Called when quick unlock is
  /// switched off, and whenever the key turns out to be invalid.
  Future<void> disarmDeviceUnlock() async {
    await SecureStorage.saveDeviceKeyBlob(null);
    await SecureStorage.saveDeviceVaultId(null);
    await HardwareKey.forget();
  }

  /// Drops decrypted material. The vault *records* stay: they are ciphertext
  /// and a salt, they hold nothing an attacker could use, and dropping them
  /// would leave the app unable to name the phrases it has — which broke
  /// saveSeed, since that ends by wiping memory as part of its normal flow.
  void _clearSensitiveData() {
    _vaultMnemonics.clear();
    _vaultKeys.clear();
    _encryptionKey = null;
    _host.forget();
  }

  /// The explicit lock. Unlike [_clearSensitiveData] this also forgets which
  /// vaults exist, so a locked wallet reveals nothing about how many phrases
  /// it holds until it is opened again.
  void lock() {
    _vaultMnemonics.clear();
    _vaultKeys.clear();
    _vaults.clear();
    _unparsed = const [];
    _activeVaultId = null;
    _encryptionKey = null;
    _host.forget();
  }
}

/// The password did not open the wallet.
///
/// **A type, because the unlock throttle depends on recognising this and
/// nothing else.** It used to arrive as `Exception('Wrong password')` and the
/// unlock screen matched the sentence with `String.contains`. That worked, and
/// it was one careless reword away from not working: every screen that opens a
/// wallet counts a wrong password toward a lockout, so a throw retitled to
/// "That is not your password" — the wording [VaultKeeper.changePassword]
/// uses — would have stopped the count without
/// stopping anything visible. The wallet would still refuse the password, still
/// say the right thing, and quietly accept guesses forever.
///
/// [WrongPin] already had this shape and `_attemptPin` already caught it by
/// type; the password was the half that never got it.
///
/// [toString] stays the sentence the old throw carried, for a log. A screen
/// words this by its type — `failureSentence` says the lock screen's "Wrong
/// password" in the reader's language — and never reads the text.
class WrongPassword implements Exception {
  const WrongPassword([this.message = 'Wrong password']);

  /// What the screen shows. It is a field rather than a fixed string because
  /// [VaultKeeper.changePassword] asks for the *current* password beside
  /// two copies of a new one, and "Wrong password" there does not say which of
  /// the three fields to look at — which is exactly why that one threw a plain
  /// `Exception` and went uncounted. **The type is what the counting reads;
  /// this is only what is said.**
  final String message;

  @override
  String toString() => message;
}

/// This wallet is stored and sealed — the password will open it.
///
/// **Not a damaged phrase, which is what the old sentence implied.** A PIN or
/// device-key unlock assembles the key for the vault it was armed for and no
/// other, deliberately: six digits opening every phrase on the device would be
/// a weaker lock than the one the person set. What was wrong was the reporting
/// — "That recovery phrase could not be opened" reads as money lost, and there
/// was no route from it to the password that would have worked.
class VaultLocked implements Exception {
  final String vaultId;
  const VaultLocked(this.vaultId);

  @override
  String toString() => 'This wallet is locked. Enter your password to open it.';
}
