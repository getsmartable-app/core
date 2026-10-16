import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart' show kDebugMode, kIsWeb;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// The device refused to store something that may only be stored securely.
///
/// **Thrown rather than worked around.** Everything this covers — a recovery
/// phrase's ciphertext, an imported private key, the blobs a PIN or a
/// fingerprint unlock with — is worth less than nothing in a place it can be
/// copied from: the wallet still opens, still shows a balance, and no longer
/// keeps the promise it is built on. The operation stops instead, and the
/// person is told, which is the only honest answer.
class SecretStorageUnavailable implements Exception {
  /// What the platform said. Kept for a log, never shown raw.
  final Object cause;

  const SecretStorageUnavailable(this.cause);

  @override
  String toString() => cause == 'web build'
      ? 'A wallet cannot be created or imported in a browser: there is no '
          'secure storage here, and a recovery phrase kept in browser storage '
          'is readable by anything else on this machine. Use the app on a '
          'phone.'
      : 'This device would not store the wallet securely, so nothing was '
          'saved. The keystore may be locked or unavailable — restart the '
          'device and try again. Nothing was written anywhere less safe.';
}

/// The readable half of a wallet was removed and the secure half was not.
///
/// **A different failure from [SecretStorageUnavailable], and it has to be.**
/// That one means nothing was written. This one means something was: the app's
/// own files are gone, the wallet no longer appears, and a recovery phrase may
/// still be in the device's keystore. Erasure is the one operation somebody
/// acts on afterwards — selling the phone, handing it over, sending it for
/// repair — so a wallet that says "erased" when it cannot confirm it has told
/// the most consequential lie in its vocabulary.
class SecretStorageDeletionIncomplete implements Exception {
  final Object cause;

  const SecretStorageDeletionIncomplete(this.cause);

  @override
  String toString() =>
      'The app\'s readable data was removed, but this device would not confirm '
      'that the secure wallet data was deleted. Do not sell, give away or hand '
      'in this device until you have erased it from the device\'s own settings.';
}

class SecureStorage {
  static const _seedKey = 'encrypted_seed';
  static const _saltKey = 'salt';
  static const _accountCountKey = 'account_count';
  static const _selectedAccountKey = 'selected_account';
  static const _importedKeysKey = 'imported_keys';

  /// Keys imported for one non-EVM network — TRON, Solana — beside the EVM
  /// ones in [_importedKeysKey].
  ///
  /// **A record of its own, not new entries in the old one.** A build from
  /// before 14 October 2026 reads `imported_keys` as a list of Ethereum keys
  /// and rewrites it whole from what it understood, so a Solana key written
  /// there would be dropped by the first older build to import or remove
  /// anything. Here, an older build never sees it.
  static const _importedChainKeysKey = 'imported_chain_keys';

  /// The JSON list of [SeedVault]s. Replaces the single `encrypted_seed` /
  /// `salt` pair, which is still read once for migration and then left alone.
  static const _vaultsKey = 'seed_vaults';
  static const _activeVaultKey = 'active_vault';

  /// The opaque id Coinbase groups this wallet's purchases and cash-outs
  /// under, generated once and kept.
  ///
  /// **Random on purpose, rather than derived from anything.** Coinbase needs
  /// *a* stable handle to answer "what happened to that sale"; it does not need
  /// to know whose. An address or a hash of one would hand over a permanent
  /// link between a person's identity at Coinbase and their self-custody
  /// wallet, which is precisely the link this app exists to avoid — and it
  /// would buy nothing, since only we ever have to recognise it.
  ///
  /// **And stored encrypted or not at all, since 23 August 2026.** The
  /// reasoning above says why it must not be derived from an address: it would
  /// hand over a permanent link between a person's identity at Coinbase and
  /// their self-custody wallet. Writing it through [write] gave that link away
  /// from the other end — anything able to read the app's preferences learned
  /// the handle tying this device to a purchase history, which is the same
  /// correlation arriving by a different door.
  static const _onrampRefKey = 'onramp_ref';

  /// Throws [SecretStorageUnavailable] when the reference cannot be stored.
  ///
  /// **Refused rather than returned unsaved, which is the unusual choice
  /// here.** Everything else moved to encrypted-only degrades quietly: a lost
  /// portfolio cache costs a round trip, a lost label costs a rename. This
  /// value's entire purpose is to be *the same next time* — a purchase made
  /// under a reference that was never stored is a purchase whose reference
  /// nobody can ever look up again, and the next call would mint a different
  /// one. Handing back a ref we know we did not keep would produce exactly the
  /// support case the ref exists to answer, and produce it silently, weeks
  /// later, when somebody asks what happened to their money.
  static Future<String> onrampRef() async {
    final existing = await readEncryptedOnly(_onrampRefKey);
    if (existing != null && existing.length >= 8) return existing;

    final random = Random.secure();
    final ref = List<String>.generate(
        16, (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
    if (!await writeEncryptedOnly(_onrampRefKey, ref)) {
      throw const SecretStorageUnavailable('on-ramp reference');
    }
    return ref;
  }

  /// Which wallet was open when the app was last closed.
  ///
  /// Without it, unlocking always lands on the first stored phrase, and
  /// switching wallets survives exactly until the app is closed — which is
  /// not switching, it is a detour.
  static Future<String?> getActiveVaultId() => read(_activeVaultKey);

  static Future<void> saveActiveVaultId(String id) => write(_activeVaultKey, id);

  /// Whether this web build may hold a wallet's secrets — see [writeSecret].
  ///
  /// Both halves are required. The flag alone would ship the moment somebody
  /// pasted a build command; `kDebugMode` alone would let every local preview
  /// keep a seed phrase in browser storage.
  static const bool _webWalletAllowed = kDebugMode &&
      bool.fromEnvironment('ALLOW_INSECURE_WEB_WALLET_DEV');

  /// **Apple's half of the rule the manifest already writes down for Android.**
  ///
  /// The Android manifest closes device backup deliberately and with a
  /// measurement behind it — `allowBackup="false"`, `fullBackupContent="false"`
  /// and `dataExtractionRules`, because Auto Backup copies `shared_prefs/`, and
  /// that is where the ciphertext lives. The argument it makes is that a
  /// recovery phrase's ciphertext reaching somebody else's servers leaves the
  /// password's PBKDF2 rounds as its only remaining protection.
  ///
  /// **That argument was never applied to the keychain, where it is the same
  /// argument.** With no `iOptions` the package's default is
  /// `KeychainAccessibility.unlocked`, which is `kSecAttrAccessibleWhenUnlocked`
  /// — and the thing that matters about it is what it is *not*:
  /// `ThisDeviceOnly`. Items without that suffix are carried by iCloud Keychain
  /// and restored out of an encrypted iTunes/Finder backup **onto a different
  /// phone**. Every wallet secret sits under this store — `seed_vaults`,
  /// `imported_keys`, the PIN blob, the device blob, `account_key` — so the
  /// door Android bolted was standing open on the other platform.
  ///
  /// `first_unlock` rather than `unlocked`: after a restart the keychain must
  /// be readable once the phone has been unlocked a first time, not only while
  /// it is unlocked, or a read that happens before the person gets there fails
  /// for a reason that is not about them. `_this_device` is the half that ends
  /// the migration.
  ///
  /// **Changing this again after an iOS release needs a migration, and this one
  /// did not.** `kSecAttrAccessible` is part of the *search* query the plugin
  /// builds, so an item written under one accessibility is not found under
  /// another: `containsKey` answers false, the write falls through to
  /// `SecItemAdd`, and that returns `errSecDuplicateItem` — a wallet that will
  /// not save on a device that already holds it. Safe here only because no iOS
  /// build has ever shipped: signing configuration, entitlements and the bundle
  /// identifier are all still open in `docs/RELEASE_CHECKLIST.md`, so there is
  /// no install to migrate. Whoever changes it next does not have that.
  ///
  /// Not seen on a device. There is no iPhone on this project — see
  /// `STATUS.md`, "iOS biometric testing: Pending hardware".
  ///
  /// **Android: the migration stated, and no `encryptedSharedPreferences`.**
  /// That flag once meant Jetpack Security's EncryptedSharedPreferences,
  /// chosen because the plugin's own KeyStore path failed outright on some
  /// devices. Google deprecated the library, and flutter_secure_storage 10
  /// replaced it with its own ciphers — RSA-OAEP-SHA256 to wrap the key,
  /// AES-GCM to encrypt — and acts on the flag only where
  /// `migrateOnAlgorithmChange` is off: its read, write and read-all each test
  /// the flag *and not* the migration, and an old store is migrated flag or no
  /// flag. Read in the plugin's own Android source, 10.3.1. So the flag was
  /// inert here, and its comment had drifted onto an unrelated constant. What
  /// matters is the migration, stated now rather than defaulted: switched off,
  /// a store an older build wrote stops being readable.
  ///
  /// **Still no jump straight to version 11.** It removes the old algorithms,
  /// and data only they can read is lost — for a wallet, somebody's recovery
  /// phrase. Version 10 in the field first, so every install has migrated,
  /// then 11: `PROJECT_HISTORY.md`, "Do not jump `flutter_secure_storage` to
  /// 11".
  ///
  /// **`resetOnError: false`, because the default erases the wallet.** With
  /// it on — the plugin's default, and ours until 19 September 2026 — a read
  /// that fails to decrypt deletes that key and retries, a failed read-all
  /// deletes everything, a failed migration deletes all data and keys, and any
  /// exception in any call is answered by deleting the whole store and
  /// returning the string "Data has been reset" as if it were the value read.
  /// Read in the plugin's Android source, 10.3.1. So a keystore that was
  /// merely busy erased a recovery phrase's ciphertext around [deleteSecret]
  /// and its report, and [readSecret] — built to say "could not look" rather
  /// than "nothing here" — was handed a real `null` and said "no wallet", and
  /// the app offered to create one. With it off, each of those is an
  /// exception: [readSecret] throws [SecretStorageUnavailable], startup shows
  /// that the store would not open, and nothing is deleted that a person did
  /// not ask to delete. iOS has no such option and deletes nothing on error.
  static const FlutterSecureStorage _secureStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(
      migrateOnAlgorithmChange: true,
      resetOnError: false,
    ),
    iOptions: IOSOptions(
        accessibility: KeychainAccessibility.first_unlock_this_device),
    mOptions: MacOsOptions(
        accessibility: KeychainAccessibility.first_unlock_this_device),
  );

  static Future<SharedPreferences> get _prefs async =>
      SharedPreferences.getInstance();

  static Future<String?> getSeedVaults() => readSecret(_vaultsKey);

  static Future<void> saveSeedVaults(String json) =>
      writeSecret(_vaultsKey, json);

  static Future<void> write(String key, String value) async {
    if (kIsWeb) {
      final prefs = await _prefs;
      await prefs.setString(key, value);
      return;
    }
    try {
      await _secureStorage.write(key: key, value: value);
      // A previous run may have left a plain copy behind via the fallback
      // below. Once the secure write succeeds, that copy is redundant and
      // must not linger as a weaker duplicate of the same secret.
      final prefs = await _prefs;
      if (prefs.containsKey(key)) await prefs.remove(key);
    } catch (_) {
      final prefs = await _prefs;
      await prefs.setString(key, value);
    }
  }

  /// Writes something whose whole value is that it was written *here*.
  ///
  /// **No fallback, because the fallback is the attack.** [write] answers a
  /// keystore failure by putting the value in plain SharedPreferences, on the
  /// argument that a vault nobody can save is a wallet nobody can open. That
  /// argument holds for a wallet's *records* and fails completely for its
  /// secrets: a vault written to a plain preferences file can be copied off
  /// the device, its ciphertext and salt handed to an offline password
  /// guesser, and its owner never told. The wallet goes on looking exactly the
  /// same — which is the part that makes it worth refusing.
  ///
  /// The three classes this storage now has:
  ///
  /// * **Secret** — vaults, the legacy seed and salt, imported keys, the PIN
  ///   and device blobs, the account-key record. This method. A failure stops
  ///   the operation and says so.
  /// * **Privacy-sensitive** — the portfolio cache. [writeEncryptedOnly]:
  ///   skipped rather than written weakly, because losing it costs one round
  ///   trip.
  /// * **Ordinary** — theme, selected tab, currency. [write], fallback and all.
  ///
  /// **Migration is by reading, not by writing.** [read] still looks in
  /// SharedPreferences after secure storage, so a wallet whose vault landed
  /// there under the old behaviour still opens; the first successful secure
  /// write removes the plain copy. Nothing is stranded and nothing new is
  /// written weakly.
  ///
  /// On web there is no keystore to fail — [write] uses SharedPreferences by
  /// design there, and `writeEncryptedOnly` says so in as many words. That is
  /// exactly why web is a development target and not a shipped one; the
  /// guarantee this method exists to keep does not exist in a browser.
  static Future<void> writeSecret(String key, String value) async {
    if (kIsWeb) {
      // **A browser is not a keystore, and saying so in a comment is not a
      // control.** The first version of this let web write secrets to
      // preferences and argued that web is a development target — which is
      // true and stops nothing: a preview gets published, somebody types a
      // real recovery phrase into it "just to check", and it lands in browser
      // storage that extensions, local malware and a profile backup can all
      // read. Raised by the security review, 23 August 2026, and it is right
      // that a documented intention is not a defence.
      //
      // So a web build cannot hold a secret at all unless a developer says so
      // in the build command, and even then only in debug. Every screen that
      // does not create or import a wallet still works under
      // `flutter run -d chrome`.
      if (!_webWalletAllowed) {
        throw const SecretStorageUnavailable('web build');
      }
      final prefs = await _prefs;
      await prefs.setString(key, value);
      return;
    }
    try {
      await _secureStorage.write(key: key, value: value);
    } catch (error) {
      throw SecretStorageUnavailable(error);
    }
    // A copy left by the old fallback is a weaker duplicate of the same
    // secret, and deleting it is the migration.
    final prefs = await _prefs;
    if (prefs.containsKey(key)) await prefs.remove(key);
  }

  /// Writes only if it can be written encrypted, and says whether it was.
  ///
  /// **The opposite trade from [write], and deliberately so.** That method
  /// falls back to plain SharedPreferences when the keystore refuses, because
  /// for a wallet's own records the alternative is an app that cannot function
  /// — a vault nobody can save is a wallet nobody can open.
  ///
  /// This is for data where the calculation runs the other way: losing it
  /// costs one network round trip, and leaking it costs something that cannot
  /// be taken back. A portfolio cache is every balance on every chain against
  /// one identity — precisely the correlation the proxy design exists to keep
  /// off other people's machines — and writing it to an unencrypted
  /// preferences file on a phone somebody else may end up holding would give
  /// that away for the sake of a convenience.
  ///
  /// So: false rather than a fallback, and the caller carries on without a
  /// cache.
  ///
  /// **A successful write also removes any readable copy, and it did not.**
  /// [read] still falls back to SharedPreferences, so a value that reached this
  /// method after living under [write] — every key moved here by a later
  /// version, and every install that ran the old code — kept its plaintext copy
  /// sitting beside the encrypted one indefinitely. Nothing overwrote it,
  /// because this method never touched preferences at all. The move to
  /// encrypted-only closed the front door and left the value where it already
  /// was, which is the leak the move exists to end. Found 23 August 2026 while
  /// moving account labels, the on-ramp reference and RPC overrides here; it
  /// applied to the approval log and the portfolio cache from the day each was
  /// moved.
  ///
  /// Deleted only after the encrypted write succeeds. On failure the plain copy
  /// stays: it is the only copy, and removing it would lose data to protect
  /// data.
  static Future<bool> writeEncryptedOnly(String key, String value) async {
    // Web has no keystore at all — `write` uses SharedPreferences there by
    // design, which is exactly the storage this method refuses.
    if (kIsWeb) return false;
    try {
      await _secureStorage.write(key: key, value: value);
    } catch (_) {
      return false;
    }
    try {
      final prefs = await _prefs;
      if (prefs.containsKey(key)) await prefs.remove(key);
    } catch (_) {
      // The encrypted copy is written and authoritative; a preferences file
      // that will not co-operate must not turn a successful write into a
      // failure the caller reports to somebody.
    }
    return true;
  }

  /// Reads a value that is held encrypted-only, and moves it out of plain
  /// preferences the first time it is found there.
  ///
  /// **The other half of [writeEncryptedOnly], and without it the move only
  /// reached values somebody happened to change again.** Deleting the plain
  /// copy on a successful write closes the leak for a portfolio cache, which is
  /// rewritten every refresh. It does nothing at all for the ones that are
  /// written rarely and read constantly: an approval log on a wallet that
  /// grants nothing new, a label map nobody renames, a custom endpoint set once
  /// a year ago. Those sat in preferences, in plaintext, being read past on
  /// every launch — for as long as their owner did not edit them, which is
  /// exactly the population least likely to ever trigger the write-side fix.
  ///
  /// This is the same shape [readSecret] uses for wallet secrets, and for the
  /// same reason: a migration that waits for a write is a migration that never
  /// happens to the quiet half of the users.
  ///
  /// **A failed migration changes nothing and hides nothing.** If the keystore
  /// will not answer, the plain copy is returned and left alone — it is the
  /// only copy there is. Nothing here reports whether the value is now held
  /// securely, because no caller can act on that and one that thought it could
  /// would be wrong on the device where it matters.
  static Future<String?> readEncryptedOnly(String key) async {
    if (kIsWeb) {
      // No keystore to migrate *to* — `writeEncryptedOnly` refuses here, so
      // nothing new is ever created. An existing value stays readable, which
      // is the state a browser can offer and the reason web is a development
      // target rather than a shipped one.
      final prefs = await _prefs;
      return prefs.getString(key);
    }

    // A throw and a null are different answers, and only one of them means the
    // value might be waiting in preferences. On a throw the plain copy must be
    // returned untouched: the keystore that would receive the migration is the
    // keystore that just refused.
    try {
      final value = await _secureStorage.read(key: key);
      if (value != null) return value;
    } catch (_) {
      final prefs = await _prefs;
      return prefs.getString(key);
    }

    final prefs = await _prefs;
    final legacy = prefs.getString(key);
    if (legacy == null) return null;

    try {
      await _secureStorage.write(key: key, value: legacy);
      await prefs.remove(key);
    } catch (_) {
      // Left exactly where it was. The caller gets the value either way; what
      // it must not get is a wallet that lost data trying to protect it.
    }
    return legacy;
  }

  /// Whether the keystore is holding a record under [key], asked without
  /// reading its value and without writing anything.
  ///
  /// `true` it has one, `false` there is none, **`null` it would not say** —
  /// and the third answer is the whole reason this exists.
  ///
  /// **A fail-closed store cannot act on [readEncryptedOnly] alone.** Null is
  /// its answer for a first launch and also its answer for a keystore that
  /// threw with no plain copy behind it, and to a store that refuses when it
  /// cannot look, those mean opposite things: one is "there is nothing here",
  /// the other is "I could not see".
  ///
  /// **Two stores once told them apart by writing an empty record over their
  /// own key** — the Agent Wallet connector's tokens and replay floor, deleted
  /// with it on 25 September 2026 — and read the write's own success. That
  /// works until the read is the half that failed: a keystore can refuse to
  /// decrypt an entry it already holds and still accept a new one. Then the
  /// probe lands, the record is replaced by nothing, and the store reports
  /// itself ready — every paired token lost while telling somebody they were
  /// never paired, every nonce floor lost, a replay defence resetting itself
  /// rather than failing.
  ///
  /// `containsKey` answers the question the probe was really asking, and
  /// answers it about presence rather than about decryptability — so an entry
  /// that exists but will not decrypt comes back `true` and its store refuses,
  /// which is the outcome the write-probe was reaching for and missing.
  ///
  /// Null on web, where there is no keystore and [writeEncryptedOnly] refuses
  /// by design — the same answer the empty-record probe produced there.
  static Future<bool?> encryptedRecordExists(String key) async {
    if (kIsWeb) return null;
    try {
      return await _secureStorage.containsKey(key: key);
    } catch (_) {
      return null;
    }
  }

  /// Lays [entries] over the JSON object held encrypted-only under [key],
  /// takes out the keys in [remove], and writes the result back.
  ///
  /// **The write for a record that is one value for the whole phone while its
  /// writer holds only part of it.** `bitcoin_formats`, `solana_branches`,
  /// `utxo_slots`, `starknet_accounts` and `account_labels` are keyed by
  /// account address and hold every wallet on the phone; the app holds one
  /// wallet's accounts at a time.
  /// What to lay over and what to take out is the caller's decision. This is
  /// the read and the write, and the two ways a merge goes wrong between them.
  ///
  /// **One merge of a key at a time, in the order they were asked.** A merge
  /// reads before it writes, so two in flight read the same value and the
  /// second write drops whatever the first added. A wallet switch can put a
  /// save from each wallet in flight at once, and what the first carried was
  /// addresses somebody had been given.
  ///
  /// **A record that is there and cannot be read is not merged onto
  /// nothing.** [readEncryptedOnly] answers null both when there is no record
  /// and when the keystore would not decrypt one and no plain copy exists —
  /// and a keystore can refuse to decrypt an entry it holds while accepting a
  /// new one. Writing then would replace every entry the caller does not hold
  /// with nothing, every other wallet's included. So false, the answer a
  /// failed write gives, unless [encryptedRecordExists] says plainly that
  /// there is none.
  ///
  /// A value that reads and will not parse starts the merge empty. The readers
  /// skip it too, so nothing in it was reachable to lose.
  static Future<bool> mergeEncryptedOnly(
    String key,
    Map<String, Object?> entries, {
    Set<String> remove = const {},
  }) async {
    // Taken before the first await, so the order is the order of the calls.
    final before = _merging[key];
    final done = Completer<void>();
    _merging[key] = done.future;
    try {
      if (before != null) await before;
      final stored = await readEncryptedOnly(key);
      if (stored == null && await encryptedRecordExists(key) != false) {
        return false;
      }
      final merged = <String, Object?>{};
      if (stored != null && stored.isNotEmpty) {
        try {
          merged.addAll(jsonDecode(stored) as Map<String, dynamic>);
        } catch (_) {}
      }
      merged.addAll(entries);
      remove.forEach(merged.remove);
      return await writeEncryptedOnly(key, jsonEncode(merged));
    } finally {
      // Released whatever became of this one: a failure is this caller's
      // answer, not a reason for the record never to be written again.
      if (identical(_merging[key], done.future)) _merging.remove(key);
      done.complete();
    }
  }

  /// The merge in flight on each key, which the next one waits for.
  ///
  /// **Empty while nothing is being merged**, and that is not tidiness. It
  /// held the last merge's future for good, and a later merge chained onto
  /// it — and a finished future schedules what is chained onto it in its own
  /// zone, not the caller's. A merge made in another zone (every widget test
  /// runs in a fake one) was continued through a zone that never ran it
  /// onward, and waited until the test timed out: two widget tests, ten
  /// minutes each, 29 September 2026. Now a merge waits only on one still
  /// running.
  ///
  /// **No timeout, deliberately.** A merge whose keystore call never returns
  /// holds up every later merge of its key — and the keystore already holds up
  /// everything after it: `flutter_secure_storage` runs every call on one
  /// `HandlerThread` on Android and one serial `DispatchQueue` on iOS (read in
  /// the locked 10.3.1 and `flutter_secure_storage_darwin` 0.3.2). Giving up
  /// on the wait would add nothing but a way for the stalled write to land
  /// after a newer one.
  static final Map<String, Future<void>> _merging = {};

  /// Reads from secure storage, then falls back to SharedPreferences.
  ///
  /// The fallback must trigger on a *null* result, not only on a thrown
  /// error: when [write] fails it stores the value in SharedPreferences, but
  /// a later `read` of a missing key returns null without throwing. Checking
  /// only for exceptions therefore reported a stored wallet as absent —
  /// "Exception: no stored seed" on a device that had the seed all along.
  static Future<String?> read(String key) async {
    if (kIsWeb) {
      final prefs = await _prefs;
      return prefs.getString(key);
    }
    String? value;
    try {
      value = await _secureStorage.read(key: key);
    } catch (_) {
      value = null;
    }
    if (value != null) return value;

    final prefs = await _prefs;
    return prefs.getString(key);
  }

  /// Reads a secret, and moves it out of plain preferences the first time it
  /// is found there.
  ///
  /// **The plain fallback is a migration path, not a storage policy, and
  /// [read] alone could not tell the difference.** A wallet whose vault landed
  /// in preferences under the old behaviour opens perfectly through `read` and
  /// stays exactly where it is — for months, if its owner never changes
  /// anything, because the only thing that removed the readable copy was the
  /// next successful write. Somebody who updates and then simply uses their
  /// wallet was left in the state the update was meant to end. Raised by the
  /// security review, 23 August 2026.
  ///
  /// So the move happens on the way past: found in preferences, written to the
  /// keystore, and the readable copy deleted — before the value is returned.
  ///
  /// **A failed migration changes nothing and claims nothing.** The legacy copy
  /// stays readable, because deleting it would strand the wallet, and no new
  /// plaintext is written. The caller gets the value either way; what it must
  /// not get is a false impression that the secret is now held securely, which
  /// is why nothing here reports success.
  static Future<String?> readSecret(String key) async {
    if (kIsWeb) {
      // **The same gate as the write, and it was missing here.** Refusing to
      // write a secret in a browser while still reading one is a door locked
      // on one side: a debug build with the flag writes a phrase into browser
      // storage, and a later release build on the same origin reads it back
      // and opens the wallet — the exact state the write guard exists to
      // prevent. Raised by the security review, 23 August 2026.
      if (!_webWalletAllowed) {
        throw const SecretStorageUnavailable('web build');
      }
      final prefs = await _prefs;
      return prefs.getString(key);
    }

    // **A failure to read is not an answer, and the difference is the whole
    // point of this method.** Swallowing the error and returning null told
    // every caller "there is no wallet here" whenever the keystore was locked,
    // busy or invalidated — which is not a stolen phrase, it is worse to meet:
    // the app offers to create a wallet over one that exists, and its owner is
    // shown the onboarding screen as if their funds had never been. Raised by
    // the security review, 23 August 2026.
    String? secure;
    Object? failure;
    try {
      secure = await _secureStorage.read(key: key);
    } catch (error) {
      failure = error;
      secure = null;
    }

    final prefs = await _prefs;
    if (secure != null) {
      // **The secure copy wins, and a stale readable one goes.** Both can
      // exist: a build that wrote through the old fallback, then a later one
      // that wrote securely without passing here.
      if (prefs.containsKey(key)) await prefs.remove(key);
      return secure;
    }

    final legacy = prefs.getString(key);
    if (legacy == null) {
      // **Only a store that answered may say "nothing here".** A legacy copy
      // still opens the wallet whatever the keystore is doing, which is why it
      // is checked first; with neither a secure value nor a readable one, the
      // honest answers are "absent" and "could not look", and they must not be
      // the same value.
      if (failure != null) throw SecretStorageUnavailable(failure);
      return null;
    }

    try {
      await _secureStorage.write(key: key, value: legacy);
      await prefs.remove(key);
    } catch (_) {
      // Left where it is, and readable. The alternative is a wallet that
      // cannot be opened at all on a device whose keystore is refusing.
    }
    return legacy;
  }

  /// Deletes from both stores. Either one may hold the value depending on
  /// whether the secure write succeeded, so removing only one can leave a
  /// stale secret behind after "Remove wallet".
  /// Removes an ordinary value from both stores, best effort.
  ///
  /// **Best effort is the right contract for a preference and the wrong one
  /// for a credential.** A keystore that refuses the delete is swallowed here
  /// so the readable copy still goes, which is correct for a cached rate or a
  /// selected tab. For anything a person can be told is *gone*, use
  /// [deleteSecret] — see the note there.
  static Future<void> delete(String key) async {
    if (kIsWeb) {
      final prefs = await _prefs;
      await prefs.remove(key);
      return;
    }
    try {
      await _secureStorage.delete(key: key);
    } catch (_) {
      // Ignored: the SharedPreferences removal below still has to run.
    }
    final prefs = await _prefs;
    await prefs.remove(key);
  }

  /// Removes a credential, and **throws when the device will not confirm it**.
  ///
  /// [delete] swallows a keystore failure, which turns "this could not be
  /// erased" into "signed out" — and the credential is back after a restart,
  /// with the screen having said it was disconnected. For a cloud key that is
  /// read, write and delete on the bucket holding a backup share, and for
  /// every wallet secret, that is the wrong way to be wrong.
  ///
  /// The readable copy is removed either way: it is the weaker of the two, and
  /// leaving it because the stronger one failed protects nothing.
  ///
  /// Throws [SecretStorageDeletionIncomplete], which already carries the
  /// sentence for this exact situation — it was written for wiping a device
  /// and says the same true thing here.
  static Future<void> deleteSecret(String key) async {
    if (kIsWeb) {
      final prefs = await _prefs;
      await prefs.remove(key);
      return;
    }
    Object? failure;
    try {
      await _secureStorage.delete(key: key);
    } catch (e) {
      failure = e;
    }
    try {
      final prefs = await _prefs;
      await prefs.remove(key);
    } catch (e) {
      failure ??= e;
    }
    if (failure != null) throw SecretStorageDeletionIncomplete(failure);
  }

  static Future<void> saveEncryptedSeed(String encryptedSeed, String salt) async {
    await writeSecret(_seedKey, encryptedSeed);
    await writeSecret(_saltKey, salt);
  }

  /// Removes the loose pre-vault pair.
  ///
  /// It was a copy of the phrase encrypted under the password, kept so a build
  /// predating vaults could still open the wallet. Once a vault carries its
  /// own random key, that copy is the only thing left that can be guessed at
  /// offline — so it is deleted rather than maintained.
  ///
  /// **[deleteSecret], not [delete], and the sentence above is the reason.**
  /// This removes an encrypted copy of somebody's recovery phrase. A best-
  /// effort delete swallows a keystore refusal, so the migration would report
  /// itself complete with the offline-guessable copy still sitting there —
  /// the one thing this method exists to get rid of.
  ///
  /// Throws [SecretStorageDeletionIncomplete]. Callers finish their remaining
  /// work and report at the end, the same shape `removeWalletFromDevice`
  /// uses: a wallet that saved correctly must not be failed over a leftover,
  /// and a leftover must not be silent.
  static Future<void> clearLegacySeed() async {
    Object? failure;
    for (final key in [_seedKey, _saltKey]) {
      try {
        await deleteSecret(key);
      } on SecretStorageDeletionIncomplete catch (error) {
        // Both, then report. Stopping at the first leaves the other half of a
        // pair behind for no reason.
        failure ??= error;
      }
    }
    if (failure != null) throw failure;
  }

  /// Whether this device holds a wallet at all.
  ///
  /// Two shapes count, and asking only one of them is how the app decides
  /// somebody's wallet does not exist: the vault list is what every wallet
  /// written since multi-phrase support uses, and the loose pair is what a
  /// build from before it left behind. A wallet that answers "no" here is
  /// offered a fresh start over the top of its own funds.
  static Future<bool> hasStoredWallet() async {
    final vaults = await getSeedVaults();
    if (vaults != null && vaults.trim().isNotEmpty && vaults.trim() != '[]') {
      return true;
    }
    return await getEncryptedSeed() != null;
  }

  static Future<String?> getEncryptedSeed() => readSecret(_seedKey);
  static Future<String?> getSalt() => readSecret(_saltKey);

  static Future<void> saveAccountCount(int count) async {
    await write(_accountCountKey, count.toString());
  }

  static Future<int?> getAccountCount() async {
    final raw = await read(_accountCountKey);
    if (raw == null) return null;
    return int.tryParse(raw);
  }

  /// The account last selected **in one wallet**.
  ///
  /// **Keyed by vault, and it was not.** One key for the whole app, while
  /// account lists are per recovery phrase, meant the value written in one
  /// wallet was read back in another. Watch-only and hardware accounts are the
  /// one kind that is global — they appear in every wallet's list — so a stale
  /// selection naming one *resolved* in the new wallet instead of falling
  /// through to its first account. Reported from a release build on 15
  /// September 2026: wallet two was opened, locked, and came back showing a
  /// watched account.
  ///
  /// The value under the old key is **not** migrated. It names an account
  /// without saying whose, so adopting it for any wallet would be a guess of
  /// exactly the kind that caused this; the cost of dropping it is that one
  /// launch opens on the first account.
  ///
  /// **An address, and it used to be an index.** An index is a position: the
  /// one an imported key or a watched address gets is allocated while the list
  /// is read, so removing a row moved every row under it and this number then
  /// named a *different* account on the next launch. The slots are stable now
  /// (see `WalletProvider`), and this is the belt beside that brace — an
  /// address names one account and cannot come to mean another.
  ///
  /// A value written by an older build is an integer. `WalletProvider` reads
  /// one as an index for that launch and writes an address the next time the
  /// selection changes, so nobody loses their place in the upgrade.
  static Future<void> saveSelectedAccount(String vaultId, String address) async {
    await write('$_selectedAccountKey:$vaultId', address.toLowerCase());
  }

  static Future<String?> getSelectedAccount(String vaultId) =>
      read('$_selectedAccountKey:$vaultId');

  /// Display currency for fiat values, e.g. "usd". Not secret.
  static Future<void> saveCurrency(String code) async {
    await write('fiat_currency', code);
  }

  static Future<String?> getCurrency() => read('fiat_currency');

  /// Custom account display names, keyed by address.
  ///
  /// **Called "not secret" until 23 August 2026, and that was a description of
  /// the field rather than of the file.** A label on its own is a word somebody
  /// chose. This is a JSON map from that word to an address, which is the one
  /// thing a chain does not publish: the addresses are pseudonymous until
  /// something on a device says *Mum*, *Salary*, *Company* beside them. In
  /// plain preferences it is a ready-made deanonymisation table for anything
  /// that can read the app's files — and unlike a balance it does not go stale.
  ///
  /// So: encrypted or not stored. Returns whether it was, because a rename that
  /// silently fails to stick is a rename somebody performs twice and then
  /// distrusts.
  static Future<bool> saveAccountLabels(String json) =>
      writeEncryptedOnly('account_labels', json);

  static Future<String?> getAccountLabels() =>
      readEncryptedOnly('account_labels');

  /// [labels] laid over the stored names and [remove] taken out — see
  /// [mergeEncryptedOnly].
  static Future<bool> mergeAccountLabels(Map<String, String> labels,
          {Set<String> remove = const {}}) =>
      mergeEncryptedOnly('account_labels', labels, remove: remove);

  /// Which Bitcoin standards each account was found to use.
  ///
  /// **Encrypted-only for the same reason labels are, and a stronger one.** A
  /// script type is not a preference — it says which addresses an account owns,
  /// so the stored map is a list of somebody's Bitcoin addresses by another
  /// name. Anything that could read it in plain preferences would be able to
  /// follow every one of them on a public chain.
  static Future<bool> saveBitcoinFormats(String json) =>
      writeEncryptedOnly('bitcoin_formats', json);

  static Future<String?> getBitcoinFormats() =>
      readEncryptedOnly('bitcoin_formats');

  /// [entries] laid over the stored map — see [mergeEncryptedOnly].
  static Future<bool> mergeBitcoinFormats(Map<String, Object> entries) =>
      mergeEncryptedOnly('bitcoin_formats', entries);

  /// Which Solana branches each account holds, and which one it shows.
  ///
  /// **Its own key, and only the exceptions are written.** Every account this
  /// wallet makes is on the four-level branch alone, so an empty value is the
  /// ordinary state and a missing entry means exactly that — not "unknown".
  /// That is also the migration for every wallet written before this existed:
  /// they come back where they already were, with the address they already had.
  ///
  /// What is stored decides which key an account's money is under, so the value
  /// is a stable id rather than an enum's spelling — see `SolanaLayout.id`.
  ///
  /// Encrypted-only like `bitcoin_formats`, and for the stronger of the two
  /// reasons it gives: the map says which accounts a person moved onto another
  /// wallet's branch, which is a fact about their other wallets.
  static Future<bool> saveSolanaBranches(String json) =>
      writeEncryptedOnly('solana_branches', json);

  static Future<String?> getSolanaBranches() =>
      readEncryptedOnly('solana_branches');

  /// [entries] laid over the stored map — see [mergeEncryptedOnly].
  static Future<bool> mergeSolanaBranches(Map<String, Object> entries) =>
      mergeEncryptedOnly('solana_branches', entries);

  /// Which Starknet account each account uses, and which have been asked.
  ///
  /// **Every asked account is written, with null for "0.4.0's own address"**,
  /// because here an absent entry means something different from an empty
  /// answer: absent is "not asked yet", which costs seven reads of the chain
  /// on the next portfolio pass, and null is "asked, nothing older to use".
  /// See `WalletProvider.resolveStarknetAccount`.
  ///
  /// Encrypted-only for the Solana branches' reason: an adopted address says
  /// which accounts a person used in another wallet, and when.
  static Future<bool> saveStarknetAccounts(String json) =>
      writeEncryptedOnly('starknet_accounts', json);

  static Future<String?> getStarknetAccounts() =>
      readEncryptedOnly('starknet_accounts');

  /// [entries] laid over the stored map — see [mergeEncryptedOnly].
  static Future<bool> mergeStarknetAccounts(Map<String, Object> entries) =>
      mergeEncryptedOnly('starknet_accounts', entries);

  /// Which addresses each account holds on Litecoin and Bitcoin Cash.
  ///
  /// **Its own key rather than a corner of `bitcoin_formats`.** That map is
  /// shaped by Bitcoin's four script types; these coins have one standard each
  /// and are keyed by chain slug, and folding two shapes into one value is how
  /// a parser comes to read one coin's slots as another's.
  ///
  /// Encrypted-only for the same reason, and it is the stronger one here: the
  /// stored map is a list of somebody's addresses on a public chain by another
  /// name.
  static Future<bool> saveUtxoSlots(String json) =>
      writeEncryptedOnly('utxo_slots', json);

  static Future<String?> getUtxoSlots() => readEncryptedOnly('utxo_slots');

  /// [entries] laid over the stored map — see [mergeEncryptedOnly].
  static Future<bool> mergeUtxoSlots(Map<String, Object> entries) =>
      mergeEncryptedOnly('utxo_slots', entries);

  // **"Show test networks" is gone, reader and writer both.** Test mode was a
  // Settings card that swapped every network for its testnet; the wallet has no
  // test network now, and no code reads a `show_testnets` value an older
  // development build may have written. It is not deleted either: no release
  // ever carried it.

  /// Whether the user has proved they wrote down the recovery phrase, by
  /// passing the word quiz at creation or from the home-screen banner.
  /// Imported wallets count as backed up — the user supplied the phrase, so
  /// they demonstrably already have it.
  ///
  /// Not secret: it says nothing about the phrase itself, only whether we
  /// should keep nagging. Defaults to false so a wallet created before this
  /// flag existed is treated as un-backed-up and prompts once.
  static Future<void> saveSeedBackedUp(bool value) async {
    await write('seed_backed_up', value ? '1' : '0');
  }

  static Future<bool> getSeedBackedUp() async {
    final raw = await read('seed_backed_up');
    return raw == '1';
  }

  /// Portfolio total hidden behind "•••••" (the eye icon on the home
  /// screen). Not secret, but persisted so it survives an app restart.
  static Future<void> saveHideBalance(bool value) async {
    await write('hide_balance', value ? '1' : '0');
  }

  static Future<bool> getHideBalance() async {
    final raw = await read('hide_balance');
    return raw == '1';
  }

  /// Which window the percentage beside an asset is measured over.
  ///
  /// Stored as the wire string rather than the enum's index: an index would
  /// silently mean a different period the moment the list changes, and the
  /// wrong period is a plausible number under the wrong label.
  static Future<void> saveChangePeriod(String wire) async {
    await write('change_period', wire);
  }

  static Future<String?> getChangePeriod() => read('change_period');

  /// Crypto symbol the headline portfolio total is denominated in ("BTC" /
  /// "ETH"), or absent to show it in the selected fiat currency. Not secret.
  static Future<void> saveTotalDenomination(String? symbol) async {
    if (symbol == null) {
      await delete('total_denomination');
    } else {
      await write('total_denomination', symbol);
    }
  }

  static Future<String?> getTotalDenomination() async {
    final raw = await read('total_denomination');
    return (raw == null || raw.isEmpty) ? null : raw;
  }

  /// Whether unlocking by the system gate is turned on.
  ///
  /// What sits behind it is the device key blob (below), not a password. The
  /// flag survives a password change even though the blob does not: the next
  /// password unlock arms a new one, and turning the switch off behind the
  /// user's back would be the app quietly deciding they no longer wanted it.
  static Future<void> saveBiometricEnabled(bool value) async {
    await write('biometric_enabled', value ? '1' : '0');
  }

  static Future<bool> getBiometricEnabled() async {
    final raw = await read('biometric_enabled');
    return raw == '1';
  }

  /// The unlock password, as builds up to 2026-08-04 kept it: written when
  /// quick unlock was turned on, with the biometric prompt standing in front of
  /// it as a door rather than as encryption.
  ///
  /// **Read-only, and on its way out.** Nothing writes this any more — the
  /// device key replaced it, and a password in storage is a password that can
  /// be read. It is still read so that a wallet upgrading from such a build
  /// opens by fingerprint the first time, and it is deleted the moment a device
  /// key is armed in its place. There is no setter, deliberately: the way to
  /// re-introduce this would be to add one back.
  static Future<String?> getBiometricPassword() => read('biometric_password');

  /// Removes that copy without touching the switch.
  ///
  /// [clearBiometricPassword] turns quick unlock off as well, which is right
  /// when the user asked for it and wrong when the app is merely replacing the
  /// old mechanism with the new one underneath them.
  ///
  /// **A copy of the wallet password**, so [deleteSecret]: it is removed at
  /// the moment the device key takes over, and the note at that call site says
  /// there is nothing that copy can do any more except be stolen. A swallowed
  /// failure makes that sentence false.
  static Future<void> clearLegacyBiometricPassword() async {
    await deleteSecret('biometric_password');
  }

  /// The vault key, wrapped by the phone's own key store.
  ///
  /// Safe to keep beside everything else precisely because it is useless on
  /// its own: unwrapping it needs a key that never leaves the device's secure
  /// hardware, and that hardware will not act without the person present.
  /// Null clears it — quick unlock switched off, or a key that turned out to
  /// be invalid.
  static Future<void> saveDeviceKeyBlob(String? blob) async {
    if (blob == null) {
      await delete('device_key_blob');
      return;
    }
    await writeSecret('device_key_blob', blob);
  }

  static Future<String?> getDeviceKeyBlob() => readSecret('device_key_blob');

  /// The same payload again, sealed under the PIN and this device.
  ///
  /// Two blobs rather than one because they open under different conditions:
  /// this one needs six digits and no system gate, the one above needs the
  /// system gate and no digits. A wallet can carry either, both, or neither,
  /// and the password opens it in every case.
  ///
  /// **Null is [deleteSecret], and it was [delete].** A best-effort removal
  /// swallowed a keystore that refused it, so "PIN off" could leave the sealed
  /// copy in place and the same six digits still opening the wallet at the
  /// next lock. Throws [SecretStorageDeletionIncomplete].
  static Future<void> savePinBlob(String? blob) async {
    if (blob == null) {
      await deleteSecret('pin_blob');
      return;
    }
    await writeSecret('pin_blob', blob);
  }

  static Future<String?> getPinBlob() => readSecret('pin_blob');

  /// Which wallet each sealed blob above was armed for.
  ///
  /// **Kept in the clear, because the blob cannot be asked.** An unlock payload
  /// names one vault — the key it carries opens that phrase and no other — but
  /// it is sealed under six digits or the secure element, so nothing can read
  /// the id back out of it without the person present. Removing a wallet then
  /// has no way to tell "the PIN opens the one you are deleting" from "the PIN
  /// opens the one you are keeping", and the code took the safe-looking answer:
  /// disarm always. That switched off a working PIN and fingerprint because a
  /// *different*, empty wallet was removed — reported 22 August 2026.
  ///
  /// A vault id is not a secret. The vault records sit beside this as
  /// ciphertext, a salt and a label, all readable; the id is how they are named
  /// in that same file. What it buys is the difference between a wallet whose
  /// quick unlock survives and one whose owner is suddenly asked for a password
  /// they may have set weeks ago.
  ///
  /// Null on a blob armed before this existed. That case falls back to the old
  /// behaviour and disarms, because a PIN left armed for a vault that is gone
  /// is the one direction with no way back.
  static Future<void> savePinVaultId(String? id) async {
    if (id == null) {
      await delete('pin_vault_id');
      return;
    }
    await write('pin_vault_id', id);
  }

  static Future<String?> getPinVaultId() => read('pin_vault_id');

  static Future<void> saveDeviceVaultId(String? id) async {
    if (id == null) {
      await delete('device_vault_id');
      return;
    }
    await write('device_vault_id', id);
  }

  static Future<String?> getDeviceVaultId() => read('device_vault_id');

  /// The key imported private keys are encrypted under, wrapped by the
  /// password. `{"salt": …, "key": …}`.
  ///
  /// Separate from the vaults because imported keys belong to no phrase: they
  /// survive switching wallets and deleting one, so hanging their key off a
  /// vault record would tie them to something they are independent of.
  ///
  /// Absent on a wallet written before this existed, and that is a supported
  /// state rather than a migration waiting to happen — for those the
  /// password-derived key is the account key, exactly as it always was.
  static Future<void> saveAccountKeyRecord(String? record) async {
    if (record == null) {
      // The key every imported private key is encrypted under. Best effort
      // would report a removal that did not happen.
      await deleteSecret('account_key');
      return;
    }
    await writeSecret('account_key', record);
  }

  static Future<String?> getAccountKeyRecord() => readSecret('account_key');

  /// The same copy, and the switch with it.
  ///
  /// **The switch goes off either way.** If the keystore will not confirm the
  /// deletion, quick unlock must still stop claiming to be on — then the
  /// failure is reported. Leaving the switch on because the delete failed
  /// would answer one wrong state with two.
  static Future<void> clearBiometricPassword() async {
    Object? failure;
    try {
      await deleteSecret('biometric_password');
    } on SecretStorageDeletionIncomplete catch (error) {
      failure = error;
    }
    await saveBiometricEnabled(false);
    if (failure != null) throw failure;
  }

  /// "dark"/"light" theme preference. Not secret.
  static Future<void> saveThemeMode(bool isDark) async {
    await write('theme_mode', isDark ? 'dark' : 'light');
  }

  /// Dark unless the person has said otherwise.
  ///
  /// The accent is a single saturated green, and on a light ground it competes
  /// with the page for attention; on a dark one it is the only source of colour
  /// and the glow behind the action tiles reads as light rather than as fill.
  /// The toggle stays on the portfolio and the choice is still remembered — this
  /// only changes which one someone sees before they have an opinion.
  ///
  /// Written as an explicit string, so "never chosen" is distinguishable from
  /// "chose light" and the default can move again without silently flipping
  /// anyone who already decided.
  static Future<bool> getThemeModeIsDark() async {
    final raw = await read('theme_mode');
    if (raw == null || raw.isEmpty) return true;
    return raw == 'dark';
  }

  /// How long the wallet stays open without being touched, in seconds.
  ///
  /// Zero means never. Five minutes was hardcoded, which is the wrong number
  /// for both ends of the range: too long for someone holding real money on a
  /// phone that gets handed around, and too short for someone reading a long
  /// transaction history who has to type their password again to finish.
  static Future<int> getAutoLockSeconds() async {
    final raw = await read('auto_lock_seconds');
    if (raw == null || raw.isEmpty) return 300;
    return int.tryParse(raw) ?? 300;
  }

  static Future<void> saveAutoLockSeconds(int seconds) =>
      write('auto_lock_seconds', '$seconds');

  /// User-added custom networks (MetaMask's "Add network"), as a JSON list.
  ///
  /// **Encrypted or not stored, like `rpc_overrides`, and it was called "not
  /// secret".** A chain id is not, and neither is an RPC URL as a kind of
  /// thing — but the URLs people actually paste carry a paid provider key in
  /// the path, which is why the other door onto a typed host, Settings → RPC
  /// endpoints, was moved encrypted-only. This door wrote the same URL through
  /// [write], whose answer to a refusing keystore is a plain preferences file.
  /// Returns whether it was stored; [readEncryptedOnly] moves a copy an older
  /// build left in preferences.
  static Future<bool> saveCustomNetworks(String json) =>
      writeEncryptedOnly('custom_networks', json);

  static Future<String?> getCustomNetworks() =>
      readEncryptedOnly('custom_networks');

  /// Custom ERC-20 tokens the user added, stored per network. Not secret —
  /// these are public contract addresses.
  static Future<void> saveCustomTokens(String networkSlug, String json) async {
    await write('custom_tokens_$networkSlug', json);
  }

  static Future<String?> getCustomTokens(String networkSlug) =>
      read('custom_tokens_$networkSlug');

  /// Stores the encrypted blob of imported private keys, or clears it when
  /// [encrypted] is null.
  ///
  /// **Cleared through [deleteSecret]**: the last imported key removed is a
  /// private key somebody asked to be gone, and a swallowed refusal brought it
  /// back at the next unlock. Throws [SecretStorageDeletionIncomplete].
  static Future<void> saveImportedKeys(String? encrypted) async {
    if (encrypted == null) {
      await deleteSecret(_importedKeysKey);
      return;
    }
    await writeSecret(_importedKeysKey, encrypted);
  }

  static Future<String?> getImportedKeys() => readSecret(_importedKeysKey);

  /// The encrypted blob of keys imported for one non-EVM network, or clears
  /// it when [encrypted] is null — through [deleteSecret], for the reason
  /// [saveImportedKeys] gives. Throws [SecretStorageDeletionIncomplete].
  static Future<void> saveImportedChainKeys(String? encrypted) async {
    if (encrypted == null) {
      await deleteSecret(_importedChainKeysKey);
      return;
    }
    await writeSecret(_importedChainKeysKey, encrypted);
  }

  static Future<String?> getImportedChainKeys() =>
      readSecret(_importedChainKeysKey);

  /// Erases everything this app has written, in both stores.
  ///
  /// **Deliberately not a list of keys, and that is the whole correction.**
  /// This method used to name five: `encrypted_seed`, `salt`, `account_count`,
  /// `selected_account` and `imported_keys` — the shape a wallet had before
  /// vaults. Everything the wallet has lived in since (`seed_vaults`, the PIN
  /// blob, the device blob, the account-key record, the watched and hardware
  /// accounts) was written by code that never came back to add itself here, so
  /// "Remove wallet" left the recovery-phrase ciphertext and every door into it
  /// exactly where they were. `hasStoredWallet` went on answering yes and the
  /// PIN went on opening the same wallet.
  ///
  /// A denylist is a list of the things somebody thought of, and this one had
  /// already failed. So the direction is inverted: remove everything, and let a
  /// key that ought to survive have to argue for itself. Nothing does today —
  /// what would be kept is display preferences, and a wrong guess in the other
  /// direction leaves somebody's data on a phone they have handed on.
  ///
  /// Both stores, because [write] falls back to plain SharedPreferences when
  /// the keystore refuses and either one may be holding the value.
  static Future<void> eraseEverything() async {
    if (kIsWeb) {
      await (await _prefs).clear();
      return;
    }
    // **The readable wipe runs either way; the secure one is reported.**
    // Swallowing this told the screen above that a wallet had been erased when
    // its phrase may still be sitting in the keystore — and "erased" is the
    // word somebody acts on before selling a phone. Raised by the security
    // review, 23 August 2026.
    Object? failure;
    try {
      await _secureStorage.deleteAll();
    } catch (error) {
      // Not rethrown here: the preferences wipe below still has to run, and on
      // a device whose keystore is refusing, that is the copy which exists and
      // can be removed.
      failure = error;
    }
    await (await _prefs).clear();
    if (failure != null) throw SecretStorageDeletionIncomplete(failure);
  }
}
