import 'dart:convert';

/// One recovery phrase, encrypted, with what the app needs to know about it
/// without unlocking it.
///
/// The wallet used to hold exactly one, stored as two loose keys
/// (`encrypted_seed` and `salt`). Supporting a second — which is what MetaMask
/// calls a Secret Recovery Phrase and Trust Wallet calls another wallet —
/// means the phrase stops being a property of the app and becomes a thing the
/// app has several of.
///
/// Two fields deserve their reason stated:
///
/// [salt] is per vault, never shared. Two phrases encrypted under one password
/// must not derive the same key: a salt exists to make the derivation unique
/// per secret, and reusing it would mean cracking one gets both for free.
///
/// [backedUp] is per vault, and this is the correction the change forces. The
/// app has a rule that mainnet funds cannot move until the phrase is written
/// down, and that rule was a single global flag. With several phrases it is
/// meaningless: backing up the first says nothing about the second, and a
/// global flag would silently unlock sending from a phrase nobody has ever
/// seen.
class SeedVault {
  /// Stable across renames and reorderings — accounts refer to it, so it must
  /// not be the label or the position.
  final String id;

  /// Base64 of the AES-GCM blob, nonce included.
  final String encryptedSeed;

  /// Base64, 16 bytes, unique to this vault.
  final String salt;

  /// The vault's own key, wrapped by the key derived from the password.
  ///
  /// Null on a vault written before this existed, and that is a supported
  /// state rather than a migration waiting to happen: for those the derived
  /// key *is* the vault key, so they open exactly as they always did. They
  /// convert the next time the password changes, which rewrites them anyway —
  /// a wallet is the wrong place to run a migration nobody asked for.
  ///
  /// What it buys: the phrase stops being encrypted under something a person
  /// types. A stolen storage file then has nothing to guess at, which is the
  /// precondition for a six-digit PIN being safe, and for the phone's secure
  /// element holding the key at all.
  final String? wrappedKey;

  /// How many accounts were derived from it, so unlock restores the same set.
  ///
  /// **It is the span, not the count of visible rows**, and the two stopped
  /// being the same number when accounts became removable. Derivation indices
  /// are allocated 0 upward and never reused — index 2 is a different address
  /// from index 3 — so removing the middle one leaves a gap that this number
  /// has to keep spanning. Reading it as "how many rows are in the list" would
  /// re-derive the removed account and drop the last one.
  final int accountCount;

  /// Derivation indices the owner has taken off the list.
  ///
  /// **Nothing is destroyed by being in here.** A seed account is an index of
  /// the recovery phrase, so it can always be derived again — the entry says
  /// "do not show this one", which is the whole of what removing a derived
  /// account can honestly mean. It lives on the vault rather than in one
  /// global store because indices belong to a phrase, and two phrases both
  /// have an index 1.
  final List<int> hiddenAccounts;

  /// Whether this phrase has been written down. See the note above: global is
  /// not a defensible answer once there is more than one.
  final bool backedUp;

  /// What the user calls it. Null falls back to a positional default at the
  /// point of display, so the stored data does not go stale when one is
  /// deleted.
  final String? label;

  /// Whether a password opens this vault at all.
  ///
  /// **False is a real, supported state**, not a half-written wallet: a wallet
  /// created since the PIN comes into being with six digits and no password,
  /// and the password is asked for later — at the first backup, export or
  /// send, where it is worth something to the person being asked.
  ///
  /// It has to be recorded explicitly rather than inferred from a null
  /// [wrappedKey], because that already means something else: a vault written
  /// before wrapping, whose key *is* the password-derived key. Overloading the
  /// one field would make an old wallet look passwordless and a passwordless
  /// wallet look old, and both readings open the wrong thing.
  ///
  /// Defaults to true, so every vault written before this existed is what it
  /// has always been: a vault with a password.
  final bool hasPassword;

  /// The split backup that was made from *this* phrase, by its 128-bit name.
  ///
  /// **Cloud storage is global; a backup belongs to a vault.** That sentence is
  /// the whole reason this field exists. A person's Drive can hold shares from
  /// a wallet they replaced, a wallet on their old phone, and a wallet they
  /// deleted — and nothing in a sealed share names the wallet it came from, by
  /// design. So "there is a share in Drive" and "this wallet has a backup" are
  /// different facts, and the screen that reports the second one has to be
  /// told which backup is ours.
  ///
  /// **Written only after the backup verified**, which is the only moment the
  /// claim is true: a set of shares that has not been reconstructed is a set of
  /// files. Null means this phrase has no split backup — the honest answer for
  /// a wallet created on a phone whose clouds are full of somebody else's.
  ///
  /// Absent on every vault written before this existed, which reads as null
  /// and is correct: those wallets are asked to make a backup again rather
  /// than told they have one that cannot be attributed.
  final String? splitBackupId;

  /// Whether this phrase is an Agent Wallet: a separate wallet, with a phrase
  /// of its own and only the money moved into it, kept for showing an AI.
  ///
  /// **Nothing connects to it.** AI never connects to Smartable — the owner's
  /// decision of 25 September 2026, `docs/AI_INTEGRATION.md` — so what this
  /// flag decides is what a person is told: the badge, "For showing an AI" in
  /// the wallet list, and the Agent Wallet screen.
  ///
  /// **False is the Primary Wallet and false is what everything absent means.**
  /// The direction is not symmetric: a Primary Wallet labelled as the one kept
  /// for showing an AI tells somebody their savings sit in the wallet meant to
  /// hold little. So only a literal `true` in the record makes this true.
  /// Absent is false, a number is false, a string `"true"` is false, an
  /// unreadable entry is false.
  ///
  /// **Not a schema version, and that is deliberate.** This record has never
  /// carried a version and every vault on every device is written without one,
  /// so a build that *required* a version would refuse every wallet in
  /// existence. The file's own convention is used instead — see [hasPassword],
  /// written only when false — and the safe reading is the one that needs no
  /// version to be correct.
  ///
  /// Set only at creation, by `VaultKeeper.addVault`; [copyWith] offers no
  /// way to move it.
  final bool isAgentVault;

  /// How many Agent Wallets one device keeps.
  ///
  /// **Two, and the number is about recovery phrases.** Each Agent Wallet is a
  /// phrase somebody has to write down before it may hold anything, and the
  /// practical outcome of four pieces of paper is not four tidy wallets, it is
  /// money in a wallet whose phrase was lost.
  ///
  /// **Enforced in `VaultKeeper.addVault`, not in a screen.** The first
  /// limit of one was a branch in `_openAgentWallet` that nobody had decided
  /// on; a product rule belongs where it cannot be walked around by a second
  /// call site.
  static const int agentWalletLimit = 2;

  const SeedVault({
    required this.id,
    required this.encryptedSeed,
    required this.salt,
    this.wrappedKey,
    this.accountCount = 1,
    this.hiddenAccounts = const [],
    this.backedUp = false,
    this.label,
    this.hasPassword = true,
    this.splitBackupId,
    this.isAgentVault = false,
  });

  /// [clearLabel] exists because `label: null` cannot mean "remove it" — the
  /// `??` below reads null as "leave it alone", which is right for every other
  /// field and wrong for the one a person can empty on purpose.
  SeedVault copyWith({
    int? accountCount,
    List<int>? hiddenAccounts,
    bool? backedUp,
    String? label,
    bool clearLabel = false,
    // Changed together or not at all: a blob re-encrypted under a new key with
    // the old salt still recorded is a phrase nothing can open.
    String? encryptedSeed,
    String? salt,
    String? wrappedKey,
    bool? hasPassword,
    String? splitBackupId,
    /// Same reason as [clearLabel]: null means "leave it", and a backup that
    /// has been retired has to be able to say it is gone.
    bool clearSplitBackup = false,
  }) =>
      SeedVault(
        id: id,
        encryptedSeed: encryptedSeed ?? this.encryptedSeed,
        salt: salt ?? this.salt,
        wrappedKey: wrappedKey ?? this.wrappedKey,
        accountCount: accountCount ?? this.accountCount,
        hiddenAccounts: hiddenAccounts ?? this.hiddenAccounts,
        backedUp: backedUp ?? this.backedUp,
        label: clearLabel ? null : (label ?? this.label),
        hasPassword: hasPassword ?? this.hasPassword,
        splitBackupId:
            clearSplitBackup ? null : (splitBackupId ?? this.splitBackupId),
        // **Carried, and there is deliberately no parameter for it.**
        //
        // A vault is an Agent Wallet from birth or never. The design is a
        // separate recovery phrase, created as one — so a setter here would
        // exist only to convert, and the conversion worth worrying about is
        // the one that goes the wrong way: a bug, a bad merge or a bad record
        // promoting the Primary Wallet, which is the whole thing this boundary
        // is between. Nothing in the ordinary edit path — renaming, backing
        // up, adding an account — has any business changing it.
        //
        // The other direction is refused for its own reason: a vault an AI has
        // been able to reach does not become the Primary Wallet again by a flag
        // being cleared. Whatever it was paired with, and whatever it was told,
        // happened.
        isAgentVault: isAgentVault,
      );

  Map<String, dynamic> toJson() => {
        'id': id,
        'seed': encryptedSeed,
        'salt': salt,
        if (wrappedKey != null) 'key': wrappedKey,
        'accounts': accountCount,
        // Absent on every wallet that has never removed one, which is most of
        // them — an empty list in every record is noise in a file read on each
        // unlock.
        if (hiddenAccounts.isNotEmpty) 'hidden': hiddenAccounts,
        'backedUp': backedUp,
        if (label != null) 'label': label,
        // Written only when false. Absent means true, which is what every
        // vault stored before this field existed actually is.
        if (!hasPassword) 'pw': false,
        if (splitBackupId != null) 'bkp': splitBackupId,
        // Written only when true, so no existing record changes shape and the
        // absent case keeps meaning the safe thing.
        if (isAgentVault) 'agent': true,
      };

  /// Returns null for anything it cannot read in full.
  ///
  /// A vault missing its ciphertext or salt is not a vault, and carrying a
  /// half-read one forward would surface later as a failed decryption that
  /// looks like a wrong password — sending the user to reset a wallet that was
  /// never actually lost.
  static SeedVault? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final id = raw['id'];
    final seed = raw['seed'];
    final salt = raw['salt'];
    if (id is! String || seed is! String || salt is! String) return null;
    if (id.isEmpty || seed.isEmpty || salt.isEmpty) return null;

    final accounts = raw['accounts'];
    return SeedVault(
      id: id,
      encryptedSeed: seed,
      salt: salt,
      wrappedKey: raw['key'] is String && (raw['key'] as String).isNotEmpty
          ? raw['key'] as String
          : null,
      // At least one: a wallet always has a first account, and older builds
      // could store zero.
      accountCount: accounts is int && accounts > 0 ? accounts : 1,
      // Anything unreadable is dropped one entry at a time rather than
      // failing the vault: the worst a bad entry can do is show an account
      // that was meant to be hidden, and refusing the whole record over it
      // would lose the phrase instead.
      hiddenAccounts: raw['hidden'] is List
          ? [
              for (final i in raw['hidden'] as List)
                if (i is int && i >= 0) i,
            ]
          : const [],
      backedUp: raw['backedUp'] == true,
      label: raw['label'] is String ? raw['label'] as String : null,
      hasPassword: raw['pw'] != false,
      // Anything that is not a backup name is no link at all. A half-read
      // identifier would point the status screen at a backup that does not
      // exist, which reads as "your backup is gone" rather than as a bad
      // record.
      splitBackupId: raw['bkp'] is String && (raw['bkp'] as String).isNotEmpty
          ? raw['bkp'] as String
          : null,
      // **Identity comparison against `true`, not a truthiness test.** Every
      // other shape — absent, null, `1`, `"true"`, a map — reads as false,
      // which is the direction that keeps the Primary Wallet out of reach.
      isAgentVault: raw['agent'] == true,
    );
  }

  /// [vaults] as the stored record, with [keep] — the entries the last read
  /// could not parse ([VaultRecord.unparsed]) — written back after them
  /// unchanged.
  static String encode(List<SeedVault> vaults, {List<Object?> keep = const []}) =>
      jsonEncode([...vaults.map((v) => v.toJson()), ...keep]);

  /// Skips entries it cannot read rather than failing the whole list: one
  /// corrupt record must not hide the other phrases, which are still perfectly
  /// recoverable.
  /// The vaults in [json], and what could not be read.
  ///
  /// **"None" and "I could not tell" were the same answer, and they are not the
  /// same thing.** A stored record that will not parse decoded to an empty
  /// list, exactly like a device with no wallet on it — so the one message a
  /// person got was *No stored seed*, on a phone whose vault was sitting right
  /// there. A wallet that says your phrase is gone when it is merely unreadable
  /// is the worst sentence this app can produce, and it was one line of
  /// `catch (_) { return const []; }`.
  ///
  /// [dropped] counts entries that were present and unusable — a record missing
  /// its id, ciphertext or salt. Those are dropped one at a time rather than
  /// failing the list, because one bad entry must not hide the vaults beside
  /// it; what must not happen is the list coming back shorter with nobody told.
  static VaultRecord read(String? json) {
    if (json == null || json.isEmpty) {
      return const VaultRecord(vaults: [], dropped: 0, unreadable: false);
    }
    final Object? raw;
    try {
      raw = jsonDecode(json);
    } catch (_) {
      return const VaultRecord(vaults: [], dropped: 0, unreadable: true);
    }
    // Stored, and not a list of anything. The bytes exist and say nothing this
    // build understands, which is the same answer as a parse failure.
    if (raw is! List) {
      return const VaultRecord(vaults: [], dropped: 0, unreadable: true);
    }
    final vaults = <SeedVault>[];
    final unparsed = <Object?>[];
    for (final entry in raw) {
      final vault = SeedVault.fromJson(entry);
      if (vault == null) {
        unparsed.add(entry);
      } else {
        vaults.add(vault);
      }
    }
    return VaultRecord(
      vaults: List.unmodifiable(vaults),
      dropped: unparsed.length,
      unreadable: false,
      unparsed: List.unmodifiable(unparsed),
    );
  }

  /// Just the vaults, for the callers that only ever wanted a list.
  static List<SeedVault> decode(String? json) => read(json).vaults;
}

/// What a stored vault list turned out to be.
class VaultRecord {
  const VaultRecord({
    required this.vaults,
    required this.dropped,
    required this.unreadable,
    this.unparsed = const [],
  });

  final List<SeedVault> vaults;

  /// Entries that were there and could not be used.
  final int dropped;

  /// Those entries, as they were stored — **kept to be written back**
  /// ([SeedVault.encode]'s `keep`). The record is rewritten whole by every
  /// change, so an entry dropped on read was gone at the next write: a newer
  /// build's vault after a downgrade, or one damaged entry, deleted with the
  /// recovery phrase sealed in it. Something this build cannot read is not
  /// something it may throw away.
  final List<Object?> unparsed;

  /// The record itself could not be parsed. **Not the same as no record**: a
  /// device with no wallet answers false here with an empty list.
  final bool unreadable;

  /// Something was stored and this build got less of it than was written.
  bool get isDamaged => unreadable || dropped > 0;
}

/// A vault record is present and this build cannot read it.
///
/// **Its own type so that nothing can report it as an absent wallet.** The
/// difference decides what a person is told and what they do next: an absent
/// wallet is a wallet to create, and a damaged record is one to restore from a
/// backup — and creating over it is the one action that would make the damage
/// permanent.
class VaultRecordUnreadable implements Exception {
  const VaultRecordUnreadable();

  @override
  String toString() =>
      'The stored wallet record could not be read. Do not create a new '
      'wallet over it — restore from a backup instead.';
}
