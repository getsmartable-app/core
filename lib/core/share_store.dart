import 'dart:convert';

import 'sealed_share.dart';
import 'secure_storage.dart';

/// Whether a store can be used right now, and if not, which kind of not.
///
/// **Two failures that look the same from outside and ask for opposite
/// things.** A store with no account on this phone wants a sign-in; a store
/// whose account is signed in and whose service did not answer wants a moment
/// and a connection. They were one `false`, so an offline Drive was offered a
/// sign-in to an account already signed in, and the status screen told
/// somebody offline that they were not signed in — on the screen where they
/// decide whether their backup is intact.
enum StoreReach {
  /// It answered.
  ready,

  /// It has no credentials here, or the service refused the ones it has.
  needsSignIn,

  /// It has credentials and could not be asked — the network, the service, or
  /// a keystore that did not answer.
  unreachable,
}

/// A share this device knows about, whether or not it can read it here.
///
/// **Paper is why this type exists.** A share written down cannot be listed:
/// nothing on the phone can read a piece of card. But a status screen that
/// therefore counted two shares where there are three would understate the
/// backup — and understating sends somebody to fix a thing that is not broken,
/// which ends with them replacing a working backup.
///
/// So a store may report a share it cannot open. [sealed] is null then, and
/// the record carries only what is needed to *count*: which backup, which
/// share, and when it was issued. No secret is in it, which is why keeping the
/// note locally costs nothing.
class ShareRecord {
  final String setId;

  /// The backup's 128-bit name, or null for a share written before that
  /// existed. Read through [backupId], never directly.
  final String? instanceId;
  final int groupIndex;
  final int memberIndex;

  /// How many shares restore this backup, as the share's label says. See
  /// [SealedShare.threshold] for what an edited label can and cannot do.
  final int threshold;

  /// How many shares the backup was divided into. Shown, never decided on —
  /// see [SealedShare.shareCount].
  final int shareCount;
  final DateTime createdAt;

  /// Null when this store knows the share exists and cannot produce it —
  /// paper, or a cloud that answered its listing and not its contents.
  ///
  /// **A caller must branch on this rather than call and catch.** "I cannot
  /// read this here" and "this backup is damaged" are opposite instructions:
  /// one says fetch the paper, the other says this copy is gone.
  final SealedShare? sealed;

  const ShareRecord({
    required this.setId,
    this.instanceId,
    required this.groupIndex,
    required this.memberIndex,
    this.threshold = SealedShare.legacyThreshold,
    this.shareCount = SealedShare.legacyShareCount,
    required this.createdAt,
    this.sealed,
  });

  /// Whether this share can be produced on this device right now.
  bool get isReadable => sealed != null;

  /// What names this backup outside SLIP-39. See [SealedShare.instanceId] for
  /// why the fifteen-bit set id could not do the job.
  String get backupId => instanceId ?? setId;

  ShareRecord.of(SealedShare share)
      : setId = share.setId,
        instanceId = share.instanceId,
        groupIndex = share.groupIndex,
        memberIndex = share.memberIndex,
        threshold = share.threshold,
        shareCount = share.shareCount,
        createdAt = share.createdAt,
        sealed = share;

  /// The share, not the copy — two stores holding one share are one share.
  String get shareKey => '$groupIndex:$memberIndex';
}

/// Where one share of a backup is kept.
///
/// **The interface exists before the second implementation does**, the shape
/// `LedgerTransport` already follows here: Google Drive and iCloud arrive
/// behind it, and nothing above this file learns the name of a vendor. It also
/// makes the part that decides *policy* — how many shares, which are present,
/// whether a threshold is met — testable without a network or a signed-in
/// account.
abstract class ShareStore {
  /// Stable, and stored nowhere: it names the store in the interface and in
  /// logs, so a person can be told which copy is missing.
  String get id;

  /// What to call this on screen.
  String get displayName;

  /// Whether this store keeps the share itself, or only a note that one was
  /// issued.
  ///
  /// **False means the words have to leave with the caller.** Paper is the
  /// case: nothing is stored, so the creating flow must show the mnemonic and
  /// make somebody write it down. Asked of the store rather than matched on
  /// its id, because a magic string is how a second non-retaining store gets
  /// silently treated as a retaining one.
  ///
  /// **Deliberately without a default.** Every store has to answer, so a new
  /// one that keeps nothing cannot inherit "keeps it" by saying nothing — and
  /// that mistake would hand somebody a share the app then believes is stored.
  bool get retainsShare;

  /// Whether this store can be used on this device right now — an account is
  /// signed in, the platform supports it, the keystore answers.
  ///
  /// **False is not an error.** A person with no Google account is not a
  /// broken installation, and the flow above has to offer them something else
  /// rather than fail.
  Future<bool> isAvailable();

  /// Writes [share], replacing any share of the same backup.
  ///
  /// Returns false rather than throwing when the store refused — losing one
  /// copy of a backup is a thing to report and carry on from, not a reason to
  /// abandon the other two.
  Future<bool> put(SealedShare share);

  /// Every share this store knows about, newest backup first.
  ///
  /// May include shares it cannot read — see [ShareRecord].
  Future<List<ShareRecord>> list();

  /// Removes every share of the backup named [backupId]. Used when a backup is
  /// replaced, so an old share cannot go on satisfying a threshold it is no
  /// longer part of.
  ///
  /// **Named for the backup, not for the SLIP-39 set.** Keyed by set id this
  /// could delete a different backup's share — fifteen bits collide — and the
  /// person would find out at a restore that no longer worked.
  Future<bool> removeBackup(String backupId);
}

/// The share that stays on this phone.
///
/// **What it is actually for, because it is easy to get backwards.** It does
/// not help with a lost phone — a new device has no device share, which is why
/// the two clouds carry that case. It is what makes losing a *cloud account*
/// survivable: device plus the remaining cloud is two of three.
///
/// **One storage key holding a list, not a key per share.** On Android
/// flutter_secure_storage encrypts values and keeps key *names* as plaintext
/// XML, so a key per backup would publish how many wallets this device has
/// backed up in a file anybody can read. [PortfolioCache] records the same
/// reasoning for the same store.
class DeviceShareStore implements ShareStore {
  static const _key = 'wallet_shares';

  const DeviceShareStore();

  @override
  String get id => 'device';

  @override
  String get displayName => 'This device';

  @override
  bool get retainsShare => true;

  @override
  Future<bool> isAvailable() async {
    // **It used to read, and the read cannot fail.** The old body called
    // [SecureStorage.readEncryptedOnly] inside a `try` and answered true when
    // nothing was thrown — but that method catches a refusing keystore itself
    // and answers with the plain legacy copy, or null. So it never threw, the
    // `catch` was unreachable, and this said *yes* on every device including
    // the one whose keystore will not hold a share at all.
    //
    // Worse than merely useless: on a device where the keystore refuses, the
    // answer came from a legacy **plaintext** value. The store would then have
    // claimed readiness on the strength of exactly the material it exists to
    // replace.
    //
    // [SecureStorage.encryptedRecordExists] is the question this was reaching
    // for — presence, asked of the keystore, without writing — and its third
    // answer is the one that matters: `null` is *it would not say*, which for
    // a store that must fail closed is a no.
    return await SecureStorage.encryptedRecordExists(_key) != null;
  }

  @override
  Future<bool> put(SealedShare share) async {
    final record = await _record();
    // **A record that is there and could not be read is not an empty one**:
    // writing this share over it would delete every share it holds.
    if (record == null) return false;
    return _write([
      share.toJson(),
      for (final s in record.shares)
        if (s.backupId != share.backupId) s.toJson(),
      ...record.unparsed,
    ]);
  }

  @override
  Future<List<ShareRecord>> list() async {
    final raw = await _read();
    if (raw == null) return const [];
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! List) return const [];
      return [
        for (final entry in decoded)
          if (SealedShare.fromJson(entry) case final share?)
            ShareRecord.of(share),
      ];
    } catch (_) {
      return const [];
    }
  }

  @override
  Future<bool> removeBackup(String backupId) async {
    final record = await _record();
    if (record == null) return false;
    return _write([
      for (final s in record.shares)
        if (s.backupId != backupId) s.toJson(),
      for (final entry in record.unparsed)
        if (!_names(entry, backupId)) entry,
    ]);
  }

  /// What is stored here: the shares this build reads, and the entries it does
  /// not, **kept as stored and written back by every change** — a newer
  /// build's share, or a damaged one. The record is rewritten whole, so an
  /// entry dropped on the way through was deleted, which nothing here may do.
  ///
  /// Null when a record exists and could not be read now: only the store can
  /// tell "absent" from "unreadable", and only "absent" may be written over.
  Future<({List<SealedShare> shares, List<Object?> unparsed})?> _record() async {
    final raw = await _read();
    if (raw == null) {
      return await SecureStorage.encryptedRecordExists(_key) == false
          ? (shares: const <SealedShare>[], unparsed: const <Object?>[])
          : null;
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(raw);
    } catch (_) {
      return null;
    }
    if (decoded is! List) return null;
    final shares = <SealedShare>[];
    final unparsed = <Object?>[];
    for (final entry in decoded) {
      if (SealedShare.fromJson(entry) case final share?) {
        shares.add(share);
      } else {
        unparsed.add(entry);
      }
    }
    return (shares: shares, unparsed: unparsed);
  }

  /// Whether an entry this build cannot read still names [backupId] — so
  /// removing a backup removes every share of it this phone holds.
  static bool _names(Object? entry, String backupId) =>
      entry is Map &&
      (entry['bid'] == backupId ||
          (entry['bid'] == null && entry['set'] == backupId));

  Future<String?> _read() async {
    try {
      return await SecureStorage.readEncryptedOnly(_key);
    } catch (_) {
      return null;
    }
  }

  Future<bool> _write(List<Object?> entries) async {
    try {
      // **Encrypted or not at all**, the rule [PortfolioCache] and
      // [TokenIdentityCache] follow — and here it is not a preference. A share
      // in a plain preferences file is half a wallet on a phone somebody else
      // may end up holding, and losing it costs one copy of a backup that has
      // two others.
      return await SecureStorage.writeEncryptedOnly(_key, jsonEncode(entries));
    } catch (_) {
      return false;
    }
  }
}

/// What a set of stores adds up to, for the screen that has to explain it.
///
/// **Counting is where a threshold quietly gets satisfied by nothing.** Two
/// copies of one share are not two shares, and a store that failed to answer
/// is not a store known to be empty — both would otherwise read as "you are
/// safe" on the screen whose whole job is to say whether somebody is.
class BackupStatus {
  /// The backup these shares belong to. **The 128-bit name**, not the
  /// fifteen-bit SLIP-39 set id — grouping by that merged two unrelated
  /// backups into one row claiming to be complete.
  final String backupId;

  /// The SLIP-39 set id, for showing and for nothing else. Equal to
  /// [backupId] for shares written before backups had a name of their own.
  final String setId;

  /// Distinct shares found, by store id.
  final Map<String, ShareRecord> byStore;

  /// Stores that could not be asked. Named rather than counted, because the
  /// person can only act on which one.
  final List<String> unreachable;

  /// How many distinct shares a recovery needs.
  final int threshold;

  /// How many shares the backup was divided into — three or five.
  final int shareCount;

  const BackupStatus({
    required this.backupId,
    required this.setId,
    required this.byStore,
    required this.unreachable,
    required this.threshold,
    required this.shareCount,
  });

  /// Distinct shares, not copies.
  int get distinctShares =>
      byStore.values.map((s) => s.shareKey).toSet().length;

  /// Distinct shares this device could actually produce right now.
  ///
  /// **Lower than [distinctShares] whenever paper is involved, and that is
  /// correct.** A backup can be complete and still not restorable without
  /// somebody fetching a piece of card — which is a true and useful thing to
  /// say, and quite different from being one share short.
  int get readableShares => byStore.values
      .where((s) => s.isReadable)
      .map((s) => s.shareKey)
      .toSet()
      .length;

  /// Whether a restore can be done from this device alone.
  bool get isRestorableHere => readableShares >= threshold;

  /// Whether what was *found* is already enough.
  ///
  /// Deliberately says nothing about [unreachable]: a store that did not
  /// answer may hold the share that would make this true, and reporting a
  /// maybe as a yes is how somebody deletes their last copy.
  bool get isRecoverable => distinctShares >= threshold;

  /// Whether losing one more copy would put this backup below its threshold.
  bool get isOneAwayFromLost => distinctShares == threshold;

  /// Groups shares from several stores into one status per backup.
  ///
  /// **Each backup's threshold comes from its own shares**, because a device
  /// can hold a two-of-three backup and a three-of-five one side by side, and
  /// one number for both would call one of them complete when it is not.
  static List<BackupStatus> from({
    required Map<String, List<ShareRecord>> byStore,
    required List<String> unreachable,
  }) {
    final sets = <String, Map<String, ShareRecord>>{};
    final setIds = <String, String>{};
    final thresholds = <String, int>{};
    final counts = <String, int>{};
    byStore.forEach((storeId, shares) {
      for (final share in shares) {
        final id = share.backupId;
        sets.putIfAbsent(id, () => {})[storeId] = share;
        setIds[id] = share.setId;
        // **The highest any share claims, never the first one read.** Nothing
        // here has a password, so the labels cannot be held to the shares yet,
        // and a cloud file whose threshold was lowered from three to two must
        // not have this screen call the backup complete with two. Raising one
        // only makes the screen more cautious than it needs to be.
        if (share.threshold > (thresholds[id] ?? 0)) {
          thresholds[id] = share.threshold;
        }
        if (share.shareCount > (counts[id] ?? 0)) counts[id] = share.shareCount;
      }
    });
    final out = [
      for (final entry in sets.entries)
        BackupStatus(
          backupId: entry.key,
          setId: setIds[entry.key] ?? entry.key,
          byStore: entry.value,
          unreachable: unreachable,
          threshold: thresholds[entry.key]!,
          shareCount: counts[entry.key]!,
        ),
    ];
    // Newest first, so a person replacing a backup sees the new one at the top
    // rather than having to work out which of two identifiers is current.
    out.sort((a, b) => b._newest.compareTo(a._newest));
    return out;
  }

  DateTime get _newest => byStore.values
      .map((s) => s.createdAt)
      .fold(DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
          (a, b) => b.isAfter(a) ? b : a);
}
