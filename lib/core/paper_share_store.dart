import 'dart:convert';

import 'sealed_share.dart';
import 'share_store.dart';
import 'secure_storage.dart';

/// The share somebody wrote down.
///
/// **It stores a note, never the share.** Twenty words on a phone are the
/// thing paper exists to keep off a phone: the whole point of this copy is
/// that it survives the device being lost, stolen or wiped, and a copy sitting
/// beside the device it is meant to outlive protects against nothing.
///
/// What is kept is what a status screen needs to *count* — which backup, which
/// share, when it was issued. No secret is in it, so the note is harmless in
/// exactly the way the share would not be.
///
/// **So this store can never restore.** [list] returns records with no sealed
/// body, and the recovery flow asks the person to type the words. That is the
/// distinction [ShareRecord.isReadable] exists for: "fetch your paper" and
/// "this copy is gone" are opposite instructions, and a store that threw would
/// make them look the same.
///
/// > **Its honesty is the person's, not the app's.** Nothing here can check
/// > that the words were really written down, or that the paper still exists.
/// > A note claiming a share that was never transcribed is a backup that looks
/// > complete and is not — which is why the flow that issues one must make
/// > somebody type the words back before it records anything, and why
/// > `WalletShares.restores` exists to verify by reconstructing rather than by
/// > counting.
class PaperShareStore implements ShareStore {
  static const _key = 'wallet_shares_paper';

  const PaperShareStore();

  @override
  String get id => 'paper';

  @override
  String get displayName => 'Written down';

  /// **The one store that keeps nothing.** See the class doc.
  @override
  bool get retainsShare => false;

  @override
  Future<bool> isAvailable() async => true;

  /// Records that [share] was issued on paper. **The sealed body is dropped.**
  @override
  Future<bool> put(SealedShare share) async {
    final stored = await _record();
    // A record that is there and could not be read is not an empty one —
    // see `DeviceShareStore.put`.
    if (stored == null) return false;
    final kept =
        stored.records.where((r) => r.backupId != share.backupId).toList();
    return _write([
      ShareRecord(
        setId: share.setId,
        instanceId: share.instanceId,
        groupIndex: share.groupIndex,
        memberIndex: share.memberIndex,
        threshold: share.threshold,
        shareCount: share.shareCount,
        createdAt: share.createdAt,
        // Deliberately absent. See the class doc: a paper share kept on the
        // device is not a paper share.
      ),
      ...kept,
    ], stored.unparsed);
  }

  @override
  Future<List<ShareRecord>> list() async =>
      (await _record())?.records ?? const [];

  /// The notes this build reads, newest first, and the entries it does not —
  /// **kept as stored and written back by every change**, because the record
  /// is rewritten whole and a note dropped on the way through is a share the
  /// status screen stops counting. Null when a record exists and could not be
  /// read now, which is never written over.
  Future<({List<ShareRecord> records, List<Object?> unparsed})?> _record() async {
    try {
      final raw = await SecureStorage.readEncryptedOnly(_key);
      if (raw == null) {
        return await SecureStorage.encryptedRecordExists(_key) == false
            ? (records: const <ShareRecord>[], unparsed: const <Object?>[])
            : null;
      }
      if (raw.isEmpty) {
        return (records: const <ShareRecord>[], unparsed: const <Object?>[]);
      }
      final decoded = jsonDecode(raw);
      if (decoded is! List) return null;
      final out = <ShareRecord>[];
      final unparsed = <Object?>[];
      for (final entry in decoded) {
        if (entry is! Map) {
          unparsed.add(entry);
          continue;
        }
        final setId = entry['set'];
        final group = entry['g'];
        final member = entry['m'];
        if (setId is! String || group is! int || member is! int) {
          unparsed.add(entry);
          continue;
        }
        // A note from before the choice carries neither number and was two of
        // three. One carrying something else unreadable is skipped, the way a
        // sealed share is: counted wrongly is worse than not counted.
        final scheme = SealedShare.schemeOf(entry['t'], entry['n'],
            legacyAllowed: true);
        if (scheme == null) {
          unparsed.add(entry);
          continue;
        }
        final at = entry['at'];
        out.add(ShareRecord(
          setId: setId,
          instanceId: entry['bid'] is String ? entry['bid'] as String : null,
          groupIndex: group,
          memberIndex: member,
          threshold: scheme.threshold,
          shareCount: scheme.count,
          createdAt: DateTime.tryParse(at is String ? at : '') ??
              DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
        ));
      }
      out.sort((a, b) => b.createdAt.compareTo(a.createdAt));
      return (records: out, unparsed: unparsed);
    } catch (_) {
      return null;
    }
  }

  @override
  Future<bool> removeBackup(String backupId) async {
    final stored = await _record();
    if (stored == null) return false;
    return _write(
      stored.records.where((r) => r.backupId != backupId).toList(),
      [
        for (final entry in stored.unparsed)
          if (!(entry is Map &&
              (entry['bid'] == backupId ||
                  (entry['bid'] == null && entry['set'] == backupId))))
            entry,
      ],
    );
  }

  Future<bool> _write(List<ShareRecord> records, List<Object?> keep) async {
    try {
      // Encrypted like the others, though it holds no secret: the *set* of
      // backups a device has is still a fact about somebody, and the store is
      // one line away from being asked to hold more.
      return await SecureStorage.writeEncryptedOnly(
        _key,
        jsonEncode([
          for (final r in records)
            {
              'set': r.setId,
              if (r.instanceId != null) 'bid': r.instanceId,
              'g': r.groupIndex,
              'm': r.memberIndex,
              't': r.threshold,
              'n': r.shareCount,
              'at': r.createdAt.toUtc().toIso8601String(),
            },
          ...keep,
        ]),
      );
    } catch (_) {
      return false;
    }
  }
}
