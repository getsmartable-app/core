import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart' show visibleForTesting;

import 'crypto_utils.dart';
import 'slip39.dart';

/// One SLIP-39 share, in the form it is allowed to leave the device in.
///
/// **The share itself is words, and words are the secret.** Two of them
/// reconstruct the wallet, so a share sitting in somebody's Drive as plain text
/// would mean a compromised cloud account is one half of a recovery rather than
/// a useless blob. It is sealed under a key derived from the person's password
/// before it is handed to anyone.
///
/// ## What stays readable, and what that gives away
///
/// [setId], [groupIndex], [memberIndex], [threshold], [shareCount] and
/// [createdAt] are **not** encrypted. They have to be legible before anything
/// is decrypted: the restore flow has to recognise which shares belong to one
/// backup and refuse to count the same share twice, the status screen has to
/// know how many make the backup whole, and a person choosing between two
/// backups needs to see when each was made.
///
/// **Readable is not editable without notice.** The set, the indices and the
/// threshold are in the share itself and [open] holds the labels to it. The
/// three the share cannot vouch for — [shareCount], [instanceId] and
/// [createdAt] — are sealed beside it on a share of [labelBoundVersion] and
/// held to that copy the same way (audit of 11 October 2026; owner's go,
/// 13 October). A share from before that version carries no copy, and those
/// three are believed as read.
///
/// What that discloses to somebody holding the file: that this account has a
/// wallet backup, when it was made, how it was divided, and which share it is.
/// The *existence* is disclosed by the file existing at all, and the identifier is
/// a random number that names no wallet, no address and no key. Written down
/// rather than glossed, because "some metadata is in the clear" is the sort of
/// thing that is discovered later and read as carelessness.
///
/// ## The consequence of sealing, stated plainly
///
/// **Every recovery path needs the password**, because every path uses at least
/// one sealed share. So the password stops being only a way into this device
/// and becomes part of the backup — somebody holding all three shares and no
/// password has nothing. That is the owner's design and it is defensible: it is
/// what makes two compromised cloud accounts still not a wallet. It has to be
/// said on screen where the backup is created, not discovered at recovery.
///
/// ## How the key is made from the password
///
/// **Argon2id since 11 October 2026 ([argon2idVersion]), PBKDF2 before it.**
/// The password is guessed away from this phone, on whatever hardware somebody
/// who reached the shares owns, so what a guess costs there is the whole of
/// the protection; PBKDF2 asks for arithmetic only, which graphics cards do by
/// the thousand, and Argon2id asks each guess for 64 MiB as well
/// ([ShareKdf.current], RFC 9106's second recommended setting). Every share
/// sealed now is Argon2id; a share sealed before is PBKDF2 and still opens,
/// because its body says which it is. Nothing is re-sealed behind
/// somebody's back: making a new backup is how an old one moves.
class SealedShare {
  /// Refused rather than half-read when it does not match — the rule
  /// [TokenIdentityCache] follows. A backup is the one thing that must never
  /// be interpreted by a build that does not fully understand it.
  ///
  /// **Version 1 is two of three, and always was.** Every share written before
  /// a person could choose is one, and every two-of-three share is still
  /// written as one, so a build from before the choice reads them exactly as
  /// it did.
  static const int version = 1;

  /// The format of a share from any other arrangement — three of five.
  ///
  /// **A new number, although `bid` was added under the old one and that was
  /// right.** An older build ignores a key it does not know. For `bid` that
  /// left it grouping by the set id, no worse than before. For a threshold it
  /// would be worse: that build believes every backup is two of three, so it
  /// would call a three-of-five backup complete with two shares found, and then
  /// hand `recoverSecret` two shares it can never combine. A version it does
  /// not know is how an older build is told to leave the share alone.
  static const int thresholdVersion = 2;

  /// What a share that carries no threshold was made as. **Only two of three
  /// existed before the labels did**, so this is a fact about those shares
  /// rather than a default for new ones.
  static const int legacyThreshold = 2;
  static const int legacyShareCount = 3;

  static final _instancePattern = RegExp(r'^[0-9a-f]{32}$');

  /// A fresh name for a backup. **One per backup, not one per share** — the
  /// three shares of a set carry the same one, which is what makes them a set
  /// to everything above SLIP-39.
  static String newBackupId() => CryptoUtils.randomBytes(16)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  /// The SLIP-39 set identifier, as four hex digits.
  ///
  /// Shares of one backup share it; shares of different backups usually do
  /// not. **Usually, and that word is load-bearing** — see [instanceId].
  final String setId;

  /// A 128-bit random name for this backup, as 32 hex digits.
  ///
  /// **[setId] is fifteen bits and `slip39.dart` says so out loud**: "two
  /// backups made on one device can collide — which is why nothing anywhere
  /// treats it as a key". The storage layer treated it as exactly that. One
  /// file per set id meant a second backup that happened to draw the same
  /// fifteen bits overwrote the first one's share in the cloud, silently; and
  /// `BackupStatus` grouped by it, so two unrelated backups merged into one
  /// row reading "your backup is complete" over shares that cannot rebuild
  /// anything. The digest catches them at reconstruction — nobody gets a wrong
  /// wallet — but by then the screen has been promising safety for weeks.
  /// Raised by the owner, 23 August 2026.
  ///
  /// 32768 possible set ids is a coin flip at around 215 backups, and the
  /// people who reach that are the ones replacing backups, holding several
  /// wallets, or testing — which is to say the careful ones.
  ///
  /// **Null on every share written before this existed, and then [backupId]
  /// falls back to the set id.** That fallback is what makes the change need
  /// no migration at all: a legacy share's file name comes out byte for byte
  /// as it always did, so nothing has to be moved, re-written or deleted, and
  /// there is no window where a share exists under neither name.
  final String? instanceId;

  /// What names this backup everywhere outside SLIP-39 — the file it lives in,
  /// the group it counts towards, the set that gets retired.
  ///
  /// Wide enough that a collision is not a thing to reason about, and equal to
  /// [setId] for shares made before it existed.
  String get backupId => instanceId ?? setId;

  final int groupIndex;
  final int memberIndex;

  /// How many shares of this backup restore it.
  ///
  /// **Read from the share when it is sealed, and held to the share again when
  /// it is opened.** The label is readable, so it is editable. An edit can make
  /// the status screen count wrongly until the share is opened, and that is
  /// why [BackupStatus] takes the highest threshold any share claims. What an
  /// edit cannot do is get past [open].
  final int threshold;

  /// How many shares the backup was divided into.
  ///
  /// **Not in the share.** SLIP-39 records a group's threshold and not its
  /// size, so this is what the creating flow said. It is shown, and nothing
  /// that decides whether a backup restores reads it. On a share of
  /// [labelBoundVersion] a copy is sealed beside the share and [open] holds
  /// this label to it; on an older share it is not checkable.
  final int shareCount;

  /// The salt this share's key was derived with. **Per share, not per wallet**:
  /// the same password sealing three shares under one salt would produce three
  /// ciphertexts under one key, so cracking one cracks all of them.
  final String salt;

  /// How [salt] and the password became the key: PBKDF2 for a share sealed
  /// before [argon2idVersion], Argon2id and its three numbers after.
  final ShareKdf kdf;

  /// The mnemonic under AES-GCM, base64 — on a share of [labelBoundVersion],
  /// the mnemonic and a copy of the labels it cannot vouch for ([open]).
  final String ciphertext;

  final DateTime createdAt;

  /// Whether [ciphertext] carries a copy of [shareCount], [instanceId] and
  /// [createdAt] beside the share: every share sealed since
  /// [labelBoundVersion], none before.
  final bool labelsSealed;

  const SealedShare({
    required this.setId,
    this.instanceId,
    required this.groupIndex,
    required this.memberIndex,
    this.threshold = legacyThreshold,
    this.shareCount = legacyShareCount,
    required this.salt,
    this.kdf = ShareKdf.pbkdf2,
    required this.ciphertext,
    required this.createdAt,
    this.labelsSealed = false,
  });

  bool get _isTwoOfThree =>
      threshold == legacyThreshold && shareCount == legacyShareCount;

  /// True when [other] is the same share of the same backup.
  ///
  /// **Identity is the set and the indices, never the ciphertext.** The same
  /// share sealed twice produces different bytes — a fresh salt and a fresh
  /// nonce each time — so comparing ciphertexts would count one share as two
  /// and satisfy a threshold that was never met.
  bool isSameShareAs(SealedShare other) =>
      setId == other.setId &&
      groupIndex == other.groupIndex &&
      memberIndex == other.memberIndex;

  Map<String, dynamic> toJson() => {
        // **The derivation decides the number before the arrangement does.** A
        // build that reads only PBKDF2 must not take an Argon2id share for one
        // of its own — it would derive the wrong key and call the right
        // password wrong — so every Argon2id share is [argon2idVersion], which
        // that build reports as made by a newer Smartable.
        'v': kdf.isArgon2id
            ? (labelsSealed ? labelBoundVersion : argon2idVersion)
            : (_isTwoOfThree ? version : thresholdVersion),
        'set': setId,
        // **Written only when there is one, and the version stays at 1.**
        // Bumping it would make every share this app has already written
        // unreadable by this build and every share it writes now unreadable by
        // the last one — for a field that is additive. An older build ignores
        // a key it does not know and goes on grouping by the set id, which is
        // what it did before and is no worse than it was.
        if (instanceId != null) 'bid': instanceId,
        'g': groupIndex,
        'm': memberIndex,
        // Written on version 1 as well, where they can only say two of three.
        // A build from before them ignores both keys, which is correct there.
        't': threshold,
        'n': shareCount,
        'salt': salt,
        if (kdf.isArgon2id) 'kdf': kdf.toJson(),
        'ct': ciphertext,
        'at': createdAt.toUtc().toIso8601String(),
      };

  /// A share whose key is Argon2id's ([ShareKdf]), whatever its arrangement:
  /// the body carries `t` and `n` as [thresholdVersion] does, and a `kdf`
  /// object with the derivation's three numbers.
  ///
  /// **The number reserved for audit item M5** — a share stretched with
  /// Argon2id — and this is the half of M5 that is built. Under which secret
  /// it is sealed is the creating flow's business: today the wallet's
  /// password, held to `PasswordPolicy` before anything is sealed. A build
  /// from before this reads a body of this number as [isNewerFormat], never as
  /// "no share here".
  static const int argon2idVersion = 3;

  /// A share of [argon2idVersion] whose labels are sealed with it: the body is
  /// the same, and the ciphertext holds the mnemonic and a copy of `n`, `bid`
  /// and `at`, which [open] holds the readable ones to.
  ///
  /// **Why a copy inside rather than AES-GCM's associated data**, which binds
  /// just as hard: with associated data an edited label fails the tag, and a
  /// failed tag is what a wrong password looks like — so somebody typing the
  /// right password would be told it was wrong, on the screen they are
  /// restoring from. A copy inside decrypts with the right password and then
  /// disagrees, which is [Slip39Altered]: "this file was changed", the truth.
  /// Raised as audit S7's last item, 11 October 2026; built on the owner's go
  /// of 13 October.
  ///
  /// A build from before it reads a body of this number as [isNewerFormat],
  /// and a body relabelled down to [argon2idVersion] does not slip past the
  /// check: its plaintext is not a share, and [open] refuses it as one.
  static const int labelBoundVersion = 4;

  /// The first version this build does not read.
  static const int firstUnreadVersion = labelBoundVersion + 1;

  /// Whether [value] is a share body written by a newer version of this app
  /// than this build reads.
  ///
  /// **Said rather than skipped.** [fromJson] answers null for it, as for
  /// anything it cannot read whole, and a store that dropped every null
  /// showed somebody whose backup a newer build had made "no share here" —
  /// on the screen they were restoring from. Only the version is looked at:
  /// nothing else in a body this build does not understand is believed.
  static bool isNewerFormat(Object? value) {
    if (value is! Map) return false;
    final v = value['v'];
    return v is int && v >= firstUnreadVersion;
  }

  /// Null for anything this build cannot read whole.
  static SealedShare? fromJson(Object? value) {
    if (value is! Map) return null;
    final v = value['v'];
    if (v != version &&
        v != thresholdVersion &&
        v != argon2idVersion &&
        v != labelBoundVersion) {
      return null;
    }
    final scheme = _schemeOf(v as int, value['t'], value['n']);
    if (scheme == null) return null;
    // **Argon2id's numbers are read, and held to bounds, before anything is
    // derived.** They are as editable as every other label; a body asking
    // for a gigabyte would take the phone's memory, and one that is not a
    // derivation this build knows is refused rather than guessed at.
    final ShareKdf kdf;
    if (v == argon2idVersion || v == labelBoundVersion) {
      final read = ShareKdf.fromJson(value['kdf']);
      if (read == null) return null;
      kdf = read;
    } else {
      if (value['kdf'] != null) return null;
      kdf = ShareKdf.pbkdf2;
    }
    final setId = value['set'];
    final salt = value['salt'];
    final ciphertext = value['ct'];
    final group = value['g'];
    final member = value['m'];
    if (setId is! String ||
        salt is! String ||
        ciphertext is! String ||
        group is! int ||
        member is! int) {
      return null;
    }
    // **Present and unreadable is a refusal, not a fallback.** Treating a
    // malformed identifier as absent would quietly file the share under its
    // fifteen-bit set id and group it with a backup it may have nothing to do
    // with — which is the failure this field exists to remove.
    final instanceId = value['bid'];
    if (instanceId != null &&
        (instanceId is! String || !_instancePattern.hasMatch(instanceId))) {
      return null;
    }

    final at = DateTime.tryParse(value['at'] as String? ?? '');
    return SealedShare(
      setId: setId,
      instanceId: instanceId as String?,
      groupIndex: group,
      memberIndex: member,
      threshold: scheme.threshold,
      shareCount: scheme.count,
      salt: salt,
      kdf: kdf,
      ciphertext: ciphertext,
      // A backup with no readable date is still a backup. Losing the label
      // must not lose the share — on a share that does not seal its date. One
      // that does is held to it in [open], so an unreadable date there reads
      // as the edit it is.
      createdAt: at ?? DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      labelsSealed: v == labelBoundVersion,
    );
  }

  /// The threshold and count a body of version [v] declares, or null when it
  /// declares something this build will not read.
  ///
  /// **Version 1 may only say two of three.** A version 1 body claiming three
  /// is one an older build would still read as two, and it was not written by
  /// anything here. Version 2 must say both numbers, because without them it is
  /// exactly the share an older build would have misread.
  ///
  /// Shared with `PaperShareStore`, whose note carries the same two numbers
  /// and must refuse the same things.
  static ({int threshold, int count})? schemeOf(Object? t, Object? n,
      {required bool legacyAllowed}) {
    if (t == null && n == null && legacyAllowed) {
      return (threshold: legacyThreshold, count: legacyShareCount);
    }
    if (t is! int || n is! int) return null;
    if (t < 2 || t > n || n > maxShareCount) return null;
    return (threshold: t, count: n);
  }

  static ({int threshold, int count})? _schemeOf(int v, Object? t, Object? n) {
    if (v == version) {
      if (t == null && n == null) {
        return (threshold: legacyThreshold, count: legacyShareCount);
      }
      if (t != legacyThreshold || n != legacyShareCount) return null;
      return (threshold: legacyThreshold, count: legacyShareCount);
    }
    return schemeOf(t, n, legacyAllowed: false);
  }

  /// Seals [mnemonic] under [password].
  ///
  /// The share is decoded first, and that is not a formality: it is what fills
  /// [setId] and the indices from the share's own bytes rather than from
  /// whatever the caller believed, and it refuses a mnemonic that is damaged
  /// **before** it is stored. A backup that turns out to be unreadable is
  /// discovered at the worst possible moment.
  ///
  /// [shareCount] is the one label the share cannot supply — see [shareCount]
  /// — so it is required rather than defaulted: a three-of-five share sealed
  /// with the default would be labelled three of three.
  /// What a test that is not about the key derivation seals under, in place
  /// of [ShareKdf.current] — null everywhere else.
  ///
  /// **Why it exists.** Each Argon2id derivation at 64 MiB spawns four
  /// isolates, and a test's timeout does not stop them. In a full parallel
  /// run on the development Mac, test files that seal and open many shares
  /// ran out of time together, and the isolates left running slowed the next
  /// ones until whole files failed (12 October 2026). The stores, backups and
  /// screens are about where shares go, not how hard a key is to guess, so
  /// they seal under [ShareKdf.cheapestReadable]; `sealed_share_test` and
  /// `crypto_utils_argon2id_test` keep the real setting.
  ///
  /// **Honoured in a debug build only.** [_debugBuild] is a compile-time
  /// constant false in release and profile builds, so the compiler removes the
  /// branch that reads this and a shipped app seals under [ShareKdf.current]
  /// whatever is assigned here; the analyser refuses an assignment outside a
  /// test, and `sealed_share_test` holds that no file under `lib/` makes one.
  @visibleForTesting
  static ShareKdf? debugSealingKdf;

  static const bool _debugBuild = !bool.fromEnvironment('dart.vm.product') &&
      !bool.fromEnvironment('dart.vm.profile');

  static Future<SealedShare> seal({
    required String mnemonic,
    required String password,
    required int shareCount,
    String? backupId,
    DateTime? now,
  }) async {
    final share = decodeShare(mnemonic);
    // **Refused before a key is derived**, for the same reason a damaged share
    // is: a label this build will not read back is a share nobody can restore.
    if (schemeOf(share.memberThreshold, shareCount, legacyAllowed: false) ==
            null ||
        share.memberIndex >= shareCount) {
      throw const Slip39Invalid(
          'This share does not fit the backup it is being filed under.');
    }
    final salt = CryptoUtils.randomKey();
    final kdf = (_debugBuild ? debugSealingKdf : null) ?? ShareKdf.current;
    final key = await kdf.derive(password, salt);
    final createdAt = (now ?? DateTime.now()).toUtc();
    // The labels the share cannot vouch for, sealed beside it — see
    // [labelBoundVersion].
    final sealed = jsonEncode(_sealedLabels(
      mnemonic: mnemonic,
      instanceId: backupId,
      shareCount: shareCount,
      createdAt: createdAt,
    ));
    return SealedShare(
      setId: share.setIdHex,
      instanceId: backupId,
      groupIndex: share.groupIndex,
      memberIndex: share.memberIndex,
      threshold: share.memberThreshold,
      shareCount: shareCount,
      salt: base64Encode(salt),
      kdf: kdf,
      ciphertext: base64Encode(CryptoUtils.encrypt(sealed, key)),
      createdAt: createdAt,
      labelsSealed: true,
    );
  }

  /// What a share of [labelBoundVersion] seals: the words under `w`, and the
  /// three labels as its body writes them.
  static Map<String, Object?> _sealedLabels({
    required String mnemonic,
    required String? instanceId,
    required int shareCount,
    required DateTime createdAt,
  }) =>
      {
        'w': mnemonic,
        'bid': instanceId,
        'n': shareCount,
        'at': createdAt.toUtc().toIso8601String(),
      };

  /// The mnemonic, or a throw.
  ///
  /// **A wrong password and a corrupted share both land here, and they are not
  /// the same situation** — one says try again, the other says this copy is
  /// gone and use another. AES-GCM cannot tell them apart (both are a failed
  /// tag), so the distinction that *is* available is made: bytes that decrypt
  /// but are not a valid share are corruption, and a failed tag is reported as
  /// the more likely and more actionable of the two.
  Future<String> open(String password) async {
    final Uint8List key;
    try {
      key = await kdf.derive(password, base64Decode(salt));
    } catch (_) {
      throw const Slip39Damaged();
    }
    String mnemonic;
    try {
      mnemonic = CryptoUtils.decrypt(base64Decode(ciphertext), key);
    } catch (_) {
      throw const Slip39WrongPassword();
    }
    if (labelsSealed) mnemonic = _heldToSealedLabels(mnemonic);
    // Decrypting is not the same as having a share. A tampered ciphertext
    // fails the tag; a share stored by a build with a different idea of the
    // format would decrypt into something that is not a share at all.
    final share = decodeShare(mnemonic);
    if (share.setIdHex != setId ||
        share.groupIndex != groupIndex ||
        share.memberIndex != memberIndex ||
        share.memberThreshold != threshold) {
      // The plaintext labels and the sealed share disagree, which means the
      // labels were edited. Trust the share, refuse the file.
      //
      // **The threshold is among them.** A label lowered from three to two
      // would otherwise have a three-of-five backup counted complete with two
      // shares, on the screen that tells somebody whether they are safe.
      throw const Slip39Altered();
    }
    return mnemonic;
  }

  /// The words of a share of [labelBoundVersion], once its readable labels
  /// have been held to the copy sealed beside them.
  ///
  /// **Altered, not wrong password**, when they disagree: this plaintext
  /// decrypted, so the password was right, and what differs is the file.
  /// A plaintext that is not the sealed shape at all is damage.
  String _heldToSealedLabels(String plaintext) {
    final Object? inner;
    try {
      inner = jsonDecode(plaintext);
    } catch (_) {
      throw const Slip39Damaged();
    }
    if (inner is! Map || inner['w'] is! String) throw const Slip39Damaged();
    final expected = _sealedLabels(
      mnemonic: inner['w'] as String,
      instanceId: instanceId,
      shareCount: shareCount,
      createdAt: createdAt,
    );
    for (final label in const ['bid', 'n', 'at']) {
      if (inner[label] != expected[label]) throw const Slip39Altered();
    }
    return inner['w'] as String;
  }
}

/// How a share's key is derived from the password and its salt.
///
/// **Two kinds and no more.** [pbkdf2] is every share sealed before
/// 11 October 2026 — `CryptoUtils.deriveKey`, 600,000 rounds — and has no
/// numbers of its own because it never had a choice. [current] is what this
/// build seals with. A body states Argon2id's numbers rather than leaving them
/// to the build that opens it, so a later build may ask for more without a new
/// format, and an earlier one opens what a later one wrote while the numbers
/// stay within [fromJson]'s bounds.
class ShareKdf {
  const ShareKdf._pbkdf2()
      : isArgon2id = false,
        memoryKiB = 0,
        iterations = 0,
        parallelism = 0;

  const ShareKdf.argon2id({
    required this.memoryKiB,
    required this.iterations,
    required this.parallelism,
  }) : isArgon2id = true;

  /// PBKDF2-HMAC-SHA256, 600,000 rounds: shares of [SealedShare.version] and
  /// [SealedShare.thresholdVersion].
  static const ShareKdf pbkdf2 = ShareKdf._pbkdf2();

  /// What a share is sealed with now: RFC 9106's second recommended setting
  /// for Argon2id — 64 MiB, three passes, four lanes.
  static const ShareKdf current =
      ShareKdf.argon2id(memoryKiB: 65536, iterations: 3, parallelism: 4);

  /// The most memory a body may ask for: 256 MiB. Above it a phone may not
  /// have it to give, and an edited label is not a reason to try.
  static const int maxMemoryKiB = 262144;

  /// The least: 8 MiB. Below it the derivation is not one this app wrote.
  static const int minMemoryKiB = 8192;

  /// The cheapest Argon2id setting [fromJson] still reads: 8 MiB, one pass,
  /// one lane. For [SealedShare.debugSealingKdf] in tests, never for a share
  /// anybody keeps.
  @visibleForTesting
  static const ShareKdf cheapestReadable =
      ShareKdf.argon2id(memoryKiB: minMemoryKiB, iterations: 1, parallelism: 1);

  final bool isArgon2id;
  final int memoryKiB;
  final int iterations;
  final int parallelism;

  /// The key for [password] and [salt].
  Future<Uint8List> derive(String password, List<int> salt) => isArgon2id
      ? CryptoUtils.deriveKeyArgon2id(password, salt,
          memoryKiB: memoryKiB,
          iterations: iterations,
          parallelism: parallelism)
      : CryptoUtils.deriveKey(password, salt);

  Map<String, Object> toJson() => {
        'alg': 'argon2id',
        'm': memoryKiB,
        't': iterations,
        'p': parallelism,
      };

  /// An Argon2id `kdf` object within bounds, or null.
  static ShareKdf? fromJson(Object? value) {
    if (value is! Map || value['alg'] != 'argon2id') return null;
    final m = value['m'];
    final t = value['t'];
    final p = value['p'];
    if (m is! int || t is! int || p is! int) return null;
    if (p < 1 || p > 8) return null;
    if (t < 1 || t > 16) return null;
    if (m < minMemoryKiB || m > maxMemoryKiB || m < 8 * p) return null;
    return ShareKdf.argon2id(memoryKiB: m, iterations: t, parallelism: p);
  }
}
