import 'package:blockchain_utils/blockchain_utils.dart'
    show HMAC, QuickCrypto, SHA256;

import 'crypto_utils.dart';
import 'slip39_wordlist.dart';

/// SLIP-39: splitting a secret into shares, any threshold of which restore it.
///
/// **Why this is written as a pure function with nothing calling it.** Getting
/// a share scheme wrong does not produce an error — it produces a *different*
/// valid secret. Two shares from unrelated sets, or one share with a
/// transcription slip, would reconstruct thirty-two perfectly well-formed
/// bytes, derive perfectly well-formed addresses, and show an empty wallet
/// belonging to nobody. There is no symptom before the money is unreachable.
/// The same reasoning built `zip244.dart` and `ledger_apdu.dart` bottom-up,
/// and for the same reason this is pinned to **SatoshiLabs' own published
/// vectors** before anything is allowed to depend on it.
///
/// **The standard is used rather than a hand-rolled Shamir**, and the checksum
/// is why. Plain secret sharing over GF(256) is a short function; what it does
/// not give you is any way to notice that the shares you combined do not
/// belong together. SLIP-39 adds a Reed-Solomon checksum over each share, an
/// identifier shared by a set, and a digest share that verifies the
/// reconstruction — three independent guards against the one failure that is
/// otherwise silent.
///
/// Terms, because two thresholds are easy to confuse: a *group* has its own
/// member threshold, and the *group threshold* says how many groups must be
/// satisfied. This wallet's case is the simple one — a single group, 2 of 3 —
/// but the general form is what the vectors exercise, so it is what is
/// implemented.

/// Thrown for every refusal, so a caller matches on the type rather than on a
/// sentence — the rule `WrongPassword` and `ChainException` already follow
/// here. A share that does not belong is a different situation from a
/// threshold that is not met, and the screens for them say different things.
///
/// **Sealed, because for a while it was one type carrying a sentence and the
/// rule above could not actually be followed.** Every refusal in this file,
/// in `sealed_share.dart` and in `share_backup.dart` was the same class with
/// different words in it, so [ShareBackup.restore] — which genuinely has to
/// tell a wrong password from a damaged copy — had nothing to match on but the
/// words:
///
/// ```dart
/// if (e.toString().contains('Wrong password')) wrongPassword = true;
/// ```
///
/// That is the exact shape `WrongPassword` was made a type to remove, in a
/// file that never got the fix. Rewording one throw would have silently turned
/// "that password does not open this backup" into "shares from 2 places are
/// needed" — sending somebody to hunt for a lost copy over a typo — and
/// "This backup has been altered" was never told apart from a store that was
/// offline at all.
///
/// Four cases, because four is what a caller branches on. The many ways a
/// share can fail to be a share are one situation with one answer, and they
/// stay one case.
sealed class Slip39Exception implements Exception {
  final String message;
  const Slip39Exception(this.message);
  @override
  String toString() => 'Slip39Exception: $message';
}

/// This is not a valid share, phrase or set: a word outside the wordlist, a
/// failed checksum, a length that cannot be a share, two shares carrying one
/// index, a threshold that cannot be met, a split nobody could perform.
///
/// **One case on purpose.** They differ in what to say and not in what to do:
/// the answer to every one of them is that these words are not the backup, so
/// find the right ones. [message] carries which it was.
final class Slip39Invalid extends Slip39Exception {
  const Slip39Invalid(super.message);
}

/// The password did not open this sealed share.
///
/// **The one a person can fix by typing again**, and the reason this hierarchy
/// exists: it has to survive being counted across several stores without
/// being confused with a copy that is simply unreadable.
final class Slip39WrongPassword extends Slip39Exception {
  const Slip39WrongPassword(
      [super.message = 'Wrong password for this backup.']);
}

/// The sealed bytes cannot be read at all — the salt, the ciphertext or the
/// key derivation is gone.
///
/// Not a wrong password: nothing about retyping helps, and the answer is a
/// different copy.
final class Slip39Damaged extends Slip39Exception {
  const Slip39Damaged([super.message = 'This backup is damaged.']);
}

/// The plaintext labels and the share sealed underneath them disagree.
///
/// **Somebody edited the file**, and it is the only one of the four that is a
/// statement about a person rather than about bytes. It reaches here only
/// after the password worked, so it is never a guess.
final class Slip39Altered extends Slip39Exception {
  const Slip39Altered([super.message = 'This backup has been altered.']);
}

/// The number of words that carry the checksum.
const int _checksumWords = 3;

/// Words of metadata before the share value: identifier, extendable flag,
/// iteration exponent, the two group fields, the two member fields.
const int _metadataWords = 4;

const int _idBits = 15;
const int _extendableBits = 1;
const int _iterationExpBits = 4;

/// The share indices reserved by the standard.
///
/// The secret sits at 255 and the digest at 254, so an ordinary member index
/// can never collide with either.
const int _digestIndex = 254;
const int _secretIndex = 255;

const int _digestLengthBytes = 4;

/// Feistel rounds, and the iteration count they divide between them.
const int _roundCount = 4;
const int _baseIterationCount = 10000;

/// The two customisation strings, which keep one form's checksums from
/// validating the other's.
const List<int> _customizationOrig = [115, 104, 97, 109, 105, 114]; // "shamir"
const List<int> _customizationExtendable = [
  115, 104, 97, 109, 105, 114, 95, // "shamir_"
  101, 120, 116, 101, 110, 100, 97, 98, 108, 101, // "extendable"
];

// --------------------------------------------------------------- GF(256)

/// Exponent and logarithm tables for the AES field, x^8 + x^4 + x^3 + x + 1.
///
/// Built once at first use rather than written out: a 511-entry literal is a
/// table nobody can check by eye, and the construction is four lines that the
/// vectors then verify end to end.
class _Gf256 {
  static final List<int> exp = List<int>.filled(255, 0);
  static final List<int> log = List<int>.filled(256, 0);
  static bool _built = false;

  static void build() {
    if (_built) return;
    var poly = 1;
    for (var i = 0; i < 255; i++) {
      exp[i] = poly;
      log[poly] = i;
      // Multiply by the polynomial x + 1.
      poly = (poly << 1) ^ poly;
      if (poly & 0x100 != 0) poly ^= 0x11B;
    }
    _built = true;
  }
}

/// Lagrange interpolation of [shares] at [x], byte by byte.
///
/// [shares] is a list of `(index, value)` pairs, all values the same length.
List<int> _interpolate(List<(int, List<int>)> shares, int x) {
  _Gf256.build();
  final xs = shares.map((s) => s.$1).toSet();
  if (xs.length != shares.length) {
    throw const Slip39Invalid('Two shares carry the same index.');
  }
  final length = shares.first.$2.length;
  for (final share in shares) {
    if (share.$2.length != length) {
      throw const Slip39Invalid('Shares are of different lengths.');
    }
    if (share.$1 == x) return List<int>.from(share.$2);
  }

  var logProd = 0;
  for (final share in shares) {
    logProd += _Gf256.log[share.$1 ^ x];
  }

  final result = List<int>.filled(length, 0);
  for (final share in shares) {
    var logBasis = logProd - _Gf256.log[share.$1 ^ x];
    for (final other in shares) {
      logBasis -= _Gf256.log[share.$1 ^ other.$1];
    }
    logBasis %= 255;
    if (logBasis < 0) logBasis += 255;
    for (var i = 0; i < length; i++) {
      final v = share.$2[i];
      if (v != 0) {
        result[i] ^= _Gf256.exp[(_Gf256.log[v] + logBasis) % 255];
      }
    }
  }
  return result;
}

// ------------------------------------------------------------- checksum

const List<int> _rs1024Gen = [
  0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009,
  0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120,
];

int _rs1024Polymod(List<int> values) {
  var chk = 1;
  for (final v in values) {
    final b = chk >> 20;
    chk = ((chk & 0xFFFFF) << 10) ^ v;
    for (var i = 0; i < 10; i++) {
      if ((b >> i) & 1 != 0) chk ^= _rs1024Gen[i];
    }
  }
  return chk;
}

List<int> _customization(bool extendable) =>
    extendable ? _customizationExtendable : _customizationOrig;

/// Whether [indices] — the whole share including its checksum — is intact.
bool _checksumIsValid(List<int> indices, bool extendable) =>
    _rs1024Polymod([..._customization(extendable), ...indices]) == 1;

List<int> _checksumFor(List<int> data, bool extendable) {
  final values = [..._customization(extendable), ...data, 0, 0, 0];
  final polymod = _rs1024Polymod(values) ^ 1;
  return [
    for (var i = 0; i < _checksumWords; i++)
      (polymod >> (10 * (2 - i))) & 1023,
  ];
}

// ------------------------------------------------------------ encryption

List<int> _roundFunction(
  int i,
  List<int> passphrase,
  int exponent,
  List<int> salt,
  List<int> r,
) {
  return QuickCrypto.pbkdf2DeriveKey(
    password: [i, ...passphrase],
    salt: [...salt, ...r],
    iterations: (_baseIterationCount << exponent) ~/ _roundCount,
    hash: () => SHA256(),
    dklen: r.length,
  );
}

/// The salt binds a share set to its identifier — **except when it does not**,
/// which is the whole of the extendable flag. An extendable backup uses an
/// empty salt, so the same secret can later be re-split under a new identifier
/// and the old shares still decrypt. That is a property somebody chooses at
/// creation and cannot change afterwards.
List<int> _salt(int identifier, bool extendable) => extendable
    ? const []
    : [..._customizationOrig, (identifier >> 8) & 0xFF, identifier & 0xFF];

List<int> _xor(List<int> a, List<int> b) =>
    [for (var i = 0; i < a.length; i++) a[i] ^ b[i]];

List<int> _cipher(
  List<int> secret,
  List<int> passphrase,
  int exponent,
  int identifier,
  bool extendable, {
  required bool decrypt,
}) {
  var l = secret.sublist(0, secret.length ~/ 2);
  var r = secret.sublist(secret.length ~/ 2);
  final salt = _salt(identifier, extendable);
  final rounds = [for (var i = 0; i < _roundCount; i++) i];
  for (final i in decrypt ? rounds.reversed : rounds) {
    final next = _xor(l, _roundFunction(i, passphrase, exponent, salt, r));
    l = r;
    r = next;
  }
  return [...r, ...l];
}

// ---------------------------------------------------------------- shares

/// One share, decoded from its words.
class Slip39Share {
  /// Identifies the set this share was made in. Shares with different
  /// identifiers are from different splits and must never be combined.
  final int identifier;

  /// Whether the set was created as extendable — see [_salt].
  final bool extendable;

  final int iterationExponent;
  final int groupIndex;
  final int groupThreshold;
  final int groupCount;
  final int memberIndex;
  final int memberThreshold;
  final List<int> value;

  const Slip39Share({
    required this.identifier,
    required this.extendable,
    required this.iterationExponent,
    required this.groupIndex,
    required this.groupThreshold,
    required this.groupCount,
    required this.memberIndex,
    required this.memberThreshold,
    required this.value,
  });

  /// The identifier as the four hex digits every store and label uses, so one
  /// formatting of it exists rather than three that can disagree.
  String get setIdHex => identifier.toRadixString(16).padLeft(4, '0');

  /// Everything except [value] and [memberIndex] — the fields every share in a
  /// set must agree on.
  List<Object> get _setIdentity => [
        identifier,
        extendable,
        iterationExponent,
        groupThreshold,
        groupCount,
      ];
}

List<int> _wordsToIndices(String mnemonic) {
  final words = mnemonic.trim().toLowerCase().split(RegExp(r'\s+'));
  return [
    for (final word in words)
      () {
        final index = kSlip39Wordlist.indexOf(word);
        if (index < 0) {
          throw Slip39Invalid('"$word" is not a SLIP-39 word.');
        }
        return index;
      }()
  ];
}

/// The shortest a share can be: the seven metadata words plus enough words to
/// carry a 128-bit secret.
const int _minShareWords = _metadataWords + _checksumWords + 13;

/// Reads a share's ten-bit words back into its fields.
///
/// **Refuses before it interprets.** Length, checksum and padding are all
/// checked ahead of any field being believed, because every one of them is a
/// way to arrive at a plausible wrong secret rather than at an error.
Slip39Share decodeShare(String mnemonic) {
  final indices = _wordsToIndices(mnemonic);
  if (indices.length < _minShareWords) {
    throw const Slip39Invalid('This share is too short to be complete.');
  }

  // The first two words are twenty bits: identifier, the extendable flag, and
  // the iteration exponent. The flag has to be read before the checksum can be
  // verified, because it decides which customisation string the checksum was
  // built with — so it is read out of data that is not yet trusted, and a
  // wrong guess simply fails the check below.
  final idExp = (indices[0] << 10) | indices[1];
  final identifier = idExp >> (_extendableBits + _iterationExpBits);
  final extendable = ((idExp >> _iterationExpBits) & 1) == 1;
  final iterationExponent = idExp & ((1 << _iterationExpBits) - 1);

  if (!_checksumIsValid(indices, extendable)) {
    throw const Slip39Invalid(
        'This share is damaged — a word is wrong or missing.');
  }

  // The next two words are five four-bit fields.
  final groupMember = (indices[2] << 10) | indices[3];
  final groupIndex = (groupMember >> 16) & 0xF;
  final groupThreshold = ((groupMember >> 12) & 0xF) + 1;
  final groupCount = ((groupMember >> 8) & 0xF) + 1;
  final memberIndex = (groupMember >> 4) & 0xF;
  final memberThreshold = (groupMember & 0xF) + 1;

  if (groupCount < groupThreshold) {
    throw const Slip39Invalid(
        'This share claims more groups are needed than exist.');
  }

  // Everything between the metadata and the checksum is the value, padded at
  // the *front* to a whole number of words. The value must be a whole number
  // of bytes and an even one — it is split in half by the cipher — which is
  // what makes the modulus 16 rather than 8.
  final valueWords =
      indices.sublist(_metadataWords, indices.length - _checksumWords);
  final padding = (valueWords.length * 10) % 16;
  if (padding > 8) {
    throw const Slip39Invalid('This share has an invalid length.');
  }
  final valueBytes = (valueWords.length * 10 - padding) ~/ 8;

  var acc = BigInt.zero;
  for (final w in valueWords) {
    acc = (acc << 10) | BigInt.from(w);
  }
  // The padding bits are the high ones, so a non-zero pad is exactly a value
  // too large for its own byte count. Checked rather than masked away: an
  // altered share must be refused, not quietly trimmed into a valid one.
  if (acc.bitLength > valueBytes * 8) {
    throw const Slip39Invalid('This share has invalid padding.');
  }

  final value = List<int>.filled(valueBytes, 0);
  var v = acc;
  for (var i = valueBytes - 1; i >= 0; i--) {
    value[i] = (v & BigInt.from(0xFF)).toInt();
    v >>= 8;
  }

  return Slip39Share(
    identifier: identifier,
    extendable: extendable,
    iterationExponent: iterationExponent,
    groupIndex: groupIndex,
    groupThreshold: groupThreshold,
    groupCount: groupCount,
    memberIndex: memberIndex,
    memberThreshold: memberThreshold,
    value: value,
  );
}

/// Writes a share's fields back out as words.
String encodeShare(Slip39Share share) {
  final valueBits = share.value.length * 8;
  final valueWords = (valueBits + 9) ~/ 10;

  // **The padding is at the front, so there is nothing to shift.** The value
  // occupies the low bits of the word field and the spare high bits are zero —
  // shifting it up by the padding width instead puts the pad at the end, which
  // produces a share of the right length, with a valid checksum, carrying a
  // different secret. Caught only by round-tripping the standard's own
  // examples; a writer checked against its own reader agrees with itself.
  var acc = BigInt.zero;
  for (final b in share.value) {
    acc = (acc << 8) | BigInt.from(b);
  }

  final indices = <int>[];
  var meta = 0;
  var metaBits = 0;
  void put(int value, int width) {
    meta = (meta << width) | value;
    metaBits += width;
    while (metaBits >= 10) {
      metaBits -= 10;
      indices.add((meta >> metaBits) & 1023);
      meta &= (1 << metaBits) - 1;
    }
  }

  put(share.identifier, _idBits);
  put(share.extendable ? 1 : 0, _extendableBits);
  put(share.iterationExponent, _iterationExpBits);
  put(share.groupIndex, 4);
  put(share.groupThreshold - 1, 4);
  put(share.groupCount - 1, 4);
  put(share.memberIndex, 4);
  put(share.memberThreshold - 1, 4);

  for (var i = valueWords - 1; i >= 0; i--) {
    indices.add(((acc >> (10 * i)) & BigInt.from(1023)).toInt());
  }
  indices.addAll(_checksumFor(indices, share.extendable));
  return indices.map((i) => kSlip39Wordlist[i]).join(' ');
}

// -------------------------------------------------------------- recovery

List<int> _digestFor(List<int> randomData, List<int> secret) {
  final mac = HMAC(() => SHA256(), randomData);
  mac.update(secret);
  return mac.digest().sublist(0, _digestLengthBytes);
}

/// Recovers one group's secret from [shares], all of the same group.
List<int> _recoverGroup(int threshold, List<(int, List<int>)> shares) {
  if (threshold == 1) return List<int>.from(shares.first.$2);
  final secret = _interpolate(shares, _secretIndex);
  final digestShare = _interpolate(shares, _digestIndex);
  final digest = digestShare.sublist(0, _digestLengthBytes);
  final random = digestShare.sublist(_digestLengthBytes);
  if (!_listsEqual(_digestFor(random, secret), digest)) {
    // **The one check that catches shares which are individually perfect and
    // do not belong together.** Each has a valid checksum and a matching
    // identifier; only the digest notices that the polynomial they describe is
    // not the one the secret was split on.
    throw const Slip39Invalid(
        'These shares do not belong to the same secret.');
  }
  return secret;
}

bool _listsEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Combines [mnemonics] and returns the master secret.
///
/// Throws [Slip39Exception] for every way the set can be wrong, and never
/// returns a secret it is not sure of.
List<int> recoverSecret(List<String> mnemonics, {List<int> passphrase = const []}) {
  if (mnemonics.isEmpty) {
    throw const Slip39Invalid('No shares were given.');
  }
  final shares = mnemonics.map(decodeShare).toList();

  final identity = shares.first._setIdentity;
  for (final share in shares) {
    if (!_listsEqualObjects(share._setIdentity, identity)) {
      throw const Slip39Invalid(
          'These shares are from different backups.');
    }
  }

  final byGroup = <int, List<Slip39Share>>{};
  for (final share in shares) {
    byGroup.putIfAbsent(share.groupIndex, () => []).add(share);
  }
  final groupThreshold = shares.first.groupThreshold;
  if (byGroup.length < groupThreshold) {
    throw Slip39Invalid(
        'Shares from $groupThreshold groups are needed; '
        '${byGroup.length} were given.');
  }
  if (byGroup.length > groupThreshold) {
    throw const Slip39Invalid('More groups were given than are needed.');
  }

  final groupSecrets = <(int, List<int>)>[];
  byGroup.forEach((index, groupShares) {
    final threshold = groupShares.first.memberThreshold;
    for (final s in groupShares) {
      if (s.memberThreshold != threshold) {
        throw const Slip39Invalid(
            'Shares in one group disagree about how many are needed.');
      }
    }
    if (groupShares.length != threshold) {
      throw Slip39Invalid(
          '$threshold shares are needed in group $index; '
          '${groupShares.length} were given.');
    }
    groupSecrets.add((
      index,
      _recoverGroup(threshold, [
        for (final s in groupShares) (s.memberIndex, s.value)
      ]),
    ));
  });

  final encrypted = _recoverGroup(groupThreshold, groupSecrets);
  return _cipher(
    encrypted,
    passphrase,
    shares.first.iterationExponent,
    shares.first.identifier,
    shares.first.extendable,
    decrypt: true,
  );
}

bool _listsEqualObjects(List<Object> a, List<Object> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// --------------------------------------------------------------- splitting

/// The most shares one group may hold, from the standard: the member index is
/// four bits.
const int maxShareCount = 16;

/// Source of randomness, injectable **only so a test can pin bytes**.
///
/// Everything real passes the platform's secure random. A split with
/// predictable randomness produces shares that look perfect and can be
/// reconstructed by anybody who knows the generator, so the default is the one
/// thing here that must never be convenient.
typedef RandomBytes = List<int> Function(int length);

List<int> _secureBytes(int length) => CryptoUtils.randomBytes(length);

/// Splits [secret] into [count] shares, [threshold] of which restore it.
List<(int, List<int>)> _splitSecret(
  int threshold,
  int count,
  List<int> secret,
  RandomBytes random,
) {
  if (threshold < 1) {
    throw const Slip39Invalid('A threshold of zero protects nothing.');
  }
  if (threshold > count) {
    throw const Slip39Invalid(
        'More shares would be needed than exist, so the secret would be lost.');
  }
  if (count > maxShareCount) {
    throw Slip39Invalid('At most $maxShareCount shares.');
  }

  // With a threshold of one every share *is* the secret, and there is no
  // polynomial to hide it in — so there is nothing for a digest to verify
  // either. The standard says so explicitly, and a digest here would make
  // shares no other implementation could read.
  if (threshold == 1) {
    return [for (var i = 0; i < count; i++) (i, List<int>.from(secret))];
  }

  final randomShareCount = threshold - 2;
  final shares = <(int, List<int>)>[
    for (var i = 0; i < randomShareCount; i++) (i, random(secret.length)),
  ];

  // The digest share sits at index 254 with the secret at 255, which is why an
  // ordinary member index — four bits, so at most 15 — can never collide with
  // either.
  final randomPart = random(secret.length - _digestLengthBytes);
  final base = [
    ...shares,
    (_digestIndex, [..._digestFor(randomPart, secret), ...randomPart]),
    (_secretIndex, secret),
  ];
  for (var i = randomShareCount; i < count; i++) {
    shares.add((i, _interpolate(base, i)));
  }
  return shares;
}

/// One group of a backup: how many of its shares are needed, and how many
/// there are.
class Slip39Group {
  final int threshold;
  final int count;
  const Slip39Group(this.threshold, this.count);
}

/// Splits [masterSecret] into mnemonics, one list per group.
///
/// This wallet's case is a single group of 2-of-3, but the general form is what
/// the published vectors exercise, so it is what is implemented — and what
/// lets the split be checked against the recovery that is already pinned to
/// somebody else's arithmetic.
///
/// **[extendable] defaults to true, and it is a decision somebody cannot
/// change later.** An extendable backup uses an empty cipher salt, so the same
/// secret can be split again under a new identifier and the old shares still
/// open it — which is what makes replacing a lost share possible without
/// reissuing every other copy. The cost is that the identifier no longer binds
/// the ciphertext, and for a wallet that trade is plainly worth it: the case
/// that actually happens is somebody losing one of three.
List<List<String>> splitSecret({
  required List<int> masterSecret,
  int groupThreshold = 1,
  List<Slip39Group> groups = const [Slip39Group(2, 3)],
  List<int> passphrase = const [],
  int iterationExponent = 0,
  bool extendable = true,
  RandomBytes random = _secureBytes,
}) {
  if (masterSecret.length < 16) {
    throw const Slip39Invalid('The secret is too short to be a key.');
  }
  if (masterSecret.length.isOdd) {
    // The cipher splits it in half, so an odd length has no halves.
    throw const Slip39Invalid('The secret must be an even number of bytes.');
  }
  if (groups.isEmpty || groupThreshold > groups.length) {
    throw const Slip39Invalid(
        'More groups would be needed than exist, so the secret would be lost.');
  }
  for (final group in groups) {
    if (group.threshold == 1 && group.count > 1) {
      // The standard forbids it, and the reason is worth keeping: a group of
      // several shares any *one* of which is enough is not a group, it is the
      // same secret copied — and it would be presented to somebody as though
      // it raised their threshold.
      throw const Slip39Invalid(
          'A group where one share is enough may only have one share.');
    }
  }

  // The identifier is random and names the set. Fifteen bits, so two backups
  // made on one device can collide — which is why nothing anywhere treats it
  // as a key and why the digest, not the identifier, is what proves shares
  // belong together.
  final idBytes = random(2);
  final identifier = ((idBytes[0] << 8) | idBytes[1]) & ((1 << _idBits) - 1);

  final encrypted = _cipher(
    masterSecret,
    passphrase,
    iterationExponent,
    identifier,
    extendable,
    decrypt: false,
  );

  final groupShares =
      _splitSecret(groupThreshold, groups.length, encrypted, random);

  return [
    for (final (groupIndex, groupSecret) in groupShares)
      [
        for (final (memberIndex, value) in _splitSecret(
          groups[groupIndex].threshold,
          groups[groupIndex].count,
          groupSecret,
          random,
        ))
          encodeShare(Slip39Share(
            identifier: identifier,
            extendable: extendable,
            iterationExponent: iterationExponent,
            groupIndex: groupIndex,
            groupThreshold: groupThreshold,
            groupCount: groups.length,
            memberIndex: memberIndex,
            memberThreshold: groups[groupIndex].threshold,
            value: value,
          ))
      ]
  ];
}
