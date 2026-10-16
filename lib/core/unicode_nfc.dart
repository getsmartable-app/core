import 'package:unorm_dart/unorm_dart.dart' as unorm;

/// Unicode Normalization Form C, for the one place in this wallet where the
/// spelling of a character decides a key.
///
/// **Why a wallet normalizes at all.** `é` is two different strings. One is
/// U+00E9; the other is `e` followed by U+0301, a combining acute. They are
/// the same character on screen, in every font, at every size — and
/// `utf8.encode` gives them different bytes, so PBKDF2 gives them different
/// keys. Which of the two a keyboard produces is the keyboard's business:
/// macOS input methods have historically emitted the decomposed form, iOS and
/// Android emit the composed one, and a person who sets a password on one
/// device and types it on another has no way to see the difference, no way to
/// describe it, and no way back into their wallet.
///
/// So the bytes are taken from one canonical spelling instead of from whatever
/// arrived. NFC is the composed form — the shorter one, and the one the web
/// platform, most keyboards and most password managers already produce, which
/// makes it the choice that changes the fewest passwords.
///
/// **What it deliberately does not do.** Nothing here trims, lowercases, folds
/// case or applies NFKC. Those all merge characters that are genuinely
/// different: a leading space is a character somebody chose, `A` and `a` are
/// two letters, and NFKC would make full-width `Ａ` and `A` the same password.
/// NFC merges only spellings that Unicode itself defines as the same
/// character, which is exactly the set where the person cannot tell and the
/// bytes can. `tool/unicode_nfc_check.dart` holds the package to that: it
/// fails if `nfc` ever trims, folds case or compatibility-composes.
///
/// **The normalizer is `unorm_dart`, not ours.** A normalization engine
/// written inside a wallet is a normalization engine nobody else is reading,
/// and the whole of it would sit in the path that decides a key. What this
/// file keeps is the decision — which form, on which secrets, with which
/// exclusions — and one call.
///
/// The package is pinned to an exact version in `pubspec.yaml` for the same
/// reason: a patch release of a normalizer can change what bytes a password
/// becomes. It moves when `tool/unicode_nfc_check.dart` has passed against the
/// new one.
///
/// `unorm_dart` is MIT, copyright 2018 Yasuhiro Shimizu, and is a Dart port of
/// `walling/unorm`. Its licence text reaches every user through the
/// application's aggregated `NOTICES`, which Settings → About →
/// Open-source licences renders; it is named in `THIRD_PARTY_NOTICES.md`
/// rather than left to that aggregate, because a reviewer of this file should
/// not have to resolve a package to learn whose code touches a password.
///
/// **It is not conformant in one place, and that place is repaired here.** See
/// [_hangulDefect].
///
/// **Stability.** Unicode's normalization stability policy guarantees that the
/// normalized form of an already-assigned character never changes, and that
/// unassigned code points normalize to themselves. A newer Unicode version
/// therefore cannot start deriving a different key for a password somebody has
/// already set; it can only add mappings for characters that did not exist
/// when the password was typed.
String toNfc(String value) {
  if (_isAscii(value)) return value;
  if (!value.contains(_hangulDefect)) return unorm.nfc(value);
  // Normalised around the character rather than through it. Splitting is sound
  // because the character is inert on both sides — see [_hangulDefect].
  return value.split(_hangulDefect).map(unorm.nfc).join(_hangulDefect);
}

/// U+D7A4, the one code point `unorm_dart` 0.3.2 does not normalise correctly.
///
/// **The defect.** `uchar.dart` guards the Hangul syllable block with
/// `_SBase + _SCount < cp` where the standard says `<=`, so exactly one code
/// point falls through into the syllable branch: U+D7A4, the first
/// *unassigned* one past the last syllable, U+D7A3. It is decomposed as though
/// it were a syllable, into U+1113 and U+1161 — and U+1113 is an archaic jamo
/// with no composition back, so the character does not survive its own
/// normalization. It also acquires a composition table on the way through, so
/// U+D7A4 followed by a trailing jamo composes into another unassigned code
/// point. Both halves of the defect need the character to be present, and
/// nothing else in the package's tables reaches it.
///
/// **Why splitting repairs it rather than covering it.** In correct NFC an
/// unassigned code point is inert: it has no canonical decomposition, its
/// combining class is zero, and it appears in no composition pair as either
/// half. So it cannot merge with a neighbour, it cannot be reordered, and —
/// being a starter — it ends the combining sequence before it and begins the
/// one after. Normalising the text on each side of it and putting it back is
/// therefore the same operation as normalising through it, and it is what
/// keeps the character away from both halves of the defect at once.
///
/// **Why repair it at all, for a character no keyboard can produce.** Because
/// the alternative is a canonical rule with an exception in it, and an
/// exception in the rule that decides a key is a thing somebody has to keep
/// remembering. `tool/unicode_nfc_check.dart` proves the repair over every
/// code point the Consortium's file does not list — 1,094,978 of them — and
/// holds the package's own behaviour to exactly this one deviation, so the day
/// it is fixed upstream we are told rather than left carrying a workaround
/// nobody can date.
///
/// **Two counts, kept apart.** `unorm_dart` upstream has one known deviation.
/// This wrapper, over everything `tool/unicode_nfc_check.dart` covers, has
/// zero observed deviations — "observed" meant literally: it is what those
/// checks looked at, not a proof that nothing else exists. The tool prints
/// them as two lines for that reason, because one number would read as though
/// the wallet still carried the defect.
///
/// This changes no derived key either way: the repaired normalizer already
/// agrees with what a fixed `unorm_dart` would produce.
// Written as an escape rather than as the character: it is unassigned, so
// what an editor or a terminal does with it is not predictable.
const String _hangulDefect = '\ud7a4';

/// **An ASCII password never reaches the normalizer at all**, and its bytes
/// are therefore unchanged by construction rather than by testing: no ASCII
/// character has a canonical decomposition, none carries a combining class,
/// and none can be the second half of a composition, so a string of them
/// already is its own NFC.
///
/// Note the asymmetry that makes the *whole-string* test necessary rather than
/// a per-character one: `<` (U+003C) *is* the first half of a composition,
/// with U+0338 producing `≮`. "This character is ASCII" would be the wrong
/// question; "every one of them is" is not.
///
/// `unicode_nfc_check.dart` proves the claim by brute force — every ASCII
/// character and every ASCII pair — rather than leaving it as an argument.
///
/// Code units are tested rather than runes because 0x80 is below the surrogate
/// range: any string holding a character outside the Basic Multilingual Plane
/// fails this test on its surrogates and goes the long way.
bool _isAscii(String value) {
  for (final unit in value.codeUnits) {
    if (unit >= 0x80) return false;
  }
  return true;
}
