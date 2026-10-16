/// What a password this wallet sets has to be.
///
/// ## Why the bar is where it is
///
/// **The password is not only a door into this phone.** It seals every share
/// of a split backup (`sealed_share.dart`): somebody who holds the shares from
/// two cloud accounts and not the password has nothing — and somebody who can
/// guess the password has the wallet. That guessing happens offline, on the
/// attacker's own hardware, where none of the unlock screen's waits apply. So
/// the password is held to what an offline guess costs, not to what typing
/// costs.
///
/// Until 11 October 2026 the rule was eight characters and nothing else, so
/// `12345678` and `password` sealed a share. Two things changed (owner's go of
/// that day on the audit's S1):
///
/// - **Twelve characters at least** ([minLength]), counted as characters a
///   person sees — Unicode scalar values after NFC, the form the key is
///   derived from ([CryptoUtils.canonicalSecretBytes]) — not as UTF-16 units,
///   which would count an emoji as two.
/// - **Not mostly a pattern** ([PasswordProblem.predictable]): a run along
///   the alphabet, the digits or a keyboard row, a repeated block, a year, or
///   one of a short list of words that guessing tools try first. What is left
///   once those are taken away has to be at least [minUnpredictable]
///   characters. `correct horse battery` passes; `password1234`,
///   `qwertyuiop12`, `aaaaaaaaaaaa` and `Summer2024!!` do not.
///
/// ## What it is not
///
/// **Not a breach corpus.** [_commonWords] is a few dozen words written here,
/// not a list taken from anybody's leak, so nothing about it needs a licence
/// and nothing in it is somebody's password. It catches the shapes people
/// reach for first; it cannot promise that what passes is strong, and the
/// screens do not say it does.
///
/// **Not applied to a password that already exists.** Unlocking, opening a
/// share and checking a password before a destructive action take what was
/// set, whatever it is: a rule that refused yesterday's password would lock
/// somebody out of their own wallet. It is applied where a password is
/// *chosen* — creating, importing, setting, changing — and where an existing
/// one is about to seal something new: a split backup (`ShareBackup.create`).
library;

import 'unicode_nfc.dart';

/// Why a password is refused.
enum PasswordProblem {
  /// Fewer than [PasswordPolicy.minLength] characters.
  tooShort,

  /// Long enough, but most of it is a pattern or a common word.
  predictable,
}

/// A password refused by [PasswordPolicy] where one was being chosen.
///
/// Typed, so that a screen says it in the reader's language
/// (`failure_wording.dart`) rather than showing [toString].
class WeakPasswordException implements Exception {
  const WeakPasswordException(this.problem);

  final PasswordProblem problem;

  @override
  String toString() => switch (problem) {
        PasswordProblem.tooShort =>
          'The password must be at least ${PasswordPolicy.minLength} characters.',
        PasswordProblem.predictable =>
          'The password is too easy to guess: most of it is a common word, a '
              'year, a run or a repeat.',
      };
}

/// The one rule every place that sets a password asks.
abstract final class PasswordPolicy {
  /// The fewest characters a new password may have.
  static const int minLength = 12;

  /// The fewest characters that must be left once patterns and common words
  /// are taken away ([unpredictableCount]).
  static const int minUnpredictable = 6;

  /// How many characters [password] has, as a person counts them: Unicode
  /// scalar values of its NFC form. Whitespace counts — a passphrase's spaces
  /// are characters somebody typed.
  static int lengthOf(String password) => toNfc(password).runes.length;

  /// Why [password] may not be set, or null when it may.
  static PasswordProblem? problemWith(String password) {
    if (lengthOf(password) < minLength) return PasswordProblem.tooShort;
    if (unpredictableCount(password) < minUnpredictable) {
      return PasswordProblem.predictable;
    }
    return null;
  }

  /// Throws [WeakPasswordException] unless [password] may be set.
  static void require(String password) {
    final problem = problemWith(password);
    if (problem != null) throw WeakPasswordException(problem);
  }

  /// The characters of [password] — whitespace not counted — that are not part
  /// of a run, a repeat, a year or a common word.
  ///
  /// Each of the four marks the characters it explains; a character explained
  /// twice is still one character. Compared lower-case, and words are looked
  /// for a second time with the usual substitutions undone (`p@ssw0rd`), on a
  /// copy of the same length so that a position means the same character in
  /// both.
  ///
  /// **Whitespace is taken out before anything is looked for**, not only left
  /// out of the count: `a b c d e f g h i j k l` is the alphabet with spaces
  /// in it, and `pass word` is the word.
  static int unpredictableCount(String password) {
    final chars = [
      for (final rune in toNfc(password).toLowerCase().runes)
        if (String.fromCharCode(rune).trim().isNotEmpty)
          String.fromCharCode(rune),
    ];
    final n = chars.length;
    final explained = List<bool>.filled(n, false);

    _markRuns(chars, explained);
    _markRepeats(chars, explained);
    _markYears(chars, explained);
    _markWords(chars, explained);
    _markWords([for (final c in chars) _unleet[c] ?? c], explained);

    var left = 0;
    for (var i = 0; i < n; i++) {
      if (!explained[i]) left++;
    }
    return left;
  }

  /// Lines a run is walked along, each read in both directions: the alphabet,
  /// the digits, and the letter rows of the keyboards this app's languages
  /// are typed on (QWERTY, QWERTZ, AZERTY and the Russian JCUKEN). The
  /// Cyrillic lines and words below are data the rule matches, not prose.
  static const List<String> _lines = [
    'abcdefghijklmnopqrstuvwxyz',
    '01234567890',
    'qwertyuiop',
    'asdfghjkl',
    'zxcvbnm',
    'qwertzuiop',
    'yxcvbnm',
    'azertyuiop',
    'qsdfghjklm',
    'wxcvbn',
    '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p',
    'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',
    'йцукенгшщзхъ',
    'фывапролджэ',
    'ячсмитьбю',
  ];

  /// Marks every stretch of three or more characters that steps one place at
  /// a time, the same way, along one of [_lines] — `abc`, `4321`, `qwerty`.
  static void _markRuns(List<String> chars, List<bool> explained) {
    final n = chars.length;
    for (final line in _lines) {
      var i = 0;
      while (i < n - 1) {
        final step = _stepAlong(line, chars[i], chars[i + 1]);
        if (step == null) {
          i++;
          continue;
        }
        var end = i + 1;
        while (end + 1 < n && _stepAlong(line, chars[end], chars[end + 1]) == step) {
          end++;
        }
        if (end - i + 1 >= 3) {
          for (var k = i; k <= end; k++) {
            explained[k] = true;
          }
        }
        i = end;
      }
    }
  }

  /// +1 or -1 when [b] is next to [a] along [line], else null. Every place [a]
  /// appears is asked: `0` is at both ends of the digits, so that `90` and
  /// `09` are both steps.
  static int? _stepAlong(String line, String a, String b) {
    for (var ia = line.indexOf(a); ia >= 0; ia = line.indexOf(a, ia + 1)) {
      if (ia + 1 < line.length && line[ia + 1] == b) return 1;
      if (ia > 0 && line[ia - 1] == b) return -1;
    }
    return null;
  }

  /// Marks a block written again straight after itself: `aaa` (one character,
  /// three times at least), `abab`, `trustno1trustno1`.
  static void _markRepeats(List<String> chars, List<bool> explained) {
    final n = chars.length;
    for (var width = 1; width <= n ~/ 2; width++) {
      for (var i = 0; i + 2 * width <= n; i++) {
        if (!_sameBlock(chars, i, i + width, width)) continue;
        var end = i + 2 * width;
        while (end + width <= n && _sameBlock(chars, i, end, width)) {
          end += width;
        }
        // One character twice is how ordinary words are spelled (`hello`,
        // `battery`); three times is not.
        if (width == 1 && end - i < 3) continue;
        for (var k = i; k < end; k++) {
          explained[k] = true;
        }
      }
    }
  }

  static bool _sameBlock(List<String> chars, int a, int b, int width) {
    for (var k = 0; k < width; k++) {
      if (chars[a + k] != chars[b + k]) return false;
    }
    return true;
  }

  /// Marks four digits that read as a year between 1900 and 2099.
  static void _markYears(List<String> chars, List<bool> explained) {
    final text = chars.join();
    // Only when every character is one code unit is a match's offset also a
    // position in [chars]; a password with characters outside the BMP has its
    // years found by the scan below instead.
    if (text.length == chars.length) {
      for (final m in RegExp(r'(19|20)\d\d').allMatches(text)) {
        for (var k = m.start; k < m.end; k++) {
          explained[k] = true;
        }
      }
      return;
    }
    for (var i = 0; i + 4 <= chars.length; i++) {
      final four = chars.sublist(i, i + 4).join();
      if (RegExp(r'^(19|20)\d\d$').hasMatch(four)) {
        for (var k = i; k < i + 4; k++) {
          explained[k] = true;
        }
      }
    }
  }

  /// Marks every place one of [_commonWords] appears.
  static void _markWords(List<String> chars, List<bool> explained) {
    final n = chars.length;
    for (final word in _commonWords) {
      final w = [for (final r in word.runes) String.fromCharCode(r)];
      for (var i = 0; i + w.length <= n; i++) {
        var match = true;
        for (var k = 0; k < w.length; k++) {
          if (chars[i + k] != w[k]) {
            match = false;
            break;
          }
        }
        if (!match) continue;
        for (var k = i; k < i + w.length; k++) {
          explained[k] = true;
        }
      }
    }
  }

  /// The substitutions guessing tools undo first, one character for one.
  static const Map<String, String> _unleet = {
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '@': 'a',
    r'$': 's',
    '!': 'i',
  };

  /// Words guessing tools try first: the word "password" in the app's
  /// languages, the classics, what a crypto wallet's owner reaches for, and
  /// the months and seasons. Written here, four letters and up; see the
  /// library comment for what this is not.
  static const List<String> _commonWords = [
    // "password", "pass" and "login" in the languages this app speaks.
    'password', 'passwort', 'passwd', 'pass', 'login', 'contraseña',
    'contrasena', 'motdepasse', 'senha', 'parola', 'haslo', 'hasło', 'sandi',
    'пароль',
    // The classics.
    'admin', 'letmein', 'welcome', 'iloveyou', 'love', 'monkey', 'dragon',
    'master', 'sunshine', 'princess', 'football', 'baseball', 'soccer',
    'superman', 'batman', 'shadow', 'trustno1', 'whatever', 'freedom',
    'secret', 'hello', 'test', 'guest', 'user', 'root', 'default',
    'changeme', 'qwerty', 'azerty', 'qwertz', 'abc123', 'привет', 'любовь',
    // What a wallet's owner reaches for.
    'smartable', 'wallet', 'bitcoin', 'crypto', 'ethereum', 'solana',
    'metamask', 'ledger', 'trezor', 'satoshi', 'nakamoto', 'lambo', 'hodl',
    'mnemonic', 'seed', 'phrase', 'private', 'money',
    // Months and seasons.
    'january', 'february', 'march', 'april', 'june', 'july', 'august',
    'september', 'october', 'november', 'december', 'spring', 'summer',
    'autumn', 'winter',
  ];
}
