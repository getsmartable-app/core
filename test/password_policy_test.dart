import 'package:flutter_test/flutter_test.dart';
import 'package:smartable_wallet_core/core/password_policy.dart';
import 'package:smartable_wallet_core/core/vault_keeper.dart';

/// The rule a new password is held to (`PasswordPolicy`), and the places that
/// must all ask it.
///
/// **What it protects is a split backup's shares**, which are guessed away
/// from the phone; so the cases here are the shapes guessing tools try first,
/// and the passphrases a person is told to use instead.
void main() {
  group('length', () {
    test('twelve characters, counted as a person counts them', () {
      expect(PasswordPolicy.minLength, 12);
      expect(PasswordPolicy.problemWith('k7#Lm9!qR2x'), PasswordProblem.tooShort,
          reason: 'eleven');
      expect(PasswordPolicy.problemWith('k7#Lm9!qR2xz'), isNull,
          reason: 'twelve, none of them a pattern');
    });

    test('an accent typed two ways is one character, not two', () {
      // NFC first, as the key derivation does: `e` + U+0301 is `é`.
      expect(PasswordPolicy.lengthOf('café au lait'), 12);
      expect(PasswordPolicy.lengthOf('café au lait'), 12);
    });

    test('a character outside the first plane is one, not two', () {
      // UTF-16 would count each of these as two and let six through as twelve.
      expect(PasswordPolicy.lengthOf('🔑🔑🔑🔑🔑🔑'), 6);
      expect(PasswordPolicy.problemWith('🔑🔑🔑🔑🔑🔑'), PasswordProblem.tooShort);
    });
  });

  group('predictable', () {
    for (final (password, why) in [
      ('password1234', 'the word and a run of digits'),
      ('p@ssw0rd2024', 'the word with the usual substitutions, and a year'),
      ('qwertyuiop12', 'a keyboard row'),
      ('1qaz2wsx3edc', 'a keyboard column walk'),
      ('йцукенгшщзхъ', 'the Russian keyboard row'),
      ('пароль123456', '"password" in Russian and a run'),
      ('abcdef123456', 'the alphabet and the digits'),
      ('0987654321ab', 'digits backwards'),
      ('aaaaaaaaaaaa', 'one character'),
      ('trustno1trustno1', 'a block written twice'),
      ('Summer2024!!', 'a season and a year'),
      ('iloveyou2024', 'a classic and a year'),
      ('bitcoin wallet', 'what a wallet owner reaches for'),
    ]) {
      test('$password — $why', () {
        expect(PasswordPolicy.problemWith(password), PasswordProblem.predictable);
      });
    }
  });

  group('accepted', () {
    for (final password in [
      'correct horse battery',
      'correct horse battery staple',
      'the one nobody remembers',
      'café au lait',
      'MyDogRex2019',
      'k7#Lm9!qR2xz',
      '我的钱包密码很安全啊好的',
    ]) {
      test(password, () {
        expect(PasswordPolicy.problemWith(password), isNull);
      });
    }

    test('two letters twice is how words are spelled, not a pattern', () {
      // `battery`, `hello`: one character twice is ordinary; three times is
      // what [PasswordPolicy] calls a repeat.
      expect(PasswordPolicy.unpredictableCount('battery'), 7);
      expect(PasswordPolicy.unpredictableCount('baaattery'), 6);
    });

    test('spaces do not break a pattern', () {
      expect(PasswordPolicy.unpredictableCount('a b c'), 0);
      expect(PasswordPolicy.problemWith('a b c d e f g h i j k l'),
          PasswordProblem.predictable);
      expect(PasswordPolicy.problemWith('pass word 1234'),
          PasswordProblem.predictable);
    });
  });

  group('one rule wherever a password is chosen', () {
    test('the wallet core holds new passwords to it', () {
      // `saveSeed`, `setPassword` and a change or reset all end here.
      expect(() => VaultKeeper.requireSealablePassword('short'),
          throwsA(isA<WeakPasswordException>().having(
              (e) => e.problem, 'problem', PasswordProblem.tooShort)));
      expect(() => VaultKeeper.requireSealablePassword('password1234'),
          throwsA(isA<WeakPasswordException>().having(
              (e) => e.problem, 'problem', PasswordProblem.predictable)));
      VaultKeeper.requireSealablePassword('correct horse battery');
    });
  });
}
