import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:smartable_wallet_core/core/unicode_nfc.dart';

/// What a password field is allowed to do to what somebody typed.
///
/// **The failure being tested for is a locked wallet, not a rendering bug.**
/// `e` with an acute written as one code point and the same letter written as
/// `e` plus a combining acute are identical on every screen and different
/// bytes to every encoder, so before NFC they derived different keys — and
/// which one a keyboard emits is the keyboard's business. Somebody who set a
/// password on one device and typed it on another had no way to see the
/// difference, no way to describe it, and no way in.
///
/// The other half is what must **not** change. Trimming, case folding and NFKC
/// each merge two passwords a person deliberately chose between, and each
/// would be a quiet weakening of every password that used the distinction.
///
/// **Every vector is an escape rather than a character, and that is not
/// pedantry.** The first version of this file typed the two forms of the
/// accented letter directly, and the editor that saved it composed both — so
/// the test asserted that a composed letter normalises to a composed letter,
/// and passed against a wallet that did no normalising at all. Two of these
/// tests were vacuous before that was noticed. A vector nothing can silently
/// rewrite is the only kind worth keeping here.
///
/// The full conformance run — twenty thousand cases, plus every code point
/// Unicode does not list — lives in `tool/unicode_nfc_check.dart`, which reads
/// the vendor's file. This is its offline half: a sample of the same file,
/// carried in the repository so a regression fails an ordinary `flutter test`.
void main() {
  // **The decomposed side of every vector below is built at run time from a
  // base letter and a lone combining mark**, never written out as a
  // finished sequence. A lone mark has nothing to compose with, so no
  // editor, terminal or formatter can quietly turn one of these inputs
  // into the answer it is supposed to produce — which is exactly how two
  // tests in the first version of this file came to assert nothing at all.
  //
  // Combining marks, by the class that decides whether they reorder.
  const acute = '́'; // class 230
  const grave = '̀'; // class 230, and so never reorders past the acute
  const dotAbove = '̇'; // class 230
  const dotBelow = '̣'; // class 220, and so always sorts before them
  const breve = '\u0306';
  const diaeresis = '\u0308';
  const hamzaAbove = '\u0653';
  const hamzaCarrier = '\u0654';

  // Hangul jamo, which compose only when they meet each other.
  const jamoH = '\u1112';
  const jamoG = '\u1100';
  const jamoA = '\u1161';
  const jamoEu = '\u1173';
  const jamoNFinal = '\u11ab';
  const jamoGFinal = '\u11a8';
  const jamoLFinal = '\u11af';

  group('the two spellings a keyboard chooses between', () {
    test('e plus a combining acute becomes the single character', () {
      expect(toNfc('e$acute'), 'é');
      expect(toNfc('e$acute').codeUnits, [0x00e9]);
      expect(toNfc('cafe$acute'), 'café');
    });

    test('the composed form is already the answer', () {
      // Idempotence, which is what the wallet actually leans on: what was
      // stored was normalised once, and what is typed tomorrow is normalised
      // again.
      expect(toNfc('é'), 'é');
      expect(toNfc(toNfc('e$acute')), toNfc('e$acute'));
    });

    test('Cyrillic i plus a breve becomes the single letter', () {
      expect(toNfc('\u0438$breve'), '\u0439');
      expect(toNfc('\u0435$diaeresis'), '\u0451');
      // The letters with no decomposition are left exactly alone.
      const word = 'пароль';
      expect(toNfc(word), word);
    });

    test('Arabic alef plus a hamza above becomes the single letter', () {
      expect(toNfc('\u0627$hamzaAbove'), '\u0622');
      expect(toNfc('\u0648$hamzaCarrier'), '\u0624');
      const phrase = 'كلمة السر';
      expect(toNfc(phrase), phrase);
    });

    test('Hangul jamo compose into syllables', () {
      // The script where both spellings are in daily use, and the one place
      // NFC is algorithmic rather than tabular.
      expect(toNfc('$jamoG$jamoA$jamoGFinal'), '\uac01');
      expect(toNfc('\uac00$jamoGFinal'), '\uac01');
      expect(toNfc('$jamoH$jamoA$jamoNFinal$jamoG$jamoEu$jamoLFinal'),
          '\ud55c\uae00');
    });

    test('a mark sequence is put in canonical order', () {
      // Two marks on one letter, typed in either order, are one password: the
      // dot below is class 220 and the dot above 230, so NFC settles them into
      // one order whichever way the keyboard sent them.
      expect(toNfc('q$dotAbove$dotBelow'), toNfc('q$dotBelow$dotAbove'));
      expect(toNfc('q$dotAbove$dotBelow'), 'q$dotBelow$dotAbove');
    });

    test('marks of the same class keep the order they were typed in', () {
      // Acute and grave are both class 230. They sit in different places on
      // the letter, so reordering them would change what is written rather
      // than how it is spelled — and would turn two passwords into one.
      expect(toNfc('a$acute$grave'), isNot(toNfc('a$grave$acute')));
    });
  });

  group('what is left exactly as it was typed', () {
    test('CJK', () {
      const chinese = '密码';
      const japanese = 'パスワード';
      expect(toNfc(chinese), chinese);
      expect(toNfc(japanese), japanese);
    });

    test('emoji, a joined family and a keycap', () {
      // Surrogate pairs, a zero-width joiner and a variation selector: three
      // things a normalizer working in UTF-16 units rather than in characters
      // would damage.
      const family = '\u{1f468}‍\u{1f469}‍\u{1f467}';
      expect(toNfc(family), family);
      expect(toNfc('\u{1f512}'), '\u{1f512}');
      expect(toNfc('1️⃣'), '1️⃣');
      // A skin tone modifier is its own code point and must survive.
      expect(toNfc('\u{1f44d}\u{1f3fd}'), '\u{1f44d}\u{1f3fd}');
    });

    test('leading and trailing spaces', () {
      expect(toNfc('  padded  '), '  padded  ');
      expect(toNfc('\ttabbed\t'), '\ttabbed\t');
      // A no-break space is a character somebody may have typed on purpose,
      // and NFKC would turn it into an ordinary one.
      expect(toNfc('a b'), 'a b');
      expect(toNfc('a b'), isNot('a b'));
    });

    test('full-width characters stay full-width', () {
      expect(toNfc('ＡＢＣ'), 'ＡＢＣ');
      expect(toNfc('Ａ'), isNot('A'));
    });

    test('case', () {
      expect(toNfc('PaSsWoRd'), 'PaSsWoRd');
      // Capital sharp s, which case folding would turn into `ss` or `SS`.
      expect(toNfc('ẞ'), 'ẞ');
      expect(toNfc('Ä'), isNot(toNfc('ä')));
    });

    test('the compatibility characters NFKC would have merged', () {
      expect(toNfc('ﬁ'), 'ﬁ'); // the fi ligature
      expect(toNfc('ﬁ'), isNot('fi'));
      expect(toNfc('²'), '²'); // superscript two
      expect(toNfc('²'), isNot('2'));
      expect(toNfc('①'), '①'); // circled digit one
    });

    test('the empty string, and a lone combining mark', () {
      expect(toNfc(''), '');
      // Nothing to compose onto, so it stays a mark rather than becoming one.
      expect(toNfc(acute), acute);
    });
  });

  group('a canonical singleton is still a canonical mapping', () {
    test('the ohm sign becomes capital omega', () {
      // NFC, not NFKC: Unicode says these are one character, so a wallet that
      // treated them as two passwords would be wrong in the same way as the
      // combining-acute case.
      // Asserted on the inputs too: these two are a single code point on
      // each side, so an editor that normalised this file would turn them
      // into their own answers and the test would still pass.
      expect('\u2126'.codeUnits, [0x2126]);
      expect('\u212b'.codeUnits, [0x212b]);
      expect(toNfc('\u2126'), '\u03a9');
      expect(toNfc('\u212b'), '\u00c5');
    });
  });

  group('ASCII is untouched, which is what keeps existing wallets opening', () {
    test('every ASCII character and every ASCII pair survives', () {
      // Brute force rather than argument. `<` is the first half of a real
      // composition — U+003C with U+0338 is the not-less-than sign — so "ASCII
      // is inert" is a claim about strings and not about characters, and it is
      // the claim the fast path in unicode_nfc.dart rests on.
      for (var first = 0; first < 0x80; first++) {
        final single = String.fromCharCode(first);
        expect(toNfc(single), single,
            reason: 'U+${first.toRadixString(16)} did not survive');
        for (var second = 0; second < 0x80; second++) {
          final pair = String.fromCharCodes([first, second]);
          expect(toNfc(pair), pair,
              reason: 'U+${first.toRadixString(16)} then '
                  'U+${second.toRadixString(16)} did not survive');
        }
      }
    });

    test('the same instance comes back, so nothing can have touched it', () {
      const password = 'correct horse battery staple';
      expect(identical(toNfc(password), password), isTrue);
    });
  });

  group('the one code point the packaged normalizer gets wrong', () {
    // unorm_dart 0.3.2 bounds the Hangul block with `<=` instead of `<`, so
    // U+D7A4 — unassigned, one past the last syllable — is decomposed as
    // though it were a syllable and cannot compose back, and it also acquires
    // a composition table that swallows a following trailing jamo. Both halves
    // need the character present; unicode_nfc.dart normalises around it.
    //
    // The whole-Unicode proof is in tool/unicode_nfc_check.dart. These are the
    // sequences that proof cannot reach, because it tests code points alone.
    const defect = '\ud7a4';

    test('it is its own NFC, alone and doubled', () {
      expect(toNfc(defect), defect);
      expect(toNfc('$defect$defect'), '$defect$defect');
    });

    test('it does not swallow the jamo after it', () {
      expect(toNfc('$defect$jamoGFinal'), '$defect$jamoGFinal');
      expect(toNfc('가$defect'), '가$defect');
    });

    test('and it does not stop the text around it normalising', () {
      expect(toNfc('e$acute$defect$dotBelow$dotAbove'),
          'é$defect$dotBelow$dotAbove');
      expect(toNfc('$jamoG$jamoA$jamoGFinal$defect'), '\uac01$defect');
      expect(toNfc('$defect\u0438$breve'), '$defect\u0439');
    });
  });

  group("the Unicode Consortium's own cases", () {
    test('every sampled line of NormalizationTest.txt', () {
      final file = File('test/fixtures/unicode/normalization_vectors.txt');
      expect(file.existsSync(), isTrue,
          reason: 'run tool/unicode_nfc_check.dart to write the fixture');

      var checked = 0;
      for (final line in file.readAsLinesSync()) {
        if (line.startsWith('#') || line.trim().isEmpty) continue;
        final columns = line.split(';');
        final part = columns.first;
        final text = [for (var i = 1; i <= 5; i++) _runes(columns[i])];
        // The file's own rule for NFC: columns 1, 2 and 3 all normalize to
        // column 2, and columns 4 and 5 both normalize to column 4.
        for (final index in [0, 1, 2]) {
          expect(toNfc(text[index]), text[1],
              reason: 'part $part, column ${index + 1}');
        }
        for (final index in [3, 4]) {
          expect(toNfc(text[index]), text[3],
              reason: 'part $part, column ${index + 1}');
        }
        checked++;
      }
      // A fixture that silently became empty would pass every assertion above.
      expect(checked, greaterThan(900));
    });
  });
}

String _runes(String field) => String.fromCharCodes([
      for (final rune in field.trim().split(' ')) int.parse(rune, radix: 16),
    ]);
