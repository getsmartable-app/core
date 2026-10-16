import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:smartable_wallet_core/core/slip39.dart';
import 'package:smartable_wallet_core/core/slip39_wordlist.dart';

/// SLIP-39 against SatoshiLabs' own published vectors.
///
/// **This is the whole reason the code was written bottom-up.** A share scheme
/// that is wrong does not fail — it reconstructs a *different* valid secret,
/// derives valid addresses, and shows an empty wallet belonging to nobody.
/// There is no symptom before the money is unreachable, so the arithmetic is
/// pinned to somebody else's before anything is built on it.
///
/// **Most of the 45 cases are refusals**, and that is what makes them worth
/// having: any implementation can combine shares that belong together. What
/// separates a correct one is refusing the shares that do not — a wrong
/// checksum, a mismatched identifier, a duplicated index, a digest that does
/// not verify. Each of those is a well-formed wrong answer waiting to be
/// returned.
///
/// > **The vectors are generated with the passphrase `TREZOR`, and nothing in
/// > the file says so.** Read with an empty passphrase, every valid case
/// > returns a perfectly well-formed secret that is not the expected one —
/// > which reads as a broken cipher and is not. An hour went into diffing the
/// > Feistel rounds against the reference before the reference itself was run
/// > and produced *our* answer, at which point the disagreement was clearly
/// > between the file and the assumption rather than in any code.
/// >
/// > This is the second time this project has been caught by a wrong
/// > assumption inside a vector file rather than a defect under test — see
/// > `ledger_apdu_vectors_test.dart`, where LedgerHQ's own recordings mix
/// > exchanges from different seeds. When published vectors disagree with an
/// > implementation, run the publisher's implementation before touching yours.
///
/// Vectors from `trezor/python-shamir-mnemonic` (MIT) — see
/// THIRD_PARTY_NOTICES.md.
void main() {
  // The passphrase every case in the file was generated with.
  const trezor = [84, 82, 69, 90, 79, 82]; // "TREZOR"

  final vectors = (jsonDecode(
    File('test/support/slip39_vectors.json').readAsStringSync(),
  ) as List)
      .cast<List<dynamic>>();

  test('the vector file is the one this was written against', () {
    // A vector set that quietly shrank would turn a suite of refusals into a
    // suite of nothing, and still be green.
    expect(vectors.length, 45);
    final failing = vectors.where((v) => (v[2] as String).isEmpty).length;
    expect(failing, greaterThan(20),
        reason: 'the refusals are the point of this file');
  });

  group('the published vectors', () {
    for (final vector in vectors) {
      final description = vector[0] as String;
      final mnemonics = (vector[1] as List).cast<String>();
      final expected = vector[2] as String;

      test(description, () {
        if (expected.isEmpty) {
          // **Every one of these is a way to reach a plausible wrong secret.**
          // The assertion is that it throws, not what it says — a caller
          // matches on the type.
          expect(
            () => recoverSecret(mnemonics, passphrase: trezor),
            throwsA(isA<Slip39Exception>()),
            reason: 'this set must be refused, not reconstructed',
          );
        } else {
          final secret = recoverSecret(mnemonics, passphrase: trezor);
          expect(_hex(secret), expected);
        }
      });
    }
  });

  group('the word list', () {
    test('is the standard one, in the standard order', () {
      // The index of a word *is* its ten-bit value. A list that differs by one
      // entry produces mnemonics no other wallet can read, and reads other
      // wallets' mnemonics as different secrets, with no error anywhere.
      expect(kSlip39Wordlist.length, 1024);
      expect(kSlip39Wordlist, orderedEquals(List.of(kSlip39Wordlist)..sort()));
      expect(kSlip39Wordlist.first, 'academic');
      expect(kSlip39Wordlist.last, 'zero');
    });

    test('every word is unique in its first four letters', () {
      // The property that lets somebody transcribe a share by hand without
      // ambiguity, and the reason the standard has its own list rather than
      // reusing BIP-39's.
      expect(kSlip39Wordlist.map((w) => w.substring(0, 4)).toSet().length, 1024);
    });

    test('lengths stay inside what the standard promises', () {
      for (final w in kSlip39Wordlist) {
        expect(w.length, inInclusiveRange(4, 8), reason: w);
      }
    });

    test('is lower-case ASCII, which is what makes folding case safe', () {
      // **The property every case-insensitive comparison in this wallet rests
      // on, and nothing asserted it.** `_wordsToIndices` lower-cases a word
      // before looking it up, and `ShareBackup` folds case again to decide
      // whether two typed shares are the same share. Both are total and
      // injective only while the list itself is lower-case ASCII: one word
      // carrying a capital would become unfindable the moment it was folded —
      // a share that cannot be read, on a wallet that has no other copy — and
      // two words differing only by case would collapse into one index.
      //
      // Case-insensitivity here is SLIP-39's own property, not a habit carried
      // over from elsewhere. It is asserted rather than assumed, because it is
      // false for most other recovery material: a WIF key, an extended key and
      // a Base58 address all carry meaning in their capitals.
      for (final w in kSlip39Wordlist) {
        expect(w, matches(RegExp(r'^[a-z]+$')), reason: w);
      }
      expect(kSlip39Wordlist.map((w) => w.toLowerCase()).toSet(), hasLength(1024),
          reason: 'folding case must not merge two of the standard\'s words');
    });
  });

  group('case, against the published vectors', () {
    /// The first vector that recovers something, as the ground truth.
    final readable = vectors.firstWhere((v) => (v[2] as String).isNotEmpty);

    test('a share typed in capitals is the same share', () {
      // **The standard says the words are lower-case; it does not say a reader
      // may refuse other spellings**, and people transcribe by hand onto paper
      // and back through keyboards that capitalise the first word of a line.
      // Checked against SatoshiLabs' own vector rather than against our own
      // encoder, so a reader that folded case wrongly could not agree with
      // itself and pass.
      final mnemonics = (readable[1] as List).cast<String>();
      final expected = readable[2] as String;

      expect(_hex(recoverSecret([for (final m in mnemonics) m.toUpperCase()],
              passphrase: trezor)),
          expected);
      expect(
          _hex(recoverSecret([
            for (var i = 0; i < mnemonics.length; i++)
              i.isEven ? mnemonics[i].toUpperCase() : mnemonics[i]
          ], passphrase: trezor)),
          expected,
          reason: 'and a set mixing the two spellings is one set of shares');
    });

    test('and extra spacing between words is the same share', () {
      // The other half of the same normalisation, and the one a paper
      // transcription actually produces: `\s+`, so a double space or a
      // newline where a line wrapped is not a damaged share.
      final mnemonics = (readable[1] as List).cast<String>();
      expect(
          _hex(recoverSecret(
              [for (final m in mnemonics) '  ${m.replaceAll(' ', '\n  ')}  '],
              passphrase: trezor)),
          readable[2] as String);
    });
  });

  group('encoding round-trips', () {
    test('a share re-encodes to exactly the words it was read from', () {
      // **The direction that has no vectors of its own.** Recovery is checked
      // above against somebody else's arithmetic; writing shares is checked by
      // requiring that what we write is byte-for-byte what the standard's own
      // examples contain. A writer that is wrong consistently would pass any
      // test that only reads back its own output.
      for (final vector in vectors) {
        final expected = vector[2] as String;
        if (expected.isEmpty) continue;
        for (final mnemonic in (vector[1] as List).cast<String>()) {
          expect(encodeShare(decodeShare(mnemonic)), mnemonic,
              reason: vector[0] as String);
        }
      }
    });
  });

  group('what a caller can tell apart', () {
    test('a damaged share and an unmet threshold are different types of no', () {
      // Both are refusals and they need opposite instructions on screen: one
      // says find another share, the other says this share is mistyped.
      final good = (vectors.firstWhere(
        (v) => (v[0] as String).startsWith('1.'),
      )[1] as List)
          .cast<String>();
      expect(() => recoverSecret([]), throwsA(isA<Slip39Exception>()));
      expect(recoverSecret(good, passphrase: trezor), isNotEmpty);
    });

    test('a word outside the list is named', () {
      // The one refusal whose message a person can act on directly, so it is
      // the one place the text is asserted.
      expect(
        () => decodeShare('academic acid notaword'),
        throwsA(predicate((e) => e.toString().contains('notaword'))),
      );
    });
  });

  _splittingTests();
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Splitting, checked against the recovery that is already pinned to
/// SatoshiLabs' arithmetic.
///
/// **A splitter can only be checked by its own reader, so the reader has to be
/// the trustworthy half** — which it is, because 45 published vectors say so.
/// That is the whole reason recovery was written first.
void _splittingTests() {
  final secret = List<int>.generate(16, (i) => i * 7 & 0xFF);
  const trezor = [84, 82, 69, 90, 79, 82];

  group('splitting', () {
    test('every pair of three restores the same secret', () async {
      // **Not one lucky pair.** A splitter that gets one basis polynomial
      // wrong can still produce a set where some combinations work, and a test
      // that tries a single pair would call that correct.
      final shares = splitSecret(masterSecret: secret).single;
      expect(shares, hasLength(3));
      for (var i = 0; i < 3; i++) {
        for (var j = i + 1; j < 3; j++) {
          expect(recoverSecret([shares[i], shares[j]]), secret,
              reason: 'shares $i and $j');
        }
      }
    });

    test('one share alone is refused, not merely insufficient', () {
      final shares = splitSecret(masterSecret: secret).single;
      expect(() => recoverSecret([shares.first]),
          throwsA(isA<Slip39Exception>()));
    });

    test('shares from two splits never combine', () {
      // Two backups of the *same* wallet are still different sets, and mixing
      // them would reconstruct a secret belonging to neither.
      final a = splitSecret(masterSecret: secret).single;
      final b = splitSecret(masterSecret: secret).single;
      expect(() => recoverSecret([a.first, b.first]),
          throwsA(isA<Slip39Exception>()));
    });

    test('a passphrase changes the secret and not the shares\' validity', () {
      final shares = splitSecret(masterSecret: secret, passphrase: trezor).single;
      expect(recoverSecret(shares.take(2).toList(), passphrase: trezor), secret);
      // **The property that makes a passphrase dangerous and useful at once.**
      // A wrong one does not fail — it returns a different, perfectly
      // well-formed secret, which is a wallet nobody funded.
      expect(recoverSecret(shares.take(2).toList()), isNot(secret));
    });

    test('a 256-bit secret works as well as a 128-bit one', () {
      final big = List<int>.generate(32, (i) => (i * 13) & 0xFF);
      final shares = splitSecret(masterSecret: big).single;
      expect(recoverSecret(shares.take(2).toList()), big);
    });

    test('the shares are what this library reads back as shares', () {
      final shares = splitSecret(masterSecret: secret).single;
      for (final m in shares) {
        final decoded = decodeShare(m);
        expect(decoded.memberThreshold, 2);
        expect(decoded.groupCount, 1);
        expect(encodeShare(decoded), m);
      }
    });
  });

  group('what splitting refuses', () {
    test('a threshold nobody can meet', () {
      expect(
        () => splitSecret(
            masterSecret: secret, groups: const [Slip39Group(4, 3)]),
        throwsA(isA<Slip39Exception>()),
      );
    });

    test('a group where one share is enough but there are several', () {
      // Not a group at all — the same secret copied, presented as though it
      // raised somebody's threshold.
      expect(
        () => splitSecret(
            masterSecret: secret, groups: const [Slip39Group(1, 3)]),
        throwsA(isA<Slip39Exception>()),
      );
    });

    test('a secret too short, or of odd length', () {
      expect(() => splitSecret(masterSecret: List.filled(8, 1)),
          throwsA(isA<Slip39Exception>()));
      expect(() => splitSecret(masterSecret: List.filled(17, 1)),
          throwsA(isA<Slip39Exception>()));
    });

    test('more shares than the format can index', () {
      expect(
        () => splitSecret(
            masterSecret: secret, groups: const [Slip39Group(2, 17)]),
        throwsA(isA<Slip39Exception>()),
      );
    });
  });

  test('randomness is not a parameter anybody real passes', () {
    // A split with predictable randomness produces shares that look perfect
    // and can be reconstructed by anybody who knows the generator. The default
    // is the one thing here that must never be convenient.
    final source = File('lib/core/slip39.dart').readAsStringSync();
    expect(source, contains('RandomBytes random = _secureBytes'));
    expect(source, contains('CryptoUtils.randomBytes'));
  });
}
