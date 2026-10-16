# Third-party notices

What in this repository came from somebody else, and what its licence asks in
return. Everything else is the project's own work under the Apache License,
Version 2.0 — see [LICENSE](LICENSE).

## SLIP-39 word list and test vectors

- **In:** `lib/core/slip39_wordlist.dart` (the word list) and
  `test/support/slip39_vectors.json` (the vectors `test/slip39_test.dart`
  reads)
- **Source:** [trezor/python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic)
- **Licence:** MIT. Copyright 2019 SatoshiLabs.
- **Licence text:** [`LICENSES/MIT-python-shamir-mnemonic.txt`](LICENSES/MIT-python-shamir-mnemonic.txt)

The word list is part of the SLIP-39 format: a share is written in exactly
these 1,024 words, so it is reproduced rather than rewritten. The vectors hold
the implementation to SatoshiLabs' own answers — valid shares, invalid shares,
identifiers, indexes and digest failures.

## Unicode normalization test cases

- **In:** `test/fixtures/unicode/normalization_vectors.txt`
- **Source:** [`NormalizationTest.txt`](https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt),
  Unicode 17.0.0, published by the Unicode Consortium. The file here is a
  subset — parts 0, 3 and 5 whole, parts 1, 2 and 4 every 25th case — as its
  header says.
- **Licence:** Unicode License v3. Copyright © 1991-2026 Unicode, Inc.
- **Licence text:** [`LICENSES/Unicode-3.0.txt`](LICENSES/Unicode-3.0.txt)

Every password, PIN and backup passphrase is normalised to NFC before a key is
derived from it, so the normaliser decides which bytes a secret becomes. These
cases hold it to the Unicode Consortium's own conformance data.

## Dependencies

The packages named in `pubspec.yaml` are fetched by `flutter pub get` and are
not redistributed in this repository. Each keeps its own licence, and
`flutter pub deps` lists them.

One is named here although the others are not: **`unorm_dart`** (MIT,
Copyright 2018 Yasuhiro Shimizu, a Dart port of
[walling/unorm](https://github.com/walling/unorm)) normalises every secret
before PBKDF2 sees it. A reviewer reading `crypto_utils.dart` should not have
to resolve a package to learn whose code that is. It is pinned to an exact
version for the same reason.
