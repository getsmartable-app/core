# Contributing

Thank you for reading the code. Questions, reports and proposals are welcome.

## How this repository works

The core is assembled from the source of the Smartable Wallet application and
is not edited here directly — see [docs/releasing.md](docs/releasing.md). That
keeps the published files identical to the ones the application runs, and it
shapes how a contribution arrives.

## A vulnerability

**Never in a public issue.** Report it privately, as
[SECURITY.md](SECURITY.md) describes: through GitHub's private vulnerability
reporting on this repository, or by email to
[hello@getsmartable.app](mailto:hello@getsmartable.app).

## A bug

Open an issue with the bug report form: the version or commit, what happened,
what you expected and how to reproduce it.

**Never include a recovery phrase, private key, password or PIN** — not a real
one, and not one you only think is unused.

## A change

A pull request is welcome as a proposal. If it is accepted, the change is made
in the application's source — with the same content, and with you credited as
co-author — and arrives here with the next version. The pull request is then
closed with a link to that version, and the changelog names the change.

What a proposal needs:

- `flutter analyze` reports no issues, infos included;
- `flutter test` passes;
- a change to a security rule comes with a test that fails without it;
- no new dependency without an issue discussing it first: every package here
  is code that handles keys;
- English, in code, comments and text.

Large changes are best discussed in an issue before the work is done.

## Licence

A contribution is made under the [Apache License, Version 2.0](LICENSE), as its
section 5 provides, unless you state otherwise when you submit it.
