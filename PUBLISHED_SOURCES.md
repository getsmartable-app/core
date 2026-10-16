# Published sources

Smartable Wallet Core is the open-source subset of the Smartable Wallet
project.

This repository contains the components that keep the wallet non-custodial on
the device: how a typed secret becomes key material, encrypted-only secret
storage, how a recovery phrase is sealed and every way it is opened, the app PIN
and its lockout, biometric unlock, SLIP-39 split backup and the platform key the
wallet is sealed under.

## Included

- Selected files from `lib/core/`: `crypto_utils.dart`, `unicode_nfc.dart`,
  `secure_storage.dart`, `hardware_key.dart`, `key_backing.dart`,
  `wallet_doors.dart`, `pin_lock.dart`, `quick_unlock.dart`,
  `vault_keeper.dart`, `password_policy.dart`, `seed_vault.dart`,
  `password_recovery.dart`,
  `unlock_throttle.dart`, `device_uptime.dart`, `slip39.dart`,
  `slip39_wordlist.dart`, `sealed_share.dart`, `share_store.dart`,
  `paper_share_store.dart`.
- Their tests and the published vectors they read, under `test/`.
- The native key and boot-clock code for Android and iOS, under `native/`,
  published for review and not built here.
- `CHANGELOG.md`, `CONTRIBUTING.md` and `docs/`: the version history, how to
  take part, and how versions are numbered, made and checked.
- `.github/`: the checks and the release workflow, the issue and pull request
  templates, and the Dependabot configuration for the workflows' actions.
- `LICENSE`.
- `NOTICE`.
- `THIRD_PARTY_NOTICES.md`.
- `LICENSES/`.
- `SECURITY.md`.
- `SECURITY_REVIEW.md`.

## Not included

The following remain proprietary and are not part of this repository:

- Product UI and application screens.
- Blockchain modules and network integrations.
- Transaction construction, review and signing, including hardware-wallet
  signing.
- Marketing pages and product copy.
- Backend and proxy infrastructure.
- Commercial routing, fee and quota logic.
- Private deployment configuration.
- Application-specific services that are not required by the published core.
- Application release records, including the release checklist, device matrix,
  backend and privacy review, and production configuration review.

An application release record is not published here. It covers UI, native
platform behaviour, backend services, supported networks, production-like
environments and release configuration — none of which this repository reviews
— and a completed one carries device identifiers, test-wallet details and other
non-public release data. `SECURITY.md` and `SECURITY_REVIEW.md` say where such
records may be kept.

## Licensing

Files in this repository are licensed under the Apache License, Version 2.0,
unless a file or directory contains a different licence notice.

Third-party material retains its original licence. See:

- `NOTICE`
- `THIRD_PARTY_NOTICES.md`
- `LICENSES/`

The Smartable and Smartable Wallet names, logos, domains, application
identifiers and visual identity are not licensed. Modified
distributions must remove those marks and use their own name and identity.

## Scope

The published source is intended to make the security-critical parts of the
wallet available for review. It is not a complete build of the Smartable Wallet
application and does not by itself constitute a security audit or a guarantee
that every release binary is reproducible from this repository.

## Current status

- Public source: this repository.
- Independent security audit: not completed unless listed in `SECURITY.md`.
- Reproducible release verification: not yet available unless documented in the
  release notes.
- Production suitability: each release must be evaluated separately.
