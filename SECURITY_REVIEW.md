# Security review record

## Scope

This document records security-focused review and testing performed for the
published Smartable Wallet Core components.

The review covers the code that keeps the wallet non-custodial on the device:

- how a typed password, PIN or backup passphrase becomes key material —
  Unicode NFC, then PBKDF2-HMAC-SHA256, or Argon2id for a split-backup share;
- encrypted-only secret storage, and what happens when it fails;
- how a recovery phrase is sealed under a random key of its own, wrapped by the
  password, and opened by the password, the PIN or the device key;
- the platform keys the wallet is sealed under — Android Keystore (StrongBox,
  then the TEE) and the iOS Secure Enclave — in `native/`;
- the app PIN: its key-store pepper, its device-key seal and its lockout;
- biometric unlock and when it is offered;
- one lockout counter, measured on the boot clock;
- SLIP-39 split backup and the sealing of each share;
- the tests and published vectors included in this repository.

Chain modules, transaction construction, review and signing, address
validation, hardware-wallet integration, the application UI, the backend and
RPC proxy, commercial routing and release configuration are not published here
and are outside this document.

Application-specific device acceptance and production release records may be
maintained separately.

## Review method

The project was reviewed with assistance from:

- Claude Code using Claude Opus 5 and other AI models;
- additional AI-assisted review passes;
- project-maintainer review;
- automated unit and integration tests;
- published protocol and test vectors;
- targeted regression tests for reproduced findings;
- emulator or simulator checks where explicitly recorded below.

AI assistance was used to identify possible defects, missing tests, unsafe
assumptions and inconsistencies. AI output was not treated as proof of
correctness.

Every material finding was either:

1. reproduced and fixed;
2. covered by a test;
3. rejected with a documented reason; or
4. recorded as an open limitation.

A code review or automated test result must not be interpreted as an
independent security audit.

## Verification levels

The following verification levels are recorded separately:

- **Code verified** — the implementation was reviewed at source level.
- **Automated tested** — relevant automated tests passed.
- **Simulator tested** — the feature was exercised in an iOS Simulator or
  Android Emulator.
- **Physical device tested** — the feature was exercised on a physical device.
- **Production-like network tested** — the feature was exercised against a
  production-like blockchain, RPC, indexer or service.
- **Production configuration reviewed** — release configuration and deployment
  settings were reviewed.

An emulator result is not a physical-device result.

A successful automated or emulator test does not prove hardware-backed
Keychain/Keystore behaviour, StrongBox behaviour, biometric invalidation,
locked-device behaviour, every backup/restore path or iOS-specific behaviour.

## Required Core verification

Before publishing a Core release, run the tests available in this repository.

At minimum:

```bash
flutter pub get --enforce-lockfile
flutter analyze
flutter test
```

The CI workflow runs these on Linux and macOS for every push, and the release
workflow runs them again before it publishes anything.

The native files under `native/` are published for review; this repository
has no Android or iOS project and does not build or test them. Their tests
(`HardwareVaultKeyRulesTest.kt`, `PinPepperKeyRulesTest.kt`,
`HardwareVaultKeyTests.swift`, `PinPepperKeyTests.swift`) are published beside
them and run in the application's repository.

If a check is not included in the Core repository, it must not be reported as
passed for the Core release. It may be documented separately as part of the
private Smartable Wallet application release process.

Record the exact command, date, source commit and result in the release notes.

## Security review checklist

### Key derivation and storage

- [ ] Every password, PIN and backup passphrase is put in one form, Unicode
      NFC, then derived by PBKDF2-HMAC-SHA256 — or, for a split-backup share,
      by Argon2id (64 MiB, three passes, four lanes), held to RFC 9106's test
      vector; a share sealed with PBKDF2 before Argon2id still opens.
- [ ] The normaliser is held to the Unicode Consortium's conformance data.
- [ ] Secrets are written to encrypted-only storage, with no plaintext
      fallback.
- [ ] A secret that cannot be decrypted is reported, never deleted, and never
      read as "no wallet here".
- [ ] Secure deletion reports failure when it cannot be confirmed.
- [ ] A recovery phrase is written under a random vault key, never under the
      password, and the password only wraps that key. A vault written before
      key wrapping is read as it is and converted at its next password change.
- [ ] Changing the password re-wraps the vault key and the imported-key key,
      writes nothing when the current password is wrong, and leaves every
      phrase openable.
- [ ] Legacy storage migration is documented and tested, and a failed one does
      not claim success.
- [ ] Which hardware holds a platform key is read from the platform and
      reported, not assumed.
- [ ] Sensitive values are not written to logs.

### PIN, biometric unlock and lockout

- [ ] Every PIN guess is a key-store operation on the phone: HMAC in Android
      Keystore, ECDH in the Secure Enclave.
- [ ] The sealed PIN is opened by a device key, which on Android 15 and later
      works only while the phone is unlocked.
- [ ] A replaced key is told apart from a wrong PIN.
- [ ] The PIN and the device key seal the vault key and the imported-key key,
      never the phrase, and open only the wallet they were set up for.
- [ ] Replacing a forgotten password through the PIN is refused for any wallet
      but the one the PIN opens.
- [ ] The biometric-bound key is released once per use: Class 3 only on
      Android, `.biometryCurrentSet` on iOS.
- [ ] No system passcode, PIN or pattern opens the wallet.
- [ ] Every password and PIN check is counted on one lockout; a storage or
      key-store failure is not counted as a guess.
- [ ] A lockout already running refuses without checking what was typed.
- [ ] The wait is measured on the boot clock, so a changed date does not end
      it and a reboot restarts it.

### Split backup

- [ ] SLIP-39 is held to SatoshiLabs' published vectors.
- [ ] The offered schemes (2-of-3 and 3-of-5) reconstruct the secret, and
      fewer shares do not.
- [ ] Each share is sealed under a key derived from the wallet password before
      it leaves the device.
- [ ] A share file this build cannot read is reported, never dropped.

### Supply chain and release

- [ ] Dependency licences are reviewed.
- [ ] Third-party notices are complete.
- [ ] Release source is tagged.
- [ ] Release binaries are linked to a source commit.
- [ ] Checksums are published where available.
- [ ] No development secrets or test credentials are included.
- [ ] Reproducible-build status is documented honestly.
- [ ] Application-specific native and physical-device checks are not claimed as
      Core verification unless separately evidenced.

## Results

Record the result for every Core release.

Do not mark a check as passed until the command has actually been executed.

| Check | Result | Date | Version / commit | Notes |
|---|---|---|---|---|
| `flutter analyze` | Not recorded | YYYY-MM-DD | COMMIT | |
| `flutter test` | Not recorded | YYYY-MM-DD | COMMIT | |
| Native tests (in the application repository) | Not recorded | YYYY-MM-DD | COMMIT | |
| AI-assisted review | Not recorded | YYYY-MM-DD | Claude Code / Claude Opus 5 | |
| Maintainer review | Not recorded | YYYY-MM-DD | COMMIT | |

For checks that are not part of a particular Core release, record:

```text
Not applicable — check is maintained in the private application repository.
```

## Android emulator verification

The following checks were performed using an Android emulator, the real
Flutter secure-storage plugin and the application lifecycle.

These results are limited to emulator and application-level verification. They
do not constitute physical-device certification.

| Check | Status | Scope | Notes |
|---|---|---|---|
| Secure-storage migration | PASS | Android emulator | A legacy readable vault record was migrated to secure storage and the readable copy was removed. The probe used synthetic ciphertext; successful unlock of a genuine migrated wallet remains unverified. |
| Secret-bearing readable storage inspection | PASS, scoped | Android emulator | The inspected readable preferences store contained none of the tested secret-bearing keys. This does not prove that no sensitive data exists in other files, caches, logs, backups or memory. |
| Wallet deletion | NOT VERIFIED | Android emulator | Not run against the shared test wallet. Requires a disposable wallet fixture. |
| Real mnemonic migration | NOT VERIFIED | Android emulator | Requires a disposable wallet with a genuine encrypted vault and successful post-migration unlock and address verification. |

### Emulator test limitations

- `adb root` must not be enabled when testing `FLAG_SECURE`. Root access may
  bypass or alter screenshot behaviour and can invalidate the result.
- `uiautomator dump` must not be used as the sole proof of the currently visible
  screen while launch or splash animations are active.
- A screenshot must be taken only after the visible screen has been confirmed
  through a reliable, non-stale procedure.
- Emulator results do not verify hardware-backed Android Keystore.
- Emulator results do not verify StrongBox.
- Emulator results do not verify biometric key invalidation on physical
  hardware.
- Emulator results do not verify locked-device behaviour.
- Emulator results do not verify Android backup and restore behaviour.
- Emulator results do not verify iOS Keychain, accessibility classes, screen
  recording, AirPlay or QuickTime capture.

## Platform verification status

### Android

| Check | Status | Notes |
|---|---|---|
| Code verification | PASS | Source review and automated tests recorded for the relevant release commit. |
| Automated verification | PASS | Relevant application and Core test suites passed for the recorded commit. |
| Android emulator verification | PARTIAL PASS | Secure-storage migration and scoped screenshot checks passed. |
| Physical Android verification | NOT VERIFIED | Hardware-backed Keystore, StrongBox, biometric invalidation, locked-device and reinstall checks remain open. |

### iOS

| Check | Status | Notes |
|---|---|---|
| Code verification | PASS or NOT RECORDED | Record the exact release commit and affected native files. |
| Automated verification | PASS or NOT RECORDED | Record the exact test command and result. |
| iOS Simulator verification | NOT VERIFIED | Record separately if performed. |
| Physical iOS verification | NOT VERIFIED | Keychain, accessibility class, screen capture, AirPlay, QuickTime and biometric checks remain open unless separately evidenced. |

Do not replace `NOT VERIFIED` with `PASS` without recording the device, OS
version, application build, source commit and evidence.

## Application-specific scope

The complete Smartable Wallet application has features outside this
published Core review, including:

- blockchain networks and their modules;
- transaction construction, review and signing;
- hardware wallets;
- WalletConnect and the embedded dApp browser;
- swaps and cross-chain routes;
- on-ramp and off-ramp integrations;
- the application screens, including the screen protections around secrets;
- private backend services, the RPC proxy and commercial routing logic;
- production release configuration.

These features must not be considered verified by this document unless they
are explicitly included in the scope and supported by release evidence.

## Release record

For each published Core release, record:

- release version;
- release date;
- Git tag;
- source commit;
- exact commands executed;
- test results;
- known limitations;
- dependency and licence review status;
- reproducible-build status, if available.

Example:

```markdown
### Release: VERSION

- Date:
- Git tag:
- Source commit:
- `flutter analyze`:
- `flutter test`:
- Native tests (application repository):
- Known limitations:
- Dependency review:
- Licence review:
- Reproducible-build status:
```

## Limitations

AI-assisted review is not an independent security audit.

AI-assisted review does not prove that the software is secure, correct or free
of vulnerabilities.

A successful test run does not prove that the wallet is free of vulnerabilities.
Tests only cover the behaviours they exercise.

A successful Android emulator check does not prove that the corresponding
physical Android or iOS behaviour is correct.

The published Core components do not represent the complete Smartable Wallet
application. The private application UI, backend infrastructure, RPC proxy,
commercial routing services and release configuration may introduce additional
risks outside the scope of this document.

Users should verify releases, review changes, keep recovery phrases secure,
maintain offline backups and test new or experimental features with small
amounts.