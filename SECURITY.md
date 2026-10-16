# Security policy

## Scope

This security policy covers the Smartable Wallet Core repository and the
security-critical components published in it.

The main Smartable Wallet application, private backend infrastructure,
commercial routing logic and unpublished product code are outside the scope of
this repository unless explicitly stated otherwise.

Application-specific release verification is maintained separately from this
Core security policy.

Application release records may be stored in the application repository, in a
private release repository, or in a combined repository containing the
application and Core. **They are not published here.**

Application-specific release records may include UI, backend, native platform,
device, network and production-configuration checks that are outside the scope
of this public Core repository, and a completed record may contain device
identifiers, test-wallet details or other non-public release data.

Keeping such a record in this repository would also make a claim it cannot
support: an application release document sitting beside the Core review reads
as though the Core review covered the application.

## Reporting a vulnerability

Please report suspected security vulnerabilities privately.

Email:

[hello@getsmartable.app](mailto:hello@getsmartable.app)

Or use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**.

Do not publish a vulnerability as a public GitHub issue before we have had a
reasonable opportunity to investigate it.

Please include:

- affected file, component or version;
- clear description of the issue;
- steps to reproduce;
- proof of concept, if available;
- possible security impact;
- suggested mitigation, if known.

Never include a recovery phrase, private key, password or real wallet funds in a
report.

## Response targets

We will try to:

- acknowledge the report within 7 days;
- provide an initial assessment within 14 days;
- communicate a mitigation or release plan after investigation.

These are response targets, not guaranteed service levels.

## Disclosure

We may coordinate a public disclosure after a fix is available and affected
users have had a reasonable opportunity to update.

We will credit researchers who want to be credited, unless they prefer to remain
anonymous.

## Security assumptions

Smartable Wallet is a non-custodial wallet, and this core is the part of it
that keeps keys on the device. Private keys and recovery phrases are intended to
remain on the user's device.

This project does not guarantee:

- that the software is free of vulnerabilities;
- that every release binary corresponds to the published source;
- that third-party networks, RPC providers or swap providers are reliable;
- that funds can be recovered after a user loses a recovery phrase;
- that a third-party integration is safe merely because it is supported.

Users should verify release versions, review changes, test with small amounts and
keep secure backups.

## Audit status

No independent security audit is claimed unless a dated audit report is linked
here. Reports are kept in this repository under `audit/`, named by date.

Current status:

- Independent security audit: not completed.
- Reproducible builds: not yet verified unless stated for a specific release.
- Maintainer security review: ongoing.
- AI-assisted review: performed during development.

AI-assisted review was performed using Claude Code with Claude Opus 5 and
additional AI-assisted review passes.

AI assistance was used to identify possible defects, missing tests, unsafe
assumptions and inconsistencies. AI output was treated as a source of
hypotheses and review suggestions, not as proof of correctness.

AI-assisted review is not an independent security audit and does not establish
that the software is secure.

For the detailed review method and Core release-by-release results, see
[SECURITY_REVIEW.md](SECURITY_REVIEW.md).

Application-specific review results, device testing, network testing, backend
verification and release limitations are maintained separately from this
public Core review unless explicitly included.

## Verification levels

Security-sensitive claims are verified at separate levels. Passing one level
does not imply that another level has passed.

The project distinguishes:

- **Code verified** — the implementation was reviewed at source level and the
  relevant behaviour is supported by the code.
- **Automated tested** — relevant unit, widget, integration, protocol or
  regression tests passed.
- **Simulator tested** — the feature was exercised in an iOS Simulator or
  Android Emulator where applicable.
- **Physical device tested** — the feature was exercised on a physical,
  supported device.
- **Production-like network tested** — the feature was exercised against a
  production-like blockchain, RPC, indexer or service environment.
- **Production configuration reviewed** — release build settings, platform
  entitlements, service configuration, logging, feature flags and release
  configuration were reviewed.

A simulator or emulator result must not be described as a physical-device
result.

Automated tests and emulator tests do not verify hardware-backed Keychain or
Keystore behaviour, biometric invalidation, every backup/restore path or all
platform-specific capture behaviour.

A feature must not be described as fully verified while an applicable
verification level remains pending.

`N/A` may be used only when a verification level genuinely does not apply to a
feature. It must not be used when testing has merely not been performed.

Evidence for a verification result may include:

- source commit or Git tag;
- test file and test name;
- exact command;
- device model and operating-system version;
- application version and build number;
- network, chain and RPC environment;
- transaction hash, receipt or fixture;
- backend log, privacy or retention review.

Detailed application release records may be maintained privately when they
contain internal device identifiers, test-wallet details, backend information
or other non-public release data.

## Supported versions

| Version | Status |
|---|---|
| The latest release | Supported |
| Previous releases | Best effort |
| Unreleased commits | Not supported |

A version is considered supported only when it is identified by a published
release and a corresponding source commit or tag. Releases are listed on this
repository's Releases page.

## Release verification

For each supported Core release, the project should record:

- Core version;
- release date;
- Git tag or source commit;
- exact commands executed;
- test results;
- known limitations;
- dependency and licence review status;
- checksums where available;
- reproducible-build status, if verified.

Application releases may require additional verification outside this Core
repository, including:

- application version and build number;
- native iOS and Android checks;
- simulator or emulator results;
- physical-device results;
- production-like network results;
- backend and privacy review;
- production configuration review;
- application-specific known limitations.

The exact application release record may be maintained in the application
repository, a private release repository or another documented release system.

A release must not describe a feature as fully verified when an applicable
physical-device, production-like-network or production-configuration check is
still pending.

A successful test run does not prove that the software is free of
vulnerabilities. Tests only cover the behaviours they exercise.

## Application feature scope

The complete Smartable Wallet application has features that are outside the
published Core scope, such as:

- blockchain networks and their modules;
- transaction construction, review and signing;
- hardware wallets;
- WalletConnect and the embedded dApp browser;
- swaps and cross-chain routes;
- on-ramp or off-ramp integrations;
- private backend services and commercial routing logic.

Application-specific features must not be presented as independently verified
by this Core repository unless they are explicitly included in the documented
scope and evidence.

## Security expectations

Before using the wallet with real funds:

- verify that the application was obtained from an official distribution
  channel;
- verify the application version where possible;
- review the corresponding release notes;
- keep the recovery phrase offline and private;
- never share a recovery phrase, private key or password with support;
- test new or experimental networks with a small amount first;
- verify the recipient, network, amount, fee and transaction details before
  signing;
- treat unsupported, unknown or unverified contract actions with caution;
- do not assume that a successful simulation guarantees transaction success;
- keep the application and operating system updated.

## Third-party services

The wallet may depend on third-party services, including blockchain networks,
RPC providers, indexers, price providers, swap providers, on-ramp providers
and phishing or domain-verification services.

Third-party service support does not mean that the service is trusted to hold
private keys or that its data is complete, accurate or available.

Application release records should document material third-party dependencies and
known service limitations where applicable.

## Privacy

Public blockchain addresses are not secret keys, but they may still be
sensitive personal or financial data when combined with IP addresses,
timestamps, device identifiers, request history, transaction history,
WalletConnect metadata or other service data.

The project should minimize collection and retention of such data.

Application release processes should review, where applicable:

- address logging;
- IP and address correlation;
- analytics events;
- crash reports and breadcrumbs;
- RPC and indexer requests;
- WalletConnect metadata;
- extended public keys;
- backend retention periods;
- third-party provider data handling.

Private keys, recovery phrases, passwords and other authentication secrets must
not be sent to network services.

## Contact

Security reports:

[hello@getsmartable.app](mailto:hello@getsmartable.app)

Support will never ask for your recovery phrase, private key or password.