# Versions and releases

How a version of Smartable Wallet Core is numbered, recorded, made and
checked.

## Where the code comes from

This repository is assembled from the source of the Smartable Wallet
application. An export copies the files the application's manifest lists —
unchanged, except that the tests import this package by its own name — and
writes `pubspec.yaml` with every dependency pinned to the exact version the
application ships. Nothing is edited here directly: what you read is what the
application runs.

So a change, including one proposed in a pull request, is made in the
application's source and arrives here with the next version. See
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Version numbers

The core has its own version, following
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). It moves only when
the core does: an application release that leaves these files untouched makes
no new version of the core.

What the three numbers mean for this code:

| Change | What it is here |
|---|---|
| **Major** — `2.0.0` | Data written by an earlier version can no longer be read: a sealed PIN, a stored secret, a sealed share, or the bytes a typed secret becomes. Or a public declaration under `lib/core/` is removed or changes meaning. |
| **Minor** — `1.1.0` | A new capability, or a new format while every earlier one is still read. The PIN's second format was this kind: a PIN sealed in the first format still opens and moves to the second the next time
the PIN is used. |
| **Patch** — `1.0.1` | A fix that changes no format and no public declaration. |

A security fix is recorded under **Security** at whichever of the three levels
its change belongs to.

## The changelog

[CHANGELOG.md](../CHANGELOG.md) follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/):

- Changes collect under `## [Unreleased]` until a version is made, which renames
  that heading to `## [X.Y.Z] - YYYY-MM-DD`.
- The first line under a version says which application release its files came
  from: `Exported from Smartable Wallet 2.3.0 (build 21).` The export refuses a
  dated version without that line.
- Changes are grouped as **Added**, **Changed**, **Deprecated**, **Removed**,
  **Fixed** and **Security**. A change that makes a major version starts with
  **BREAKING:** and says what an earlier version's data or caller must do.
- An entry says what changed for somebody relying on the code — not how the
  code was edited.
- A security fix is described once the application release that carries it is
  out; until then the entry says only that a security issue was fixed.

## How a version is made

1. The change lands in the application's source, with its tests.
2. Its changelog entry is written, and `[Unreleased]` becomes the new version.
3. The export writes the new version over this repository's previous state and
   runs `flutter pub get`, `flutter analyze` and `flutter test` on the result.
4. It arrives as a pull request named for the version. Its diff is exactly the
   change between the two versions, and the CI checks run on it before it is
   merged. The merge commit is tagged `vX.Y.Z`.
5. The [release workflow](../.github/workflows/release.yml) refuses unless the
   tag, the version in `pubspec.yaml` and a dated changelog entry all agree. It
   then runs the analysis and the tests again, archives the tagged source with
   `git archive`, writes `SHA256SUMS`, signs a provenance attestation and
   publishes the release, with the changelog entry as its notes.

Each release is kept: a new version is added beside the earlier ones and none
is replaced.

## Checking a release

Download the archive and `SHA256SUMS` from the release, then:

```bash
sha256sum -c SHA256SUMS
gh attestation verify smartable-wallet-core-vX.Y.Z.tar.gz --repo getsmartable-app/core
```

The first shows the archive is the one the release lists. The second shows it
was built by this repository's release workflow from the tagged commit,
through GitHub's signing identity, without trusting us.

Neither shows that an application binary was built from this source. The core
is not a build of the application, and no reproducible build is claimed.

## Supported versions

Which versions receive security fixes is in [SECURITY.md](../SECURITY.md).
