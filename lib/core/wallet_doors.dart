/// Which doors this wallet actually has, for the sentences that name them.
///
/// **A wallet always has a password and may have no PIN**, and the app kept
/// forgetting the second half. Owner's reports, 21 September 2026: with the
/// PIN switched off, Android's fingerprint sheet offered *"Use PIN instead"*,
/// and cancelling it produced *"Quick unlock was cancelled. Your PIN and
/// password still open this wallet."* Both named a door that was not there.
/// A sweep found three more sentences doing the same thing.
///
/// **Every one of them is written where the answer cannot be awaited.**
/// `UnlockPromptWords` is built in `main.dart`'s `builder`, which has the
/// resolved language and no way to read secure storage; `unlockFailureText` is
/// a pure mapping from a failure to a sentence, called from six screens, some
/// of which have no wallet to ask. Threading a `Future<bool>` into all of that
/// would be plumbing in six places to answer one question — so the question is
/// answered once, where it is already asked, and remembered here.
///
/// **Kept fresh by the question itself.** Every `VaultKeeper.hasPin` writes
/// its answer here, including the one the lock screen asks while building the
/// unlock offer, immediately before the prompt — which is the only moment any
/// of this is read. Arming and disarming set it outright, so a door stops
/// being named the moment it stops existing.
///
/// **False is the default, and that is the safe direction.** Before anything
/// has been observed the sentences name the password, which every wallet has.
/// Being wrong the other way would send somebody looking for a PIN they never
/// set — or, on the system sheet, for the phone's own PIN, which this wallet
/// refuses as a door by design.
///
/// This is display only. Nothing decides what may open a wallet from here:
/// that is `UnlockOffer`, built from the real answers each time.
library;

/// Whether six digits will open this wallet, as last observed.
bool pinArmedAsObserved = false;

/// Test seam — the value above is process-wide.
void resetWalletDoorsForTest() => pinArmedAsObserved = false;
