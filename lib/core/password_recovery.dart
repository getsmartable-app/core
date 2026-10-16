/// Whether a forgotten password can be replaced from this device, and why not.
///
/// **One password covers every phrase on the device.** Replacing it re-seals
/// them all, so it is only safe when every phrase is in hand — and after a
/// quick unlock only the wallet that blob was sealed for is. That is not a
/// missing feature: setting a new password while another wallet's phrase is
/// closed would re-seal the list around a phrase nothing could open again.
///
/// Three answers rather than a yes and a no, because the middle one is the
/// state somebody is actually in when they are stuck, and hiding it looks
/// exactly like the app having nothing to say. See
/// `docs/BIOMETRIC_UNLOCK.md`.
library;

enum PasswordRecoveryOffer {
  /// Nothing to offer, and nothing to explain.
  ///
  /// No quick unlock armed, no password to replace, a locked wallet, or an
  /// account this phrase does not derive — a watched address, an imported key,
  /// a hardware account. Recovery belongs to the phrase, and those accounts are
  /// not it.
  none,

  /// Every phrase is open, and a quick unlock can prove this wallet.
  available,

  /// A quick unlock opens this wallet, and another on this device is closed.
  ///
  /// The way through is that wallet's password, so the sentence says so. The
  /// offer is withheld rather than shown and then refused, and the reason is
  /// shown rather than left as silence.
  otherWalletsClosed,
}
