import 'dart:async';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

/// The keystore every test runs against — the half of `flutter_test_config.dart`
/// the published core needs too.
///
/// **A file of its own since 15 October 2026** so the core publishes this as its
/// `test/flutter_test_config.dart` (`export_manifest.txt`) without the app's
/// network choices, which the app's own config adds around it.
///
/// **The suite was passing through the plaintext fallback and nobody could
/// see it.** `flutter_secure_storage` has no implementation on a test host, so
/// every write to it threw, and `SecureStorage.write` answered that by putting
/// the value in SharedPreferences — which is exactly the behaviour that has
/// just been forbidden for secrets. Every wallet these tests create was being
/// stored the weak way, and the tests were green, because green was all the
/// fallback was for.
///
/// Making `writeSecret` refuse turned 114 of them red at once. That is the
/// change working: the tests were relying on a path that must not exist. The
/// answer is to give them a keystore rather than to give the app a hole —
/// `setMockInitialValues` installs the plugin's own in-memory store, so the
/// secure path is what runs here, as it does on a phone.
///
/// A `flutter_test_config.dart` rather than a line in every `setUp`: a test
/// file that forgot it would go green through the fallback again, and the one
/// thing this must not be is opt-in.
Future<void> testExecutable(FutureOr<void> Function() testMain) async {
  TestWidgetsFlutterBinding.ensureInitialized();

  // **Emptied between tests, not once at the start.** Each test used to begin
  // with `SharedPreferences.setMockInitialValues({})`, and that wiped
  // everything precisely because everything was landing in preferences. With
  // secrets in a keystore of their own, a single store for the whole file
  // carries one test's wallet into the next — which showed up immediately as
  // favourites and sort orders surviving a wipe that no longer reached them.
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
  });

  FlutterSecureStorage.setMockInitialValues({});
  await testMain();
}
