package com.smartable.wallet

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which Android versions get the PIN's key that refuses while the phone is
 * locked (audit M2).
 *
 * **The line is Google's, not ours.** The `setUnlockedDeviceRequired`
 * documentation lists four bugs in Android 12 to 14 — no such key without a
 * secure lock screen, every such key deleted when the lock screen is removed,
 * no release by a face unlock, none in a profile sharing its parent's lock —
 * fixed in 15, and advises the flag only from there. Each of those would be a
 * PIN that stops working for a reason nobody could connect to it.
 */
class HardwareVaultKeyRulesTest {
    @Test
    fun androidFifteenAndLaterGetTheKey() {
        assertTrue(HardwareVaultKey.unlockedOnlyApplies(35))
        assertTrue(HardwareVaultKey.unlockedOnlyApplies(36))
        assertTrue(HardwareVaultKey.unlockedOnlyApplies(37))
    }

    @Test
    fun theVersionsWithTheBugsDoNot() {
        for (sdk in 31..34) {
            assertFalse("API $sdk", HardwareVaultKey.unlockedOnlyApplies(sdk))
        }
    }

    @Test
    fun nothingOlderDoesEither() {
        for (sdk in 24..30) {
            assertFalse("API $sdk", HardwareVaultKey.unlockedOnlyApplies(sdk))
        }
    }
}
