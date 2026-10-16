package com.smartable.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The PIN pepper key's rules that hold without a key store: what it will MAC,
 * and that it is a key of its own.
 *
 * Whether the keystore makes it, computes with it and refuses while the phone
 * is locked is a phone's to answer — see `STATUS.md`.
 */
class PinPepperKeyRulesTest {
    @Test
    fun itKeysWhatAPinNeedsAndNothingLarger() {
        // A domain tag, a 16-byte salt and six to twelve digits.
        assertTrue(PinPepperKey.acceptsInput("smartable-pin-v2|".length + 16 + 13))
        assertTrue(PinPepperKey.acceptsInput(PinPepperKey.MAX_INPUT))
        assertFalse(PinPepperKey.acceptsInput(PinPepperKey.MAX_INPUT + 1))
        assertFalse(PinPepperKey.acceptsInput(0))
    }

    @Test
    fun itIsNotTheDeviceKeyUnderAnotherName() {
        // Forgetting one must never drop the other, and a key made for one
        // purpose must never be asked to serve both.
        for (alias in listOf(
            HardwareVaultKey.VAULT_ALIAS,
            HardwareVaultKey.DEVICE_ALIAS,
            HardwareVaultKey.DEVICE_UNLOCKED_ALIAS,
        )) {
            assertNotEquals(alias, PinPepperKey.ALIAS)
        }
        assertEquals("com.smartable.wallet/pin_pepper", PinPepperKey.CHANNEL)
    }
}
