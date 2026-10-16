package com.smartable.wallet

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * An HMAC key in the phone's keystore that every PIN guess has to go through.
 *
 * **What it changes.** The PIN is six digits. Its wrapper is sealed by the
 * device key, so a guess cannot be made anywhere but this phone — until
 * somebody makes *one* call to that key (root, an instrumented process, a
 * forensic tool on an unlocked phone) and takes the outer seal off. Then the
 * million PINs under it were PBKDF2 alone: 2.4 hours on the eight cores of an
 * Apple M3 laptop, measured 3 October 2026, and far less on a graphics card.
 * A memory-hard function in its place would have doubled that (Argon2id at
 * 64 MiB, measured beside it: 0.13 s a guess against 0.068) and still left the
 * work to be done anywhere.
 *
 * With this key the PIN is first run through an HMAC the keystore computes and
 * never hands out, so the derivation cannot be finished without the phone:
 * every one of the million guesses is a keystore operation, made one at a
 * time on this device, while it stays unlocked and compromised. The work moves
 * off rented hardware and onto the victim's phone.
 *
 * **What it does not change**, said as plainly as `PinLock` says the rest: an
 * unlocked, rooted phone can still make those calls, and a person typing a PIN
 * into a compromised phone can be watched doing it. The password and the phrase
 * are what stand behind the PIN there.
 *
 * Bound like the PIN's device key: StrongBox where the phone has one, the TEE
 * where it does not, no user authentication, and from Android 15 refused while
 * the phone is locked ([HardwareVaultKey.unlockedOnlyApplies]).
 *
 * **Never made by a guess.** `mac` uses the key that exists and answers
 * `key_gone` when there is none: a new key would give every PIN a different
 * answer, and the person would be told their right PIN was wrong and
 * throttled for it. Only `prepare`, called when a PIN is armed, makes one.
 */
class PinPepperKey {
    companion object {
        const val CHANNEL = "com.smartable.wallet/pin_pepper"
        const val ALIAS = "smartable.pin.pepper"

        private const val LOG_TAG = "SmartableKey"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val ALGORITHM = "HmacSHA256"

        /**
         * The most a caller may ask to be MACed: a domain tag, a 16-byte salt
         * and six digits fit in far less. Bounded so the channel is not an
         * HMAC oracle for anything else somebody might hand it.
         */
        const val MAX_INPUT = 128

        fun acceptsInput(size: Int): Boolean = size in 1..MAX_INPUT
    }

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isSupported" -> result.success(existing() != null || canCreate())
            "prepare" -> result.success(prepare())
            "mac" -> mac(call, result)
            "forget" -> {
                forget()
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun keystore(): KeyStore =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun existing(): SecretKey? = try {
        keystore().getKey(ALIAS, null) as? SecretKey
    } catch (e: Exception) {
        android.util.Log.w(LOG_TAG, "pin pepper read refused", e)
        null
    }

    /** Whether a key could be made, without leaving one behind. */
    private fun canCreate(): Boolean = prepare().also { made ->
        if (made) forget()
    }

    /** The key, made if there is none. True when one exists afterwards. */
    private fun prepare(): Boolean {
        if (existing() != null) return true
        return try {
            val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM &&
                HardwareVaultKey.unlockedOnlyApplies(Build.VERSION.SDK_INT)
            ) {
                builder.setUnlockedDeviceRequired(true)
            }
            strongBoxThenTee(builder)
            existing() != null
        } catch (e: Exception) {
            android.util.Log.w(LOG_TAG, "pin pepper generation refused", e)
            false
        }
    }

    private fun strongBoxThenTee(builder: KeyGenParameterSpec.Builder) {
        try {
            generate(builder, strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(builder, strongBox = false)
        }
    }

    /** The StrongBox flag set either way — see `HardwareVaultKey.generate`. */
    private fun generate(builder: KeyGenParameterSpec.Builder, strongBox: Boolean) {
        builder.setIsStrongBoxBacked(strongBox)
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    private fun mac(call: MethodCall, result: MethodChannel.Result) {
        val input = call.argument<ByteArray>("bytes")
        if (input == null || !acceptsInput(input.size)) {
            result.error("bad_argument", "Nothing to MAC.", null)
            return
        }
        val key = existing()
        if (key == null) {
            result.error("key_gone", "The PIN's device key is no longer available.", null)
            return
        }
        try {
            val mac = Mac.getInstance(ALGORITHM).apply { init(key) }
            result.success(mac.doFinal(input))
        } catch (e: UserNotAuthenticatedException) {
            result.error("auth_required", "The phone is locked.", null)
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            result.error("key_gone", "The PIN's device key was invalidated.", null)
        } catch (e: Exception) {
            android.util.Log.w(LOG_TAG, "pin pepper refused", e)
            result.error("unavailable", e.message ?: "Keystore refused.", null)
        }
    }

    private fun forget() {
        try {
            keystore().deleteEntry(ALIAS)
        } catch (e: Exception) {
            // Nothing to delete is the same outcome as having deleted it.
        }
    }
}
