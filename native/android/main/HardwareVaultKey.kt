package com.smartable.wallet

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import io.flutter.plugin.common.MethodCall
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * A key the app can use and cannot read.
 *
 * The wallet's vault key is a random 256 bits that seals the recovery phrase.
 * Until now the only thing protecting it was a password, and a password can be
 * guessed offline: copy the storage file, guess at leisure, and the wallet's
 * strength is whatever the person chose. This holds a second copy of that vault
 * key inside the phone's keystore, where it is generated, used, and never
 * handed back — the app can ask the chip to unwrap something, it cannot ask for
 * the key itself. Root does not change that on a device with a secure element,
 * because the key never enters the operating system's memory at all.
 *
 * **Bound to the person, not just the phone.** `setUserAuthenticationRequired`
 * means the chip refuses to use the key until the system gate has been passed
 * recently — a biometric or the device's own unlock code. That is what makes a
 * short PIN defensible later: there is nothing to attack offline, and every
 * attempt has to go through hardware that counts them and slows down.
 *
 * **Enrolling a new fingerprint destroys it.** Deliberate, and the one
 * behaviour worth understanding before shipping: somebody who can add their own
 * fingerprint to an unlocked phone would otherwise inherit the wallet. The key
 * dying is the correct outcome — the password still opens everything, and the
 * recovery phrase still exists.
 */
/**
 * @param alias which key in the store this instance speaks for.
 * @param requireAuth whether the chip refuses to use it until the person has
 *   proved who they are. True for the copy that stands behind quick unlock;
 *   **false** for the one the PIN sits on, and that difference is the whole
 *   design rather than a setting:
 *
 *   A six-digit PIN cannot protect anything by being hard to guess — a million
 *   combinations fall in milliseconds against a stolen file. What protects it
 *   is that the file cannot be attacked away from this phone at all, so every
 *   guess has to go through the running app and its throttle. A device-bound
 *   key gives exactly that and nothing more, which is why it does not ask for
 *   a fingerprint: requiring one would mean the PIN could only be typed by
 *   somebody who had already passed the gate the PIN exists to replace.
 */
class HardwareVaultKey(
    private val alias: String,
    private val requireAuth: Boolean,
    /**
     * The activity the prompt is drawn over. Null for the PIN's key, which
     * asks for nobody and must keep working with no UI at all.
     */
    private val activity: FragmentActivity? = null,
    /**
     * Whether the key refuses every use while the phone is locked (audit M2).
     * Only the PIN's second key sets it, and only where [unlockedOnlyApplies]:
     * on any other version this instance holds nothing and says so.
     */
    private val unlockedDeviceRequired: Boolean = false,
) {

    companion object {
        /** The copy behind quick unlock: released by the system gate. */
        const val CHANNEL = "com.smartable.wallet/hardware_key"
        const val VAULT_ALIAS = "smartable.vault.key"

        /** The copy behind the PIN: bound to the phone, gated by nothing. */
        const val DEVICE_CHANNEL = "com.smartable.wallet/device_key"
        const val DEVICE_ALIAS = "smartable.device.key"

        /**
         * The PIN's key on Android 15 and later: bound to the phone, and
         * usable only while the phone is unlocked (audit M2).
         *
         * **What that buys.** The PIN is six digits under PBKDF2, sealed by
         * this key. Whoever can make one call to the key — root, an
         * instrumented process, a forensic tool on a seized phone — takes the
         * outer layer off in that one call, and the million PINs under it are
         * then minutes of work on a graphics card, away from the phone and its
         * throttle. With this flag that one call fails while the phone is
         * locked, so a locked phone gives nothing to work on without its own
         * lock screen code. An unlocked, rooted phone still does: the password
         * and the phrase are what stand behind the PIN there.
         *
         * **A second alias, not the same one regenerated.** A key's flags are
         * fixed when it is made, and regenerating the old alias would destroy
         * the key that opens every PIN blob already stored. The old key stays
         * until the blob has been sealed again under this one — see
         * `PinLock.upgrade` — and is dropped only after that.
         */
        const val DEVICE_UNLOCKED_CHANNEL = "com.smartable.wallet/device_key_unlocked"
        const val DEVICE_UNLOCKED_ALIAS = "smartable.device.key.unlocked"

        /**
         * Android 15 and later, and never earlier — Google's own advice in the
         * `setUnlockedDeviceRequired` documentation. In Android 12 to 14 such a
         * key could not be made or used without a secure lock screen, was
         * deleted when the lock screen was removed, and was not released by a
         * face unlock on many phones — each of which would be a PIN that stops
         * working for a reason nobody could connect to it. Google fixed them in
         * 15 and advises the flag only from there; 9 to 11 are outside those
         * bugs but also outside that advice, and there is no such phone here
         * to measure one on. So below 15 the PIN keeps the key it has, and the
         * limit is written down rather than half-closed.
         */
        fun unlockedOnlyApplies(sdk: Int): Boolean =
            sdk >= Build.VERSION_CODES.VANILLA_ICE_CREAM

        private const val LOG_TAG = "SmartableKey"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORM = "AES/GCM/NoPadding"

        /** Nonce length for AES-GCM, and the prefix of every blob below. */
        private const val IV_BYTES = 12

        /**
         * The prompt's own words, in English, for when Dart has not sent any.
         *
         * **Fallbacks rather than the source.** These were the source, and the
         * sheet is drawn by the system on top of every screen this app has —
         * so the first thing a person saw on opening the wallet was English,
         * whatever language the other thirteen screens were in. The words now
         * arrive with the call, from the app's own bundle, which is also what
         * makes them follow the in-app language override rather than only the
         * phone's. These stay for the prompt raised before a widget tree
         * exists to ask.
         */
        private const val PROMPT_TITLE = "Unlock Smartable Wallet"
        private const val PROMPT_SUBTITLE = "Use your fingerprint to unlock"
        private const val PROMPT_CANCEL = "Use PIN instead"

        /**
         * Class 3 alone. `BIOMETRIC_STRONG` is what a keystore key can be
         * bound to; `BIOMETRIC_WEAK` — a Class 2 sensor — cannot back one on
         * any Android version, and `DEVICE_CREDENTIAL` is the phone's PIN,
         * password or **pattern**, which this wallet does not accept as a door.
         */
        private const val ALLOWED = BiometricManager.Authenticators.BIOMETRIC_STRONG
    }

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isSupported" -> result.success(isSupported())
            "describe" -> result.success(describe())
            "wrap" -> wrap(call, result)
            "unwrap" -> unwrap(call, result)
            "forget" -> {
                forget()
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    /**
     * Whether this device can hold the key at all.
     *
     * Answered by trying, not by reading a version number: a keystore that is
     * present and refuses to generate a key is a real device, and reporting it
     * as capable would mean an app that silently keeps no hardware copy while
     * telling the user it does.
     */
    private fun isSupported(): Boolean = try {
        if (unlockedDeviceRequired && !unlockedOnlyApplies(Build.VERSION.SDK_INT)) {
            false
        } else {
            val keystore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            keystore.containsAlias(alias) || createKey() != null
        }
    } catch (e: Exception) {
        false
    }

    /**
     * What is actually holding this key, for a screen that reports it.
     *
     * **It never creates one.** `isSupported` above deliberately does — it is
     * answering "can this phone do it" and the only honest way to answer that
     * is to try. This answers "what happened", and a report that arms a key as
     * a side effect of being read would be describing its own footprint.
     * So an absent alias comes back `exists: false`, and the screen says the
     * backing will be known once quick unlock or a PIN is set up.
     *
     * **`precise` is the field that keeps this honest.** Only API 31 reports
     * which kind of secure hardware a key sits in; before that the platform
     * answers a bare "inside secure hardware or not", so a phone with a real
     * StrongBox chip and one with only a TEE give the same answer. Claiming
     * either would be inventing it, and claiming StrongBox is the direction
     * that overstates what protects somebody's money.
     *
     * `SECURITY_LEVEL_UNKNOWN_SECURE` is its own case and not a failure: it
     * means the key *is* in secure hardware and the platform will not say which
     * kind. That is exactly `hardware` with `precise: false`.
     */
    private fun describe(): Map<String, Any> = try {
        val keystore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val secret = keystore.getKey(alias, null) as? SecretKey
        if (secret == null) {
            mapOf("exists" to false, "backing" to "unknown", "precise" to false)
        } else {
            val info = SecretKeyFactory
                .getInstance(secret.algorithm, KEYSTORE)
                .getKeySpec(secret, KeyInfo::class.java) as KeyInfo

            @Suppress("DEPRECATION")
            val legacy = if (info.isInsideSecureHardware) "hardware" else "software"

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX ->
                        mapOf("exists" to true, "backing" to "strongbox", "precise" to true)
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                        mapOf("exists" to true, "backing" to "hardware", "precise" to true)
                    KeyProperties.SECURITY_LEVEL_SOFTWARE ->
                        mapOf("exists" to true, "backing" to "software", "precise" to true)
                    KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE ->
                        mapOf("exists" to true, "backing" to "hardware", "precise" to false)
                    // SECURITY_LEVEL_UNKNOWN, and anything a later Android adds.
                    else -> mapOf("exists" to true, "backing" to legacy, "precise" to false)
                }
            } else {
                mapOf("exists" to true, "backing" to legacy, "precise" to false)
            }
        }
    } catch (e: Exception) {
        // Logged for the same reason every other refusal here is: the Dart side
        // has one answer for all of them, and a screen reporting "unknown" with
        // nothing anywhere saying why is how a day goes.
        android.util.Log.w(LOG_TAG, "describe refused", e)
        mapOf("exists" to false, "backing" to "unknown", "precise" to false)
    }

    private fun createKey(): SecretKey? {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(requireAuth)

        if (!requireAuth) {
            // The PIN's key, and it is deliberately the plainest thing in this
            // file: bound to this phone, released to this app, gated by
            // nothing. It must also survive a new fingerprint — see the
            // enrolment note below — because a PIN that dies when somebody adds
            // a finger is a PIN that dies for a reason nobody will connect to
            // it.
            if (unlockedDeviceRequired) {
                // Never made where it would be unreliable; see
                // [unlockedOnlyApplies].
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                    return null
                }
                builder.setUnlockedDeviceRequired(true)
            }
            return try {
                generatePreferringStrongBox(builder)
            } catch (e: Exception) {
                android.util.Log.w(LOG_TAG, "device key generation refused", e)
                null
            }
        }

        // **Per-use.** The key is released for one crypto
        // operation carried by the prompt itself and for nothing else.
        //
        // The old shape was a thirty-second validity window, and the window is
        // what admitted a pattern: a time-bound key is released by the
        // keyguard's record of *any* enrolled authentication, so a pattern
        // typed at the lock screen opened the wallet's key whatever the prompt
        // had asked for. That was not an Android 10 limitation and not a flag
        // — it was the window, and it is gone.
        // Zero seconds means per-use, and the authenticators argument is what
        // names the biometric as the only thing that releases it. The app's
        // floor is API 30 (`app/build.gradle.kts`), where this call exists; the
        // `setUserAuthenticationValidityDurationSeconds(-1)` route that 24–29
        // needed was never run on a phone and went with those versions.
        builder.setUserAuthenticationParameters(
            0,
            KeyProperties.AUTH_BIOMETRIC_STRONG,
        )

        // A newly enrolled fingerprint invalidates the key. See the class
        // comment: this is the point, not a limitation. It applies only to the
        // auth-bound copy — the PIN's key returned above never reaches this
        // line, because somebody adding a finger to their own phone has not
        // invalidated their PIN.
        builder.setInvalidatedByBiometricEnrollment(true)

        return try {
            generatePreferringStrongBox(builder)
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            android.util.Log.w(LOG_TAG, "key generation refused", e)
            null
        } catch (e: Exception) {
            android.util.Log.w(LOG_TAG, "key generation refused", e)
            null
        }
    }

    /**
     * StrongBox where the phone has one, the TEE where it does not.
     *
     * Most phones have no dedicated security chip. The keystore's TEE-backed
     * key is still a key the OS cannot read, and refusing to work without
     * StrongBox would mean protecting almost nobody.
     *
     * A failure of the TEE retry reaches the caller's handlers and is logged as
     * a refused generation; every caller answers it the same way —
     * `unavailable`.
     */
    private fun generatePreferringStrongBox(
        builder: KeyGenParameterSpec.Builder,
    ): SecretKey = strongBoxThenTee(builder)

    private fun strongBoxThenTee(builder: KeyGenParameterSpec.Builder): SecretKey =
        try {
            generate(builder, strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(builder, strongBox = false)
        }

    /**
     * **The flag is always set, never merely raised.**
     *
     * The retry in [strongBoxThenTee] hands the *same* builder back with
     * `strongBox = false`, and a builder remembers what it was told. Setting
     * the flag only in the true case therefore left `setIsStrongBoxBacked(true)`
     * in place on the
     * second attempt, which threw `StrongBoxUnavailableException` again — this
     * time out of the catch block, past every handler, into the generic
     * "this device cannot hold a key" answer.
     *
     * The visible result was quick unlock that could not be armed on any phone
     * without a dedicated security chip, which is most of them: the switch went
     * on, nothing was stored, and the unlock screen offered no fingerprint
     * because there was genuinely nothing behind it. A fallback that is never
     * reached is worse than no fallback, because it reads as working.
     */
    private fun generate(builder: KeyGenParameterSpec.Builder, strongBox: Boolean): SecretKey {
        builder.setIsStrongBoxBacked(strongBox)
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun key(): SecretKey? {
        val keystore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val existing = keystore.getKey(alias, null) as? SecretKey
        return existing ?: createKey()
    }

    /**
     * What the sheet should say, from the call, falling back to English.
     *
     * Blank is treated as absent: an empty title renders as a sheet with a
     * missing row rather than as a sheet nobody asked to name.
     */
    private fun words(call: MethodCall): Triple<String, String, String> {
        fun pick(name: String, fallback: String): String {
            val given = call.argument<String>(name)
            return if (given.isNullOrBlank()) fallback else given
        }
        return Triple(
            pick("promptTitle", PROMPT_TITLE),
            pick("promptSubtitle", PROMPT_SUBTITLE),
            pick("promptCancel", PROMPT_CANCEL),
        )
    }

    private fun wrap(call: MethodCall, result: MethodChannel.Result) {
        val plain = call.argument<ByteArray>("bytes")
        if (plain == null) {
            result.error("bad_argument", "Nothing to wrap.", null)
            return
        }
        try {
            val secret = key() ?: throw IllegalStateException("no key")
            val cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, secret) }
            // **The prompt carries the cipher, or there is no prompt at all.**
            // The PIN's key asks for nobody, so it finishes here; the vault's
            // key is per-use and finishes inside `authorised`.
            authorised(cipher, result, words(call)) { authed ->
                authed.iv + authed.doFinal(plain)
            }
        } catch (e: UserNotAuthenticatedException) {
            // The caller is expected to show the biometric prompt and try
            // again. Named separately so Dart can tell "prove it is you" apart
            // from "this device cannot do it".
            result.error("auth_required", "Authentication required.", null)
        } catch (e: Exception) {
            // Logged because the Dart side deliberately collapses every one of
            // these into "this device cannot", and quick unlock then fails with
            // nothing anywhere saying why. That cost a day: the keystore was
            // refusing for a reason it was perfectly willing to state.
            android.util.Log.w(LOG_TAG, "wrap refused", e)
            result.error("unavailable", e.message ?: "Keystore refused.", null)
        }
    }

    private fun unwrap(call: MethodCall, result: MethodChannel.Result) {
        val blob = call.argument<ByteArray>("bytes")
        if (blob == null || blob.size <= IV_BYTES) {
            result.error("bad_argument", "Nothing to unwrap.", null)
            return
        }
        try {
            val keystore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val secret = keystore.getKey(alias, null) as? SecretKey
            if (secret == null) {
                // The key is gone: a new fingerprint was enrolled, the screen
                // lock was removed, or the app's data was cleared. Not an
                // error to swallow — it means the password is the only way in
                // now, and the app has to say so rather than loop.
                result.error("key_gone", "The device key is no longer available.", null)
                return
            }
            val cipher = Cipher.getInstance(TRANSFORM).apply {
                init(
                    Cipher.DECRYPT_MODE,
                    secret,
                    GCMParameterSpec(128, blob, 0, IV_BYTES),
                )
            }
            authorised(cipher, result, words(call)) { authed ->
                authed.doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
            }
        } catch (e: UserNotAuthenticatedException) {
            result.error("auth_required", "Authentication required.", null)
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            result.error("key_gone", "The device key was invalidated.", null)
        } catch (e: Exception) {
            result.error("unavailable", e.message ?: "Keystore refused.", null)
        }
    }

    /**
     * Runs [use] on a cipher the person has just authorised, or refuses.
     *
     * **This is where a per-use key is actually released.** The cipher goes
     * into the prompt as a `CryptoObject`; the system returns it only after a
     * Class 3 biometric matched, and any other outcome returns nothing at all.
     * There is no code path here that produces plaintext without that match.
     *
     * **Every refusal is its own answer, because the app does different things
     * with them.** A cancel means the person chose the PIN and is not an error
     * to apologise for; a lockout means the sensor is closed for a while and
     * the PIN is the only way in; no strong biometric at all means this phone
     * — a Class 2 sensor, or nothing enrolled — never gets this door, and the
     * wallet has to say so rather than offer a fingerprint that cannot work.
     */
    private fun authorised(
        cipher: Cipher,
        result: MethodChannel.Result,
        say: Triple<String, String, String>,
        use: (Cipher) -> ByteArray,
    ) {
        if (!requireAuth) {
            result.success(use(cipher))
            return
        }
        val host = activity
        if (host == null) {
            result.error("unavailable", "No activity to authenticate against.", null)
            return
        }
        when (BiometricManager.from(host).canAuthenticate(ALLOWED)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Unit
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                return result.error(
                    "auth_unavailable", "No fingerprint is enrolled.", null)
            else ->
                // Includes a Class 2 sensor: `BIOMETRIC_STRONG` is what a
                // keystore key can be bound to, and a weak sensor answers
                // `ERROR_UNSUPPORTED` or `ERROR_NO_HARDWARE` here rather than
                // producing a key that cannot be used.
                return result.error(
                    "auth_unavailable", "No strong biometric on this device.", null)
        }

        val prompt = BiometricPrompt(
            host,
            ContextCompat.getMainExecutor(host),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    authResult: BiometricPrompt.AuthenticationResult,
                ) {
                    val authed = authResult.cryptoObject?.cipher
                    if (authed == null) {
                        // Never observed, and not assumed away: without the
                        // cipher back there is nothing the match authorised.
                        result.error("unavailable", "No cipher was returned.", null)
                        return
                    }
                    try {
                        result.success(use(authed))
                    } catch (e: Exception) {
                        android.util.Log.w(LOG_TAG, "authorised use refused", e)
                        result.error("unavailable", e.message ?: "Refused.", null)
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    val reason = when (code) {
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_CANCELED,
                        -> "auth_cancelled"
                        BiometricPrompt.ERROR_LOCKOUT,
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                        -> "auth_lockout"
                        else -> "auth_unavailable"
                    }
                    result.error(reason, message.toString(), null)
                }

                // A finger that did not match is not an outcome: the system
                // keeps the sheet up and lets the person try again, and
                // answering here would close a prompt Android is still showing.
                override fun onAuthenticationFailed() = Unit
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(say.first)
            .setSubtitle(say.second)
            // **The negative button is the app's own fallback, and it is
            // required.** Without `DEVICE_CREDENTIAL` in the allowed set the
            // builder demands one — and what it says is "use PIN instead",
            // meaning *this app's* PIN, not the phone's.
            .setNegativeButtonText(say.third)
            .setAllowedAuthenticators(ALLOWED)
            .setConfirmationRequired(false)
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    private fun forget() {
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias)
        } catch (e: Exception) {
            // Nothing to delete is the same outcome as having deleted it.
        }
    }
}
