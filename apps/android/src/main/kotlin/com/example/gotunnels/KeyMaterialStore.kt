package com.example.gotunnels

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores WireGuard private material without putting the X25519 key itself in
 * Android Keystore, which does not expose an X25519 key type. The Keystore
 * holds a non-exportable AES wrapping key; only the encrypted blob is kept in
 * private app storage. The service receives an alias and decrypts the value
 * immediately before handing it to the reviewed WireGuard engine.
 */
class KeyMaterialStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /** Saves or replaces one device-local WireGuard private key. */
    fun saveWireGuardPrivateKey(alias: String, privateKey: String) {
        validateAlias(alias)
        require(privateKey.isNotEmpty()) { "private key is required" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key(alias))
        val ciphertext = cipher.doFinal(privateKey.toByteArray(StandardCharsets.UTF_8))
        val payload = ByteArray(cipher.iv.size + ciphertext.size)
        cipher.iv.copyInto(payload)
        ciphertext.copyInto(payload, destinationOffset = cipher.iv.size)
        check(preferences.edit().putString(alias, Base64.encodeToString(payload, Base64.NO_WRAP)).commit()) {
            "could not persist WireGuard private key"
        }
    }

    /** Loads one private key; callers should keep the returned value short-lived. */
    fun loadWireGuardPrivateKey(alias: String): String {
        validateAlias(alias)
        val encoded = preferences.getString(alias, null) ?: error("WireGuard key is not enrolled")
        val payload = Base64.decode(encoded, Base64.DEFAULT)
        require(payload.size > GCM_IV_BYTES) { "stored WireGuard key is invalid" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            key(alias),
            GCMParameterSpec(GCM_TAG_BITS, payload.copyOfRange(0, GCM_IV_BYTES)),
        )
        return String(cipher.doFinal(payload.copyOfRange(GCM_IV_BYTES, payload.size)), StandardCharsets.UTF_8)
    }

    /** Removes local key material and its non-exportable wrapping key. */
    fun deleteWireGuardPrivateKey(alias: String) {
        validateAlias(alias)
        preferences.edit().remove(alias).commit()
        keyStore.deleteEntry(keystoreAlias(alias))
    }

    private fun key(alias: String): SecretKey {
        val name = keystoreAlias(alias)
        (keyStore.getKey(name, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                name,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun keystoreAlias(alias: String): String = "$KEY_PREFIX$alias"

    private fun validateAlias(alias: String) {
        require(ALIAS_PATTERN.matches(alias)) { "invalid key alias" }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val PREFERENCES = "device_key_material"
        const val KEY_PREFIX = "gotunnels.wg."
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
        val ALIAS_PATTERN = Regex("[A-Za-z0-9._-]{1,64}")
    }
}
