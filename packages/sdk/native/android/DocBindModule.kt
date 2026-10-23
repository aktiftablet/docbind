package com.securedoc.docbind

import android.app.Activity
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyInfo
import java.security.KeyFactory
import android.util.Base64
import android.view.WindowManager
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * React Native Android Native Module for DocBind:
 * 1. Enforces WindowManager.LayoutParams.FLAG_SECURE to prevent screenshots & screen recording.
 * 2. Generates non-extractable RSA-OAEP 2048 keys inside the hardware-backed AndroidKeyStore.
 */
class DocBindModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = "DocBindScreenGuard"
    override fun getConstants(): MutableMap<String, Any> = mutableMapOf("keyAlgorithm" to "RSA-OAEP-256-MGF1-SHA1")

    private fun requireHardwareKey(alias: String) {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(alias, null)
        val info = KeyFactory.getInstance("RSA", "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        if (!info.isInsideSecureHardware) throw IllegalStateException("Hardware-backed RSA required on this device")
    }

    @ReactMethod
    fun getPublicKeyPem(alias: String, promise: Promise) {
        try {
            requireHardwareKey(alias)
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val certificate = ks.getCertificate(alias) ?: throw IllegalStateException("Key not found")
            promise.resolve(formatPem(Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP)))
        } catch (e: Exception) { promise.reject("KEYSTORE_ERROR", e.message, e) }
    }

    @ReactMethod
    fun enableSecureFlag(promise: Promise) {
        val activity: Activity? = currentActivity
        if (activity == null) {
            promise.resolve(null)
            return
        }
        activity.runOnUiThread {
            activity.window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
            promise.resolve(null)
        }
    }

    @ReactMethod
    fun disableSecureFlag(promise: Promise) {
        val activity: Activity? = currentActivity
        if (activity == null) {
            promise.resolve(null)
            return
        }
        activity.runOnUiThread {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            promise.resolve(null)
        }
    }

    @ReactMethod
    fun hasKeyPair(alias: String, promise: Promise) {
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            promise.resolve(ks.containsAlias(alias))
        } catch (e: Exception) {
            promise.reject("KEYSTORE_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun generateRsaKeyPair(alias: String, promise: Promise) {
        try {
            val existing = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (existing.containsAlias(alias)) {
                getPublicKeyPem(alias, promise)
                return
            }
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                "AndroidKeyStore"
            )
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
            )
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .build()

            kpg.initialize(spec)
            val keyPair = kpg.generateKeyPair()
            requireHardwareKey(alias)
            val spkiBase64 = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
            val pem = formatPem(spkiBase64)
            promise.resolve(pem)
        } catch (e: Exception) {
            promise.reject("KEYGEN_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun rsaOaepDecrypt(alias: String, encryptedDekBase64: String, promise: Promise) {
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            requireHardwareKey(alias)
            val privateKey = ks.getKey(alias, null)
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            val oaepParams = OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA1,
                PSource.PSpecified.DEFAULT
            )
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams)
            val ciphertext = Base64.decode(encryptedDekBase64, Base64.DEFAULT)
            val dekBytes = cipher.doFinal(ciphertext)
            val resultBase64 = Base64.encodeToString(dekBytes, Base64.NO_WRAP)
            dekBytes.fill(0)
            promise.resolve(resultBase64)
        } catch (e: Exception) {
            promise.reject("DECRYPT_ERROR", e.message, e)
        }
    }

    private fun formatPem(base64: String): String {
        val chunked = base64.chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$chunked\n-----END PUBLIC KEY-----"
    }
}
