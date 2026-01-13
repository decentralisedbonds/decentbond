package com.example.decentbond

import android.content.Context
import android.util.Base64
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.spec.RSAPublicKeySpec
import java.security.interfaces.RSAPrivateKey
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.spec.RSAPrivateCrtKeySpec
import java.nio.ByteBuffer
import java.security.interfaces.RSAPrivateCrtKey
import java.util.Base64.getDecoder
object KeyUtils {

    /* ------------------------------------------------------------------ */
    /*  Constants                                                        */
    /* ------------------------------------------------------------------ */
    private const val RSA_ALGORITHM = "RSA"
    private const val SIGNATURE_ALGORITHM = "SHA256withRSA"

    /** AES‑GCM (12‑byte IV, 128‑bit tag) */
    private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128

    /** PBKDF2 parameters – 256‑bit key, 65536 iterations */
    private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
    private const val PBKDF2_ITERATIONS = 65536
    private const val KEY_SIZE_BITS = 256
    private const val SALT_LENGTH = 16   // bytes
    private const val IV_LENGTH = 12     // bytes

    /* ------------------------------------------------------------------ */
    /*  In‑memory key pair (singleton)                                   */
    /* ------------------------------------------------------------------ */
    @Volatile
    private var keyPair: KeyPair? = null

    /* ------------------------------------------------------------------ */
    /*  Public helpers – key generation & signing                       */
    /* ------------------------------------------------------------------ */
    @Synchronized
    fun generateRSAKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance(RSA_ALGORITHM)
        generator.initialize(2048, SecureRandom())
        return generator.generateKeyPair()
    }

    fun publicKeyFromBase64Url(b64Url: String): PublicKey {
        // Convert the URL‑safe string back to normal Base64
        val b64 = b64Url.replace('-', '+').replace('_', '/')
        val padded = when (b64.length % 4) {
            2 -> b64 + "=="
            3 -> b64 + "="
            else -> b64
        }
        val derBytes = java.util.Base64.getDecoder().decode(padded)

        val keyFactory = KeyFactory.getInstance(RSA_ALGORITHM)
        return keyFactory.generatePublic(X509EncodedKeySpec(derBytes))
    }

    fun verifySignatureWithPublicKey(
        data: ByteArray,
        signatureBytes: ByteArray,
        publicKey: PublicKey
    ): Boolean {
        val verifier = java.security.Signature.getInstance(SIGNATURE_ALGORITHM)
        verifier.initVerify(publicKey)
        verifier.update(data)
        return verifier.verify(signatureBytes)
    }

    fun signData(data: ByteArray): ByteArray {
        val kp = getKeyPair()
        val signer = java.security.Signature.getInstance(SIGNATURE_ALGORITHM)
        signer.initSign(kp.private)
        signer.update(data)
        return signer.sign()
    }

    fun verifySignature(data: ByteArray, sigBytes: ByteArray): Boolean {
        val kp = getKeyPair()
        val verifier = java.security.Signature.getInstance(SIGNATURE_ALGORITHM)
        verifier.initVerify(kp.public)
        verifier.update(data)
        return verifier.verify(sigBytes)
    }

    /* ------------------------------------------------------------------ */
    /*  PEM helpers (public key only)                                    */
    /* ------------------------------------------------------------------ */
    fun getPublicKeyPem(): String {
        val kp = getKeyPair()
        val der = kp.public.encoded
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP)
        return buildString {
            appendLine("-----BEGIN PUBLIC KEY-----")
            b64.chunked(64).forEach { line -> appendLine(line) }
            append("-----END PUBLIC KEY-----")
        }
    }

    fun getPublicKeyPemBase64Url(): String {
        val kp = getKeyPair()
        val der = kp.public.encoded
        var b64 = Base64.encodeToString(der, Base64.NO_WRAP)
        b64 = b64.replace('+', '-').replace('/', '_').replace("=", "")
        return b64
    }

    /* ------------------------------------------------------------------ */
    /*  Persistence helpers – encrypted file in the app’s files dir      */
    /* ------------------------------------------------------------------ */
    private const val FILE_NAME = "private_key.enc"

    /** Returns true if the encrypted key file exists. */
    fun keyFileExists(context: Context): Boolean =
        File(context.filesDir, FILE_NAME).exists()

    /**
     *  Save the given RSA key pair to the app’s internal storage.
     *  The private key is encrypted with a key derived from the supplied password.
     *
     *  @param context  Android context
     *  @param password Password used to derive the AES key
     *  @param kp       The RSA key pair to persist (defaults to the current pair)
     */
    suspend fun saveKey(context: Context, password: String, kp: KeyPair = getKeyPair()) =
        withContext(Dispatchers.IO) {

            // --------------------------------------------------------------------
            // 1️⃣  Derive a 256‑bit AES key from the password + random salt
            // --------------------------------------------------------------------
            val salt = ByteArray(SALT_LENGTH)
            SecureRandom().nextBytes(salt)

            val secretKey = deriveKeyFromPassword(password, salt)

            // --------------------------------------------------------------------
            // 2️⃣  Encrypt the PKCS#8 private key bytes with AES‑GCM
            // --------------------------------------------------------------------
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)          // "AES/GCM/NoPadding"
            val iv = ByteArray(IV_LENGTH)
            SecureRandom().nextBytes(iv)

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            val pkcs8Bytes = (kp.private as RSAPrivateCrtKey).encoded
            val ciphertext = cipher.doFinal(pkcs8Bytes)

            // --------------------------------------------------------------------
            // 3️⃣  Prepare the public key bytes (X.509 encoding)
            // --------------------------------------------------------------------
            val publicKeyBytes = kp.public.encoded            // RSAPublicKey in X.509

            // --------------------------------------------------------------------
            // 4️⃣  Build the final payload
            // --------------------------------------------------------------------
            val pubLenBytes = ByteBuffer.allocate(4).putInt(publicKeyBytes.size).array()
            val payload = salt + iv + pubLenBytes + publicKeyBytes + ciphertext

            // --------------------------------------------------------------------
            // 5️⃣  Persist the payload
            // --------------------------------------------------------------------
            val file = File(context.filesDir, FILE_NAME)
            file.writeBytes(payload)
        }

    /**
     *  Load the RSA key pair that was stored by [saveKey].
     *
     *  @param context  Android context
     *  @param password Password that was used to encrypt the private key
     *  @return the loaded KeyPair or `null` if anything goes wrong
     */
    suspend fun loadKey(context: Context, password: String): KeyPair? =
        withContext(Dispatchers.IO) {
            try {
                val file = File(context.filesDir, FILE_NAME)
                if (!file.exists()) return@withContext null

                val data = file.readBytes()

                // ---------- 1.  Pull out the header fields ----------
                val salt = data.copyOfRange(0, SALT_LENGTH)
                val iv   = data.copyOfRange(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)

                val pubLenOffset = SALT_LENGTH + IV_LENGTH
                val pubLenBytes = data.copyOfRange(pubLenOffset, pubLenOffset + 4)
                val pubLen = ByteBuffer.wrap(pubLenBytes).int

                val pubStart = pubLenOffset + 4
                val pubEnd   = pubStart + pubLen
                val publicKeyBytes = data.copyOfRange(pubStart, pubEnd)

                // The ciphertext starts right after the public key
                val ciphertextStart = pubEnd
                val ciphertext = data.copyOfRange(ciphertextStart, data.size)

                // ---------- 2.  Derive the AES key ----------
                val secretKey = deriveKeyFromPassword(password, salt)

                // ---------- 3.  Decrypt the private key ----------
                val cipher = Cipher.getInstance(AES_TRANSFORMATION)
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    secretKey,
                    GCMParameterSpec(GCM_TAG_LENGTH, iv)
                )
                val pkcs8Bytes = cipher.doFinal(ciphertext)

                // ---------- 4.  Reconstruct the key pair ----------
                val keyFactory = KeyFactory.getInstance("RSA")

                val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(pkcs8Bytes))
                val publicKey  = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

                val kp = KeyPair(publicKey, privateKey)
                keyPair = kp   // keep in memory for quick future access
                kp
            } catch (e: Exception) {
                // Any error (bad password, corrupted file, unsupported spec, …) → null
                null
            }
        }
    /* ------------------------------------------------------------------ */
    /*  Helpers – key derivation & in‑memory accessor                   */
    /* ------------------------------------------------------------------ */
    private fun deriveKeyFromPassword(password: String, salt: ByteArray): SecretKeySpec {
        val keySpec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE_BITS)
        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        val keyBytes = factory.generateSecret(keySpec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }

    @Synchronized
    private fun getKeyPair(): KeyPair {
        if (keyPair == null) {
            keyPair = generateRSAKeyPair()
        }
        return keyPair!!
    }

    @Synchronized
    fun clearKey() {
        keyPair = null
    }

    fun deleteKeyFile(context: Context): Boolean {
        val file = File(context.filesDir, FILE_NAME)

        return try {
            // Delete the file if it exists; File.delete() returns true on success
            if (file.exists()) {
                file.delete()
            }
            // Clear the in‑memory key so that any subsequent usage starts fresh
            clearKey()
            true
        } catch (e: Exception) {
            // Log the exception if you have a logger, otherwise swallow
            // For example: Log.e(TAG, "Failed to delete key file", e)
            false
        }
    }

}