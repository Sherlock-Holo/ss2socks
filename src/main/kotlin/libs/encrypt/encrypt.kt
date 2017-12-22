package libs.encrypt

import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class Cipher(key: ByteArray, iv: ByteArray? = null, cipherMode: String) {
    private val inner: GeneralCipher
    init {
        when (cipherMode) {
            "aes-256-ctr" -> {
                inner = AES256CTR(key, iv)
            }
            else -> TODO("support other cipher mode")
        }
    }

    fun encrypt(plainText: ByteArray) = inner.encrypt(plainText)

    fun encrypt(plainBuffer: ByteBuffer, cipherBuffer: ByteBuffer) = inner.encrypt(plainBuffer, cipherBuffer)

    fun decrypt(cipherText: ByteArray) = inner.decrypt(cipherText)

    fun decrypt(cipherBuffer: ByteBuffer, plainBuffer: ByteBuffer) = inner.decrypt(cipherBuffer, plainBuffer)

    fun finish() = inner.finish()

    fun getIVorNonce() = inner.getIVorNonce()
}

interface GeneralCipher {
    // maybe some encrypt module doesn't use IV or Nonce
    fun getIVorNonce(): ByteArray? = null

    fun encrypt(plainText: ByteArray): ByteArray

    fun decrypt(cipherText: ByteArray): ByteArray

    fun encrypt(plainBuffer: ByteBuffer, cipherBuffer: ByteBuffer)

    fun decrypt(cipherBuffer: ByteBuffer, plainBuffer: ByteBuffer)

    fun finish()
}

fun password2key(passwd: String): ByteArray {
    var keyGen = MessageDigest.getInstance("MD5")
    keyGen.update(passwd.toByteArray())
    var encodeKey = keyGen.digest()
    keyGen = MessageDigest.getInstance("MD5")
    keyGen.update(encodeKey + passwd.toByteArray())
    encodeKey += keyGen.digest()
    return encodeKey
}

private class AES256CTR(key: ByteArray, private var iv: ByteArray? = null): GeneralCipher {
    private val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    private val skey = SecretKeySpec(key, "AES")

    init {
        if (iv != null) {
            cipher.init(Cipher.DECRYPT_MODE, skey, IvParameterSpec(iv))
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, skey)
            this.iv = cipher.iv
        }
    }

    override fun encrypt(plainText: ByteArray): ByteArray {
        return cipher.update(plainText)
    }

    override fun decrypt(cipherText: ByteArray): ByteArray {
        return cipher.update(cipherText)
    }

    override fun getIVorNonce(): ByteArray? {
        return iv
    }

    override fun encrypt(plainBuffer: ByteBuffer, cipherBuffer: ByteBuffer) {
        cipher.update(plainBuffer, cipherBuffer)
    }

    override fun decrypt(cipherBuffer: ByteBuffer, plainBuffer: ByteBuffer) {
        cipher.update(cipherBuffer, plainBuffer)
    }

    override fun finish() {
        cipher.doFinal()
    }
}