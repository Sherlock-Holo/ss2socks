package encrypt

import dynamicBuffer.DynamicBuffer
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private interface GeneralCipher {
    // maybe some encrypt module doesn't use IV or Nonce
    fun getIVorNonce(): ByteArray?

    fun encrypt(plainText: ByteArray): ByteArray

    fun decrypt(cipherText: ByteArray): ByteArray

    fun encrypt(plainBuffer: ByteBuffer, cipherBuffer: ByteBuffer)

    fun decrypt(cipherBuffer: ByteBuffer, plainBuffer: ByteBuffer)
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

class AES256CTR(key: ByteArray, private var iv: ByteArray? = null): GeneralCipher {
    private val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    private val skey = SecretKeySpec(key, "AES")
    lateinit var tmpBuffer: ByteArray

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

    fun finish() {
        cipher.doFinal()
    }

    fun encrypt(plainBuffer: DynamicBuffer, cipherBuffer: DynamicBuffer) {
        tmpBuffer = ByteArray(plainBuffer.limit())
        plainBuffer.get(tmpBuffer)
        cipherBuffer.put(this.encrypt(tmpBuffer))
    }

    fun decrypt(cipherBuffer: DynamicBuffer, plainBuffer: DynamicBuffer) {
        tmpBuffer = ByteArray(cipherBuffer.limit())
        cipherBuffer.get(tmpBuffer)
        plainBuffer.put(this.decrypt(tmpBuffer))
    }
}