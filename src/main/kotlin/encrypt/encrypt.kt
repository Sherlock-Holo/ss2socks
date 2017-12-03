package encrypt

import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

val EncryptMode = 0
val DecryptMode = 1

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
    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    val skey = SecretKeySpec(key, "AES")

    init {
        if (iv != null) {
//            cipher.init(Cipher.DECRYPT_MODE, skey, IvParameterSpec(iv))
            init(DecryptMode, iv)
        } else {
            init(EncryptMode)
        }
    }

    private fun init(mode: Int, iv: ByteArray? = null) {
        when (mode) {
            EncryptMode -> {
                cipher.init(Cipher.ENCRYPT_MODE, skey)
                this.iv = cipher.iv
            }

            DecryptMode -> {
                if (iv != null) {
                    cipher.init(Cipher.DECRYPT_MODE, skey, IvParameterSpec(iv))
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, skey, IvParameterSpec(getIVorNonce()))
                }
            }
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

    fun stop() {
        cipher.doFinal()
    }
}

fun main(args: Array<String>) {
    val plainText = "sherlock".toByteArray()
    val key = password2key("qlx")

    val en = AES256CTR(key)
    val iv = en.getIVorNonce()!!

    val de = AES256CTR(key, iv)

    val cipherText = en.encrypt(plainText)
    println(String(de.decrypt(cipherText.copyOfRange(0, 3))))
    println(String(de.decrypt(cipherText.copyOfRange(3, cipherText.size))))
}