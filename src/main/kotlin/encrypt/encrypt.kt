package encrypt

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

    fun bufferEncrypt(plainBuffer: ByteBuffer, cipherBuffer: ByteBuffer)

    fun bufferDecrypt(cipherBuffer: ByteBuffer, plainBuffer: ByteBuffer)
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

class AES256CFB(key: ByteArray, private var iv: ByteArray? = null): GeneralCipher {
    val cipher: Cipher

    init {
        val skey = SecretKeySpec(key, "AES")

        cipher = Cipher.getInstance("AES/CFB/NoPadding")

        if (iv != null) {
            cipher.init(Cipher.DECRYPT_MODE, skey, IvParameterSpec(iv))
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, skey)
            iv = cipher.iv
        }
    }

    override fun encrypt(plainText: ByteArray): ByteArray {
        return cipher.doFinal(plainText)
    }

    override fun decrypt(cipherText: ByteArray): ByteArray {
        return cipher.doFinal(cipherText)
    }

    override fun getIVorNonce(): ByteArray? {
        return iv
    }

    override fun bufferEncrypt(plainBuffer: ByteBuffer, cipherBuffer: ByteBuffer) {
        cipher.doFinal(plainBuffer, cipherBuffer)
    }

    override fun bufferDecrypt(cipherBuffer: ByteBuffer, plainBuffer: ByteBuffer) {
        cipher.doFinal(cipherBuffer, plainBuffer)
    }
}

fun main(args: Array<String>) {
    val plainText = "holo".toByteArray()
    val plainText2 = "sherlock".toByteArray()

    val key = password2key("qlx")

    val en = AES256CFB(key)
    val iv = en.getIVorNonce()!!

    val de = AES256CFB(key, iv)
    val cipherText = en.encrypt(plainText)
//    val cipherText2 = en.encrypt(plainText2)
    println("plain text: ${String(plainText)}")
    val newText = de.decrypt(cipherText)
//    val newText2 = de.decrypt(cipherText2)
    println("new text: ${String(newText)}")

    val plainBuffer = ByteBuffer.allocate(100)
    val cipherBuffer = ByteBuffer.allocate(100)
    plainBuffer.put(plainText2)
    plainBuffer.flip()
    en.bufferEncrypt(plainBuffer, cipherBuffer)
    cipherBuffer.flip()
    plainBuffer.clear()
    de.bufferDecrypt(cipherBuffer, plainBuffer)
    plainBuffer.flip()
    println(String(byteArrayOf(plainBuffer.get())))
    println(String(byteArrayOf(plainBuffer.get())))
    println(String(byteArrayOf(plainBuffer.get())))
    println(String(byteArrayOf(plainBuffer.get())))

}