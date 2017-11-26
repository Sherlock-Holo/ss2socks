package encrypt

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private interface GeneralCipher {
    // maybe some encrypt module doesn't use IV or Nonce
    fun getIVorNonce(): ByteArray?

    fun encrypt(plainText: ByteArray): ByteArray

    fun decrypt(cipherText: ByteArray): ByteArray
}

class AES256CFB(key: String, var iv: ByteArray? = null): GeneralCipher {
    val cipher: Cipher

    init {
        val keyGen = MessageDigest.getInstance("SHA-256")
        keyGen.update(key.toByteArray())
        val encodeKey = keyGen.digest()
        val skey = SecretKeySpec(encodeKey, "AES")

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
}

fun main(args: Array<String>) {
    val plainText = "holo".toByteArray()
    val plainText2 = "sherlock".toByteArray()

    val en = AES256CFB("qlx")
    val iv = en.getIVorNonce()!!

    val de = AES256CFB("qlx", iv)
    val cipherText = en.encrypt(plainText)
    val cipherText2 = en.encrypt(plainText2)
    println("plain text: ${String(plainText)}")
    val newText = de.decrypt(cipherText)
    val newText2 = de.decrypt(cipherText2)
    println("new text: ${String(newText)}")
    println("new text2: ${String(newText2)}")
    println("check: ${newText.contentEquals(plainText)}")
    println("check: ${newText2.contentEquals(plainText2)}")
}