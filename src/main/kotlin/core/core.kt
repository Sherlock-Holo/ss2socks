package core

import config.config
import encrypt.AES256CTR
import encrypt.password2key
import kotlinx.coroutines.experimental.async
import kotlinx.coroutines.experimental.nio.aAccept
import kotlinx.coroutines.experimental.nio.aConnect
import kotlinx.coroutines.experimental.nio.aRead
import kotlinx.coroutines.experimental.nio.aWrite
import kotlinx.coroutines.experimental.runBlocking
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousServerSocketChannel
import java.nio.channels.AsynchronousSocketChannel
import java.util.*
import java.util.logging.Logger
import kotlin.system.exitProcess

val logger = Logger.getLogger("ss2socks logger")

private fun makeSendPort(i: Int): ByteArray {
    val binaryNumber = StringBuffer(Integer.toBinaryString(i))
    while (binaryNumber.length <= 8) {
        binaryNumber.insert(0, '0')
    }
    val byteArray = ByteArray(2)
    byteArray[0] = Integer.parseInt(binaryNumber.substring(0 until binaryNumber.lastIndex - 7), 2).toByte()
    byteArray[1] = Integer.parseInt(binaryNumber.substring(binaryNumber.lastIndex - 7 until binaryNumber.lastIndex + 1), 2).toByte()
    return byteArray
}

private fun getPort(byteArray: ByteArray): Int {
    return (byteArray[0].toInt() and 0xFF shl 8) or (byteArray[1].toInt() and 0xFF)
}

class Server(ssAddr: String, ssPort: Int, private val backEndAddr: String, private val backEndPort: Int, password: String) {
    val serverChannel = AsynchronousServerSocketChannel.open()
    val key = password2key(password)
    init {
        serverChannel.bind(InetSocketAddress(ssAddr, ssPort))
    }

    suspend fun runForever() {
        while (true) {
            val client = serverChannel.aAccept()
            async {
                handle(client)
            }
        }
    }

    suspend private fun handle(client: AsynchronousSocketChannel) {
        val cipherReadBuffer = ByteBuffer.allocate(4096)
        val cipherWriteBuffer = ByteBuffer.allocate(4096)
        val plainWriteBuffer = ByteBuffer.allocate(4096)
        val plainReadBuffer = ByteBuffer.allocate(4096)

        val backEndSocketChannel = AsynchronousSocketChannel.open()

        try {
            var ssCanRead = 0
            while (ssCanRead < 17) {
                ssCanRead += client.aRead(cipherReadBuffer)
            }
            cipherReadBuffer.flip()

            val readIv = ByteArray(16)
            cipherReadBuffer.get(readIv)
            cipherReadBuffer.compact()
            cipherReadBuffer.flip()

//            val base64 = Base64.getEncoder()
//            logger.info(base64.encodeToString(readIv))

            val readCipher = AES256CTR(key, readIv)

            var rawatyp = ByteArray(1)
            cipherReadBuffer.get(rawatyp)
            cipherReadBuffer.compact()
            rawatyp = readCipher.decrypt(rawatyp)
            val atyp = rawatyp[0].toInt() and 0xFF
            var addrLen = 0
            var addr = ByteArray(4)
            var port = ByteArray(2)

            logger.info("atyp: $atyp")

            when (atyp) {
                1 -> {
                    while (ssCanRead < 17 + 4 + 2) {
                        ssCanRead += client.aRead(cipherReadBuffer)
                    }
                    cipherReadBuffer.flip()

                    cipherReadBuffer.get(addr)
                    cipherReadBuffer.get(port)
//                    cipherReadBuffer.compact()

                    addr = readCipher.decrypt(addr)
                    port = readCipher.decrypt(port)

                    logger.info("addr: ${InetAddress.getByAddress(addr).hostAddress}, port: ${getPort(port)}")
                }

                3 -> {
                    while (ssCanRead < 17 + 1) {
                        ssCanRead += client.aRead(cipherReadBuffer)
                    }
                    cipherReadBuffer.flip()

                    var rawAddrLen = ByteArray(1)
                    cipherReadBuffer.get(rawAddrLen)
                    cipherReadBuffer.compact()

                    rawAddrLen = readCipher.decrypt(rawAddrLen)
                    addrLen = rawAddrLen[0].toInt() and 0xFF
                    logger.info("addr len: $addrLen")

                    while (ssCanRead < 17 + 1 + addrLen) {
                        ssCanRead += client.aRead(cipherReadBuffer)
                    }
                    cipherReadBuffer.flip()

                    addr = ByteArray(addrLen)
                    cipherReadBuffer.get(addr)
                    cipherReadBuffer.get(port)
//                    cipherReadBuffer.compact()

                    addr = readCipher.decrypt(addr)
                    port = readCipher.decrypt(port)

                    logger.info("addr: ${String(addr)}, port: ${getPort(port)}")
                }

                4 -> {
                    while (ssCanRead < 17 + 16 + 2) {
                        ssCanRead += client.aRead(cipherReadBuffer)
                    }
                    cipherReadBuffer.flip()
                    addr = ByteArray(16)
                    cipherReadBuffer.get(addr)
                    cipherReadBuffer.get(port)
//                    cipherReadBuffer.compact()

                    addr = readCipher.decrypt(addr)
                    port = readCipher.decrypt(port)

                    logger.info("addr: ${InetAddress.getByAddress(addr).hostAddress}, port: ${getPort(port)}")
                }

                else -> {
                    TODO("other atyp handle")
                }
            }

            // ready to relay
            cipherReadBuffer.compact()
//            cipherReadBuffer.flip()

            // connect to backEnd
//            backEndSocketChannel = AsynchronousSocketChannel.open()
            backEndSocketChannel.aConnect(InetSocketAddress(backEndAddr, backEndPort))

            // request socks5
            plainWriteBuffer.put(byteArrayOf(5, 1, 0))
            plainWriteBuffer.flip()
            backEndSocketChannel.aWrite(plainWriteBuffer)
            plainWriteBuffer.clear()

            var backEndCanRead = 0

            // read method
            while (backEndCanRead < 2) {
                backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
            }
            plainReadBuffer.flip()
            val method = ByteArray(2)
            plainReadBuffer.get(method)
            plainReadBuffer.clear()

            if (method[0].toInt() != 5) {
                TODO("socks version is not 5")
            }

            if (method[1].toInt() != 0) {
                TODO("auth is not No-auth")
            }

            // send request
            plainWriteBuffer.put(byteArrayOf(5, 1, 0, atyp.toByte()))

            if (atyp == 3) plainWriteBuffer.put(addrLen.toByte())

            plainWriteBuffer.put(addr)
            plainWriteBuffer.put(port)
            plainWriteBuffer.flip()

            backEndSocketChannel.aWrite(plainWriteBuffer)

            // ready to relay
            plainWriteBuffer.clear()

//            backEndCanRead = 0
            while (backEndCanRead < 6) {
                backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
            }
            plainReadBuffer.flip()

            val repliesCheck = ByteArray(4)
            plainReadBuffer.get(repliesCheck)
            plainReadBuffer.compact()
//            plainReadBuffer.flip()

            if (repliesCheck[1].toInt() != 0) {
                TODO("rep is not 0")
            }

            var bindAddr = ByteArray(4)
            val bindPort = ByteArray(2)
//            backEndCanRead = 0
            when (repliesCheck[3].toInt()) {
                1 -> {
                    while (backEndCanRead < 6 + 6) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
                    }
                    plainReadBuffer.flip()
                    plainReadBuffer.get(bindAddr)
                    plainReadBuffer.get(bindPort)
//                    plainReadBuffer.compact()
                }

                3 -> {
                    while (backEndCanRead < 6 + 1) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
                    }
                    plainReadBuffer.flip()
                    val bindAddrLen = plainReadBuffer.get().toInt()
                    plainReadBuffer.compact()

                    while (backEndCanRead < 7 + bindAddrLen + 2) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
                    }
                    plainReadBuffer.flip()
                    bindAddr = ByteArray(bindAddrLen)
                    plainReadBuffer.get(bindAddr)
                    plainReadBuffer.get(bindPort)
//                    plainReadBuffer.compact()
                }

                4 -> {
                    while (backEndCanRead < 6 + 16 + 2) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
                    }
                    plainReadBuffer.flip()
                    bindAddr = ByteArray(16)
                    plainReadBuffer.get(bindAddr)
                    plainReadBuffer.get(bindPort)
//                    plainReadBuffer.compact()
                }

                else -> {
                    TODO("maybe other atyp?")
                }
            }

            val writeCipher = AES256CTR(key)
            val writeIv = writeCipher.getIVorNonce()

            // ready to relay
            plainReadBuffer.clear()

            // send IV of ss2socks -> sslocal
            cipherWriteBuffer.put(writeIv)
            cipherWriteBuffer.flip()

            client.aWrite(cipherWriteBuffer)

            // ready to relay
            cipherWriteBuffer.clear()

            // sslocal -> ss2socks -> backEnd
            async {
                var haveRead: Int
                try {
                    while (true) {
                        haveRead = client.aRead(cipherReadBuffer)
                        if (haveRead <= 0) {
                            client.shutdownOutput()
                            client.shutdownInput()
                            backEndSocketChannel.shutdownInput()
                            backEndSocketChannel.shutdownOutput()
                            break
                        }

                        cipherReadBuffer.flip()
                        readCipher.decrypt(cipherReadBuffer, plainWriteBuffer)
                        cipherReadBuffer.compact()
                        plainWriteBuffer.flip()
                        backEndSocketChannel.aWrite(plainWriteBuffer)
                        plainWriteBuffer.clear()
                    }
                } catch (e: Throwable) {
                    TODO("log this error")
                } finally {
                    client.close()
                    backEndSocketChannel.close()
                }
            }

            // backEnd -> ss2socks > sslocal
            async {
                var haveRead: Int
                try {
                    while (true) {
                        haveRead = backEndSocketChannel.aRead(plainReadBuffer)
                        if (haveRead <= 0) {
                            client.shutdownOutput()
                            client.shutdownInput()
                            backEndSocketChannel.shutdownInput()
                            backEndSocketChannel.shutdownOutput()
                            break
                        }

                        plainReadBuffer.flip()
                        writeCipher.encrypt(plainReadBuffer, cipherWriteBuffer)
                        plainReadBuffer.compact()
                        cipherWriteBuffer.flip()
                        client.aWrite(cipherWriteBuffer)
                        cipherWriteBuffer.clear()
                    }
                } catch (e: Throwable) {
                    TODO("log this error")
                } finally {
                    client.close()
                    backEndSocketChannel.close()
                }
            }
        } catch (e: Throwable) {
            client.close()
            backEndSocketChannel.close()
            logger.warning(e.toString())
        }
    }
}

fun main(args: Array<String>) = runBlocking<Unit> {
//    if (args.size != 2) {
//        if (args[0] != "-c") {
//            println("error args")
//            exitProcess(1)
//        }
//    }
//
//    val configFile = File(args[1])
//    if (!configFile.exists()) {
//        println("config file not exist")
//        exitProcess(1)
//    }
//
//    val ss2socksConfig = config(configFile).getConfig()

//    val core = Server(ss2socksConfig.ssAddr, ss2socksConfig.ssPort, ss2socksConfig.backEndAddr, ss2socksConfig.backEndPort, ss2socksConfig.password)
    val core = Server("127.0.0.2", 1088, "127.0.0.2", 1888, "holo")
//    async {
//        core.runForever()
//    }
    core.runForever()
}