package core

import config.Config
import encrypt.AES256CTR
import encrypt.password2key
import kotlinx.coroutines.experimental.async
import kotlinx.coroutines.experimental.nio.aAccept
import kotlinx.coroutines.experimental.nio.aConnect
import kotlinx.coroutines.experimental.nio.aRead
import kotlinx.coroutines.experimental.nio.aWrite
import kotlinx.coroutines.experimental.runBlocking
import utils.GetPort
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousServerSocketChannel
import java.nio.channels.AsynchronousSocketChannel
import java.util.logging.Logger
import kotlin.system.exitProcess

val logger = Logger.getLogger("ss2socks logger")!!

class Server(ssAddr: String, ssPort: Int, private val backEndAddr: String, private val backEndPort: Int, password: String) {
    private val serverChannel = AsynchronousServerSocketChannel.open()
    private val key = password2key(password)
    private val defaultBufferSize = 4096
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
        var cipherReadBuffer = ByteBuffer.allocate(defaultBufferSize)
        var cipherWriteBuffer = ByteBuffer.allocate(defaultBufferSize)
        var plainWriteBuffer = ByteBuffer.allocate(defaultBufferSize)
        var plainReadBuffer = ByteBuffer.allocate(defaultBufferSize)

        val backEndSocketChannel = AsynchronousSocketChannel.open()

        try {
            var ssCanRead = 0
            // read IV and atyp
            while (ssCanRead < 17) {
                ssCanRead += client.aRead(cipherReadBuffer)
            }
            cipherReadBuffer.flip()

            val readIv = ByteArray(16)
            cipherReadBuffer.get(readIv)
            cipherReadBuffer.compact()
            cipherReadBuffer.flip()

            val readCipher = AES256CTR(key, readIv)

            var rawatyp = ByteArray(1)
            cipherReadBuffer.get(rawatyp)
            cipherReadBuffer.compact()
            rawatyp = readCipher.decrypt(rawatyp)

            // get real atyp
            val atyp = rawatyp[0].toInt() and 0xFF
            var addrLen = 0
            var addr = ByteArray(4)
            var port = ByteArray(2)

            logger.fine("atyp: $atyp")

            when (atyp) {
                1 -> {
                    while (ssCanRead < 17 + 4 + 2) {
                        ssCanRead += client.aRead(cipherReadBuffer)
                    }
                    cipherReadBuffer.flip()

                    cipherReadBuffer.get(addr)
                    cipherReadBuffer.get(port)

                    addr = readCipher.decrypt(addr)
                    port = readCipher.decrypt(port)

                    logger.fine("addr: ${InetAddress.getByAddress(addr).hostAddress}, port: ${GetPort(port)}")
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
                    logger.fine("addr len: $addrLen")

                    while (ssCanRead < 17 + 1 + addrLen) {
                        ssCanRead += client.aRead(cipherReadBuffer)
                    }
                    cipherReadBuffer.flip()

                    addr = ByteArray(addrLen)
                    cipherReadBuffer.get(addr)
                    cipherReadBuffer.get(port)

                    addr = readCipher.decrypt(addr)
                    port = readCipher.decrypt(port)

                    logger.fine("addr: ${String(addr)}, port: ${GetPort(port)}")
                }

                4 -> {
                    while (ssCanRead < 17 + 16 + 2) {
                        ssCanRead += client.aRead(cipherReadBuffer)
                    }
                    cipherReadBuffer.flip()
                    addr = ByteArray(16)
                    cipherReadBuffer.get(addr)
                    cipherReadBuffer.get(port)

                    addr = readCipher.decrypt(addr)
                    port = readCipher.decrypt(port)

                    logger.fine("addr: ${InetAddress.getByAddress(addr).hostAddress}, port: ${GetPort(port)}")
                }

                else -> {
                    logger.warning("error atyp")
                    client.close()
                    backEndSocketChannel.close()
                    readCipher.finish()
                    return
                }
            }

            // ready to relay
            cipherReadBuffer.compact()

            // connect to backEnd
            backEndSocketChannel.aConnect(InetSocketAddress(backEndAddr, backEndPort))
            logger.fine("connected to back end server")

            // socks5 version request
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
                logger.warning("socks version is not 5")
                client.close()
                backEndSocketChannel.close()
                readCipher.finish()
                return
            }

            if (method[1].toInt() != 0) {
                logger.warning("auth is not No-auth")
                client.close()
                backEndSocketChannel.close()
                readCipher.finish()
                return
            }

            logger.fine("use no auth mode")

            // send request
            plainWriteBuffer.put(byteArrayOf(5, 1, 0, atyp.toByte()))

            if (atyp == 3) plainWriteBuffer.put(addrLen.toByte())

            plainWriteBuffer.put(addr)
            plainWriteBuffer.put(port)
            plainWriteBuffer.flip()

            backEndSocketChannel.aWrite(plainWriteBuffer)

            // ready to relay
            plainWriteBuffer.clear()

            // recv reply
            while (backEndCanRead < 2 + 4) {
                backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
            }
            plainReadBuffer.flip()

            val repliesCheck = ByteArray(4)
            plainReadBuffer.get(repliesCheck)

            plainReadBuffer.compact()

            if (repliesCheck[1].toInt() != 0) {
                logger.warning("rep is not 0")
                client.close()
                backEndSocketChannel.close()
                readCipher.finish()
                return
            }

            var bindAddr = ByteArray(4)
            val bindPort = ByteArray(2)

            logger.fine("bind atyp: ${repliesCheck[3].toInt()}")

            when (repliesCheck[3].toInt()) {
                1 -> {
                    while (backEndCanRead < 2 + 4 + 6) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
                    }
                    plainReadBuffer.flip()
                    plainReadBuffer.get(bindAddr)
                    plainReadBuffer.get(bindPort)
                    logger.fine("bind addr: ${InetAddress.getByAddress(bindAddr).hostAddress}, port: ${GetPort(bindPort)}")
                }

                3 -> {
                    while (backEndCanRead < 2 + 4 + 1) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
                    }
                    plainReadBuffer.flip()
                    val bindAddrLen = plainReadBuffer.get().toInt()
                    logger.fine("bind addr length: $bindAddr")
                    plainReadBuffer.compact()

                    while (backEndCanRead < 2 + 4 + 1 + bindAddrLen + 2) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
                    }
                    plainReadBuffer.flip()
                    bindAddr = ByteArray(bindAddrLen)
                    plainReadBuffer.get(bindAddr)
                    plainReadBuffer.get(bindPort)
                    logger.fine("bind addr: ${String(bindAddr)}, port: ${GetPort(bindPort)}")
                }

                4 -> {
                    while (backEndCanRead < 2 + 4 + 16 + 2) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
                    }
                    plainReadBuffer.flip()
                    bindAddr = ByteArray(16)
                    plainReadBuffer.get(bindAddr)
                    plainReadBuffer.get(bindPort)
                    logger.fine("bind addr: ${InetAddress.getByAddress(bindAddr).hostAddress}, port: ${GetPort(bindPort)}")
                }

                else -> {
                    logger.warning("other atyp we don't know")
                    client.close()
                    backEndSocketChannel.close()
                    readCipher.finish()
                    return
                }
            }

            val writeCipher = AES256CTR(key)
            val writeIv = writeCipher.getIVorNonce()!!

            // ready to relay
            plainReadBuffer.clear()

            // send IV of ss2socks -> sslocal
            cipherWriteBuffer.put(writeIv)
            cipherWriteBuffer.flip()

            client.aWrite(cipherWriteBuffer)

            // ready to relay
            cipherWriteBuffer.clear()

            // sslocal -> ss2socks -> backEnd
            logger.fine("start relay to backEnd")
            async {
                var bufferSize = defaultBufferSize
                var times = 0
                var haveRead: Int
                try {
                    if (cipherReadBuffer.position() != 0) {
                        cipherReadBuffer.flip()
                        readCipher.decrypt(cipherReadBuffer, plainWriteBuffer)
                        cipherReadBuffer.clear()
                        plainWriteBuffer.flip()
                        backEndSocketChannel.aWrite(plainWriteBuffer)
                        plainWriteBuffer.clear()
                    }

                    while (true) {
                        haveRead = client.aRead(cipherReadBuffer)
                        if (haveRead <= 0) {
                            break
                        }

                        // expend buffer size
                        if (haveRead == bufferSize) {
                            if (times < 3) {
                                times++
                            } else {
                                bufferSize *= 2
                                cipherReadBuffer.flip()
                                cipherReadBuffer = ByteBuffer.allocate(bufferSize).put(cipherReadBuffer)
                                plainWriteBuffer = ByteBuffer.allocate(bufferSize)
                                times = 0
                                logger.info("expend buffer size to $bufferSize")
                            }
                        } else {
                            times--
                            if (times < 0) times = 0
                        }

                        cipherReadBuffer.flip()
                        readCipher.decrypt(cipherReadBuffer, plainWriteBuffer)
                        cipherReadBuffer.clear()
                        plainWriteBuffer.flip()
                        backEndSocketChannel.aWrite(plainWriteBuffer)
                        plainWriteBuffer.clear()
                    }
                } catch (e: Throwable) {
                    logger.warning(e.message)
                } finally {
                    client.close()
                    backEndSocketChannel.close()
                    readCipher.finish()
                    writeCipher.finish()
                }
            }

            // backEnd -> ss2socks > sslocal
            logger.fine("start relay back to sslocal")
            async {
                var bufferSize = defaultBufferSize
                var times = 0
                var haveRead: Int
                try {
                    while (true) {
                        haveRead = backEndSocketChannel.aRead(plainReadBuffer)
                        if (haveRead <= 0) {
                            break
                        }

                        if (haveRead == bufferSize) {
                            if (times < 3) {
                                times++
                            } else {
                                bufferSize *= 2
                                plainReadBuffer.flip()
                                plainReadBuffer = ByteBuffer.allocate(bufferSize).put(plainReadBuffer)
                                cipherWriteBuffer = ByteBuffer.allocate(bufferSize)
                                times = 0
                                logger.info("expend buffer size to $bufferSize")
                            }
                        } else {
                            times--
                            if (times < 0) times = 0
                        }

                        plainReadBuffer.flip()
                        writeCipher.encrypt(plainReadBuffer, cipherWriteBuffer)
                        plainReadBuffer.clear()
                        cipherWriteBuffer.flip()
                        client.aWrite(cipherWriteBuffer)
                        cipherWriteBuffer.clear()
                    }
                } catch (e: Throwable) {
                    logger.warning(e.message)
                } finally {
                    client.close()
                    backEndSocketChannel.close()
                    readCipher.finish()
                    writeCipher.finish()
                }
            }
        } catch (e: Throwable) {
            client.close()
            backEndSocketChannel.close()
            logger.warning(e.message)
        }
    }
}

fun main(args: Array<String>) = runBlocking<Unit> {
    if (args.size != 2) {
        if (args[0] != "-c") {
            println("error args")
            exitProcess(1)
        }
    }

    val configFile = File(args[1])
    if (!configFile.exists()) {
        println("config file not exist")
        exitProcess(1)
    }

    val ss2socksConfig = Config(configFile).getConfig()

    val core = Server(ss2socksConfig.ssAddr, ss2socksConfig.ssPort, ss2socksConfig.backEndAddr, ss2socksConfig.backEndPort, ss2socksConfig.password)
//    val core = Server("127.0.0.2", 1088, "127.0.0.2", 1888, "holo")
    logger.info("Start ss2socks service")
    logger.info("shadowsocks listen on ${ss2socksConfig.ssAddr}:${ss2socksConfig.ssPort}")
    logger.info("backEnd listen on ${ss2socksConfig.backEndAddr}:${ss2socksConfig.backEndPort}")
    core.runForever()
}