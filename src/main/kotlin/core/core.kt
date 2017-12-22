package core

import config.Config
import libs.encrypt.password2key
import kotlinx.coroutines.experimental.async
import kotlinx.coroutines.experimental.nio.aAccept
import kotlinx.coroutines.experimental.nio.aConnect
import kotlinx.coroutines.experimental.nio.aRead
import kotlinx.coroutines.experimental.nio.aWrite
import kotlinx.coroutines.experimental.runBlocking
import libs.AsynchronousSocketChannel.shutdownAll
import libs.TCPPort.GetPort
import libs.encrypt.Cipher
import libs.geoIP.GeoIP
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousCloseException
import java.nio.channels.AsynchronousServerSocketChannel
import java.nio.channels.AsynchronousSocketChannel
import java.util.logging.Logger
import kotlin.system.exitProcess

val logger = Logger.getLogger("ss2socks logger")!!

class Server(private val ss2socks: Config.TopConfig) {
    private val ssAddr = ss2socks.server.ssAddr
    private val ssPort = ss2socks.server.ssPort
    private val backEndAddr = ss2socks.server.backEndAddr
    private val backEndPort = ss2socks.server.backEndPort
    private val serverChannel = AsynchronousServerSocketChannel.open()
    private val key = password2key(ss2socks.security.password)
    private val defaultBufferSize = 4096
    private val useGeoip = ss2socks.securityChannel.GeoIP
    private val geoip: GeoIP

    init {
        serverChannel.bind(InetSocketAddress(ssAddr, ssPort))
        geoip = if (useGeoip) {
            logger.info("Use geoIP")
            logger.info("geoIP path: ${ss2socks.securityChannel.GeoIPDatabaseFilePath}")
            GeoIP(ss2socks.securityChannel.GeoIPDatabaseFilePath)
        }
        else {
            logger.info("Don't use geoIP")
            GeoIP(null)
        }
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
        val cipherReadBuffer = ByteBuffer.allocate(defaultBufferSize)
        val cipherWriteBuffer = ByteBuffer.allocate(defaultBufferSize)
        val plainWriteBuffer = ByteBuffer.allocate(defaultBufferSize)
        val plainReadBuffer = ByteBuffer.allocate(defaultBufferSize)

        val backEndSocketChannel = AsynchronousSocketChannel.open()

        val readCipher: Cipher

        val atyp: Int
        var addrLen: Int
        var addr: ByteArray
        var port: ByteArray

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

            readCipher = Cipher(key, readIv, ss2socks.security.cipherMode)

            var rawatyp = ByteArray(1)
            cipherReadBuffer.get(rawatyp)
            cipherReadBuffer.compact()
            rawatyp = readCipher.decrypt(rawatyp)

            // get real atyp
            atyp = rawatyp[0].toInt() and 0xFF
            addrLen = 0
            addr = ByteArray(4)
            port = ByteArray(2)

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

                    logger.fine("addr: ${InetAddress.getByAddress(addr).hostAddress}, TCPPort: ${GetPort(port)}")
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

                    logger.fine("addr: ${String(addr)}, TCPPort: ${GetPort(port)}")
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

                    logger.fine("addr: ${InetAddress.getByAddress(addr).hostAddress}, TCPPort: ${GetPort(port)}")
                }

                else -> {
                    logger.warning("error atyp")
                    client.shutdownAll()
                    backEndSocketChannel.shutdownAll()
                    client.close()
                    backEndSocketChannel.close()
                    readCipher.finish()
                    return
                }
            }
        } catch (e: AsynchronousCloseException) {
            client.close()
            backEndSocketChannel.close()
            logger.warning("decode shadowsocks address info failed")
            return
        }

        // ready to relay
        cipherReadBuffer.compact()

        when (atyp) {
            1 -> {
                if (addr.contentEquals(InetAddress.getByName("8.8.8.8").address)) {
                    logger.info("detect 8.8.8.8 DNS data, redirect to local DNS")
                    isChina(
                            InetAddress.getByName("127.0.0.1").address, port, client, backEndSocketChannel,
                            cipherReadBuffer, plainWriteBuffer, readCipher, plainReadBuffer, cipherWriteBuffer)
                } else if (!geoip.isChinaIP(addr)) {
                    logger.info("${InetAddress.getByAddress(addr).hostAddress} is not China IP")
                    async {
                        notChina(
                                atyp, addrLen, addr, port, client, backEndSocketChannel, cipherReadBuffer,
                                plainWriteBuffer, readCipher, plainReadBuffer, cipherWriteBuffer)
                    }
                } else {
                    logger.info("${InetAddress.getByAddress(addr).hostAddress} is China IP")
                    async {
                        isChina(
                                addr, port, client, backEndSocketChannel, cipherReadBuffer, plainWriteBuffer,
                                readCipher, plainReadBuffer, cipherWriteBuffer)
                    }
                }
            }

            3 -> {
                val IPAddr = InetAddress.getByName(String(addr)).address
                if (!geoip.isChinaIP(IPAddr)) {
                    logger.info("${String(addr)} is not in China: ${InetAddress.getByAddress(IPAddr).hostAddress}")
                    async {
                        when (IPAddr.size) {
                            4 -> {
                                notChina(
                                        1, addrLen, IPAddr, port, client, backEndSocketChannel, cipherReadBuffer,
                                        plainWriteBuffer, readCipher, plainReadBuffer, cipherWriteBuffer
                                )
                            }
                            16 -> {
                                notChina(
                                        4, addrLen, IPAddr, port, client, backEndSocketChannel, cipherReadBuffer,
                                        plainWriteBuffer, readCipher, plainReadBuffer, cipherWriteBuffer
                                )
                            }
                        }
                    }
                } else {
                    logger.info("${String(addr)} is in China: ${InetAddress.getByAddress(IPAddr).hostAddress}")
                    async {
                        isChina(
                                IPAddr, port, client, backEndSocketChannel, cipherReadBuffer, plainWriteBuffer,
                                readCipher, plainReadBuffer, cipherWriteBuffer
                        )
                    }
                }
            }

            4 -> {
                async {
                    logger.info("${InetAddress.getByAddress(addr).hostAddress} is IPv6")
                    notChina(
                            atyp, addrLen, addr, port, client, backEndSocketChannel, cipherReadBuffer,
                            plainWriteBuffer, readCipher, plainReadBuffer, cipherWriteBuffer)
                }
            }
        }
    }

    suspend private fun isChina(
            addr: ByteArray, port: ByteArray, client: AsynchronousSocketChannel, backEndSocketChannel: AsynchronousSocketChannel,
            rawCipherReadBuffer: ByteBuffer, rawPlainWriteBuffer: ByteBuffer,
            readCipher: Cipher, rawPlainReadBuffer: ByteBuffer, rawCipherWriteBuffer: ByteBuffer) {
        var cipherReadBuffer = rawCipherReadBuffer
        var plainWriteBuffer = rawPlainWriteBuffer
        var plainReadBuffer = rawPlainReadBuffer
        var cipherWriteBuffer = rawCipherWriteBuffer
        val writeCipher = Cipher(key, cipherMode = ss2socks.security.cipherMode)

        // connect to China server
        try {
            backEndSocketChannel.aConnect(InetSocketAddress(InetAddress.getByAddress(addr), GetPort(port)))
        } catch (e: AsynchronousCloseException) {
            client.shutdownAll()
            client.close()
            backEndSocketChannel.close()
            logger.warning("connect to China server: failed")
            return
        }
        logger.fine("connected to China server")

//        val writeIv = writeCipher.getIVorNonce()!!

        // ready to relay
        plainReadBuffer.clear()

        // send IV of ss2socks -> sslocal
        cipherWriteBuffer.put(writeCipher.getIVorNonce())
        cipherWriteBuffer.flip()

        try {
            client.aWrite(cipherWriteBuffer)
        } catch (e: AsynchronousCloseException) {
            client.close()
            backEndSocketChannel.shutdownAll()
            backEndSocketChannel.close()
            logger.warning("send write IV: failed")
            return
        }

        // ready to relay
        cipherWriteBuffer.clear()

        // sslocal -> ss2socks -> China
        logger.fine("start relay to China")
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
                        client.shutdownAll()
                        backEndSocketChannel.shutdownAll()
                        break
                    }

                    // expend buffer size
                    if (haveRead == bufferSize) {
                        if (times < 2) {
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
            } catch (e: AsynchronousCloseException) {
                logger.warning("sslocal -> ss2socks -> China : connect reset by peer")
            } finally {
                client.close()
                backEndSocketChannel.close()
                readCipher.finish()
                writeCipher.finish()
            }
        }

        // China -> ss2socks > sslocal
        logger.fine("start relay back to sslocal")
        async {
            var bufferSize = defaultBufferSize
            var times = 0
            var haveRead: Int
            try {
                while (true) {
                    haveRead = backEndSocketChannel.aRead(plainReadBuffer)
                    if (haveRead <= 0) {
                        client.shutdownAll()
                        backEndSocketChannel.shutdownAll()
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
            } catch (e: AsynchronousCloseException) {
                logger.warning("Cina -> ss2socks > sslocal : connect reset by peer")
            } finally {
                client.close()
                backEndSocketChannel.close()
                readCipher.finish()
                writeCipher.finish()
            }
        }
    }

    suspend private fun notChina(
            atyp: Int, addrLen: Int, addr: ByteArray, port: ByteArray,
            client: AsynchronousSocketChannel, backEndSocketChannel: AsynchronousSocketChannel,
            rawCipherReadBuffer: ByteBuffer, rawPlainWriteBuffer: ByteBuffer, readCipher: Cipher,
            rawPlainReadBuffer: ByteBuffer, rawCipherWriteBuffer: ByteBuffer) {

        var cipherReadBuffer = rawCipherReadBuffer
        var plainWriteBuffer = rawPlainWriteBuffer
        var plainReadBuffer = rawPlainReadBuffer
        var cipherWriteBuffer = rawCipherWriteBuffer

        // connect to backEnd
        try {
            backEndSocketChannel.aConnect(InetSocketAddress(backEndAddr, backEndPort))
        } catch (e: AsynchronousCloseException) {
            client.shutdownAll()
            client.close()
            backEndSocketChannel.close()
            logger.warning("connect to backend: failed")
            return
        }
        logger.fine("connected to backend server")

        try {
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
                    logger.fine("bind addr: ${InetAddress.getByAddress(bindAddr).hostAddress}, TCPPort: ${GetPort(bindPort)}")
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
                    logger.fine("bind addr: ${String(bindAddr)}, TCPPort: ${GetPort(bindPort)}")
                }

                4 -> {
                    while (backEndCanRead < 2 + 4 + 16 + 2) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer)
                    }
                    plainReadBuffer.flip()
                    bindAddr = ByteArray(16)
                    plainReadBuffer.get(bindAddr)
                    plainReadBuffer.get(bindPort)
                    logger.fine("bind addr: ${InetAddress.getByAddress(bindAddr).hostAddress}, TCPPort: ${GetPort(bindPort)}")
                }

                else -> {
                    logger.warning("other atyp we don't know")
                    client.close()
                    backEndSocketChannel.close()
                    readCipher.finish()
                    return
                }
            }
        } catch (e: AsynchronousCloseException) {
            client.shutdownAll()
            client.close()
            backEndSocketChannel.close()
            logger.warning("handshake with backend: failed")
            return
        }

        val writeCipher = Cipher(key, cipherMode = ss2socks.security.cipherMode)
//        val writeIv = writeCipher.getIVorNonce()!!

        // ready to relay
        plainReadBuffer.clear()

        // send IV of ss2socks -> sslocal
        cipherWriteBuffer.put(writeCipher.getIVorNonce())
        cipherWriteBuffer.flip()

        try {
            client.aWrite(cipherWriteBuffer)
        } catch (e: AsynchronousCloseException) {
            client.close()
            backEndSocketChannel.shutdownAll()
            backEndSocketChannel.close()
            logger.warning("send writeIV: failed")
            return
        }

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
                        client.shutdownAll()
                        backEndSocketChannel.shutdownAll()
                        break
                    }

                    // expend buffer size
                    if (haveRead == bufferSize) {
                        if (times < 2) {
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
            } catch (e: AsynchronousCloseException) {
                logger.warning("sslocal -> ss2socks -> backEnd : connect reset by peer")

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
                        client.shutdownAll()
                        backEndSocketChannel.shutdownAll()
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
            } catch (e: AsynchronousCloseException) {
                logger.warning("backEnd -> ss2socks > sslocal : connect reset by peer")

            } finally {
                client.close()
                backEndSocketChannel.close()
                readCipher.finish()
                writeCipher.finish()
            }
        }
    }
}

fun main(args: Array<String>) = runBlocking {
    if (args.size != 2) {
        println("Usage: -c config.yaml")
        exitProcess(1)
    }

    if (args[0] != "-c") {
        println("error args")
        exitProcess(1)
    }

    val configFile = File(args[1])
    if (!configFile.exists()) {
        println("config file not exist")
        exitProcess(1)
    }

    val ss2socksConfig = Config(configFile).getConfig()

    val core = Server(ss2socksConfig)
    logger.info("Start ss2socks service")
    logger.info("shadowsocks listen on ${ss2socksConfig.server.ssAddr}:${ss2socksConfig.server.ssPort}")
    logger.info("backEnd listen on ${ss2socksConfig.server.backEndAddr}:${ss2socksConfig.server.backEndPort}")
    core.runForever()
}