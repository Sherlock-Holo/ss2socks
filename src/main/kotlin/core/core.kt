package core

import kotlinx.coroutines.experimental.async
import kotlinx.coroutines.experimental.nio.aAccept
import kotlinx.coroutines.experimental.nio.aConnect
import kotlinx.coroutines.experimental.nio.aRead
import kotlinx.coroutines.experimental.nio.aWrite
import kotlinx.coroutines.experimental.runBlocking
import libs.AsynchronousSocketChannel.shutdownAll
import libs.TCPPort.GetPort
import libs.bufferPool.BufferPool
import libs.config.Config
import libs.encrypt.Cipher
import libs.encrypt.password2key
import libs.geoIP.GeoIP
import libs.logger.logger
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardSocketOptions
import java.nio.channels.AsynchronousCloseException
import java.nio.channels.AsynchronousServerSocketChannel
import java.nio.channels.AsynchronousSocketChannel
import kotlin.system.exitProcess


class Server(private val ss2socks: Config.TopConfig) {
    private val ssAddr = ss2socks.server.ssAddr
    private val ssPort = ss2socks.server.ssPort
    private val backEndAddr = ss2socks.server.backEndAddr
    private val backEndPort = ss2socks.server.backEndPort
    private val serverChannel = AsynchronousServerSocketChannel.open()
    private val key = password2key(ss2socks.security.password)
    private val useGeoIP = ss2socks.securityChannel.GeoIP
    private val geoIP: GeoIP
    private val bufferPool = BufferPool()

    init {
        serverChannel.bind(InetSocketAddress(ssAddr, ssPort))
        geoIP = if (useGeoIP) {
            logger.info("Use GeoIP")
            logger.info("GeoIP path: ${ss2socks.securityChannel.GeoIPDatabaseFilePath}")
            GeoIP(ss2socks.securityChannel.GeoIPDatabaseFilePath)
        } else {
            logger.info("Don't use GeoIP")
            GeoIP(null)
        }
    }

    suspend fun runForever() {
        while (true) {
            val client = serverChannel.aAccept()
            client.setOption(StandardSocketOptions.TCP_NODELAY, true)
            client.setOption(StandardSocketOptions.SO_KEEPALIVE, true)
            client.setOption(StandardSocketOptions.SO_REUSEPORT, true)
            async {
                handle(client)
            }
        }
    }

    suspend private fun handle(client: AsynchronousSocketChannel) {
        val cipherReadBuffer = bufferPool.get()
        val cipherWriteBuffer = bufferPool.get()
        val plainWriteBuffer = bufferPool.get()
        val plainReadBuffer = bufferPool.get()

        val backEndSocketChannel = AsynchronousSocketChannel.open()
        backEndSocketChannel.setOption(StandardSocketOptions.TCP_NODELAY, true)
        backEndSocketChannel.setOption(StandardSocketOptions.SO_KEEPALIVE, true)

        val readCipher: Cipher

        val atyp: Int
        var addrLen: Int
        var addr: ByteArray
        var port: ByteArray

        try {
            var ssCanRead = 0
            // read IV and atyp
            while (ssCanRead < 17) {
                ssCanRead += client.aRead(cipherReadBuffer.buffer)
            }
            cipherReadBuffer.buffer.flip()

            val readIv = ByteArray(16)
            cipherReadBuffer.buffer.get(readIv)
            cipherReadBuffer.buffer.compact()
            cipherReadBuffer.buffer.flip()

            readCipher = Cipher(key, readIv, ss2socks.security.cipherMode)

            var rawatyp = ByteArray(1)
            cipherReadBuffer.buffer.get(rawatyp)
            cipherReadBuffer.buffer.compact()
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
                        ssCanRead += client.aRead(cipherReadBuffer.buffer)
                    }
                    cipherReadBuffer.buffer.flip()

                    cipherReadBuffer.buffer.get(addr)
                    cipherReadBuffer.buffer.get(port)

                    addr = readCipher.decrypt(addr)
                    port = readCipher.decrypt(port)

                    logger.fine("addr: ${InetAddress.getByAddress(addr).hostAddress}, TCPPort: ${GetPort(port)}")
                }

                3 -> {
                    while (ssCanRead < 17 + 1) {
                        ssCanRead += client.aRead(cipherReadBuffer.buffer)
                    }
                    cipherReadBuffer.buffer.flip()

                    var rawAddrLen = ByteArray(1)
                    cipherReadBuffer.buffer.get(rawAddrLen)
                    cipherReadBuffer.buffer.compact()

                    rawAddrLen = readCipher.decrypt(rawAddrLen)
                    addrLen = rawAddrLen[0].toInt() and 0xFF
                    logger.fine("addr len: $addrLen")

                    while (ssCanRead < 17 + 1 + addrLen) {
                        ssCanRead += client.aRead(cipherReadBuffer.buffer)
                    }
                    cipherReadBuffer.buffer.flip()

                    addr = ByteArray(addrLen)
                    cipherReadBuffer.buffer.get(addr)
                    cipherReadBuffer.buffer.get(port)

                    addr = readCipher.decrypt(addr)
                    port = readCipher.decrypt(port)

                    logger.fine("addr: ${String(addr)}, TCPPort: ${GetPort(port)}")
                }

                4 -> {
                    while (ssCanRead < 17 + 16 + 2) {
                        ssCanRead += client.aRead(cipherReadBuffer.buffer)
                    }
                    cipherReadBuffer.buffer.flip()
                    addr = ByteArray(16)
                    cipherReadBuffer.buffer.get(addr)
                    cipherReadBuffer.buffer.get(port)

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

                    cipherReadBuffer.release()
                    cipherWriteBuffer.release()
                    plainWriteBuffer.release()
                    plainReadBuffer.release()

                    readCipher.finish()
                    return
                }
            }
        } catch (e: AsynchronousCloseException) {
            client.close()
            backEndSocketChannel.close()

            cipherReadBuffer.release()
            cipherWriteBuffer.release()
            plainWriteBuffer.release()
            plainReadBuffer.release()

            logger.warning("decode shadowsocks address info failed")
            return
        }

        // ready to relay
        cipherReadBuffer.buffer.compact()

        when (atyp) {
            1 -> {
                if (addr.contentEquals(InetAddress.getByName("8.8.8.8").address)) {
                    logger.info("detect 8.8.8.8 DNS data, redirect to local DNS")
                    isChina(
                            InetAddress.getByName("127.0.0.1").address, port, client, backEndSocketChannel,
                            cipherReadBuffer, plainWriteBuffer, readCipher, plainReadBuffer, cipherWriteBuffer)
                } else if (!geoIP.isChinaIP(addr)) {
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
                if (!geoIP.isChinaIP(IPAddr)) {
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
            cipherReadBuffer: BufferPool.CustomBuffer, plainWriteBuffer: BufferPool.CustomBuffer,
            readCipher: Cipher, plainReadBuffer: BufferPool.CustomBuffer, cipherWriteBuffer: BufferPool.CustomBuffer) {

        val writeCipher = Cipher(key, cipherMode = ss2socks.security.cipherMode)

        // connect to China server
        try {
            backEndSocketChannel.aConnect(InetSocketAddress(InetAddress.getByAddress(addr), GetPort(port)))
        } catch (e: AsynchronousCloseException) {
            client.shutdownAll()
            client.close()
            backEndSocketChannel.close()

            cipherReadBuffer.release()
            cipherWriteBuffer.release()
            plainWriteBuffer.release()
            plainReadBuffer.release()

            logger.warning("connect to China server: failed")
            return
        }
        logger.fine("connected to China server")

        // ready to relay
        plainReadBuffer.buffer.clear()

        // send IV of ss2socks -> sslocal
        cipherWriteBuffer.buffer.put(writeCipher.getIVorNonce())
        cipherWriteBuffer.buffer.flip()

        try {
            client.aWrite(cipherWriteBuffer.buffer)
        } catch (e: AsynchronousCloseException) {
            client.close()
            backEndSocketChannel.shutdownAll()
            backEndSocketChannel.close()

            cipherReadBuffer.release()
            cipherWriteBuffer.release()
            plainWriteBuffer.release()
            plainReadBuffer.release()

            logger.warning("send write IV: failed")
            return
        }

        // ready to relay
        cipherWriteBuffer.buffer.clear()

        // sslocal -> ss2socks -> China
        logger.fine("start relay to China")
        async {
            var haveRead: Int
            try {
                if (cipherReadBuffer.buffer.position() != 0) {
                    cipherReadBuffer.buffer.flip()
                    readCipher.decrypt(cipherReadBuffer.buffer, plainWriteBuffer.buffer)
                    cipherReadBuffer.buffer.clear()
                    plainWriteBuffer.buffer.flip()
                    backEndSocketChannel.aWrite(plainWriteBuffer.buffer)
                    plainWriteBuffer.buffer.clear()
                }

                while (true) {
                    haveRead = client.aRead(cipherReadBuffer.buffer)
                    if (haveRead <= 0) {
                        client.shutdownAll()
                        backEndSocketChannel.shutdownAll()
                        break
                    }

                    cipherReadBuffer.buffer.flip()
                    readCipher.decrypt(cipherReadBuffer.buffer, plainWriteBuffer.buffer)
                    cipherReadBuffer.buffer.clear()
                    plainWriteBuffer.buffer.flip()
                    backEndSocketChannel.aWrite(plainWriteBuffer.buffer)
                    plainWriteBuffer.buffer.clear()
                }

            } catch (e: AsynchronousCloseException) {
                logger.warning("sslocal -> ss2socks -> China : connect reset by peer")
            } finally {
                client.close()
                backEndSocketChannel.close()

                cipherReadBuffer.release()
                cipherWriteBuffer.release()
                plainWriteBuffer.release()
                plainReadBuffer.release()

                readCipher.finish()
                writeCipher.finish()
            }
        }

        // China -> ss2socks > sslocal
        logger.fine("start relay back to sslocal")
        async {
            var haveRead: Int
            try {
                while (true) {
                    haveRead = backEndSocketChannel.aRead(plainReadBuffer.buffer)
                    if (haveRead <= 0) {
                        client.shutdownAll()
                        backEndSocketChannel.shutdownAll()
                        break
                    }

                    plainReadBuffer.buffer.flip()
                    writeCipher.encrypt(plainReadBuffer.buffer, cipherWriteBuffer.buffer)
                    plainReadBuffer.buffer.clear()
                    cipherWriteBuffer.buffer.flip()
                    client.aWrite(cipherWriteBuffer.buffer)
                    cipherWriteBuffer.buffer.clear()
                }
            } catch (e: AsynchronousCloseException) {
                logger.warning("Cina -> ss2socks > sslocal : connect reset by peer")
            } finally {
                client.close()
                backEndSocketChannel.close()

                cipherReadBuffer.release()
                cipherWriteBuffer.release()
                plainWriteBuffer.release()
                plainReadBuffer.release()

                readCipher.finish()
                writeCipher.finish()
            }
        }
    }

    suspend private fun notChina(
            atyp: Int, addrLen: Int, addr: ByteArray, port: ByteArray,
            client: AsynchronousSocketChannel, backEndSocketChannel: AsynchronousSocketChannel,
            cipherReadBuffer: BufferPool.CustomBuffer, plainWriteBuffer: BufferPool.CustomBuffer, readCipher: Cipher,
            plainReadBuffer: BufferPool.CustomBuffer, cipherWriteBuffer: BufferPool.CustomBuffer) {

        // connect to backEnd
        try {
            backEndSocketChannel.aConnect(InetSocketAddress(backEndAddr, backEndPort))
        } catch (e: AsynchronousCloseException) {
            client.shutdownAll()
            client.close()
            backEndSocketChannel.close()

            cipherReadBuffer.release()
            cipherWriteBuffer.release()
            plainWriteBuffer.release()
            plainReadBuffer.release()

            logger.warning("connect to backend: failed")
            return
        }
        logger.fine("connected to backend server")

        try {
            plainWriteBuffer.buffer.put(byteArrayOf(5, 1, 0))
            plainWriteBuffer.buffer.flip()
            backEndSocketChannel.aWrite(plainWriteBuffer.buffer)
            plainWriteBuffer.buffer.clear()

            var backEndCanRead = 0

            // read method
            while (backEndCanRead < 2) {
                backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer.buffer)
            }
            plainReadBuffer.buffer.flip()
            val method = ByteArray(2)
            plainReadBuffer.buffer.get(method)

            plainReadBuffer.buffer.clear()

            if (method[0].toInt() != 5) {
                logger.warning("socks version is not 5")
                client.close()
                backEndSocketChannel.close()

                cipherReadBuffer.release()
                cipherWriteBuffer.release()
                plainWriteBuffer.release()
                plainReadBuffer.release()

                readCipher.finish()
                return
            }

            if (method[1].toInt() != 0) {
                logger.warning("auth is not No-auth")
                client.close()
                backEndSocketChannel.close()

                cipherReadBuffer.release()
                cipherWriteBuffer.release()
                plainWriteBuffer.release()
                plainReadBuffer.release()

                readCipher.finish()
                return
            }

            logger.fine("use no auth mode")

            // send request
            plainWriteBuffer.buffer.put(byteArrayOf(5, 1, 0, atyp.toByte()))

            if (atyp == 3) plainWriteBuffer.buffer.put(addrLen.toByte())

            plainWriteBuffer.buffer.put(addr)
            plainWriteBuffer.buffer.put(port)
            plainWriteBuffer.buffer.flip()

            backEndSocketChannel.aWrite(plainWriteBuffer.buffer)

            // ready to relay
            plainWriteBuffer.buffer.clear()

            // recv reply
            while (backEndCanRead < 2 + 4) {
                backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer.buffer)
            }
            plainReadBuffer.buffer.flip()

            val repliesCheck = ByteArray(4)
            plainReadBuffer.buffer.get(repliesCheck)

            plainReadBuffer.buffer.compact()

            if (repliesCheck[1].toInt() != 0) {
                logger.warning("rep is not 0")
                client.close()
                backEndSocketChannel.close()

                cipherReadBuffer.release()
                cipherWriteBuffer.release()
                plainWriteBuffer.release()
                plainReadBuffer.release()

                readCipher.finish()
                return
            }

            var bindAddr = ByteArray(4)
            val bindPort = ByteArray(2)

            logger.fine("bind atyp: ${repliesCheck[3].toInt()}")

            when (repliesCheck[3].toInt()) {
                1 -> {
                    while (backEndCanRead < 2 + 4 + 6) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer.buffer)
                    }
                    plainReadBuffer.buffer.flip()
                    plainReadBuffer.buffer.get(bindAddr)
                    plainReadBuffer.buffer.get(bindPort)
                    logger.fine("bind addr: ${InetAddress.getByAddress(bindAddr).hostAddress}, TCPPort: ${GetPort(bindPort)}")
                }

                3 -> {
                    while (backEndCanRead < 2 + 4 + 1) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer.buffer)
                    }
                    plainReadBuffer.buffer.flip()
                    val bindAddrLen = plainReadBuffer.buffer.get().toInt()
                    logger.fine("bind addr length: $bindAddr")
                    plainReadBuffer.buffer.compact()

                    while (backEndCanRead < 2 + 4 + 1 + bindAddrLen + 2) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer.buffer)
                    }
                    plainReadBuffer.buffer.flip()
                    bindAddr = ByteArray(bindAddrLen)
                    plainReadBuffer.buffer.get(bindAddr)
                    plainReadBuffer.buffer.get(bindPort)
                    logger.fine("bind addr: ${String(bindAddr)}, TCPPort: ${GetPort(bindPort)}")
                }

                4 -> {
                    while (backEndCanRead < 2 + 4 + 16 + 2) {
                        backEndCanRead += backEndSocketChannel.aRead(plainReadBuffer.buffer)
                    }
                    plainReadBuffer.buffer.flip()
                    bindAddr = ByteArray(16)
                    plainReadBuffer.buffer.get(bindAddr)
                    plainReadBuffer.buffer.get(bindPort)
                    logger.fine("bind addr: ${InetAddress.getByAddress(bindAddr).hostAddress}, TCPPort: ${GetPort(bindPort)}")
                }

                else -> {
                    logger.warning("other atyp we don't know")
                    client.close()
                    backEndSocketChannel.close()

                    cipherReadBuffer.release()
                    cipherWriteBuffer.release()
                    plainWriteBuffer.release()
                    plainReadBuffer.release()

                    readCipher.finish()
                    return
                }
            }
        } catch (e: AsynchronousCloseException) {
            client.shutdownAll()
            client.close()
            backEndSocketChannel.close()

            cipherReadBuffer.release()
            cipherWriteBuffer.release()
            plainWriteBuffer.release()
            plainReadBuffer.release()

            logger.warning("handshake with backend: failed")
            return
        }

        val writeCipher = Cipher(key, cipherMode = ss2socks.security.cipherMode)

        // ready to relay
        plainReadBuffer.buffer.clear()

        // send IV of ss2socks -> sslocal
        cipherWriteBuffer.buffer.put(writeCipher.getIVorNonce())
        cipherWriteBuffer.buffer.flip()

        try {
            client.aWrite(cipherWriteBuffer.buffer)
        } catch (e: AsynchronousCloseException) {
            client.close()
            backEndSocketChannel.shutdownAll()
            backEndSocketChannel.close()

            cipherReadBuffer.release()
            cipherWriteBuffer.release()
            plainWriteBuffer.release()
            plainReadBuffer.release()

            logger.warning("send writeIV: failed")
            return
        }

        // ready to relay
        cipherWriteBuffer.buffer.clear()

        // sslocal -> ss2socks -> backEnd
        logger.fine("start relay to backEnd")
        async {
            var haveRead: Int
            try {
                if (cipherReadBuffer.buffer.position() != 0) {
                    cipherReadBuffer.buffer.flip()
                    readCipher.decrypt(cipherReadBuffer.buffer, plainWriteBuffer.buffer)
                    cipherReadBuffer.buffer.clear()
                    plainWriteBuffer.buffer.flip()
                    backEndSocketChannel.aWrite(plainWriteBuffer.buffer)
                    plainWriteBuffer.buffer.clear()
                }

                while (true) {
                    haveRead = client.aRead(cipherReadBuffer.buffer)
                    if (haveRead <= 0) {
                        client.shutdownAll()
                        backEndSocketChannel.shutdownAll()
                        break
                    }

                    cipherReadBuffer.buffer.flip()
                    readCipher.decrypt(cipherReadBuffer.buffer, plainWriteBuffer.buffer)
                    cipherReadBuffer.buffer.clear()
                    plainWriteBuffer.buffer.flip()
                    backEndSocketChannel.aWrite(plainWriteBuffer.buffer)
                    plainWriteBuffer.buffer.clear()
                }
            } catch (e: AsynchronousCloseException) {
                logger.warning("sslocal -> ss2socks -> backEnd : connect reset by peer")

            } finally {
                client.close()
                backEndSocketChannel.close()

                cipherReadBuffer.release()
                cipherWriteBuffer.release()
                plainWriteBuffer.release()
                plainReadBuffer.release()

                readCipher.finish()
                writeCipher.finish()
            }
        }

        // backEnd -> ss2socks > sslocal
        logger.fine("start relay back to sslocal")
        async {
            var haveRead: Int
            try {
                while (true) {
                    haveRead = backEndSocketChannel.aRead(plainReadBuffer.buffer)
                    if (haveRead <= 0) {
                        client.shutdownAll()
                        backEndSocketChannel.shutdownAll()
                        break
                    }

                    plainReadBuffer.buffer.flip()
                    writeCipher.encrypt(plainReadBuffer.buffer, cipherWriteBuffer.buffer)
                    plainReadBuffer.buffer.clear()
                    cipherWriteBuffer.buffer.flip()
                    client.aWrite(cipherWriteBuffer.buffer)
                    cipherWriteBuffer.buffer.clear()
                }
            } catch (e: AsynchronousCloseException) {
                logger.warning("backEnd -> ss2socks > sslocal : connect reset by peer")

            } finally {
                client.close()
                backEndSocketChannel.close()

                cipherReadBuffer.release()
                cipherWriteBuffer.release()
                plainWriteBuffer.release()
                plainReadBuffer.release()

                readCipher.finish()
                writeCipher.finish()
            }
        }
    }
}

fun main(args: Array<String>) = runBlocking {
    if (args.size != 2) {
        println("Usage: -c config.toml")
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