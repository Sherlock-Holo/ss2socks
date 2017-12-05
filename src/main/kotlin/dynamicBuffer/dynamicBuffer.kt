package dynamicBuffer

import java.nio.ByteBuffer

class DynamicBuffer {
    lateinit var buffer: ByteBuffer
    var bufferSize = 4096
    var continueTimes = 0

    fun allocate(uselessCapacity: Int): DynamicBuffer {
        buffer = ByteBuffer.allocate(bufferSize)
        return this
    }

    fun customAllocate(capacity: Int): DynamicBuffer {
        bufferSize = capacity
        buffer = ByteBuffer.allocate(bufferSize)
        return this
    }

    fun get(): Byte {
        return buffer.get()
    }

    fun get(dst: ByteArray): ByteBuffer {
        return buffer.get(dst)
    }

    fun get(int: Int): Byte {
        return buffer.get(int)
    }

    fun put(byte: Byte): ByteBuffer {
        return buffer.put(byte)
    }

    fun put(src: ByteArray): ByteBuffer {
        if (src.size == bufferSize) {
            if (continueTimes < 3) {
                continueTimes++
            } else {
                bufferSize *= 2
                buffer = ByteBuffer.allocate(bufferSize).put(buffer)
            }
        } else {
            continueTimes = 0
        }
        return buffer.put(src)
    }

    fun put(src: ByteBuffer): ByteBuffer {
        if (src.capacity() == bufferSize) {
            if (continueTimes < 3) {
                continueTimes++
            } else {
                bufferSize *= 2
                buffer = ByteBuffer.allocate(bufferSize).put(buffer)
            }
        } else {
            continueTimes = 0
        }
        return buffer.put(src)
    }

    fun flip(): ByteBuffer {
        return buffer.flip() as ByteBuffer
    }

    fun compact(): ByteBuffer {
        return buffer.compact()
    }

    fun clear(): ByteBuffer {
        return buffer.clear() as ByteBuffer
    }

    fun position(): Int {
        return buffer.position()
    }

    fun position(newPosition: Int): ByteBuffer {
        return buffer.position(newPosition) as ByteBuffer
    }

    fun limit(): Int {
        return buffer.limit()
    }

    fun limit(newLimit: Int): ByteBuffer {
        return buffer.limit(newLimit) as ByteBuffer
    }

    fun capacity(): Int {
        return bufferSize
    }
}

fun main(args: Array<String>) {
    val dbuffer = DynamicBuffer().allocate(4096)
//    dbuffer.allocate(4096)
    dbuffer.put("sherlock".toByteArray())
    dbuffer.flip()
    println(String(byteArrayOf(dbuffer.get())))
    dbuffer.compact()
    println(dbuffer.position())
    dbuffer.flip()
    val test = ByteArray(7)
    dbuffer.get(test)
    println(String(test))
}