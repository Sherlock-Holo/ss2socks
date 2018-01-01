package libs.bufferPool

import kotlinx.coroutines.experimental.channels.LinkedListChannel
import libs.logger.logger
import java.nio.ByteBuffer

class BufferPool(private val bufferSize: Int = 8192, initPoolSize: Int = 100) {
    private val bufferQueue = LinkedListChannel<CustomBuffer>()

    init {
        for (i in 0 until initPoolSize) bufferQueue.offer(CustomBuffer(bufferSize))
    }

    fun get(): CustomBuffer {
        return if (bufferQueue.isEmpty) {
            logger.info("buffer pool is not enough, create a new buffer")
            bufferQueue.offer(CustomBuffer(bufferSize))
            bufferQueue.poll()!!.outQueue()
        } else bufferQueue.poll()!!.outQueue()
    }

    inner class CustomBuffer(size: Int) {
        val buffer = ByteBuffer.allocateDirect(size)!!
        private var inQueue: Boolean = false

        fun release() {
            if (!inQueue) {
                buffer.clear()
                bufferQueue.offer(this)
                inQueue = true
            }
        }

        fun outQueue(): CustomBuffer {
            inQueue = false
            return this
        }
    }
}