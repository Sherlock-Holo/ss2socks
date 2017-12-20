package libs.AsynchronousSocketChannel

import java.nio.channels.AsynchronousSocketChannel

fun AsynchronousSocketChannel.shutdownAll(): AsynchronousSocketChannel {
    this.shutdownInput()
    this.shutdownOutput()
    return this
}