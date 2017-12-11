package libs.TCPPort

fun MakeSendPort(i: Int): ByteArray {
    val binaryNumber = StringBuffer(Integer.toBinaryString(i))
    while (binaryNumber.length <= 8) {
        binaryNumber.insert(0, '0')
    }
    val byteArray = ByteArray(2)
    byteArray[0] = Integer.parseInt(binaryNumber.substring(0 until binaryNumber.lastIndex - 7), 2).toByte()
    byteArray[1] = Integer.parseInt(binaryNumber.substring(binaryNumber.lastIndex - 7 until binaryNumber.lastIndex + 1), 2).toByte()
    return byteArray
}

fun GetPort(byteArray: ByteArray): Int {
    return (byteArray[0].toInt() and 0xFF shl 8) or (byteArray[1].toInt() and 0xFF)
}