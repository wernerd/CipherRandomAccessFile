package wdi.cipherrandomaccess

import org.junit.jupiter.api.Test

class DataIoTests {

    @Test
    fun shift_test() {
        val i = 0xff00fe00
        println("first shift ${i.ushr(8)}")
        println("second shift ${i.ushr(8)}")
        println("third shift ${i.ushr(16)}")
    }
}
