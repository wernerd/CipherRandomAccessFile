/*
 * Copyright (c) 2018 Werner Dittman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package wdi.cipherrandomaccess

import org.junit.jupiter.api.*
import java.io.EOFException
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

class ReadWriteTest {

    private lateinit var craf: CipherRandomAccessFile

    companion object {
        const val TEST_FILE_NAME = "test_1.dat"

        val KEY = byteArrayOf(
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
        )
        val IV = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)

        val testDataArray = ByteArray(256)

        @Suppress("unused")
        @BeforeAll
        @JvmStatic
        fun setupTestData() {
            for (i in testDataArray.indices) testDataArray[i] = i.toByte()
        }
    }

    @BeforeEach
    fun setup() {
        val testFile = File(TEST_FILE_NAME)
        if (testFile.exists()) testFile.delete()
        craf = CipherRandomAccessFile(TEST_FILE_NAME, "rw")
        craf.initializeCipher(KEY, IV)

    }

    @AfterEach
    fun teardown() {
        craf.close()
        val testFile = File(TEST_FILE_NAME)
        if (testFile.exists()) testFile.delete()
    }

    @Test
    fun read_byte_from_empty_file() {
        Assertions.assertEquals(-1, craf.read())
    }

    @Test
    fun read_bytearray_from_empty_file() {
        val array = ByteArray(10)
        Assertions.assertEquals(-1, craf.read(array))
    }

    @Test
    fun cipher_not_initialized_write_then_ioException() {
        val racfLocal = CipherRandomAccessFile(TEST_FILE_NAME, "rw")
        Assertions.assertThrows(IOException::class.java, { racfLocal.write(0) }) { "Does not throw exception" }
        racfLocal.close()
    }

    @Test
    fun initialize_cipher_then_check_iv() {
        // initializeCipher must not change the original IV
        Assertions.assertEquals(12, IV[12])
        Assertions.assertEquals(13, IV[13])
        Assertions.assertEquals(14, IV[14])
        Assertions.assertEquals(15, IV[15])

        // Counter part of the IV inside must be zero
        Assertions.assertEquals(0, craf.ivWithCounter[12])
        Assertions.assertEquals(0, craf.ivWithCounter[13])
        Assertions.assertEquals(0, craf.ivWithCounter[14])
        Assertions.assertEquals(0, craf.ivWithCounter[15])
        craf.close()
    }

    @Test
    fun write_then_check_data_encrypted() {

        craf.write(testDataArray)

        // We need 16 writes to store the data, counting from 0 leaves us with 15, The
        // crypt function skips the last cipher call if possible
        Assertions.assertEquals(15, craf.ivWithCounter[15].toInt())

        Assertions.assertEquals(testDataArray.size, craf.length.toInt())
        Assertions.assertEquals(testDataArray.size, craf.filePointer.toInt())

        craf.close()

        val ra = RandomAccessFile(TEST_FILE_NAME, "r")
        val encryptedArray = ByteArray(256)
        val read = ra.read(encryptedArray)
        Assertions.assertEquals(testDataArray.size, read)


        // With this test data and key setup we have a "same" value at index 68. That's OK because of counter mode
        // This is just a coincidence of the test data and the way the check works
        for (i in 0..50) Assertions.assertNotEquals(
            encryptedArray[i],
            testDataArray[i]
        ) { "Failed at index $i, data ${testDataArray[i]}" }
        ra.close()
    }

    @Test
    fun write_read_then_check_data() {

        craf.write(testDataArray)
        // We need 16 writes to store the data, counting from 0 leaves us with 15, The
        // crypt function skips the last cipher call if possible
        Assertions.assertEquals(15, craf.ivWithCounter[15].toInt())

        Assertions.assertEquals(testDataArray.size, craf.length.toInt())
        Assertions.assertEquals(testDataArray.size, craf.filePointer.toInt())

        // set to position 0, then read back data
        craf.seek(0)
        Assertions.assertEquals(0, craf.filePointer.toInt())

        val encryptedArray = ByteArray(256)
        val read = craf.read(encryptedArray)
        Assertions.assertEquals(testDataArray.size, read)
        craf.close()

        for ((i, b) in testDataArray.withIndex()) Assertions.assertEquals(
            b,
            encryptedArray[i]
        ) { "Failed at index $i, data ${encryptedArray[i]}" }
    }

    @Test
    fun write_readFully_then_check_data() {

        craf.write(testDataArray)
        // We need 16 writes to store the data, counting from 0 leaves us with 15, The
        // crypt function skips the last cipher call if possible
        Assertions.assertEquals(15, craf.ivWithCounter[15].toInt())

        Assertions.assertEquals(testDataArray.size, craf.length.toInt())
        Assertions.assertEquals(testDataArray.size, craf.filePointer.toInt())

        // set to position 0, then read back data
        craf.seek(0)
        Assertions.assertEquals(0, craf.filePointer.toInt())

        val encryptedArray = ByteArray(256)
        craf.readFully(encryptedArray)
        craf.close()

        for ((i, b) in testDataArray.withIndex()) Assertions.assertEquals(
            b,
            encryptedArray[i]
        ) { "Failed at index $i, data ${encryptedArray[i]}" }
    }

    @Test
    fun write_readFully_too_much_then_eofException() {

        craf.write(testDataArray)
        // We need 16 writes to store the data, counting from 0 leaves us with 15, The
        // crypt function skips the last cipher call if possible
        Assertions.assertEquals(15, craf.ivWithCounter[15].toInt())

        Assertions.assertEquals(testDataArray.size, craf.length.toInt())
        Assertions.assertEquals(testDataArray.size, craf.filePointer.toInt())

        // set to position 0, then read back data
        craf.seek(0)
        Assertions.assertEquals(0, craf.filePointer.toInt())

        val encryptedArray = ByteArray(256 + 1)
        Assertions.assertThrows(
            EOFException::class.java,
            { craf.readFully(encryptedArray) }) { "Does not throw exception" }

        craf.close()
    }

    @Test
    fun write_seek_read_then_check_data() {

        craf.write(testDataArray)
        // We need 16 writes to store the data, counting from 0 leaves us with 15, The
        // crypt function skips the last cipher call if possible
        Assertions.assertEquals(15, craf.ivWithCounter[15].toInt())

        Assertions.assertEquals(testDataArray.size, craf.length.toInt())
        Assertions.assertEquals(testDataArray.size, craf.filePointer.toInt())

        // set to position 14, then read back data, crossing cipher block boundary
        craf.seek(14)
        Assertions.assertEquals(14, craf.filePointer.toInt())

        val encryptedArray = ByteArray(4)
        craf.read(encryptedArray)
        craf.close()

        Assertions.assertEquals(testDataArray[14], encryptedArray[0])
        Assertions.assertEquals(testDataArray[15], encryptedArray[1])
        Assertions.assertEquals(testDataArray[16], encryptedArray[2])
        Assertions.assertEquals(testDataArray[17], encryptedArray[3])
    }

    @Test
    fun write_seek_read_byte_then_check_data() {

        craf.write(testDataArray)

        // We need 16 writes to store the data, counting from 0 leaves us with 15, The
        // crypt function skips the last cipher call if possible
        Assertions.assertEquals(15, craf.ivWithCounter[15].toInt())

        Assertions.assertEquals(testDataArray.size, craf.length.toInt())
        Assertions.assertEquals(testDataArray.size, craf.filePointer.toInt())

        // set to position 14, then read back data, crossing cipher block boundary
        craf.seek(14)
        Assertions.assertEquals(14, craf.filePointer.toInt())

        var datum = craf.read()
        Assertions.assertEquals(testDataArray[14], datum.toByte())

        datum = craf.read()
        Assertions.assertEquals(testDataArray[15], datum.toByte())

        datum = craf.read()
        Assertions.assertEquals(testDataArray[16], datum.toByte())

        datum = craf.read()
        Assertions.assertEquals(testDataArray[17], datum.toByte())

        craf.close()
    }

    @Test
    fun seek_write_seek_read_then_check_data() {

        // set to position 14, then write data, crossing cipher block boundary
        craf.seek(14)
        Assertions.assertEquals(14, craf.filePointer.toInt())

        craf.write(testDataArray)

        // We need 16 writes to store the data, counting from 0 leaves us with 15. Because
        // not starting on a cipher boundary the crypto function performs one additional
        // cipher call, thus 17 - counting from 0 -> 16
        Assertions.assertEquals(16, craf.ivWithCounter[15].toInt())

        // File ist longer than test data because of the seek (+14)
        Assertions.assertEquals(testDataArray.size + 14, craf.length.toInt())
        Assertions.assertEquals(testDataArray.size + 14, craf.filePointer.toInt())

        // set to position 14, then read back data, crossing cipher block boundary
        craf.seek(14)
        Assertions.assertEquals(14, craf.filePointer.toInt())

        val encryptedArray = ByteArray(testDataArray.size)
        craf.read(encryptedArray)
        craf.close()

        for ((i, b) in testDataArray.withIndex()) Assertions.assertEquals(
            b,
            encryptedArray[i]
        ) { "Failed at index $i, data ${encryptedArray[i]}" }
    }


    @Test
    fun seek_write_bytes_seek_read_then_check_data() {

        // set to position 14, then write data, crossing cipher block boundary
        craf.seek(14)
        Assertions.assertEquals(14, craf.filePointer.toInt())

        // write 4 single bytes, crossing a cipher block boundary
        craf.write(testDataArray[0].toInt())
        craf.write(testDataArray[1].toInt())
        craf.write(testDataArray[2].toInt())
        craf.write(testDataArray[3].toInt())

        // Counter at one, after first block
        Assertions.assertEquals(1, craf.ivWithCounter[15].toInt())

        // File ist longer than test data because of the seek (+14)
        Assertions.assertEquals(14 + 4, craf.length.toInt())
        Assertions.assertEquals(14 + 4, craf.filePointer.toInt())

        // set to position 14, then read back data, crossing cipher block boundary
        craf.seek(14)
        Assertions.assertEquals(14, craf.filePointer.toInt())

        val encryptedArray = ByteArray(4)
        craf.read(encryptedArray)
        craf.close()

        Assertions.assertEquals(testDataArray[0], encryptedArray[0])
        Assertions.assertEquals(testDataArray[1], encryptedArray[1])
        Assertions.assertEquals(testDataArray[2], encryptedArray[2])
        Assertions.assertEquals(testDataArray[3], encryptedArray[3])
    }

    @Test
    fun write4k_read_then_check_data() {

        for (i in 0..16) craf.write(testDataArray)

        // We need 17 writes to store the data, counting from 0 leaves us with 16, The
        // crypt function skips the last cipher call if possible
        Assertions.assertEquals(15, craf.ivWithCounter[15].toInt())
        Assertions.assertEquals(1, craf.ivWithCounter[14].toInt())

        Assertions.assertEquals(testDataArray.size * 17, craf.length.toInt())
        Assertions.assertEquals(testDataArray.size * 17, craf.filePointer.toInt())

        // set to position 0, then read back data
        craf.seek(0)
        Assertions.assertEquals(0, craf.filePointer.toInt())

        for (k in 0..16) {
            val encryptedArray = ByteArray(256)
            val read = craf.read(encryptedArray)
            Assertions.assertEquals(testDataArray.size, read)
            for ((i, b) in testDataArray.withIndex()) Assertions.assertEquals(
                b,
                encryptedArray[i]
            ) { "Failed at index $i, data ${encryptedArray[i]}, loop $k" }
        }
        craf.close()
    }

    @Test
    fun write4k_seek_read_then_check_data() {

        for (i in 0..16) craf.write(testDataArray)

        // We need 17 writes to store the data, counting from 0 leaves us with 16, The
        // crypt function skips the last cipher call if possible
        Assertions.assertEquals(15, craf.ivWithCounter[15].toInt())
        Assertions.assertEquals(1, craf.ivWithCounter[14].toInt())

        Assertions.assertEquals(testDataArray.size * 17, craf.length.toInt())
        Assertions.assertEquals(testDataArray.size * 17, craf.filePointer.toInt())

        // set to position 4094, then read back data. This crosses a 4KB, a 256B and a block size
        // boundary and overflows the least significant counter byte and increments the next one
        // by one. Then read 4 bytes and check if everything is as expected.
        craf.seek(4094)
        Assertions.assertEquals(4094, craf.filePointer.toInt())

        val encryptedArray = ByteArray(4)
        craf.read(encryptedArray)

        Assertions.assertEquals(0, craf.ivWithCounter[15].toInt())
        Assertions.assertEquals(1, craf.ivWithCounter[14].toInt())

        Assertions.assertEquals(testDataArray[254], encryptedArray[0])
        Assertions.assertEquals(testDataArray[255], encryptedArray[1])
        Assertions.assertEquals(testDataArray[0], encryptedArray[2])
        Assertions.assertEquals(testDataArray[1], encryptedArray[3])

        craf.close()
    }


    @Test
    fun write_read_basic_data_types() {
        craf.writeBoolean(true)
        craf.writeBoolean(false)
        craf.seek(0)
        Assertions.assertTrue(craf.readBoolean())
        Assertions.assertFalse(craf.readBoolean())

        // byte values
        var pos = craf.filePointer
        craf.writeByte(0)
        craf.writeByte(255)
        craf.writeByte(127)
        craf.writeByte(-128)
        craf.writeByte(-1)

        craf.seek(pos)
        Assertions.assertEquals(0, craf.readByte())
        Assertions.assertEquals(255, craf.readUnsignedByte())
        Assertions.assertEquals(127, craf.readByte())
        Assertions.assertEquals(-128, craf.readByte())
        Assertions.assertEquals(-1, craf.readByte())

        pos = craf.filePointer
        craf.writeShort(0)
        craf.writeShort(0xffff)
        craf.writeShort(32767)
        craf.writeShort(-32768)
        craf.writeShort(-1)

        craf.seek(pos)
        Assertions.assertEquals(0, craf.readShort())
        Assertions.assertEquals(0xffff, craf.readUnsignedShort())
        Assertions.assertEquals(Short.MAX_VALUE, craf.readShort())
        Assertions.assertEquals(Short.MIN_VALUE, craf.readShort())
        Assertions.assertEquals(-1, craf.readShort())

        pos = craf.filePointer
        craf.writeInt(0)
        craf.writeInt(Int.MAX_VALUE)
        craf.writeInt(Int.MIN_VALUE)
        craf.writeInt(-1)

        craf.seek(pos)
        Assertions.assertEquals(0, craf.readInt())
        Assertions.assertEquals(Int.MAX_VALUE, craf.readInt())
        Assertions.assertEquals(Int.MIN_VALUE, craf.readInt())
        Assertions.assertEquals(-1, craf.readInt())

        pos = craf.filePointer
        craf.writeLong(0)
        craf.writeLong(Long.MAX_VALUE)
        craf.writeLong(Long.MIN_VALUE)
        craf.writeLong(-1)

        craf.seek(pos)
        Assertions.assertEquals(0, craf.readLong())
        Assertions.assertEquals(Long.MAX_VALUE, craf.readLong())
        Assertions.assertEquals(Long.MIN_VALUE, craf.readLong())
        Assertions.assertEquals(-1, craf.readLong())

        pos = craf.filePointer
        craf.writeFloat(0.0f)
        craf.writeFloat(Float.MAX_VALUE)
        craf.writeFloat(Float.MIN_VALUE)
        craf.writeFloat(-1.0f)

        craf.seek(pos)
        Assertions.assertEquals(0.0f, craf.readFloat())
        Assertions.assertEquals(Float.MAX_VALUE, craf.readFloat())
        Assertions.assertEquals(Float.MIN_VALUE, craf.readFloat())
        Assertions.assertEquals(-1.0f, craf.readFloat())

        pos = craf.filePointer
        craf.writeDouble(0.0)
        craf.writeDouble(Double.MAX_VALUE)
        craf.writeDouble(Double.MIN_VALUE)
        craf.writeDouble(-1.0)

        craf.seek(pos)
        Assertions.assertEquals(0.0, craf.readDouble())
        Assertions.assertEquals(Double.MAX_VALUE, craf.readDouble())
        Assertions.assertEquals(Double.MIN_VALUE, craf.readDouble())
        Assertions.assertEquals(-1.0, craf.readDouble())

    }

    @Test
    fun string_write_read() {
        // The functions writeBytes() and readLine() do not write/read real Java/Kotlin chars, only
        // the lower byte of a char, i.e. usable for ASCII mainly.
        val testString = "abcdef\n"
        craf.writeBytes(testString)
        craf.seek(0)

        // readLine does not store the newline character in the returned string
        val readBack = craf.readLine()
        Assertions.assertEquals(testString.substring(0, testString.length-1), readBack)

        val pos = craf.filePointer
        val utfString = "abäöüßéàâ∫√∑€Ωπ"
        craf.writeUTF(utfString)
        craf.seek(pos)
        val readUtf = craf.readUTF()
        Assertions.assertEquals(utfString, readUtf)
    }
}