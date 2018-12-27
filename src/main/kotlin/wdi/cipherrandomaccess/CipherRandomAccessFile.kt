/*
 * Copyright 2018 Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package wdi.cipherrandomaccess

import java.io.Closeable
import java.io.DataInput
import java.io.DataOutput
import java.io.EOFException
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.RandomAccessFile
import java.io.UTFDataFormatException
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec


/**
 * Instances of this class support both reading and writing to an encrypted random access file.
 *
 * Actually this class is a wrapper of the standard [RandomAccessFile] class and provides all
 * of its features and functions (thus a plugin-replacement in that regard). Thus for the documentation
 * of the functions refer to [RandomAccessFile], [DataInput], [DataOutput] and [Closeable].
 *
 * The encryption/decryption function of this class uses an AES cipher in counter mode, 256-bit
 * key length. Currently the function uses a counter IV with 12 bytes of random data and a 4 byte
 * counter. Thus the maximum length of a file (message) is 64GB. This also gives plenty of room
 * to use long-term keys to encrypt files, see notes below.
 *
 * Some notes and caveats on how to use this class:
 *
 * - the encryption/decryption functions do _not_ perform any authentication (HMAC or alike). If
 *   required the caller should perform an HMAC of the file _after_ closing it and check before
 *   using it again.
 *
 * - never use the same IV with one (long term) key, make sure that the first 12 bytes
 *   (0 - 11) of the IV are always different (random) for different files. If possible use
 *   different keys for different files. If your application needs a single long-term key for
 *   its files then check this SO article:
 *       https://crypto.stackexchange.com/questions/10044/aes-ctr-with-similar-ivs-and-same-key
 *   to determine the how many files you could safely encrypt with one long-term key :-) .
 *   This class uses 12 bytes of random data (2^96 possible values) for the IV, thus if you
 *   use one long term key to encrypt 2^20 (> 1 million) files then the probability (according
 *   to my computation) to get the same random number again is 1 in 2^56 (2^40/2^96).
 *
 * - this class does not provide functions to store the key and IV. This should be done
 *   elsewhere.
 *
 * The main use cases for this class are e-mail, messaging or storage systems (file archiving
 * systems for example) that need to store their attachments/files as encrypted files.
 * These system should provide some (secure) way to store the necessary keys, IVs and maybe
 * HMACs for the encrypted attachment/files. Some sort of an encrypted database would
 * be of great help (SqlCipher is one example).
 */
class CipherRandomAccessFile
@Throws(FileNotFoundException::class) constructor(file: File, mode: String) : DataInput, DataOutput, Closeable {

    constructor(fileName: String, mode: String) : this(File(fileName), mode)

    // This may throw a FileNotFoundException
    private val randomAccess = RandomAccessFile(file, mode)

    // keep track of read/write position in file. Cipher function use it to compute counter and offsets
    private var positionInFile = 0L

    // @VisibleForTesting
    internal val ivWithCounter = ByteArray(CRYPT_BLOCK_SIZE)

    // Helper array for single byte read
    private val singleByteArray = ByteArray(1)

    // using counter mode, the basic cipher is ECB, no padding
    private val cipher by lazy { Cipher.getInstance("AES/ECB/NoPadding") }
    private var cipherInitialized = false
    private var cryptBuffer = ByteArray(0)


    // region Random access file function wrapper

    /**
     * The current offset in this file.
     */
    val filePointer: Long
        get() {
            positionInFile = randomAccess.filePointer
            return positionInFile
        }

    /**
     * The length of this file.
     */
    val length: Long
        get() = randomAccess.length()

    /**
     * Read one byte of data and decrypts it.
     *
     * Details
     * @see [RandomAccessFile]
     */
    @Throws(IOException::class)
    fun read(): Int {
        var datum = randomAccess.read()
        if (datum == -1) return -1

        singleByteArray[0] = datum.toByte()
        applyCryptTransform(singleByteArray, 0, 1, true)
        datum = (singleByteArray[0].toInt()) and 0xff
        positionInFile += 1

        return datum
    }


    /**
     * Read up to `len` bytes of data, decrypt and store them into an array of bytes.
     *
     * Details
     * @see [RandomAccessFile]
     */
    @Throws(IOException::class)
    fun read(buffer: ByteArray, offset: Int, len: Int): Int {
        val length = randomAccess.read(buffer, offset, len)
        if (length == -1) return -1

        applyCryptTransform(buffer, offset, length, true)
        positionInFile += length
        return length
    }

    /**
     * Read up to `buffer.length` bytes of data, decrypt and store them into an array of bytes.
     *
     * Details
     * @see [RandomAccessFile]
     */
    @Throws(IOException::class)
    fun read(buffer: ByteArray): Int {
        return read(buffer, 0, buffer.size)

    }

    /**
     * Sets the file-pointer offset, measured from the beginning of this file, at which the next read or write occurs.
     *
     * Details
     * @see [RandomAccessFile]
     */
    @Throws(IOException::class)
    fun seek(filePointer: Long) {
        if (filePointer < 0) {
            throw IOException("Negative seek offset")
        } else {
            positionInFile = filePointer
            randomAccess.seek(filePointer)
        }
    }

    /**
     * Encrypts and writes the specified byte to this file.
     *
     * The write starts at the current file pointer.
     *
     * @param      buffer   the `byte` to be written.
     * @exception  IOException  if an I/O error occurs.
     */
    @Throws(IOException::class)
    override fun write(buffer: Int) {
        singleByteArray[0] = buffer.toByte()
        applyCryptTransform(singleByteArray, 0, 1)
        randomAccess.write((cryptBuffer[0].toInt()) and 0xff)

        cryptBuffer[0] = 0
        positionInFile += 1
    }

    /**
     * Encrypts and writes `buffer.length` bytes from the specified byte array to this file.
     *
     * The write starts at the current file pointer.
     *
     * @param      buffer   the data.
     * @exception  IOException  if an I/O error occurs.
     */
    @Throws(IOException::class)
    override fun write(buffer: ByteArray) {
        write(buffer, 0, buffer.size)
    }

    /**
     * Encrypts and writes `len` bytes from the specified byte array starting at offset `offset` to this file.
     *
     * The write starts at the current file pointer.
     *
     * @param      buffer  the data.
     * @param      offset  the start offset in the data.
     * @param      len     the number of bytes to write.
     * @exception  IOException  if an I/O error occurs.
     */
    @Throws(IOException::class)
    override fun write(buffer: ByteArray, offset: Int, len: Int) {
        applyCryptTransform(buffer, offset, len)
        randomAccess.write(cryptBuffer, 0, len)

        cryptBuffer.fill(0, 0, len)
        positionInFile += len
    }

    // endregion

    // region Cipher functions
    /**
     * Set the cipher key and IV and initialize the cipher
     *
     * The key must have a length of 32 bytes (256 bit) because this class uses a 256 AES cipher to encrypt
     * and decrypt the data. The IV must have a length of 16 bytes (128 bits) which is the AES block size.
     * The first 12 bytes of the IV must be random data and should be different for different files if the
     * caller (application) uses the same key for different files.
     *
     * This function copies the IV and sets the byte 12 to 15 (4 bytes) to zero. The cipher mode uses these
     * 4 bytes as the counter.
     *
     * The functions does _not_ store or persists the key of IV with the file. The application needs to
     * store this information to be able to read the file.
     *
     * @param key the encryption/decryption key
     * @param ivCtr the IV - see notes above
     *
     */
    fun initializeCipher(key: ByteArray, ivCtr: ByteArray) {
        if (ivCtr.size != CRYPT_BLOCK_SIZE) throw IllegalArgumentException("IV does not match crypto block size")
        if (key.size != KEY_LENGTH) throw IllegalArgumentException("Key does not match expected key length")

        // Use the last four bytes as counter. This gives us a file size of 16 * 2^32 bytes (64GB)
        System.arraycopy(ivCtr, 0, ivWithCounter, 0, ivWithCounter.size)
        for (idx in CRYPT_BLOCK_SIZE - COUNTER_BYTES until CRYPT_BLOCK_SIZE) ivWithCounter[idx] = 0

        val keySpec = SecretKeySpec(key, "AES")

        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        cipherInitialized = true
    }

    /**
     * Encrypt or decrypt a buffer.
     *
     * This function performs the counter mode encryption and decryption on the data based
     * on the current file position. The counter in the IV is a 4 byte, using the block
     * number inside the file as the counter value. Because the file position is not always
     * on a block boundary the function computes the necessary offset where to start the
     * crypto transform using on the encrypted IV with counter.
     *
     * If this is a transform to write data then the function uses a crypto buffer as its
     * destination to avoid overwriting the input data. The write functions deal with
     * this feature.
     */
    private fun applyCryptTransform(inData: ByteArray, start: Int, length: Int, reading: Boolean = false) {
        if (!cipherInitialized) throw IOException(" Cipher not initialized")
        if (length <= 0) return

        if (cryptBuffer.size < length) cryptBuffer = ByteArray(length)

        val blockNumber = (positionInFile ushr CRYPT_BLOCK_SIZE_SHIFT).toInt()   // divide by 16
        var startOffset = (positionInFile and CRYPT_BLOCK_SIZE_MASK).toInt()     // what's left


        // use last 4 bytes as counter, put blockNumber in network order to last 4 bytes of IV
        var ivIdx = CRYPT_BLOCK_SIZE - COUNTER_BYTES
        ivWithCounter[ivIdx++] = (blockNumber ushr 24).toByte()
        ivWithCounter[ivIdx++] = (blockNumber ushr 16).toByte()
        ivWithCounter[ivIdx++] = (blockNumber ushr 8).toByte()
        ivWithCounter[ivIdx] = (blockNumber and 0xff).toByte()

        val encryptedIvCtr = cipher.doFinal(ivWithCounter)
        var len = length
        var inOffset = start
        var outIndex = if (reading) start else 0
        val outBuffer = if (reading) inData else cryptBuffer

        while (len-- > 0) {
            // The line without the toInt() call actually produces more code (JVM byte codes). This may be due to
            // the JVM baload/bastore property to widen (sign-extend) the byte to an integer when loading from a
            // byte array and truncate when storing in the array. Kotlin's experimental byte xor handling somehow
            // produces some more code when dealing with bytes.
//            outBuffer[outIndex++] = inData[inOffset++] xor encryptedIvCtr[startOffset++]
            outBuffer[outIndex++] = (inData[inOffset++].toInt() xor encryptedIvCtr[startOffset++].toInt()).toByte()
            if (startOffset >= CRYPT_BLOCK_SIZE && len > 0) {
                incrementCounter()
                cipher.doFinal(
                    ivWithCounter, 0,
                    CRYPT_BLOCK_SIZE, encryptedIvCtr
                )
                startOffset = 0
            }
        }
    }

    // Increment the counter: lowest byte first, if it wraps then next one and so on. Max 4 bytes.
    private fun incrementCounter() {
        var size = 3
        while (size >= 0 && (++ivWithCounter[CRYPT_BLOCK_SIZE - COUNTER_BYTES + size]).toInt() == 0) {
            size--
        }
    }

    // endregion

    companion object {

        const val CRYPT_BLOCK_SIZE = 16
        const val CRYPT_BLOCK_SIZE_SHIFT = 4
        const val CRYPT_BLOCK_SIZE_MASK = 0xfL

        const val COUNTER_BYTES = 4

        const val KEY_LENGTH = 32
    }

    // region Closeable implementation
    /**
     * Closes this cipher random access file and releases any system resources associated with the stream.
     *
     * A closed cipher random access file cannot perform input or output operations and cannot be reopened.
     *
     * @exception  IOException  if an I/O error occurs.
     */
    @Throws(IOException::class)
    override fun close() {
        randomAccess.close()
        cipherInitialized = false

        cryptBuffer.fill(0)
        ivWithCounter.fill(0)
    }

    // endregion

    // region DataInput implementation

    /**
     * Read exactly `buffer.length` bytes of data, decrypt and store them into an array of bytes.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readFully(buffer: ByteArray) {
        readFully(buffer, 0, buffer.size)
    }

    /**
     * Read exactly `length` bytes of data, decrypt and store them into an array of bytes.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readFully(buffer: ByteArray, offset: Int, length: Int) {
        var numRead = 0
        while (numRead < length) {
            val count = read(buffer, offset + numRead, length - numRead)
            if (count < 0) throw EOFException()
            numRead += count
        }
        positionInFile += length
    }

    /**
     * Attempts to skip over `bytesToSkip` bytes of input discarding the skipped bytes.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun skipBytes(bytesToSkip: Int): Int {
        if (bytesToSkip <= 0) {
            return 0
        }
        val pointer = filePointer       // cache because 'filePointer' uses a system call to get file pointer
        val fileLength = length         // cache because 'length' uses a system call to get file size

        var newPointer = pointer + bytesToSkip
        if (newPointer > fileLength) {
            newPointer = fileLength
        }
        seek(newPointer)
        return (newPointer - pointer).toInt()
    }

    /**
     * Reads a `boolean` from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readBoolean(): Boolean {
        val value = read()
        if (value < 0) throw EOFException()
        return value != 0
    }

    /**
     * Reads a signed eight-bit value from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readByte(): Byte {
        val value = read()
        if (value < 0) throw EOFException()
        return value.toByte()
    }

    /**
     * Reads an unsigned eight-bit value from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readUnsignedByte(): Int {
        val value = read()
        if (value < 0) throw EOFException()
        return value
    }

    /**
     * Reads a signed 16-bit number from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readShort(): Short {
        val value1 = read()
        val value2 = read()
        if (value1 or value2 < 0) throw EOFException()
        return ((value1 shl 8) or value2).toShort()
    }

    /**
     * Reads an unsigned 16-bit number from this file, return as lower two bytes in an Int
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readUnsignedShort(): Int {
        val value1 = read()
        val value2 = read()
        if (value1 or value2 < 0) throw EOFException()
        return (value1 shl 8) or value2
    }

    /**
     * Reads a character from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readChar(): Char {
        val value = readUnsignedShort()
        return value.toChar()
    }

    /**
     * Reads a signed 32-bit integer from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readInt(): Int {
        val value1 = this.read()
        val value2 = this.read()
        val value3 = this.read()
        val value4 = this.read()
        if ((value1 or value2 or value3 or value4) < 0) throw EOFException()
        return (value1 shl 24) or (value2 shl 16) or (value3 shl 8) or value4
    }

    /**
     * Reads a signed 64-bit integer from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readLong(): Long {
        return (readInt().toLong() shl 32) or (readInt().toLong() and 0xFFFFFFFF)
    }

    /**
     * Reads a `float` from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readFloat(): Float {
        return java.lang.Float.intBitsToFloat(readInt())
    }

    /**
     * Reads a `double` from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readDouble(): Double {
        return java.lang.Double.longBitsToDouble(readLong())
    }

    /**
     * Reads the next line of text from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readLine(): String? {
        val input = StringBuffer()
        var value = -1
        var eol = false

        while (!eol) {
            value = read()
            when (value) {
                -1, '\n'.toInt() -> eol = true
                '\r'.toInt() -> {
                    eol = true
                    val cur = filePointer
                    if (read() != '\n'.toInt()) {
                        seek(cur)
                    }
                }
                else -> input.append(value.toChar())
            }
        }

        return if (value == -1 && input.isEmpty()) null else input.toString()
    }

    /**
     * Reads in a string from this file.
     *
     * Details
     * @see [DataInput]
     */
    @Throws(IOException::class)
    override fun readUTF(): String {
        val length = readUnsignedShort()

        val inArray = ByteArray(length)
        read(inArray)
        return String(inArray)
    }

    // endregion

    // region DataOut implementation
    /**
     * Writes a `boolean` to the file as a one-byte value.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeBoolean(value: Boolean) {
        write(if (value) 1 else 0)
    }

    /**
     * Writes a `byte` to the file as a one-byte value.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeByte(value: Int) {
        write(value)
    }

    /**
     * Writes a `short` to the file as two bytes, high byte first.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeShort(value: Int) {
        write(value.ushr(8) and 0xFF)
        write(value and 0xFF)
    }

    /**
     * Writes a `char` to the file as a two-byte value, high byte first.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeChar(value: Int) {
        writeShort(value)
    }

    /**
     * Writes an `int` to the file as four bytes, high byte first.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeInt(value: Int) {
        write(value.ushr(24) and 0xFF)
        write(value.ushr(16) and 0xFF)
        write(value.ushr(8) and 0xFF)
        write(value and 0xFF)
    }

    /**
     * Writes a `long` to the file as eight bytes, high byte first.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeLong(value: Long) {
        write(value.ushr(56).toInt() and 0xFF)
        write(value.ushr(48).toInt() and 0xFF)
        write(value.ushr(40).toInt() and 0xFF)
        write(value.ushr(32).toInt() and 0xFF)
        write(value.ushr(24).toInt() and 0xFF)
        write(value.ushr(16).toInt() and 0xFF)
        write(value.ushr(8).toInt() and 0xFF)
        write(value.toInt() and 0xFF)
    }

    /**
     * Writes a `float`to the file.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeFloat(value: Float) {
        writeInt(java.lang.Float.floatToIntBits(value))
    }

    /**
     * Writes `double` to the file.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeDouble(value: Double) {
        writeLong(java.lang.Double.doubleToLongBits(value))
    }

    /**
     * Writes the string to the file as a sequence of bytes (lower byte of the characters only).
     *
     * Details
     * @see [DataOutput]
     */
    @Deprecated("Does not perform UTF conversion.", ReplaceWith("writeChars(String)"))
    @Throws(IOException::class)
    override fun writeBytes(inString: String) {
        val chars = inString.toCharArray()
        val b = ByteArray(chars.size * 2)
        for ((i, chr) in chars.withIndex()) b[i] = chr.toInt().toByte()
        write(b)
    }

    /**
     * Writes a string to the file as a sequence of characters.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeChars(inString: String) {
        val chars = inString.toCharArray()
        val b = ByteArray(chars.size * 2)
        var j = 0
        for (chr in chars) {
            b[j++] = (chr.toInt().ushr(8)).toByte()
            b[j++] = chr.toInt().toByte()
        }
        write(b)
    }

    /**
     * Writes a string to the file using modified UTF-8 encoding in a machine-independent manner.
     *
     * The readUTF() function can read this data, see above.
     *
     * Details
     * @see [DataOutput]
     */
    @Throws(IOException::class)
    override fun writeUTF(strng: String) {
        val buffer = strng.toByteArray()
        if (buffer.size > 65535) throw UTFDataFormatException("String too long: ${buffer.size} bytes")

        writeShort(buffer.size)
        write(buffer)
    }
    // endregion
}