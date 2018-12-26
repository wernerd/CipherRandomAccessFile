package wdi.cipherrandomaccess

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.io.FileNotFoundException

class BasicConstructorTest {

    @BeforeEach
    fun setup() {
        val testFile = File(TEST_FILE_NAME)
        if (testFile.exists()) testFile.delete()
    }

    @AfterEach
    fun teardown() {
        val testFile = File(TEST_FILE_NAME)
        if (testFile.exists()) testFile.delete()
    }

    @Test
    fun no_filename_mode_rw_then_file_exists() {

        val testFile = File(TEST_FILE_NAME)
        val sf = CipherRandomAccessFile(
            TEST_FILE_NAME,
            "rw"
        ); Assertions.assertTrue(testFile.exists()) { "Test file does not exist" }
        Assertions.assertEquals(0L, sf.filePointer)
        sf.close()
    }

    @Test
    fun no_file_mode_rw_then_file_exists() {

        val testFile = File(TEST_FILE_NAME)
        val sf = CipherRandomAccessFile(testFile, "rw")
        Assertions.assertTrue(testFile.exists()) { "Test file does not exist" }
        Assertions.assertEquals(0L, sf.filePointer)
        sf.close()
    }

    @Test
    fun no_filename_mode_r_then_exception() {
        Assertions.assertThrows(FileNotFoundException::class.java, {
            CipherRandomAccessFile(TEST_FILE_NAME, "r")
        }) { "Does not throw exception" }
    }

    @Test
    fun no_file_mode_r_then_exception() {

        val testFile = File(TEST_FILE_NAME)
        Assertions.assertThrows(
            FileNotFoundException::class.java,
            { CipherRandomAccessFile(testFile, "r") }) { "Does not throw exception" }
    }

    @Test
    fun has_filename_mode_r_then_no_exception() {

        val testFile = File(TEST_FILE_NAME)
        testFile.createNewFile()
        val sf = CipherRandomAccessFile(TEST_FILE_NAME, "r"); Assertions.assertEquals(0L, sf.filePointer)
        sf.close()
    }


    @Test
    fun has_file_mode_r_then_no_exception() {

        val testFile = File(TEST_FILE_NAME)
        testFile.createNewFile()
        val sf = CipherRandomAccessFile(testFile, "r")
        Assertions.assertEquals(0L, sf.filePointer)
        sf.close()
    }

    @Test
    fun has_filename_mode_rw_then_no_exception() {

        val testFile = File(TEST_FILE_NAME)
        testFile.createNewFile()
        val sf = CipherRandomAccessFile(TEST_FILE_NAME, "rw"); Assertions.assertEquals(0L, sf.filePointer)
        sf.close()
    }


    @Test
    fun has_file_mode_rw_then_no_exception() {

        val testFile = File(TEST_FILE_NAME)
        testFile.createNewFile()
        val sf = CipherRandomAccessFile(testFile, "rw")
        Assertions.assertEquals(0L, sf.filePointer)
        sf.close()
    }

    companion object {
        const val TEST_FILE_NAME = "test_1.dat"
    }
}