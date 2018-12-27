## Encrypted random access file (Kotlin) ##

This small project provides the _CipherRandomAccessFile_ class which implements functions
to create, write and read encrypted random access files and serves an addition to Java's 
_CipherInputStream_

Actually the class is a wrapper of Java's _RandomAccessFile_ class and provides all
of its features and functions (thus a plugin-replacement in that regard). Thus, for the 
documentation of the functions, refer to _RandomAccessFile_, _DataInput_, _DataOutput_ 
and _Closeable_.

The encryption/decryption function of this class uses an AES cipher in counter mode, 256-bit
key length. Currently the function uses a counter IV with 12 bytes of random data and a 4 byte
counter. Thus the maximum length of a file (message) is 64GB. This also gives plenty of room
to use long-term keys to encrypt files, see notes below.

This is one of the main differences to Java's _CipherInputStream_ where the application can use
different cipher modes. To implement the random access feature the functions of 
_CipherRandomAccessFile_ required the counter mode.

Some notes and caveats on how to use this class:

- the encryption/decryption functions of _CipherRandomAccessFile_ do __not__ perform any 
  authentication (HMAC or alike). If required the caller should perform an HMAC of the 
  file _after_ closing it and check before using it again.

- be careful when using the same IV with one (long-term) key. Make sure that the first 12 bytes
  (0 - 11) of the IV are always different (random data) for different files. If possible use
  different keys for different files. If your application needs a single long-term key for
  its files then check this [SO article][so_1] to determine how many files you could safely
  encrypt with one long-term key :-) .
  
  _CipherRandomAccessFile_ uses 12 bytes of random data (2^96 possible values) for the IV, thus if
  you use one long term key to encrypt 2^20 (> 1 million) files then the probability (according
  to my computation) to get the same random number again is 1 in 2^56 (2^40/2^96).

- _CipherRandomAccessFile_ does not provide functions to store the key and IV. This should be done
  elsewhere. However, a simple enhancement would enable it to store the IV (you should
  not store the key within the file ;-) ).

The main use cases for this class are e-mail, messaging or storage systems (file archiving
systems for example) that need to store their attachments/files as encrypted random access 
files (for example media players often require random access files to play video and/or audio).
These system should provide some (secure) way to store the necessary keys, IVs and maybe
HMACs for the encrypted attachment/files. Some sort of an encrypted database would
be of great help (SqlCipher is one example).


#### License ####
Licensed using Apache 2.0 license.

[so_1]: https://crypto.stackexchange.com/questions/10044/aes-ctr-with-similar-ivs-and-same-key

