# CCCryptor
CN:
1. 因网络上大部分Block Cipher方式的加解密都是采用读取整个文件方式，未考虑到占用内存问题。
   本CCCryptor.m文件内方法采用AES加解密方式，同时考虑到内存占用问题。
   采用读取文件流，逐步加解密整个文件。

EN:
1. most open source en/decrypt Block Cipher Tool, did not consider large file causing memory peak.
   this CCCryptor.m use AES(CBC model) en/decrypt, and consider large file causing memory peak problem.
   read file stream and step by step en/decrypt whole large file.
