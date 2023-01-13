# FileCrypt
Small console application that allows the encryption of files with AES and using a password (key derived using PKCS7)

This program is a small C# console application that allows the encryption and decryption of a file using AES.
It furthermore computes an HMAC (with SHA512) which it adds to the "header" of the encrypted file, 
thus, the user is able to see if the encrypted file was manipulated by an attacker.
 
This program supports encryption:
> FileCrypt encrypt InputFileName OutputFileName
 
This program supports decryption:
> FileCrypt decrypt InputFileName OutputFileName
 
In both cases, the program asks the user for a password which is used to compute the AES key as well as the HMAC key.
For both key generations, PBKDF2 (with SHA512) is used.
 
AES is used with 256 bit keys. The used mode of operation is CBC. The used padding is PKCS7.
For IV and salt generation, the rng crypto service provider of .net is used.

This program is intended for educational purposes. Feel free to use, modify, and play with it :-)
