/*
   Copyright 2022 Nils Kopal <Nils.Kopal<at>CrypTool.org>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FileCrypt
{
    /// <summary>
    /// This program is a small C# console application that allows the encryption and decryption of a file using AES.
    /// It furthermore computes an HMAC (with SHA512) which it adds to the "header" of the encrypted file, 
    /// thus, the user is able to see if the encrypted file was manipulated by an attacker.
    /// 
    /// This program supports encryption:
    /// > FileCrypt encrypt InputFileName OutputFileName
    /// 
    /// This program supports decryption:
    /// > FileCrypt decrypt InputFileName OutputFileName
    /// 
    /// In both cases, the program asks the user for a password which is used to compute the AES key as well as the HMAC key.
    /// For both key generations, PBKDF2 (with SHA512) is used.
    /// 
    /// AES is used with 256 bit keys. The used mode of operation is CBC. The used padding is PKCS7.
    /// For IV and salt generation, the rng crypto service provider of .net is used
    /// </summary>
    public class Program
    {
        private const int ITERATIONS = 50000; //iteration count for PBDKDF2
        private const int BUFFERSIZE = 4096 * 10; // 40 KB read and write buffer

        /// <summary>
        /// Entry in the encryption/decryption program
        /// </summary>
        /// <param name="args"></param>
        public static void Main(string[] args)
        {
            try
            {
                //step 1: check arguments
                if (args.Length != 3)
                {
                    throw new ArgumentException(string.Format("{0} command line arguments given. Need exactly 3: E.g. 'filecrypt encrypt inputFile outputFile' to encrypt inputFile into outputFile", args.Length));
                }
                if (!args[0].ToLower().Equals("encrypt") && !args[0].ToLower().Equals("decrypt"))
                {
                    throw new ArgumentException("First argument has to be 'encrypt' or 'decrypt'");
                }

                string sourceFile = args[1];
                string destinationFile = args[2];

                //step 2: the user has to provide a password (enter password and repeat it)
                Console.Write("Password:");
                string password = ReadPasswordFromConsole();
                Console.WriteLine();
                Console.Write("Repeat  :");
                string password2 = ReadPasswordFromConsole();
                Console.WriteLine();
                if (!password.Equals(password2))
                {
                    throw new Exception("Entered passwords did not match!");
                }

                //Step 3: encrypt or decrypt file
                if (args[0].ToLower().Equals("encrypt"))
                {
                    EncryptFile(sourceFile, destinationFile, password);
                }
                if (args[0].ToLower().Equals("decrypt"))
                {
                    DecryptFile(sourceFile, destinationFile, password);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("Exception occured: {0}", ex.Message);
            }
#if DEBUG
            finally
            {
                //in debug mode, to avoid closing of the console window, we wait
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey(true);
            }
#endif
        }

        /// <summary>
        /// Reads a password from the console without displaying it
        /// </summary>
        /// <returns></returns>
        private static string ReadPasswordFromConsole()
        {
            StringBuilder passwordBuilder = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo consoleKeyInfo = Console.ReadKey(true);
                if (consoleKeyInfo.Key == ConsoleKey.Enter)
                {
                    break;
                }
                if (consoleKeyInfo.Key == ConsoleKey.Backspace)
                {
                    if (passwordBuilder.Length != 0)
                    {
                        Console.Write("\b \b");
                        passwordBuilder.Remove(passwordBuilder.Length - 1, 1);
                    }
                    continue;
                }
                passwordBuilder.Append(consoleKeyInfo.KeyChar);
                Console.Write("*");
            }
            return passwordBuilder.ToString();
        }

        /// <summary>
        /// Encrypts a given source file into a given destination file using the given password
        /// </summary>
        /// <param name="sourceFile"></param>
        /// <param name="destinationFile"></param>
        /// <param name="password"></param>
        public static void EncryptFile(string sourceFile, string destinationFile, string password)
        {
            byte[] buffer = new byte[BUFFERSIZE];
            long totalBytesRead = 0, lastTotalBytesRead = 0;
            long inputFileSize = new FileInfo(sourceFile).Length;

            //create salt for key derivation and iv for encryption
            byte[] iv = new byte[16];
            byte[] salt = new byte[16];
            using (RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                rngCryptoServiceProvider.GetBytes(iv);
                rngCryptoServiceProvider.GetBytes(salt);
            }

            //create AES and hmac keys
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, ITERATIONS, HashAlgorithmName.SHA512);
            byte[] key = rfc2898DeriveBytes.GetBytes(32);
            byte[] hmackey = rfc2898DeriveBytes.GetBytes(32);

            //compute HMAC of input file
            byte[] hmac = ComputeHMAC(sourceFile, hmackey);

            //create AES
            Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            Console.WriteLine("Encrypting {0} into {1}", sourceFile, destinationFile);

            using (FileStream inputFileStream = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
            using (FileStream outputFileStream = new FileStream(destinationFile, FileMode.CreateNew, FileAccess.Write))
            {
                //write "header" (iv, salt, and hmac)
                outputFileStream.Write(iv, 0, iv.Length);
                outputFileStream.Write(salt, 0, salt.Length);
                outputFileStream.Write(hmac, 0, hmac.Length);
                outputFileStream.Flush();

                //encrypt and write output file
                using (CryptoStream encryptStream = new CryptoStream(outputFileStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    DateTime nextUpdateTime = DateTime.Now.AddSeconds(1);

                    //write encrypted data
                    int readCount = 0, percentage = 0;
                    while ((readCount = inputFileStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        totalBytesRead += readCount;
                        encryptStream.Write(buffer, 0, readCount);
                        if (DateTime.Now >= nextUpdateTime)
                        {
                            nextUpdateTime = DateTime.Now.AddSeconds(1);
                            percentage = (int)(100f * totalBytesRead / inputFileSize);
                            Console.Write("\rProgress {0}% ({1})     ", percentage, FormatSpeedString(totalBytesRead - lastTotalBytesRead));
                            lastTotalBytesRead = totalBytesRead;
                            outputFileStream.Flush();
                        }
                    }
                    outputFileStream.Flush();

                    percentage = (int)(100f * totalBytesRead / inputFileSize);
                    Console.WriteLine("\rProgress {0}%                           ", percentage);
                }
            }
            Console.WriteLine("File successfully encrypted");
        }

        /// <summary>
        /// Decrypts a given source file into a given destination file using the given password
        /// </summary>
        /// <param name="sourceFile"></param>
        /// <param name="destinationFile"></param>
        /// <param name="password"></param>
        public static void DecryptFile(string sourceFile, string destinationFile, string password)
        {
            Console.WriteLine("Decrypting {0} into {1}", sourceFile, destinationFile);

            byte[] buffer = new byte[BUFFERSIZE];
            long totalBytesRead, lastTotalBytesRead = 0;

            long inputFileSize = new FileInfo(sourceFile).Length;
            byte[] hmac = new byte[64];
            byte[] hmackey;

            using (FileStream inputFileStream = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
            using (FileStream outputFileStream = new FileStream(destinationFile, FileMode.CreateNew, FileAccess.Write))
            {
                //read "header" (iv, salt, and hmac)
                byte[] iv = new byte[16];
                byte[] salt = new byte[16];
                int offset = 0, readCount = 0;
                while ((readCount = inputFileStream.Read(iv, offset, iv.Length - offset)) > 0)
                {
                    offset += readCount;
                }
                offset = 0;
                readCount = 0;
                while ((readCount = inputFileStream.Read(salt, offset, salt.Length - offset)) > 0)
                {
                    offset += readCount;
                }
                offset = 0;
                readCount = 0;
                while ((readCount = inputFileStream.Read(hmac, offset, hmac.Length - offset)) > 0)
                {
                    offset += readCount;
                }

                //create AES and hmac keys
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, ITERATIONS, HashAlgorithmName.SHA512);
                byte[] key = rfc2898DeriveBytes.GetBytes(32);
                hmackey = rfc2898DeriveBytes.GetBytes(32);

                //create AES
                Aes aes = Aes.Create();
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                //we already read the iv, the salt, and the HMAC
                totalBytesRead = iv.Length + salt.Length + hmac.Length;

                using (CryptoStream decryptStream = new CryptoStream(inputFileStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    DateTime nextUpdateTime = DateTime.Now.AddSeconds(1);

                    //write decrypted data
                    readCount = 0;
                    int percentage = 0;
                    while ((readCount = decryptStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        totalBytesRead += readCount;
                        outputFileStream.Write(buffer, 0, readCount);
                        if (DateTime.Now >= nextUpdateTime)
                        {
                            nextUpdateTime = DateTime.Now.AddSeconds(1);
                            percentage = (int)(100f * totalBytesRead / inputFileSize);
                            Console.Write("\rProgress {0}% ({1})     ", percentage, FormatSpeedString(totalBytesRead - lastTotalBytesRead));
                            lastTotalBytesRead = totalBytesRead;
                            outputFileStream.Flush();
                        }
                    }
                    outputFileStream.Flush();

                    percentage = (int)(100f * totalBytesRead / inputFileSize);
                    Console.WriteLine("\rProgress {0}%                           ", percentage);
                }
            }
            Console.WriteLine("File successfully decrypted");

            //compute HMAC of output file
            byte[] hmac2 = ComputeHMAC(destinationFile, hmackey);

            //compare HMACs            
            if (ArrayEquals(hmac, hmac2))
            {
                Console.WriteLine("HMAC is valid. File was not manipulated");
            }
            else
            {
                Console.WriteLine("HMAC is invalid. File was probably manipulated");
            }
        }

        /// <summary>
        /// Computes an HMAC of the file using the given hmackey
        /// </summary>
        /// <param name="file"></param>
        /// <param name="hmackey"></param>
        /// <returns></returns>
        private static byte[] ComputeHMAC(string file, byte[] hmackey)
        {
            Console.WriteLine("Computing hmac of {0}", file);
            byte[] hmac; //HMACSHA512 is 64 bytes
            using (HMACSHA512 hMACSHA = new HMACSHA512(hmackey))
            {
                using (FileStream inputFileStream = new FileStream(file, FileMode.Open, FileAccess.Read))
                {
                    hmac = hMACSHA.ComputeHash(inputFileStream);
                }
            }
            Console.WriteLine("Computing hmac finished");
            return hmac;
        }

        /// <summary>
        /// Compares, if two given byte arrays are equal
        /// </summary>
        /// <param name="array1"></param>
        /// <param name="array2"></param>
        /// <returns></returns>
        public static bool ArrayEquals(byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length)
            {
                return false;
            }
            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i])
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Returns a formatted speed string based on byte/sec
        /// Shows speed in GB/sec, MB/sec, KB/sec, and byte/sec
        /// </summary>
        /// <param name="bytePerSecond"></param>
        /// <returns></returns>
        public static string FormatSpeedString(long bytePerSecond)
        {
            if (bytePerSecond > (1024 * 1024 * 1024)) //GiB / sec
            {
                return Math.Round(bytePerSecond / (1024 * 1024 * 1024.0), 2) + " GB/sec";
            }
            if (bytePerSecond > (1024 * 1024))
            {
                return Math.Round(bytePerSecond / (1024 * 1024.0), 2) + " MB/sec";
            }
            if (bytePerSecond > 1024)
            {
                return Math.Round(bytePerSecond / 1024.0, 2) + " KB/sec";
            }
            return bytePerSecond + " byte/sec";
        }
    }
}