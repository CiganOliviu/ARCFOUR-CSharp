/*
MIT License

Copyright (c) 2020 Cigan Oliviu David

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

﻿using System;
using System.Text;
using System.Security.Cryptography;

namespace ARCFOUR
{
    class Program
    {
        class EncryptorDecryptorEngine
        {
            private static string IV = "IV_VALUE_16_BYTE";
            private static string PASSWORD = "PASSWORD_VALUE";
            private static string SALT = "SALT_VALUE";

            public static string EncryptData(string RawData)
            {
                using (var CSP = new AesCryptoServiceProvider())
                {
                    ICryptoTransform e = GetCryptoTransform(CSP, true);

                    byte[] inputBuffer = Encoding.UTF8.GetBytes(RawData);
                    byte[] output = e.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
                    string encrypted = Convert.ToBase64String(output);

                    return encrypted;
                }
            }

            public static string DecryptData(string encryptedData)
            {
                using (var CSP = new AesCryptoServiceProvider())
                {
                    var Data = GetCryptoTransform(CSP, false);

                    byte[] output = Convert.FromBase64String(encryptedData);
                    byte[] decryptedOutput = Data.TransformFinalBlock(output, 0, output.Length);
                    string decypted = Encoding.UTF8.GetString(decryptedOutput);

                    return decypted;
                }
            }

            private static ICryptoTransform GetCryptoTransform(AesCryptoServiceProvider CSP, bool encrypting)
            {
                CSP.Mode = CipherMode.CBC;
                CSP.Padding = PaddingMode.PKCS7;
                var spec = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(PASSWORD), Encoding.UTF8.GetBytes(SALT), 65536);
                byte[] key = spec.GetBytes(16);


                CSP.IV = Encoding.UTF8.GetBytes(IV);
                CSP.Key = key;

                if (encrypting)
                {
                    return CSP.CreateEncryptor();
                }

                return CSP.CreateDecryptor();
            }
        }

        public static void Main(string[] args)
        {
            string RawData;
            string EncryptedData;
            string DecryptedData;

            RawData = Console.ReadLine();

            Console.WriteLine("Data = " + RawData);

            EncryptedData = EncryptorDecryptorEngine.EncryptData(RawData);
            Console.WriteLine("encypted: " + EncryptedData);

            DecryptedData = EncryptorDecryptorEngine.DecryptData(EncryptedData);
            Console.WriteLine("decrypted: " + DecryptedData);

            Console.ReadKey();
        }
    }
}
