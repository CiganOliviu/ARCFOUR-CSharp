using System;
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