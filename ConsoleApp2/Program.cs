using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp2
{
    internal class Program
    {
        static void Main ()
        {
            Console.WriteLine("Введите текст");
            string content = Console.ReadLine();
            Console.WriteLine("Введите ключ");
            string password = Console.ReadLine();

            string cryptContent = Protector.Encrypt(content, password);

            Console.WriteLine($"Шифрованный текст: \n {cryptContent}");

            Console.WriteLine($"Расшифрованный текст: \n { Protector.Decrypt (cryptContent, password) } " );
        }
    }

    public static class Protector
    {
        private static readonly byte[] salt = Encoding.Unicode.GetBytes("7BANANAS");
        private static readonly int iterations = 2000;
        private static object ms;

        public static string Encrypt(string plainText, string password)
        {
            byte[] encryptedBytes;
            byte[] plainBytes = Encoding.Unicode.GetBytes(plainText);
            var aes = Aes.Create();
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);

            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plainBytes, 0, plainBytes.Length);
                }
                encryptedBytes = ms.ToArray();
            }
            return Convert.ToBase64String(encryptedBytes);
        }
        
        public static string Decrypt(string cryptoText, string password)
        {
            byte[] plainBytes;
            byte[] cryptoBytes = Convert.FromBase64String(cryptoText);
            var aes = Aes.Create();
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);

            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write)) 
                {
                    cs.Write (cryptoBytes, 0, cryptoBytes.Length);
                }
                plainBytes = ms.ToArray();
            }
           
            return Encoding.Unicode.GetString(plainBytes);
        }
    }
}
