using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Xml;

/*
 * This tool makes your data unreadable, so you can protect your files (e.g. images, videos) from watching it.
 * 
 * ----------------
 * MAP.XML EXAMPLE:
 * 
 * <map
 *  jpg = "wer"
 *  png = "cvf"
 * />
 * 
 * ----------------
 * TODO:
 *  - Decryption
 *  - Reading settings.xml
 */
namespace Corapter
{
    class Program
    {
        static void Main(string[] args)
        {
            const string ENC_KEY = "SF45 BGRG4M6V";

            var formatMap = new Dictionary<string, string>();
            var invertedFormatMap = new Dictionary<string, string>();
            invertedFormatMap.Add(".crp", ".ini");

            string path = string.Empty;

            if (File.Exists("settings.xml"))
            {
                // TODO
            }

            else
            {
                Console.WriteLine("settings.xml not found. Enter directory path for corrupting: ");
                path = Console.ReadLine();

                if(!Directory.Exists(path))
                {
                    Console.WriteLine("Path is not valid or does not exist!");
                    Console.ReadLine();
                    return;
                }
            }


            // FIND MAP FILE AND DO STUFF WITH DATA
            if (File.Exists(path + "\\map.xml"))
            {
                formatMap = ReadMap(path + "\\map.xml", false);
                foreach (string filePath in Directory.GetFiles(path))
                {
                    var ext = Path.GetExtension(filePath);
                    if (!formatMap.ContainsKey(ext))
                        continue;

                    EncryptFile(filePath);
                    ChangeFileExt(filePath, formatMap[ext]);
                }

                Console.WriteLine("Encryption done.");
                Console.ReadLine();
                return;
            }

            if (File.Exists(path + "\\map.repl"))
            {
                Console.WriteLine("Decryption done.");
                Console.ReadLine();
                return;
            }

            Console.WriteLine("Map file not found!");
            Console.ReadLine();
        }





        private static Dictionary<string, string> ReadMap(string path, bool isInverted)
        {
            var map = new Dictionary<string, string>();
            if (!isInverted)
            {
                map.Add(".xml", ".repl");
            }

            else
            {
                map.Add(".repl", ".xml");
            }

            XmlReader xmlReader = XmlReader.Create(path);
            while (xmlReader.MoveToNextAttribute() || xmlReader.Read())
            {
                Console.WriteLine(xmlReader.NodeType.ToString());
                if ((xmlReader.NodeType == XmlNodeType.Attribute))
                {
                    var ext = xmlReader.Name;
                    var repl = xmlReader.Value;
                    if (!isInverted)
                    {
                        map.Add($".{ext}", $".{repl}");
                    }

                    else
                    {
                        map.Add($".{repl}", $".{ext}");
                    }
                }
            }
            xmlReader.Close();
            xmlReader.Dispose();

            return map;
        }

        private static void ChangeFileExt(string path, string newExt)
        {
            var oldExt = Path.GetExtension(path);
            var newFilePath = path.Replace(oldExt, newExt);
            File.Move(path, newFilePath);
        }

        static readonly string PasswordHash = "oii@gf@fgd";
        static readonly string SaltKey = "S@LT&KEY";
        static readonly string VIKey = "@1B2c3D4e5F6g7H8";

        private static string Encrypt(string plainText)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));

            byte[] cipherTextBytes;

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }

            return Convert.ToBase64String(cipherTextBytes);
        }

        private static string Decrypt(string encryptedText)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };

            var decryptor = symmetricKey.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));
            var memoryStream = new MemoryStream(cipherTextBytes);
            var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();

            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd("\0".ToCharArray());
        }

        private static void EncryptFile(string path)
        {
            var plainText = File.ReadAllText(path);
   
            var encryptedText = Encrypt(plainText);
            File.WriteAllText(path, encryptedText);
        }

        private static void DecryptFile(string path)
        {
            var encryptedText = File.ReadAllText(path);

            var plainText = Decrypt(encryptedText);
            File.WriteAllText(path, plainText);
        }
    }
}
