using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public char[] arr = new char[26] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };

        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            string plainText2 = plainText.ToUpper();
            string cipherText2 = cipherText.ToUpper();

            for (int i = 0; i < plainText2.Length; i++)
            {
                int keyIndex = (Array.IndexOf(arr, cipherText2[i]) - Array.IndexOf(arr, plainText2[i])) % 26;
                if (keyIndex < 0)
                {
                    keyIndex += 26;
                }
                key += arr[keyIndex];
            }
            String str = "";
            for (int i = 0; i < key.Length; i++)
            {
                str += key[i];
                if (str.Equals(key.Substring(i + 1, str.Length))) break;
            }
            return str.ToLower();
        }


        public string Decrypt(string cipherText, string key)
        {

            int keyIndex = 0;

            string output = string.Concat(cipherText.Select(c =>
            {
                int plainIndex = char.ToUpper(c) - 'A';
                int keyChar = char.ToUpper(key[keyIndex++ % key.Length]) - 'A';
                int encryptedIndex = (plainIndex - keyChar) % 26;
                if (encryptedIndex < 0)
                {
                    encryptedIndex += 26;
                }
                return arr[encryptedIndex];
            }));

            return output;
        }

        public string Encrypt(string plainText, string key)
        {
            int keyIndex = 0;

            string output = string.Concat(plainText.Select(c =>
            {
                int plainIndex = char.ToUpper(c) - 'A';
                int keyChar = char.ToUpper(key[keyIndex++ % key.Length]) - 'A';
                int encryptedIndex = (plainIndex + keyChar) % 26;
                return arr[encryptedIndex];
            }));

            return output;
        }
    }
}

