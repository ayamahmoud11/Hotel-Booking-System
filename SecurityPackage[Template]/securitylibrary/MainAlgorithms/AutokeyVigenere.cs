using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
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
            String res = "";
            for (int i = 0; i < key.Length; i++)
            {
                String str = "";
                for (int j = i; j < key.Length; j++)
                {
                    str += key[j];
                }
                if (plainText2.Contains(str))
                {
                    break;
                }
                else
                {
                    res += key[i];
                }
            }

            return res.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            int keyIndex = 0;

            string output = string.Concat(cipherText.Select(c =>
            {
                int encryptedIndex = char.ToUpper(c) - 'A';
                int keyChar = char.ToUpper(key[keyIndex++ % key.Length]) - 'A';
                int plainIndex = (encryptedIndex - keyChar + 26) % 26;
                key += arr[plainIndex];
                return arr[plainIndex];
            }));

            return output;

        }

        public string Encrypt(string plainText, string key)
        {
            string autoKey = key + plainText;

            int keyIndex = 0;

            string output = string.Concat(plainText.Select(c =>
            {
                int plainIndex = char.ToUpper(c) - 'A';
                int keyChar = char.ToUpper(autoKey[keyIndex++ % autoKey.Length]) - 'A';
                int encryptedIndex = (plainIndex + keyChar) % 26;
                return arr[encryptedIndex];
            }));

            return output;


        }
    }
}

