using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        char[] arr = new char[26] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
        public string Encrypt(string plainText, int key)
        {
            string output = new string(plainText.ToUpper().Select(c =>
            {
                    int index = Array.IndexOf(arr, c);
                   
                        int eIndex = (index + key) % 26;
                        return arr[eIndex];
            }).ToArray());

            return output;

        }

        public string Decrypt(string cipherText, int key)
        {
            string output = new string(cipherText.ToUpper().Select(c =>
            {
                int index = Array.IndexOf(arr, c);

                int dIndex = (index - key + 26) % 26;
                return arr[dIndex];
            }).ToArray());

            return output;

        }

        public int Analyse(string plainText, string cipherText)
        {
            return Enumerable.Range(0, 26)
         .FirstOrDefault(key => Decrypt(cipherText, key).Equals(plainText, StringComparison.InvariantCultureIgnoreCase));
        }
    }
    
}