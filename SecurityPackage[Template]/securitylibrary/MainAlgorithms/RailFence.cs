using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            //string plain = "meetmeaftertheparty";
            //string cipher = "mematrhpryetefeteat";
            string ciphertext = cipherText.ToLower();
            Dictionary<char, int> charIndexMap = new Dictionary<char, int>();

            for (int i = 0; i < Math.Min(ciphertext.Length, 10); i++)
            {
                charIndexMap[ciphertext[i]] = plainText.IndexOf(ciphertext[i]);
            }

            //List<char> keys = new List<char>(charIndexMap.Keys);
            List<int> valueDifferences = new List<int>(charIndexMap.Values);


            List<int> differences = new List<int>();
            for (int i = 0; i < valueDifferences.Count - 1; i++)
            {
                int diff = valueDifferences[i + 1] - valueDifferences[i];
                differences.Add(diff);
            }

            // Find the most common number in differences
            int mostCommonNumber = differences
                .GroupBy(x => x)
                .OrderByDescending(g => g.Count())
                .First()
                .Key;

            return mostCommonNumber;

        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            /*
            StringBuilder plainTextBuilder = new StringBuilder(cipherText.Length);

            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < cipherText.Length; j += key)
                {
                    plainTextBuilder.Append(cipherText[j]);
                }
            }

            string plainText = plainTextBuilder.ToString();
            return plainText.ToLower();
            */

            int numRows = cipherText.Length / key;
            if (cipherText.Length % key != 0)
            {
                numRows++;
            }

            char[,] grid = new char[numRows, key];
            int index = 0;

            for (int j = 0; j < key; j++)
            {
                for (int i = 0; i < numRows; i++)
                {
                    if (index < cipherText.Length)
                    {
                        grid[i, j] = cipherText[index];
                        index++;
                    }
                }
            }

            StringBuilder plainTextBuilder = new StringBuilder();
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (grid[i, j] != '\0')
                    {
                        plainTextBuilder.Append(grid[i, j]);
                    }
                }
            }

            string plainText = plainTextBuilder.ToString();
            return plainText.ToLower();


        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            //int length = plainText.Length / key;
            string[] cipherTextParts = new string[key];

            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < plainText.Length; j += key)
                {
                    cipherTextParts[i] += plainText[j];
                }
            }

            string cipherText = string.Concat(cipherTextParts);
            return cipherText.ToUpper();
        }

    }
}
