using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            var keyMap = new Dictionary<char, char>();
            for (int i = 0; i < plainText.Length; i++)
            {
                char plainChar = char.ToUpper(plainText[i]);
                char cipherChar = char.ToUpper(cipherText[i]);

                keyMap[plainChar] = cipherChar;

            }

            HashSet<char> distinctLetters = new HashSet<char>("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
            foreach (char c in cipherText.ToUpper())
            {
                distinctLetters.Remove(c);
            }

            string key = "";
            foreach (char c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            {
                key += keyMap.ContainsKey(c) ? keyMap[c] : (distinctLetters.Count > 0 ? distinctLetters.First() : c);
                if (keyMap.ContainsKey(c) || (distinctLetters.Count > 0))
                {
                    distinctLetters.Remove(key[key.Length - 1]);
                }
            }

            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string Key = key.ToUpper();
            if (key.Length != 26)
            {
                foreach (char c in Alphabet)
                {
                    if (!Key.Contains(c))
                    {
                        Key += c;
                    }
                }
            }
            string plainText = "";
            foreach (char c in cipherText)
            {
                int index = Key.IndexOf(char.ToUpper(c));
                plainText += char.IsLower(c) ? char.ToLower(Alphabet[index]) : Alphabet[index];
            }
            return plainText;

        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string Key = key.ToUpper();
            if (key.Length != 26)
            {
                foreach (char c in Alphabet)
                {
                    if (!Key.Contains(c))
                    {
                        Key += c;
                    }
                }
            }
            string cipherText = "";
            foreach (char c in plainText)
            {
                int index = Alphabet.IndexOf(char.ToUpper(c));
                cipherText += char.IsLower(c) ? char.ToLower(Key[index]) : Key[index];
            }
            return cipherText;
        }







        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	= 8.85%
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {
            string Topfrequencies = "ETAOINSRHLDCUMFPGWYBVKXJQZ";
            var frequencyMap = new Dictionary<char, int>();


            foreach (char c in cipher)
            {
                char upperC = char.ToUpper(c);
                if (char.IsLetter(upperC))
                {
                    if (frequencyMap.ContainsKey(upperC))
                    {
                        frequencyMap[upperC]++;
                    }
                    else
                    {
                        frequencyMap[upperC] = 1;
                    }
                }
            }


            var orderedCipher = frequencyMap.OrderByDescending(pair => pair.Value).ThenBy(pair => pair.Key).Select(pair => pair.Key);


            var map = new Dictionary<char, char>();
            int i = 0;
            foreach (char c in orderedCipher)
            {
                if (i < Topfrequencies.Length)
                {
                    map[c] = Topfrequencies[i];
                    i++;
                }
                else
                {
                    break;
                }
            }
            /*
          Console.WriteLine("\nOrdered Cipher");
          foreach (var elemnt in map)
            {
                Console.WriteLine($"{elemnt.Key}: {elemnt.Value}");
            }
            foreach (var pair in frequencyMap.OrderByDescending(x => x.Value))
            {
             Console.WriteLine($"Letter: {pair.Key}, Frequency: {pair.Value}");
            }
            int summation = frequencyMap.Sum(x => x.Value);
            Console.WriteLine($"Summation of frequencies: {summation}");

             
             Dictionary<char, double> percentages = new Dictionary<char, double>();
            foreach (char letter in new char[] { 'h', 'w', 'd', 'r', 'l', 'q', 'v', 'u', 'g', 'f', 'j' })
            {
                if (frequencyMap.ContainsKey(letter))
                {
                    double percentage = (double)map[letter] / summation * 100;
                    percentages[letter] = percentage;
                    Console.WriteLine($"Letter: {letter}, Frequency: {map[letter]}, Percentage: {percentage}%");
                }
            }
            */
            //Console.WriteLine("\nOrdered Cipher");
            //foreach (var elemnt in map)
            //{
            //    Console.WriteLine($"{elemnt.Key}: {elemnt.Value}");
            //}

            StringBuilder plainText = new StringBuilder();
            foreach (char c in cipher)
            {
                if (char.IsLetter(c))
                {
                    char swapped = map.ContainsKey(char.ToUpper(c)) ? map[char.ToUpper(c)] : c;
                    plainText.Append(char.IsUpper(c) ? char.ToLower(swapped) : swapped);
                }
                else
                {
                    plainText.Append(c);
                }
            }

            return plainText.ToString();

        }

    }
    }