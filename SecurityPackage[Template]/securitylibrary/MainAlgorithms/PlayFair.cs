using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Net.Security;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Process(string txt)
        {
            string ret = txt.ToLower().Replace('j', 'i');
            return ret;
        }

        public void MakeMat(string key, int[,] mat, Tuple<int, int>[] pos)
        {
            pos[(int)('j' - 'a')] = Tuple.Create(-1, -1);

            int i = 0, j = 0;
            for (int k = 0; k < key.Length + 26; k++)
            {
                int x;
                if (k >= key.Length)
                {
                    x = k - key.Length;
                }
                else
                {
                    x = (int)(key[k] - 'a');
                }
                if (pos[x] != null)
                {
                    continue;
                }
                mat[i, j] = x;
                pos[x] = Tuple.Create(i, j);
                j++;
                if (j == 5)
                {
                    i++;
                    j = 0;
                }
            }
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = Process(cipherText);
            key = Process(key);
            int[,] mat = new int[5, 5];
            Tuple<int, int>[] pos = new Tuple<int, int>[26];
            MakeMat(key, mat, pos);

            string Decrypted = "";
            for (int k = 0; k < cipherText.Length; k += 2)
            {
                int a = cipherText[k] - 'a';
                int b = cipherText[k + 1] - 'a';

                int r1 = pos[a].Item1, c1 = pos[a].Item2;
                int r2 = pos[b].Item1, c2 = pos[b].Item2;

                int ai, bi;
                if (r1 == r2)
                {
                    ai = mat[r1, (c1 - 1 + 5) % 5];
                    bi = mat[r2, (c2 - 1 + 5) % 5];
                }
                else if (c1 == c2)
                {
                    ai = mat[(r1 - 1 + 5) % 5, c1];
                    bi = mat[(r2 - 1 + 5) % 5, c2];
                }
                else
                {
                    ai = mat[r1, c2];
                    bi = mat[r2, c1];
                }
                Decrypted += (char)(ai + 'a');
                Decrypted += (char)(bi + 'a');
            }

            string ret = "";
            for (int i = 0; i < Decrypted.Length; i+=2)
            {
                if (Decrypted[i + 1] == 'x' && (i + 2 >= Decrypted.Length || Decrypted[i + 2] == Decrypted[i]))
                {
                    ret += Decrypted[i];
                }
                else
                {
                    ret += Decrypted[i];
                    ret += Decrypted[i + 1];
                }
            }
            return ret;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = Process(plainText);
            key = Process(key);
            int[,] mat = new int[5, 5];
            Tuple<int, int>[] pos = new Tuple<int, int>[26];
            MakeMat(key, mat, pos);

            string Encrypted = "";

            for (int k = 0; k < plainText.Length; k += 2)
            {
                int a = plainText[k] - 'a';
                int b;
                if (k >= plainText.Length-1)
                {
                    b = 'x' - 'a';
                }
                else
                {
                    b = plainText[k + 1] - 'a';
                    if (a == b)
                    {
                        b = 'x' - 'a';
                        k -= 1;
                    }
                }

                int r1 = pos[a].Item1, c1 = pos[a].Item2;
                int r2 = pos[b].Item1, c2 = pos[b].Item2;

                int ai, bi;
                if (r1 == r2)
                {
                    ai = mat[r1, (c1 + 1) % 5];
                    bi = mat[r2, (c2 + 1) % 5];
                }
                else if (c1 == c2)
                {
                    ai = mat[(r1 + 1) % 5, c1];
                    bi = mat[(r2 + 1) % 5, c2];

                }
                else
                {
                    ai = mat[r1, c2];
                    bi = mat[r2, c1];
                }
                Encrypted += (char)(ai + 'a');
                Encrypted += (char)(bi + 'a');
            }
            return Encrypted.ToUpper();
        }
    }
}