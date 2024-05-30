using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {


        public List<int> Analyse(string plainText, string cipherText)
        {

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int cols = 0;

            List<int> key = new List<int>();

            int r = 0;
            int c = 0;
            char[,] matrix = new char[0, 0];

            for (int i = 2; i < 100; i++)
            {
                r = i;
                c = plainText.Length / r;

                if (plainText.Length % r != 0)
                {
                    c += 1;
                }
                matrix = build_table(plainText, r);

                if (col_in_matrix(matrix, cipherText))
                {
                    break;
                }
            }

            for (int j = 0; j < c; j++)
            {
                var col = new StringBuilder();

                for (int i = 0; i < r; i++)
                {
                    if (matrix[i, j] != ' ')
                    {
                        col.Append(matrix[i, j]);
                    }
                }

                key.Add(cipherText.IndexOf(col.ToString()) / r + 1);
            }

            return key;
        }


        char[,] build_table(string p_text, int cols)
        {
            int c = cols;
            int rs = p_text.Length / c;
            if (p_text.Length % c != 0)
            {
                rs += 1;
            }

            char[,] g = new char[c, rs];

            int row = 0;
            int col = 0;

            for (int i = 0; i < p_text.Length; i++)
            {
                g[row, col] = p_text[i];

                col++;
                if (col == rs)
                {
                    row++;
                    col = 0;
                }
            }

            return g;
        }


        bool col_in_matrix(char[,] matrix, string cipher)
        {
            int cols = matrix.GetLength(0);
            int rows = matrix.GetLength(1);

            for (int j = 0; j < rows; j++)
            {
                var col = new StringBuilder();

                for (int i = 0; i < cols; i++)
                {
                    /*
                    if (matrix[i, j] != ' ')
                    {
                        col.Append(matrix[i, j]);
                    }
                    */
                    //not null

                    if (matrix[i, j] != '\0')
                    {
                        col.Append(matrix[i, j]);
                    }
                }

                if (!cipher.Contains(col.ToString()))
                {
                    return false;
                }
            }

            return true;
        }

        public List<List<int>> get_all_perms(int cols)
        {
            int[] ks = new int[cols];

            for (int i = 0; i < cols; ++i)
                ks[i] = i + 1;

            List<List<int>> perms = new List<List<int>>();

            return this.perms(ks, 0, ks.Length - 1, perms);
        }

        public List<List<int>> perms(int[] ks, int s_i, int ei, List<List<int>> perms)
        {
            if (s_i == ei)
                perms.Add(new List<int>(ks));
            else
            {
                for (int i = s_i; i <= ei; ++i)
                {
                    if (i % s_i == 0)
                    {
                        i += 2;
                    }
                    this.perms(ks, s_i + 1, ei, perms);
                }
            }

            return perms;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int c = key.Count;
            int length = cipherText.Length;
            int r = length / c;
            if (length % c != 0)
            {
                r += 1;
            }

            char[,] g = new char[r, c];
            int i = 0;
            int j = 0;

            for (int n = 0; n < cipherText.Length; n++)
            {
                g[i, j] = cipherText[n];
                i++;
                if (i == r)
                {
                    i = 0;
                    j++;
                }
            }
            char[,] l = new char[r, c];

            for (int cc = 0; cc < c; cc++)
            {
                for (int rr = 0; rr < r; rr++)
                {
                    l[rr, cc] = g[rr, key[cc] - 1];
                }
            }


            var plain = new StringBuilder();

            for (int it = 0; it < r; it++)
            {
                for (int m = 0; m < c; m++)
                {
                    plain.Append(l[it, m]);
                }
            }




            return plain.ToString();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int c = key.Count;
            int lengh = plainText.Length;
            int r = lengh / c;

            if (lengh % c != 0)
            {
                r += 1;

            }

            char[,] g = new char[r, c];
            int i = 0;
            int j = 0;

            for (int x = 0; x < plainText.Length; x++)
            {
                g[i, j] = plainText[x];

                j++;
                if (j == c)
                {
                    j = 0;
                    i++;

                }
            }
            var dec = new StringBuilder();

            for (int it = 0; it < key.Count(); it++)
            {
                for (int m = 0; m < r; m++)
                {
                    dec.Append(g[m, key.IndexOf(it + 1)]);
                }
            }



            return dec.ToString();

        }


    }
}
