using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        private int GCD(int a, int b)
        {
            if (b == 0)
                return a;

            return GCD(b, a % b);
        }
        private int CalcDet(int s, List<int> l)
        {
            if (s == 1)
            {
                return l[0];
            }
            if (s == 2)
            {
                return l[0] * l[3] - l[1] * l[2];
            }
            else
            {
                int res = 0;
                for (int c = 0; c < s; c++)
                {
                    int subDet = 0;
                    List<int> subList = new List<int>();
                    for (int i = s; i < l.Count; i++)
                    {
                        if (i % s == c)
                        {
                            continue;
                        }
                        subList.Add(l[i]);
                    }
                    int sign = 1;
                    if (c % 2 == 1)
                    {
                        sign = -1;
                    }
                    res += sign * l[c] * CalcDet(s - 1, subList);
                }
                return res;
            }
        }
        private int CalCmod(int N)
        {
            int Mod = N % 26;

            if (Mod < 0) Mod += 26; 
            return Mod;
        }
        private List<int> MakeMatrix(int size, List<int> matrix)
        {
            List<int> mar = Enumerable.Repeat(0, matrix.Count).ToList();

            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    mar[j * size + i] = matrix[i * size + j];
                }
            }

            return mar;
        }
        private List<int> MultiplyMatrices(List<int> matrix1, List<int> matrix2)
        {
          
            int matrixSize = (int)Math.Sqrt(matrix1.Count);
            List<int> res = Enumerable.Repeat(0, matrix2.Count).ToList();
            for (int i = 0; i < matrixSize; i++)
            {
                for (int j = 0; j < matrixSize; j++)
                {
                    for (int k = 0; k < matrixSize; k++)
                    {
                        res[i * matrixSize + j] += matrix1[i * matrixSize + k] * matrix2[k * matrixSize + j];
                    }
                }
            }

            return res.Select(value => CalCmod(value)).ToList();
        }
        private List<int> getInverse(int s, List<int> l)
        {
            int detK = CalcDet(s, l);
            int b = -1;

            for (int i = 0; i < 26; i++)
            {
                if ((i * detK + 26 * 1000) % 26 == 1)
                {
                    b = i; break;
                }
            }

            foreach (int x in l)
            {
                if (x<0 || x>26) throw new NotImplementedException();
            }
            if (detK == 0 || GCD(Math.Abs(detK), 26) != 1 || b == -1)
            {
                throw new NotImplementedException();
            }

            int[] InverseKey = new int[s * s];

            for (int i = 0; i < s; i++)
            {
                for (int j = 0; j < s; j++)
                {
                    List<int> subList = new List<int>();
                    for (int k = 0; k < s * s; k++)
                    {
                        if (k / s == i || k % s == j)
                        {
                            continue;
                        }
                        subList.Add(l[k]);
                    }
                    int sign = 1;
                    if ((i + j) % 2 == 1)
                    {
                        sign = -1;
                    }
                    InverseKey[i + j * s] = (sign * b * CalcDet(s - 1, subList) + 26 * 1000) % 26;
                }
            }

            return InverseKey.ToList();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = 1;
            while (m * m < key.Count)
            {
                m++;
            }
            while (key.Count < m * m)
            {
                key.Add(0);
            }
            while (plainText.Count % m != 0)
            {
                plainText.Add(0);
            }

            int[,] kMat = new int[m, m];
            int k = 0;
            for (int r = 0; r < m; r++)
            {
                for (int c = 0; c < m; c++, k++)
                {
                    kMat[r, c] = key[k];
                }
            }
            List<int> cipherText = new List<int>();
            for (int start = 0; start < plainText.Count; start += m)
            {
                for (int r = 0; r < m; r++)
                {
                    int res = 0;
                    for (int c = 0; c < m; c++)
                    {
                        res += (kMat[r, c] * plainText[start + c]) % 26;
                    }
                    res %= 26;
                    cipherText.Add(res);
                }
            }

            return cipherText;
        }
        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m = 1;
            while (m * m < key.Count)
            {
                m++;
            }

            return Encrypt(cipherText, getInverse(m, key));
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
           

            List<int> key = new List<int>();

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            key.Clear();
                            key.AddRange(new int[] { i, j, k, l });
                            List<int> decipheredText = Encrypt(plainText, key);
                            if (decipheredText.SequenceEqual(cipherText))
                            {
                                return key;
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
            // throw new NotImplementedException();
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
           List<int> plain= MakeMatrix(3,plain3);
           List<int> invplain = getInverse(3, plain);
            List<int> cipher= MakeMatrix(3, cipher3);
          List<int> res= MultiplyMatrices(cipher, invplain);


            return res;
            // throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }



    }
}

