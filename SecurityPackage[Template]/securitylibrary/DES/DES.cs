using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        private static int[,] PC_1 = new int[8, 7] {
            { 57 , 49 , 41 , 33 , 25 , 17 , 9  },
            { 1  , 58 , 50 , 42 , 34 , 26 , 18 },
            { 10 , 2  , 59 , 51 , 43 , 35 , 27 },
            { 19 , 11 , 3  , 60 , 52 , 44 , 36 },
            { 63 , 55 , 47 , 39 , 31 , 23 , 15 },
            { 7  , 62 , 54 , 46 , 38 , 30 , 22 },
            { 14 , 6  , 61 , 53 , 45 , 37 , 29 },
            { 21 , 13 , 5  , 28 , 20 , 12 , 4 }};

        private static int[,] PC_2 = new int[8, 6] {
            { 14 , 17 , 11 , 24 , 1  ,  5  },
            { 3  , 28 , 15 , 6  , 21 , 10  },
            { 23 , 19 , 12 , 4  , 26 ,  8  },
            { 16 , 7  , 27 , 20 , 13 ,  2  },
            { 41 , 52 , 31 , 37 , 47 , 55  },
            { 30 , 40 , 51 , 45 , 33 , 48  },
            { 44 , 49 , 39 , 56 , 34 , 53  },
            { 46 , 42 , 50 , 36 , 29 , 32  } };

        private static int[,] IP = new int[8, 8] {
            { 58, 50, 42, 34, 26, 18, 10, 2 },
            { 60, 52, 44, 36, 28, 20, 12, 4 },
            { 62, 54, 46, 38, 30, 22, 14, 6 },
            { 64, 56, 48, 40, 32, 24, 16, 8 },
            { 57, 49, 41, 33, 25, 17, 9 , 1 },
            { 59, 51, 43, 35, 27, 19, 11, 3 },
            { 61, 53, 45, 37, 29, 21, 13, 5 },
            { 63, 55, 47, 39, 31, 23, 15, 7 } };

        private static int[,] IP_1 = new int[8, 8] {
            { 40, 8, 48, 16, 56, 24, 64, 32 },
            { 39, 7, 47, 15, 55, 23, 63, 31 },
            { 38, 6, 46, 14, 54, 22, 62, 30 },
            { 37, 5, 45, 13, 53, 21, 61, 29 },
            { 36, 4, 44, 12, 52, 20, 60, 28 },
            { 35, 3, 43, 11, 51, 19, 59, 27 },
            { 34, 2, 42, 10, 50, 18, 58, 26 },
            { 33, 1, 41, 9, 49, 17, 57, 25 } };

        private static int[,,] s = new int[8, 4, 16] {
            { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
            { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
            { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
            { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
            { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
            { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
            { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
            { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } }
        };

        private static int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

        private static int[,] EBit = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

        public override string Decrypt(string cipherText, string key)
        {
            string ciphertextBinary = ToBinray(cipherText), keyBinary = ToBinray(key);
            string key56 = Permutation(keyBinary, PC_1);

            //divide key to c and d
            string c = key56.Substring(0, 28), d = key56.Substring(28, 28);
            List<string> cc = new List<string>(), dd = new List<string>();

            for (int round = 0; round <= 16; round++)
            {
                cc.Add(c);
                dd.Add(d);
                int shift = (round == 0 || round == 1 || round == 8 || round == 15) ? 1 : 2;
                c = c.Substring(shift) + c.Substring(0, shift);
                d = d.Substring(shift) + d.Substring(0, shift);
            }

            List<string> keyTotal = new List<string>();

            for (int i = 0; i < cc.Count; i++)
            {
                keyTotal.Add(cc[i] + dd[i]);
            }

            List<string> keys48 = GenerateKeys48(keyTotal);

            string ct64 = Permutation(ciphertextBinary, IP);
            string l = ct64.Substring(0, 32), r = ct64.Substring(32, 32);
            List<string> ll = new List<string>(), rr = new List<string>(), B = new List<string>();
            string rowno, colno, exor, er, qq, ress, f;
            int row, col;

            ll.Add(l);
            rr.Add(r);

            for (int i = 0; i < 16; i++)
            {
                ll.Add(r);
                ress = "";
                B.Clear();

                er = Permutation(r, EBit);

                exor = xor(keys48[keys48.Count - i - 1], er);

                int q = 0;
                while (q < exor.Length)
                {
                    qq = "";
                    int w = q;

                    while (w < exor.Length && w < q + 6)
                    {
                        qq += exor[w];
                        w++;
                    }

                    B.Add(qq);
                    q += 6;
                }

                // permutation by s1 to s8
                for (int a = 0; a < B.Count; a++)
                {
                    qq = B[a];
                    rowno = qq[0].ToString() + qq[5];
                    colno = qq[1].ToString() + qq[2] + qq[3] + qq[4];
                    row = Convert.ToInt32(rowno, 2);
                    col = Convert.ToInt32(colno, 2);

                    ress += Convert.ToString(s[a, row, col], 2).PadLeft(4, '0');
                }

                f = Permutation(ress, P);
                r = xor(f, l); //ln-1 xor f(r0,k)
                l = ll[i + 1];
                rr.Add(r);
            }

            return ToString(Permutation(rr[16] + ll[16], IP_1));
        }

        public override string Encrypt(string plainText, string key)
        {
            string plaintextBinary = ToBinray(plainText), keyBinary = ToBinray(key);
            string key56 = Permutation(keyBinary, PC_1);

            //divide key to c and d
            string c = key56.Substring(0, 28), d = key56.Substring(28, 28);
            List<string> cc = new List<string>(), dd = new List<string>();

            for (int round = 0; round <= 16; round++)
            {
                cc.Add(c);
                dd.Add(d);
                int shift = (round == 0 || round == 1 || round == 8 || round == 15) ? 1 : 2;
                c = c.Substring(shift) + c.Substring(0, shift);
                d = d.Substring(shift) + d.Substring(0, shift);
            }

            List<string> keyTotal = new List<string>();

            for (int i = 0; i < cc.Count; i++)
            {
                keyTotal.Add(cc[i] + dd[i]);
            }

            List<string> keys48 = GenerateKeys48(keyTotal);

            string pt64 = Permutation(plaintextBinary, IP);
            string l = pt64.Substring(0, 32), r = pt64.Substring(32, 32);
            List<string> ll = new List<string>(), rr = new List<string>(), B = new List<string>();
            string rowno, colno, exor, er, qq, ress, f;
            int row, col;

            ll.Add(l);
            rr.Add(r);

            for (int i = 0; i < 16; i++)
            {
                ll.Add(r);
                ress = "";
                B.Clear();

                er = Permutation(r, EBit);

                exor = xor(keys48[i], er);

                int q = 0;
                while (q < exor.Length)
                {
                    qq = "";
                    int w = q;

                    while (w < exor.Length && w < q + 6)
                    {
                        qq += exor[w];
                        w++;
                    }

                    B.Add(qq);
                    q += 6;
                }

                // permutation by s1 to s8
                for (int a = 0; a < B.Count; a++)
                {
                    qq = B[a];
                    rowno = qq[0].ToString() + qq[5];
                    colno = qq[1].ToString() + qq[2] + qq[3] + qq[4];
                    row = Convert.ToInt32(rowno, 2);
                    col = Convert.ToInt32(colno, 2);

                    ress += Convert.ToString(s[a, row, col], 2).PadLeft(4, '0');
                }

                f = Permutation(ress, P);
                r = xor(f, l); //ln-1 xor f(r0,k)
                l = ll[i + 1];
                rr.Add(r);
            }

            return ToString(Permutation(rr[16] + ll[16], IP_1));
        }

        private string ToBinray(string text)
        {
            return Convert.ToString(Convert.ToInt64(text, 16), 2).PadLeft(64, '0');
        }

        private string ToString(string binary)
        {
            return "0x" + Convert.ToInt64(binary, 2).ToString("X").PadLeft(16, '0');
        }

        private string Permutation(string binary, int[,] subtitutionArray)
        {
            string result = string.Empty;

            for (int rowIndex = 0; rowIndex < subtitutionArray.GetLength(0); rowIndex++)
            {
                for (int colIndex = 0; colIndex < subtitutionArray.GetLength(1); colIndex++)
                {
                    result += binary[subtitutionArray[rowIndex, colIndex] - 1];
                }
            }

            return result;
        }

        private string xor(string str1, string str2)
        {
            string result = "";

            for (int index = 0; index < str1.Length; index++)
            {
                result += (str1[index] ^ str2[index]).ToString();
            }

            return result;
        }

        private List<string> GenerateKeys48(List<string> KeyTotal)
        {
            List<string> keys48 = new List<string>();

            for (int index = 1; index < KeyTotal.Count; index++)
            {
                keys48.Add(Permutation(KeyTotal[index], PC_2));
            }

            return keys48;
        }
    }
}
