using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {

            int c1 = 1;
            for (int i = 0; i < k; i++)
            {
                c1 *= alpha;
                c1 %= q;
            }

            int K = 1;
            for (int i = 0; i < k; i++)
            {
                K *= y;
                K %= q;
            }
            int c2 = (K * m) % q;
            List<long> list = new List<long>();
            list.Add(c1);
            list.Add(c2);
            return list;

        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = 1;
            for (int i = 0; i < x; i++)
            {
                K *= c1;
                K %= q;
            }
            int K2 = 1;
            for (int i = 0; i < (q - 1 - x); i++)
            {
                K2 *= c1;
                K2 %= q;
            }
            int m = (c2 * K2) % q;
            return m;

        }
    }
}
