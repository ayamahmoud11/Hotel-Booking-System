using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        private int GCD(int a, int b)
        {
            if (b == 0)
                return a;

            return GCD(b, a % b);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
            int gcd = GCD(number, baseN);
            if (gcd != 1)
            {
                return -1;
            }
            if (number > baseN)
            {
                int m0 = baseN;
                int y = 0, x = 1;

                if (baseN == 1)
                    return 0;

                while (number > 1)
                {
                    int q = number / baseN;

                    int t = baseN;

                    baseN = number % baseN;
                    number = t;
                    t = y;

                    y = x - q * y;
                    x = t;
                }
                if (x < 0)
                    x += m0;

                return x;
            }
            else
            {
                int Sub = baseN - number;
                bool found = false;
                int res = -1;
                for (int n = 0; n <= baseN && !found; n++)
                {
                    double c = ((baseN + 1) + baseN * n) / (double)Sub;
                    if (c % 1 == 0)
                    {
                        res = baseN - (int)c;
                        found = true;
                    }
                }
                return res;
            }
        }
    }
}
