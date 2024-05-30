using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int GetMultiplicativeInverse(int number, int baseN)
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
        public int PowerMod(int x, int exponent, int modulus)
        {
            long result = 1;
            long baseValue = x % modulus;

            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                {
                    result = (result * baseValue) % modulus;
                }

                baseValue = (baseValue * baseValue) % modulus;
                exponent /= 2;
            }

            return (int)result;
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            //int ejn = (p - 1) * (q - 1);
            //int d = GetMultiplicativeInverse(e, ejn);
            int C = PowerMod(M, e, n);
            return C;

        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int ejn = (p - 1) * (q - 1);
            int d = GetMultiplicativeInverse(e, ejn);
            int M = PowerMod(C, d, n);
            return M;
        }
    }
}
