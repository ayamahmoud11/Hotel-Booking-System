using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{


    public class DiffieHellman
    {

        public int power(int f, int s, int sf)
        {
            int r = 1;
            for (int i = 0; i < f; i++)
            {
                r *= s;
                r %= sf;
            }
            return r;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = power(xa, alpha, q);
            int yb = power(xb, alpha, q);

            int k = power(xa, yb, q);
            int k2 = power(xb, ya, q);
            List<int> keys = new List<int>();
            keys.Add(k);
            keys.Add(k2);
            return keys;
        }
    }
}