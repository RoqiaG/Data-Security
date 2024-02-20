using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        private int ModPow(int baseValue, int exp, int modulus)
        {
            int result = 1;
            while (exp > 0)
            {
                if (exp % 2 == 1)
                {
                    result = (result * baseValue) % modulus;
                }
                baseValue = (baseValue * baseValue) % modulus;
                exp /= 2;
            }
            return result;
        }
            public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = ModPow(alpha, xa, q);
            int yb = ModPow(alpha, xb, q);

            // Calculate the shared secret keys
            int ka = ModPow(yb, xa, q);
            int kb = ModPow(ya, xb, q);

            // Return the keys as a list
            return new List<int> { ka, kb };
        }
    }
}