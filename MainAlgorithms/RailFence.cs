using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            RailFence obj = new RailFence();
            int keyF = 0;
            for (int key = 1; key < 4; key++)
            {
                string plaint = obj.Decrypt(cipherText, key);
                if (plaint == plainText)
                {
                    keyF = key;
                }
            }
            return keyF;
        }

        public string Decrypt(string cipherText, int key)
        {
            StringBuilder cipherTextF = new StringBuilder(cipherText.ToLower());
            double c1 = Convert.ToDouble(cipherTextF.Length) / key;
            double c2 = Math.Ceiling(c1);
            int col = Convert.ToInt32(c2);
            char[,] matrix = new char[key, col];
            if (cipherTextF.Length % key != 0)
            {
                for (int i = col + (col - 1); i < cipherTextF.Length + (key - 1); i += col)
                {
                    cipherTextF = cipherTextF.Insert(i, ' ');
                }
            }
            int k = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    matrix[i, j] = cipherTextF[k];
                    k++;
                }
            }
            string PT = "";
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    PT += matrix[j, i];
                }
            }
            StringBuilder p = new StringBuilder(PT);
            for (int j = 0; j < (key - 1); j++)
            {
                for (int i = 0; i < p.Length; i++)
                {
                    if (p[i] == ' ')
                        p.Remove(i, 1);
                }
            }
            string plainTF = p.ToString();
            return plainTF;
        }

        public string Encrypt(string plainText, int key)
        {
            StringBuilder plainTextF = new StringBuilder(plainText.ToLower());
            double c1 = Convert.ToDouble(plainTextF.Length) / key;
            double c2 = Math.Ceiling(c1);
            int col = Convert.ToInt32(c2);
            char[,] matrix = new char[key, col];
            if (plainTextF.Length % key != 0)
            {
                for (int i = 0; i < (key - 1); i++)
                {
                    plainTextF = plainTextF.Append(' ');
                }
            }
            int k = 0;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    matrix[j, i] = plainTextF[k];
                    k++;
                }
            }
            string CT = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    CT += matrix[i, j];
                }
            }
            StringBuilder c = new StringBuilder(CT);
            for (int j = 0; j < (key - 1); j++)
            {
                for (int i = 0; i < c.Length; i++)
                {
                    if (c[i] == ' ')
                        c.Remove(i, 1);
                }
            }
            string ciperTF = c.ToString();
            return ciperTF;
        }
    }
}