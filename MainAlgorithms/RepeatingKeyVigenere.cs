using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[,] matrix = new char[26, 26];
            int a;
            int k;
            StringBuilder f = new StringBuilder(cipherText.ToUpper());
            StringBuilder n = new StringBuilder(plainText.ToUpper());
            string l = "";
            char x = 'A';
            char y = ' ';
            for (int i = 0; i < 26; i++)
            {
                y = x;
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = y;
                    a = Convert.ToInt32(y);
                    a++;
                    y = Convert.ToChar(a);
                    if (y > 'Z') { y = 'A'; }
                }
                a = Convert.ToInt32(x);
                a++;
                x = Convert.ToChar(a);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    int column = Convert.ToInt32(n[i]) - 65;
                    if (matrix[j, column] == f[i])

                    {

                        k = j;
                        k += 65;
                        l += Convert.ToChar(k);

                    }
                }

            }

            string pattern = "";
            for (int length = 1; length <= l.Length / 2; length++)
            {
                pattern = l.Substring(0, length);
                bool flag = true;

                for (int i = 0; i < l.Length; i++)
                {
                    if (!l[i].Equals(pattern[i % pattern.Length]))
                    {
                        flag = false;
                    }
                }
                if (flag == true)
                {
                    return pattern;
                }
            }
            return pattern;
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] matrix = new char[26, 26];
            StringBuilder f = new StringBuilder(cipherText.ToUpper());
            StringBuilder pkey = new StringBuilder(key.ToUpper());


            char x = 'A';
            char y = ' ';
            int a;
            int k;
            string l = "";
            for (int i = 0; i < 26; i++)
            {
                y = x;
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = y;
                    a = Convert.ToInt32(y);
                    a++;
                    y = Convert.ToChar(a);
                    if (y > 'Z') { y = 'A'; }
                }
                a = Convert.ToInt32(x);
                a++;
                x = Convert.ToChar(a);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    int row = Convert.ToInt32(pkey[i]) - 65;
                    if (matrix[row, j] == f[i])
                    {

                        k = j;
                        k += 65;
                        l += Convert.ToChar(k);
                        //   Console.WriteLine(l);

                        //   break;
                    }
                }

                if (f.Length > pkey.Length)
                {
                    pkey.Append(pkey[i]);

                }

            }

            return l;
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] matrix = new char[26, 26];
            StringBuilder f = new StringBuilder(plainText.ToUpper());
            StringBuilder pkey = new StringBuilder(key.ToUpper());

            char x = 'A';
            char y = ' ';
            int a;
            for (int i = 0; i < 26; i++)
            {
                y = x;
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = y;
                    a = Convert.ToInt32(y);
                    a++;
                    y = Convert.ToChar(a);
                    if (y > 'Z') { y = 'A'; }
                }
                a = Convert.ToInt32(x);
                a++;
                x = Convert.ToChar(a);
            }
            for (int i = 0; i < f.Length - key.Length; i++)
            {
                if (f.Length > key.Length)
                {
                    pkey.Append(pkey[i]);

                }

            }
            StringBuilder l = new StringBuilder();
            for (int i = 0; i < pkey.Length; i++)
            {
                int row = Convert.ToInt32(pkey[i]) - 65;
                int column = Convert.ToInt32(f[i]) - 65;
                l.Append(matrix[row, column]);
            }
            string r = Convert.ToString(l);

            return r;
        }
    }
}