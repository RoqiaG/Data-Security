using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            int csize = (int)Math.Sqrt(cipherText.Count());
            int CTrows;
            int pTrows;
            if (cipherText.Count() % csize == 0 && plainText.Count() % csize == 0)
            {
                CTrows = cipherText.Count() / csize;
                pTrows = plainText.Count() / csize;
            }
            else
            {
                CTrows = (cipherText.Count() / csize) + 1;
                pTrows = (plainText.Count() / csize) + 1;
            }

            int[,] CipherMatrix = new int[CTrows, CTrows];
            int[,] plainMatrix = new int[pTrows, pTrows];
            //int[,] KeyMatrix = new int[ksize, ksize];
            List<int> key = new List<int>();
            for (int a = 0; a < 26; a++)
            {
                for (int b = 0; b < 26; b++)
                {
                    for (int c = 0; c < 26; c++)
                    {
                        for (int d = 0; d < 26; d++)
                        {
                            key = new List<int>(new[] { a, b, c, d });
                            List<int> newCipher = Encrypt(plainText, key);
                            if (newCipher.SequenceEqual(cipherText))
                            {
                                return key;

                            }

                        }
                    }
                }
            }
            if (cipherText.Count > 26 && plainText.Count > 26)
            {
                throw new Exception("cant find key");
            }
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            List<int> plain = new List<int>();
            //get the size
            int ksize = (int)Math.Sqrt(key.Count());
            int CTrows;
            if (cipherText.Count() % ksize == 0)
                CTrows = cipherText.Count() / ksize;
            else
                CTrows = (cipherText.Count() / ksize) + 1;

            //fill the martix key and cipher
            double[,] CipherMatrix = new double[CTrows, CTrows];
            double[,] KeyMatrix = new double[ksize, ksize];
            int k = 0;
            for (int i = 0; i < CTrows; i++)
            {
                for (int j = 0; j < ksize; j++)
                {
                    CipherMatrix[i, j] = cipherText[k];
                    k++;
                }
            }
            int l = 0;
            for (int i = 0; i < ksize; i++)
            {
                for (int j = 0; j < ksize; j++)
                {
                    if ((key[l] >= 0) && (key[l] < 26))
                    {
                        KeyMatrix[i, j] = key[l];
                        l++;
                    }

                }
            }
            //det for 2*2
            double det;
            if (ksize == 2)
            {
                det = (KeyMatrix[0, 0] * KeyMatrix[1, 1]) - (KeyMatrix[0, 1] * KeyMatrix[1, 0]);
               // det %= 26;
              
            }
            else
            {
               //det for 3*3
                det = KeyMatrix[0, 0] * ((KeyMatrix[1, 1] * KeyMatrix[2, 2]) - (KeyMatrix[2, 1] * KeyMatrix[1, 2])) - KeyMatrix[0, 1]
                    * (KeyMatrix[1, 0] * KeyMatrix[2, 2] - KeyMatrix[2, 0] * KeyMatrix[1, 2]) + KeyMatrix[0, 2] *
                       (KeyMatrix[1, 0] * KeyMatrix[2, 1] - KeyMatrix[2, 0] * KeyMatrix[1, 1]);
                det %= 26;
                if (det < 0)
                    det += 26;
            }
            //No common factors between det and 26  so gcd=1 
            int gcd = 1;
            for (int i = 1; i <= 26 && i <= det; ++i)
            {
                // check if i perfectly divides both 
                if (26 % i == 0 && det % i == 0)
                    gcd = i;
            }
            if (det == 0|| gcd!=1)
                throw new Exception("can find Inverse for the key");

            double[,] newk = new double[ksize, ksize];
            double[,] temp = new double[ksize, ksize];

            //get the inverse martix key for 2*2
            if (ksize == 2 && det != 0)
            {
                var temp0 = KeyMatrix[0, 0];
                KeyMatrix[0, 0] = KeyMatrix[1, 1];
                KeyMatrix[1, 1] = temp0;
                KeyMatrix[0, 1] = -1 * KeyMatrix[0, 1];
                KeyMatrix[1, 0] = -1 * KeyMatrix[1, 0];
                for (int i = 0; i < ksize; i++)//rows
                {
                    for (int j = 0; j < ksize; j++)//columns
                    {
                        double res = (KeyMatrix[i,j]*(1 / det)) % 26;
                        if (res < 0)
                             temp[i,j] = (res + 26) % 26;
                         else
                             temp[i, j] = res;
                     }
                 }
             }
             //get the inverse martix key for 3*3
             if (ksize == 3 && det != 0)
             {
                 int b = 0;
                 for (int i = 1; i < 26; i++)
                 {
                     if (((i * det) % 26) == 1)
                     {
                         b = i;
                         break;
                     }
                 }
                 if (b == 0) throw new Exception("can find value for Multiplicative Inverse b");

                 for (int i = 0; i < ksize; i++)//rows
                 {
                     for (int j = 0; j < ksize; j++)//columns
                     {
                         int pow = i + j;

                         var d = GetMinorDet(i, j, ksize, KeyMatrix);
                         var res = (b * (int)(Math.Pow(-1, pow)) * d) % 26;
                         if (res < 0)
                             newk[i, j] = (res + 26) % 26;

                         else
                             newk[i, j] = res;
                        temp[j, i] = newk[i, j];
                    }
                 }
             }

             //inverse * cipher to get the plain
             double sum = 0;
             for (int h = 0; h < CTrows; h++)
             {
                 for (int i = 0; i < ksize; i++)
                 {
                     for (int j = 0; j < ksize; j++)
                     {
                         sum += CipherMatrix[h, j] * temp[i, j];

                     }
                     var final = (int)sum;
                     plain.Add(final % 26);
                     sum = 0;
                 }
             }
                        return plain;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            List<int> cipher = new List<int>();
            // determine the size 
            int ksize = (int)Math.Sqrt(key.Count());
            int PTrows;
            if (plainText.Count() % ksize == 0)
                PTrows = plainText.Count() / ksize;
            else
                PTrows = (plainText.Count() / ksize) + 1;

            int[,] PlainMatrix = new int[PTrows, PTrows];
            int[,] KeyMatrix = new int[ksize, ksize];
            //fill the matrix
            int k = 0;
            for (int i = 0; i < PTrows; i++)
            {
                for (int j = 0; j < ksize; j++)
                {
                    PlainMatrix[i, j] = plainText[k];
                    k++;
                }
            }
            int l = 0;
            for (int i = 0; i < ksize; i++)
            {
                for (int j = 0; j < ksize; j++)
                {
                    KeyMatrix[i, j] = key[l];
                    l++;
                }
            }
            int sum = 0;
             // plain* key to get the cipher
            for (int h = 0; h < PTrows; h++)
            {
                for (int i = 0; i < ksize; i++)
                {
                    for (int j = 0; j < ksize; j++)
                    {
                        sum += (PlainMatrix[h, j] * KeyMatrix[i, j]);
                    }

                    cipher.Add(sum % 26);
                    sum = 0;
                }
            }
            return cipher;
        }
        
        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            List<int> key = new List<int>() { };
            
            int ncol = (int)Math.Sqrt(cipher3.Count());
            double[,] plainmat = new double[ncol, plain3.Count() / ncol];
            double[,] ciphermat = new double[ncol, cipher3.Count() / ncol];
            double[,] newk = new double[3, 3];
            double[,] temp = new double[3, 3];
            int k = 0;
            double det;
            
            //fill the matrix
            for (int i = 0; i < 3; i++)
            {

                for (int j = 0; j < 3; j++)
                {
                    plainmat[i, j] = plain3[k];
                    k++;   
                }
            }
            k = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    ciphermat[i, j] = cipher3[k];
                    k++;
                }
            }
            //calculate the determine
            det = plainmat[0, 0] * ((plainmat[1, 1] * plainmat[2, 2]) - (plainmat[2, 1] * plainmat[1, 2])) - plainmat[0, 1]
                   * (plainmat[1, 0] * plainmat[2, 2] - plainmat[2, 0] * plainmat[1, 2]) + plainmat[0, 2] *
                      (plainmat[1, 0] * plainmat[2, 1] - plainmat[2, 0] * plainmat[1, 1]);

            // get the inverse of the plain
            if (det != 0)
            {
                int b = 0;
                for (int i = 1; i < 26; i++)
                {
                    if (((i * det) % 26) == 1)
                    {
                        b = i;
                        break;
                    }
                }

                if (b == 0) throw new Exception("can find value for Multiplicative Inverse b");

                for (int i = 0; i < 3; i++)//rows
                {
                    for (int j = 0; j < 3; j++)//columns
                    {
                        int pow = i + j;

                        double d = GetMinorDet(i, j, 3, plainmat);
                        double res = (b * (Math.Pow(-1, pow)) * d) % 26;
                        if (res < 0)
                            newk[i, j] = (res + 26) % 26;

                        else
                            newk[i, j] = res;
                    }
                }
                for (int i = 0; i < 3; i++)//rows
                {
                    for (int a = 0; a < 3; a++)//columns
                    {
                        temp[a, i] = newk[i, a];

                    }
                }
            }

            //inverse * cipher to get the key
            double sum = 0;
            for (int h = 0; h < 3; h++)
            {
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        sum += ciphermat[j,h] * temp[i, j];

                    }

                    var final = (int)sum;
                    key.Add(final % 26);
                    sum = 0;
                }
            }
            return key;
        }
        // to get the minor det in 3*3 matrix
        public static double GetMinorDet(int row, int col, int size, double[,] matrix)
        {
            int nrows = size;
            int ncol = size;
            int rowindx = 0;
            double[,] minor = new double[nrows, ncol];
            for (int n = 0; n < nrows; ++n)
            {
                if (n == row) continue;
                // minor[rowindx] = new int[]
                int colindx = 0;
                for (int j = 0; j < ncol; ++j)
                {
                    if (j == col) continue;

                    minor[rowindx, colindx] = matrix[n, j];
                    colindx++;
                }
                ++rowindx;
            }
            double det = minor[0, 0] * minor[1, 1] - minor[0, 1] * minor[1, 0];
            return det;
        }
        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}