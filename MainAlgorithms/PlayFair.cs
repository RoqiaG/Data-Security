using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            char[,] matrix = new char[5, 5];
            string ct = cipherText.ToLower();
            string keyFinal = key.ToLower();
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ".ToLower();
            string Text = keyFinal + alphabet;
            //Matrix==============================Text=====================================================
            //SWITCH J
            for (int i = 0; i < Text.Length; i++)
            {
                if (Text[i] == 'j')
                    Text.Replace('j', 'i');
            }

            //REMOVE DUPLICATION

            for (int i = 0; i < key.Length; i++)
            {
                for (int j = i + 1; j < Text.Length; j++)
                {
                    if (key[i] == Text[j])
                        Text = Text.Remove(j, 1);
                }
            }


            //REMOVE SPACE
            for (int i = 0; i < Text.Length; i++)
            {
                if (Text[i] == ' ')
                {
                    Text.Remove(i, 1);
                }
            }
            string TextF = Text.ToString();

            //FILL MATRIX
            int k = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = TextF[k];
                    k++;
                }
            }
            /*  for (int l = 0; l < ct.Length - 1; l += 2)
              {

                  // SIMILAR CHAR
                  if (ct[l] != ct[l + 1])
                  {
                      if (ct[l+1]=='x')
                      ct.Remove(l + 1);


                  }
              }
              if (ct.Length % 2 != 1)
                  ct.Remove('x');*/
            string ct2 = ct.ToString();
            string pText = "";


            int pCharRow1 = 0;
            int pCharCol1 = 0;
            int pCharRow2 = 0;
            int pCharCol2 = 0;

            int r1 = 0;
            int c1 = 0;
            int r2 = 0;
            int c2 = 0;


            for (int l = 0; l < ct2.Length - 1; l += 2)
            {

                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (ct2[l] == matrix[i, j])
                        {

                            r1 = i;
                            c1 = j;
                        }
                        else if (ct2[l + 1] == matrix[i, j])
                        {
                            r2 = i;
                            c2 = j;
                        }
                    }
                }
                if (r1 == r2)
                {
                    pCharRow1 = r1;
                    pCharRow2 = r2;

                    pCharCol1 = (c1 - 1 + 5) % 5;
                    pCharCol2 = (c2 - 1 + 5) % 5;


                }
                else if (c1 == c2)
                {
                    pCharCol1 = c1;
                    pCharCol2 = c2;


                    pCharRow1 = (r1 - 1 + 5) % 5;
                    pCharRow2 = (r2 - 1 + 5) % 5;

                }
                else
                {
                    pCharRow1 = r1;
                    pCharRow2 = r2;

                    pCharCol1 = c2;
                    pCharCol2 = c1;
                }
                pText += matrix[pCharRow1, pCharCol1];
                pText += matrix[pCharRow2, pCharCol2];


            }
            string pnew = pText;
            if (pText[pText.Length - 1] == 'x')
            {
                pnew = pText.Remove(pText.Length - 1);


            }


            int x = 0;
            for (int i = 1; i < pnew.Length - 1; i++)
            {
                if (pText[i] == 'x')
                {
                    if (pText[i - 1] == pText[i + 1])
                    {
                        if (i % 2 != 0 && (i + 1) % 2 == 0 && i + x < pText.Length)
                        {
                            pnew = pnew.Remove(i + x, 1);
                            x--;

                        }
                    }
                }

            }

            return pnew;

        }

        public string Encrypt(string plainText, string key)
        {

            char[,] matrix = new char[5, 5];

            string keyFinal = key.ToLower();

            StringBuilder plainTextF = new StringBuilder(plainText.ToLower());

            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ".ToLower();

            string Text1 = keyFinal + alphabet;

            StringBuilder Text = new StringBuilder(Text1.ToLower());


            //Matrix==============================Text=====================================================
            //SWITCH J
            for (int i = 0; i < Text.Length; i++)
            {
                if (Text[i] == 'j')
                    Text.Replace('j', 'i');
            }

            //REMOVE DUPLICATION
            for (int i = 0; i < key.Length; i++)
                for (int j = i + 1; j < Text.Length; j++)
                {
                    if (key[i] == Text[j])
                        Text.Remove(j, 1);
                }


            //REMOVE SPACE
            for (int i = 0; i < Text.Length; i++)
            {
                if (Text[i] == ' ')
                {
                    Text.Remove(i, 1);
                }
            }
            string TextF = Text.ToString();

            //FILL MATRIX
            int k = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = TextF[k];
                    k++;
                }
            }

            //PlainText====================================================================================          
            //SWITCH J
            for (int i = 0; i < plainTextF.Length; i++)
            {
                if (plainTextF[i] == 'j')
                    plainTextF.Replace('j', 'i');
            }


            //REMOVE SPACE
            for (int i = 0; i < plainTextF.Length; i++)
            {
                if (plainTextF[i] == ' ')
                {
                    plainTextF.Remove(i, 1);
                }
            }


            for (int l = 0; l < plainTextF.Length - 1; l += 2)
            {

                // SIMILAR CHAR
                if (plainTextF[l] == plainTextF[l + 1])
                {
                    plainTextF.Insert(l + 1, 'x');


                }
            }
            if (plainTextF.Length % 2 != 0)
                plainTextF.Append('x');

            string plainTextF2 = plainTextF.ToString();
            string cText = "";


            int cipherCharRow1 = 0;
            int cipherCharCol1 = 0;
            int cipherCharRow2 = 0;
            int cipherCharCol2 = 0;

            int r1 = 0;
            int c1 = 0;
            int r2 = 0;
            int c2 = 0;


            for (int l = 0; l < plainTextF2.Length; l += 2)
            {

                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (plainTextF2[l] == matrix[i, j])
                        {

                            r1 = i;
                            c1 = j;
                        }
                        else if (plainTextF2[l + 1] == matrix[i, j])
                        {
                            r2 = i;
                            c2 = j;
                        }
                    }
                }
                if (r1 == r2)
                {
                    cipherCharRow1 = r1;
                    cipherCharRow2 = r2;

                    cipherCharCol1 = (c1 + 1) % 5;
                    cipherCharCol2 = (c2 + 1) % 5;
                }
                else if (c1 == c2)
                {
                    cipherCharCol1 = c1;
                    cipherCharCol2 = c2;

                    cipherCharRow1 = (r1 + 1) % 5;
                    cipherCharRow2 = (r2 + 1) % 5;

                }
                else
                {
                    cipherCharRow1 = r1;
                    cipherCharRow2 = r2;

                    cipherCharCol1 = c2;
                    cipherCharCol2 = c1;
                }

                cText += matrix[cipherCharRow1, cipherCharCol1];
                cText += matrix[cipherCharRow2, cipherCharCol2];


            }
            return cText;
        }

    }
}