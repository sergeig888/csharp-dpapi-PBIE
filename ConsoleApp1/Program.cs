/* Created by Sergei Gundorov 1/2/2020
 * Intent: provide sample project for encrypting secrets with DPAPI while working with 
 * Power BI Embedded and API tutorials and samples. 
 * 
 * Power BI embedded calls for supplying credetials of AAD user (or service principal) to obtain the access token.
 * Very insecure flow if secrets are kept in the code or config file in plain text. 
 * Password/secret protection should be applied even in exploratory projects. 
 */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptCredential
{    
    class Program
    {
        //NOTE: many .Net Framework cryptographic samples reference default codepage which could lead to all sorts of 
        //hard to troubleshoot problems. It is best to set the exact codepage for your specifc configuration and environment

        //NOTE: the line below can be used with .Net Framework implementaion if there is a need to change codepage without 
        //requiring recompilation; use of .Net Core 3.1 self-contained executable file in my case makes the use of appconfig unnecessarily hard
        //private static Encoding codePage = Encoding.GetEncoding(Convert.ToInt32(ConfigurationManager.AppSettings["codePage"]));

        //setting code page to what works in both .Net and .Net Core; .Default is not considered best practice
        private static Encoding codePage = Encoding.GetEncoding(28591);
        //NOTE: file path is hardcoded because .Net Core doesn't work well with extenal config file with self-contained exe files
        //user of the console app can always specify alternative file name
        private static string secretsFile = "C:\\temp\\Encoded64BitSecret.bin";
        private static string secretsStore; 
        private static DataProtectionScope protScope;

        static void Main(string[] args)
        {
            Console.WriteLine("1 - encrypt or 2 - decrypt (using codepage {0}):", codePage.CodePage);
            int choice = Int32.TryParse(Console.ReadLine(), out choice) ? choice : 1;

            Console.WriteLine("Specify file path and name:\n(Press [ENTER] for default '{0}')", secretsFile);
            string userFile = Console.ReadLine();

            secretsFile = userFile.Length == 0 ? secretsFile : userFile;

            try
            {
                if (choice <= 1)
                {
                    Console.WriteLine("1 - machine or 2 - user data protection scope:\n(Press [ENTER] for default machine scope)");
                    int protChoice = Int32.TryParse(Console.ReadLine(), out protChoice) ? protChoice : 1;

                    protScope = protChoice <= 1 ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser;

                    EncryptString();
                }

                DecryptString();
            }

            catch (Exception e)
            {
                Console.Write(e.Message);             
            }

            Console.ReadLine();
        }

        private static void DecryptString()
        {

            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();

            sw.Start();

            string protectedString64Bit = File.ReadAllText(secretsFile);

            //NOTE: DataProtectionScope enum value in decrypt operations doesn't seem to make any difference
            byte[] plainText = ProtectedData.Unprotect(System.Convert.FromBase64String(protectedString64Bit), null, DataProtectionScope.CurrentUser);

            sw.Stop();
            
            Console.WriteLine(codePage.GetString(plainText));
            Console.WriteLine("Time to decrypt from file: {0} ticks (1/10,000 millisecond)", sw.ElapsedTicks);
            
            if (secretsStore == null) return;

            sw.Reset();
            sw.Start();

            plainText = ProtectedData.Unprotect(codePage.GetBytes(secretsStore), null, DataProtectionScope.CurrentUser);

            sw.Stop();

            Console.WriteLine(codePage.GetString(plainText));
            Console.WriteLine("Time to decrypt from memory: {0} ticks (1/10,000 millisecond)", sw.ElapsedTicks);
        }

        private static void EncryptString()
        {
            Console.WriteLine("Enter test string or hit enter for default:");

            //NOTE: the line below can be used to explore what encodings are available on the target system
            //var enc = Encoding.GetEncodings();

            string plainTextPwd = Console.ReadLine();

            plainTextPwd = plainTextPwd.Length == 0 ? "password" : plainTextPwd;

            Console.WriteLine("Plain text password:\n{0}\n", plainTextPwd);

            byte[] buffer = codePage.GetBytes(plainTextPwd);

            buffer = ProtectedData.Protect(buffer, null, protScope);
            
            string protectedString = codePage.GetString(buffer);
            
            //NOTE: conversion to base 64 string is an optional extra step to produce human readable string.            
            //Encrypted bytes can be stored and read in binary format without being converted to base 64 string
            string protectedString64Bit = System.Convert.ToBase64String(buffer);

            secretsStore = protectedString;

            Console.WriteLine("64 bit encoded encrypted string:\n{0}\n", protectedString64Bit);

            File.WriteAllText(secretsFile, protectedString64Bit);
        }
    }
}