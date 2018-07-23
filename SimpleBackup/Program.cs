using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace SimpleBackup
{
    class Program
    {
        static void Main(string[] args)
        {

        }

        public void PromptForUsernameAndPassword()
        {
            Console.WriteLine("Please enter the email address to deliver the report to: ");
            string emailTo = Console.ReadLine();

            Console.WriteLine("Please enter your email address to send from: ");
            string emailFrom = Console.ReadLine();

            var pwd = new SecureString();
            while (true)
            {
                ConsoleKeyInfo i = Console.ReadKey(true);
                if (i.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (i.Key == ConsoleKey.Backspace)
                {
                    if (pwd.Length > 0)
                    {
                        pwd.RemoveAt(pwd.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    pwd.AppendChar(i.KeyChar);
                    Console.Write("*");
                }
            }
            pwd.MakeReadOnly();
            // Generate additional entropy (will be used as the Initialization vector)
            byte[] entropy = new byte[20];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(entropy);
            }



            byte[] ciphertext = ProtectedData.Protect(pwd., entropy,
                DataProtectionScope.CurrentUser);


        }
        
    }



}
