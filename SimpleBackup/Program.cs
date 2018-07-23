using CommandLine;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
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
            try
            {
                ParserResult<Options> result = Parser.Default.ParseArguments<Options>(args);
                if (result.Tag != ParserResultType.Parsed) throw new Exception("Invalid inputs!" + result.ToString());

                Options options = ((Parsed<Options>)result).Value;

                if(options.EditCredentialsFile != null)
                {
                    
                    string filepath = options.EditCredentialsFile;
                    if (File.Exists(filepath))
                    {
                        Console.WriteLine("Current Settings: ");
                        Console.WriteLine(eSettings.ReadFromFile(filepath).Decrypt());
                    }
                    else
                    {
                        Console.WriteLine("No Existing Settings File Found at : " + options.EditCredentialsFile);
                    }

                    Console.WriteLine("Change Or Create Settings? (Y/N):");
                    if (Console.ReadKey().Key != ConsoleKey.Y)
                        return;
                    Console.WriteLine();
                    var set = GetSettings();
                    set.SerializeToFile(filepath);

                    Console.WriteLine("New Settings: ");
                    Console.WriteLine(eSettings.ReadFromFile(filepath).Decrypt());
                }
                else if (options.SourcePath == null || options.SourcePath == "" || options.DestinationPath == null || options.DestinationPath == "")
                {
                    throw new Exception("Invalid inputs! Must provide source and destination folders!");
                }
                else
                {
                    PerformBackup(options);
                }



            }
            catch(Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        public static void PerformBackup(Options options)
        {
            
        }

        public static void SaveCredentials(string filepath)
        {
            var enc = GetSettings();
            enc.SerializeToFile(filepath);
        }

        public static eSettings FetchSettings (string filepath)
        {
            return eSettings.ReadFromFile(filepath);
        }

        [DataContract]
        public class eSettings
        {
            [DataMember]
            public DateTime LastUpdated { get; set; }

            [DataMember]
            public string Version { get; set; }

            private Credentials _credentials;
            [DataMember]
            public Credentials Credentials {
                get {
                    _credentials = _credentials ?? new Credentials();
                    return _credentials;
                }
                set {
                    _credentials = value;
                }
            }
            [DataMember]
            public byte[] DeliveryEmail { get; set; }

            public eSettings() { }
            public eSettings(byte[] del, byte[] send, byte[] pwd)
            {
                this.DeliveryEmail = del;
                this.Credentials.Email = send;
                this.Credentials.Password = pwd;
            }

            public void SerializeToFile(string path)
            {
                using (FileStream fs = new FileStream(path, FileMode.Create))
                {
                    this.LastUpdated = DateTime.UtcNow;
                    System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
                    System.Diagnostics.FileVersionInfo fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(assembly.Location);
                    this.Version = fvi.FileVersion;
                    DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(eSettings));
                    ser.WriteObject(fs, this);
                    fs.Close();
                }
            }

            //// Deserialize a JSON stream to a User object.  
            public static eSettings ReadFromFile(string path)
            {
                eSettings deserialized = new eSettings();
                FileStream fs = new FileStream(path, FileMode.Open);

                //MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json));
                DataContractJsonSerializer ser = new DataContractJsonSerializer(deserialized.GetType());
                deserialized = ser.ReadObject(fs) as eSettings;
                fs.Close();
                return deserialized;
            }

            public string Decrypt()
            {
                StringBuilder sb = new StringBuilder();
                if (this.DeliveryEmail != null)
                    sb.AppendLine("Delivery Email: " + this.DeliveryEmail.Decrypt());

                if (this.Credentials.Email != null)
                    sb.AppendLine("Sending Email: " + this.Credentials.Email.Decrypt());

                if (this.Credentials.Password != null)
                    sb.AppendLine("Sending Password: " + this.Credentials.Password.Decrypt());

                return sb.ToString();
            }
        }

        [DataContract]
        public class Credentials
        {
            [DataMember]
            public byte[] Email { get; set; }
            [DataMember]
            public byte[] Password { get; set; }
        }

        public static eSettings GetSettings()
        {

            Console.WriteLine("Please enter the delivery email address");
            byte[] delEmail = GetSecureField(false);

            Console.WriteLine();

            Console.WriteLine("Please enter your sending email server's address: ");
            byte[] sendEmail = GetSecureField(false);

            Console.WriteLine();

            Console.WriteLine("Please enter your sending email server's password: ");
            byte[] password = GetSecureField(true);
            Console.WriteLine();

            return new eSettings(delEmail, sendEmail, password);
            
        }

        public static byte[] GetSecureField(bool hideChars)
        {
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
                    if (hideChars)
                        Console.Write("*");
                    else
                        Console.Write(i.KeyChar);
                }
            }
            pwd.MakeReadOnly();
            // Generate additional entropy (will be used as the Initialization vector)
            //byte[] entropy = new byte[20];
            //using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            //{
            //    rng.GetBytes(entropy);
            //}

            byte[] b = pwd.Encrypt(pwd.Length);
            return b;
        }
        internal class Options
        {
            [Option('s', "source", Required = false, HelpText = "The source folder path.")]
            public string SourcePath { get; set; }

            [Option('s', "destination", Required = false, HelpText = "The destination folder path.")]
            public string DestinationPath { get; set; }

            [Option('e', "email", Required = false, HelpText = "The full file path of the credentials file to use for the email server.")]
            public string Email { get; set; }

            [Option('r', "reportFolder", Required = false, HelpText = "A folder to output the backup reports to. Logs will still be saved in appdata.")]
            public string ReportFolder { get; set; }

            [Option('x', "createCredentialsFile", Required = false, HelpText = "Provide the filepath to save the encrypted credentials file to, will prompt for email and password. ")]
            public string EditCredentialsFile { get; set; }

            
            //[HelpOption]
            public string GetUsage()
            {
                // this without using CommandLine.Text
                //  or using HelpText.AutoBuild
                var usage = new StringBuilder();
                usage.AppendLine("Quickstart Application 1.0");
                usage.AppendLine("Read user manual for usage instructions...");
                return usage.ToString();
            }

        }
    }



}
