using CommandLine;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace SimpleBackup
{

    public static class EncryptionExtensions
    {
        private static string Decrypt(this byte[] data)
        {
            // Create BLOBs to hold data.
            DATA_BLOB plainTextBlob = new DATA_BLOB();
            DATA_BLOB cipherTextBlob = new DATA_BLOB();
            DATA_BLOB entropyBlob = new DATA_BLOB();

            // We only need prompt structure because it is a required
            // parameter.
            CRYPTPROTECT_PROMPTSTRUCT prompt =
                                      new CRYPTPROTECT_PROMPTSTRUCT();
            InitPrompt(ref prompt);


            try
            {
                // Convert ciphertext bytes into a BLOB structure.
                try
                {
                    //InitBLOB(cipherTextBytes, ref cipherTextBlob);
                    // Use empty array for null parameter.
                    if (data == null)
                        data = new byte[0];

                    // Allocate memory for the BLOB data.
                    cipherTextBlob.pbData = Marshal.AllocHGlobal(data.Length);

                    // Make sure that memory allocation was successful.
                    if (cipherTextBlob.pbData == IntPtr.Zero)
                        throw new Exception(
                            "Unable to allocate data buffer for BLOB structure.");

                    // Specify number of bytes in the BLOB.
                    cipherTextBlob.cbData = data.Length;

                    // Copy data from original source to the BLOB structure.
                    Marshal.Copy(data, 0, cipherTextBlob.pbData, data.Length);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize ciphertext BLOB.", ex);
                }

                // Convert entropy bytes into a BLOB structure.
                //try
                //{
                //    InitBLOB(entropyBytes, ref entropyBlob);
                //}
                //catch (Exception ex)
                //{
                //    throw new Exception(
                //        "Cannot initialize entropy BLOB.", ex);
                //}

                
                // Call DPAPI to decrypt data.
                bool success = CryptUnprotectData(ref cipherTextBlob, null, ref entropyBlob, IntPtr.Zero, ref prompt, CryptProtectFlags.CRYPTPROTECT_UI_FORBIDDEN, ref plainTextBlob);

                // Check the result.
                if (!success)
                {
                    // If operation failed, retrieve last Win32 error.
                    int errCode = Marshal.GetLastWin32Error();

                    // Win32Exception will contain error message corresponding
                    // to the Windows error code.
                    throw new Exception(
                        "CryptUnprotectData failed.", new Win32Exception(errCode));
                }

                return Marshal.PtrToStringBSTR(plainTextBlob.pbData);
            }
            catch (Exception ex)
            {
                throw new Exception("DPAPI was unable to decrypt data.", ex);
            }
            // Free all memory allocated for BLOBs.
            finally
            {
                if (plainTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(plainTextBlob.pbData);

                if (cipherTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(cipherTextBlob.pbData);

                if (entropyBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(entropyBlob.pbData);
            }
        }

        private static Byte[] Encrypt(this SecureString self, int length)
        {
            IntPtr unmanagedString = Marshal.SecureStringToBSTR(self);
            int len = Marshal.ReadInt32(unmanagedString, -4); //get the length of the bstr string type, it's always the first 4 bytes stored as an int.

            DATA_BLOB plainTextBlob = new DATA_BLOB();
            DATA_BLOB cipherTextBlob = new DATA_BLOB();
            DATA_BLOB entropyTextBlob = new DATA_BLOB();
            CRYPTPROTECT_PROMPTSTRUCT prompt = new CRYPTPROTECT_PROMPTSTRUCT();

            try
            {
                //Processing code here. Resist the urge to Marshal.PtrToStringBSTR.

                plainTextBlob.cbData = len;//set the length of the array
                plainTextBlob.pbData = unmanagedString;//set the data to our pointer.
                InitPrompt(ref prompt);


                // Call DPAPI to encrypt data.

                bool success = CryptProtectData(ref plainTextBlob, null, ref entropyTextBlob, IntPtr.Zero, ref prompt, CryptProtectFlags.CRYPTPROTECT_UI_FORBIDDEN, ref cipherTextBlob);

                // Check the result.
                if (!success)
                {
                    // If operation failed, retrieve last Win32 error.
                    int errCode = Marshal.GetLastWin32Error();

                    // Win32Exception will contain error message corresponding
                    // to the Windows error code.
                    throw new Exception(
                        "CryptProtectData failed.", new Win32Exception(errCode));
                }

                // Allocate memory to hold ciphertext.
                byte[] cipherTextBytes = new byte[cipherTextBlob.cbData];

                // Copy ciphertext from the BLOB to a byte array.
                Marshal.Copy(cipherTextBlob.pbData,
                                cipherTextBytes,
                                0,
                                cipherTextBlob.cbData);

                // Return the result.
                return cipherTextBytes;

            }
            finally
            {
                Marshal.ZeroFreeBSTR(unmanagedString); //free the buffer holding our secret
                if (plainTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(plainTextBlob.pbData);

                if (cipherTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(cipherTextBlob.pbData);

                //if (entropyBlob.pbData != IntPtr.Zero)
                //    Marshal.FreeHGlobal(entropyBlob.pbData);
            }
        }

        /// <summary>
        /// Initializes empty prompt structure.
        /// </summary>
        /// <param name="ps">
        /// Prompt parameter (which we do not actually need).
        /// </param>
        private static void InitPrompt(ref CRYPTPROTECT_PROMPTSTRUCT ps)
        {
            ps.cbSize = Marshal.SizeOf(typeof(CRYPTPROTECT_PROMPTSTRUCT));
            ps.dwPromptFlags = 0;
            ps.hwndApp = IntPtr.Zero;
            ps.szPrompt = null;
        }

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn,
            String szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            CryptProtectFlags dwFlags,
            ref DATA_BLOB pDataOut
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public CryptProtectPromptFlags dwPromptFlags;
            public IntPtr hwndApp;
            public String szPrompt;
        }

        [Flags]
        private enum CryptProtectPromptFlags
        {
            // prompt on unprotect
            CRYPTPROTECT_PROMPT_ON_UNPROTECT = 0x1,

            // prompt on protect
            CRYPTPROTECT_PROMPT_ON_PROTECT = 0x2
        }

        [Flags]
        private enum CryptProtectFlags
        {
            // for remote-access situations where ui is not an option
            // if UI was specified on protect or unprotect operation, the call
            // will fail and GetLastError() will indicate ERROR_PASSWORD_RESTRICTION
            CRYPTPROTECT_UI_FORBIDDEN = 0x1,

            // per machine protected data -- any user on machine where CryptProtectData
            // took place may CryptUnprotectData
            CRYPTPROTECT_LOCAL_MACHINE = 0x4,

            // force credential synchronize during CryptProtectData()
            // Synchronize is only operation that occurs during this operation
            CRYPTPROTECT_CRED_SYNC = 0x8,

            // Generate an Audit on protect and unprotect operations
            CRYPTPROTECT_AUDIT = 0x10,

            // Protect data with a non-recoverable key
            CRYPTPROTECT_NO_RECOVERY = 0x20,


            // Verify the protection of a protected blob
            CRYPTPROTECT_VERIFY_PROTECTION = 0x40
        }

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn,
            StringBuilder szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            CryptProtectFlags dwFlags,
            ref DATA_BLOB pDataOut
        );


    }
    



}
