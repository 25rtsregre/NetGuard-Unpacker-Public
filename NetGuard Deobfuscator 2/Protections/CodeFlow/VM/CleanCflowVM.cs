using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetGuard_Deobfuscator_2.Protections.CodeFlow.VM
{
    class CleanCflowVM:CodeFlowBase
    {
        private static Stream resources;
        private static bool koivm;

        public override void Deobfuscate()
        {

            resources = ((EmbeddedResource)ModuleDefMD.Resources.Find("661644340"))?.CreateReader().AsStream();
          
            Cleaner();
            
        }
        private static string getString(MethodDef method)
        {
            foreach (Instruction instr in method.Body.Instructions)
            {
                if (instr.OpCode == OpCodes.Ldstr)
                {
                    return instr.Operand.ToString();
                }
            }
            return null;
        }
        public static void Cleaner()
        {
            foreach (TypeDef typeDef in ModuleDefMD.GetTypes())
            {
                foreach (MethodDef methods in typeDef.Methods)
                {
                    if (!methods.HasBody) continue;
                    for (int i = 0; i < methods.Body.Instructions.Count; i++)
                    {
                        if (methods.Body.Instructions[i].OpCode == OpCodes.Call &&
                            methods.Body.Instructions[i].Operand is MethodDef)
                        {
                            MethodDef methods2 = (MethodDef)methods.Body.Instructions[i].Operand;
                            if (methods2.Parameters.Count == 2 && methods2.ReturnType == ModuleDefMD.CorLibTypes.Int32)
                            {
                                if (methods.Body.Instructions[i - 1].IsLdcI4() &&
                                    methods.Body.Instructions[i - 2].OpCode == OpCodes.Ldstr)
                                {
                                    if (resources == null)
                                    {
                                        foreach (MethodDef methods3 in methods2.DeclaringType.Methods)
                                        {
                                            if (!methods3.HasBody) continue;
                                            for (int z = 0; z < methods3.Body.Instructions.Count; z++)
                                            {
                                                if (methods3.Body.Instructions[z].OpCode == OpCodes.Callvirt && methods3.Body.Instructions[z].Operand.ToString().Contains("GetManifestResourceStream"))
                                                {

                                                    resources = ((EmbeddedResource)ModuleDefMD.Resources.Find(getString(methods3)))?.CreateReader().AsStream();
                                                    if (getString(methods3) == "DLL")

                                                        koivm = true;

                                                    break;
                                                }
                                            }
                                            if (resources != null)
                                                break;

                                        }
                                    }
                                    if (koivm)
                                    {
                                        foreach (MethodDef methods3 in methods2.DeclaringType.Methods)
                                        {
                                            if (!methods3.HasBody) continue;
                                            if (!methods3.Body.Instructions.Any(y => y.OpCode == OpCodes.Callvirt && y.Operand.ToString().Contains("GetManifestResourceStream"))) continue;
                                            for (int z = 0; z < methods3.Body.Instructions.Count; z++)
                                            {
                                                if (methods3.Body.Instructions[z].OpCode == OpCodes.Ldstr && methods3.Body.Instructions[z - 1].OpCode == OpCodes.Ldstr && methods3.Body.Instructions[z - 2].OpCode == OpCodes.Ldstr)
                                                {

                                                    var str = methods3.Body.Instructions[z - 2].Operand.ToString();
                                                    var key = methods3.Body.Instructions[z - 1].Operand.ToString();
                                                    var iv = methods3.Body.Instructions[z].Operand.ToString();
                                                    if (IsBase64Key(key) && IsBase64IV(iv))
                                                    {
                                                        using (RijndaelManaged rijAlg = new RijndaelManaged())
                                                        {
                                                            rijAlg.Key = (Convert.FromBase64String(key));
                                                            rijAlg.IV = Convert.FromBase64String(iv);

                                                            // Create a decryptor to perform the stream transform.
                                                            ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                                                            // Create the streams used for decryption.
                                                            var str2 = Convert.FromBase64String(str);
                                                            using (MemoryStream msDecrypt = new MemoryStream((str2)))
                                                            {
                                                                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                                                                {
                                                                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                                                    {
                                                                        // Read the decrypted bytes from the decrypting stream
                                                                        // and place them in a string.
                                                                        var plaintext = srDecrypt.ReadToEnd();
                                                                        resources = ((EmbeddedResource)ModuleDefMD.Resources.Find(plaintext))?.CreateReader().AsStream();
                                                                    }
                                                                }
                                                            }

                                                        }
                                                    }
                                                    else
                                                    {
                                                        var Dkey = "WquhBrzBuPv$G@gG07K#5#4S&*oHg#";
                                                        var strDec= Decrypt(str, Dkey);
                                                        var ivDec = Decrypt(iv, Dkey);
                                                        var keyDec = Decrypt(key, Dkey);
                                                        using (RijndaelManaged rijAlg = new RijndaelManaged())
                                                        {
                                                            rijAlg.Key = (Convert.FromBase64String(keyDec));
                                                            rijAlg.IV = Convert.FromBase64String(ivDec);

                                                            // Create a decryptor to perform the stream transform.
                                                            ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                                                            // Create the streams used for decryption.
                                                            var str2 = Convert.FromBase64String(strDec);
                                                            using (MemoryStream msDecrypt = new MemoryStream((str2)))
                                                            {
                                                                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                                                                {
                                                                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                                                    {
                                                                        // Read the decrypted bytes from the decrypting stream
                                                                        // and place them in a string.
                                                                        var plaintext = srDecrypt.ReadToEnd();
                                                                        resources = ((EmbeddedResource)ModuleDefMD.Resources.Find(plaintext))?.CreateReader().AsStream();
                                                                    }
                                                                }
                                                            }

                                                        }
                                                    }


                                                    break;

                                                }
                                            }
                                        }
                                    }
                                    string valueStr = methods.Body.Instructions[i - 2].Operand.ToString();
                                    int valueInt = methods.Body.Instructions[i - 1].GetLdcI4Value();
                                    var decryptedVal = Class_0.Method_0(valueStr, valueInt, resources);
                                    methods.Body.Instructions[i].OpCode = OpCodes.Nop;
                                    methods.Body.Instructions[i - 1].OpCode = OpCodes.Nop;
                                    methods.Body.Instructions[i - 2].OpCode = OpCodes.Ldc_I4;
                                    methods.Body.Instructions[i - 2].Operand = decryptedVal;

                                }
                            }
                        }
                    }
                }
            }
        }
        public static string Decrypt(string one, string two)
        {
            byte[] array = Convert.FromBase64String(one);
            byte[] key;
            using (HashAlgorithm hashAlgorithm = new MD5CryptoServiceProvider())
            {
                key = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(two));
                hashAlgorithm.Clear();
            }
            SymmetricAlgorithm symmetricAlgorithm = new TripleDESCryptoServiceProvider
            {
                Key = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };
            byte[] bytes = symmetricAlgorithm.CreateDecryptor().TransformFinalBlock(array, 0, array.Length);
            symmetricAlgorithm.Clear();
            return Encoding.UTF8.GetString(bytes);
        }
        public static bool IsBase64Key(string base64String)
        {
            // Credit: oybek https://stackoverflow.com/users/794764/oybek
            if (string.IsNullOrEmpty(base64String) || base64String.Length % 4 != 0
               || base64String.Contains(" ") || base64String.Contains("\t") || base64String.Contains("\r") || base64String.Contains("\n"))
                return false;

            try
            {
                using (RijndaelManaged rijAlg = new RijndaelManaged())
                {
                    rijAlg.Key = (Convert.FromBase64String(base64String));
                }
                    return true;
            }
            catch (Exception exception)
            {
                // Handle the exception
            }
            return false;
        }
        public static bool IsBase64IV(string base64String)
        {
            // Credit: oybek https://stackoverflow.com/users/794764/oybek
            if (string.IsNullOrEmpty(base64String) || base64String.Length % 4 != 0
               || base64String.Contains(" ") || base64String.Contains("\t") || base64String.Contains("\r") || base64String.Contains("\n"))
                return false;

            try
            {
                using (RijndaelManaged rijAlg = new RijndaelManaged())
                {
                    rijAlg.IV = (Convert.FromBase64String(base64String));
                }
                return true;
            }
            catch (Exception exception)
            {
                // Handle the exception
            }
            return false;
        }
    }
}
