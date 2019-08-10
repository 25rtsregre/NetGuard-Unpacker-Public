using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;

namespace NetGuard_Deobfuscator_2.Protections.Mutations.Fields
{
    class FieldProxy : MutationsBase
    {
        public static Dictionary<FieldDef, uint> ListedDelegateInfo2s = new Dictionary<FieldDef, uint>();
        public override bool Deobfuscate()
        {
            ListedDelegateInfo2s = new Dictionary<FieldDef, uint>();
            ScrapeCctor(ModuleDefMD);
            GetFieldValue();

            return Replace();
        }
        private static bool Replace()
        {
            var modified = false;
            var cctor = ModuleDefMD.GlobalType.FindOrCreateStaticConstructor();
            if (cctor.Body.Instructions[0].OpCode == OpCodes.Call &&
                cctor.Body.Instructions[0].Operand.ToString().Contains("Koi"))
                cctor = (MethodDef)cctor.Body.Instructions[0].Operand;
            foreach(Instruction instruction in cctor.Body.Instructions)
            {
                if (instruction.OpCode != OpCodes.Ldsfld) continue;
                if (!ListedDelegateInfo2s.ContainsKey(instruction.Operand as FieldDef)) continue;
                if (ListedDelegateInfo2s[instruction.Operand as FieldDef] == 300) continue;
                var value = ListedDelegateInfo2s[instruction.Operand as FieldDef];
                instruction.OpCode = OpCodes.Ldc_I4;
                instruction.Operand = (int)value;
                modified = true;

            }
            return modified;
        }
        private static void GetFieldValue()
        {
            var cctor = ModuleDefMD.GlobalType.FindOrCreateStaticConstructor();
            if (cctor.Body.Instructions[0].OpCode == OpCodes.Call &&
                cctor.Body.Instructions[0].Operand.ToString().Contains("Koi"))
                cctor = (MethodDef)cctor.Body.Instructions[0].Operand;
            foreach(Instruction instruction in cctor.Body.Instructions)
            {
                if (instruction.OpCode != OpCodes.Call) continue;
                if (!(instruction.Operand is MethodDef)) continue;
                MethodDef method = instruction.Operand as MethodDef;
                var stsfld = method.Body.Instructions[method.Body.Instructions.Count - 2];
                if (stsfld.OpCode != OpCodes.Stsfld) continue;
                if (!ListedDelegateInfo2s.ContainsKey(stsfld.Operand as FieldDef)) continue;
                try
                {
                    CawkEmulatorV4.Emulation emulation = new CawkEmulatorV4.Emulation(method);
                    emulation.Emulate();
                    var fieldVal = emulation.ValueStack.Fields[stsfld.Operand as FieldDef];
                    byte castedField = (byte)fieldVal;
                    ListedDelegateInfo2s[stsfld.Operand as FieldDef] = castedField;
                }
                catch
                {

                }
                
            }
        }
        private static void ScrapeCctor(ModuleDefMD module)
        {
            var cctor = module.GlobalType.FindOrCreateStaticConstructor();
            if (cctor.Body.Instructions[0].OpCode == OpCodes.Call &&
                cctor.Body.Instructions[0].Operand.ToString().Contains("Koi"))
                cctor = (MethodDef)cctor.Body.Instructions[0].Operand;
            for (int i = 0; i < cctor.Body.Instructions.Count; i++)
            {
                if (cctor.Body.Instructions[i].OpCode == OpCodes.Ldtoken && cctor.Body.Instructions[i + 1].OpCode==OpCodes.Ldsfld &&
                    cctor.Body.Instructions[i + 2].OpCode == OpCodes.Call)
                {
                    FieldDef fieldDef = cctor.Body.Instructions[i+1].Operand as FieldDef;


                    ListedDelegateInfo2s.Add(fieldDef,300);
                }
                else if (cctor.Body.Instructions[i].OpCode == OpCodes.Ldtoken && cctor.Body.Instructions[i + 2].OpCode == OpCodes.Ldsfld &&
                         cctor.Body.Instructions[i + 3].OpCode == OpCodes.Call)
                {
                    FieldDef fieldDef = cctor.Body.Instructions[i+2].Operand as FieldDef;


                    ListedDelegateInfo2s.Add(fieldDef,300);
                }
                else if (cctor.Body.Instructions[i].OpCode == OpCodes.Ldtoken && cctor.Body.Instructions[i + 3].OpCode == OpCodes.Ldsfld &&
                         cctor.Body.Instructions[i + 4].OpCode == OpCodes.Call)
                {
                    FieldDef fieldDef = cctor.Body.Instructions[i+3].Operand as FieldDef;

                    ListedDelegateInfo2s.Add(fieldDef,300);
                }

            }
        }
    }
}
