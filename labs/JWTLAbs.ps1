# JWT Signing Verification Test Tool
# Usage: .\Test-JWTSigning.ps1 [-InputFile "path\to\file.json"] [-TestResigning] [-TestPadding] [-TestAuthentication]
# Examples:
#   .\Test-JWTSigning.ps1
#   .\Test-JWTSigning.ps1 -InputFile "tokens.json" -TestResigning
#   .\Test-JWTSigning.ps1 -TestPadding
#   .\Test-JWTSigning.ps1 -TestAuthentication

param(
    [Parameter(Mandatory=$false)]
    [string]$InputFile = "captured_tokens.json",
    
    [Parameter(Mandatory=$false)]
    [switch]$TestResigning,
    
    [Parameter(Mandatory=$false)]
    [switch]$TestPadding,
    
    [Parameter(Mandatory=$false)]
    [switch]$TestAuthentication
)

$ErrorActionPreference = 'Continue'
$logTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "JWT_Test_Log_" + $logTimestamp + ".txt"

$script:AuthenticationResults = @()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        "ALERT" { "Magenta" }
        "CRITICAL" { "Red" }
        default { "White" }
    }
    
    Write-Host $logEntry -ForegroundColor $color
    Add-Content -Path $logFile -Value $logEntry
}

function Write-Banner {
    param([string]$Message)
    $banner = "=" * 80
    Write-Log $banner "ALERT"
    Write-Log $Message "ALERT"
    Write-Log $banner "ALERT"
}

function ConvertFrom-Base64Url {
    param([string]$Base64Url)
    
    $base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
    
    switch ($base64.Length % 4) {
        0 { break }
        2 { $base64 += '==' }
        3 { $base64 += '=' }
    }
    
    return [Convert]::FromBase64String($base64)
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    
    $base64 = [Convert]::ToBase64String($Bytes)
    return $base64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function Parse-JWT {
    param([string]$Token)
    
    Write-Log "Parsing JWT token" "DEBUG"
    
    $parts = $Token.Split('.')
    
    if ($parts.Length -ne 3) {
        Write-Log "Invalid JWT format - expected 3 parts, got $($parts.Length)" "ERROR"
        return $null
    }
    
    try {
        $headerBytes = ConvertFrom-Base64Url -Base64Url $parts[0]
        $payloadBytes = ConvertFrom-Base64Url -Base64Url $parts[1]
        $signatureBytes = ConvertFrom-Base64Url -Base64Url $parts[2]
        
        $headerJson = [System.Text.Encoding]::UTF8.GetString($headerBytes)
        $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
        
        $header = $headerJson | ConvertFrom-Json
        $payload = $payloadJson | ConvertFrom-Json
        
        Write-Log "Header Algorithm: $($header.alg)" "DEBUG"
        Write-Log "Payload Issuer: $($payload.iss)" "DEBUG"
        
        return @{
            Header = $header
            Payload = $payload
            HeaderBase64 = $parts[0]
            PayloadBase64 = $parts[1]
            SignatureBase64 = $parts[2]
            SignatureBytes = $signatureBytes
            SigningInput = $parts[0] + "." + $parts[1]
        }
    }
    catch {
        Write-Log "Error parsing JWT: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function New-RSAKey {
    param([int]$KeySize = 2048)
    
    Write-Log "Generating RSA key pair with size: $KeySize" "INFO"
    
    try {
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new($KeySize)
        Write-Log "RSA key generated successfully" "INFO"
        return $rsa
    }
    catch {
        Write-Log "Error generating RSA key: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function New-ECDSAKey {
    param([string]$Curve = "nistP256")
    
    Write-Log "Generating ECDSA key pair with curve: $Curve" "INFO"
    
    try {
        $curveName = switch ($Curve) {
            "nistP256" { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256 }
            "nistP384" { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP384 }
            "nistP521" { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP521 }
            default { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256 }
        }
        
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create($curveName)
        Write-Log "ECDSA key generated successfully" "INFO"
        return $ecdsa
    }
    catch {
        Write-Log "Error generating ECDSA key: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Sign-JWTWithRSA {
    param(
        [string]$SigningInput,
        [System.Security.Cryptography.RSA]$RSAKey,
        [string]$Algorithm = "RS256"
    )
    
    Write-Log "Signing JWT with RSA algorithm: $Algorithm" "INFO"
    
    try {
        $hashAlgorithm = switch ($Algorithm) {
            "RS256" { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
            "RS384" { [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
            "RS512" { [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
            default { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
        }
        
        $signingBytes = [System.Text.Encoding]::ASCII.GetBytes($SigningInput)
        Write-Log "Signing input length: $($signingBytes.Length) bytes" "DEBUG"
        
        $signature = $RSAKey.SignData(
            $signingBytes,
            $hashAlgorithm,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        
        Write-Log "Signature generated: $($signature.Length) bytes" "INFO"
        return $signature
    }
    catch {
        Write-Log "Error signing with RSA: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Sign-JWTWithECDSA {
    param(
        [string]$SigningInput,
        [System.Security.Cryptography.ECDsa]$ECDSAKey,
        [string]$Algorithm = "ES256"
    )
    
    Write-Log "Signing JWT with ECDSA algorithm: $Algorithm" "INFO"
    
    try {
        $hashAlgorithm = switch ($Algorithm) {
            "ES256" { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
            "ES384" { [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
            "ES512" { [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
            default { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
        }
        
        $signingBytes = [System.Text.Encoding]::ASCII.GetBytes($SigningInput)
        Write-Log "Signing input length: $($signingBytes.Length) bytes" "DEBUG"
        
        $signature = $ECDSAKey.SignData($signingBytes, $hashAlgorithm)
        
        Write-Log "Signature generated: $($signature.Length) bytes" "INFO"
        return $signature
    }
    catch {
        Write-Log "Error signing with ECDSA: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Verify-RSASignature {
    param(
        [string]$SigningInput,
        [byte[]]$Signature,
        [System.Security.Cryptography.RSA]$RSAKey,
        [string]$Algorithm = "RS256"
    )
    
    Write-Log "Verifying RSA signature with algorithm: $Algorithm" "INFO"
    
    try {
        $hashAlgorithm = switch ($Algorithm) {
            "RS256" { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
            "RS384" { [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
            "RS512" { [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
            default { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
        }
        
        $signingBytes = [System.Text.Encoding]::ASCII.GetBytes($SigningInput)
        
        $verified = $RSAKey.VerifyData(
            $signingBytes,
            $Signature,
            $hashAlgorithm,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        
        Write-Log "Signature verification result: $verified" "INFO"
        return $verified
    }
    catch {
        Write-Log "Error verifying RSA signature: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Verify-ECDSASignature {
    param(
        [string]$SigningInput,
        [byte[]]$Signature,
        [System.Security.Cryptography.ECDsa]$ECDSAKey,
        [string]$Algorithm = "ES256"
    )
    
    Write-Log "Verifying ECDSA signature with algorithm: $Algorithm" "INFO"
    
    try {
        $hashAlgorithm = switch ($Algorithm) {
            "ES256" { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
            "ES384" { [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
            "ES512" { [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
            default { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
        }
        
        $signingBytes = [System.Text.Encoding]::ASCII.GetBytes($SigningInput)
        
        $verified = $ECDSAKey.VerifyData($signingBytes, $Signature, $hashAlgorithm)
        
        Write-Log "Signature verification result: $verified" "INFO"
        return $verified
    }
    catch {
        Write-Log "Error verifying ECDSA signature: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Build-JWT {
    param(
        [string]$HeaderBase64,
        [string]$PayloadBase64,
        [byte[]]$Signature
    )
    
    $signatureBase64 = ConvertTo-Base64Url -Bytes $Signature
    return $HeaderBase64 + "." + $PayloadBase64 + "." + $signatureBase64
}

function Test-JWTResigning {
    param(
        [object]$ParsedJWT,
        [string]$OriginalToken
    )
    
    Write-Log "=== Starting JWT Resigning Tests ===" "INFO"
    Write-Log "Original Token Length: $($OriginalToken.Length)" "DEBUG"
    
    Write-Log "--- Testing RSA Signing ---" "INFO"
    $rsaTests = @("RS256", "RS384", "RS512")
    $rsaKeySizes = @(2048, 3072, 4096)
    
    foreach ($keySize in $rsaKeySizes) {
        Write-Log "Testing with RSA key size: $keySize" "INFO"
        $rsaKey = New-RSAKey -KeySize $keySize
        
        if ($rsaKey) {
            foreach ($algo in $rsaTests) {
                Write-Log "Attempting to sign with $algo" "INFO"
                $signature = Sign-JWTWithRSA -SigningInput $ParsedJWT.SigningInput -RSAKey $rsaKey -Algorithm $algo
                
                if ($signature) {
                    $newToken = Build-JWT -HeaderBase64 $ParsedJWT.HeaderBase64 -PayloadBase64 $ParsedJWT.PayloadBase64 -Signature $signature
                    Write-Log "New token created with $algo" "INFO"
                    Write-Log "New Token Length: $($newToken.Length)" "DEBUG"
                    Write-Log "Signature Length: $($signature.Length) bytes" "DEBUG"
                    
                    $verified = Verify-RSASignature -SigningInput $ParsedJWT.SigningInput -Signature $signature -RSAKey $rsaKey -Algorithm $algo
                    Write-Log "Self-verification with same key: $verified" "INFO"
                    
                    Write-Log "Token Preview: $($newToken.Substring(0, [Math]::Min(100, $newToken.Length)))..." "DEBUG"
                }
            }
            
            $rsaKey.Dispose()
        }
    }
    
    Write-Log "--- Testing ECDSA Signing ---" "INFO"
    $ecdsaTests = @(
        @{Algo="ES256"; Curve="nistP256"},
        @{Algo="ES384"; Curve="nistP384"},
        @{Algo="ES512"; Curve="nistP521"}
    )
    
    foreach ($test in $ecdsaTests) {
        Write-Log "Testing with ECDSA curve: $($test.Curve)" "INFO"
        $ecdsaKey = New-ECDSAKey -Curve $test.Curve
        
        if ($ecdsaKey) {
            Write-Log "Attempting to sign with $($test.Algo)" "INFO"
            $signature = Sign-JWTWithECDSA -SigningInput $ParsedJWT.SigningInput -ECDSAKey $ecdsaKey -Algorithm $test.Algo
            
            if ($signature) {
                $newToken = Build-JWT -HeaderBase64 $ParsedJWT.HeaderBase64 -PayloadBase64 $ParsedJWT.PayloadBase64 -Signature $signature
                Write-Log "New token created with $($test.Algo)" "INFO"
                Write-Log "New Token Length: $($newToken.Length)" "DEBUG"
                Write-Log "Signature Length: $($signature.Length) bytes" "DEBUG"
                
                $verified = Verify-ECDSASignature -SigningInput $ParsedJWT.SigningInput -Signature $signature -ECDSAKey $ecdsaKey -Algorithm $test.Algo
                Write-Log "Self-verification with same key: $verified" "INFO"
                
                Write-Log "Token Preview: $($newToken.Substring(0, [Math]::Min(100, $newToken.Length)))..." "DEBUG"
            }
            
            $ecdsaKey.Dispose()
        }
    }
    
    Write-Log "=== JWT Resigning Tests Complete ===" "INFO"
}

function Test-SignaturePadding {
    param(
        [object]$ParsedJWT,
        [string]$OriginalToken
    )
    
    Write-Log "=== Starting Signature Padding Tests ===" "INFO"
    
    Write-Log "Original signature length: $($ParsedJWT.SignatureBytes.Length) bytes" "DEBUG"
    $originalSigBase64 = $ParsedJWT.SignatureBase64
    Write-Log "Original signature (Base64Url): $originalSigBase64" "DEBUG"
    
    Write-Log "--- Testing Signature Padding with Additional Signature ---" "INFO"
    
    $rsaKey = New-RSAKey -KeySize 2048
    if ($rsaKey) {
        $additionalSignature = Sign-JWTWithRSA -SigningInput $ParsedJWT.SigningInput -RSAKey $rsaKey -Algorithm "RS256"
        
        if ($additionalSignature) {
            Write-Log "Generated additional RSA signature: $($additionalSignature.Length) bytes" "INFO"
            
            $combinedSignature = [byte[]]::new($ParsedJWT.SignatureBytes.Length + $additionalSignature.Length)
            [Array]::Copy($ParsedJWT.SignatureBytes, 0, $combinedSignature, 0, $ParsedJWT.SignatureBytes.Length)
            [Array]::Copy($additionalSignature, 0, $combinedSignature, $ParsedJWT.SignatureBytes.Length, $additionalSignature.Length)
            
            Write-Log "Combined signature length: $($combinedSignature.Length) bytes" "INFO"
            
            $paddedToken = Build-JWT -HeaderBase64 $ParsedJWT.HeaderBase64 -PayloadBase64 $ParsedJWT.PayloadBase64 -Signature $combinedSignature
            Write-Log "Padded token created" "INFO"
            Write-Log "Padded Token Length: $($paddedToken.Length)" "DEBUG"
            Write-Log "Token Preview: $($paddedToken.Substring(0, [Math]::Min(100, $paddedToken.Length)))..." "DEBUG"
        }
        
        $rsaKey.Dispose()
    }
    
    Write-Log "--- Testing Signature Appending ---" "INFO"
    
    $ecdsaKey = New-ECDSAKey -Curve "nistP256"
    if ($ecdsaKey) {
        $ecdsaSignature = Sign-JWTWithECDSA -SigningInput $ParsedJWT.SigningInput -ECDSAKey $ecdsaKey -Algorithm "ES256"
        
        if ($ecdsaSignature) {
            Write-Log "Generated additional ECDSA signature: $($ecdsaSignature.Length) bytes" "INFO"
            
            $appendedSignature = [byte[]]::new($ParsedJWT.SignatureBytes.Length + $ecdsaSignature.Length + 4)
            [Array]::Copy($ParsedJWT.SignatureBytes, 0, $appendedSignature, 0, $ParsedJWT.SignatureBytes.Length)
            
            $separator = [byte[]]@(0x00, 0x00, 0x00, 0x00)
            [Array]::Copy($separator, 0, $appendedSignature, $ParsedJWT.SignatureBytes.Length, 4)
            [Array]::Copy($ecdsaSignature, 0, $appendedSignature, $ParsedJWT.SignatureBytes.Length + 4, $ecdsaSignature.Length)
            
            Write-Log "Appended signature length: $($appendedSignature.Length) bytes" "INFO"
            
            $appendedToken = Build-JWT -HeaderBase64 $ParsedJWT.HeaderBase64 -PayloadBase64 $ParsedJWT.PayloadBase64 -Signature $appendedSignature
            Write-Log "Appended token created" "INFO"
            Write-Log "Token Preview: $($appendedToken.Substring(0, [Math]::Min(100, $appendedToken.Length)))..." "DEBUG"
        }
        
        $ecdsaKey.Dispose()
    }
    
    Write-Log "=== Signature Padding Tests Complete ===" "INFO"
}

function Test-APIAuthentication {
    param(
        [string]$Token,
        [object]$TokenData,
        [string]$TestType = "Original"
    )
    
    Write-Log "=== Starting API Authentication Test ($TestType Token) ===" "INFO"
    
    $endpoints = @()
    
    $audience = $TokenData.payload.aud
    Write-Log "Token Audience: $audience" "INFO"
    
    if ($audience -match "graph\.microsoft\.com") {
        $endpoints += @{
            Name = "Microsoft Graph - Me"
            Url = "https://graph.microsoft.com/v1.0/me"
            Method = "GET"
        }
        $endpoints += @{
            Name = "Microsoft Graph - Organization"
            Url = "https://graph.microsoft.com/v1.0/organization"
            Method = "GET"
        }
    }
    elseif ($audience -match "substrate\.office\.com") {
        $endpoints += @{
            Name = "Substrate Search"
            Url = "https://substrate.office.com/search/api/v1/suggestions?query=test&EntityTypes=File"
            Method = "GET"
        }
    }
    elseif ($audience -match "00000003-0000-0000-c000-000000000000") {
        $endpoints += @{
            Name = "Microsoft Graph - Me (Office 365)"
            Url = "https://graph.microsoft.com/v1.0/me"
            Method = "GET"
        }
    }
    else {
        $endpoints += @{
            Name = "Generic API Test"
            Url = $audience
            Method = "GET"
        }
    }
    
    $endpoints += @{
        Name = "Microsoft Graph - Me (Default)"
        Url = "https://graph.microsoft.com/v1.0/me"
        Method = "GET"
    }
    
    $testSuccessful = $false
    $testEndpoint = ""
    
    foreach ($endpoint in $endpoints) {
        Write-Log "--- Testing Endpoint: $($endpoint.Name) ---" "INFO"
        Write-Log "URL: $($endpoint.Url)" "INFO"
        Write-Log "Method: $($endpoint.Method)" "INFO"
        
        try {
            $headers = @{
                "Authorization" = "Bearer " + $Token
                "Content-Type" = "application/json"
                "Accept" = "application/json"
                "User-Agent" = "JWT-Test-Tool/1.0"
            }
            
            Write-Log "Request Headers:" "DEBUG"
            foreach ($key in $headers.Keys) {
                if ($key -eq "Authorization") {
                    $maskedValue = "Bearer " + $Token.Substring(0, [Math]::Min(20, $Token.Length)) + "...[REDACTED]"
                    Write-Log "  ${key}: $maskedValue" "DEBUG"
                }
                else {
                    Write-Log "  ${key}: $($headers[$key])" "DEBUG"
                }
            }
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            Write-Log "Sending HTTP request..." "INFO"
            
            $response = $null
            $statusCode = $null
            $responseBody = $null
            $responseHeaders = $null
            
            try {
                $webRequest = [System.Net.WebRequest]::Create($endpoint.Url)
                $webRequest.Method = $endpoint.Method
                $webRequest.Headers.Add("Authorization", $headers["Authorization"])
                $webRequest.ContentType = $headers["Content-Type"]
                $webRequest.Accept = $headers["Accept"]
                $webRequest.UserAgent = $headers["User-Agent"]
                $webRequest.Timeout = 30000
                
                try {
                    $webResponse = $webRequest.GetResponse()
                    $statusCode = [int]$webResponse.StatusCode
                    $statusDescription = $webResponse.StatusDescription
                    
                    $responseHeaders = @{}
                    foreach ($headerName in $webResponse.Headers.AllKeys) {
                        $responseHeaders[$headerName] = $webResponse.Headers[$headerName]
                    }
                    
                    $stream = $webResponse.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $responseBody = $reader.ReadToEnd()
                    $reader.Close()
                    $stream.Close()
                    $webResponse.Close()
                }
                catch [System.Net.WebException] {
                    $errorResponse = $_.Exception.Response
                    if ($errorResponse) {
                        $statusCode = [int]$errorResponse.StatusCode
                        $statusDescription = $errorResponse.StatusDescription
                        
                        $responseHeaders = @{}
                        foreach ($headerName in $errorResponse.Headers.AllKeys) {
                            $responseHeaders[$headerName] = $errorResponse.Headers[$headerName]
                        }
                        
                        $stream = $errorResponse.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($stream)
                        $responseBody = $reader.ReadToEnd()
                        $reader.Close()
                        $stream.Close()
                    }
                    else {
                        throw
                    }
                }
            }
            catch {
                Write-Log "Request failed with exception: $($_.Exception.Message)" "ERROR"
                Write-Log "Exception Type: $($_.Exception.GetType().FullName)" "ERROR"
                
                if ($_.Exception.InnerException) {
                    Write-Log "Inner Exception: $($_.Exception.InnerException.Message)" "ERROR"
                }
            }
            
            $stopwatch.Stop()
            $elapsed = $stopwatch.ElapsedMilliseconds
            
            Write-Log "Request completed in ${elapsed}ms" "INFO"
            
            if ($statusCode) {
                Write-Log "HTTP Status Code: $statusCode - $statusDescription" "INFO"
                
                Write-Log "Response Headers:" "DEBUG"
                if ($responseHeaders) {
                    foreach ($key in $responseHeaders.Keys) {
                        Write-Log "  ${key}: $($responseHeaders[$key])" "DEBUG"
                    }
                }
                
                if ($responseBody) {
                    Write-Log "Response Body Length: $($responseBody.Length) characters" "INFO"
                    
                    if ($responseBody.Length -lt 2000) {
                        Write-Log "Response Body: $responseBody" "DEBUG"
                    }
                    else {
                        Write-Log "Response Body (truncated): $($responseBody.Substring(0, 2000))..." "DEBUG"
                    }
                    
                    try {
                        $jsonResponse = $responseBody | ConvertFrom-Json
                        Write-Log "Response parsed as JSON successfully" "INFO"
                        
                        if ($jsonResponse.error) {
                            Write-Log "API Error Code: $($jsonResponse.error.code)" "ERROR"
                            Write-Log "API Error Message: $($jsonResponse.error.message)" "ERROR"
                        }
                        
                        if ($jsonResponse.displayName) {
                            Write-Log "User Display Name: $($jsonResponse.displayName)" "INFO"
                        }
                        
                        if ($jsonResponse.userPrincipalName) {
                            Write-Log "User Principal Name: $($jsonResponse.userPrincipalName)" "INFO"
                        }
                        
                        if ($jsonResponse.id) {
                            Write-Log "Resource ID: $($jsonResponse.id)" "INFO"
                        }
                    }
                    catch {
                        Write-Log "Response is not valid JSON or parsing failed" "DEBUG"
                    }
                }
                
                if ($statusCode -ge 200 -and $statusCode -lt 300) {
                    Write-Log "Authentication SUCCESSFUL - Token is valid" "SUCCESS"
                    $testSuccessful = $true
                    $testEndpoint = $endpoint.Url
                    
                    if ($TestType -ne "Original") {
                        Write-Banner "!!! CRITICAL SECURITY ISSUE DETECTED !!!"
                        Write-Log "TAMPERED TOKEN AUTHENTICATED SUCCESSFULLY!" "CRITICAL"
                        Write-Log "Token Type: $TestType" "CRITICAL"
                        Write-Log "Endpoint: $($endpoint.Url)" "CRITICAL"
                        Write-Log "Status Code: $statusCode" "CRITICAL"
                        Write-Banner "!!! THIS INDICATES A SERIOUS VULNERABILITY !!!"
                    }
                }
                elseif ($statusCode -eq 401) {
                    Write-Log "Authentication FAILED - Token is invalid or expired (401 Unauthorized)" "ERROR"
                }
                elseif ($statusCode -eq 403) {
                    Write-Log "Authentication succeeded but access DENIED (403 Forbidden)" "WARN"
                }
                else {
                    Write-Log "Unexpected status code: $statusCode" "WARN"
                }
            }
        }
        catch {
            Write-Log "Unexpected error during API test: $($_.Exception.Message)" "ERROR"
            Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
        }
        
        Write-Log "" "INFO"
    }
    
    $script:AuthenticationResults += @{
        TestType = $TestType
        Success = $testSuccessful
        Endpoint = $testEndpoint
        IsTampered = ($TestType -ne "Original")
    }
    
    Write-Log "=== API Authentication Test Complete ===" "INFO"
}

function Test-AuthenticationWithModifiedTokens {
    param(
        [object]$ParsedJWT,
        [string]$OriginalToken,
        [object]$TokenData
    )
    
    Write-Log "=== Testing Authentication with Modified Tokens ===" "INFO"
    
    Write-Log "--- Testing with Original Token ---" "INFO"
    Test-APIAuthentication -Token $OriginalToken -TokenData $TokenData -TestType "Original"
    
    Write-Log "--- Testing with Re-signed Token (RSA) ---" "INFO"
    $rsaKey = New-RSAKey -KeySize 2048
    if ($rsaKey) {
        $signature = Sign-JWTWithRSA -SigningInput $ParsedJWT.SigningInput -RSAKey $rsaKey -Algorithm "RS256"
        if ($signature) {
            $resignedToken = Build-JWT -HeaderBase64 $ParsedJWT.HeaderBase64 -PayloadBase64 $ParsedJWT.PayloadBase64 -Signature $signature
            Write-Log "Created re-signed token with RSA" "INFO"
            Test-APIAuthentication -Token $resignedToken -TokenData $TokenData -TestType "Re-signed RSA"
        }
        $rsaKey.Dispose()
    }
    
    Write-Log "--- Testing with Re-signed Token (ECDSA) ---" "INFO"
    $ecdsaKey = New-ECDSAKey -Curve "nistP256"
    if ($ecdsaKey) {
        $signature = Sign-JWTWithECDSA -SigningInput $ParsedJWT.SigningInput -ECDSAKey $ecdsaKey -Algorithm "ES256"
        if ($signature) {
            $resignedToken = Build-JWT -HeaderBase64 $ParsedJWT.HeaderBase64 -PayloadBase64 $ParsedJWT.PayloadBase64 -Signature $signature
            Write-Log "Created re-signed token with ECDSA" "INFO"
            Test-APIAuthentication -Token $resignedToken -TokenData $TokenData -TestType "Re-signed ECDSA"
        }
        $ecdsaKey.Dispose()
    }
    
    Write-Log "--- Testing with Padded Signature Token ---" "INFO"
    $rsaKey2 = New-RSAKey -KeySize 2048
    if ($rsaKey2) {
        $additionalSignature = Sign-JWTWithRSA -SigningInput $ParsedJWT.SigningInput -RSAKey $rsaKey2 -Algorithm "RS256"
        if ($additionalSignature) {
            $combinedSignature = [byte[]]::new($ParsedJWT.SignatureBytes.Length + $additionalSignature.Length)
            [Array]::Copy($ParsedJWT.SignatureBytes, 0, $combinedSignature, 0, $ParsedJWT.SignatureBytes.Length)
            [Array]::Copy($additionalSignature, 0, $combinedSignature, $ParsedJWT.SignatureBytes.Length, $additionalSignature.Length)
            
            $paddedToken = Build-JWT -HeaderBase64 $ParsedJWT.HeaderBase64 -PayloadBase64 $ParsedJWT.PayloadBase64 -Signature $combinedSignature
            Write-Log "Created padded signature token" "INFO"
            Test-APIAuthentication -Token $paddedToken -TokenData $TokenData -TestType "Padded Signature"
        }
        $rsaKey2.Dispose()
    }
    
    Write-Log "=== Modified Token Authentication Tests Complete ===" "INFO"
}

Write-Log "========================================" "INFO"
Write-Log "JWT Signing Verification Test Tool" "INFO"
Write-Log "Log File: $logFile" "INFO"
Write-Log "========================================" "INFO"

if (-not (Test-Path $InputFile)) {
    Write-Log "Input file not found: $InputFile" "ERROR"
    Write-Log "Please provide a valid JSON file with JWT tokens" "ERROR"
    exit 1
}

Write-Log "Reading input file: $InputFile" "INFO"

try {
    $jsonContent = Get-Content -Path $InputFile -Raw | ConvertFrom-Json
    Write-Log "JSON file loaded successfully" "INFO"
    
    if ($jsonContent.jwt_tokens) {
        Write-Log "Found $($jsonContent.jwt_tokens.Count) JWT tokens" "INFO"
        
        for ($i = 0; $i -lt [Math]::Min(3, $jsonContent.jwt_tokens.Count); $i++) {
            $tokenData = $jsonContent.jwt_tokens[$i]
            
            Write-Log "========================================" "INFO"
            Write-Log "Processing Token $($i + 1) of $($jsonContent.jwt_tokens.Count)" "INFO"
            Write-Log "========================================" "INFO"
            
            if ($tokenData.raw) {
                Write-Log "Token Source: $($tokenData.source)" "INFO"
                Write-Log "Token Algorithm: $($tokenData.header.alg)" "INFO"
                Write-Log "Token Issuer: $($tokenData.payload.iss)" "INFO"
                
                $parsedToken = Parse-JWT -Token $tokenData.raw
                
                if ($parsedToken) {
                    Write-Log "Token parsed successfully" "INFO"
                    
                    if ($TestResigning) {
                        Test-JWTResigning -ParsedJWT $parsedToken -OriginalToken $tokenData.raw
                    }
                    
                    if ($TestPadding) {
                        Test-SignaturePadding -ParsedJWT $parsedToken -OriginalToken $tokenData.raw
                    }
                    
                    if ($TestAuthentication) {
                        Test-AuthenticationWithModifiedTokens -ParsedJWT $parsedToken -OriginalToken $tokenData.raw -TokenData $tokenData
                    }
                    
                    if (-not $TestResigning -and -not $TestPadding -and -not $TestAuthentication) {
                        Test-JWTResigning -ParsedJWT $parsedToken -OriginalToken $tokenData.raw
                        Write-Log "" "INFO"
                        Test-SignaturePadding -ParsedJWT $parsedToken -OriginalToken $tokenData.raw
                        Write-Log "" "INFO"
                        Test-AuthenticationWithModifiedTokens -ParsedJWT $parsedToken -OriginalToken $tokenData.raw -TokenData $tokenData
                    }
                }
            }
            
            Write-Log "" "INFO"
        }
    }
    else {
        Write-Log "No jwt_tokens array found in JSON" "ERROR"
    }
}
catch {
    Write-Log "Error processing file: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
}

Write-Log "========================================" "INFO"
Write-Log "Test execution completed" "INFO"
Write-Log "Results saved to: $logFile" "INFO"
Write-Log "========================================" "INFO"

if ($script:AuthenticationResults.Count -gt 0) {
    Write-Log "" "INFO"
    Write-Banner "AUTHENTICATION TEST SUMMARY"
    Write-Log "" "INFO"
    
    $tamperedSuccesses = $script:AuthenticationResults | Where-Object { $_.IsTampered -eq $true -and $_.Success -eq $true }
    $originalSuccesses = $script:AuthenticationResults | Where-Object { $_.IsTampered -eq $false -and $_.Success -eq $true }
    $totalTests = $script:AuthenticationResults.Count
    $totalSuccess = ($script:AuthenticationResults | Where-Object { $_.Success -eq $true }).Count
    
    Write-Log "Total Authentication Tests: $totalTests" "INFO"
    Write-Log "Successful Authentications: $totalSuccess" "INFO"
    Write-Log "" "INFO"
    
    if ($originalSuccesses.Count -gt 0) {
        Write-Log "Original Token Results:" "INFO"
        foreach ($result in $originalSuccesses) {
            Write-Log "  [SUCCESS] $($result.TestType) - $($result.Endpoint)" "SUCCESS"
        }
        Write-Log "" "INFO"
    }
    
    Write-Log "Tampered Token Results:" "INFO"
    $tamperedTests = $script:AuthenticationResults | Where-Object { $_.IsTampered -eq $true }
    if ($tamperedTests.Count -eq 0) {
        Write-Log "  No tampered tokens were tested" "INFO"
    }
    else {
        foreach ($result in $tamperedTests) {
            if ($result.Success) {
                Write-Log "  [SUCCESS] $($result.TestType) - $($result.Endpoint)" "CRITICAL"
            }
            else {
                Write-Log "  [FAILED] $($result.TestType) - Authentication rejected (Expected)" "INFO"
            }
        }
    }
    
    Write-Log "" "INFO"
    
    if ($tamperedSuccesses.Count -gt 0) {
        Write-Banner "!!! CRITICAL SECURITY VULNERABILITY DETECTED !!!"
        Write-Log "" "CRITICAL"
        Write-Log "NUMBER OF TAMPERED TOKENS THAT AUTHENTICATED: $($tamperedSuccesses.Count)" "CRITICAL"
        Write-Log "" "CRITICAL"
        Write-Log "Details of successful tampered authentications:" "CRITICAL"
        foreach ($result in $tamperedSuccesses) {
            Write-Log "  - Token Type: $($result.TestType)" "CRITICAL"
            Write-Log "    Endpoint: $($result.Endpoint)" "CRITICAL"
            Write-Log "" "CRITICAL"
        }
        Write-Log "This indicates the API is NOT properly validating JWT signatures!" "CRITICAL"
        Write-Log "The following attack vectors were successful:" "CRITICAL"
        foreach ($result in $tamperedSuccesses) {
            Write-Log "  * $($result.TestType)" "CRITICAL"
        }
        Write-Log "" "CRITICAL"
        Write-Banner "!!! IMMEDIATE INVESTIGATION REQUIRED !!!"
    }
    else {
        Write-Log "========================================" "SUCCESS"
        Write-Log "SECURITY CHECK PASSED" "SUCCESS"
        Write-Log "All tampered tokens were properly rejected" "SUCCESS"
        Write-Log "JWT signature validation is working correctly" "SUCCESS"
        Write-Log "========================================" "SUCCESS"
    }
}
