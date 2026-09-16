# ===========================================================================
# НАСТРОЙКИ
# ===========================================================================

# Временно: 10.0.3.10 для проверок, затем вернуть 10.0.1.235
$FtpHost = "10.0.3.10"
$FtpPort = 2121
$FtpUser = "rkn"
$FtpPassword = "secret123"

$OperatorName = "ООО СМАРТС-СИТИС"
$Inn = "631403951052"
$Ogrn = "1186313077488"
$Email = "smarts@smarts.ru"

# Параметр выбора сертификата — ИНН в Subject
$CertInnFilter = "6324094850"

# ===========================================================================
# КОД
# ===========================================================================

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(866)
[Console]::InputEncoding  = [System.Text.Encoding]::GetEncoding(866)

Write-Host "========================================="
Write-Host "  RKN Signature Generator"
Write-Host "========================================="
Write-Host ""

# 1. Создание request.xml
Write-Host "[1/3] Sozdanie request.xml..."

$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$xml  = "<?xml version=`"1.0`" encoding=`"windows-1251`"?>`r`n"
$xml += "<request>`r`n"
$xml += "  <requestTime>$timestamp</requestTime>`r`n"
$xml += "  <operatorName>$OperatorName</operatorName>`r`n"
$xml += "  <inn>$Inn</inn>`r`n"
$xml += "  <ogrn>$Ogrn</ogrn>`r`n"
$xml += "  <email>$Email</email>`r`n"
$xml += "</request>"

$enc1251 = [System.Text.Encoding]::GetEncoding(1251)
[System.IO.File]::WriteAllText("$PSScriptRoot\request.xml", $xml, $enc1251)

Write-Host "    Gotovo: request.xml" -ForegroundColor Green

# 2. Подписание
Write-Host ""
Write-Host "[2/3] Podpisanie..."

# --- Поиск cryptcp.exe ---
$cryptcp = $null
$cryptcpPaths = @(
    "$PSScriptRoot\cryptcp.exe",
    "C:\Program Files\Crypto Pro\CSP\cryptcp.exe",
    "C:\Program Files (x86)\Crypto Pro\CSP\cryptcp.exe",
    "C:\Program Files\Crypto Pro\CSP\cryptcp.x64.exe",
    "C:\Program Files (x86)\Crypto Pro\CSP\cryptcp.x64.exe",
    "C:\Program Files\Crypto Pro\CryptoPro PKI Client\cryptcp.exe",
    "C:\Program Files (x86)\Crypto Pro\CryptoPro PKI Client\cryptcp.exe"
)

foreach ($path in $cryptcpPaths) {
    if (Test-Path $path) { $cryptcp = $path; break }
}
if (-not $cryptcp) {
    $found = Get-Command cryptcp.exe -ErrorAction SilentlyContinue
    if ($found) { $cryptcp = $found.Source }
}

if ($cryptcp) {
    Write-Host "    cryptcp: $cryptcp" -ForegroundColor Green
} else {
    Write-Host "    cryptcp.exe ne nayden, budet ispolzovan CAdESCOM COM" -ForegroundColor Yellow
}

# --- Получаем сертификаты через .NET ---
Write-Host "    Poluchaem spisok sertifikatov..." -ForegroundColor Gray

$allCerts = @(Get-ChildItem -Path "Cert:\CurrentUser\My" |
    Where-Object { $_.HasPrivateKey -and $_.NotBefore -le (Get-Date) -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending)

if ($allCerts.Count -eq 0) {
    Write-Host "    Net podhodyaschih sertifikatov s zakrytym klyuchom!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "    Vse sertifikaty:" -ForegroundColor Cyan
for ($i = 0; $i -lt $allCerts.Count; $i++) {
    $c = $allCerts[$i]
    Write-Host ("    [{0}] {1}  (do {2:dd.MM.yyyy})" -f $i, $c.Subject, $c.NotAfter) -ForegroundColor White
}
Write-Host ""

# --- Фильтрация по ИНН в Subject ---
Write-Host "    Filtraciya: INN=$CertInnFilter" -ForegroundColor Gray

$matchedCerts = @()

foreach ($c in $allCerts) {
    $subject = $c.Subject
    $innMatch = $false

    if ($subject -like "*INN=$CertInnFilter*") { $innMatch = $true }
    if ($subject -match "1\.2\.643\.3\.131\.1\.1=0*$CertInnFilter") { $innMatch = $true }
    if (-not $innMatch -and $subject -like "*$CertInnFilter*") { $innMatch = $true }

    if ($innMatch) { $matchedCerts += $c }
}

if ($matchedCerts.Count -eq 0) {
    Write-Host "    Sertifikat s INN=$CertInnFilter ne nayden!" -ForegroundColor Red
    Write-Host "    Proverte Subject sertifikata vyshen v spiske." -ForegroundColor Yellow
    exit 1
}

if ($matchedCerts.Count -gt 1) {
    Write-Host "    Naydeno neskolko sertifikatov ($($matchedCerts.Count))!" -ForegroundColor Yellow
    Write-Host "    Budet ispolzovan pervyy (samyy svezhiy po sroku)." -ForegroundColor Yellow
}

$cert = $matchedCerts[0]
$thumbprint = $cert.Thumbprint

Write-Host "    Vybran: $($cert.Subject)" -ForegroundColor Cyan
Write-Host "    Thumbprint: $thumbprint" -ForegroundColor Gray

# Удаляем старую подпись
$sigPath = "$PSScriptRoot\request.xml.sig"
if (Test-Path $sigPath) {
    Remove-Item $sigPath -Force
    Write-Host "    Udalen staryy .sig" -ForegroundColor Gray
}

# --- Подписание ---
Write-Host "    Podpisanie..." -ForegroundColor Gray

if ($cryptcp) {
    & $cryptcp -sign -detached -der -cert -thumbprint $thumbprint "$PSScriptRoot\request.xml" $sigPath

    if ($LASTEXITCODE -ne 0) {
        Write-Host "    Oshibka podpisi! (kod: 0x$('{0:X8}' -f $LASTEXITCODE))" -ForegroundColor Red
        Write-Host "    Proverte: zakrytyy klyuch, srok sertifikata, PIN-kod tokena." -ForegroundColor Yellow
        exit 1
    }
    if (!(Test-Path $sigPath)) {
        Write-Host "    Fail .sig ne sozdan!" -ForegroundColor Red
        exit 1
    }

} else {
    # ---- CAdESCOM COM (фолбэк) ----

    $CAPICOM_CURRENT_USER_STORE         = 2
    $CAPICOM_MY_STORE                   = "My"
    $CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2
    $CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0
    $CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN = 1
    $CADES_BES                          = 1
    $CADESCOM_BASE64_TO_BINARY          = 1

    try {
        Write-Host "    [COM] Sozdanie Store..." -ForegroundColor Gray
        $store = New-Object -ComObject CAPICOM.Store -ErrorAction Stop

        Write-Host "    [COM] Otkrytie hranilishha..." -ForegroundColor Gray
        $store.Open($CAPICOM_CURRENT_USER_STORE, $CAPICOM_MY_STORE, $CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED)

        Write-Host "    [COM] Poisk sertifikata po thumbprint..." -ForegroundColor Gray
        $comCert = $null

        try {
            $foundCerts = $store.Certificates.Find($CAPICOM_CERTIFICATE_FIND_SHA1_HASH, $thumbprint)
            if ($foundCerts.Count -gt 0) {
                $comCert = $foundCerts.Item(1)
            }
        } catch {
            Write-Host "    [COM] Find ne srabotal: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        if ($null -eq $comCert) {
            Write-Host "    [COM] Ruchnoy poisk po thumbprint..." -ForegroundColor Gray
            $storeCerts = $store.Certificates
            $certCount = $storeCerts.Count

            for ($i = 1; $i -le $certCount; $i++) {
                $c = $storeCerts.Item($i)
                $cThumb = ($c.Thumbprint -replace '\s','').ToUpper()
                if ($cThumb -eq $thumbprint.ToUpper()) {
                    $comCert = $c
                    break
                }
            }
        }

        if ($null -eq $comCert) {
            Write-Host "    [COM] Sertifikat ne nayden v COM store!" -ForegroundColor Red
            $store.Close()
            exit 1
        }

        $store.Close()

        Write-Host "    [COM] Sozdanie CPSigner..." -ForegroundColor Gray
        $signer = New-Object -ComObject CAdESCOM.CPSigner -ErrorAction Stop
        $signer.Certificate = $comCert
        $signer.Options = $CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN

        Write-Host "    [COM] Chtenie faila..." -ForegroundColor Gray
        $fileBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\request.xml")
        $base64Content = [Convert]::ToBase64String($fileBytes)

        Write-Host "    [COM] Sozdanie CadesSignedData..." -ForegroundColor Gray
        $signedData = New-Object -ComObject CAdESCOM.CadesSignedData -ErrorAction Stop
        $signedData.ContentEncoding = $CADESCOM_BASE64_TO_BINARY
        $signedData.Content = $base64Content

        Write-Host "    [COM] Vyzov SignCades..." -ForegroundColor Gray
        $signatureBase64 = $null

        try {
            $signatureBase64 = $signedData.SignCades($signer, $CADES_BES, $true)
        } catch {
            Write-Host "    [COM] SignCades(3 args) ne udalsya, popytka s 4..." -ForegroundColor Yellow
            $signatureBase64 = $signedData.SignCades($signer, $CADES_BES, $true, 0)
        }

        if ([string]::IsNullOrEmpty($signatureBase64)) {
            Write-Host "    [COM] SignCades vernul pustotu!" -ForegroundColor Red
            exit 1
        }

        Write-Host "    [COM] Dekodirovanie i sohranenie..." -ForegroundColor Gray
        $sigBytes = [Convert]::FromBase64String($signatureBase64)
        [System.IO.File]::WriteAllBytes($sigPath, $sigBytes)

        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($signedData) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($signer) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($comCert) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($store) | Out-Null

    } catch {
        Write-Host "    Oshibka CAdESCOM: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    Ustanovite cryptcp.exe rjadom so skriptom ili KriptoPro ECP Browser plug-in." -ForegroundColor Yellow
        exit 1
    }

    if (!(Test-Path $sigPath)) {
        Write-Host "    Fail .sig ne sozdan!" -ForegroundColor Red
        exit 1
    }
}

Write-Host "    Podpis sozdan: request.xml.sig" -ForegroundColor Green

# 3. Отправка на FTP (raw TCP)
Write-Host ""
Write-Host "[3/3] Otpravka na FTP..."

Write-Host "    Server: $FtpHost`:$FtpPort" -ForegroundColor Gray

$sigBytes = [System.IO.File]::ReadAllBytes($sigPath)
Write-Host "    Razmer .sig: $($sigBytes.Length) bayt" -ForegroundColor Gray

try {
    # --- Control-соединение ---
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($FtpHost, $FtpPort)
    $client.NoDelay = $true
    $client.ReceiveTimeout = 30000
    $client.SendTimeout = 30000

    $ctrlStream = $client.GetStream()
    # ASCII — никаких BOM, FTP-протокол использует ASCII
    $ctrlReader = New-Object System.IO.StreamReader($ctrlStream, [System.Text.Encoding]::ASCII)
    $ctrlWriter = New-Object System.IO.StreamWriter($ctrlStream, [System.Text.Encoding]::ASCII)
    $ctrlWriter.AutoFlush = $true
    $ctrlWriter.NewLine = "`r`n"

    # 1. Ждём приветствие
    $welcome = $ctrlReader.ReadLine()
    Write-Host "    <- $welcome" -ForegroundColor DarkGray

    # 2. Авторизация
    Write-Host "    -> USER $FtpUser" -ForegroundColor DarkGray
    $ctrlWriter.WriteLine("USER $FtpUser")
    $userResp = $ctrlReader.ReadLine()
    Write-Host "    <- $userResp" -ForegroundColor DarkGray

    Write-Host "    -> PASS ***" -ForegroundColor DarkGray
    $ctrlWriter.WriteLine("PASS $FtpPassword")
    $passResp = $ctrlReader.ReadLine()
    Write-Host "    <- $passResp" -ForegroundColor DarkGray

    if ($passResp -notlike "230*") {
        Write-Host "    Oshibka autentifikatsii: $passResp" -ForegroundColor Red
        $client.Close()
        exit 1
    }

    # 3. Бинарный режим
    Write-Host "    -> TYPE I" -ForegroundColor DarkGray
    $ctrlWriter.WriteLine("TYPE I")
    $typeResp = $ctrlReader.ReadLine()
    Write-Host "    <- $typeResp" -ForegroundColor DarkGray

    # 4. PASV
    Write-Host "    -> PASV" -ForegroundColor DarkGray
    $ctrlWriter.WriteLine("PASV")
    $pasvResp = $ctrlReader.ReadLine()
    Write-Host "    <- $pasvResp" -ForegroundColor DarkGray

    if ($pasvResp -notlike "227*") {
        Write-Host "    Server ne podderzhivaet PASV: $pasvResp" -ForegroundColor Red
        $client.Close()
        exit 1
    }

    # Парсим содержимое скобок: (h1,h2,h3,h4,p1,p2)
    $pasvResp = $pasvResp.Trim()
    $dataHost = $null
    $dataPort = 0

    $openIdx = $pasvResp.IndexOf('(')
    $closeIdx = $pasvResp.IndexOf(')')

    if ($openIdx -ge 0 -and $closeIdx -gt $openIdx) {
        $parenContent = $pasvResp.Substring($openIdx + 1, $closeIdx - $openIdx - 1)
        $nums = $parenContent -split ','
        if ($nums.Count -eq 6) {
            $dataHost = "$($nums[0]).$($nums[1]).$($nums[2]).$($nums[3])"
            $dataPort = ([int]$nums[4] * 256) + [int]$nums[5]
        }
    }

    if ($null -eq $dataHost -or $dataPort -eq 0) {
        Write-Host "    Ne udalos rasparst PASV: $pasvResp" -ForegroundColor Red
        $client.Close()
        exit 1
    }

    Write-Host "    Data: $dataHost`:$dataPort" -ForegroundColor Gray

    # 5. STOR
    Write-Host "    -> STOR request.xml.sig" -ForegroundColor DarkGray
    $ctrlWriter.WriteLine("STOR request.xml.sig")
    $storResp = $ctrlReader.ReadLine()
    Write-Host "    <- $storResp" -ForegroundColor DarkGray

    if ($storResp -notlike "150*") {
        Write-Host "    Server otklonil STOR: $storResp" -ForegroundColor Red
        $client.Close()
        exit 1
    }

    # 6. Подключаемся к data-порту и отправляем файл
    Write-Host "    Podklyuchenie k data-portu..." -ForegroundColor Gray
    $dataClient = New-Object System.Net.Sockets.TcpClient
    $dataClient.Connect($dataHost, $dataPort)
    $dataClient.NoDelay = $true
    $dataClient.SendTimeout = 30000

    $dataStream = $dataClient.GetStream()
    $dataStream.Write($sigBytes, 0, $sigBytes.Length)
    $dataStream.Flush()

    # Закрываем data-соединение — сервер получит EOF
    $dataStream.Close()
    $dataClient.Close()

    Write-Host "    Data otpravlen" -ForegroundColor Gray

    # 7. Ждём 226
    $doneResp = $ctrlReader.ReadLine()
    Write-Host "    <- $doneResp" -ForegroundColor DarkGray

    # 8. QUIT
    Write-Host "    -> QUIT" -ForegroundColor DarkGray
    $ctrlWriter.WriteLine("QUIT")
    $quitResp = $ctrlReader.ReadLine()
    Write-Host "    <- $quitResp" -ForegroundColor DarkGray

    $client.Close()

    if ($doneResp -like "226*") {
        Write-Host "    FTP: OK ($doneResp)" -ForegroundColor Green
    } else {
        Write-Host "    FTP: neprivet: $doneResp" -ForegroundColor Red
        exit 1
    }

} catch {
    Write-Host "    Oshibka FTP: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================="
Write-Host "  GOTOVO!"
Write-Host "========================================="