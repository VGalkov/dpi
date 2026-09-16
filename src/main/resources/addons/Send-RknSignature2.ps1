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

# --- Логирование ---
$logPath = "$PSScriptRoot\rkn_signature.log"
$lockPath = "$PSScriptRoot\rkn_signature.lock"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts [$Level] $Message"
    $line | Out-File -FilePath $logPath -Append -Encoding UTF8
    # Дублируем в консоль для интерактивного запуска
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARN"  { Write-Host $Message -ForegroundColor Yellow }
        "OK"    { Write-Host $Message -ForegroundColor Green }
        "DBG"   { Write-Host $Message -ForegroundColor DarkGray }
        default { Write-Host $Message }
    }
}

# --- Защита от параллельных запусков ---
if (Test-Path $lockPath) {
    $lockAge = (Get-Date) - (Get-Item $lockPath).LastWriteTime
    if ($lockAge.TotalMinutes -lt 10) {
        Write-Log "Другой экземпляр уже работает. Выход." "WARN"
        exit 0
    } else {
        Write-Log "Найден устаревший lock-файл ($([int]$lockAge.TotalMinutes) мин). Удаляю." "WARN"
        Remove-Item $lockPath -Force
    }
}
New-Item -Path $lockPath -ItemType File -Force | Out-Null

# Функция для гарантированного выхода с очисткой
function Stop-Script {
    param([int]$ExitCode = 0)
    if (Test-Path $lockPath) {
        Remove-Item $lockPath -Force -ErrorAction SilentlyContinue
    }
    exit $ExitCode
}

Write-Log "=========================================" "OK"
Write-Log "  RKN Signature Generator"
Write-Log "========================================="
Write-Log ""

# 1. Создание request.xml
Write-Log "[1/3] Sozdanie request.xml..."

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

Write-Log "    Gotovo: request.xml" "OK"

# 2. Подписание
Write-Log ""
Write-Log "[2/3] Podpisanie..."

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
    Write-Log "    cryptcp: $cryptcp" "OK"
} else {
    Write-Log "    cryptcp.exe ne nayden, budet ispolzovan CAdESCOM COM" "WARN"
}

# --- Получаем сертификаты через .NET ---
Write-Log "    Poluchaem spisok sertifikatov..." "DBG"

$allCerts = @(Get-ChildItem -Path "Cert:\CurrentUser\My" |
    Where-Object { $_.HasPrivateKey -and $_.NotBefore -le (Get-Date) -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending)

if ($allCerts.Count -eq 0) {
    Write-Log "    Net podhodyaschih sertifikatov s zakrytym klyuchom!" "ERROR"
    Stop-Script 1
}

Write-Log ""
Write-Log "    Vse sertifikaty:"
for ($i = 0; $i -lt $allCerts.Count; $i++) {
    $c = $allCerts[$i]
    Write-Log ("    [{0}] {1}  (do {2:dd.MM.yyyy})" -f $i, $c.Subject, $c.NotAfter)
}
Write-Log ""

# --- Фильтрация по ИНН в Subject ---
Write-Log "    Filtraciya: INN=$CertInnFilter" "DBG"

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
    Write-Log "    Sertifikat s INN=$CertInnFilter ne nayden!" "ERROR"
    Write-Log "    Proverte Subject sertifikata vyshen v spiske." "WARN"
    Stop-Script 1
}

if ($matchedCerts.Count -gt 1) {
    Write-Log "    Naydeno neskolko sertifikatov ($($matchedCerts.Count))!" "WARN"
    Write-Log "    Budet ispolzovan pervyy (samyy svezhiy po sroku)." "WARN"
}

$cert = $matchedCerts[0]
$thumbprint = $cert.Thumbprint

Write-Log "    Vybran: $($cert.Subject)"
Write-Log "    Thumbprint: $thumbprint" "DBG"

# Удаляем старую подпись
$sigPath = "$PSScriptRoot\request.xml.sig"
if (Test-Path $sigPath) {
    Remove-Item $sigPath -Force
    Write-Log "    Udalen staryy .sig" "DBG"
}

# --- Подписание ---
Write-Log "    Podpisanie..." "DBG"

if ($cryptcp) {
    & $cryptcp -sign -detached -der -cert -thumbprint $thumbprint "$PSScriptRoot\request.xml" $sigPath

    if ($LASTEXITCODE -ne 0) {
        Write-Log "    Oshibka podpisi! (kod: 0x$('{0:X8}' -f $LASTEXITCODE))" "ERROR"
        Write-Log "    Proverte: zakrytyy klyuch, srok sertifikata, PIN-kod tokena." "WARN"
        Stop-Script 1
    }
    if (!(Test-Path $sigPath)) {
        Write-Log "    Fail .sig ne sozdan!" "ERROR"
        Stop-Script 1
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
        Write-Log "    [COM] Sozdanie Store..." "DBG"
        $store = New-Object -ComObject CAPICOM.Store -ErrorAction Stop

        Write-Log "    [COM] Otkrytie hranilishha..." "DBG"
        $store.Open($CAPICOM_CURRENT_USER_STORE, $CAPICOM_MY_STORE, $CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED)

        Write-Log "    [COM] Poisk sertifikata po thumbprint..." "DBG"
        $comCert = $null

        try {
            $foundCerts = $store.Certificates.Find($CAPICOM_CERTIFICATE_FIND_SHA1_HASH, $thumbprint)
            if ($foundCerts.Count -gt 0) {
                $comCert = $foundCerts.Item(1)
            }
        } catch {
            Write-Log "    [COM] Find ne srabotal: $($_.Exception.Message)" "WARN"
        }

        if ($null -eq $comCert) {
            Write-Log "    [COM] Ruchnoy poisk po thumbprint..." "DBG"
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
            Write-Log "    [COM] Sertifikat ne nayden v COM store!" "ERROR"
            $store.Close()
            Stop-Script 1
        }

        $store.Close()

        Write-Log "    [COM] Sozdanie CPSigner..." "DBG"
        $signer = New-Object -ComObject CAdESCOM.CPSigner -ErrorAction Stop
        $signer.Certificate = $comCert
        $signer.Options = $CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN

        Write-Log "    [COM] Chtenie faila..." "DBG"
        $fileBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\request.xml")
        $base64Content = [Convert]::ToBase64String($fileBytes)

        Write-Log "    [COM] Sozdanie CadesSignedData..." "DBG"
        $signedData = New-Object -ComObject CAdESCOM.CadesSignedData -ErrorAction Stop
        $signedData.ContentEncoding = $CADESCOM_BASE64_TO_BINARY
        $signedData.Content = $base64Content

        Write-Log "    [COM] Vyzov SignCades..." "DBG"
        $signatureBase64 = $null

        try {
            $signatureBase64 = $signedData.SignCades($signer, $CADES_BES, $true)
        } catch {
            Write-Log "    [COM] SignCades(3 args) ne udalsya, popytka s 4..." "WARN"
            $signatureBase64 = $signedData.SignCades($signer, $CADES_BES, $true, 0)
        }

        if ([string]::IsNullOrEmpty($signatureBase64)) {
            Write-Log "    [COM] SignCades vernul pustotu!" "ERROR"
            Stop-Script 1
        }

        Write-Log "    [COM] Dekodirovanie i sohranenie..." "DBG"
        $sigBytes = [Convert]::FromBase64String($signatureBase64)
        [System.IO.File]::WriteAllBytes($sigPath, $sigBytes)

        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($signedData) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($signer) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($comCert) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($store) | Out-Null

    } catch {
        Write-Log "    Oshibka CAdESCOM: $($_.Exception.Message)" "ERROR"
        Write-Log "    Ustanovite cryptcp.exe rjadom so skriptom ili KriptoPro ECP Browser plug-in." "WARN"
        Stop-Script 1
    }

    if (!(Test-Path $sigPath)) {
        Write-Log "    Fail .sig ne sozdan!" "ERROR"
        Stop-Script 1
    }
}

Write-Log "    Podpis sozdan: request.xml.sig" "OK"

# 3. Отправка на FTP (raw TCP)
Write-Log ""
Write-Log "[3/3] Otpravka na FTP..."

Write-Log "    Server: $FtpHost`:$FtpPort" "DBG"

$sigBytes = [System.IO.File]::ReadAllBytes($sigPath)
Write-Log "    Razmer .sig: $($sigBytes.Length) bayt" "DBG"

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
    Write-Log "    <- $welcome" "DBG"

    # 2. Авторизация
    Write-Log "    -> USER $FtpUser" "DBG"
    $ctrlWriter.WriteLine("USER $FtpUser")
    $userResp = $ctrlReader.ReadLine()
    Write-Log "    <- $userResp" "DBG"

    Write-Log "    -> PASS ***" "DBG"
    $ctrlWriter.WriteLine("PASS $FtpPassword")
    $passResp = $ctrlReader.ReadLine()
    Write-Log "    <- $passResp" "DBG"

    if ($passResp -notlike "230*") {
        Write-Log "    Oshibka autentifikatsii: $passResp" "ERROR"
        $client.Close()
        Stop-Script 1
    }

    # 3. Бинарный режим
    Write-Log "    -> TYPE I" "DBG"
    $ctrlWriter.WriteLine("TYPE I")
    $typeResp = $ctrlReader.ReadLine()
    Write-Log "    <- $typeResp" "DBG"

    # 4. PASV
    Write-Log "    -> PASV" "DBG"
    $ctrlWriter.WriteLine("PASV")
    $pasvResp = $ctrlReader.ReadLine()
    Write-Log "    <- $pasvResp" "DBG"

    if ($pasvResp -notlike "227*") {
        Write-Log "    Server ne podderzhivaet PASV: $pasvResp" "ERROR"
        $client.Close()
        Stop-Script 1
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
        Write-Log "    Ne udalos rasparst PASV: $pasvResp" "ERROR"
        $client.Close()
        Stop-Script 1
    }

    Write-Log "    Data: $dataHost`:$dataPort" "DBG"

    # 5. STOR
    Write-Log "    -> STOR request.xml.sig" "DBG"
    $ctrlWriter.WriteLine("STOR request.xml.sig")
    $storResp = $ctrlReader.ReadLine()
    Write-Log "    <- $storResp" "DBG"

    if ($storResp -notlike "150*") {
        Write-Log "    Server otklonil STOR: $storResp" "ERROR"
        $client.Close()
        Stop-Script 1
    }

    # 6. Подключаемся к data-порту и отправляем файл
    Write-Log "    Podklyuchenie k data-portu..." "DBG"
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

    Write-Log "    Data otpravlen" "DBG"

    # 7. Ждём 226
    $doneResp = $ctrlReader.ReadLine()
    Write-Log "    <- $doneResp" "DBG"

    # 8. QUIT
    Write-Log "    -> QUIT" "DBG"
    $ctrlWriter.WriteLine("QUIT")
    $quitResp = $ctrlReader.ReadLine()
    Write-Log "    <- $quitResp" "DBG"

    $client.Close()

    if ($doneResp -like "226*") {
        Write-Log "    FTP: OK ($doneResp)" "OK"
    } else {
        Write-Log "    FTP: neprivet: $doneResp" "ERROR"
        Stop-Script 1
    }

} catch {
    Write-Log "    Oshibka FTP: $($_.Exception.Message)" "ERROR"
    Stop-Script 1
}

Write-Log ""
Write-Log "=========================================" "OK"
Write-Log "  GOTOVO!"
Write-Log "=========================================" "OK"

# Снимаем lock
if (Test-Path $lockPath) {
    Remove-Item $lockPath -Force -ErrorAction SilentlyContinue
}
