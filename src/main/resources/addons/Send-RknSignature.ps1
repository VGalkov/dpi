<#
.SYNOPSIS
    Генерация request.xml и подписи request.xml.sig, отправка на FTP-сервер DPI
.DESCRIPTION
    Скрипт выполняет:
    1. Генерация request.xml с текущим timestamp
    2. Подписание через CryptoPro cryptcp
    3. Отправка request.xml.sig на FTP-сервер DPI (10.0.1.235)
.PARAMETER FtpHost
    Адрес FTP-сервера DPI (по умолчанию: 10.0.1.235)
.PARAMETER FtpPort
    Порт FTP-сервера (по умолчанию: 2121)
.PARAMETER FtpUser
    Пользователь FTP (по умолчанию: rkn)
.PARAMETER FtpPassword
    Пароль FTP
.PARAMETER CertDn
    DN сертификата для подписи (по умолчанию: ищет первый действующий)
.PARAMETER OutputDir
    Директория для временных файлов (по умолчанию: текущая)
.EXAMPLE
    .\Send-RknSignature.ps1 -FtpHost 10.0.1.235 -FtpPassword "secret123"
#>

param(
    [string]$FtpHost = "10.0.1.235",
    [int]$FtpPort = 2121,
    [string]$FtpUser = "rkn",
    [Parameter(Mandatory=$true)]
    [string]$FtpPassword,
    [string]$CertDn = "",
    [string]$OutputDir = ".",
    [string]$OperatorName = "ООО ""Пример""",
    [string]$Inn = "1234567890",
    [string]$Ogrn = "1234567890123",
    [string]$Email = "admin@example.ru"
)

$ErrorActionPreference = "Stop"

# ============================================================================
# 1. Генерация request.xml
# ============================================================================

Write-Host "=== Генерация request.xml ===" -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$requestXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<request>
  <requestTime>$timestamp</requestTime>
  <operatorName>$OperatorName</operatorName>
  <inn>$Inn</inn>
  <ogrn>$Ogrn</ogrn>
  <email>$Email</email>
</request>
"@

$requestXmlPath = Join-Path $OutputDir "request.xml"
$requestXmlPath = (Resolve-Path $OutputDir).Path + "\request.xml"
Set-Content -Path $requestXmlPath -Value $requestXml -Encoding UTF8

Write-Host "Создан: $requestXmlPath" -ForegroundColor Green
Write-Host "Содержимое:" -ForegroundColor Gray
Get-Content $requestXmlPath | Write-Host

# ============================================================================
# 2. Подписание через CryptoPro
# ============================================================================

Write-Host "`n=== Подписание через CryptoPro ===" -ForegroundColor Cyan

# Поиск сертификата, если не указан
if ([string]::IsNullOrEmpty($CertDn)) {
    Write-Host "Поиск действующего сертификата..." -ForegroundColor Yellow

    # Попытка найти через certmgr
    $certOutput = & "C:\Program Files\Crypto Pro\CSP\certmgr.exe" -list -store u 2>&1
    $certOutput | Write-Host

    # Извлекаем первый сертификат (упрощённо)
    $match = $certOutput | Select-String -Pattern "\[.*\].*<([^>]+)>" | Select-Object -First 1
    if ($match) {
        $CertDn = $match.Matches[0].Groups[1].Value
        Write-Host "Найден сертификат: $CertDn" -ForegroundColor Green
    } else {
        throw "Не удалось найти сертификат. Укажите -CertDn вручную"
    }
}

# Подписание
$signaturePath = Join-Path $OutputDir "request.xml.sig"
$signaturePath = (Resolve-Path $OutputDir).Path + "\request.xml.sig"

$cryptcpPath = "C:\Program Files\Crypto Pro\CSP\cryptcp.exe"
if (!(Test-Path $cryptcpPath)) {
    $cryptcpPath = "C:\Program Files (x86)\Crypto Pro\CSP\cryptcp.exe"
}

if (!(Test-Path $cryptcpPath)) {
    throw "CryptoPro cryptcp.exe не найден"
}

Write-Host "Подписание: $cryptcpPath -sign -detached -dn `"$CertDn`" $requestXmlPath $signaturePath" -ForegroundColor Yellow

& $cryptcpPath -sign -detached -dn $CertDn $requestXmlPath $signaturePath

if ($LASTEXITCODE -ne 0) {
    throw "Ошибка подписания (код: $LASTEXITCODE)"
}

if (!(Test-Path $signaturePath)) {
    throw "Файл подписи не создан"
}

$signatureSize = (Get-Item $signaturePath).Length
Write-Host "Подпись создана: $signaturePath ($signatureSize байт)" -ForegroundColor Green

# ============================================================================
# 3. Отправка на FTP-сервер DPI
# ============================================================================

Write-Host "`n=== Отправка на FTP-сервер ===" -ForegroundColor Cyan
Write-Host "Сервер: $FtpHost:$FtpPort"
Write-Host "Пользователь: $FtpUser"
Write-Host "Файл: request.xml.sig"

# Создание FTP-запроса
$ftpUri = "ftp://$FtpHost`:$FtpPort/request.xml.sig"
Write-Host "URI: $ftpUri" -ForegroundColor Gray

$ftpRequest = [System.Net.FtpWebRequest]::Create($ftpUri)
$ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
$ftpRequest.Credentials = New-Object System.Net.NetworkCredential($FtpUser, $FtpPassword)
$ftpRequest.UseBinary = $true
$ftpRequest.UsePassive = $false  # Активный режим
$ftpRequest.KeepAlive = $false

# Чтение файла подписи
$signatureBytes = [System.IO.File]::ReadAllBytes($signaturePath)
$ftpRequest.ContentLength = $signatureBytes.Length

# Отправка
Write-Host "Загрузка $($signatureBytes.Length) байт..." -ForegroundColor Yellow

try {
    $requestStream = $ftpRequest.GetRequestStream()
    $requestStream.Write($signatureBytes, 0, $signatureBytes.Length)
    $requestStream.Close()

    $ftpResponse = $ftpRequest.GetResponse()
    Write-Host "Ответ сервера: $($ftpResponse.StatusDescription)" -ForegroundColor Green
    $ftpResponse.Close()

    Write-Host "`n=== Успешно! ===" -ForegroundColor Green
    Write-Host "Файл request.xml.sig отправлен на $FtpHost"
    Write-Host "Теперь DPI сервер может использовать его для загрузки из РKN"

} catch {
    Write-Host "Ошибка отправки: $($_.Exception.Message)" -ForegroundColor Red
    throw
}

# ============================================================================
# 4. Очистка (опционально)
# ============================================================================

Write-Host "`n=== Очистка ===" -ForegroundColor Cyan

# Удалить временные файлы (раскомментировать если нужно)
# Remove-Item $requestXmlPath -Force
# Remove-Item $signaturePath -Force
# Write-Host "Временные файлы удалены"

Write-Host "Готово!" -ForegroundColor Green


# 1. Запустить скрипт
#.\Send-RknSignature.ps1 -FtpHost 10.0.1.235 -FtpPassword "secret123"

# 2. Проверить вывод
# === Успешно! ===
# Файл request.xml.sig отправлен на 10.0.1.235