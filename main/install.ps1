# VulScan PowerShell Installer v4.0.0
# Advanced Web Security Scanner
# by ATOMGAMERAGA

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Stable", "Development", "Manual")]
    [string]$Version,
    
    [Parameter(Mandatory = $false)]
    [string]$InstallPath,
    
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

               VulScan PowerShell Installer v4.0.0
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
        "url" = "https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/dev/main-4.0.0.go"
        "tag" = "v4.0.0-dev"
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
        $goVersion = go version 2>$null
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
    param([string]$SelectedVersion)
    
    Write-Log "Installing VulScan $SelectedVersion version..." -Level Info
    
    # Create temporary directory
    if (Test-Path $Script:Config.TempDir) {
        Remove-Item $Script:Config.TempDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Script:Config.TempDir -Force | Out-Null
    
    if ($SelectedVersion -eq "Manual") {
        Install-ManualVersion
        return
    }
    
    $versionConfig = $Script:Versions[$SelectedVersion]
    
    # Download source code
    Write-Log "Downloading source code from GitHub..." -Level Info
    Show-Progress -Activity "VulScan Installation" -Status "Downloading source code..." -PercentComplete 50
    
    $sourcePath = Join-Path $Script:Config.TempDir "main.go"
    
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "VulScan-Installer/$($Script:Config.Version)")
        $webClient.DownloadFile($versionConfig.Url, $sourcePath)
    }
    catch {
        Write-Log "Failed to download source code: $($_.Exception.Message)" -Level Error
        throw
    }
    
    # Create go.mod file
    Write-Log "Preparing Go module..." -Level Info
    Show-Progress -Activity "VulScan Installation" -Status "Preparing Go module..." -PercentComplete 60
    
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
        Write-Log "Compiling VulScan..." -Level Info
        Show-Progress -Activity "VulScan Installation" -Status "Compiling executable..." -PercentComplete 75
        
        $buildArgs = @(
            "build"
            "-ldflags", "-s -w -X main.Version=$($versionConfig.Tag)"
            "-o", "vulscan.exe"
            "main.go"
        )
        
        $buildProcess = Start-Process -FilePath "go" -ArgumentList $buildArgs -Wait -PassThru -NoNewWindow
        
        if ($buildProcess.ExitCode -ne 0) {
            throw "Compilation failed with exit code: $($buildProcess.ExitCode)"
        }
        
        if (-not (Test-Path "vulscan.exe")) {
            throw "Executable not created"
        }
        
        Write-Log "VulScan compiled successfully" -Level Success
    }
    finally {
        Pop-Location
    }
}

# Manual installation handler
function Install-ManualVersion {
    Write-Log "Manual installation mode selected" -Level Info
    
    if ($Silent) {
        throw "Manual installation not supported in silent mode"
    }
    
    Write-Host ""
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host "                    MANUAL INSTALLATION" -ForegroundColor $Script:Config.Colors.Header
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host ""
    
    $currentDir = Split-Path -Parent $MyInvocation.ScriptName
    $exePath = Join-Path $currentDir "vulscan.exe"
    
    Write-Host "Please place 'vulscan.exe' in: " -ForegroundColor $Script:Config.Colors.Info -NoNewline
    Write-Host $currentDir -ForegroundColor $Script:Config.Colors.Progress
    Write-Host ""
    
    do {
        Read-Host "Press Enter when ready"
        
        if (Test-Path $exePath) {
            # Copy to temp directory for further processing
            Copy-Item $exePath (Join-Path $Script:Config.TempDir "vulscan.exe")
            Write-Log "Manual executable found and copied" -Level Success
            break
        }
        else {
            Write-Host "vulscan.exe not found! Please place the file in the specified directory." -ForegroundColor $Script:Config.Colors.Error
        }
    } while ($true)
}

# Create installation directories and copy files
function Install-Files {
    Write-Log "Creating installation directories..." -Level Info
    Show-Progress -Activity "File Installation" -Status "Creating directories..." -PercentComplete 80
    
    # Set installation path
    $installDir = if ($InstallPath) { $InstallPath } else { $Script:Config.DefaultInstallDir }
    $configDir = $Script:Config.ConfigDir
    $payloadsDir = Join-Path $configDir "payloads"
    
    # Remove existing installation
    if (Test-Path $installDir) {
        Write-Log "Removing existing installation..." -Level Info
        Remove-Item $installDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Create directories
    $directories = @($installDir, $configDir, $payloadsDir, $Script:Config.StartMenuDir)
    foreach ($dir in $directories) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    
    # Copy executable
    Write-Log "Installing VulScan executable..." -Level Info
    Show-Progress -Activity "File Installation" -Status "Copying files..." -PercentComplete 85
    
    $sourceExe = Join-Path $Script:Config.TempDir "vulscan.exe"
    $targetExe = Join-Path $installDir "vulscan.exe"
    Copy-Item $sourceExe $targetExe -Force
    
    # Create batch wrapper
    $batchContent = @"
@echo off
"$targetExe" %*
"@
    Set-Content -Path (Join-Path $installDir "vuls.bat") -Value $batchContent
    
    # Create PowerShell module wrapper
    $psModuleContent = @"
function Invoke-VulScan {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = `$true)]
        [string[]]`$Arguments
    )
    
    & "$targetExe" @Arguments
}

Set-Alias -Name vulscan -Value Invoke-VulScan
Set-Alias -Name vuls -Value Invoke-VulScan

Export-ModuleMember -Function Invoke-VulScan -Alias vulscan, vuls
"@
    
    $moduleDir = Join-Path $installDir "PowerShell"
    New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null
    Set-Content -Path (Join-Path $moduleDir "VulScan.psm1") -Value $psModuleContent
    
    # Store installation info for later use
    $Script:InstallationPaths = @{
        InstallDir = $installDir
        ConfigDir = $configDir
        PayloadsDir = $payloadsDir
        ExecutablePath = $targetExe
    }
}

# Create configuration files and payloads
function New-ConfigurationFiles {
    Write-Log "Creating configuration files..." -Level Info
    Show-Progress -Activity "Configuration" -Status "Creating config files..." -PercentComplete 90
    
    $configDir = $Script:InstallationPaths.ConfigDir
    $payloadsDir = $Script:InstallationPaths.PayloadsDir
    
    # Create main config file
    $configContent = @"
# VulScan Configuration File
# Generated by PowerShell Installer v$($Script:Config.Version)
# $(Get-Date)

scan:
  threads: 5
  timeout: 10
  user_agent: "VulScan/PowerShell-$($Script:Config.Version)"
  rate_limit: 10
  follow_redirects: true
  verify_ssl: false

payloads:
  sql_injection: "$payloadsDir\sql.txt"
  xss: "$payloadsDir\xss.txt"
  directory_traversal: "$payloadsDir\lfi.txt"
  command_injection: "$payloadsDir\cmd.txt"
  xxe: "$payloadsDir\xxe.txt"
  ssti: "$payloadsDir\ssti.txt"

output:
  verbose: false
  format: "json"
  report: false
  colors: true
  
logging:
  enabled: true
  level: "info"
  file: "$configDir\vulscan.log"

updates:
  check_on_startup: true
  auto_update_payloads: false
"@
        Set-Content -Path (Join-Path $configDir "config.yaml") -Value $configContent
        
        # Create payload files
        Write-ColorOutput "Payload dosyaları oluşturuluyor..." "White"
        
        # SQL Injection payloads
        $sqlPayloads = @"
# SQL Injection Payloads - VulScan v4.1.0
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
# XSS Payloads - VulScan v4.1.0
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
# Directory Traversal / LFI Payloads - VulScan v4.1.0
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
# Command Injection Payloads - VulScan v4.1.0
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
        if ($currentPath -split ';' -contains $installDir) {
            Write-Log "Installation directory already in PATH" -Level Info
            return
        }
        
        # Add to PATH
        $newPath = if ($currentPath.EndsWith(';')) {
            "$currentPath$installDir"
        } else {
            "$currentPath;$installDir"
        }
        
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
        
        # Update current session PATH
        $env:PATH = "$env:PATH;$installDir"
        
        Write-Log "PATH updated successfully" -Level Success
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
            Write-Host "[2] Development Release (v4.0.0-dev) - Geliştirme sürümü" -ForegroundColor Yellow
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

# Entry point
if ($MyInvocation.InvocationName -ne '.') {
    Start-Installation
}
