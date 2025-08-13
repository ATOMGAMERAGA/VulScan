# VulScan Quick Installer - PowerShell Wrapper v4.1.0
# Bu scripti GitHub'a install.ps1 olarak kaydedin

param(
    [switch]$Dev,
    [switch]$Help
)

# Admin hakları kontrolü
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Başlık göster
function Show-Banner {
    Write-Host @"
██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████╝
  ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

"@ -ForegroundColor Cyan
    
    Write-Host "VulScan Quick Installer v4.1.0" -ForegroundColor Green
    Write-Host "Advanced Web Security Scanner by ATOMGAMERAGA" -ForegroundColor Yellow
    Write-Host "===============================================" -ForegroundColor Gray
    Write-Host ""
}

# Yardim goster
function Show-Help {
    Write-Host @"
KULLANIM:
  irm https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/refs/heads/main/main/install.ps1 | iex

PARAMETRELER:
  -Dev     : Development surumunu kur
  -Help    : Bu yardim mesajini goster

ORNEKLER:
  # Stable surum kur (varsayilan):
  irm https://raw.githubusercontent.com/.../install.ps1 | iex
  
  # Development surum kur:
  irm https://raw.githubusercontent.com/.../install.ps1 | iex -ArgumentList '-Dev'

REQUIREMENTS:
  - Windows 10/11
  - PowerShell 5.0+
  - Yonetici hakklari
  - Internet baglantisi

DESTEK:
  GitHub: https://github.com/ATOMGAMERAGA/VulScan
  Issues: https://github.com/ATOMGAMERAGA/VulScan/issues
"@ -ForegroundColor White
}

# Ana işlev
function Start-Installation {
    Show-Banner
    
    if ($Help) {
        Show-Help
        return
    }
    
    # URL'yi belirle
    $installerUrl = "https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/refs/heads/main/main/install.bat"
    $tempFile = "$env:TEMP\vulscan-install-$(Get-Random -Minimum 1000 -Maximum 9999).bat"
    
    try {
        # Admin hakklari kontrolu
        if (-not (Test-Admin)) {
            Write-Host "[!] Bu islem yonetici hakklari gerektirir!" -ForegroundColor Red
            Write-Host "[i] PowerShell'i yonetici olarak calistirin veya UAC onayini bekleyin..." -ForegroundColor Yellow
            Write-Host ""
            
            # Kendini admin olarak yeniden baslat
            $arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"& {irm $($MyInvocation.MyCommand.Definition) | iex $(if($Dev){'-Dev'})}`""
            Start-Process powershell -Verb RunAs -ArgumentList $arguments -Wait
            return
        }
        
        Write-Host "[+] Yonetici hakklari dogrulandi" -ForegroundColor Green
        Write-Host "[i] VulScan installer indiriliyor..." -ForegroundColor Yellow
        
        # Installer'i indir
        $progressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $installerUrl -OutFile $tempFile -UseBasicParsing -UserAgent "VulScan-QuickInstall/4.1.0"
        
        if (-not (Test-Path $tempFile)) {
            throw "Installer indirilemedi!"
        }
        
        Write-Host "[+] Installer basariyla indirildi" -ForegroundColor Green
        Write-Host "[i] Kurulum baslatiliyor..." -ForegroundColor Yellow
        Write-Host ""
        
        # Installer'i calistir
        $process = Start-Process -FilePath $tempFile -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Host ""
            Write-Host "[+] Kurulum basariyla tamamlandi!" -ForegroundColor Green
            Write-Host "[i] Yeni terminal acarak 'vulscan --help' komutunu deneyin" -ForegroundColor Cyan
        } else {
            Write-Host ""
            Write-Host "[!] Kurulum sirasinda bir hata olustu (Exit Code: $($process.ExitCode))" -ForegroundColor Red
        }
        
    } catch {
        Write-Host ""
        Write-Host "[ERROR] Kurulum basarisiz: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[i] Manuel kurulum icin: https://github.com/ATOMGAMERAGA/VulScan" -ForegroundColor Yellow
        
        # Detayli hata bilgisi (debug icin)
        if ($VerbosePreference -eq 'Continue') {
            Write-Host ""
            Write-Host "DETAYLI HATA:" -ForegroundColor Red
            Write-Host $_.Exception.ToString() -ForegroundColor DarkRed
        }
    } finally {
        # Temp dosyayi temizle
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

# Script'i çalıştır
try {
    Start-Installation
} catch {
    Write-Host "[FATAL] Beklenmeyen hata: $($_.Exception.Message)" -ForegroundColor DarkRed
} finally {
    Write-Host ""
    Write-Host "Cikmak icin herhangi bir tusa basin..." -ForegroundColor Gray
    if (-not $env:GITHUB_ACTIONS) {  # CI/CD ortaminda bekleme
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}
