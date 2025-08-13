@echo off
setlocal enabledelayedexpansion
title VulScan Windows Installer v4.1.0
color 0A
chcp 65001 >nul 2>&1

echo.
echo  ██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
echo  ██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
echo  ██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
echo  ╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
echo   ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████╝
echo    ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
echo.
echo                VulScan Windows Installer v4.1.0
echo                  Advanced Web Security Scanner
echo                    by ATOMGAMERAGA
echo.
echo ══════════════════════════════════════════════════════════════════
echo.

:: Ana menu
:main_menu
echo ══════════════════════════════════════════════════════════════════
echo                           ANA MENU
echo ══════════════════════════════════════════════════════════════════
echo.
echo [1] VulScan Kur
echo [2] VulScan Kaldir
echo [3] Cikis
echo.
set /p main_choice="Seciminizi yapin (1/2/3): "

if "%main_choice%"=="1" goto :install_menu
if "%main_choice%"=="2" goto :uninstall_menu
if "%main_choice%"=="3" exit /b 0
echo [ERROR] Gecersiz secim!
echo.
goto :main_menu

:uninstall_menu
echo.
echo ══════════════════════════════════════════════════════════════════
echo                         KALDIR MENU
echo ══════════════════════════════════════════════════════════════════
echo.

:: Kurulum kontrolu
if not exist "C:\Program Files\VulScan\vulscan.exe" (
    echo [INFO] VulScan kurulu degil.
    echo.
    pause
    goto :main_menu
)

echo [INFO] VulScan kurulumu bulundu.
echo.
set /p uninstall_confirm="VulScan'i kaldirmak istediginizden emin misiniz? (y/n): "

if /i "%uninstall_confirm%" neq "y" (
    echo [INFO] Kaldirma iptal edildi.
    echo.
    pause
    goto :main_menu
)

:: Yonetici hakki kontrolu
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Kaldirma islemi yonetici hakklari gerektirir!
    echo [INFO]  Sag tik yapip "Yonetici olarak calistir" secenegini kullanin.
    echo.
    pause
    goto :main_menu
)

echo.
echo [INFO] VulScan kaldiriliyor...

:: PATH'den kaldir
echo [INFO] PATH ortam degiskeni guncelleniyor...
for /f "tokens=2*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul') do set "CURRENT_PATH=%%j"
set "NEW_PATH=!CURRENT_PATH:C:\Program Files\VulScan;=!"
set "NEW_PATH=!NEW_PATH:;C:\Program Files\VulScan=!"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH /t REG_EXPAND_SZ /d "!NEW_PATH!" /f >nul 2>&1

:: Registry kayitlarini kaldir
echo [INFO] Registry kayitlari kaldiriliyor...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /f >nul 2>&1

:: Dosya ve klasorleri kaldir
echo [INFO] Dosyalar kaldiriliyor...
rmdir /s /q "C:\Program Files\VulScan" >nul 2>&1
rmdir /s /q "C:\ProgramData\VulScan" >nul 2>&1
rmdir /s /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\VulScan" >nul 2>&1

:: Masaustu kisayolunu kaldir
if exist "%USERPROFILE%\Desktop\VulScan.lnk" del "%USERPROFILE%\Desktop\VulScan.lnk" >nul 2>&1
if exist "%PUBLIC%\Desktop\VulScan.lnk" del "%PUBLIC%\Desktop\VulScan.lnk" >nul 2>&1

echo [INFO] VulScan basariyla kaldirildi!
echo [INFO] Yeni terminal oturumu acarak PATH degisikliklerini uygulayin.
echo.
pause
goto :main_menu

:install_menu
:: Yonetici hakki kontrolu
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Bu installer yonetici hakklari gerektirir!
    echo [INFO]  Sag tik yapip "Yonetici olarak calistir" secenegini kullanin.
    echo.
    pause
    goto :main_menu
)

echo [INFO] Yonetici hakklari dogrulandi ✓
echo.

:: Kurulum yollarini ayarla
set "INSTALL_DIR=C:\Program Files\VulScan"
set "CONFIG_DIR=C:\ProgramData\VulScan"
set "TEMP_DIR=%TEMP%\VulScan_Install"
set "PAYLOADS_DIR=%CONFIG_DIR%\payloads"

echo [INFO] Kurulum dizini: %INSTALL_DIR%
echo [INFO] Yapilandirma dizini: %CONFIG_DIR%
echo.

:: Surum secim menusu
echo ══════════════════════════════════════════════════════════════════
echo                         SURUM SECIMI
echo ══════════════════════════════════════════════════════════════════
echo.
echo Hangi surumu kurmak istiyorsunuz?
echo.
echo [1] Stable Release (v4.1) - Kararli surum
echo     └─ Ana gelistirme dali, test edilmis ve kararli
echo     └─ GitHub: https://github.com/ATOMGAMERAGA/VulScan/blob/main/main.go
echo.
echo [2] Development Release (v4.1.0-dev) - Gelistirme surumu
echo     └─ Yeni ozellikler, guncel guncellemeler
echo     └─ GitHub: https://github.com/ATOMGAMERAGA/VulScan/blob/main/dev/main-4.1.0.go
echo.
echo [3] Manuel Kurulum - Kendi .exe dosyanizi kullanin
echo.

set /p version_choice="Seciminizi yapin (1/2/3): "

if "%version_choice%"=="1" (
    set "DOWNLOAD_URL=https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main.go"
    set "VERSION_TAG=v4.1-stable"
    echo [INFO] Stable Release secildi
) else if "%version_choice%"=="2" (
    set "DOWNLOAD_URL=https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/dev/main-4.1.0.go"
    set "VERSION_TAG=v4.1.0-dev"
    echo [INFO] Development Release secildi
) else if "%version_choice%"=="3" (
    goto :manual_setup
) else (
    echo [ERROR] Gecersiz secim!
    pause
    goto :main_menu
)

echo.

:: Go kurulumu kontrolu
echo [INFO] Go kurulumu kontrol ediliyor...
where go >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Go bulunamadi! VulScan'i derlemek icin Go gerekli.
    echo.
    echo Go'yu suradan indirip kurun: https://golang.org/dl/
    echo Kurulum tamamlandiktan sonra bu installer'i tekrar calistirin.
    echo.
    echo Alternatif olarak manuel kurulum secenegini kullanabilirsiniz.
    pause
    goto :main_menu
)

for /f "tokens=3" %%i in ('go version') do set "GO_VERSION=%%i"
echo [INFO] Go bulundu: %GO_VERSION% ✓
echo.

:: Gecici dizin olustur
if exist "%TEMP_DIR%" rmdir /s /q "%TEMP_DIR%"
mkdir "%TEMP_DIR%"

:: Kaynak kod indir
echo [INFO] Kaynak kod indiriliyor...
echo [URL] %DOWNLOAD_URL%

powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%TEMP_DIR%\main.go' -UserAgent 'VulScan-Installer/4.1.0' } catch { exit 1 }}" 2>nul

if not exist "%TEMP_DIR%\main.go" (
    echo [ERROR] Kaynak kod indirilemedi!
    echo [INFO]  Internet baglantinizi kontrol edin veya manuel kurulum yapin.
    pause
    goto :main_menu
)

echo [INFO] Kaynak kod basariyla indirildi ✓
echo.

:: go.mod dosyasi olustur
echo [INFO] Go modulu hazirlaniyor...
cd /d "%TEMP_DIR%"

(
echo module VulScan
echo.
echo go 1.19
echo.
echo require ^(
echo     golang.org/x/time v0.5.0
echo     gopkg.in/yaml.v3 v3.0.1
echo ^)
) > go.mod

:: Bagimliliklar indir
echo [INFO] Bagimliliklar indiriliyor...
go mod tidy >nul 2>&1

if %errorLevel% neq 0 (
    echo [WARNING] Bazi bagimliliklar indirilemedi, devam ediliyor...
)

:: Calistirilebilir dosya derle
echo [INFO] VulScan derleniyor...
go build -ldflags "-s -w -X main.Version=%VERSION_TAG%" -o vulscan.exe main.go

if not exist "vulscan.exe" (
    echo [ERROR] Derleme basarisiz!
    echo [INFO]  Go kurulumunuzu kontrol edin veya manuel kurulum yapin.
    pause
    goto :main_menu
)

echo [INFO] Derleme basarili ✓
goto :install_files

:manual_setup
echo.
echo ══════════════════════════════════════════════════════════════════
echo                        MANUEL KURULUM
echo ══════════════════════════════════════════════════════════════════
echo.
echo [INFO] Manuel kurulum modu secildi.
echo [INFO] Lutfen 'vulscan.exe' dosyasini bu klasore koyun: %~dp0
echo.
set /p "manual_confirm=Hazir oldugunuzda Enter'a basin..."

if not exist "%~dp0vulscan.exe" (
    echo [ERROR] vulscan.exe dosyasi bulunamadi!
    echo [INFO]  Dosyayi %~dp0 klasorune koyup tekrar deneyin.
    pause
    goto :main_menu
)

set "TEMP_DIR=%~dp0"
echo [INFO] Manuel .exe dosyasi bulundu ✓
echo.

:install_files
:: Kurulum dizinleri olustur
echo [INFO] Kurulum dizinleri olusturuluyor...

if exist "%INSTALL_DIR%" (
    echo [INFO] Mevcut kurulum kaldiriliyor...
    rmdir /s /q "%INSTALL_DIR%" 2>nul
)

mkdir "%INSTALL_DIR%" 2>nul
mkdir "%CONFIG_DIR%" 2>nul
mkdir "%PAYLOADS_DIR%" 2>nul

:: Calistirilebilir dosyayi kopyala
echo [INFO] Dosyalar kopyalaniyor...
copy "%TEMP_DIR%\vulscan.exe" "%INSTALL_DIR%\vulscan.exe" >nul

if %errorLevel% neq 0 (
    echo [ERROR] Dosya kopyalama basarisiz!
    pause
    goto :main_menu
)

:: Kisayol komutlar icin batch wrapper olustur
echo [INFO] Komut kisayollari olusturuluyor...

:: vuls.bat olustur
(
echo @echo off
echo "%INSTALL_DIR%\vulscan.exe" %%*
) > "%INSTALL_DIR%\vuls.bat"

:: config.yaml olustur
echo [INFO] Varsayilan yapilandirma olusturuluyor...
(
echo # VulScan Configuration File v4.1.0
echo # Generated by Windows Installer v4.1.0
echo.
echo scan:
echo   threads: 5
echo   timeout: 10
echo   user_agent: "VulScan/v4.1.0"
echo   rate_limit: 10
echo   max_redirects: 5
echo   verify_ssl: true
echo.
echo payloads:
echo   sql_injection: "%PAYLOADS_DIR%\sql.txt"
echo   xss: "%PAYLOADS_DIR%\xss.txt"
echo   directory_traversal: "%PAYLOADS_DIR%\lfi.txt"
echo   command_injection: "%PAYLOADS_DIR%\cmd.txt"
echo   custom: "%PAYLOADS_DIR%\custom.txt"
echo.
echo output:
echo   verbose: false
echo   format: "json"
echo   report: false
echo   output_file: ""
echo.
echo advanced:
echo   deep_scan: false
echo   aggressive_mode: false
echo   stealth_mode: false
) > "%CONFIG_DIR%\config.yaml"

:: Payload dosyalari olustur
echo [INFO] Payload dosyalari olusturuluyor...

:: SQL Injection payloads
(
echo # SQL Injection Payloads - VulScan v4.1.0
echo ' OR '1'='1
echo ' OR 1=1 --
echo ' UNION SELECT NULL--
echo '; DROP TABLE users; --
echo ' AND SLEEP^(5^) --
echo ' OR IF^(1=1,SLEEP^(5^),0^) --
echo admin'--
echo admin' #
echo ^) or '1'='1--
echo ' OR 1=1#
echo ' UNION ALL SELECT 1,2,3,4,5--
echo ' AND ^(SELECT COUNT^(*^) FROM information_schema.tables^)^>0 --
echo '; WAITFOR DELAY '00:00:05' --
echo ' OR BENCHMARK^(10000000,MD5^(1^)^) --
) > "%PAYLOADS_DIR%\sql.txt"

:: XSS payloads
(
echo # XSS Payloads - VulScan v4.1.0
echo ^<script^>alert^('XSS'^)^</script^>
echo ^<script^>alert^(document.cookie^)^</script^>
echo ^<img src=x onerror=alert^('XSS'^)^>
echo ^<svg onload=alert^('XSS'^)^>
echo javascript:alert^('XSS'^)
echo '^>^<script^>alert^('XSS'^)^</script^>
echo "^>^<script^>alert^('XSS'^)^</script^>
echo ^<iframe src=javascript:alert^('XSS'^)^>^</iframe^>
echo ^<body onload=alert^('XSS'^)^>
echo ^<input type=image src=x onerror=alert^('XSS'^)^>
echo ^<object data=javascript:alert^('XSS'^)^>^</object^>
echo ^<embed src=javascript:alert^('XSS'^)^>
) > "%PAYLOADS_DIR%\xss.txt"

:: LFI/Directory Traversal payloads
(
echo # Directory Traversal / LFI Payloads - VulScan v4.1.0
echo ../
echo ..\
echo ../../../etc/passwd
echo ..\..\..\windows\system32\drivers\etc\hosts
echo ....//....//....//etc/passwd
echo ....\\....\\....\\windows\system32\drivers\etc\hosts
echo %%252e%%252e%%252f
echo %%c0%%af../
echo %%c1%%9c../
echo /var/www/html/../../../../etc/passwd
echo file:///etc/passwd
echo file:///c:/windows/system32/drivers/etc/hosts
) > "%PAYLOADS_DIR%\lfi.txt"

:: Command Injection payloads
(
echo # Command Injection Payloads - VulScan v4.1.0
echo ; ls
echo ^| id
echo ^& whoami
echo `id`
echo $^(id^)
echo ; cat /etc/passwd
echo ^| type c:\windows\system32\drivers\etc\hosts
echo ^& dir
echo ; uname -a
echo ^|^| id
echo ^&^& whoami
echo ; sleep 5
echo ^| timeout 5
echo `sleep 5`
echo $^(sleep 5^)
) > "%PAYLOADS_DIR%\cmd.txt"

:: Custom payloads
(
echo # Custom Payloads - VulScan v4.1.0
echo # Bu dosyaya kendi payload'larinizi ekleyebilirsiniz
echo # Her satir bir payload olmalidir
echo.
echo # Ornek custom payloads:
echo test
echo admin
echo administrator
echo root
echo guest
) > "%PAYLOADS_DIR%\custom.txt"

:: PATH'e ekle
echo [INFO] PATH ortam degiskeni guncelleniyor...

:: Mevcut PATH'i al
for /f "tokens=2*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul') do set "CURRENT_PATH=%%j"

:: PATH'de zaten var mi kontrol et
echo %CURRENT_PATH% | find /i "%INSTALL_DIR%" >nul
if %errorLevel% neq 0 (
    :: PATH'e ekle
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH /t REG_EXPAND_SZ /d "%CURRENT_PATH%;%INSTALL_DIR%" /f >nul
    if %errorLevel% neq 0 (
        echo [WARNING] PATH guncellenemedi! Manuel olarak %INSTALL_DIR% ekleyin.
    ) else (
        echo [INFO] PATH basariyla guncellendi ✓
    )
) else (
    echo [INFO] PATH zaten guncel ✓
)

:: Baslat menusu kisayollari olustur
echo [INFO] Baslat menusu kisayollari olusturuluyor...
set "START_MENU=%ProgramData%\Microsoft\Windows\Start Menu\Programs"
mkdir "%START_MENU%\VulScan" 2>nul

:: VulScan.lnk olustur
powershell -Command "& {$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%START_MENU%\VulScan\VulScan.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\vulscan.exe'; $Shortcut.WorkingDirectory = '%INSTALL_DIR%'; $Shortcut.Description = 'VulScan v4.1.0 - Web Security Scanner'; $Shortcut.Save()}" 2>nul

:: VulScan Command Prompt.lnk olustur
powershell -Command "& {$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%START_MENU%\VulScan\VulScan Command Prompt.lnk'); $Shortcut.TargetPath = 'cmd.exe'; $Shortcut.Arguments = '/k echo VulScan v4.1.0 - Ready! ^& echo Type: vulscan --help for usage ^& echo.'; $Shortcut.WorkingDirectory = '%USERPROFILE%'; $Shortcut.Description = 'VulScan Command Prompt'; $Shortcut.Save()}" 2>nul

:: Uninstall VulScan.lnk olustur
powershell -Command "& {$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%START_MENU%\VulScan\Uninstall VulScan.lnk'); $Shortcut.TargetPath = '%~f0'; $Shortcut.WorkingDirectory = '%~dp0'; $Shortcut.Description = 'Uninstall VulScan v4.1.0'; $Shortcut.Save()}" 2>nul

:: Masaustu kisayolu olustur
echo [INFO] Masaustu kisayolu olusturuluyor...
set /p create_desktop="Masaustunde kisayol olusturulsun mu? (y/n): "
if /i "%create_desktop%"=="y" (
    powershell -Command "& {$WshShell = New-Object -comObject WScript.Shell; $Desktop = $WshShell.SpecialFolders('Desktop'); $Shortcut = $WshShell.CreateShortcut('$Desktop\VulScan.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\vulscan.exe'; $Shortcut.WorkingDirectory = '%INSTALL_DIR%'; $Shortcut.Description = 'VulScan v4.1.0 - Web Security Scanner'; $Shortcut.Save()}" 2>nul
    echo [INFO] Masaustu kisayolu olusturuldu ✓
)

:: Windows Programs listesine kaydet
echo [INFO] Windows Programs listesine ekleniyor...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v DisplayName /t REG_SZ /d "VulScan - Web Security Scanner v4.1.0" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v DisplayVersion /t REG_SZ /d "%VERSION_TAG%" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v Publisher /t REG_SZ /d "ATOMGAMERAGA" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v UninstallString /t REG_SZ /d "%~f0" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v InstallLocation /t REG_SZ /d "%INSTALL_DIR%" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v DisplayIcon /t REG_SZ /d "%INSTALL_DIR%\vulscan.exe" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v EstimatedSize /t REG_DWORD /d 25600 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v NoModify /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VulScan" /v NoRepair /t REG_DWORD /d 1 /f >nul

:: Temizlik
if exist "%TEMP_DIR%\main.go" rmdir /s /q "%TEMP_DIR%" 2>nul

:: Kurulum tamamlandi
echo.
echo ══════════════════════════════════════════════════════════════════
echo                      KURULUM TAMAMLANDI!
echo ══════════════════════════════════════════════════════════════════
echo.
echo ✅ VulScan v4.1.0 basariyla kuruldu!
echo.
echo 📁 Kurulum dizini: %INSTALL_DIR%
echo ⚙️  Yapilandirma: %CONFIG_DIR%\config.yaml
echo 🎯 Payloadlar: %PAYLOADS_DIR%\
echo.
echo 🚀 KULLANIM ORNEKLERI:
echo ────────────────────────────────────────────────────────────────
echo   vulscan http://example.com
echo   vulscan --help
echo   vulscan --verbose http://example.com/page.php?id=1
echo   vulscan --output report.json --report http://example.com
echo   vuls http://example.com  (kisa komut)
echo.
echo 💡 IPUCU: Yeni terminal oturumu acarak komutlari kullanmaya baslayin!
echo.
echo 📋 Baslat Menusu: Baslat ^> VulScan
echo 🗑️  Kaldirmak icin: Bu installer'i tekrar calistirin ve "2" secin
echo.

:: Kurulum testi
echo [TEST] Kurulum testi yapiliyor...
"%INSTALL_DIR%\vulscan.exe" --version >nul 2>&1
if %errorLevel% equ 0 (
    echo [INFO] ✅ Test basarili!
) else (
    echo [WARNING] ⚠️ Test basarisiz - Manuel kontrol gerekli
)

echo.
echo Kurulum tamamlandi! Yeni terminal acarak "vulscan --help" komutunu deneyin.
echo.
pause
goto :main_menu
