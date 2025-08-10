#!/bin/bash
# Bu betik, bir kurulum dosyasını internetten indirir,
# size içeriğini gösterir ve çalıştırmak için onayınızı ister.

# İndirilecek betiğin URL'si
URL="https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main/install.sh"

# Betiğin indirileceği geçici dosya
TMP_SCRIPT="/tmp/install_vulscan.sh"

echo "Kurulum betiği şu adresten indiriliyor: $URL"
# curl ile betiği indir
curl -L -o "$TMP_SCRIPT" "$URL"

# İndirme başarılı oldu mu diye kontrol et
if [ $? -ne 0 ]; then
  echo "HATA: Betik indirilemedi. Lütfen URL'yi ve internet bağlantınızı kontrol edin."
  exit 1
fi

echo -e "\n--- GÜVENLİK KONTROLÜ ---"
echo "İndirilen betiğin içeriği aşağıdadır. Lütfen çalıştırmadan önce dikkatle inceleyin."
echo "------------------------------------------------------------------"
# İndirilen betiğin içeriğini kullanıcıya göster
cat "$TMP_SCRIPT"
echo "------------------------------------------------------------------"

# Kullanıcıdan onay iste
read -p "Yukarıdaki betiği 'sudo' ile çalıştırmayı ONAYLIYOR MUSUNUZ? (evet/hayır): " user_approval

# Kullanıcının cevabını küçük harfe çevirerek kontrol et
if [[ "${user_approval,,}" == "evet" || "${user_approval,,}" == "e" ]]; then
  echo "Onay verildi. Betiğe çalıştırma izni veriliyor ve 'sudo' ile çalıştırılıyor..."
  chmod +x "$TMP_SCRIPT"
  sudo "$TMP_SCRIPT"
else
  echo "İşlem iptal edildi. Betik çalıştırılmadı."
fi

# Temizlik: Geçici betik dosyasını sil
rm -f "$TMP_SCRIPT"
echo "Geçici kurulum dosyası ($TMP_SCRIPT) silindi."
