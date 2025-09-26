# 🚀 Ubuntu 22.04 Cryptocurrency Trading Bot Kurulum Rehberi

Bu rehber, Upbit-Bitget otomatik trading botunu Ubuntu 22.04 sunucusuna kurmanız için gereken tüm adımları içerir.

## 🎯 GitHub Repository Avantajları

✅ **Kolay Kurulum:** `git clone` ile tek komutta tüm dosyalar indirilir  
✅ **Otomatik Güncellemeler:** `git pull` ile en son özellikleri alabilirsin  
✅ **Version Control:** Kod değişiklikleri takip edilir  
✅ **Backup Güvenliği:** Kodlar GitHub'da güvenli şekilde saklanır  
✅ **Paylaşım:** Repository link'ini paylaşarak başkalarının da kullanmasını sağlayabilirsin

## 📋 İçindekiler
1. [Sistem Gereksinimleri](#sistem-gereksinimleri)
2. [Telegram API Kurulumu](#telegram-api-kurulumu) 
3. [Telegram Bot Oluşturma](#telegram-bot-oluşturma)
4. [Dosya Yapısını Hazırlama](#dosya-yapısını-hazırlama)
5. [Bağımlılıkları Yükleme](#bağımlılıkları-yükleme)
6. [Environment Variables Ayarlama](#environment-variables-ayarlama)
7. [Sistemi Çalıştırma](#sistemi-çalıştırma)
8. [Test Etme](#test-etme)
9. [Servis Olarak Çalıştırma](#servis-olarak-çalıştırma)
10. [Sorun Giderme](#sorun-giderme)

---

## 🖥️ Sistem Gereksinimleri

### Minimum Donanım:
- **RAM:** 2GB (önerilen: 4GB)
- **CPU:** 2 Core (önerilen: 4 Core)  
- **Disk:** 10GB boş alan (önerilen: 20GB)
- **Network:** Stabil internet bağlantısı

### Yazılım:
- **Ubuntu:** 22.04 LTS
- **Go:** 1.19+ (otomatik yüklenecek)
- **Python:** 3.10+ (sistem ile geliyor)

---

## 📱 Telegram API Kurulumu

### 1. Telegram Developer Hesabı Oluşturma

1. **https://my.telegram.org** adresine git
2. Telefon numaranla giriş yap (uluslararası format: +90XXXXXXXXXX)
3. SMS ile gelen kodu gir
4. **"API Development Tools"** sekmesine tıkla
5. Yeni uygulama oluştur:
   - **App title:** "Upbit Bot Monitor" 
   - **Short name:** "upbit_bot"
   - **Platform:** Desktop
   - **Description:** "Cryptocurrency trading bot"

6. **ÖNEMLİ:** Aşağıdaki bilgileri kaydet:
   ```
   API ID: 12345678 (örnek)
   API Hash: abc123def456ghi789 (örnek)
   ```

### 2. @AstronomicaNews Kanalına Katılma

1. Telegram'da **@AstronomicaNews** ara
2. Kanala katıl (Join/Katıl)
3. Kanalın mesajlarını görebildiğini kontrol et

---

## 🤖 Telegram Bot Oluşturma

### 1. BotFather ile Bot Oluşturma

1. Telegram'da **@BotFather** ara
2. `/start` komutunu gönder
3. `/newbot` komutunu gönder
4. Bot ismi belirle: `Upbit Trading Bot`
5. Bot username belirle: `your_upbit_bot` (benzersiz olmalı)
6. **Bot Token'ı kaydet:** `123456789:ABCdefGHIjklMNOpqrSTUvwxYZ`

### 2. Bot Ayarları

```
/setprivacy - Disable (gruplardan mesaj alabilmesi için)
/setcommands - start - Bot'u başlat
```

---

## 📁 Projeyi GitHub'dan İndirme

### 1. Git Kurulumu

```bash
# Git'i yükle (eğer yüklü değilse)
sudo apt install git -y
```

### 2. Projeyi Klonlama

```bash
# GitHub'dan projeyi indir
git clone https://github.com/0xmtnslk/upbit-perp.git

# Proje dizinine gir
cd upbit-perp

# Yetkileri ayarla
sudo chown -R $USER:$USER .
```

### 3. Dosya Yapısını Kontrol Etme

```bash
# Dosyaların doğru indiğini kontrol et
ls -la

# Şu dosyaları görmelisin:
# main.go (Telegram monitor)
# bot_main.go (Telegram bot)
# bitget.go (Bitget API)
# go.mod, go.sum (Go dependencies)
# active_positions.json
# upbit_new.json
# bot_users.json
# sessions/ (klasör)
```

---

## 🔧 Bağımlılıkları Yükleme

### 1. Sistem Güncellemesi

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Go Kurulumu

```bash
# Go'nun en son sürümünü yükle
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# PATH'e ekle
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Kontrol et
go version  # go version go1.21.5 linux/amd64 çıkması gerekli
```

### 3. Python Bağımlılıkları

```bash
sudo apt install python3 python3-pip -y
pip3 install python-telegram-bot requests schedule telegram telethon
```

### 4. Go Modül Bağımlılıkları

```bash
cd upbit-perp
go mod tidy
go mod download
```

---

## 🔐 Environment Variables Ayarlama

### 1. Environment Dosyası Oluşturma

```bash
nano .env
```

### 2. Gerekli Değişkenleri Ekleme

```bash
# Telegram API (my.telegram.org'dan aldığın)
TELEGRAM_API_ID=12345678
TELEGRAM_API_HASH=abc123def456ghi789

# Telegram Bot (BotFather'dan aldığın)  
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ

# Bot Encryption Key (32 karakter random string)
BOT_ENCRYPTION_KEY=oH6YUVxMEZlcNb9zJw8gFp3yPtW7aX5uRm2vK0qH4L8=
```

### 3. BOT_ENCRYPTION_KEY Oluşturma

Encryption key'i oluşturmak için:

```bash
# Rastgele 32 karakter base64 key oluştur
openssl rand -base64 32
```

Çıkan değeri `BOT_ENCRYPTION_KEY` olarak kullan.

### 4. Environment Yükleme Script'i

```bash
nano load_env.sh
```

```bash
#!/bin/bash
export $(cat .env | grep -v '#' | sed 's/\r$//' | awk '/=/ {print $1}' )
```

```bash
chmod +x load_env.sh
```

---

## 🏃‍♂️ Sistemi Çalıştırma

### 1. İlk JSON Dosyaları Hazırlama

JSON dosyaları GitHub'dan geldi, ancak boş olabilir. İçeriklerini kontrol et:

```bash
# upbit_new.json içeriğini kontrol et
cat upbit_new.json

# Eğer boşsa, başlangıç formatını ayarla:
echo '{"listings": []}' > upbit_new.json

# active_positions.json kontrol et
cat active_positions.json

# Eğer boşsa, başlangıç formatını ayarla:
echo '{}' > active_positions.json

# bot_users.json kontrol et  
cat bot_users.json

# Eğer boşsa, başlangıç formatını ayarla:
echo '{"Users":{}}' > bot_users.json
```

### 2. Telegram Session Oluşturma (ÖNEMLİ!)

**⚠️ ZORUNLU ADIM:** Servisi çalıştırmadan önce Telegram session'ını oluştur!

```bash
cd upbit-perp

# Environment değişkenlerini yükle
source load_env.sh

# İLK KEZ Telegram Monitor'u manuel çalıştır
go run main.go
```

**Bu adımda:**
1. Telefon numaranı isteyecek (örnek: +90XXXXXXXXXX)
2. Telegram'a SMS kodu gelecek
3. Kodu gir (örnek: 12345)  
4. 2-factor authentication varsa şifreni gir
5. `✅ Authentication successful` görene kadar bekle
6. `Ctrl+C` ile programı durdur

**Session dosyası `sessions/` klasörüne kaydedildi!** ✅

### 3. Bot Servisini Test Etme

```bash
# Yeni terminal aç (Terminal 2)  
# Telegram Bot'u çalıştır
BOT_ENCRYPTION_KEY="$BOT_ENCRYPTION_KEY" go run bot_main.go bitget.go
```

Bot'un düzgün çalıştığını görünce `Ctrl+C` ile durdur.

---

## 🧪 Test Etme

### 1. Go Monitor Test

```bash
# Terminal 1'de çalışan monitor loglarını kontrol et:
# "🚀 Telegram Monitor başladı" mesajını görmeli
# "📋 Processing recent messages" mesajlarını görmeli
```

### 2. Telegram Bot Test

```bash
# Terminal 2'de bot loglarını kontrol et:
# "🤖 Telegram Bot starting..." mesajını görmeli
```

### 3. Telegram'dan Bot Testi

1. Telegram'da botuna git
2. `/start` komutunu gönder  
3. Ana menüyü görmeli
4. **"🔧 Setup"** ile API ayarlarını gir:
   - Bitget API Key
   - Bitget Secret
   - Bitget Passkey
   - Margin miktarı (örnek: 20)
   - Kaldıraç (örnek: 20)

### 4. Yeni Coin Test

Test için yeni coin simülasyonu:

```bash
# upbit_new.json'a test coin ekle
nano upbit_new.json
```

```json
{
  "listings": [
    {
      "symbol": "TEST",
      "timestamp": "2024-01-01T12:00:00Z", 
      "detected_at": "2024-01-01 12:00:00 UTC"
    }
  ]
}
```

Dosyayı kaydet ve bot loglarında otomatik işlem açılıp açılmadığını kontrol et.

---

## ⚙️ Servis Olarak Çalıştırma

**⚠️ UYARI:** Servisleri çalıştırmadan önce yukarıdaki **Telegram Session Oluşturma** adımını mutlaka yap!

### 1. Systemd Servis Dosyaları Oluşturma

#### Go Monitor Servisi:

```bash
sudo nano /etc/systemd/system/upbit-monitor.service
```

```ini
[Unit]
Description=Upbit Telegram Monitor
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/$USER/upbit-perp
Environment=TELEGRAM_API_ID=12345678
Environment=TELEGRAM_API_HASH=abc123def456ghi789
ExecStart=/usr/local/go/bin/go run main.go
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=upbit-monitor

[Install]
WantedBy=multi-user.target
```

**⚠️ ÖNEMLİ:** 
- `$USER` kısmını kendi kullanıcı adınla değiştir (örnek: `ubuntu`)
- `TELEGRAM_API_ID` ve `TELEGRAM_API_HASH`'i gerçek değerlerinle değiştir

#### Telegram Bot Servisi:

```bash
sudo nano /etc/systemd/system/upbit-bot.service  
```

```ini
[Unit]
Description=Upbit Trading Telegram Bot
After=network.target upbit-monitor.service
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/$USER/upbit-perp
Environment=TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ
Environment=BOT_ENCRYPTION_KEY=oH6YUVxMEZlcNb9zJw8gFp3yPtW7aX5uRm2vK0qH4L8=
ExecStart=/usr/local/go/bin/go run bot_main.go bitget.go
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=upbit-bot

[Install]
WantedBy=multi-user.target
```

**⚠️ ÖNEMLİ:** 
- `$USER` kısmını kendi kullanıcı adınla değiştir (örnek: `ubuntu`)
- `TELEGRAM_BOT_TOKEN` ve `BOT_ENCRYPTION_KEY`'i gerçek değerlerinle değiştir

### 2. Servisleri Etkinleştirme

**⚠️ ÖNEMLİ:** Session oluşturulduktan sonra servisleri başlat!

```bash
# Systemd'yi reload et
sudo systemctl daemon-reload

# Servisleri etkinleştir (boot'ta başlaması için)
sudo systemctl enable upbit-monitor
sudo systemctl enable upbit-bot

# ÖNCE Monitor'u başlat
sudo systemctl start upbit-monitor  

# Monitor'un başladığını kontrol et
sudo systemctl status upbit-monitor

# Monitor çalışıyorsa Bot'u başlat  
sudo systemctl start upbit-bot

# Her iki servisin durumunu kontrol et
sudo systemctl status upbit-monitor
sudo systemctl status upbit-bot
```

### 3. Session Sorun Giderme

Eğer servis "authentication failed" hatası verirse:

```bash
# Servisi durdur
sudo systemctl stop upbit-monitor

# Manuel olarak tekrar çalıştırıp session'ı yenile
cd ~/upbit-perp
source load_env.sh
go run main.go
# Telefon numarası + SMS kodu + (varsa) şifre gir
# Ctrl+C ile durdur

# Servisi tekrar başlat
sudo systemctl start upbit-monitor
sudo systemctl status upbit-monitor
```

### 3. Logları İzleme

```bash
# Monitor logları
sudo journalctl -f -u upbit-monitor

# Bot logları  
sudo journalctl -f -u upbit-bot

# Her iki servisi birlikte izle
sudo journalctl -f -u upbit-monitor -u upbit-bot
```

---

## 🔧 Sorun Giderme

### Log Dosyaları

```bash
# Sistem logları
tail -f /var/log/syslog | grep upbit

# Servis logları
sudo journalctl -f -u upbit-monitor
sudo journalctl -f -u upbit-bot
```

### Yaygın Sorunlar

#### 1. "Permission Denied" Hatası
```bash
sudo chown -R $USER:$USER ~/upbit-perp
chmod +x ~/upbit-perp/*.sh
```

#### 2. "Module Not Found" Hatası  
```bash
cd ~/upbit-perp
go mod tidy
go mod download
```

#### 3. Telegram API Hatası
- API ID ve Hash'in doğru olduğunu kontrol et
- my.telegram.org'da uygulamanın aktif olduğunu kontrol et

#### 4. Session Authentication Hatası
```bash
# Session dosyasını sil ve yeniden oluştur
rm -rf ~/upbit-perp/sessions/*
cd ~/upbit-perp
source load_env.sh
go run main.go
# Telefon + SMS kodu + şifre gir
```

#### 5. Bot Token Hatası
- BotFather'dan aldığın token'ı kontrol et
- Bot'un aktif olduğunu kontrol et

### Servisleri Yeniden Başlatma

```bash
# Servisleri durdur
sudo systemctl stop upbit-bot upbit-monitor

# Servisleri başlat
sudo systemctl start upbit-monitor
sleep 5  # Monitor'un başlamasını bekle
sudo systemctl start upbit-bot
```

### Manuel Debug

```bash
cd ~/upbit-perp
source load_env.sh

# Debug modunda çalıştır
go run main.go  # Terminal 1
BOT_ENCRYPTION_KEY="$BOT_ENCRYPTION_KEY" go run bot_main.go bitget.go  # Terminal 2
```

---

## 🎯 Kullanıcı Ekleme ve Yönetim

### Yeni Kullanıcı Ekleme:
1. Kullanıcı botuna `/start` gönderir
2. **"🔧 Setup"** butonuna tıklar
3. Bitget API bilgilerini girer:
   - API Key
   - Secret
   - Passkey  
   - Margin miktarı
   - Kaldıraç oranı

### Çoklu Kullanıcı:
- Her kullanıcı kendi API anahtarlarını kullanır
- Her kullanıcı kendi margin ve kaldıraç ayarlarına sahip
- Yeni coin tespiti → tüm aktif kullanıcılara otomatik işlem
- Her kullanıcı kendi pozisyonlarını bağımsız kapatabilir

---

## 📊 Monitoring ve Maintenance

### Günlük Kontroller:
```bash
# Servis durumları
sudo systemctl status upbit-monitor upbit-bot

# Disk kullanımı
df -h ~/upbit-perp

# Log boyutları  
sudo du -sh /var/log/journal/
```

### Haftalık Bakım:
```bash
# Sistem güncellemesi
sudo apt update && sudo apt upgrade -y

# GitHub'dan son güncellemeleri çek
cd ~/upbit-perp
git pull origin main

# Go bağımlılık güncellemesi
go get -u ./...
go mod tidy

# Servisleri yeniden başlat
sudo systemctl restart upbit-monitor upbit-bot
```

### Backup:
```bash
# Veri dosyalarını yedekle
mkdir -p ~/backup
cp ~/upbit-perp/*.json ~/backup/
cp ~/upbit-perp/.env ~/backup/
cp ~/upbit-perp/sessions/* ~/backup/ 2>/dev/null || true
```

---

## ✅ Kurulum Tamamlandı!

Artık sisteminiz Ubuntu 22.04 sunucusunda çalışıyor:

✅ **Go Monitor:** @AstronomicaNews'u takip ediyor  
✅ **Telegram Bot:** Kullanıcılara hizmet veriyor  
✅ **Otomatik Trading:** Yeni coin → herkese işlem  
✅ **5-dakika Reminder:** Açık pozisyonlar için hatırlatma  
✅ **Persistent Storage:** Bot restart → pozisyonlar korunur  

**Bot Linkin:** `t.me/your_upbit_bot`

---

## 🔗 GitHub Repository

**Kaynak Kod:** https://github.com/0xmtnslk/upbit-perp

### 🔄 Gelecekteki Güncellemeler:
```bash
# Son güncellemeleri almak için
cd ~/upbit-perp  
git pull origin main
sudo systemctl restart upbit-monitor upbit-bot
```

### 🍴 Repository'yi Fork Etme:
GitHub'da repo'yu fork ederek kendi değişikliklerini yapabilir ve kendi versiyonunu oluşturabilirsin!

---

## 🌟 Yeni Özellikler (Son Güncelleme)

✅ **6-Saatlik Durum Bildirimleri:** Her 6 saatte bir esprili sistem durumu mesajları  
✅ **Gelişmiş P&L Hesaplaması:** Hatırlatmalarda gerçek Bitget API verisi kullanımı  
✅ **GitHub Entegrasyonu:** Kolay kurulum ve güncelleme sistemi  
✅ **Persistent Storage:** Bot restart → pozisyonlar korunur  
✅ **Multi-User Support:** Sınırsız kullanıcı desteği

Sistemi paylaşarak birden fazla kişinin kullanmasını sağlayabilirsin! 🚀