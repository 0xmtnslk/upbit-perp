# 🚀 Ubuntu 22.04 Cryptocurrency Trading Bot Kurulum Rehberi

Bu rehber, Upbit-Bitget otomatik trading botunu Ubuntu 22.04 sunucusuna kurmanız için gereken tüm adımları içerir.

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

## 📁 Dosya Yapısını Hazırlama

### 1. Proje Klasörü Oluşturma

```bash
# Ana dizin oluştur
sudo mkdir -p /opt/upbit-trading-bot
cd /opt/upbit-trading-bot

# Yetkileri ayarla
sudo chown -R $USER:$USER /opt/upbit-trading-bot
```

### 2. Gerekli Dosyaları Kopyalama

Replit'teki dosyaları sunucuya kopyala:

```bash
# Ana Go dosyaları
scp main.go user@server:/opt/upbit-trading-bot/
scp bot_main.go user@server:/opt/upbit-trading-bot/
scp bitget.go user@server:/opt/upbit-trading-bot/
scp go.mod user@server:/opt/upbit-trading-bot/
scp go.sum user@server:/opt/upbit-trading-bot/

# Veri dosyaları (boş olarak oluştur)
touch upbit_new.json
touch active_positions.json
touch bot_users.json

# Oturum klasörü
mkdir -p sessions
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
cd /opt/upbit-trading-bot
go mod tidy
go mod download
```

---

## 🔐 Environment Variables Ayarlama

### 1. Environment Dosyası Oluşturma

```bash
nano /opt/upbit-trading-bot/.env
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
nano /opt/upbit-trading-bot/load_env.sh
```

```bash
#!/bin/bash
export $(cat .env | grep -v '#' | sed 's/\r$//' | awk '/=/ {print $1}' )
```

```bash
chmod +x /opt/upbit-trading-bot/load_env.sh
```

---

## 🏃‍♂️ Sistemi Çalıştırma

### 1. İlk JSON Dosyaları Hazırlama

```bash
# upbit_new.json
cat > /opt/upbit-trading-bot/upbit_new.json << 'EOF'
{
  "listings": []
}
EOF

# active_positions.json  
echo '{}' > /opt/upbit-trading-bot/active_positions.json

# bot_users.json
echo '{"Users":{}}' > /opt/upbit-trading-bot/bot_users.json
```

### 2. Manuel Çalıştırma (Test için)

```bash
cd /opt/upbit-trading-bot

# Environment değişkenlerini yükle
source load_env.sh

# Go Telegram Monitor'u çalıştır (Terminal 1)
go run main.go

# Yeni terminal aç (Terminal 2)
# Telegram Bot'u çalıştır  
BOT_ENCRYPTION_KEY="$BOT_ENCRYPTION_KEY" go run bot_main.go bitget.go
```

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
nano /opt/upbit-trading-bot/upbit_new.json
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
User=ubuntu
WorkingDirectory=/opt/upbit-trading-bot
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
User=ubuntu
WorkingDirectory=/opt/upbit-trading-bot
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

**⚠️ ÖNEMLİ:** Environment değişkenlerini gerçek değerlerinle değiştir!

### 2. Servisleri Etkinleştirme

```bash
# Systemd'yi reload et
sudo systemctl daemon-reload

# Servisleri etkinleştir (boot'ta başlaması için)
sudo systemctl enable upbit-monitor
sudo systemctl enable upbit-bot

# Servisleri başlat
sudo systemctl start upbit-monitor  
sudo systemctl start upbit-bot

# Durum kontrol et
sudo systemctl status upbit-monitor
sudo systemctl status upbit-bot
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
sudo chown -R $USER:$USER /opt/upbit-trading-bot
chmod +x /opt/upbit-trading-bot/*.sh
```

#### 2. "Module Not Found" Hatası  
```bash
cd /opt/upbit-trading-bot
go mod tidy
go mod download
```

#### 3. Telegram API Hatası
- API ID ve Hash'in doğru olduğunu kontrol et
- my.telegram.org'da uygulamanın aktif olduğunu kontrol et

#### 4. Bot Token Hatası
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
cd /opt/upbit-trading-bot
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
df -h /opt/upbit-trading-bot

# Log boyutları  
sudo du -sh /var/log/journal/
```

### Haftalık Bakım:
```bash
# Sistem güncellemesi
sudo apt update && sudo apt upgrade -y

# Go bağımlılık güncellemesi
cd /opt/upbit-trading-bot
go get -u ./...
go mod tidy

# Servisleri yeniden başlat
sudo systemctl restart upbit-monitor upbit-bot
```

### Backup:
```bash
# Veri dosyalarını yedekle
cp /opt/upbit-trading-bot/*.json ~/backup/
cp /opt/upbit-trading-bot/.env ~/backup/
cp /opt/upbit-trading-bot/sessions/* ~/backup/
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

Sistemi paylaşarak birden fazla kişinin kullanmasını sağlayabilirsin! 🚀