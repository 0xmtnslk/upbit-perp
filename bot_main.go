package main

import (
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "crypto/sha256"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io"
        "io/ioutil"
        "log"
        "os"
        "strconv"
        "strings"
        "sync"
        "time"

        "github.com/fsnotify/fsnotify"
        tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// UserState represents user's current setup state
type UserState string

const (
        StateNone        UserState = "none"
        StateAwaitingKey UserState = "awaiting_api_key"
        StateAwaitingSecret UserState = "awaiting_secret"
        StateAwaitingPasskey UserState = "awaiting_passkey"  
        StateAwaitingMargin UserState = "awaiting_margin"
        StateAwaitingLeverage UserState = "awaiting_leverage"
        StateComplete     UserState = "complete"
)

// UserData represents individual user settings and API credentials
type UserData struct {
        UserID        int64     `json:"user_id"`
        Username      string    `json:"username"`
        BitgetAPIKey  string    `json:"bitget_api_key"`      // Encrypted when stored
        BitgetSecret  string    `json:"bitget_secret"`       // Encrypted when stored
        BitgetPasskey string    `json:"bitget_passkey"`      // Encrypted when stored
        MarginUSDT    float64   `json:"margin_usdt"`
        Leverage      int       `json:"leverage"`
        IsActive      bool      `json:"is_active"`
        State         UserState `json:"current_state"`
        CreatedAt     string    `json:"created_at"`
        UpdatedAt     string    `json:"updated_at"`
}

// BotDatabase represents multi-user storage
type BotDatabase struct {
        Users map[int64]*UserData `json:"users"`
        mutex sync.RWMutex
}

// UpbitDetection represents a detected coin from upbit_new.json
type UpbitDetection struct {
        Symbol      string `json:"symbol"`
        Timestamp   string `json:"timestamp"`
        DetectedAt  string `json:"detected_at"`
}

// UpbitData represents the wrapper structure for upbit_new.json
type UpbitData struct {
        Listings []UpbitDetection `json:"listings"`
}

// TelegramBot represents our multi-user bot
type TelegramBot struct {
        bot          *tgbotapi.BotAPI
        database     *BotDatabase
        dbFile       string
        encryptionKey []byte
        lastProcessedSymbol string // Track last processed coin to prevent duplicates
}

// Generate encryption key from environment (required for persistence)
func generateEncryptionKey() ([]byte, error) {
        envKey := os.Getenv("BOT_ENCRYPTION_KEY")
        if envKey == "" {
                return nil, fmt.Errorf("BOT_ENCRYPTION_KEY environment variable is required for secure credential storage")
        }
        
        // First try to decode as base64 (proper format)
        if key, err := base64.StdEncoding.DecodeString(envKey); err == nil && len(key) == 32 {
                return key, nil
        }
        
        // Fallback: hash the string to create consistent 32-byte key
        // This supports legacy string-based keys
        hash := sha256.Sum256([]byte(envKey))
        return hash[:], nil
}

// Encrypt sensitive data using AES-GCM
func (tb *TelegramBot) encryptSensitiveData(plaintext string) (string, error) {
        if plaintext == "" {
                return "", nil
        }
        
        block, err := aes.NewCipher(tb.encryptionKey)
        if err != nil {
                return "", fmt.Errorf("failed to create cipher: %v", err)
        }
        
        gcm, err := cipher.NewGCM(block)
        if err != nil {
                return "", fmt.Errorf("failed to create GCM: %v", err)
        }
        
        nonce := make([]byte, gcm.NonceSize())
        if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
                return "", fmt.Errorf("failed to generate nonce: %v", err)
        }
        
        ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
        return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt sensitive data using AES-GCM
func (tb *TelegramBot) decryptSensitiveData(ciphertext string) (string, error) {
        if ciphertext == "" {
                return "", nil
        }
        
        data, err := base64.StdEncoding.DecodeString(ciphertext)
        if err != nil {
                return "", fmt.Errorf("failed to decode base64: %v", err)
        }
        
        block, err := aes.NewCipher(tb.encryptionKey)
        if err != nil {
                return "", fmt.Errorf("failed to create cipher: %v", err)
        }
        
        gcm, err := cipher.NewGCM(block)
        if err != nil {
                return "", fmt.Errorf("failed to create GCM: %v", err)
        }
        
        nonceSize := gcm.NonceSize()
        if len(data) < nonceSize {
                return "", fmt.Errorf("ciphertext too short")
        }
        
        nonce, ciphertext_bytes := data[:nonceSize], data[nonceSize:]
        plaintext, err := gcm.Open(nil, nonce, ciphertext_bytes, nil)
        if err != nil {
                return "", fmt.Errorf("failed to decrypt: %v", err)
        }
        
        return string(plaintext), nil
}

// NewTelegramBot creates a new bot instance with encryption
func NewTelegramBot(token string) (*TelegramBot, error) {
        bot, err := tgbotapi.NewBotAPI(token)
        if err != nil {
                return nil, fmt.Errorf("failed to create bot: %v", err)
        }

        // Generate or get encryption key
        encryptionKey, err := generateEncryptionKey()
        if err != nil {
                return nil, fmt.Errorf("failed to setup encryption: %v", err)
        }

        botInstance := &TelegramBot{
                bot:           bot,
                dbFile:        "bot_users.json",
                encryptionKey: encryptionKey,
                database: &BotDatabase{
                        Users: make(map[int64]*UserData),
                },
        }

        // Load existing user data (will decrypt automatically)
        if err := botInstance.loadDatabase(); err != nil {
                log.Printf("Warning: Could not load database: %v", err)
        }

        // Start file watcher for upbit_new.json
        go botInstance.startFileWatcher()

        return botInstance, nil
}

// Save user database to JSON file (assumes caller has mutex lock)
func (tb *TelegramBot) saveDatabaseUnsafe() error {
        data, err := json.MarshalIndent(tb.database, "", "  ")
        if err != nil {
                return fmt.Errorf("failed to marshal database: %v", err)
        }

        return ioutil.WriteFile(tb.dbFile, data, 0644)
}

// Save user database to JSON file (thread-safe)
func (tb *TelegramBot) saveDatabase() error {
        tb.database.mutex.Lock()
        defer tb.database.mutex.Unlock()
        return tb.saveDatabaseUnsafe()
}

// Load user database from JSON file
func (tb *TelegramBot) loadDatabase() error {
        if _, err := os.Stat(tb.dbFile); os.IsNotExist(err) {
                return nil // File doesn't exist yet
        }

        data, err := ioutil.ReadFile(tb.dbFile)
        if err != nil {
                return fmt.Errorf("failed to read database file: %v", err)
        }

        tb.database.mutex.Lock()
        defer tb.database.mutex.Unlock()

        return json.Unmarshal(data, tb.database)
}

// Get user data by ID (decrypts sensitive fields)
func (tb *TelegramBot) getUser(userID int64) (*UserData, bool) {
        tb.database.mutex.RLock()
        defer tb.database.mutex.RUnlock()
        
        encryptedUser, exists := tb.database.Users[userID]
        if !exists {
                return nil, false
        }
        
        // Create a copy for decryption
        user := *encryptedUser
        
        // Decrypt sensitive fields
        if encryptedUser.BitgetAPIKey != "" {
                decrypted, err := tb.decryptSensitiveData(encryptedUser.BitgetAPIKey)
                if err != nil {
                        log.Printf("Warning: Failed to decrypt API key for user %d: %v", userID, err)
                        // Return user with empty credentials rather than failing completely
                        user.BitgetAPIKey = ""
                } else {
                        user.BitgetAPIKey = decrypted
                }
        }
        
        if encryptedUser.BitgetSecret != "" {
                decrypted, err := tb.decryptSensitiveData(encryptedUser.BitgetSecret)
                if err != nil {
                        log.Printf("Warning: Failed to decrypt secret for user %d: %v", userID, err)
                        user.BitgetSecret = ""
                } else {
                        user.BitgetSecret = decrypted
                }
        }
        
        if encryptedUser.BitgetPasskey != "" {
                decrypted, err := tb.decryptSensitiveData(encryptedUser.BitgetPasskey)
                if err != nil {
                        log.Printf("Warning: Failed to decrypt passkey for user %d: %v", userID, err)
                        user.BitgetPasskey = ""
                } else {
                        user.BitgetPasskey = decrypted
                }
        }
        
        return &user, true
}

// Save or update user data (encrypts sensitive fields before saving)
func (tb *TelegramBot) saveUser(user *UserData) error {
        tb.database.mutex.Lock()
        defer tb.database.mutex.Unlock()

        user.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
        if user.CreatedAt == "" {
                user.CreatedAt = user.UpdatedAt
        }

        // Create a copy for encryption (don't modify original)
        encryptedUser := *user
        
        // Encrypt sensitive fields before saving
        if user.BitgetAPIKey != "" {
                encrypted, err := tb.encryptSensitiveData(user.BitgetAPIKey)
                if err != nil {
                        return fmt.Errorf("failed to encrypt API key: %v", err)
                }
                encryptedUser.BitgetAPIKey = encrypted
        }
        
        if user.BitgetSecret != "" {
                encrypted, err := tb.encryptSensitiveData(user.BitgetSecret)
                if err != nil {
                        return fmt.Errorf("failed to encrypt secret: %v", err)
                }
                encryptedUser.BitgetSecret = encrypted
        }
        
        if user.BitgetPasskey != "" {
                encrypted, err := tb.encryptSensitiveData(user.BitgetPasskey)
                if err != nil {
                        return fmt.Errorf("failed to encrypt passkey: %v", err)
                }
                encryptedUser.BitgetPasskey = encrypted
        }

        tb.database.Users[user.UserID] = &encryptedUser
        return tb.saveDatabaseUnsafe() // Use unsafe version since we already have lock
}

// Get all active users (with decrypted credentials)
func (tb *TelegramBot) getAllActiveUsers() []*UserData {
        tb.database.mutex.RLock()
        defer tb.database.mutex.RUnlock()

        var activeUsers []*UserData
        for _, encryptedUser := range tb.database.Users {
                if encryptedUser.IsActive {
                        // Decrypt sensitive fields for each user
                        user := *encryptedUser
                        
                        if encryptedUser.BitgetAPIKey != "" {
                                if decrypted, err := tb.decryptSensitiveData(encryptedUser.BitgetAPIKey); err == nil {
                                        user.BitgetAPIKey = decrypted
                                } else {
                                        log.Printf("Warning: Failed to decrypt API key for user %d: %v", encryptedUser.UserID, err)
                                        user.BitgetAPIKey = ""
                                }
                        }
                        
                        if encryptedUser.BitgetSecret != "" {
                                if decrypted, err := tb.decryptSensitiveData(encryptedUser.BitgetSecret); err == nil {
                                        user.BitgetSecret = decrypted
                                } else {
                                        log.Printf("Warning: Failed to decrypt secret for user %d: %v", encryptedUser.UserID, err)
                                        user.BitgetSecret = ""
                                }
                        }
                        
                        if encryptedUser.BitgetPasskey != "" {
                                if decrypted, err := tb.decryptSensitiveData(encryptedUser.BitgetPasskey); err == nil {
                                        user.BitgetPasskey = decrypted
                                } else {
                                        log.Printf("Warning: Failed to decrypt passkey for user %d: %v", encryptedUser.UserID, err)
                                        user.BitgetPasskey = ""
                                }
                        }
                        
                        activeUsers = append(activeUsers, &user)
                }
        }
        return activeUsers
}

// Start file watcher for upbit_new.json to trigger auto-trading
func (tb *TelegramBot) startFileWatcher() {
        watcher, err := fsnotify.NewWatcher()
        if err != nil {
                log.Printf("❌ Failed to create file watcher: %v", err)
                return
        }
        defer watcher.Close()

        // Watch upbit_new.json file
        upbitFile := "upbit_new.json"
        err = watcher.Add(upbitFile)
        if err != nil {
                log.Printf("❌ Failed to watch %s: %v", upbitFile, err)
                return
        }

        log.Printf("👁️  Started watching %s for new UPBIT listings...", upbitFile)

        // Initialize with current latest symbol to prevent triggering on startup
        if latestSymbol := tb.getLatestDetectedSymbol(); latestSymbol != "" {
                tb.lastProcessedSymbol = latestSymbol
                log.Printf("🔄 Current latest symbol: %s", latestSymbol)
        }

        for {
                select {
                case event, ok := <-watcher.Events:
                        if !ok {
                                return
                        }
                        if event.Op&fsnotify.Write == fsnotify.Write {
                                log.Printf("📝 Detected file change: %s", event.Name)
                                tb.processUpbitFile()
                        }
                case err, ok := <-watcher.Errors:
                        if !ok {
                                return
                        }
                        log.Printf("❌ File watcher error: %v", err)
                }
        }
}

// Get latest detected symbol from upbit_new.json
func (tb *TelegramBot) getLatestDetectedSymbol() string {
        data, err := ioutil.ReadFile("upbit_new.json")
        if err != nil {
                log.Printf("Warning: Could not read upbit_new.json: %v", err)
                return ""
        }

        var upbitData UpbitData
        if err := json.Unmarshal(data, &upbitData); err != nil {
                log.Printf("Warning: Could not parse upbit_new.json: %v", err)
                return ""
        }

        if len(upbitData.Listings) == 0 {
                return ""
        }

        // Return the latest (first) detection symbol - Go monitor inserts new listings at index 0
        return upbitData.Listings[0].Symbol
}

// Process upbit_new.json changes and trigger auto-trading
func (tb *TelegramBot) processUpbitFile() {
        latestSymbol := tb.getLatestDetectedSymbol()
        if latestSymbol == "" {
                return
        }

        // Check if this is a new symbol we haven't processed yet
        if latestSymbol == tb.lastProcessedSymbol {
                log.Printf("🔄 Symbol %s already processed, skipping", latestSymbol)
                return
        }

        // Update last processed symbol
        tb.lastProcessedSymbol = latestSymbol
        log.Printf("🚨 NEW UPBIT LISTING DETECTED: %s", latestSymbol)

        // Get all active users for auto-trading
        activeUsers := tb.getAllActiveUsers()
        if len(activeUsers) == 0 {
                log.Printf("⚠️  No active users found for auto-trading")
                return
        }

        log.Printf("📊 Triggering auto-trading for %d users on symbol: %s", len(activeUsers), latestSymbol)

        // Trigger auto-trading for each active user
        for _, user := range activeUsers {
                go tb.executeAutoTrade(user, latestSymbol)
        }
}

// Execute automatic trading for a user when new UPBIT listing is detected
func (tb *TelegramBot) executeAutoTrade(user *UserData, symbol string) {
        log.Printf("🤖 Auto-trading for user %d (%s) on symbol: %s", user.UserID, user.Username, symbol)

        // Validate user has complete setup
        if user.BitgetAPIKey == "" || user.BitgetSecret == "" || user.BitgetPasskey == "" {
                log.Printf("⚠️  User %d missing API credentials, skipping auto-trade", user.UserID)
                tb.sendMessage(user.UserID, fmt.Sprintf("🚫 Auto-trade failed for %s: Missing API credentials. Please /setup first.", symbol))
                return
        }

        if user.MarginUSDT <= 0 {
                log.Printf("⚠️  User %d has invalid margin amount: %f", user.UserID, user.MarginUSDT)
                tb.sendMessage(user.UserID, fmt.Sprintf("🚫 Auto-trade failed for %s: Invalid margin amount. Please /setup first.", symbol))
                return
        }

        // Format symbol for Bitget (add USDT suffix)
        tradingSymbol := symbol + "USDT"
        
        // Initialize Bitget API client
        bitgetAPI := NewBitgetAPI(user.BitgetAPIKey, user.BitgetSecret, user.BitgetPasskey)
        
        // Send notification to user
        tb.sendMessage(user.UserID, fmt.Sprintf("🚀 Auto-trade triggered for %s\nMargin: %.2f USDT\nLeverage: %dx\nOpening long position...", tradingSymbol, user.MarginUSDT, user.Leverage))
        
        // Execute long position
        result, err := bitgetAPI.OpenLongPosition(tradingSymbol, user.MarginUSDT, user.Leverage)
        if err != nil {
                log.Printf("❌ Auto-trade failed for user %d on %s: %v", user.UserID, tradingSymbol, err)
                tb.sendMessage(user.UserID, fmt.Sprintf("❌ Auto-trade FAILED for %s: %v", tradingSymbol, err))
                return
        }

        log.Printf("✅ Auto-trade SUCCESS for user %d on %s", user.UserID, tradingSymbol)
        
        // Send success notification with close position button
        resultText := fmt.Sprintf("Pozisyon başarıyla açıldı! OrderId: %s", result.OrderID)
        tb.sendPositionNotification(user.UserID, tradingSymbol, resultText)
}

// Send message to user (helper method)
func (tb *TelegramBot) sendMessage(chatID int64, text string) {
        msg := tgbotapi.NewMessage(chatID, text)
        _, err := tb.bot.Send(msg)
        if err != nil {
                log.Printf("Failed to send message to %d: %v", chatID, err)
        }
}

// Create main menu keyboard
func (tb *TelegramBot) createMainMenu() tgbotapi.InlineKeyboardMarkup {
        return tgbotapi.NewInlineKeyboardMarkup(
                tgbotapi.NewInlineKeyboardRow(
                        tgbotapi.NewInlineKeyboardButtonData("📊 Bakiye", "balance"),
                        tgbotapi.NewInlineKeyboardButtonData("⚙️ Ayarlar", "settings"),
                ),
                tgbotapi.NewInlineKeyboardRow(
                        tgbotapi.NewInlineKeyboardButtonData("🔧 Setup", "setup"),
                        tgbotapi.NewInlineKeyboardButtonData("❌ Pozisyonları Kapat", "close_all"),
                ),
                tgbotapi.NewInlineKeyboardRow(
                        tgbotapi.NewInlineKeyboardButtonData("📈 Pozisyonlar", "positions"),
                        tgbotapi.NewInlineKeyboardButtonData("❓ Yardım", "help"),
                ),
        )
}

// Handle /start command
func (tb *TelegramBot) handleStart(chatID int64, userID int64, username string) {
        user, exists := tb.getUser(userID)
        if !exists {
                // Create new user
                user = &UserData{
                        UserID:   userID,
                        Username: username,
                        IsActive: false,
                        State:    StateNone,
                }
                tb.saveUser(user)
        }

        welcomeMsg := fmt.Sprintf(`👋 **Hoşgeldin @%s!**

🚀 **Upbit-Bitget Otomatik Trading Botu**

Bu bot, Upbit'te listelenen yeni coinleri otomatik olarak Bitget'te long position ile alır.

**Nasıl Çalışır:**
1. Upbit'te yeni coin listesi açıklandığında
2. Bot otomatik olarak Bitget'te long position açar
3. Senin belirlediğin miktar ve leverage ile işlem yapar

**Ana Menü:** Aşağıdaki butonlardan istediğin işlemi seç:`, username)

        msg := tgbotapi.NewMessage(chatID, welcomeMsg)
        msg.ParseMode = "Markdown"
        msg.ReplyMarkup = tb.createMainMenu()
        tb.bot.Send(msg)
}

// Handle /setup command (start setup process)
func (tb *TelegramBot) handleSetup(chatID int64, userID int64, username string) {
        setupMsg := `🔧 **Bitget API Setup**

API bilgilerinizi adım adım girelim:

1️⃣ **Bitget API Key'inizi gönderin**

API bilgilerinizi Bitget > API Management bölümünden alabilirsiniz:
https://www.bitget.com/api-doc

⚠️ **Güvenlik:** Sensitive data güvenli şekilde saklanır.
⚠️ **İptal:** Setup'ı iptal etmek için /start yazın.`

        msg := tgbotapi.NewMessage(chatID, setupMsg)
        msg.ParseMode = "Markdown"
        tb.bot.Send(msg)

        // Set user state for expecting API key
        user, exists := tb.getUser(userID)
        if !exists {
                user = &UserData{
                        UserID:   userID,
                        Username: username,
                        IsActive: false,
                        State:    StateAwaitingKey,
                }
        } else {
                user.State = StateAwaitingKey
        }
        
        tb.saveUser(user)
}

// Handle /settings command
func (tb *TelegramBot) handleSettings(chatID int64, userID int64) {
        log.Printf("🔧 Settings called for user %d", userID)
        
        user, exists := tb.getUser(userID)
        if !exists {
                log.Printf("❌ User %d not found", userID)
                msg := tgbotapi.NewMessage(chatID, "❌ Henüz hiç kurulum yapmadınız. 🔧 Setup butonuna tıklayın.")
                msg.ReplyMarkup = tb.createMainMenu()
                tb.bot.Send(msg)
                return
        }
        
        if user.BitgetAPIKey == "" {
                log.Printf("❌ User %d has no API key", userID)
                msg := tgbotapi.NewMessage(chatID, "❌ Henüz API ayarlarını yapmadınız. 🔧 Setup butonuna tıklayın.")
                msg.ReplyMarkup = tb.createMainMenu()
                tb.bot.Send(msg)
                return
        }
        
        log.Printf("✅ Showing settings for user %d", userID)

        // Calculate risk level properly
        var riskLevel string
        if user.Leverage <= 5 {
                riskLevel = "🟢 Düşük"
        } else if user.Leverage <= 20 {
                riskLevel = "🟡 Orta"
        } else {
                riskLevel = "🔴 Yüksek"
        }

        // Safe API key preview
        var keyPreview string
        if len(user.BitgetAPIKey) >= 8 {
                keyPreview = user.BitgetAPIKey[:8] + "..."
        } else {
                keyPreview = strings.Repeat("*", len(user.BitgetAPIKey)) + "..."
        }

        // Professional settings summary with safe formatting
        settingsMsg := fmt.Sprintf(`⚙️ *Trading Ayarlarınız*

👤 *Hesap Bilgileri:*
• Kullanıcı: @%s (ID: %d)
• Durum: %s

💰 *Trade Parametreleri:*
• Margin Miktarı: %.2f USDT
• Leverage Oranı: %dx
• Risk Seviyesi: %s

🔐 *API Konfigürasyonu:*
• API Key: %s
• Bağlantı Durumu: ✅ Aktif
• Son Güncelleme: Bitget v2 API

🚀 *Auto-Trading:*
• UPBIT Listening: 🟢 Aktif
• Otomatik İşlem: %s
• Pozisyon Yönetimi: Otomatik

💡 *Hızlı İşlemler:*
🔧 Setup değiştirmek için: /setup
📊 Bakiye görmek için: /start menüsü
📈 Pozisyonlar için: /start menüsü`,
                user.Username,
                user.UserID,
                map[bool]string{true: "🟢 Aktif", false: "🔴 Pasif"}[user.IsActive],
                user.MarginUSDT,
                user.Leverage,
                riskLevel,
                keyPreview,
                map[bool]string{true: "🟢 Aktif", false: "🔴 Pasif"}[user.IsActive])

        log.Printf("📤 Creating settings message for chat %d", chatID)
        msg := tgbotapi.NewMessage(chatID, settingsMsg)
        msg.ParseMode = "Markdown"
        msg.ReplyMarkup = tb.createMainMenu()
        
        log.Printf("📤 Sending settings message...")
        response, err := tb.bot.Send(msg)
        if err != nil {
                log.Printf("❌ Failed to send settings message: %v", err)
                // Try simpler message
                simpleMsg := tgbotapi.NewMessage(chatID, "⚙️ Settings error. Bot çalışıyor ama mesaj gönderemedi.")
                tb.bot.Send(simpleMsg)
        } else {
                log.Printf("✅ Settings message sent successfully! Message ID: %d", response.MessageID)
        }
}

// Handle /close command
func (tb *TelegramBot) handleClose(chatID int64, userID int64) {
        user, exists := tb.getUser(userID)
        if !exists || user.BitgetAPIKey == "" {
                msg := tgbotapi.NewMessage(chatID, "❌ API ayarlarını yapmadınız.")
                tb.bot.Send(msg)
                return
        }

        if !user.IsActive {
                msg := tgbotapi.NewMessage(chatID, "❌ Setup'ınız tamamlanmamış. /setup komutunu kullanın.")
                tb.bot.Send(msg)
                return
        }

        msg := tgbotapi.NewMessage(chatID, "🚨 Tüm pozisyonlarınız kapatılıyor...")
        tb.bot.Send(msg)

        // Close all positions using Bitget API
        tb.closeUserPositions(chatID, user)
}

// Close all positions for a user
func (tb *TelegramBot) closeUserPositions(chatID int64, user *UserData) {
        api := NewBitgetAPI(user.BitgetAPIKey, user.BitgetSecret, user.BitgetPasskey)
        
        // Close all USDT futures positions
        resp, err := api.CloseAllPositions()
        if err != nil {
                errorMsg := fmt.Sprintf("❌ Pozisyon kapatma başarısız:\n%s", err.Error())
                msg := tgbotapi.NewMessage(chatID, errorMsg)
                tb.bot.Send(msg)
                return
        }

        successMsg := fmt.Sprintf(`✅ **Pozisyonlar Başarıyla Kapatıldı**

📋 **Order ID:** %s
👤 **Kullanıcı:** @%s
💼 **Tüm USDT-Futures pozisyonlarınız kapatıldı.**

/settings - Ayarları görüntüle
/setup - Yeni ayarlar yap`, resp.OrderID, user.Username)

        msg := tgbotapi.NewMessage(chatID, successMsg)
        msg.ParseMode = "Markdown"
        tb.bot.Send(msg)
}

// Main message handler
func (tb *TelegramBot) handleMessage(update tgbotapi.Update) {
        if update.Message == nil {
                return
        }

        chatID := update.Message.Chat.ID
        userID := update.Message.From.ID
        username := update.Message.From.UserName
        text := update.Message.Text

        log.Printf("📨 Message from @%s (ID:%d): %s", username, userID, text)

        // Handle commands
        if update.Message.IsCommand() {
                switch update.Message.Command() {
                case "start":
                        tb.handleStart(chatID, userID, username)
                case "setup":
                        tb.handleSetup(chatID, userID, username)
                case "settings", "setting":  // Both /settings and /setting work
                        tb.handleSettings(chatID, userID)
                case "close":
                        tb.handleClose(chatID, userID)
                case "status":
                        msg := tgbotapi.NewMessage(chatID, "🤖 Bot aktif olarak çalışıyor!")
                        tb.bot.Send(msg)
                case "help":
                        tb.handleStart(chatID, userID, username) // Same as start
                default:
                        msg := tgbotapi.NewMessage(chatID, "❓ Bilinmeyen komut. /help komutunu deneyin.")
                        tb.bot.Send(msg)
                }
                return
        }

        // Handle non-command messages (setup process)
        tb.handleSetupProcess(chatID, userID, text)
}

// Handle setup process messages (API key, secret, etc.)
func (tb *TelegramBot) handleSetupProcess(chatID int64, userID int64, text string) {
        user, exists := tb.getUser(userID)
        if !exists || user.State == StateNone {
                return // User not in setup process
        }

        switch user.State {
        case StateAwaitingKey:
                user.BitgetAPIKey = strings.TrimSpace(text)
                user.State = StateAwaitingSecret
                tb.saveUser(user)
                
                msg := tgbotapi.NewMessage(chatID, "✅ API Key alındı!\n\n2️⃣ **Secret Key'inizi gönderin**")
                msg.ParseMode = "Markdown"
                tb.bot.Send(msg)

        case StateAwaitingSecret:
                user.BitgetSecret = strings.TrimSpace(text)
                user.State = StateAwaitingPasskey
                tb.saveUser(user)
                
                msg := tgbotapi.NewMessage(chatID, "✅ Secret Key alındı!\n\n3️⃣ **Passphrase'inizi gönderin**")
                msg.ParseMode = "Markdown"
                tb.bot.Send(msg)

        case StateAwaitingPasskey:
                user.BitgetPasskey = strings.TrimSpace(text)
                user.State = StateAwaitingMargin
                tb.saveUser(user)
                
                msg := tgbotapi.NewMessage(chatID, "✅ Passphrase alındı!\n\n4️⃣ **Margin tutarını USDT olarak gönderin**\nÖrnek: 100")
                msg.ParseMode = "Markdown"
                tb.bot.Send(msg)

        case StateAwaitingMargin:
                margin, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
                if err != nil || margin <= 0 {
                        msg := tgbotapi.NewMessage(chatID, "❌ Geçersiz tutar! Pozitif bir sayı girin (örn: 100)")
                        tb.bot.Send(msg)
                        return
                }
                
                user.MarginUSDT = margin
                user.State = StateAwaitingLeverage
                tb.saveUser(user)
                
                msg := tgbotapi.NewMessage(chatID, "✅ Margin tutarı alındı!\n\n5️⃣ **Leverage değerini gönderin**\nÖrnek: 10 (10x leverage için)")
                msg.ParseMode = "Markdown"
                tb.bot.Send(msg)

        case StateAwaitingLeverage:
                leverage, err := strconv.Atoi(strings.TrimSpace(text))
                if err != nil || leverage < 1 || leverage > 125 {
                        msg := tgbotapi.NewMessage(chatID, "❌ Geçersiz leverage! 1-125 arası bir sayı girin")
                        tb.bot.Send(msg)
                        return
                }
                
                user.Leverage = leverage
                user.State = StateComplete
                user.IsActive = true
                tb.saveUser(user)
                
                // Test API credentials
                tb.testUserAPI(chatID, user)

        default:
                // Reset to start if unknown state
                user.State = StateNone
                tb.saveUser(user)
        }
}

// Test user's Bitget API credentials
func (tb *TelegramBot) testUserAPI(chatID int64, user *UserData) {
        msg := tgbotapi.NewMessage(chatID, "🔍 API bağlantısı test ediliyor...")
        tb.bot.Send(msg)

        api := NewBitgetAPI(user.BitgetAPIKey, user.BitgetSecret, user.BitgetPasskey)
        
        // Test API with account balance
        _, err := api.GetAccountBalance()
        if err != nil {
                user.IsActive = false
                user.State = StateNone
                tb.saveUser(user)
                
                errorMsg := fmt.Sprintf(`❌ **API Bağlantısı Başarısız**

Hata: %s

Lütfen API bilgilerinizi kontrol edip /setup ile tekrar deneyin.

**Kontrol Listesi:**
• API Key doğru mu?
• Secret Key doğru mu? 
• Passphrase doğru mu?
• API'da futures trading izni var mı?`, err.Error())

                msg := tgbotapi.NewMessage(chatID, errorMsg)
                msg.ParseMode = "Markdown"
                tb.bot.Send(msg)
                return
        }

        successMsg := fmt.Sprintf(`✅ **Setup Başarıyla Tamamlandı!**

👤 **Kullanıcı:** @%s
💰 **Margin:** %.2f USDT
📈 **Leverage:** %dx
🔐 **API:** Bağlantı başarılı
🎯 **Durum:** Aktif - Auto trading hazır!

🚀 **Bot artık Upbit'te yeni listelenen coinleri otomatik olarak Bitget'te long position ile alacak.**

**Komutlar:**
• /settings - Ayarları görüntüle
• /close - Tüm pozisyonları kapat
• /setup - Ayarları değiştir`, user.Username, user.MarginUSDT, user.Leverage)

        msg = tgbotapi.NewMessage(chatID, successMsg)
        msg.ParseMode = "Markdown"
        tb.bot.Send(msg)
}

// Start the bot
func (tb *TelegramBot) Start() {
        log.Printf("🤖 Telegram Bot starting...")

        updateConfig := tgbotapi.NewUpdate(0)
        updateConfig.Timeout = 60

        updates := tb.bot.GetUpdatesChan(updateConfig)

        for update := range updates {
                if update.Message != nil {
                        tb.handleMessage(update)
                } else if update.CallbackQuery != nil {
                        tb.handleCallbackQuery(update.CallbackQuery)
                }
        }
}

// Handle callback queries from inline keyboards
func (tb *TelegramBot) handleCallbackQuery(callback *tgbotapi.CallbackQuery) {
        // Answer the callback query to remove loading state
        callbackConfig := tgbotapi.NewCallback(callback.ID, "")
        tb.bot.Request(callbackConfig)

        chatID := callback.Message.Chat.ID
        userID := callback.From.ID
        data := callback.Data

        switch data {
        case "balance":
                tb.handleBalanceQuery(chatID, userID)
        case "settings":
                tb.handleSettings(chatID, userID)
        case "setup":
                tb.handleSetup(chatID, userID, callback.From.UserName)
        case "close_all":
                tb.handleClose(chatID, userID)
        case "positions":
                tb.handlePositionsQuery(chatID, userID)
        case "help":
                tb.handleHelpQuery(chatID)
        case "main_menu":
                tb.handleStart(chatID, userID, callback.From.UserName)
        default:
                if strings.HasPrefix(data, "close_position_") {
                        symbol := strings.TrimPrefix(data, "close_position_")
                        tb.handleCloseSpecificPosition(chatID, userID, symbol)
                }
        }
}

// Handle balance query
func (tb *TelegramBot) handleBalanceQuery(chatID int64, userID int64) {
        user, exists := tb.getUser(userID)
        if !exists || user.BitgetAPIKey == "" {
                tb.sendMessage(chatID, "❌ Henüz API ayarlarınızı yapmadınız. 🔧 Setup butonuna tıklayın.")
                return
        }

        if !user.IsActive {
                tb.sendMessage(chatID, "❌ Setup'ınız tamamlanmamış. 🔧 Setup butonuna tıklayın.")
                return
        }

        tb.sendMessage(chatID, "💰 Bakiye bilgileri alınıyor...")

        // Get balance using Bitget API
        api := NewBitgetAPI(user.BitgetAPIKey, user.BitgetSecret, user.BitgetPasskey)
        balances, err := api.GetAccountBalance()
        if err != nil {
                tb.sendMessage(chatID, fmt.Sprintf("❌ Bakiye alınamadı: %v", err))
                return
        }

        balanceText := "📊 **Bakiye Bilgileri:**\n\n"
        if len(balances) == 0 {
                balanceText += "✅ Henüz bakiye bilgisi yok"
        } else {
                for _, balance := range balances {
                        availableFloat, _ := strconv.ParseFloat(balance.Available, 64)
                balanceText += fmt.Sprintf("💰 **%s**: %.2f USDT\n", balance.MarginCoin, availableFloat)
                }
        }

        balanceMsg := fmt.Sprintf(`💰 **Futures Bakiye**

%s

🔄 **Ana Menü için /start yazın**`, balanceText)

        msg := tgbotapi.NewMessage(chatID, balanceMsg)
        msg.ParseMode = "Markdown"
        msg.ReplyMarkup = tb.createMainMenu()
        tb.bot.Send(msg)
}

// Handle positions query
func (tb *TelegramBot) handlePositionsQuery(chatID int64, userID int64) {
        user, exists := tb.getUser(userID)
        if !exists || user.BitgetAPIKey == "" {
                tb.sendMessage(chatID, "❌ Henüz API ayarlarınızı yapmadınız. 🔧 Setup butonuna tıklayın.")
                return
        }

        if !user.IsActive {
                tb.sendMessage(chatID, "❌ Setup'ınız tamamlanmamış. 🔧 Setup butonuna tıklayın.")
                return
        }

        tb.sendMessage(chatID, "📈 Pozisyon bilgileri alınıyor...")

        // Get positions using Bitget API
        api := NewBitgetAPI(user.BitgetAPIKey, user.BitgetSecret, user.BitgetPasskey)
        positions, err := api.GetAllPositions()
        if err != nil {
                tb.sendMessage(chatID, fmt.Sprintf("❌ Pozisyonlar alınamadı: %v", err))
                return
        }

        if len(positions) == 0 {
                msg := tgbotapi.NewMessage(chatID, "📈 **Pozisyonlar**\n\n✅ Şu anda açık pozisyon bulunmuyor.")
                msg.ParseMode = "Markdown"
                msg.ReplyMarkup = tb.createMainMenu()
                tb.bot.Send(msg)
                return
        }

        positionsText := "📊 **Açık Pozisyonlar:**\n\n"
        for _, pos := range positions {
                if pos.Size != "0" {
                        positionsText += fmt.Sprintf("💹 **%s** - Size: %s - PnL: %s\n", pos.Symbol, pos.Size, pos.UnrealizedPL)
                }
        }
        
        if positionsText == "📊 **Açık Pozisyonlar:**\n\n" {
                positionsText = "✅ Şu anda açık pozisyon bulunmuyor."
        }

        positionsMsg := fmt.Sprintf(`📈 **Açık Pozisyonlar**

%s

🔄 **Ana Menü için /start yazın**`, positionsText)

        msg := tgbotapi.NewMessage(chatID, positionsMsg)
        msg.ParseMode = "Markdown"
        msg.ReplyMarkup = tb.createMainMenu()
        tb.bot.Send(msg)
}

// Handle help query
func (tb *TelegramBot) handleHelpQuery(chatID int64) {
        helpMsg := `❓ **Yardım & Rehber**

🚀 **Bot Nasıl Çalışır:**
• Upbit'te yeni coin listelendiğinde otomatik tespit eder
• Sizin ayarlarınızla Bitget'te long position açar
• İşlem sonucunu size bildirir
• İstediğinizde pozisyonları kapatabilirsiniz

🔧 **Setup Süreci:**
1. 📊 Bakiye - Futures bakiyenizi görüntüleyin
2. ⚙️ Ayarlar - Mevcut ayarlarınızı kontrol edin
3. 🔧 Setup - API bilgilerinizi girin
4. ❌ Pozisyonları Kapat - Tüm pozisyonları kapatın

⚠️ **Önemli Uyarılar:**
• Bu bot gerçek parayla işlem yapar
• Sadece kaybetmeyi göze alabileceğiniz miktarla kullanın
• API bilgileriniz güvenli şekilde şifrelenir
• Leverage kullanımına dikkat edin

📞 **Destek:** @oxmtnslk ile iletişime geçin`

        msg := tgbotapi.NewMessage(chatID, helpMsg)
        msg.ParseMode = "Markdown"
        msg.ReplyMarkup = tb.createMainMenu()
        tb.bot.Send(msg)
}

// Handle closing specific position
func (tb *TelegramBot) handleCloseSpecificPosition(chatID int64, userID int64, symbol string) {
        user, exists := tb.getUser(userID)
        if !exists || user.BitgetAPIKey == "" {
                tb.sendMessage(chatID, "❌ API ayarlarınızı yapmadınız.")
                return
        }

        tb.sendMessage(chatID, fmt.Sprintf("🚨 %s pozisyonu kapatılıyor...", symbol))

        api := NewBitgetAPI(user.BitgetAPIKey, user.BitgetSecret, user.BitgetPasskey)
        result, err := api.FlashClosePosition(symbol, "long")
        if err != nil {
                tb.sendMessage(chatID, fmt.Sprintf("❌ %s pozisyonu kapatılamadı: %v", symbol, err))
                return
        }

        tb.sendMessage(chatID, fmt.Sprintf("✅ %s pozisyonu başarıyla kapatıldı!\n\nPozisyon ID: %s", symbol, result.OrderID))
}

// Send position notification with close button
func (tb *TelegramBot) sendPositionNotification(chatID int64, symbol string, result string) {
        notificationMsg := fmt.Sprintf(`🎉 **Pozisyon Açıldı!**

💹 **Sembol:** %s
📊 **Sonuç:** 
%s

**Pozisyonunuzu istediğiniz zaman kapatabilirsiniz:**`, symbol, result)

        // Create close position button
        closeButton := tgbotapi.NewInlineKeyboardMarkup(
                tgbotapi.NewInlineKeyboardRow(
                        tgbotapi.NewInlineKeyboardButtonData(fmt.Sprintf("❌ %s Pozisyonunu Kapat", symbol), fmt.Sprintf("close_position_%s", symbol)),
                ),
                tgbotapi.NewInlineKeyboardRow(
                        tgbotapi.NewInlineKeyboardButtonData("📊 Bakiye", "balance"),
                        tgbotapi.NewInlineKeyboardButtonData("📈 Tüm Pozisyonlar", "positions"),
                ),
                tgbotapi.NewInlineKeyboardRow(
                        tgbotapi.NewInlineKeyboardButtonData("🏠 Ana Menü", "main_menu"),
                ),
        )

        msg := tgbotapi.NewMessage(chatID, notificationMsg)
        msg.ParseMode = "Markdown"
        msg.ReplyMarkup = closeButton
        tb.bot.Send(msg)
}

// StartTradingBot starts the trading bot (to be called from main.go)
func StartTradingBot() {
        token := os.Getenv("TELEGRAM_BOT_TOKEN")
        if token == "" {
                log.Fatal("TELEGRAM_BOT_TOKEN environment variable is required")
        }

        bot, err := NewTelegramBot(token)
        if err != nil {
                log.Fatalf("Failed to create bot: %v", err)
        }

        log.Printf("🚀 Starting Multi-User Upbit-Bitget Auto Trading Bot...")
        bot.Start()
}

// Main entry point  
func main() {
        StartTradingBot()
}