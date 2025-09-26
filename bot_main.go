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
        HumanTime   string `json:"human_time"`
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

        var detections []UpbitDetection
        if err := json.Unmarshal(data, &detections); err != nil {
                log.Printf("Warning: Could not parse upbit_new.json: %v", err)
                return ""
        }

        if len(detections) == 0 {
                return ""
        }

        // Return the latest (last) detection symbol
        return detections[len(detections)-1].Symbol
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
        tb.sendMessage(user.UserID, fmt.Sprintf("✅ Auto-trade SUCCESS for %s!\n\n%s", tradingSymbol, result))
}

// Send message to user (helper method)
func (tb *TelegramBot) sendMessage(chatID int64, text string) {
        msg := tgbotapi.NewMessage(chatID, text)
        _, err := tb.bot.Send(msg)
        if err != nil {
                log.Printf("Failed to send message to %d: %v", chatID, err)
        }
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

        welcomeMsg := `🚀 **Upbit-Bitget Auto Trading Bot**

Bu bot Upbit'te yeni listelenen coinleri otomatik olarak Bitget'te long position ile alır.

**Başlangıç Adımları:**
1. /setup - Bitget API bilgilerinizi ve ayarlarınızı girin
2. Bot otomatik olarak yeni Upbit coinlerini izleyecek
3. /close - İstediğinizde pozisyonlarınızı kapatın

**Komutlar:**
• /setup - API bilgilerini ve ayarları gir
• /settings - Mevcut ayarları görüntüle
• /status - Bot durumunu kontrol et  
• /close - Tüm pozisyonları kapat
• /help - Yardım menüsü

⚠️ **Uyarı:** Bu bot gerçek parayla işlem yapar. Ayarlarınızı dikkatli yapın!`

        msg := tgbotapi.NewMessage(chatID, welcomeMsg)
        msg.ParseMode = "Markdown"
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
        user, exists := tb.getUser(userID)
        if !exists || user.BitgetAPIKey == "" {
                msg := tgbotapi.NewMessage(chatID, "❌ Henüz API ayarlarını yapmadınız. /setup komutunu kullanın.")
                tb.bot.Send(msg)
                return
        }

        settingsMsg := fmt.Sprintf(`⚙️ **Mevcut Ayarlarınız**

👤 **Kullanıcı:** @%s
💰 **Margin:** %.2f USDT
📈 **Leverage:** %dx
🔐 **API Key:** %s...
✅ **Durum:** %s

/setup - Ayarları değiştir
/close - Pozisyonları kapat`,
                user.Username,
                user.MarginUSDT,
                user.Leverage,
                user.BitgetAPIKey[:8],
                map[bool]string{true: "Aktif", false: "Pasif"}[user.IsActive])

        msg := tgbotapi.NewMessage(chatID, settingsMsg)
        msg.ParseMode = "Markdown"
        tb.bot.Send(msg)
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
                case "settings":
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
                tb.handleMessage(update)
        }
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