package main

import (
        "bufio"
        "context"
        "encoding/json"
        "fmt"
        "io/ioutil"
        "log"
        "os"
        "regexp"
        "strconv"
        "strings"
        "time"

        "github.com/gotd/td/telegram"
        "github.com/gotd/td/telegram/auth"
        "github.com/gotd/td/telegram/updates"
        "github.com/gotd/td/tg"
        "github.com/gotd/td/session"
)

// Custom authentication handler that doesn't send empty passwords
type codeOnlyAuth struct {
        phone        string
        codeFunc     func(context.Context, *tg.AuthSentCode) (string, error)
        passwordFunc func(context.Context) (string, error)
}

func (c *codeOnlyAuth) Phone(_ context.Context) (string, error) {
        return c.phone, nil
}

func (c *codeOnlyAuth) Password(ctx context.Context) (string, error) {
        log.Printf("🔐 2FA password required...")
        return c.passwordFunc(ctx)
}

func (c *codeOnlyAuth) Code(ctx context.Context, sentCode *tg.AuthSentCode) (string, error) {
        return c.codeFunc(ctx, sentCode)
}

func (c *codeOnlyAuth) AcceptTermsOfService(_ context.Context, tos tg.HelpTermsOfService) error {
        // Auto-accept TOS if needed
        return nil
}

func (c *codeOnlyAuth) SignUp(ctx context.Context) (auth.UserInfo, error) {
        // We don't handle sign up - only sign in
        return auth.UserInfo{}, fmt.Errorf("sign up not supported - please register your phone number first")
}

type ListingEntry struct {
        Symbol     string `json:"symbol"`
        Timestamp  string `json:"timestamp"`
        DetectedAt string `json:"detected_at"`
}

type ListingsData struct {
        Listings []ListingEntry `json:"listings"`
}

type TelegramUpbitMonitor struct {
        client          *telegram.Client
        channelUsername string
        jsonFile        string
        detectedSymbols map[string]bool
        ctx             context.Context
}

func NewTelegramUpbitMonitor() *TelegramUpbitMonitor {
        return &TelegramUpbitMonitor{
                channelUsername: "AstronomicaNews",
                jsonFile:        "upbit_new.json",
                detectedSymbols: make(map[string]bool),
                ctx:             context.Background(),
        }
}

func (m *TelegramUpbitMonitor) loadExistingData() error {
        if _, err := os.Stat(m.jsonFile); os.IsNotExist(err) {
                return nil
        }

        data, err := ioutil.ReadFile(m.jsonFile)
        if err != nil {
                return fmt.Errorf("error reading JSON file: %v", err)
        }

        var listingsData ListingsData
        if err := json.Unmarshal(data, &listingsData); err != nil {
                return fmt.Errorf("error parsing JSON: %v", err)
        }

        for _, entry := range listingsData.Listings {
                m.detectedSymbols[entry.Symbol] = true
        }

        log.Printf("Loaded %d existing symbols from %s", len(m.detectedSymbols), m.jsonFile)
        return nil
}

func (m *TelegramUpbitMonitor) extractCryptoSymbols(text string) []string {
        // Pattern to match text in parentheses, expecting uppercase letters
        re := regexp.MustCompile(`\(([A-Z]{2,10})\)`)
        matches := re.FindAllStringSubmatch(strings.ToUpper(text), -1)
        
        var symbols []string
        for _, match := range matches {
                if len(match) > 1 {
                        symbols = append(symbols, match[1])
                }
        }
        return symbols
}

func (m *TelegramUpbitMonitor) saveToJSON(symbol string) error {
        // Load existing data
        var data ListingsData
        if _, err := os.Stat(m.jsonFile); err == nil {
                fileData, err := ioutil.ReadFile(m.jsonFile)
                if err != nil {
                        return fmt.Errorf("error reading existing JSON: %v", err)
                }
                json.Unmarshal(fileData, &data)
        }

        // Create new entry
        now := time.Now()
        newEntry := ListingEntry{
                Symbol:     symbol,
                Timestamp:  now.Format(time.RFC3339),
                DetectedAt: now.UTC().Format("2006-01-02 15:04:05 UTC"),
        }

        // Insert at beginning (latest first)
        data.Listings = append([]ListingEntry{newEntry}, data.Listings...)

        // Write atomically using temporary file
        tempFile := m.jsonFile + ".tmp"
        jsonData, err := json.MarshalIndent(data, "", "  ")
        if err != nil {
                return fmt.Errorf("error marshaling JSON: %v", err)
        }

        if err := ioutil.WriteFile(tempFile, jsonData, 0644); err != nil {
                return fmt.Errorf("error writing temp file: %v", err)
        }

        if err := os.Rename(tempFile, m.jsonFile); err != nil {
                os.Remove(tempFile)
                return fmt.Errorf("error renaming temp file: %v", err)
        }

        log.Printf("Successfully saved %s to %s", symbol, m.jsonFile)
        return nil
}

func (m *TelegramUpbitMonitor) processMessage(text string) {
        if text == "" {
                return
        }

        upperText := strings.ToUpper(text)
        
        // Enhanced filtering to ensure only UPBIT listings (not BITHUMB)
        isUpbitListing := strings.Contains(upperText, "UPBIT LISTING") || strings.Contains(upperText, "UPBIT LİSTELEME")
        isBithumbRelated := strings.Contains(upperText, "BITHUMB") || strings.Contains(upperText, "BİTHUMB")

        // Only process if it's a UPBIT listing and NOT related to Bithumb
        if isUpbitListing && !isBithumbRelated {
                log.Printf("Found UPBIT LISTING message: %s", text[:min(100, len(text))])

                // Extract symbols from parentheses
                symbols := m.extractCryptoSymbols(text)

                if len(symbols) > 0 {
                        for _, symbol := range symbols {
                                if !m.detectedSymbols[symbol] {
                                        log.Printf("New UPBIT symbol detected: %s", symbol)
                                        m.detectedSymbols[symbol] = true
                                        if err := m.saveToJSON(symbol); err != nil {
                                                log.Printf("Error saving symbol %s: %v", symbol, err)
                                        }
                                } else {
                                        log.Printf("UPBIT symbol %s already detected, skipping", symbol)
                                }
                        }
                } else {
                        log.Printf("No cryptocurrency symbols found in parentheses")
                }
        } else if isBithumbRelated {
                log.Printf("Skipping BITHUMB-related message")
        } else if strings.Contains(upperText, "LISTING") && !isUpbitListing {
                log.Printf("Skipping non-UPBIT listing message")
        }
}

// Interactive authentication helpers
func (m *TelegramUpbitMonitor) readPhone() (string, error) {
        fmt.Print("Telefon numaranızı girin (ör: +905551234567): ")
        reader := bufio.NewReader(os.Stdin)
        phone, err := reader.ReadString('\n')
        if err != nil {
                return "", err
        }
        return strings.TrimSpace(phone), nil
}

func (m *TelegramUpbitMonitor) readCode() (string, error) {
        fmt.Print("Telegram'dan gelen kodu girin: ")
        reader := bufio.NewReader(os.Stdin)
        code, err := reader.ReadString('\n')
        if err != nil {
                return "", err
        }
        return strings.TrimSpace(code), nil
}

func (m *TelegramUpbitMonitor) readPassword() (string, error) {
        fmt.Print("2FA şifrenizi girin (boşsa Enter'a basın): ")
        reader := bufio.NewReader(os.Stdin)
        password, err := reader.ReadString('\n')
        if err != nil {
                return "", err
        }
        return strings.TrimSpace(password), nil
}

// Message handler for real-time updates
func (m *TelegramUpbitMonitor) messageHandler(ctx context.Context, e tg.Entities, u *tg.UpdateNewChannelMessage) error {
        msg, ok := u.Message.(*tg.Message)
        if !ok {
                return nil
        }

        // Check if message is from our target channel
        if peer, ok := msg.PeerID.(*tg.PeerChannel); ok {
                if channel, exists := e.Channels[peer.ChannelID]; exists {
                        if channel.Username == m.channelUsername {
                                if msg.Message != "" {
                                        log.Printf("📨 Received new message from @%s", m.channelUsername)
                                        m.processMessage(msg.Message)
                                }
                        }
                }
        }

        return nil
}

// Check recent messages from channel
func (m *TelegramUpbitMonitor) checkRecentMessages() error {
        // Resolve channel username
        resolved, err := m.client.API().ContactsResolveUsername(m.ctx, &tg.ContactsResolveUsernameRequest{
                Username: m.channelUsername,
        })
        if err != nil {
                return fmt.Errorf("failed to resolve channel @%s: %v", m.channelUsername, err)
        }

        if len(resolved.Chats) == 0 {
                return fmt.Errorf("channel not found: @%s", m.channelUsername)
        }

        channel, ok := resolved.Chats[0].(*tg.Channel)
        if !ok {
                return fmt.Errorf("resolved entity is not a channel")
        }

        // Get recent messages
        inputPeer := &tg.InputPeerChannel{
                ChannelID:  channel.ID,
                AccessHash: channel.AccessHash,
        }

        history, err := m.client.API().MessagesGetHistory(m.ctx, &tg.MessagesGetHistoryRequest{
                Peer:  inputPeer,
                Limit: 50,
        })
        if err != nil {
                return fmt.Errorf("failed to get channel history: %v", err)
        }

        if channelMessages, ok := history.(*tg.MessagesChannelMessages); ok {
                log.Printf("📋 Processing %d recent messages from @%s", len(channelMessages.Messages), m.channelUsername)
                
                for _, msg := range channelMessages.Messages {
                        if message, ok := msg.(*tg.Message); ok && message.Message != "" {
                                m.processMessage(message.Message)
                        }
                }
        }

        return nil
}

func (m *TelegramUpbitMonitor) Start() error {
        // Load existing symbols
        if err := m.loadExistingData(); err != nil {
                log.Printf("Warning: %v", err)
        }

        // Get API credentials
        apiIDStr := os.Getenv("TELEGRAM_API_ID")
        apiHash := os.Getenv("TELEGRAM_API_HASH")

        if apiIDStr == "" || apiHash == "" {
                return fmt.Errorf("TELEGRAM_API_ID and TELEGRAM_API_HASH environment variables must be set")
        }

        // Parse API ID as integer
        apiID, err := strconv.Atoi(apiIDStr)
        if err != nil {
                // Try to parse the other way around (in case they're swapped)
                if hashID, err2 := strconv.Atoi(apiHash); err2 == nil {
                        log.Printf("⚠️  API credentials appear to be swapped, auto-correcting...")
                        apiID = hashID
                        apiHash = apiIDStr
                } else {
                        return fmt.Errorf("TELEGRAM_API_ID must be a valid integer, got: %s", apiIDStr)
                }
        }

        log.Printf("🚀 Starting Go Telegram Upbit Monitor...")
        log.Printf("📡 Using API ID: %d", apiID)
        log.Printf("🔐 Using API Hash: %s...", apiHash[:8])

        // Create session storage
        sessionDir := "./sessions"
        os.MkdirAll(sessionDir, 0755)

        // Create Telegram client
        opts := telegram.Options{
                SessionStorage: &session.FileStorage{
                        Path: fmt.Sprintf("%s/go_session.json", sessionDir),
                },
        }

        m.client = telegram.NewClient(apiID, apiHash, opts)

        // Start the client
        return m.client.Run(m.ctx, func(ctx context.Context) error {
                // Check if already authenticated
                status, err := m.client.Auth().Status(ctx)
                if err != nil {
                        return fmt.Errorf("failed to get auth status: %v", err)
                }

                if !status.Authorized {
                        log.Printf("🔐 Authentication required...")
                        
                        // Get phone number
                        phone, err := m.readPhone()
                        if err != nil {
                                return fmt.Errorf("failed to read phone number: %v", err)
                        }

                        // Clear any existing session issues
                        log.Printf("📱 Starting fresh authentication flow...")

                        // Try authentication with proper flow
                        err = m.client.Auth().IfNecessary(ctx, auth.NewFlow(
                                &codeOnlyAuth{
                                        phone: phone,
                                        codeFunc: func(ctx context.Context, sentCode *tg.AuthSentCode) (string, error) {
                                                return m.readCode()
                                        },
                                        passwordFunc: func(ctx context.Context) (string, error) {
                                                return m.readPassword()
                                        },
                                },
                                auth.SendCodeOptions{},
                        ))

                        if err != nil {
                                return fmt.Errorf("authentication failed: %v", err)
                        }
                }

                // Get user info
                me, err := m.client.Self(ctx)
                if err != nil {
                        return fmt.Errorf("failed to get self info: %v", err)
                }

                log.Printf("✅ Successfully authenticated as: %s", me.FirstName)

                // Test channel access
                log.Printf("🔍 Testing access to @%s...", m.channelUsername)
                if err := m.checkRecentMessages(); err != nil {
                        log.Printf("⚠️  Error accessing channel: %v", err)
                        log.Printf("🔄 Will continue monitoring and retry periodically...")
                } else {
                        log.Printf("✅ Successfully connected to @%s", m.channelUsername)
                }

                // Setup real-time updates handler
                dispatcher := tg.NewUpdateDispatcher()
                gaps := updates.New(updates.Config{
                        Handler: dispatcher,
                })

                // Register message handler
                dispatcher.OnNewChannelMessage(m.messageHandler)

                log.Printf("🎯 Starting continuous monitoring of @%s for UPBIT LISTING messages", m.channelUsername)
                log.Printf("💾 Output file: %s", m.jsonFile)

                // Setup periodic checks every 5 seconds
                ticker := time.NewTicker(5 * time.Second)
                defer ticker.Stop()

                go func() {
                        for range ticker.C {
                                log.Printf("🔄 Running periodic message check...")
                                if err := m.checkRecentMessages(); err != nil {
                                        log.Printf("❌ Error in periodic check: %v", err)
                                }
                        }
                }()

                // Start the updates loop
                log.Printf("🟢 Monitor is now running - listening for real-time updates...")
                return gaps.Run(ctx, m.client.API(), me.ID, updates.AuthOptions{
                        IsBot: false,
                })
        })
}

func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}

func main() {
        log.SetFlags(log.LstdFlags | log.Lshortfile)
        log.Printf("Starting Telegram Upbit Monitor (Go)...")

        monitor := NewTelegramUpbitMonitor()
        
        if err := monitor.Start(); err != nil {
                log.Fatalf("Monitor failed: %v", err)
        }
}