package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
	"path/filepath"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/updates"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/session"
)

type ListingEntry struct {
	Symbol     string `json:"symbol"`
	Timestamp  string `json:"timestamp"`
	DetectedAt string `json:"detected_at"`
}

type ListingsData struct {
	Listings []ListingEntry `json:"listings"`
}

type TelegramUpbitMonitor struct {
	client         *telegram.Client
	channelUsername string
	jsonFile       string
	detectedSymbols map[string]bool
	ctx            context.Context
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

func (m *TelegramUpbitMonitor) messageHandler(ctx context.Context, e tg.Entities, u *tg.UpdateNewChannelMessage) error {
	msg, ok := u.Message.(*tg.Message)
	if !ok {
		return nil
	}

	// Check if message is from our target channel
	if peer, ok := msg.PeerID.(*tg.PeerChannel); ok {
		// Get channel info to verify it's the right channel
		if channel, exists := e.Channels[peer.ChannelID]; exists {
			if channel.Username == m.channelUsername {
				if msg.Message != "" {
					log.Printf("Received new message from @%s", m.channelUsername)
					m.processMessage(msg.Message)
				}
			}
		}
	}

	return nil
}

func (m *TelegramUpbitMonitor) checkRecentMessages() error {
	// Get channel entity
	resolved, err := m.client.API().ContactsResolveUsername(m.ctx, m.channelUsername)
	if err != nil {
		return fmt.Errorf("failed to resolve channel: %v", err)
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
		log.Printf("Processing %d recent messages from @%s", len(channelMessages.Messages), m.channelUsername)
		
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

	// Setup Telegram client
	apiID := os.Getenv("TELEGRAM_API_ID")
	apiHash := os.Getenv("TELEGRAM_API_HASH")

	if apiID == "" || apiHash == "" {
		return fmt.Errorf("TELEGRAM_API_ID and TELEGRAM_API_HASH environment variables must be set")
	}

	// Create session storage directory
	sessionDir := "./sessions"
	os.MkdirAll(sessionDir, 0755)

	// Create client
	opts := telegram.Options{
		SessionStorage: &session.FileStorage{
			Path: filepath.Join(sessionDir, "session.json"),
		},
	}

	m.client = telegram.NewClient(mustParseInt(apiID), apiHash, opts)

	// Start client
	return m.client.Run(m.ctx, func(ctx context.Context) error {
		log.Printf("Successfully authenticated with Telegram")

		// Set up message handler for real-time updates
		dispatcher := tg.NewUpdateDispatcher()
		gaps := updates.New(updates.Config{
			Handler: dispatcher,
		})

		dispatcher.OnNewChannelMessage(m.messageHandler)

		// Check recent messages first
		log.Printf("Checking recent messages...")
		if err := m.checkRecentMessages(); err != nil {
			log.Printf("Error checking recent messages: %v", err)
		}

		log.Printf("Starting continuous monitoring...")
		
		// Set up periodic checks
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		go func() {
			for range ticker.C {
				log.Printf("Running periodic message check...")
				if err := m.checkRecentMessages(); err != nil {
					log.Printf("Error in periodic check: %v", err)
				}
			}
		}()

		// Start updates handling
		return gaps.Run(ctx, m.client.API(), auth.NewFlow(auth.Constant("", "", auth.CodeAuthenticatorFunc(
			func(ctx context.Context, sentCode *tg.AuthSentCode) (string, error) {
				return "", fmt.Errorf("interactive authentication required")
			})),
			auth.SendCodeOptions{}))
	})
}

func mustParseInt(s string) int {
	// Try to parse as integer
	if i := 0; true {
		for _, r := range s {
			if r >= '0' && r <= '9' {
				i = i*10 + int(r-'0')
			} else {
				break
			}
		}
		if i > 0 {
			return i
		}
	}
	panic(fmt.Sprintf("invalid integer: %s", s))
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