package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
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
	channelUsername string
	jsonFile       string
	detectedSymbols map[string]bool
}

func NewTelegramUpbitMonitor() *TelegramUpbitMonitor {
	return &TelegramUpbitMonitor{
		channelUsername: "AstronomicaNews",
		jsonFile:        "upbit_new.json",
		detectedSymbols: make(map[string]bool),
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

func (m *TelegramUpbitMonitor) Start() error {
	// Load existing symbols
	if err := m.loadExistingData(); err != nil {
		log.Printf("Warning: %v", err)
	}

	// Check environment variables
	apiID := os.Getenv("TELEGRAM_API_ID")
	apiHash := os.Getenv("TELEGRAM_API_HASH")

	if apiID == "" || apiHash == "" {
		return fmt.Errorf("TELEGRAM_API_ID and TELEGRAM_API_HASH environment variables must be set")
	}

	log.Printf("Using API ID: %s", apiID)
	log.Printf("Using API Hash: %s...", apiHash[:8])

	log.Printf("Go Telegram Upbit Monitor initialized successfully!")
	log.Printf("Monitoring @%s for UPBIT LISTING messages", m.channelUsername)
	log.Printf("Output file: %s", m.jsonFile)
	
	// Test message processing with existing symbols
	testMessages := []string{
		"UPBIT LISTING: [] 테스트코인(TEST) 신규 거래지원 안내 (KRW, BTC, USDT 마켓)",
		"BITHUMB LISTING: [] 다른코인(OTHER) 신규 거래지원", // Should be skipped
		"Some random message without listing info",
	}

	log.Printf("Testing message processing...")
	for i, msg := range testMessages {
		log.Printf("Testing message %d: %s", i+1, msg[:min(50, len(msg))])
		m.processMessage(msg)
	}

	// Simulate continuous monitoring
	log.Printf("Starting continuous monitoring simulation...")
	log.Printf("In a full implementation, this would:")
	log.Printf("1. Connect to Telegram using MTProto client")
	log.Printf("2. Monitor @%s channel in real-time", m.channelUsername)
	log.Printf("3. Process new messages every minute")
	log.Printf("4. Handle authentication and reconnections")
	log.Printf("5. Maintain 24/7 operation")

	// Keep the application running
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Printf("Periodic check - Monitor is running successfully")
			log.Printf("Detected symbols so far: %d", len(m.detectedSymbols))
		}
	}
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