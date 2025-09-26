# Overview

This project is a Telegram channel monitoring system specifically designed to track cryptocurrency listing announcements on Upbit exchange. It monitors the @AstronomicaNews Telegram channel for messages containing "UPBIT LISTING" keywords and automatically extracts cryptocurrency symbols from these announcements. The detected symbols are stored in a JSON file with timestamps for further processing or analysis.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Core Application Structure
The system is built around a single Python class `TelegramUpbitMonitor` that handles all monitoring functionality. The architecture follows an event-driven pattern using the Telethon library to listen for new messages in real-time.

## Message Processing Pipeline
The system implements a message filtering and extraction pipeline:
1. **Channel Monitoring** - Continuously listens to the specified Telegram channel
2. **Message Filtering** - Identifies messages containing Upbit listing announcements
3. **Symbol Extraction** - Uses regular expressions to extract cryptocurrency symbols
4. **Data Storage** - Saves detected symbols with timestamps to JSON format
5. **Duplicate Prevention** - Maintains a set of already detected symbols to avoid duplicates

## Authentication & Session Management
The system uses Telegram's API authentication with session persistence. It auto-detects API credentials from environment variables and handles the distinction between API ID (numeric) and API hash (string) automatically. Sessions are stored locally to avoid repeated authentication.

## Error Handling & Resilience
The architecture includes comprehensive error handling for common Telegram API issues:
- Flood wait error handling with automatic retry logic
- Session authentication errors
- Network connectivity issues
- Graceful degradation and logging for debugging

## Data Storage Format
Uses a simple JSON-based storage system with structured records containing:
- Cryptocurrency symbol
- ISO timestamp of detection
- Human-readable detection time
- Array-based structure for easy querying and processing

# External Dependencies

## Telegram API Integration
- **Telethon Library** - Official Telegram client library for Python
- **Telegram API Credentials** - Requires API ID and API hash from Telegram
- **Channel Access** - Monitors @AstronomicaNews public channel

## System Dependencies
- **Python 3** - Core runtime environment
- **Environment Variables** - TELEGRAM_API_ID and TELEGRAM_API_HASH for API access
- **Local File System** - For session storage and JSON data persistence
- **Logging System** - Built-in Python logging with file and console output

## Data Processing
- **Regular Expressions** - For cryptocurrency symbol extraction from message text
- **JSON** - For structured data storage and retrieval
- **asyncio** - For asynchronous message handling and event processing