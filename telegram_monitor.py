#!/usr/bin/env python3
"""
Telegram Channel Monitor for Upbit Listings
Monitors @AstronomicaNews channel for UPBIT LISTING messages and extracts cryptocurrency symbols.
"""

import os
import json
import re
import logging
import time
from datetime import datetime
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError, FloodWaitError
import asyncio

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('telegram_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TelegramUpbitMonitor:
    def __init__(self):
        api_id_env = os.getenv('TELEGRAM_API_ID')
        api_hash_env = os.getenv('TELEGRAM_API_HASH')
        self.channel_username = 'AstronomicaNews'
        self.json_file = 'upbit_new.json'
        self.detected_symbols = set()
        self.session_name = 'telegram_monitor_session'
        
        if not api_id_env or not api_hash_env:
            raise ValueError("TELEGRAM_API_ID and TELEGRAM_API_HASH environment variables must be set")
        
        # Auto-detect which value is the API ID (numeric) and which is the hash (string)
        try:
            # Try converting api_id_env to int
            self.api_id = int(api_id_env)
            self.api_hash = api_hash_env
        except ValueError:
            try:
                # If that fails, try the other way around
                self.api_id = int(api_hash_env)
                self.api_hash = api_id_env
            except ValueError:
                raise ValueError("Neither TELEGRAM_API_ID nor TELEGRAM_API_HASH contains a valid integer")
        
        logger.info(f"Using API ID: {self.api_id}")
        logger.info(f"Using API Hash: {self.api_hash[:8]}...")  # Only show first 8 chars for security
        
        self.client = TelegramClient(self.session_name, self.api_id, self.api_hash)
        
        # Load existing data
        self.load_existing_data()
        
    def load_existing_data(self):
        """Load existing symbols from JSON file to prevent duplicates"""
        try:
            if os.path.exists(self.json_file):
                with open(self.json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for entry in data:
                            if isinstance(entry, dict) and 'symbol' in entry:
                                self.detected_symbols.add(entry['symbol'])
                    elif isinstance(data, dict) and 'listings' in data:
                        for entry in data['listings']:
                            if isinstance(entry, dict) and 'symbol' in entry:
                                self.detected_symbols.add(entry['symbol'])
                logger.info(f"Loaded {len(self.detected_symbols)} existing symbols from {self.json_file}")
        except Exception as e:
            logger.error(f"Error loading existing data: {e}")
            self.detected_symbols = set()

    def extract_crypto_symbols(self, text):
        """Extract cryptocurrency symbols from parentheses in the text"""
        # Pattern to match text in parentheses, expecting uppercase letters
        pattern = r'\(([A-Z]{2,10})\)'
        matches = re.findall(pattern, text.upper())
        return matches

    def save_to_json(self, symbol):
        """Save new symbol to JSON file with atomic write"""
        timestamp = datetime.now().isoformat()
        
        # Load existing data
        data = {'listings': []}
        try:
            if os.path.exists(self.json_file):
                with open(self.json_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                    if isinstance(existing_data, dict) and 'listings' in existing_data:
                        data = existing_data
                    elif isinstance(existing_data, list):
                        data = {'listings': existing_data}
        except Exception as e:
            logger.error(f"Error reading existing JSON: {e}")
        
        # Add new entry
        new_entry = {
            'symbol': symbol,
            'timestamp': timestamp,
            'detected_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        }
        data['listings'].append(new_entry)
        
        # Atomic write using temporary file
        temp_file = self.json_file + '.tmp'
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(temp_file, self.json_file)
            logger.info(f"Successfully saved {symbol} to {self.json_file}")
        except Exception as e:
            logger.error(f"Error saving to JSON: {e}")
            if os.path.exists(temp_file):
                os.remove(temp_file)

    async def start_client(self):
        """Start the Telegram client and authenticate if needed"""
        try:
            await self.client.start()
            me = await self.client.get_me()
            logger.info(f"Successfully authenticated as: {me.first_name or me.username or 'Unknown'}")
            
            # Try to get channel entity to verify access
            try:
                entity = await self.client.get_entity(f"@{self.channel_username}")
                channel_name = getattr(entity, 'title', getattr(entity, 'username', 'Unknown'))
                logger.info(f"Successfully connected to channel: {channel_name} (@{self.channel_username})")
            except Exception as e:
                logger.error(f"Could not access channel @{self.channel_username}: {e}")
                raise
                
        except Exception as e:
            logger.error(f"Failed to start client: {e}")
            raise

    async def check_recent_messages(self):
        """Check recent messages from the channel"""
        try:
            entity = await self.client.get_entity(f"@{self.channel_username}")
            
            # Get recent messages (last 50)
            messages = await self.client.get_messages(entity, limit=50)
            
            processed_count = 0
            if messages:
                for message in messages:
                    if message and message.text:
                        await self.process_message(message)
                        processed_count += 1
            
            logger.info(f"Processed {processed_count} recent messages from @{self.channel_username}")
                
        except FloodWaitError as e:
            logger.warning(f"Rate limited, waiting {e.seconds} seconds")
            await asyncio.sleep(e.seconds)
        except Exception as e:
            logger.error(f"Error checking recent messages: {e}")

    async def process_message(self, message):
        """Process a message to check for UPBIT listings"""
        if not message.text:
            return
            
        text = message.text.upper()
        logger.debug(f"Processing message: {message.text[:100]}...")
        
        # Check if message contains UPBIT LISTING
        if 'UPBIT LISTING' in text:
            logger.info(f"Found UPBIT LISTING message: {message.text}")
            
            # Extract symbols from parentheses
            symbols = self.extract_crypto_symbols(message.text)
            
            for symbol in symbols:
                if symbol not in self.detected_symbols:
                    logger.info(f"New symbol detected: {symbol}")
                    self.detected_symbols.add(symbol)
                    self.save_to_json(symbol)
                else:
                    logger.info(f"Symbol {symbol} already detected, skipping")

    async def monitor_once(self):
        """Single monitoring cycle"""
        logger.info("Checking for new messages...")
        if not self.client.is_connected():
            await self.start_client()
        await self.check_recent_messages()


    async def setup_real_time_monitoring(self):
        """Setup real-time event handler for new messages"""
        @self.client.on(events.NewMessage(chats=f"@{self.channel_username}"))
        async def handler(event):
            logger.info("Received new message from channel")
            await self.process_message(event.message)
        
        logger.info("Real-time message handler registered")

async def main_async():
    """Main async function to run the monitoring service"""
    logger.info("Starting Telegram Upbit Monitor...")
    
    try:
        monitor = TelegramUpbitMonitor()
        logger.info(f"Monitor initialized. Watching @{monitor.channel_username} for UPBIT LISTING messages")
        logger.info(f"Output file: {monitor.json_file}")
        
        # Start the client and authenticate
        await monitor.start_client()
        
        # Set up real-time monitoring
        await monitor.setup_real_time_monitoring()
        
        # Run initial check of recent messages
        await monitor.check_recent_messages()
        
        logger.info("Starting continuous monitoring with real-time updates and periodic checks...")
        
        # Set up periodic message checking (every 60 seconds)
        last_check_time = time.time()
        check_interval = 60  # 60 seconds
        
        # Keep the client running
        while True:
            current_time = time.time()
            
            # Periodic message check
            if current_time - last_check_time >= check_interval:
                try:
                    logger.info("Running periodic message check...")
                    await monitor.check_recent_messages()
                    last_check_time = current_time
                except Exception as e:
                    logger.error(f"Error in periodic check: {e}")
            
            # Keep client alive
            if not monitor.client.is_connected():
                logger.warning("Client disconnected, attempting to reconnect...")
                try:
                    await monitor.start_client()
                    await monitor.setup_real_time_monitoring()
                except Exception as e:
                    logger.error(f"Failed to reconnect: {e}")
                    await asyncio.sleep(30)  # Wait before retry
                    continue
            
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Monitor stopped by user")
        if 'monitor' in locals() and monitor.client:
            await monitor.client.disconnect()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if 'monitor' in locals() and monitor.client:
            await monitor.client.disconnect()
        raise

def main():
    """Main function to run the monitoring service"""
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Application failed: {e}")
        raise

if __name__ == "__main__":
    main()