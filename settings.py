"""
Configuration file for the Honeypot System
==========================================

This file contains all configuration settings for the honeypot system.
Edit the values below to customize your setup.
"""

# ============================================================================
# TELEGRAM BOT CONFIGURATION
# ============================================================================
# Get these from @BotFather on Telegram
TELEGRAM_BOT_TOKEN = ""  # Replace with your actual bot token
TELEGRAM_CHAT_ID = 0  # Replace with your actual chat ID (as integer)

# ============================================================================
# HONEYPOT SERVICE CONFIGURATION
# ============================================================================
HOST = "0.0.0.0"
SSH_PORT = 22
HTTP_PORT = 80
MYSQL_PORT = 3306
FTP_PORT = 2122

# ============================================================================
# WEB INTERFACE CONFIGURATION
# ============================================================================
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================
DATABASE_PATH = "database/honeypot.db"  

# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================
# Rate Limiting
MAX_CONNECTIONS_PER_MINUTE = 10
MAX_FAILED_AUTH_PER_MINUTE = 5
AUTO_BLACKLIST_ENABLED = True
BLACKLIST_DURATION_HOURS = 24

# ============================================================================
# THREAT INTELLIGENCE CONFIGURATION
# ============================================================================
THREAT_INTELLIGENCE_ENABLED = True
ABUSEIPDB_KEY = ""  # Get from https://www.abuseipdb.com/
SHODAN_KEY = ""     # Get from https://account.shodan.io/
THREAT_CACHE_DURATION = 3600  # Cache duration in seconds (1 hour)

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = "logs/honeypot.log"
LOG_MAX_SIZE_MB = 100

# ============================================================================
# GEOIP CONFIGURATION
# ============================================================================
GEOIP_RATE_LIMIT_DELAY = 0.1  # Seconds between API calls

# ============================================================================
# ADVANCED CONFIGURATION
# ============================================================================
# Web Interface Settings
WEB_DEBUG_MODE = True
WEB_SECRET_KEY = "honeypot-secret-key-2024"

# Connection Timeouts
CONNECTION_TIMEOUT = 30  # seconds
READ_TIMEOUT = 10       # seconds

# Notification Settings
NOTIFICATION_ENABLED = True
STATUS_UPDATE_INTERVAL = 60  # seconds

# File Upload Settings (for FTP)
FTP_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
FTP_WELCOME_MESSAGE = "Welcome to FTP Server"

# SSH Settings
SSH_WELCOME_MESSAGE = "Welcome to SSH Server"
SSH_MAX_ATTEMPTS = 3

# HTTP Settings
HTTP_WELCOME_MESSAGE = "Welcome to HTTP Server"
HTTP_SERVER_NAME = "Apache/2.4.41 (Ubuntu)"

# MySQL Settings
MYSQL_WELCOME_MESSAGE = "Welcome to MySQL Server"
MYSQL_VERSION = "8.0.26"
