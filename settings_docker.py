"""
Docker Configuration file for the Honeypot System
================================================

This file contains Docker-specific configuration settings.
Environment variables can override these settings.
"""

import os

# ============================================================================
# TELEGRAM BOT CONFIGURATION
# ============================================================================
# Get these from @BotFather on Telegram
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = int(os.getenv("TELEGRAM_CHAT_ID", ""))

# ============================================================================
# HONEYPOT SERVICE CONFIGURATION
# ============================================================================
HOST = os.getenv("HOST", "0.0.0.0")  # Docker containers should bind to 0.0.0.0
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
FTP_PORT = int(os.getenv("FTP_PORT", "2122"))

# ============================================================================
# WEB INTERFACE CONFIGURATION
# ============================================================================
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")  # Docker containers should bind to 0.0.0.0
WEB_PORT = int(os.getenv("WEB_PORT", "5000"))

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
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
SHODAN_KEY = os.getenv("SHODAN_KEY", "")
THREAT_CACHE_DURATION = 3600

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
GEOIP_RATE_LIMIT_DELAY = 0.1

# ============================================================================
# ADVANCED CONFIGURATION
# ============================================================================
# Web Interface Settings
WEB_DEBUG_MODE = False
WEB_SECRET_KEY = "honeypot-secret-key-2024"

# Connection Timeouts
CONNECTION_TIMEOUT = 30
READ_TIMEOUT = 10

# Notification Settings
NOTIFICATION_ENABLED = True
STATUS_UPDATE_INTERVAL = 60

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