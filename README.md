# 🚨 Advanced Honeypot System

> **A comprehensive cybersecurity honeypot system for monitoring, logging, and analyzing connection attempts to simulated services with real-time threat intelligence and web-based dashboard.**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Dhype7/DemoHonyPot?style=social)](https://github.com/Dhype7/DemoHonyPot)
[![Forks](https://img.shields.io/github/forks/Dhype7/DemoHonyPot?style=social)](https://github.com/Dhype7/DemoHonyPot)

---

## 🏆 Credits

**Created by Dhype7 from NYX Team**  
*Advanced Cybersecurity Research & Development*

---

## 🚀 Quick Start

### **Prerequisites**
- Python 3.8 or higher
- Git
- Internet connection (for threat intelligence APIs)

### **Installation**

1. **Clone the repository**
   ```bash
   git clone https://github.com/Dhype7/DemoHonyPot.git
   cd DemoHoneyPot
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the system**
   ```bash
   # Copy the example settings file
   cp settings_example.py settings.py
   
   # Edit settings.py with your configuration
   # (See Configuration section below)
   ```

4. **Start the honeypot**
   ```bash
   python main.py
   ```

5. **Access the web dashboard**
   - Open: `http://127.0.0.1:5000`

---

## ⚙️ Configuration

### **Essential Configuration**

1. **Copy the example settings**
   ```bash
   cp settings_example.py settings.py
   ```

2. **Edit `settings.py` with your configuration:**
   ```python
   # ============================================================================
   # TELEGRAM BOT CONFIGURATION (Optional but Recommended)
   # ============================================================================
   TELEGRAM_BOT_TOKEN = "your_telegram_bot_token_here"  # Get from @BotFather
   TELEGRAM_CHAT_ID = 123456789  # Your chat ID as integer

   # ============================================================================
   # HONEYPOT SERVICE CONFIGURATION
   # ============================================================================
   HOST = "0.0.0.0"  # Listen on all interfaces (recommended)
   SSH_PORT = 22     # SSH service port
   HTTP_PORT = 80    # HTTP service port
   MYSQL_PORT = 3306 # MySQL service port
   FTP_PORT = 2122   # FTP service port

   # ============================================================================
   # WEB INTERFACE CONFIGURATION
   # ============================================================================
   WEB_HOST = "127.0.0.1"  # Web interface host
   WEB_PORT = 5000         # Web interface port

   # ============================================================================
   # THREAT INTELLIGENCE CONFIGURATION (Optional)
   # ============================================================================
   ABUSEIPDB_KEY = "your_abuseipdb_key"  # Get from https://www.abuseipdb.com/
   SHODAN_KEY = "your_shodan_key"        # Get from https://account.shodan.io/
   ```

### **Telegram Bot Setup**

1. **Create a Telegram bot**
   - Message [@BotFather](https://t.me/botfather) on Telegram
   - Send `/newbot` and follow the instructions
   - Copy the bot token

2. **Get your Chat ID**
   - Message [@userinfobot](https://t.me/userinfobot)
   - Copy your chat ID

3. **Update settings.py**
   ```python
   TELEGRAM_BOT_TOKEN = "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz"
   TELEGRAM_CHAT_ID = 123456789
   ```

### **API Keys Setup (Optional)**

1. **AbuseIPDB API Key**
   - Visit [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
   - Create an account and get your API key

2. **Shodan API Key**
   - Visit [https://account.shodan.io/](https://account.shodan.io/)
   - Create an account and get your API key

---

## 🐳 Docker Installation

### **Using Docker Compose (Recommended)**

1. **Clone and navigate to the project**
   ```bash
   git clone https://github.com/Dhype7/DemoHonyPot.git
   cd DemoHonyPot
   ```

2. **Configure for Docker**
   ```bash
   # Copy Docker settings
   cp settings_docker.py settings.py
   
   # Edit settings.py with your configuration
   ```

3. **Build and run**
   ```bash
   docker compose up -d
   ```

4. **Check status**
   ```bash
   docker compose ps
   docker compose logs -f
   ```

### **Using Docker directly**

1. **Build the image**
   ```bash
   docker build -t demohonypot .
   ```

2. **Run the container**
   ```bash
   docker run -d \
     --name honeypot \
     -p 22:22 -p 80:80 -p 3306:3306 -p 2122:2122 -p 5000:5000 \
     -v $(pwd)/database:/app/database \
     -v $(pwd)/logs:/app/logs \
     demohonypot
   ```

---

## ✨ Features

### 🔍 **Honeypot Services**
- **SSH Honeypot** - Simulates OpenSSH server with authentication logging
- **HTTP Honeypot** - Web server simulation with request analysis
- **MySQL Honeypot** - Database server simulation with query logging
- **FTP Honeypot** - File transfer protocol simulation with command logging

### 🛡️ **Security & Intelligence**
- **Real-time Threat Intelligence** - IP analysis using AbuseIPDB, Shodan, and WHOIS
- **Rate Limiting** - Automatic protection against brute force attacks
- **Auto-Blacklisting** - Dynamic IP blocking based on suspicious activity
- **Geolocation Tracking** - IP geolocation with country, city, and ISP data

### 📊 **Monitoring & Analytics**
- **Web Dashboard** - Real-time monitoring interface with connection logs
- **Threat Analysis** - Detailed risk assessment and threat scoring
- **Statistics Dashboard** - Service breakdown and connection analytics
- **Security Dashboard** - Blacklist management and threat intelligence

### 🔔 **Notifications**
- **Telegram Integration** - Real-time alerts and status updates
- **Connection Alerts** - Immediate notifications for new connections
- **Status Reports** - Periodic system health updates
- **Threat Alerts** - High-risk connection notifications

### 🛠️ **Advanced Features**
- **Docker Support** - Containerized deployment
- **Database Logging** - SQLite-based persistent storage
- **API Endpoints** - RESTful API for external integrations
- **Modular Architecture** - Extensible service framework

---

## 💻 System Requirements

### **Minimum Requirements**
- **Python**: 3.8 or higher
- **RAM**: 512MB
- **Storage**: 100MB free space
- **Network**: Internet connection for threat intelligence APIs

### **Recommended Requirements**
- **Python**: 3.11 or higher
- **RAM**: 1GB or more
- **Storage**: 500MB free space
- **OS**: Linux, Windows 10/11, or macOS

### **Optional Requirements**
- **Docker**: For containerized deployment
- **Telegram Bot**: For notifications
- **API Keys**: AbuseIPDB and Shodan for enhanced threat intelligence

---

## 🎯 Usage

### **Starting the Honeypot**

1. **Start the system**
   ```bash
   python main.py
   ```

2. **Access the web dashboard**
   - Open your browser and go to: `http://127.0.0.1:5000`
   - Or if using Docker: `http://localhost:5000`

3. **Monitor connections**
   - View real-time connection logs
   - Analyze threat intelligence data
   - Manage blacklisted IPs

### **Web Dashboard Features**

- **📊 Dashboard**: Overview of all honeypot activity
- **📋 Connections**: Detailed connection logs with filtering
- **🛡️ Security**: Threat intelligence and blacklist management
- **⚙️ Settings**: System configuration overview

### **Testing the Honeypot**

1. **SSH Test**
   ```bash
   ssh -p 22 user@your-server-ip
   ```

2. **HTTP Test**
   ```bash
   curl http://your-server-ip:80
   ```

3. **MySQL Test**
   ```bash
   mysql -h your-server-ip -P 3306 -u root -p
   ```

4. **FTP Test**
   ```bash
   ftp your-server-ip 2122
   ```

---

## 📁 Project Structure

```
DemoHonyPot/
├── core/                   # Core honeypot services
│   ├── honeypot.py        # Main honeypot manager
│   └── ftp_honeypot.py    # FTP service implementation
├── utils/                  # Utility modules
│   ├── logger.py          # Logging configuration
│   ├── notifier.py        # Telegram notifications
│   ├── geoip.py           # Geolocation services
│   ├── rate_limiter.py    # Rate limiting
│   └── threat_intelligence.py  # Threat intelligence
├── webapp/                 # Web interface
│   ├── app.py             # Flask web application
│   └── templates/         # HTML templates
├── database/              # Database files
├── logs/                  # Log files
├── main.py                # Main entry point
├── settings.py            # Configuration file
├── requirements.txt       # Python dependencies
├── Dockerfile             # Docker configuration
├── docker-compose.yml     # Docker Compose configuration
└── README.md              # This file
```

---

## 🔧 Development

### **Contributing**

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### **Local Development Setup**

1. **Clone the repository**
   ```bash
   git clone https://github.com/Dhype7/DemoHonyPot.git
   cd DemoHonyPot
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run in development mode**
   ```bash
   python main.py
   ```

---

## 📊 Statistics

- **Total Lines of Code**: ~6,080 lines
- **Python Files**: 15+
- **Services**: 4 (SSH, HTTP, MySQL, FTP)
- **API Integrations**: 3 (Telegram, AbuseIPDB, Shodan)
- **Web Interface**: Full-featured dashboard

---

## 🛡️ Security Considerations

### **Important Security Notes**

1. **This is a honeypot system** - It's designed to attract and monitor malicious activity
2. **Use in isolated environments** - Don't run on production systems
3. **Monitor logs regularly** - Check for any unexpected behavior
4. **Keep updated** - Regularly update dependencies and the system
5. **Use strong passwords** - If implementing real authentication
6. **Network isolation** - Consider running in a DMZ or isolated network

### **Legal Considerations**

- Ensure you have permission to run honeypots in your network
- Be aware of local laws regarding network monitoring
- Don't use this system for malicious purposes
- Respect privacy and data protection regulations

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Support

### **Getting Help**

- **Issues**: [GitHub Issues](https://github.com/Dhype7/DemoHonyPot/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Dhype7/DemoHonyPot/discussions)
- **Wiki**: [Project Wiki](https://github.com/Dhype7/DemoHonyPot/wiki)

### **Community**

- **Star the repository** if you find it useful
- **Fork and contribute** to improve the project
- **Share your experiences** in discussions
- **Report bugs** and request features

---

## 🙏 Acknowledgments

- **Flask** - Web framework
- **Requests** - HTTP library
- **SQLite** - Database
- **Telegram Bot API** - Notifications
- **AbuseIPDB** - Threat intelligence
- **Shodan** - Network intelligence
- **GeoIP2** - Geolocation services

---

**⭐ Star this repository if you found it helpful!** 
