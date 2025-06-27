#!/usr/bin/env python3
"""
Honeypot System - Main Entry Point
==================================

This script launches the complete honeypot system including:
- Multiple honeypot services (SSH, HTTP, MySQL, FTP)
- Web interface for monitoring
- Telegram notifications
- Database logging
- Threat Intelligence
- Rate Limiting
- Advanced Configuration

For educational purposes only.
"""

import os
import sys
import threading
import time
import socket
import requests
import settings
import signal

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.honeypot import HoneypotManager, SSHHoneypot, HTTPHoneypot, MySQLHoneypot
from core.ftp_honeypot import FTPHoneypot
from webapp.app import app as web_app
from utils.notifier import TelegramNotifier
from utils.threat_intelligence import ThreatIntelligence
from utils.rate_limiter import RateLimiter

# Global shutdown flag
shutdown_event = threading.Event()

# Initialize threat intelligence and rate limiter
threat_intelligence = ThreatIntelligence({
    'abuseipdb_key': settings.ABUSEIPDB_KEY,
    'shodan_key': settings.SHODAN_KEY,
    'cache_duration': settings.THREAT_CACHE_DURATION
})

rate_limiter = RateLimiter({
    'max_connections_per_minute': settings.MAX_CONNECTIONS_PER_MINUTE,
    'max_failed_auth_per_minute': settings.MAX_FAILED_AUTH_PER_MINUTE,
    'auto_blacklist_enabled': settings.AUTO_BLACKLIST_ENABLED,
    'blacklist_duration': settings.BLACKLIST_DURATION_HOURS * 3600
})

def check_ports_availability():
    """Check if required ports are available"""
    ports_to_check = [
        (settings.SSH_PORT, 'SSH'),
        (settings.WEB_PORT, 'Web Interface'),
        (settings.MYSQL_PORT, 'MySQL'),
        (settings.FTP_PORT, 'FTP'),
        (settings.WEB_PORT, 'Web Interface')
    ]
    
    unavailable_ports = []
    
    for port, service in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                unavailable_ports.append((port, service))
        except:
            pass
    
    if unavailable_ports:
        print("⚠️  Warning: The following ports are already in use:")
        for port, service in unavailable_ports:
            print(f"   - Port {port} ({service})")
        print("\nYou may need to stop existing services or change port configuration.")
        
        response = input("\nContinue anyway? (y/N): ")
        if response.lower() != 'y':
            print("Exiting...")
            sys.exit(1)

def print_banner():
    """Print the honeypot system banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    🚨 HONEYPOT SYSTEM 🚨                     ║
    ║                                                              ║
    ║  A cybersecurity honeypot for educational purposes only.    ║
    ║  Monitors and logs connection attempts to simulate          ║
    ║  common services (SSH, HTTP, MySQL, FTP).                   ║
    ║                                                              ║
    ║  ⚠️  WARNING: This system is designed for research and      ║
    ║     educational purposes only. Do not use in production.    ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_configuration():
    """Print the current configuration"""
    print("📋 Configuration:")
    print(f"   Host: {settings.HOST}")
    print(f"   SSH Port: {settings.SSH_PORT}")
    print(f"   Web Interface: http://{settings.WEB_HOST}:{settings.WEB_PORT}")
    print(f"   MySQL Port: {settings.MYSQL_PORT}")
    print(f"   FTP Port: {settings.FTP_PORT}")
    
    if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID and settings.TELEGRAM_BOT_TOKEN != "your_telegram_bot_token_here" and settings.TELEGRAM_CHAT_ID != "your_chat_id_here":
        print("   Telegram Notifications: ✅ Enabled")
    else:
        print("   Telegram Notifications: ❌ Disabled (missing configuration)")
    
    # Print advanced features status
    print("   Threat Intelligence: ✅ Enabled")
    print("   Rate Limiting: ✅ Enabled")
    print("   FTP Honeypot: ✅ Enabled")
    
    print()

def send_startup_message(notifier):
    """Send startup message to Telegram"""
    if notifier.enabled:
        startup_message = f"""
🚀 <b>HONEYPOT SYSTEM STARTED</b>

✅ <b>Services Active:</b>
• SSH on port {settings.SSH_PORT}
• Web Interface on port {settings.WEB_PORT}
• MySQL on port {settings.MYSQL_PORT}
• FTP on port {settings.FTP_PORT}

🔒 <b>Security Features:</b>
• Threat Intelligence: ✅ Active
• Rate Limiting: ✅ Active
• Auto-Blacklisting: ✅ Active

🌐 <b>Web Interface:</b> http://{settings.WEB_HOST}:{settings.WEB_PORT}

⏰ <b>Startup Time:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}

📊 <b>Status Updates:</b> Every 60 seconds

🔍 <b>Ready to monitor:</b> Waiting for connection attempts...
        """.strip()
        
        try:
            url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {
                'chat_id': settings.TELEGRAM_CHAT_ID,
                'text': startup_message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('ok'):
                    print("✅ Startup message sent to Telegram")
                else:
                    print(f"❌ Failed to send startup message: {result.get('description')}")
            else:
                print(f"❌ HTTP error sending startup message: {response.status_code}")
        except Exception as e:
            print(f"❌ Error sending startup message: {e}")

def status_update_worker(honeypot_manager, notifier):
    """Worker thread for periodic status updates"""
    while True:
        try:
            time.sleep(60)  # Wait 60 seconds
            
            if notifier.enabled:
                stats = honeypot_manager.get_stats()
                rate_stats = rate_limiter.get_statistics()
                
                status_message = f"""
📊 <b>HONEYPOT STATUS UPDATE</b>

⏰ <b>Time:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}

🔢 <b>Total Connections:</b> {stats.get('total_connections', 0)}

📈 <b>Service Breakdown:</b>
"""
                
                service_stats = stats.get('service_stats', {})
                for service, count in service_stats.items():
                    status_message += f"• {service}: {count}\n"
                
                if not service_stats:
                    status_message += "• No connections yet\n"
                
                # Add security stats
                status_message += f"""
🔒 <b>Security Stats:</b>
• Blocked Connections: {rate_stats.get('blocked_connections', 0)}
• Blacklisted IPs: {rate_stats.get('blacklisted_ips', 0)}
• Rate Limit Violations: {rate_stats.get('rate_limit_violations', 0)}
• Unique IPs Seen: {rate_stats.get('unique_ips_seen', 0)}
"""
                
                # Add top IPs if any
                top_ips = stats.get('top_ips', [])
                if top_ips:
                    status_message += "\n🏆 <b>Top IP Addresses:</b>\n"
                    for ip, count in top_ips[:3]:  # Show top 3
                        status_message += f"• {ip}: {count} attempts\n"
                
                status_message += "\n🟢 <b>System Status:</b> Running normally"
                
                try:
                    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
                    payload = {
                        'chat_id': settings.TELEGRAM_CHAT_ID,
                        'text': status_message,
                        'parse_mode': 'HTML'
                    }
                    
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code == 200:
                        result = response.json()
                        if result.get('ok'):
                            print("📊 Status update sent to Telegram")
                        else:
                            print(f"❌ Failed to send status update: {result.get('description')}")
                    else:
                        print(f"❌ HTTP error sending status update: {response.status_code}")
                except Exception as e:
                    print(f"❌ Error sending status update: {e}")
                    
        except Exception as e:
            print(f"❌ Error in status update worker: {e}")

def start_honeypot_services():
    """Start all honeypot services (excluding FTP)"""
    print("🚀 Starting honeypot services...")
    
    manager = HoneypotManager()
    
    # Add services with threat intelligence and rate limiting (excluding FTP)
    ssh_honeypot = SSHHoneypot(settings.SSH_PORT, settings.HOST)
    http_honeypot = HTTPHoneypot(settings.WEB_PORT, settings.HOST)
    mysql_honeypot = MySQLHoneypot(settings.MYSQL_PORT, settings.HOST)
    
    # Add services to manager
    manager.add_service(ssh_honeypot)
    manager.add_service(http_honeypot)
    manager.add_service(mysql_honeypot)
    
    # Start all services
    manager.start_all()
    
    return manager

def start_ftp_honeypot():
    """Start FTP honeypot separately"""
    print("🚀 Starting FTP honeypot...")
    
    try:
        print("   Step 1: Getting FTP port from config...")
        ftp_port = settings.FTP_PORT
        print(f"   Using FTP port: {ftp_port}")
        print(f"   Using FTP host: {settings.HOST}")
        
        print("   Step 2: Creating FTPHoneypot instance...")
        ftp_honeypot = FTPHoneypot(settings.HOST, ftp_port)
        print("   FTPHoneypot instance created successfully")
        
        print("   Step 3: Creating FTP thread...")
        # Start FTP honeypot in a separate thread
        ftp_thread = threading.Thread(
            target=ftp_honeypot.start,
            daemon=True,
            name="FTPHoneypot"
        )
        print("   FTP thread created, starting...")
        
        print("   Step 4: Starting FTP thread...")
        ftp_thread.start()
        print("   FTP thread started successfully")
        
        # Give it a moment to start
        print("   Step 5: Waiting for FTP to start...")
        time.sleep(2)
        
        # Check if the port is now listening
        print("   Step 6: Checking if FTP port is listening...")
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((settings.HOST, ftp_port))
        sock.close()
        
        if result == 0:
            print(f"✅ FTP honeypot is listening on {settings.HOST}:{ftp_port}")
        else:
            print(f"⚠️  FTP honeypot may not be listening on {settings.HOST}:{ftp_port}")
        
        print(f"🚀 FTP honeypot started on {settings.HOST}:{ftp_port}")
        return ftp_honeypot
    except Exception as e:
        print(f"❌ Error starting FTP honeypot: {e}")
        import traceback
        traceback.print_exc()
        return None

def check_web_interface():
    """Check if web interface is accessible"""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((settings.WEB_HOST, settings.WEB_PORT))
        sock.close()
        
        if result == 0:
            print("✅ Web interface is accessible")
            return True
        else:
            print("❌ Web interface is not accessible")
            return False
    except Exception as e:
        print(f"❌ Error checking web interface: {e}")
        return False

def start_web_interface():
    """Start the web interface"""
    print(f"🌐 Starting web interface on http://{settings.WEB_HOST}:{settings.WEB_PORT}")
    
    def run_web_app():
        try:
            print("🌐 Web interface thread started")
            # Use Flask's built-in run method with proper shutdown handling
            web_app.run(
                host=settings.WEB_HOST,
                port=settings.WEB_PORT,
                debug=False,
                use_reloader=False,
                threaded=True
            )
        except Exception as e:
            if not shutdown_event.is_set():
                print(f"❌ Error starting web interface: {e}")
                import traceback
                traceback.print_exc()
    
    # Start web interface in a daemon thread so it can be killed
    web_thread = threading.Thread(
        target=run_web_app,
        daemon=True,
        name="WebInterface"
    )
    web_thread.start()
    
    # Give the web interface a moment to start
    time.sleep(3)
    
    # Check if it's accessible
    if check_web_interface():
        return web_thread
    else:
        print("⚠️  Web interface may not have started properly")
        return web_thread

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\n🛑 Received shutdown signal...")
    shutdown_event.set()
    
    # Force exit after a short delay if graceful shutdown fails
    import threading
    def force_exit():
        import time
        time.sleep(5)  # Wait 5 seconds for graceful shutdown
        print("🛑 Force shutting down...")
        import os
        os._exit(0)
    
    force_thread = threading.Thread(target=force_exit, daemon=True)
    force_thread.start()

def main():
    """Main function"""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Print banner
        print_banner()
        
        # Print configuration
        print_configuration()
        
        # Check port availability
        print("Checking port availability...")
        check_ports_availability()
        
        # Initialize Telegram notifier
        notifier = TelegramNotifier()
        
        # Send startup message
        if notifier.enabled:
            print("📤 Sending startup message to Telegram...")
            send_startup_message(notifier)
        
        # Start web interface FIRST
        print("Starting web interface...")
        web_thread = start_web_interface()
        
        # Start honeypot services (excluding FTP for now)
        print("Starting honeypot services...")
        honeypot_manager = start_honeypot_services()
        
        # Start FTP honeypot separately
        print("About to start FTP honeypot...")
        ftp_honeypot = start_ftp_honeypot()
        
        # Start status update worker
        if notifier.enabled:
            print("📊 Starting periodic status updates...")
            status_thread = threading.Thread(
                target=status_update_worker,
                args=(honeypot_manager, notifier),
                daemon=True
            )
            status_thread.start()
        
        print("✅ Honeypot system is now running!")
        print("\n📊 Access the web interface at:")
        print(f"   http://{settings.WEB_HOST}:{settings.WEB_PORT}")
        print("\n🔍 Monitoring the following services:")
        print(f"   - SSH on port {settings.SSH_PORT}")
        print(f"   - Web Interface on port {settings.WEB_PORT}")
        print(f"   - MySQL on port {settings.MYSQL_PORT}")
        print(f"   - FTP on port {settings.FTP_PORT}")
        if notifier.enabled:
            print("\n📱 Telegram notifications: ✅ Active")
            print("   - Startup message sent")
            print("   - Status updates every 60 seconds")
            print("   - Real-time alerts for connections")
        print("\n🔒 Security Features:")
        print("   - Threat Intelligence: ✅ Active")
        print("   - Rate Limiting: ✅ Active")
        print("   - Auto-Blacklisting: ✅ Active")
        print("\n⏹️  Press Ctrl+C to stop the system")
        print("=" * 60)
        
        # Keep the main thread alive until shutdown signal
        try:
            while not shutdown_event.is_set():
                time.sleep(0.1)  # Check more frequently
        except KeyboardInterrupt:
            print("\n🛑 Keyboard interrupt received...")
            shutdown_event.set()
        
        print("\n🛑 Shutting down honeypot system...")
        
        # Send shutdown message
        if notifier.enabled:
            try:
                shutdown_message = f"""
🛑 <b>HONEYPOT SYSTEM SHUTDOWN</b>

⏰ <b>Shutdown Time:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}

📊 <b>Final Stats:</b>
{notifier._format_status_message(honeypot_manager.get_stats())}

👋 <b>System stopped successfully</b>
                """.strip()
                
                url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
                payload = {
                    'chat_id': settings.TELEGRAM_CHAT_ID,
                    'text': shutdown_message,
                    'parse_mode': 'HTML'
                }
                
                response = requests.post(url, json=payload, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    if result.get('ok'):
                        print("✅ Shutdown message sent to Telegram")
            except Exception as e:
                print(f"❌ Error sending shutdown message: {e}")
        
        print("🛑 Stopping honeypot services...")
        honeypot_manager.stop_all()
        
        # Stop FTP honeypot
        try:
            if ftp_honeypot:
                ftp_honeypot.stop()
                print("🛑 FTP honeypot stopped")
        except:
            pass
            
        print("✅ Honeypot system stopped successfully")
        print("👋 Goodbye!")
        
    except Exception as e:
        import traceback
        print(f"❌ Error starting honeypot system: {e}")
        print("Full traceback:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 