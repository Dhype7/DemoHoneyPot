import requests
from typing import Dict, Any, Optional
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from settings import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

class TelegramNotifier:
    """Handles sending Telegram alerts for honeypot events"""
    
    def __init__(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None):
        """
        Initialize Telegram notifier
        
        Args:
            bot_token: Telegram bot token (if not provided, will use config)
            chat_id: Telegram chat ID (if not provided, will use config)
        """
        self.bot_token = bot_token or TELEGRAM_BOT_TOKEN
        self.chat_id = chat_id or TELEGRAM_CHAT_ID
        self.base_url = "https://api.telegram.org/bot"
        
        if not self.bot_token or not self.chat_id or self.bot_token == "your_telegram_bot_token_here" or self.chat_id == "your_chat_id_here":
            print("Warning: Telegram bot token or chat ID not configured. Alerts will be disabled.")
            self.enabled = False
        else:
            self.enabled = True
    
    def send_alert(self, connection_data: Dict[str, Any]) -> bool:
        """
        Send a Telegram alert for a new connection attempt
        
        Args:
            connection_data: Dictionary containing connection information
            
        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        if not self.enabled:
            print("Telegram alerts are disabled due to missing configuration")
            return False
        
        try:
            message = self._format_alert_message(connection_data)
            
            url = f"{self.base_url}{self.bot_token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if result.get('ok'):
                print(f"Telegram alert sent successfully for connection from {connection_data.get('ip_address')}")
                return True
            else:
                print(f"Failed to send Telegram alert: {result.get('description', 'Unknown error')}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"Error sending Telegram alert: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error sending Telegram alert: {e}")
            return False
    
    def _format_alert_message(self, connection_data: Dict[str, Any]) -> str:
        """
        Format connection data into a Telegram message
        
        Args:
            connection_data: Connection information dictionary
            
        Returns:
            str: Formatted HTML message for Telegram
        """
        ip_address = connection_data.get('ip_address', 'Unknown')
        port = connection_data.get('port', 'Unknown')
        service = connection_data.get('service_name', 'Unknown')
        timestamp = connection_data.get('timestamp', datetime.now())
        
        # Format timestamp
        if isinstance(timestamp, datetime):
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            timestamp_str = str(timestamp)
        
        # Get location info
        country = connection_data.get('country', 'Unknown')
        city = connection_data.get('city', 'Unknown')
        isp = connection_data.get('isp', 'Unknown')
        
        # Create location string
        location_parts = []
        if city and city != 'Unknown':
            location_parts.append(city)
        if country and country != 'Unknown':
            location_parts.append(country)
        location_str = ", ".join(location_parts) if location_parts else "Unknown"
        
        # Create emoji based on service
        service_emoji = {
            'SSH': '🔐',
            'HTTP': '🌐',
            'MySQL': '🗄️',
            'FTP': '📁',
            'SMTP': '📧'
        }.get(service, '🔍')
        
        message = f"""
🚨 <b>HONEYPOT ALERT</b> 🚨

{service_emoji} <b>Service:</b> {service}
🌍 <b>IP Address:</b> <code>{ip_address}</code>
🔌 <b>Port:</b> {port}
⏰ <b>Time:</b> {timestamp_str}

📍 <b>Location:</b> {location_str}
🏢 <b>ISP:</b> {isp}

⚠️ <i>Potential intrusion attempt detected!</i>
        """.strip()
        
        return message
    
    def send_status_update(self, stats: Dict[str, Any]) -> bool:
        """
        Send a status update with honeypot statistics
        
        Args:
            stats: Dictionary containing honeypot statistics
            
        Returns:
            bool: True if update was sent successfully, False otherwise
        """
        if not self.enabled:
            return False
        
        try:
            message = self._format_status_message(stats)
            
            url = f"{self.base_url}{self.bot_token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            return result.get('ok', False)
            
        except Exception as e:
            print(f"Error sending status update: {e}")
            return False
    
    def _format_status_message(self, stats: Dict[str, Any]) -> str:
        """
        Format statistics into a status message
        
        Args:
            stats: Statistics dictionary
            
        Returns:
            str: Formatted HTML status message
        """
        total_connections = stats.get('total_connections', 0)
        service_stats = stats.get('service_stats', {})
        top_ips = stats.get('top_ips', [])
        top_countries = stats.get('top_countries', [])
        
        message = f"""
📊 <b>HONEYPOT STATUS REPORT</b>

🔢 <b>Total Connections:</b> {total_connections}

📈 <b>Service Breakdown:</b>
"""
        
        for service, count in service_stats.items():
            message += f"• {service}: {count}\n"
        
        if top_ips:
            message += "\n🏆 <b>Top IP Addresses:</b>\n"
            for ip, count in top_ips[:5]:
                message += f"• {ip}: {count} attempts\n"
        
        if top_countries:
            message += "\n🌍 <b>Top Countries:</b>\n"
            for country, count in top_countries[:5]:
                message += f"• {country}: {count} attempts\n"
        
        return message.strip()
    
    def test_connection(self) -> bool:
        """
        Test the Telegram bot connection
        
        Returns:
            bool: True if connection is working, False otherwise
        """
        if not self.enabled:
            return False
        
        try:
            url = f"{self.base_url}{self.bot_token}/getMe"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if result.get('ok'):
                bot_info = result.get('result', {})
                print(f"Telegram bot connection successful: {bot_info.get('first_name', 'Unknown')}")
                return True
            else:
                print(f"Telegram bot connection failed: {result.get('description', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"Error testing Telegram connection: {e}")
            return False 