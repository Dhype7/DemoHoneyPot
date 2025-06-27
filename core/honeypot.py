import socket
import threading
import time
import os
from datetime import datetime
from typing import Dict, Any, Optional, Union
import sys
import socket as pysocket  # For reverse DNS
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import DatabaseLogger
from utils.geoip import GeoIPService
from utils.notifier import TelegramNotifier
from utils.threat_intelligence import ThreatIntelligence
from utils.rate_limiter import RateLimiter
import settings

HOST = settings.HOST
SSH_PORT = settings.SSH_PORT
HTTP_PORT = settings.HTTP_PORT
MYSQL_PORT = settings.MYSQL_PORT
WEB_PORT = settings.WEB_PORT

class HoneypotService:
    """Base class for honeypot services"""
    
    def __init__(self, port: int, service_name: str, host: Optional[str] = None):
        """
        Initialize a honeypot service
        
        Args:
            port: Port number to listen on
            service_name: Name of the service being simulated
            host: Host address to bind to (defaults to settings.HOST)
        """
        self.port = port
        self.service_name = service_name
        self.host = host or settings.HOST
        self.socket = None
        self.running = False
        self.logger = DatabaseLogger()
        self.geoip = GeoIPService()
        self.notifier = TelegramNotifier()
        
        # Initialize threat intelligence and rate limiter
        self.threat_intelligence = ThreatIntelligence()
        self.rate_limiter = RateLimiter()
    
    def start(self):
        """Start the honeypot service"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            print(f"🚀 {self.service_name} honeypot started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    client_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection on {self.service_name}: {e}")
                        
        except Exception as e:
            print(f"Error starting {self.service_name} honeypot: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the honeypot service"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print(f"🛑 {self.service_name} honeypot stopped")
    
    def _handle_connection(self, client_socket: socket.socket, address: tuple):
        """
        Handle an incoming connection
        
        Args:
            client_socket: Client socket connection
            address: Client address tuple (ip, port)
        """
        ip_address = address[0]
        client_port = address[1]
        
        # Check rate limiting first
        allowed, reason = self.rate_limiter.check_connection(ip_address, self.service_name)
        if not allowed:
            print(f"🚫 {self.service_name} connection blocked from {ip_address}: {reason}")
            client_socket.close()
            return
        
        try:
            # Get geolocation information
            location_info = self.geoip.get_location_info(ip_address)
            # Reverse DNS lookup
            try:
                reverse_dns = pysocket.gethostbyaddr(ip_address)[0]
            except Exception:
                reverse_dns = None
            
            # Perform threat intelligence analysis
            threat_analysis = self.threat_intelligence.analyze_ip(ip_address)
            
            # Prepare connection data
            connection_data = {
                'ip_address': ip_address,
                'port': self.port,
                'service_name': self.service_name,
                'timestamp': datetime.now(),
                'country': location_info.get('country') if location_info else None,
                'city': location_info.get('city') if location_info else None,
                'isp': location_info.get('isp') if location_info else None,
                'latitude': location_info.get('latitude') if location_info else None,
                'longitude': location_info.get('longitude') if location_info else None,
                'user_agent': None,
                'request_data': None,
                'reverse_dns': reverse_dns,
                'threat_score': threat_analysis.get('threat_score', 0),
                'risk_level': threat_analysis.get('risk_level', 'unknown'),
                'threat_sources': list(threat_analysis.get('sources', {}).keys())
            }
            
            # Log the connection
            record_id = self.logger.log_connection(connection_data)
            
            # Send Telegram alert with threat information
            self.notifier.send_alert(connection_data)
            
            # Handle the specific service interaction
            self._interact_with_client(client_socket, connection_data)
            
            print(f"📝 {self.service_name} connection logged from {ip_address} (ID: {record_id}, Threat Score: {connection_data['threat_score']})")
            
        except Exception as e:
            print(f"Error handling {self.service_name} connection from {ip_address}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _interact_with_client(self, client_socket: socket.socket, connection_data: Dict[str, Any]):
        """
        Interact with the client (to be overridden by subclasses)
        
        Args:
            client_socket: Client socket connection
            connection_data: Connection information dictionary
        """
        # Default behavior: just close the connection
        pass

class SSHHoneypot(HoneypotService):
    """SSH honeypot service"""
    
    def __init__(self, port: Optional[int] = None, host: Optional[str] = None):
        super().__init__(port or SSH_PORT, "SSH", host or HOST)
    
    def _interact_with_client(self, client_socket: socket.socket, connection_data: Dict[str, Any]):
        """Handle SSH connection interaction"""
        try:
            # Send SSH banner
            ssh_banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
            client_socket.send(ssh_banner.encode())
            
            # Wait for client data (simulate SSH handshake)
            data = client_socket.recv(1024)
            if data:
                try:
                    connection_data['request_data'] = data.decode('utf-8', errors='ignore')
                except Exception as decode_error:
                    connection_data['request_data'] = data.hex()
                    print(f"Warning: Could not decode SSH data as UTF-8, storing as hex: {decode_error}")
            
            # Simulate SSH login prompt
            client_socket.send(b"login as: ")
            username = client_socket.recv(1024).strip().decode(errors='ignore')
            connection_data['ssh_username'] = username
            client_socket.send(b"\r\nPassword: ")
            password = client_socket.recv(1024).strip().decode(errors='ignore')
            connection_data['ssh_password'] = password
            
            # Record failed authentication for rate limiting
            self.rate_limiter.record_failed_auth(connection_data['ip_address'], username, password)
            
            # Simulate login failure
            error_msg = "Permission denied, please try again.\r\n"
            client_socket.send(error_msg.encode())
            time.sleep(1)
            
            # Log the enhanced connection data
            self.logger.log_connection(connection_data)
            self.notifier.send_alert(connection_data)
            
        except Exception as e:
            print(f"Error in SSH interaction: {e}")

class HTTPHoneypot(HoneypotService):
    """HTTP honeypot service"""
    
    def __init__(self, port: Optional[int] = None, host: Optional[str] = None):
        super().__init__(port or HTTP_PORT, "HTTP", host or HOST)
    
    def _interact_with_client(self, client_socket: socket.socket, connection_data: Dict[str, Any]):
        """Handle HTTP connection interaction"""
        try:
            # Receive HTTP request
            data = client_socket.recv(4096)
            if data:
                try:
                    request_text = data.decode('utf-8', errors='ignore')
                    connection_data['request_data'] = request_text
                    
                    # Parse headers
                    lines = request_text.split('\n')
                    headers = {}
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip()] = value.strip()
                    
                    connection_data['http_headers'] = str(headers)
                    connection_data['user_agent'] = headers.get('User-Agent', 'Unknown')
                    
                except Exception as decode_error:
                    connection_data['request_data'] = data.hex()
                    print(f"Warning: Could not decode HTTP data as UTF-8, storing as hex: {decode_error}")
            
            # Send HTTP response
            response = """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 0

"""
            client_socket.send(response.encode())
            
        except Exception as e:
            print(f"Error in HTTP interaction: {e}")

class MySQLHoneypot(HoneypotService):
    """MySQL honeypot service"""
    
    def __init__(self, port: Optional[int] = None, host: Optional[str] = None):
        super().__init__(port or MYSQL_PORT, "MySQL", host or HOST)
    
    def _interact_with_client(self, client_socket: socket.socket, connection_data: Dict[str, Any]):
        """Handle MySQL connection interaction"""
        try:
            # Send MySQL server greeting
            greeting = b'\x0a\x35\x2e\x37\x2e\x32\x38\x2d\x30\x75\x62\x75\x6e\x74\x75\x30\x2e\x31\x38\x2e\x30\x34\x2e\x31\x00'
            client_socket.send(greeting)
            
            # Receive client response
            data = client_socket.recv(1024)
            if data:
                connection_data['request_data'] = data.hex()
                
                # Extract username if possible
                try:
                    # Simple username extraction (this is a basic implementation)
                    if len(data) > 4:
                        username_length = data[4]
                        if len(data) > 5 + username_length:
                            username = data[5:5+username_length].decode('utf-8', errors='ignore')
                            connection_data['mysql_username'] = username
                except:
                    pass
            
            # Send error response
            error_response = b'\xff\x15\x04#28000Access denied for user'
            client_socket.send(error_response)
            
        except Exception as e:
            print(f"Error in MySQL interaction: {e}")

class HoneypotManager:
    """Manages multiple honeypot services"""
    
    def __init__(self):
        """Initialize the honeypot manager"""
        self.services = []
        self.running = False
        self.logger = DatabaseLogger()
        self.notifier = TelegramNotifier()
    
    def add_service(self, service: HoneypotService):
        """
        Add a honeypot service to the manager
        
        Args:
            service: Honeypot service instance
        """
        self.services.append(service)
    
    def start_all(self):
        """Start all honeypot services"""
        if self.running:
            print("Honeypot manager is already running")
            return
        
        self.running = True
        
        # Test Telegram connection
        if self.notifier.enabled:
            self.notifier.test_connection()
        
        # Start all services in separate threads
        for service in self.services:
            service_thread = threading.Thread(target=service.start)
            service_thread.daemon = True
            service_thread.start()
        
        print("🎯 All honeypot services started")
        
        try:
            # Keep the main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down honeypot services...")
            self.stop_all()
    
    def stop_all(self):
        """Stop all honeypot services"""
        self.running = False
        
        for service in self.services:
            service.stop()
        
        print("✅ All honeypot services stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics from all services
        
        Returns:
            dict: Combined statistics from all services
        """
        return self.logger.get_connection_stats()
    
    def send_status_report(self):
        """Send a status report via Telegram"""
        if self.notifier.enabled:
            stats = self.get_stats()
            self.notifier.send_status_update(stats) 