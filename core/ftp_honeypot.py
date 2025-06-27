#!/usr/bin/env python3
"""
FTP Honeypot Module
===================

This module implements an FTP honeypot service that simulates an FTP server
to capture and log connection attempts and authentication attempts.

For educational purposes only.
"""

import socket
import threading
import time
import os
from datetime import datetime
from typing import Dict, Any, Optional
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.honeypot import HoneypotService
from utils.logger import DatabaseLogger
from utils.geoip import GeoIPService
from utils.notifier import TelegramNotifier
from utils.threat_intelligence import ThreatIntelligence
from utils.rate_limiter import RateLimiter
import settings

class FTPHoneypot(HoneypotService):
    """FTP honeypot service that simulates an FTP server"""
    
    def __init__(self, host: Optional[str] = None, port: int = 21):
        """
        Initialize FTP honeypot
        
        Args:
            host: Host address to bind to (defaults to settings.HOST)
            port: Port number to listen on
        """
        super().__init__(port, "FTP", host or settings.HOST)
        self.ftp_users = {}  # Simulated user database
        self.active_connections = {}
        
        # Initialize FTP-specific components
        self.logger = DatabaseLogger()
        self.geoip = GeoIPService()
        self.notifier = TelegramNotifier()
        self.threat_intelligence = ThreatIntelligence()
        self.rate_limiter = RateLimiter()
    
    def _interact_with_client(self, client_socket: socket.socket, connection_data: Dict[str, Any]):
        """Handle FTP connection interaction"""
        try:
            # Send FTP welcome banner
            welcome_msg = "220 (vsFTPd 3.0.3)\r\n"
            client_socket.send(welcome_msg.encode())
            
            # FTP command processing loop
            while True:
                try:
                    # Receive command
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    command = data.decode('utf-8', errors='ignore').strip()
                    connection_data['ftp_commands'] = connection_data.get('ftp_commands', []) + [command]
                    
                    # Parse command
                    parts = command.split(' ', 1)
                    cmd = parts[0].upper() if parts else ''
                    args = parts[1] if len(parts) > 1 else ''
                    
                    # Handle different FTP commands
                    if cmd == 'USER':
                        response = f"331 Please specify the password.\r\n"
                        connection_data['ftp_username'] = args
                        
                    elif cmd == 'PASS':
                        username = connection_data.get('ftp_username', '')
                        connection_data['ftp_password'] = args
                        
                        # Record failed authentication for rate limiting
                        self.rate_limiter.record_failed_auth(connection_data['ip_address'], username, args)
                        
                        # Always reject login
                        response = "530 Login incorrect.\r\n"
                        
                    elif cmd == 'QUIT':
                        response = "221 Goodbye.\r\n"
                        client_socket.send(response.encode())
                        break
                        
                    elif cmd == 'SYST':
                        response = "215 UNIX Type: L8\r\n"
                        
                    elif cmd == 'FEAT':
                        response = "211-Features:\r\n PASV\r\n EPSV\r\n UTF8\r\n211 End\r\n"
                        
                    elif cmd == 'PWD':
                        response = "257 \"/\" is the current directory\r\n"
                        
                    elif cmd == 'TYPE':
                        response = "200 Switching to Binary mode.\r\n"
                        
                    elif cmd == 'PASV':
                        response = "227 Entering Passive Mode (127,0,0,1,192,168).\r\n"
                        
                    elif cmd == 'LIST':
                        response = "150 Here comes the directory listing.\r\n"
                        client_socket.send(response.encode())
                        time.sleep(0.1)
                        response = "226 Directory send OK.\r\n"
                        
                    elif cmd == 'CWD':
                        response = "250 Directory successfully changed.\r\n"
                        
                    elif cmd == 'CDUP':
                        response = "250 Directory successfully changed.\r\n"
                        
                    elif cmd == 'NOOP':
                        response = "200 OK\r\n"
                        
                    else:
                        response = "500 Unknown command.\r\n"
                    
                    client_socket.send(response.encode())
                    
                except Exception as e:
                    print(f"Error processing FTP command: {e}")
                    break
                    
        except Exception as e:
            print(f"Error in FTP interaction: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass 