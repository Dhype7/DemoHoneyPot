#!/usr/bin/env python3
"""
Rate Limiting and Blacklisting Module
=====================================

This module provides rate limiting and automatic blacklisting capabilities
to protect the honeypot from abuse and identify suspicious behavior.

For educational purposes only.
"""

import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiting and blacklisting system"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Rate limiting settings
        self.max_connections_per_minute = self.config.get('max_connections_per_minute', 10)
        self.max_connections_per_hour = self.config.get('max_connections_per_hour', 100)
        self.max_failed_auth_per_minute = self.config.get('max_failed_auth_per_minute', 5)
        self.max_failed_auth_per_hour = self.config.get('max_failed_auth_per_hour', 20)
        
        # Blacklisting settings
        self.auto_blacklist_enabled = self.config.get('auto_blacklist_enabled', True)
        self.blacklist_duration = self.config.get('blacklist_duration', 3600)  # 1 hour
        self.whitelist_duration = self.config.get('whitelist_duration', 86400)  # 24 hours
        
        # Tracking data structures
        self.connection_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.failed_auth_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.blacklisted_ips: Dict[str, datetime] = {}
        self.whitelisted_ips: Dict[str, datetime] = {}
        
        # Manual lists
        self.manual_blacklist: Set[str] = set(self.config.get('manual_blacklist', []))
        self.manual_whitelist: Set[str] = set(self.config.get('manual_whitelist', []))
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'blocked_connections': 0,
            'blacklisted_ips': 0,
            'whitelisted_ips': 0,
            'rate_limit_violations': 0
        }
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def check_connection(self, ip_address: str, service: str = "unknown") -> Tuple[bool, str]:
        """
        Check if connection should be allowed
        
        Args:
            ip_address: IP address to check
            service: Service being accessed
            
        Returns:
            Tuple of (allowed, reason)
        """
        with self.lock:
            # Check manual lists first
            if ip_address in self.manual_blacklist:
                self.stats['blocked_connections'] += 1
                return False, "IP in manual blacklist"
            
            if ip_address in self.manual_whitelist:
                return True, "IP in manual whitelist"
            
            # Check automatic blacklist
            if ip_address in self.blacklisted_ips:
                blacklist_time = self.blacklisted_ips[ip_address]
                if datetime.now() - blacklist_time < timedelta(seconds=self.blacklist_duration):
                    self.stats['blocked_connections'] += 1
                    return False, f"IP blacklisted until {blacklist_time + timedelta(seconds=self.blacklist_duration)}"
                else:
                    # Remove expired blacklist entry
                    del self.blacklisted_ips[ip_address]
            
            # Check whitelist
            if ip_address in self.whitelisted_ips:
                whitelist_time = self.whitelisted_ips[ip_address]
                if datetime.now() - whitelist_time < timedelta(seconds=self.whitelist_duration):
                    return True, "IP in automatic whitelist"
                else:
                    # Remove expired whitelist entry
                    del self.whitelisted_ips[ip_address]
            
            # Check rate limits
            now = datetime.now()
            
            # Connection rate limiting
            if not self._check_connection_rate_limit(ip_address, now):
                self.stats['rate_limit_violations'] += 1
                if self.auto_blacklist_enabled:
                    self._auto_blacklist_ip(ip_address, "Connection rate limit exceeded")
                return False, "Connection rate limit exceeded"
            
            # Record connection
            self.connection_history[ip_address].append(now)
            self.stats['total_connections'] += 1
            
            return True, "Connection allowed"
    
    def record_failed_auth(self, ip_address: str, username: str = "", password: str = "") -> None:
        """
        Record a failed authentication attempt
        
        Args:
            ip_address: IP address that failed authentication
            username: Username attempted
            password: Password attempted
        """
        with self.lock:
            now = datetime.now()
            self.failed_auth_history[ip_address].append({
                'timestamp': now,
                'username': username,
                'password': password
            })
            
            # Check if IP should be blacklisted due to failed auth
            if self._check_failed_auth_rate_limit(ip_address, now):
                if self.auto_blacklist_enabled:
                    self._auto_blacklist_ip(ip_address, "Too many failed authentication attempts")
                    logger.warning(f"Auto-blacklisted {ip_address} for failed auth attempts")
    
    def _check_connection_rate_limit(self, ip_address: str, now: datetime) -> bool:
        """Check connection rate limits"""
        # Check per-minute limit
        minute_ago = now - timedelta(minutes=1)
        recent_connections = sum(
            1 for timestamp in self.connection_history[ip_address]
            if timestamp > minute_ago
        )
        
        if recent_connections >= self.max_connections_per_minute:
            return False
        
        # Check per-hour limit
        hour_ago = now - timedelta(hours=1)
        hourly_connections = sum(
            1 for timestamp in self.connection_history[ip_address]
            if timestamp > hour_ago
        )
        
        if hourly_connections >= self.max_connections_per_hour:
            return False
        
        return True
    
    def _check_failed_auth_rate_limit(self, ip_address: str, now: datetime) -> bool:
        """Check failed authentication rate limits"""
        # Check per-minute limit
        minute_ago = now - timedelta(minutes=1)
        recent_failures = sum(
            1 for auth_data in self.failed_auth_history[ip_address]
            if auth_data['timestamp'] > minute_ago
        )
        
        if recent_failures >= self.max_failed_auth_per_minute:
            return True
        
        # Check per-hour limit
        hour_ago = now - timedelta(hours=1)
        hourly_failures = sum(
            1 for auth_data in self.failed_auth_history[ip_address]
            if auth_data['timestamp'] > hour_ago
        )
        
        if hourly_failures >= self.max_failed_auth_per_hour:
            return True
        
        return False
    
    def _auto_blacklist_ip(self, ip_address: str, reason: str) -> None:
        """Automatically blacklist an IP"""
        self.blacklisted_ips[ip_address] = datetime.now()
        self.stats['blacklisted_ips'] += 1
        logger.info(f"Auto-blacklisted {ip_address}: {reason}")
    
    def add_to_blacklist(self, ip_address: str, reason: str = "", duration: Optional[int] = None) -> None:
        """Manually add IP to blacklist"""
        with self.lock:
            self.manual_blacklist.add(ip_address)
            if duration:
                # Schedule removal
                threading.Timer(duration, self.remove_from_blacklist, args=[ip_address]).start()
            logger.info(f"Added {ip_address} to blacklist: {reason}")
    
    def remove_from_blacklist(self, ip_address: str) -> bool:
        """Remove IP from blacklist"""
        with self.lock:
            if ip_address in self.manual_blacklist:
                self.manual_blacklist.remove(ip_address)
                logger.info(f"Removed {ip_address} from blacklist")
                return True
            return False
    
    def add_to_whitelist(self, ip_address: str, reason: str = "", duration: Optional[int] = None) -> None:
        """Manually add IP to whitelist"""
        with self.lock:
            self.manual_whitelist.add(ip_address)
            if duration:
                # Schedule removal
                threading.Timer(duration, self.remove_from_whitelist, args=[ip_address]).start()
            logger.info(f"Added {ip_address} to whitelist: {reason}")
    
    def remove_from_whitelist(self, ip_address: str) -> bool:
        """Remove IP from whitelist"""
        with self.lock:
            if ip_address in self.manual_whitelist:
                self.manual_whitelist.remove(ip_address)
                logger.info(f"Removed {ip_address} from whitelist")
                return True
            return False
    
    def get_ip_status(self, ip_address: str) -> Dict[str, Any]:
        """Get detailed status for an IP address"""
        with self.lock:
            now = datetime.now()
            
            # Check blacklist status
            blacklisted = False
            blacklist_reason = ""
            if ip_address in self.manual_blacklist:
                blacklisted = True
                blacklist_reason = "Manual blacklist"
            elif ip_address in self.blacklisted_ips:
                blacklist_time = self.blacklisted_ips[ip_address]
                if now - blacklist_time < timedelta(seconds=self.blacklist_duration):
                    blacklisted = True
                    blacklist_reason = "Auto-blacklist"
            
            # Check whitelist status
            whitelisted = False
            whitelist_reason = ""
            if ip_address in self.manual_whitelist:
                whitelisted = True
                whitelist_reason = "Manual whitelist"
            elif ip_address in self.whitelisted_ips:
                whitelist_time = self.whitelisted_ips[ip_address]
                if now - whitelist_time < timedelta(seconds=self.whitelist_duration):
                    whitelisted = True
                    whitelist_reason = "Auto-whitelist"
            
            # Get connection statistics
            recent_connections = sum(
                1 for timestamp in self.connection_history[ip_address]
                if now - timestamp < timedelta(minutes=1)
            )
            
            recent_failures = sum(
                1 for auth_data in self.failed_auth_history[ip_address]
                if now - auth_data['timestamp'] < timedelta(minutes=1)
            )
            
            return {
                'ip_address': ip_address,
                'blacklisted': blacklisted,
                'blacklist_reason': blacklist_reason,
                'whitelisted': whitelisted,
                'whitelist_reason': whitelist_reason,
                'recent_connections': recent_connections,
                'recent_failures': recent_failures,
                'total_connections': len(self.connection_history[ip_address]),
                'total_failures': len(self.failed_auth_history[ip_address])
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        try:
            # Count blocked connections
            blocked_count = self.stats['blocked_connections']
            
            # Count blacklisted IPs
            blacklisted_count = len(self.blacklisted_ips)
            
            # Count rate limit violations
            violations_count = self.stats['rate_limit_violations']
            
            # Count unique IPs seen
            unique_ips_count = len(self.connection_history)
            
            return {
                'blocked_connections': blocked_count,
                'blacklisted_ips': blacklisted_count,
                'rate_limit_violations': violations_count,
                'unique_ips_seen': unique_ips_count,
                'max_connections_per_minute': self.max_connections_per_minute,
                'max_failed_auth_per_minute': self.max_failed_auth_per_minute
            }
        except Exception as e:
            print(f"Error getting rate limiter statistics: {e}")
            return {
                'blocked_connections': 0,
                'blacklisted_ips': 0,
                'rate_limit_violations': 0,
                'unique_ips_seen': 0,
                'max_connections_per_minute': self.max_connections_per_minute,
                'max_failed_auth_per_minute': self.max_failed_auth_per_minute
            }
    
    def get_blacklisted_ips(self) -> List[Dict[str, Any]]:
        """Get list of blacklisted IPs with their details"""
        try:
            blacklisted_ips = []
            current_time = datetime.now()
            
            for ip_address, blacklist_time in self.blacklisted_ips.items():
                # Check if still blacklisted
                if current_time - blacklist_time < timedelta(seconds=self.blacklist_duration):
                    blacklisted_ips.append({
                        'ip_address': ip_address,
                        'reason': "Automatic blacklist",
                        'blacklisted_at': blacklist_time.isoformat(),
                        'expires_at': (blacklist_time + timedelta(seconds=self.blacklist_duration)).isoformat(),
                        'remaining_time': (blacklist_time + timedelta(seconds=self.blacklist_duration) - current_time).total_seconds()
                    })
                else:
                    # Remove expired blacklist entry
                    del self.blacklisted_ips[ip_address]
            
            return blacklisted_ips
        except Exception as e:
            print(f"Error getting blacklisted IPs: {e}")
            return []
    
    def blacklist_ip(self, ip_address: str, duration_seconds: int = 86400) -> bool:
        """
        Manually blacklist an IP address
        
        Args:
            ip_address: IP address to blacklist
            duration_seconds: Duration in seconds (default: 24 hours)
            
        Returns:
            bool: True if successfully blacklisted
        """
        try:
            with self.lock:
                self.blacklisted_ips[ip_address] = datetime.now()
                self.stats['blacklisted_ips'] += 1
            
            print(f"🚫 IP {ip_address} manually blacklisted for {duration_seconds // 3600} hours")
            return True
        except Exception as e:
            print(f"Error blacklisting IP {ip_address}: {e}")
            return False
    
    def whitelist_ip(self, ip_address: str) -> bool:
        """
        Whitelist an IP address (remove from blacklist)
        
        Args:
            ip_address: IP address to whitelist
            
        Returns:
            bool: True if successfully whitelisted
        """
        try:
            with self.lock:
                if ip_address in self.blacklisted_ips:
                    del self.blacklisted_ips[ip_address]
                    print(f"✅ IP {ip_address} whitelisted (removed from blacklist)")
                else:
                    print(f"ℹ️ IP {ip_address} was not blacklisted")
            
            return True
        except Exception as e:
            print(f"Error whitelisting IP {ip_address}: {e}")
            return False
    
    def _cleanup_worker(self) -> None:
        """Background worker to clean up expired entries"""
        while True:
            try:
                time.sleep(300)  # Run every 5 minutes
                self._cleanup_expired_entries()
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")
    
    def _cleanup_expired_entries(self) -> None:
        """Clean up expired blacklist and whitelist entries"""
        with self.lock:
            now = datetime.now()
            
            # Clean up expired blacklist entries
            expired_blacklist = [
                ip for ip, timestamp in self.blacklisted_ips.items()
                if now - timestamp >= timedelta(seconds=self.blacklist_duration)
            ]
            for ip in expired_blacklist:
                del self.blacklisted_ips[ip]
            
            # Clean up expired whitelist entries
            expired_whitelist = [
                ip for ip, timestamp in self.whitelisted_ips.items()
                if now - timestamp >= timedelta(seconds=self.whitelist_duration)
            ]
            for ip in expired_whitelist:
                del self.whitelisted_ips[ip]
            
            if expired_blacklist or expired_whitelist:
                logger.info(f"Cleaned up {len(expired_blacklist)} blacklist and {len(expired_whitelist)} whitelist entries")
    
    def get_top_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top IPs by connection count"""
        with self.lock:
            ip_counts = [(ip, len(history)) for ip, history in self.connection_history.items()]
            return sorted(ip_counts, key=lambda x: x[1], reverse=True)[:limit]
    
    def get_suspicious_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get IPs with most failed authentication attempts"""
        with self.lock:
            ip_failures = [(ip, len(history)) for ip, history in self.failed_auth_history.items()]
            return sorted(ip_failures, key=lambda x: x[1], reverse=True)[:limit] 