#!/usr/bin/env python3
"""
GeoIP Service Module
====================

This module provides geolocation services for IP addresses using various
free and paid APIs. It includes caching and rate limiting to optimize
performance and respect API limits.

For educational purposes only.
"""

import requests
import time
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import settings

GEOIP_RATE_LIMIT_DELAY = settings.GEOIP_RATE_LIMIT_DELAY

class GeoIPService:
    """Handles IP geolocation lookups using multiple services"""
    
    def __init__(self):
        """Initialize the GeoIP service"""
        self.services = [
            {
                'name': 'ip-api.com',
                'url': 'http://ip-api.com/json/{ip}',
                'timeout': 10
            },
            {
                'name': 'ipapi.co',
                'url': 'https://ipapi.co/{ip}/json/',
                'timeout': 10
            }
        ]
        self.rate_limit_delay = GEOIP_RATE_LIMIT_DELAY
    
    def get_location_info(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation information for an IP address
        
        Args:
            ip_address: The IP address to lookup
            
        Returns:
            dict: Location information or None if lookup failed
        """
        # Check if it's a private IP first
        if self.is_private_ip(ip_address):
            print(f"GeoIP lookup skipped for {ip_address}: private range")
            return {
                'country': 'Private Network',
                'city': 'Local Network',
                'isp': 'Internal Network',
                'latitude': None,
                'longitude': None,
                'note': 'Private IP address'
            }
        
        # Try multiple services
        for service in self.services:
            try:
                result = self._query_service(service, ip_address)
                if result:
                    print(f"✅ GeoIP lookup successful for {ip_address} using {service['name']}")
                    return result
            except Exception as e:
                print(f"❌ GeoIP lookup failed for {ip_address} using {service['name']}: {e}")
                continue
        
        print(f"❌ All GeoIP services failed for {ip_address}")
        return None
    
    def _query_service(self, service: Dict[str, Any], ip_address: str) -> Optional[Dict[str, Any]]:
        """Query a specific GeoIP service"""
        try:
            # Add delay to respect rate limits
            time.sleep(self.rate_limit_delay)
            
            url = service['url'].format(ip=ip_address)
            response = requests.get(url, timeout=service['timeout'])
            response.raise_for_status()
            
            data = response.json()
            
            # Handle different service response formats
            if service['name'] == 'ip-api.com':
                return self._parse_ipapi_com(data)
            elif service['name'] == 'ipapi.co':
                return self._parse_ipapi_co(data)
            
        except Exception as e:
            raise Exception(f"Service error: {e}")
    
    def _parse_ipapi_com(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse ip-api.com response"""
        if data.get('status') == 'success':
            return {
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'zip': data.get('zip'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'as': data.get('as'),
                'query': data.get('query')
            }
        return None
    
    def _parse_ipapi_co(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse ipapi.co response"""
        if data.get('error') is None:
            return {
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'region': data.get('region'),
                'city': data.get('city'),
                'zip': data.get('postal'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timezone'),
                'isp': data.get('org'),
                'org': data.get('org'),
                'as': data.get('asn'),
                'query': data.get('ip')
            }
        return None
    
    def get_batch_location_info(self, ip_addresses: list) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        Get geolocation information for multiple IP addresses
        
        Args:
            ip_addresses: List of IP addresses to lookup
            
        Returns:
            dict: Dictionary mapping IP addresses to their location info
        """
        results = {}
        
        for ip in ip_addresses:
            results[ip] = self.get_location_info(ip)
        
        return results
    
    def is_private_ip(self, ip_address: str) -> bool:
        """
        Check if an IP address is private/internal
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            bool: True if the IP is private, False otherwise
        """
        try:
            # Split IP into octets
            octets = ip_address.split('.')
            if len(octets) != 4:
                return False
            
            first_octet = int(octets[0])
            second_octet = int(octets[1])
            
            # Private IP ranges:
            # 10.0.0.0 - 10.255.255.255
            # 172.16.0.0 - 172.31.255.255
            # 192.168.0.0 - 192.168.255.255
            # 127.0.0.0 - 127.255.255.255 (localhost)
            
            if first_octet == 10:
                return True
            elif first_octet == 172 and 16 <= second_octet <= 31:
                return True
            elif first_octet == 192 and second_octet == 168:
                return True
            elif first_octet == 127:
                return True
            
            return False
            
        except (ValueError, IndexError):
            return False
    
    def format_location_string(self, location_data: Optional[Dict[str, Any]]) -> str:
        """
        Format location data into a readable string
        
        Args:
            location_data: Location information dictionary
            
        Returns:
            str: Formatted location string
        """
        if not location_data:
            return "Unknown"
        
        parts = []
        
        if location_data.get('city'):
            parts.append(location_data['city'])
        
        if location_data.get('region'):
            parts.append(location_data['region'])
        
        if location_data.get('country'):
            parts.append(location_data['country'])
        
        if location_data.get('isp'):
            parts.append(f"({location_data['isp']})")
        
        return ", ".join(parts) if parts else "Unknown"
    
    def test_geoip_service(self):
        """Test the GeoIP service with known IPs"""
        print("🧪 Testing GeoIP Service...")
        
        # Test with a public IP (Google DNS)
        print("\n📍 Testing with public IP (8.8.8.8):")
        result = self.get_location_info("8.8.8.8")
        if result:
            print(f"✅ Success: {self.format_location_string(result)}")
        else:
            print("❌ Failed to get location for public IP")
        
        # Test with a private IP
        print("\n🏠 Testing with private IP (192.168.1.1):")
        result = self.get_location_info("192.168.1.1")
        if result:
            print(f"✅ Success: {self.format_location_string(result)}")
        else:
            print("❌ Failed to get location for private IP")
        
        # Test with localhost
        print("\n🖥️ Testing with localhost (127.0.0.1):")
        result = self.get_location_info("127.0.0.1")
        if result:
            print(f"✅ Success: {self.format_location_string(result)}")
        else:
            print("❌ Failed to get location for localhost")
        
        print("\n🎯 GeoIP Service Test Complete!") 