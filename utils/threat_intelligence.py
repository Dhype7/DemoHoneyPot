#!/usr/bin/env python3
"""
Threat Intelligence Module
==========================

This module provides threat intelligence capabilities by checking IP addresses
against various threat databases and services including:
- AbuseIPDB (via direct API calls)
- Shodan
- WHOIS information
- Custom blacklist/whitelist

For educational purposes only.
"""

import requests
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import logging

logger = logging.getLogger(__name__)

# Optional imports
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed. WHOIS checks will be disabled.")

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    logger.warning("shodan not installed. Shodan checks will be disabled.")

class ThreatIntelligence:
    """Threat intelligence analyzer for IP addresses"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_duration = 3600  # 1 hour cache
        self.rate_limit_delay = 1  # 1 second between requests
        
        # API keys (should be in config)
        self.abuseipdb_key = self.config.get('abuseipdb_key', '')
        self.shodan_key = self.config.get('shodan_key', '')
        
        # Custom lists
        self.blacklist = set(self.config.get('blacklist', []))
        self.whitelist = set(self.config.get('whitelist', []))
        
        # Threat scores
        self.threat_scores = {
            'abuseipdb': 0,
            'shodan': 0,
            'whois': 0,
            'custom': 0
        }
    
    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform comprehensive threat analysis on an IP address
        
        Args:
            ip_address: IP address to analyze
            
        Returns:
            Dictionary containing threat intelligence data
        """
        if not self._is_valid_ip(ip_address):
            return self._create_error_result("Invalid IP address")
        
        # Check cache first
        cache_key = f"threat_{ip_address}"
        if cache_key in self.cache:
            cached_data = self.cache[cache_key]
            if datetime.now() - cached_data['timestamp'] < timedelta(seconds=self.cache_duration):
                return cached_data['data']
        
        try:
            # Initialize result
            result: Dict[str, Any] = {
                'ip': ip_address,
                'timestamp': datetime.now().isoformat(),
                'threat_score': 0,
                'risk_level': 'low',
                'sources': {},
                'recommendations': []
            }
            
            # Check custom lists first
            custom_result = self._check_custom_lists(ip_address)
            result['sources']['custom'] = custom_result
            result['threat_score'] += custom_result.get('score', 0)
            
            # Check AbuseIPDB (using direct API calls)
            if self.abuseipdb_key:
                abuse_result = self._check_abuseipdb(ip_address)
                result['sources']['abuseipdb'] = abuse_result
                result['threat_score'] += abuse_result.get('score', 0)
                time.sleep(self.rate_limit_delay)
            
            # Check Shodan
            if self.shodan_key and SHODAN_AVAILABLE:
                shodan_result = self._check_shodan(ip_address)
                result['sources']['shodan'] = shodan_result
                result['threat_score'] += shodan_result.get('score', 0)
                time.sleep(self.rate_limit_delay)
            
            # Check WHOIS
            if WHOIS_AVAILABLE:
                whois_result = self._check_whois(ip_address)
                result['sources']['whois'] = whois_result
                result['threat_score'] += whois_result.get('score', 0)
            
            # Determine risk level
            result['risk_level'] = self._calculate_risk_level(result['threat_score'])
            
            # Generate recommendations
            result['recommendations'] = self._generate_recommendations(result)
            
            # Cache the result
            self.cache[cache_key] = {
                'data': result,
                'timestamp': datetime.now()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing IP {ip_address}: {e}")
            return self._create_error_result(str(e))
    
    def _is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip_address.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _check_custom_lists(self, ip_address: str) -> Dict[str, Any]:
        """Check IP against custom blacklist/whitelist"""
        result: Dict[str, Any] = {
            'score': 0,
            'status': 'clean',
            'details': {}
        }
        
        if ip_address in self.blacklist:
            result['score'] = 100
            result['status'] = 'blacklisted'
            result['details']['reason'] = 'IP in custom blacklist'
        elif ip_address in self.whitelist:
            result['score'] = -50
            result['status'] = 'whitelisted'
            result['details']['reason'] = 'IP in custom whitelist'
        
        return result
    
    def _check_abuseipdb(self, ip_address: str) -> Dict[str, Any]:
        """Check IP against AbuseIPDB using direct API calls"""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90'
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                abuse_confidence = data['data'].get('abuseConfidenceScore', 0)
                
                return {
                    'score': abuse_confidence,
                    'status': 'suspicious' if abuse_confidence > 0 else 'clean',
                    'details': {
                        'abuse_confidence': abuse_confidence,
                        'country_code': data['data'].get('countryCode'),
                        'usage_type': data['data'].get('usageType'),
                        'isp': data['data'].get('isp'),
                        'domain': data['data'].get('domain')
                    }
                }
            else:
                return {
                    'score': 0,
                    'status': 'error',
                    'details': {'error': f'HTTP {response.status_code}'}
                }
                
        except Exception as e:
            logger.error(f"AbuseIPDB check failed for {ip_address}: {e}")
            return {
                'score': 0,
                'status': 'error',
                'details': {'error': str(e)}
            }
    
    def _check_shodan(self, ip_address: str) -> Dict[str, Any]:
        """Check IP against Shodan"""
        if not SHODAN_AVAILABLE:
            return {
                'score': 0,
                'status': 'error',
                'details': {'error': 'Shodan library not available'}
            }
        
        try:
            api = shodan.Shodan(self.shodan_key)
            host = api.host(ip_address)
            
            # Calculate threat score based on open ports and services
            threat_score = 0
            open_ports = len(host.get('ports', []))
            
            # High-risk ports
            high_risk_ports = {22, 23, 3389, 1433, 3306, 5432, 6379, 27017}
            high_risk_count = len(set(host.get('ports', [])) & high_risk_ports)
            
            threat_score += high_risk_count * 10
            threat_score += open_ports * 2
            
            return {
                'score': min(threat_score, 100),
                'status': 'suspicious' if threat_score > 20 else 'clean',
                'details': {
                    'open_ports': host.get('ports', []),
                    'hostnames': host.get('hostnames', []),
                    'org': host.get('org'),
                    'os': host.get('os'),
                    'last_update': host.get('last_update')
                }
            }
            
        except Exception as e:
            logger.error(f"Shodan check failed for {ip_address}: {e}")
            return {
                'score': 0,
                'status': 'error',
                'details': {'error': str(e)}
            }
    
    def _check_whois(self, ip_address: str) -> Dict[str, Any]:
        """Check WHOIS information for IP"""
        if not WHOIS_AVAILABLE:
            return {
                'score': 0,
                'status': 'error',
                'details': {'error': 'WHOIS library not available'}
            }
        
        try:
            w = whois.whois(ip_address)
            
            threat_score = 0
            suspicious_indicators = []
            
            # Check for suspicious registrars
            suspicious_registrars = ['cloudflare', 'amazon', 'google', 'microsoft']
            if w.registrar:
                registrar_lower = w.registrar.lower()
                if any(indicator in registrar_lower for indicator in suspicious_registrars):
                    threat_score += 5
                    suspicious_indicators.append('Cloud/proxy registrar')
            
            # Check for recent registration
            if w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if creation_date and (datetime.now() - creation_date).days < 30:
                    threat_score += 15
                    suspicious_indicators.append('Recently registered')
            
            return {
                'score': threat_score,
                'status': 'suspicious' if threat_score > 10 else 'clean',
                'details': {
                    'registrar': w.registrar,
                    'creation_date': w.creation_date,
                    'suspicious_indicators': suspicious_indicators
                }
            }
            
        except Exception as e:
            logger.error(f"WHOIS check failed for {ip_address}: {e}")
            return {
                'score': 0,
                'status': 'error',
                'details': {'error': str(e)}
            }
    
    def _calculate_risk_level(self, threat_score: int) -> str:
        """Calculate risk level based on threat score"""
        if threat_score >= 80:
            return 'critical'
        elif threat_score >= 60:
            return 'high'
        elif threat_score >= 40:
            return 'medium'
        elif threat_score >= 20:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        threat_score = result['threat_score']
        
        if threat_score >= 80:
            recommendations.append("🚨 CRITICAL: Immediate blocking recommended")
            recommendations.append("🔍 Investigate for potential data breach")
        elif threat_score >= 60:
            recommendations.append("⚠️ HIGH RISK: Consider blocking this IP")
            recommendations.append("📊 Monitor for suspicious activity patterns")
        elif threat_score >= 40:
            recommendations.append("⚡ MEDIUM RISK: Enhanced monitoring recommended")
        elif threat_score >= 20:
            recommendations.append("👀 LOW RISK: Standard monitoring sufficient")
        
        # Service-specific recommendations
        sources = result.get('sources', {})
        
        if 'abuseipdb' in sources and sources['abuseipdb'].get('score', 0) > 50:
            recommendations.append("🛡️ IP reported in abuse database - high confidence")
        
        if 'shodan' in sources and sources['shodan'].get('score', 0) > 30:
            recommendations.append("🔍 Multiple high-risk ports detected")
        
        return recommendations
    
    def _create_error_result(self, error_message: str) -> Dict[str, Any]:
        """Create error result structure"""
        return {
            'ip': 'unknown',
            'timestamp': datetime.now().isoformat(),
            'threat_score': 0,
            'risk_level': 'unknown',
            'sources': {},
            'recommendations': [f"❌ Error: {error_message}"],
            'error': error_message
        }
    
    def add_to_blacklist(self, ip_address: str, reason: str = "") -> None:
        """Add IP to custom blacklist"""
        self.blacklist.add(ip_address)
        logger.info(f"Added {ip_address} to blacklist: {reason}")
    
    def add_to_whitelist(self, ip_address: str, reason: str = "") -> None:
        """Add IP to custom whitelist"""
        self.whitelist.add(ip_address)
        logger.info(f"Added {ip_address} to whitelist: {reason}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        return {
            'total_analyzed': len(self.cache),
            'blacklist_size': len(self.blacklist),
            'whitelist_size': len(self.whitelist),
            'cache_size': len(self.cache),
            'average_threat_score': sum(
                data['data']['threat_score'] for data in self.cache.values()
            ) / len(self.cache) if self.cache else 0
        } 