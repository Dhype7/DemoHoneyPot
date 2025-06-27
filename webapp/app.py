#!/usr/bin/env python3
"""
Web Interface for Honeypot System
=================================

This module provides a web-based dashboard for monitoring honeypot activity,
viewing connection logs, and managing the system.

For educational purposes only.
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
import os
import sys
from datetime import datetime, timedelta
import json
import sqlite3
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import DatabaseLogger
from utils.threat_intelligence import ThreatIntelligence
from utils.rate_limiter import RateLimiter
import settings

app = Flask(__name__)
app.config['SECRET_KEY'] = settings.WEB_SECRET_KEY

# Initialize components
logger = DatabaseLogger()
threat_intelligence = ThreatIntelligence()
rate_limiter = RateLimiter()

@app.route('/')
def index():
    """Main dashboard page"""
    try:
        # Get basic statistics
        stats = logger.get_connection_stats()
        
        # Get threat intelligence stats
        threat_stats = threat_intelligence.get_statistics()
        
        # Get rate limiting stats
        rate_stats = rate_limiter.get_statistics()
        
        # Get recent connections
        recent_connections = logger.get_recent_connections(limit=10)
        
        # Calculate threat level distribution
        threat_levels = {}
        for conn in recent_connections:
            level = conn.get('risk_level', 'unknown')
            threat_levels[level] = threat_levels.get(level, 0) + 1
        
        return render_template('index.html', 
                             stats=stats,
                             threat_stats=threat_stats,
                             rate_stats=rate_stats,
                             recent_connections=recent_connections,
                             threat_levels=threat_levels)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/connections')
def connections():
    """Connections page with detailed logs"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        # Get filters from request
        filters = {
            'ip': request.args.get('ip', ''),
            'service': request.args.get('service', ''),
            'country': request.args.get('country', ''),
            'date_from': request.args.get('date_from', ''),
            'date_to': request.args.get('date_to', '')
        }
        
        # Get paginated connections
        connections_data = logger.get_connections_paginated(page, per_page)
        
        # Add filter variables to pagination for template
        pagination = connections_data['pagination']
        pagination['filters'] = filters
        
        return render_template('connections.html', 
                             connections=connections_data['connections'],
                             pagination=pagination,
                             filters=filters,
                             current_page=pagination['current_page'],
                             total_pages=pagination['total_pages'])
    except Exception as e:
        print(f"Error in connections route: {e}")
        import traceback
        traceback.print_exc()
        return render_template('error.html', error=str(e))

@app.route('/security')
def security():
    """Security dashboard with threat intelligence and rate limiting"""
    try:
        # Get threat intelligence data
        threat_stats = threat_intelligence.get_statistics()
        
        # Get rate limiting data
        rate_stats = rate_limiter.get_statistics()
        
        # Get blacklisted IPs
        blacklisted_ips = rate_limiter.get_blacklisted_ips()
        
        # Get recent threat events
        recent_threats = logger.get_recent_connections(limit=20)
        high_threat_connections = [conn for conn in recent_threats 
                                 if conn.get('threat_score', 0) > 50]
        
        return render_template('security.html',
                             threat_stats=threat_stats,
                             rate_stats=rate_stats,
                             blacklisted_ips=blacklisted_ips,
                             high_threat_connections=high_threat_connections)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/api/stats')
def api_stats():
    """API endpoint for real-time statistics"""
    try:
        stats = logger.get_connection_stats()
        threat_stats = threat_intelligence.get_statistics()
        rate_stats = rate_limiter.get_statistics()
        
        return jsonify({
            'success': True,
            'data': {
                'connections': stats,
                'threat_intelligence': threat_stats,
                'rate_limiting': rate_stats,
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/connections')
def api_connections():
    """API endpoint for connection data"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        connections_data = logger.get_connections_paginated(page, per_page)
        
        return jsonify({
            'success': True,
            'data': connections_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/security/blacklist', methods=['POST'])
def api_blacklist_ip():
    """API endpoint to manually blacklist an IP"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        duration_hours = data.get('duration_hours', 24)
        
        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address is required'
            }), 400
        
        # Add to blacklist
        rate_limiter.blacklist_ip(ip_address, duration_hours * 3600)
        
        return jsonify({
            'success': True,
            'message': f'IP {ip_address} blacklisted for {duration_hours} hours'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/security/whitelist', methods=['POST'])
def api_whitelist_ip():
    """API endpoint to whitelist an IP"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address is required'
            }), 400
        
        # Add to whitelist
        rate_limiter.whitelist_ip(ip_address)
        
        return jsonify({
            'success': True,
            'message': f'IP {ip_address} whitelisted'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/security/threat-analysis/<ip_address>')
def api_threat_analysis(ip_address):
    """API endpoint to get threat analysis for an IP"""
    try:
        # Check if refresh is requested
        refresh = request.args.get('refresh', 'false').lower() == 'true'
        
        # If refresh is requested, clear the cache for this IP
        if refresh:
            # Clear cache by setting a very old timestamp
            cache_key = f"threat_{ip_address}"
            if hasattr(threat_intelligence, 'cache') and cache_key in threat_intelligence.cache:
                threat_intelligence.cache[cache_key]['timestamp'] = datetime.now() - timedelta(hours=2)
        
        # Get threat analysis
        analysis = threat_intelligence.analyze_ip(ip_address)
        
        # Add additional metadata
        cache_key = f"threat_{ip_address}"
        analysis['cached'] = hasattr(threat_intelligence, 'cache') and cache_key in threat_intelligence.cache
        analysis['analysis_time'] = datetime.now().isoformat()
        analysis['ip_address'] = ip_address
        
        return jsonify({
            'success': True,
            'data': analysis
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/settings')
def settings_page():
    """Settings page"""
    try:
        # Get current configuration from settings.py
        config = {
            'host': settings.HOST,
            'ssh_port': settings.SSH_PORT,
            'http_port': settings.HTTP_PORT,
            'mysql_port': settings.MYSQL_PORT,
            'ftp_port': settings.FTP_PORT,
            'web_port': settings.WEB_PORT,
            'web_host': settings.WEB_HOST,
            'telegram_enabled': bool(settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID),
            'threat_intelligence_enabled': settings.THREAT_INTELLIGENCE_ENABLED,
            'rate_limiting_enabled': settings.AUTO_BLACKLIST_ENABLED,
            'database_path': settings.DATABASE_PATH,
            'log_level': settings.LOG_LEVEL
        }
        
        return render_template('settings.html', config=config)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/api/connection/<int:connection_id>')
def api_connection_details(connection_id):
    """API endpoint to get connection details by ID"""
    try:
        conn = sqlite3.connect(logger.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM connections WHERE id = ?", (connection_id,))
        row = cursor.fetchone()
        
        if row:
            columns = [description[0] for description in cursor.description]
            connection = dict(zip(columns, row))
            conn.close()
            
            return jsonify({
                'success': True,
                'data': connection
            })
        else:
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Connection not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/clear_database', methods=['POST'])
def api_clear_database():
    """API endpoint to clear the database"""
    try:
        success = logger.clear_database()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Database cleared successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to clear database'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/status_report', methods=['POST'])
def api_status_report():
    """API endpoint to send a status report via Telegram"""
    try:
        from utils.notifier import TelegramNotifier
        notifier = TelegramNotifier()
        if notifier.enabled:
            # Get current stats
            stats = logger.get_connection_stats()
            
            # Send status report
            success = notifier.send_status_update(stats)
            
            if success:
                return jsonify({'success': True, 'message': 'Status report sent successfully!'})
            else:
                return jsonify({'success': False, 'message': 'Failed to send status report'}), 500
        else:
            return jsonify({'success': False, 'message': 'Telegram notifications are not enabled.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error sending status report: {e}'}), 500

@app.route('/api/alert', methods=['POST'])
def api_alert():
    """API endpoint to send a test alert (e.g., Telegram)"""
    try:
        from utils.notifier import TelegramNotifier
        notifier = TelegramNotifier()
        if notifier.enabled:
            url = f"{notifier.base_url}{notifier.bot_token}/sendMessage"
            payload = {
                'chat_id': notifier.chat_id,
                'text': "🚨 Test alert from Honeypot web dashboard!",
                'parse_mode': 'HTML'
            }
            import requests
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()
            if result.get('ok'):
                return jsonify({'success': True, 'message': 'Test alert sent successfully!'})
            else:
                return jsonify({'success': False, 'message': result.get('description', 'Unknown error')}), 500
        else:
            return jsonify({'success': False, 'message': 'Telegram notifications are not enabled.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error sending test alert: {e}'}), 500

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error'), 500

@app.template_filter('format_timestamp')
def format_timestamp_filter(value):
    if not value:
        return ''
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    try:
        # Try to parse string to datetime
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(value)

if __name__ == '__main__':
    app.run(host=settings.WEB_HOST, port=settings.WEB_PORT, debug=False) 