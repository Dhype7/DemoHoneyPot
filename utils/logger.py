import sqlite3
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import settings

DATABASE_PATH = settings.DATABASE_PATH

class DatabaseLogger:
    """Handles logging of connection attempts to SQLite database"""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize database logger with path to SQLite database"""
        self.db_path = db_path or DATABASE_PATH
        self._ensure_database_exists()
        self._create_tables()
    
    def _ensure_database_exists(self):
        """Ensure the database directory exists"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    def _create_tables(self):
        """Create the necessary tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create connections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                country TEXT,
                city TEXT,
                isp TEXT,
                latitude REAL,
                longitude REAL,
                user_agent TEXT,
                request_data TEXT,
                ssh_username TEXT,
                ssh_password TEXT,
                http_headers TEXT,
                http_post_data TEXT,
                mysql_username TEXT,
                mysql_query TEXT,
                reverse_dns TEXT
            )
        ''')
        
        # Create index for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ip_timestamp 
            ON connections(ip_address, timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_service 
            ON connections(service_name)
        ''')
        
        conn.commit()
        conn.close()
    
    def log_connection(self, connection_data: Dict[str, Any]) -> int:
        """
        Log a connection attempt to the database
        
        Args:
            connection_data: Dictionary containing connection information
            
        Returns:
            int: The ID of the inserted record
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Ensure all data is properly converted to strings/appropriate types
        try:
            # Handle request_data specifically - ensure it's a string
            request_data = connection_data.get('request_data')
            if request_data is not None:
                if isinstance(request_data, bytes):
                    request_data = request_data.hex()
                elif not isinstance(request_data, str):
                    request_data = str(request_data)
            
            # New fields with default values
            ssh_username = connection_data.get('ssh_username')
            ssh_password = connection_data.get('ssh_password')
            http_headers = connection_data.get('http_headers')
            http_post_data = connection_data.get('http_post_data')
            mysql_username = connection_data.get('mysql_username')
            mysql_query = connection_data.get('mysql_query')
            reverse_dns = connection_data.get('reverse_dns')
            
            # Check if new columns exist, if not add them
            cursor.execute("PRAGMA table_info(connections)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # Add missing columns if they don't exist
            missing_columns = []
            if 'ssh_username' not in columns:
                missing_columns.append("ADD COLUMN ssh_username TEXT")
            if 'ssh_password' not in columns:
                missing_columns.append("ADD COLUMN ssh_password TEXT")
            if 'http_headers' not in columns:
                missing_columns.append("ADD COLUMN http_headers TEXT")
            if 'http_post_data' not in columns:
                missing_columns.append("ADD COLUMN http_post_data TEXT")
            if 'mysql_username' not in columns:
                missing_columns.append("ADD COLUMN mysql_username TEXT")
            if 'mysql_query' not in columns:
                missing_columns.append("ADD COLUMN mysql_query TEXT")
            if 'reverse_dns' not in columns:
                missing_columns.append("ADD COLUMN reverse_dns TEXT")
            
            # Add missing columns
            for column_def in missing_columns:
                try:
                    cursor.execute(f"ALTER TABLE connections {column_def}")
                except Exception as e:
                    print(f"Warning: Could not add column {column_def}: {e}")
            
            cursor.execute('''
                INSERT INTO connections 
                (ip_address, port, service_name, timestamp, country, city, isp, 
                 latitude, longitude, user_agent, request_data, ssh_username, ssh_password, http_headers, http_post_data, mysql_username, mysql_query, reverse_dns)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(connection_data.get('ip_address', '')),
                int(connection_data.get('port', 0)),
                str(connection_data.get('service_name', '')),
                connection_data.get('timestamp', datetime.now()),
                str(connection_data.get('country', '')) if connection_data.get('country') else None,
                str(connection_data.get('city', '')) if connection_data.get('city') else None,
                str(connection_data.get('isp', '')) if connection_data.get('isp') else None,
                float(connection_data.get('latitude', 0)) if connection_data.get('latitude') else None,
                float(connection_data.get('longitude', 0)) if connection_data.get('longitude') else None,
                str(connection_data.get('user_agent', '')) if connection_data.get('user_agent') else None,
                request_data,
                ssh_username,
                ssh_password,
                http_headers,
                http_post_data,
                mysql_username,
                mysql_query,
                reverse_dns
            ))
            
            record_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return record_id if record_id is not None else 0
            
        except Exception as e:
            print(f"Error logging connection to database: {e}")
            conn.close()
            return 0
    
    def get_connections(self, limit: int = 100, offset: int = 0, 
                       filters: Optional[Dict[str, Any]] = None) -> list:
        """
        Retrieve connection records from database with optional filtering
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            filters: Dictionary of filters to apply
            
        Returns:
            list: List of connection records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM connections"
        params = []
        
        if filters:
            conditions = []
            for key, value in filters.items():
                if value:
                    if key == 'ip_address':
                        conditions.append("ip_address LIKE ?")
                        params.append(f"%{value}%")
                    elif key == 'service_name':
                        conditions.append("service_name LIKE ?")
                        params.append(f"%{value}%")
                    elif key == 'country':
                        conditions.append("country LIKE ?")
                        params.append(f"%{value}%")
                    elif key == 'date_from':
                        conditions.append("timestamp >= ?")
                        params.append(value)
                    elif key == 'date_to':
                        conditions.append("timestamp <= ?")
                        params.append(value)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        columns = [description[0] for description in cursor.description]
        records = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return records
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get total connections
            cursor.execute("SELECT COUNT(*) FROM connections")
            total_connections = cursor.fetchone()[0]
            
            # Get service breakdown
            cursor.execute("""
                SELECT service_name, COUNT(*) as count 
                FROM connections 
                GROUP BY service_name 
                ORDER BY count DESC
            """)
            service_stats = dict(cursor.fetchall())
            
            # Get top IP addresses
            cursor.execute("""
                SELECT ip_address, COUNT(*) as count 
                FROM connections 
                GROUP BY ip_address 
                ORDER BY count DESC 
                LIMIT 10
            """)
            top_ips = cursor.fetchall()
            
            # Get recent activity (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*) FROM connections 
                WHERE timestamp >= datetime('now', '-1 day')
            """)
            recent_activity = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_connections': total_connections,
                'service_stats': service_stats,
                'top_ips': top_ips,
                'recent_activity_24h': recent_activity
            }
        except Exception as e:
            print(f"Error getting connection stats: {e}")
            import traceback
            traceback.print_exc()
            return {
                'total_connections': 0,
                'service_stats': {},
                'top_ips': [],
                'recent_activity_24h': 0
            }
    
    def get_recent_connections(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent connections"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM connections 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            columns = [description[0] for description in cursor.description]
            connections = []
            
            for row in cursor.fetchall():
                connection = dict(zip(columns, row))
                connections.append(connection)
            
            conn.close()
            return connections
        except Exception as e:
            print(f"Error getting recent connections: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_connections_paginated(self, page: int = 1, per_page: int = 50) -> Dict[str, Any]:
        """Get paginated connections"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get total count
            cursor.execute("SELECT COUNT(*) FROM connections")
            total_count = cursor.fetchone()[0]
            
            # Calculate pagination
            offset = (page - 1) * per_page
            total_pages = max(1, (total_count + per_page - 1) // per_page)
            
            # Ensure page is within valid range
            if page < 1:
                page = 1
            elif page > total_pages:
                page = total_pages
            
            # Get connections for current page
            cursor.execute("""
                SELECT * FROM connections 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            """, (per_page, offset))
            
            columns = [description[0] for description in cursor.description]
            connections = []
            
            for row in cursor.fetchall():
                connection = dict(zip(columns, row))
                connections.append(connection)
            
            conn.close()
            
            return {
                'connections': connections,
                'pagination': {
                    'current_page': page,
                    'per_page': per_page,
                    'total_pages': total_pages,
                    'total_count': total_count,
                    'has_prev': page > 1,
                    'has_next': page < total_pages
                }
            }
        except Exception as e:
            print(f"Error getting paginated connections: {e}")
            import traceback
            traceback.print_exc()
            return {
                'connections': [],
                'pagination': {
                    'current_page': 1,
                    'per_page': per_page,
                    'total_pages': 1,
                    'total_count': 0,
                    'has_prev': False,
                    'has_next': False
                }
            }
    
    def clear_database(self) -> bool:
        """
        Clear all connection records from the database
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Delete all records from connections table
            cursor.execute("DELETE FROM connections")
            
            # Reset the auto-increment counter
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='connections'")
            
            conn.commit()
            conn.close()
            
            print("🗑️ Database cleared successfully")
            return True
            
        except Exception as e:
            print(f"Error clearing database: {e}")
            return False 