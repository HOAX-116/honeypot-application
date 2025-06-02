#!/usr/bin/env python3
"""
HTTP Honeypot Service
Captures web application attacks and logs detailed information
"""

import json
import logging
import os
import time
from datetime import datetime
from flask import Flask, request, render_template_string, jsonify, redirect
import requests

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('http_honeypot')

app = Flask(__name__)

class HTTPHoneypot:
    def __init__(self):
        self.logstash_host = os.getenv('LOGSTASH_HOST', 'logstash')
        self.logstash_port = int(os.getenv('LOGSTASH_PORT', '5044'))
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'unique_ips': set(),
            'attack_types': {},
            'user_agents': {},
            'request_methods': {}
        }

    def log_event(self, event_data):
        """Log event to file and send to Logstash"""
        # Add timestamp and service info
        event_data.update({
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'http',
            'honeypot_type': 'http_honeypot',
            'version': '1.0.0'
        })
        
        # Log to file
        log_file = '/var/log/honeypot/http.log'
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(event_data) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to log file: {e}")
        
        # Send to Logstash
        try:
            response = requests.post(
                f'http://{self.logstash_host}:5000',
                json=event_data,
                timeout=5
            )
            if response.status_code != 200:
                logger.warning(f"Failed to send to Logstash: {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to send to Logstash: {e}")

    def analyze_request(self, request_data):
        """Analyze request for attack patterns"""
        attack_types = []
        threat_level = 'low'
        
        uri = request_data.get('request_uri', '').lower()
        user_agent = request_data.get('user_agent', '').lower()
        method = request_data.get('method', '')
        
        # SQL Injection detection
        sql_patterns = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', "'", '"', '--', '/*']
        if any(pattern in uri for pattern in sql_patterns):
            attack_types.append('sql_injection')
            threat_level = 'high'
        
        # XSS detection
        xss_patterns = ['<script', 'javascript:', 'onload=', 'onerror=', 'alert(', 'document.cookie']
        if any(pattern in uri for pattern in xss_patterns):
            attack_types.append('xss')
            threat_level = 'high'
        
        # Directory traversal
        if '../' in uri or '..\\' in uri:
            attack_types.append('directory_traversal')
            threat_level = 'medium'
        
        # Admin panel access
        admin_patterns = ['admin', 'wp-admin', 'phpmyadmin', 'login', 'administrator', 'manager']
        if any(pattern in uri for pattern in admin_patterns):
            attack_types.append('admin_access')
            threat_level = 'medium'
        
        # Automated scanning
        scanner_agents = ['bot', 'crawler', 'scanner', 'nikto', 'sqlmap', 'nmap', 'masscan']
        if any(agent in user_agent for agent in scanner_agents):
            attack_types.append('automated_scan')
            threat_level = 'medium'
        
        # File inclusion
        if 'include' in uri or 'require' in uri:
            attack_types.append('file_inclusion')
            threat_level = 'high'
        
        # Command injection
        cmd_patterns = ['|', ';', '&&', '||', '`', '$', '$(']
        if any(pattern in uri for pattern in cmd_patterns):
            attack_types.append('command_injection')
            threat_level = 'high'
        
        return attack_types, threat_level

honeypot = HTTPHoneypot()

@app.before_request
def log_request():
    """Log all incoming requests"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    honeypot.stats['total_requests'] += 1
    honeypot.stats['unique_ips'].add(client_ip)
    
    method = request.method
    honeypot.stats['request_methods'][method] = honeypot.stats['request_methods'].get(method, 0) + 1
    
    user_agent = request.headers.get('User-Agent', '')
    honeypot.stats['user_agents'][user_agent] = honeypot.stats['user_agents'].get(user_agent, 0) + 1
    
    # Prepare request data
    request_data = {
        'event_type': 'http_request',
        'source_ip': client_ip,
        'method': method,
        'request_uri': request.full_path,
        'user_agent': user_agent,
        'referer': request.headers.get('Referer', ''),
        'content_type': request.headers.get('Content-Type', ''),
        'content_length': request.headers.get('Content-Length', ''),
        'headers': dict(request.headers),
        'query_string': request.query_string.decode('utf-8'),
        'form_data': dict(request.form) if request.form else {},
        'session_id': f"{client_ip}_{int(time.time())}"
    }
    
    # Analyze for attack patterns
    attack_types, threat_level = honeypot.analyze_request(request_data)
    request_data['attack_types'] = attack_types
    request_data['threat_level'] = threat_level
    
    # Update statistics
    for attack_type in attack_types:
        honeypot.stats['attack_types'][attack_type] = honeypot.stats['attack_types'].get(attack_type, 0) + 1
    
    # Log the request
    honeypot.log_event(request_data)
    
    logger.info(f"Request from {client_ip}: {method} {request.full_path}")
    if attack_types:
        logger.warning(f"Detected attacks from {client_ip}: {attack_types}")

# Fake login page
@app.route('/login', methods=['GET', 'POST'])
@app.route('/admin', methods=['GET', 'POST'])
@app.route('/wp-admin', methods=['GET', 'POST'])
def fake_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Log login attempt
        login_event = {
            'event_type': 'login_attempt',
            'source_ip': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
            'username': username,
            'password': password,
            'success': False,
            'attack_type': 'credential_stuffing'
        }
        honeypot.log_event(login_event)
        
        return render_template_string("""
        <html>
        <head><title>Login Failed</title></head>
        <body>
        <h2>Login Failed</h2>
        <p>Invalid credentials. Please try again.</p>
        <a href="/login">Back to Login</a>
        </body>
        </html>
        """)
    
    return render_template_string("""
    <html>
    <head><title>Admin Login</title></head>
    <body>
    <h2>Administrator Login</h2>
    <form method="post">
        <p>Username: <input type="text" name="username" required></p>
        <p>Password: <input type="password" name="password" required></p>
        <p><input type="submit" value="Login"></p>
    </form>
    </body>
    </html>
    """)

# Fake file manager
@app.route('/filemanager')
@app.route('/files')
def fake_filemanager():
    return render_template_string("""
    <html>
    <head><title>File Manager</title></head>
    <body>
    <h2>File Manager</h2>
    <ul>
        <li><a href="/files/config.php">config.php</a></li>
        <li><a href="/files/database.sql">database.sql</a></li>
        <li><a href="/files/passwords.txt">passwords.txt</a></li>
        <li><a href="/files/backup.zip">backup.zip</a></li>
    </ul>
    </body>
    </html>
    """)

# Fake database interface
@app.route('/phpmyadmin')
@app.route('/database')
def fake_database():
    return render_template_string("""
    <html>
    <head><title>phpMyAdmin</title></head>
    <body>
    <h2>phpMyAdmin 4.9.5</h2>
    <p>MySQL Database Administration</p>
    <form method="post" action="/phpmyadmin/login">
        <p>Username: <input type="text" name="pma_username"></p>
        <p>Password: <input type="password" name="pma_password"></p>
        <p><input type="submit" value="Go"></p>
    </form>
    </body>
    </html>
    """)

# Vulnerable endpoints for testing
@app.route('/search')
def vulnerable_search():
    query = request.args.get('q', '')
    return f"<html><body><h2>Search Results for: {query}</h2><p>No results found.</p></body></html>"

@app.route('/user')
def vulnerable_user():
    user_id = request.args.get('id', '1')
    return f"<html><body><h2>User Profile</h2><p>User ID: {user_id}</p></body></html>"

# API endpoints
@app.route('/api/users')
def api_users():
    return jsonify({
        "users": [
            {"id": 1, "username": "admin", "role": "administrator"},
            {"id": 2, "username": "user", "role": "user"}
        ]
    })

@app.route('/api/config')
def api_config():
    return jsonify({
        "database": {
            "host": "localhost",
            "username": "root",
            "password": "password123"
        },
        "api_key": "abc123def456"
    })

# Default routes
@app.route('/')
def index():
    return render_template_string("""
    <html>
    <head><title>Welcome</title></head>
    <body>
    <h1>Welcome to Our Website</h1>
    <p>This is a sample web application.</p>
    <ul>
        <li><a href="/login">Admin Login</a></li>
        <li><a href="/filemanager">File Manager</a></li>
        <li><a href="/phpmyadmin">Database</a></li>
        <li><a href="/api/users">API Users</a></li>
    </ul>
    </body>
    </html>
    """)

@app.route('/robots.txt')
def robots():
    return """User-agent: *
Disallow: /admin/
Disallow: /config/
Disallow: /backup/
Disallow: /database/
"""

# Catch-all route
@app.route('/<path:path>')
def catch_all(path):
    return render_template_string("""
    <html>
    <head><title>404 Not Found</title></head>
    <body>
    <h2>404 - Page Not Found</h2>
    <p>The requested page "{{ path }}" was not found.</p>
    <a href="/">Home</a>
    </body>
    </html>
    """, path=path), 404

if __name__ == '__main__':
    logger.info("Starting HTTP honeypot on port 80")
    app.run(host='0.0.0.0', port=80, debug=False)