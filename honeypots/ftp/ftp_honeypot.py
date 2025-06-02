#!/usr/bin/env python3
"""
FTP Honeypot Service
Captures FTP attacks and logs detailed information
"""

import json
import logging
import os
import time
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import requests

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ftp_honeypot')

class FTPHoneypot:
    def __init__(self):
        self.logstash_host = os.getenv('LOGSTASH_HOST', 'logstash')
        self.logstash_port = int(os.getenv('LOGSTASH_PORT', '5044'))
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'login_attempts': 0,
            'unique_ips': set(),
            'common_usernames': {},
            'common_passwords': {},
            'file_operations': {}
        }

    def log_event(self, event_data):
        """Log event to file and send to Logstash"""
        # Add timestamp and service info
        event_data.update({
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'ftp',
            'honeypot_type': 'ftp_honeypot',
            'version': '1.0.0'
        })
        
        # Log to file
        log_file = '/var/log/honeypot/ftp.log'
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

honeypot = FTPHoneypot()

class HoneypotFTPHandler(FTPHandler):
    """Custom FTP handler for honeypot"""
    
    def on_connect(self):
        """Called when client connects"""
        client_ip = self.remote_ip
        honeypot.stats['total_connections'] += 1
        honeypot.stats['unique_ips'].add(client_ip)
        
        logger.info(f"FTP connection from {client_ip}")
        
        # Log connection
        event_data = {
            'event_type': 'connection',
            'source_ip': client_ip,
            'source_port': self.remote_port,
            'destination_port': 21,
            'protocol': 'ftp',
            'connection_id': f"{client_ip}_{int(time.time())}"
        }
        honeypot.log_event(event_data)

    def on_disconnect(self):
        """Called when client disconnects"""
        client_ip = self.remote_ip
        
        logger.info(f"FTP disconnection from {client_ip}")
        
        # Log disconnection
        event_data = {
            'event_type': 'disconnect',
            'source_ip': client_ip,
            'duration': 'unknown'
        }
        honeypot.log_event(event_data)

    def on_login(self, username):
        """Called on successful login (shouldn't happen in honeypot)"""
        client_ip = self.remote_ip
        
        logger.warning(f"Unexpected successful login from {client_ip}: {username}")
        
        # Log successful login
        event_data = {
            'event_type': 'login_success',
            'source_ip': client_ip,
            'username': username,
            'success': True
        }
        honeypot.log_event(event_data)

    def on_logout(self, username):
        """Called on logout"""
        client_ip = self.remote_ip
        
        logger.info(f"FTP logout from {client_ip}: {username}")
        
        # Log logout
        event_data = {
            'event_type': 'logout',
            'source_ip': client_ip,
            'username': username
        }
        honeypot.log_event(event_data)

    def on_file_sent(self, file):
        """Called when file is sent to client"""
        client_ip = self.remote_ip
        
        logger.info(f"File sent to {client_ip}: {file}")
        
        # Log file download
        event_data = {
            'event_type': 'file_download',
            'source_ip': client_ip,
            'filename': file,
            'attack_type': 'data_exfiltration'
        }
        honeypot.log_event(event_data)

    def on_file_received(self, file):
        """Called when file is received from client"""
        client_ip = self.remote_ip
        
        logger.info(f"File received from {client_ip}: {file}")
        
        # Log file upload
        event_data = {
            'event_type': 'file_upload',
            'source_ip': client_ip,
            'filename': file,
            'attack_type': 'malware_upload'
        }
        honeypot.log_event(event_data)

class HoneypotAuthorizer(DummyAuthorizer):
    """Custom authorizer that logs all authentication attempts"""
    
    def validate_authentication(self, username, password, handler):
        """Validate authentication and log attempts"""
        client_ip = handler.remote_ip
        
        honeypot.stats['login_attempts'] += 1
        honeypot.stats['common_usernames'][username] = honeypot.stats['common_usernames'].get(username, 0) + 1
        honeypot.stats['common_passwords'][password] = honeypot.stats['common_passwords'].get(password, 0) + 1
        
        logger.info(f"FTP login attempt from {client_ip}: {username}:{password}")
        
        # Log authentication attempt
        event_data = {
            'event_type': 'login_attempt',
            'source_ip': client_ip,
            'username': username,
            'password': password,
            'success': False,
            'attack_type': 'brute_force',
            'session_id': f"{client_ip}_{int(time.time())}"
        }
        honeypot.log_event(event_data)
        
        # Always deny authentication for honeypot
        raise Exception("Authentication failed")

def main():
    """Main function to start FTP honeypot"""
    logger.info("Starting FTP honeypot...")
    
    # Create authorizer
    authorizer = HoneypotAuthorizer()
    
    # Create handler
    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    
    # Set passive ports range
    handler.passive_ports = range(21000, 21011)
    
    # Create server
    server = FTPServer(('0.0.0.0', 21), handler)
    
    # Set limits
    server.max_cons = 256
    server.max_cons_per_ip = 5
    
    logger.info("FTP honeypot listening on port 21")
    logger.info("Passive ports: 21000-21010")
    
    try:
        # Start server
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down FTP honeypot...")
        server.close_all()

if __name__ == '__main__':
    main()