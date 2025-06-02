#!/usr/bin/env python3
"""
SSH Honeypot Service
Captures SSH brute force attacks and logs detailed information
"""

import json
import logging
import socket
import threading
import time
from datetime import datetime
import paramiko
import requests
import os

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ssh_honeypot')

class SSHHoneypot:
    def __init__(self, host='0.0.0.0', port=22):
        self.host = host
        self.port = port
        self.logstash_host = os.getenv('LOGSTASH_HOST', 'logstash')
        self.logstash_port = int(os.getenv('LOGSTASH_PORT', '5044'))
        
        # Generate server key
        self.server_key = paramiko.RSAKey.generate(2048)
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'auth_attempts': 0,
            'unique_ips': set(),
            'common_usernames': {},
            'common_passwords': {}
        }

    def log_event(self, event_data):
        """Log event to file and send to Logstash"""
        # Add timestamp and service info
        event_data.update({
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'ssh',
            'honeypot_type': 'ssh_honeypot',
            'version': '1.0.0'
        })
        
        # Log to file
        log_file = '/var/log/honeypot/ssh.log'
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

    def handle_auth(self, username, password, client_ip):
        """Handle authentication attempt"""
        self.stats['auth_attempts'] += 1
        self.stats['unique_ips'].add(client_ip)
        
        # Track common credentials
        self.stats['common_usernames'][username] = self.stats['common_usernames'].get(username, 0) + 1
        self.stats['common_passwords'][password] = self.stats['common_passwords'].get(password, 0) + 1
        
        # Log authentication attempt
        event_data = {
            'event_type': 'auth_attempt',
            'source_ip': client_ip,
            'username': username,
            'password': password,
            'success': False,
            'session_id': f"{client_ip}_{int(time.time())}",
            'user_agent': 'ssh_client',
            'attack_type': 'brute_force'
        }
        
        self.log_event(event_data)
        logger.info(f"Auth attempt from {client_ip}: {username}:{password}")
        
        # Always return failure for honeypot
        return False

    def handle_client(self, client_socket, client_addr):
        """Handle individual client connection"""
        client_ip = client_addr[0]
        self.stats['total_connections'] += 1
        
        logger.info(f"New connection from {client_ip}")
        
        # Log connection
        connection_event = {
            'event_type': 'connection',
            'source_ip': client_ip,
            'source_port': client_addr[1],
            'destination_port': self.port,
            'protocol': 'ssh',
            'connection_id': f"{client_ip}_{int(time.time())}"
        }
        self.log_event(connection_event)
        
        try:
            # Create SSH transport
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.server_key)
            
            # Create server interface
            server = SSHServerInterface(self, client_ip)
            
            # Start SSH server
            transport.set_subsystem_handler('sftp', paramiko.SFTPServer)
            transport.start_server(server=server)
            
            # Wait for authentication
            channel = transport.accept(timeout=30)
            if channel is not None:
                # Log successful channel creation (shouldn't happen in honeypot)
                logger.warning(f"Channel created for {client_ip} - unexpected!")
                channel.close()
                
        except Exception as e:
            logger.error(f"Error handling client {client_ip}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            # Log disconnection
            disconnect_event = {
                'event_type': 'disconnect',
                'source_ip': client_ip,
                'duration': 'unknown',
                'reason': 'auth_failed'
            }
            self.log_event(disconnect_event)

    def start(self):
        """Start the SSH honeypot server"""
        logger.info(f"Starting SSH honeypot on {self.host}:{self.port}")
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(100)
            
            logger.info(f"SSH honeypot listening on {self.host}:{self.port}")
            
            while True:
                try:
                    client_socket, client_addr = server_socket.accept()
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    logger.info("Shutting down SSH honeypot...")
                    break
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to start SSH honeypot: {e}")
        finally:
            server_socket.close()

class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, honeypot, client_ip):
        self.honeypot = honeypot
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Log the authentication attempt
        self.honeypot.handle_auth(username, password, self.client_ip)
        
        # Always deny authentication
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # Log public key attempt
        event_data = {
            'event_type': 'pubkey_auth',
            'source_ip': self.client_ip,
            'username': username,
            'key_type': key.get_name(),
            'key_fingerprint': key.get_fingerprint().hex(),
            'success': False
        }
        self.honeypot.log_event(event_data)
        
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

def main():
    """Main function"""
    honeypot = SSHHoneypot()
    
    # Start statistics thread
    def print_stats():
        while True:
            time.sleep(300)  # Every 5 minutes
            logger.info(f"Stats: {honeypot.stats['total_connections']} connections, "
                       f"{honeypot.stats['auth_attempts']} auth attempts, "
                       f"{len(honeypot.stats['unique_ips'])} unique IPs")
    
    stats_thread = threading.Thread(target=print_stats)
    stats_thread.daemon = True
    stats_thread.start()
    
    # Start honeypot
    honeypot.start()

if __name__ == '__main__':
    main()