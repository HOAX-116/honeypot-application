#!/usr/bin/env python3
"""
Telnet Honeypot Service
Captures Telnet attacks and logs detailed information
"""

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime
import requests

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('telnet_honeypot')

class TelnetHoneypot:
    def __init__(self, host='0.0.0.0', port=23):
        self.host = host
        self.port = port
        self.logstash_host = os.getenv('LOGSTASH_HOST', 'logstash')
        self.logstash_port = int(os.getenv('LOGSTASH_PORT', '5044'))
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'login_attempts': 0,
            'unique_ips': set(),
            'common_usernames': {},
            'common_passwords': {},
            'commands_executed': {}
        }

    def log_event(self, event_data):
        """Log event to file and send to Logstash"""
        # Add timestamp and service info
        event_data.update({
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'telnet',
            'honeypot_type': 'telnet_honeypot',
            'version': '1.0.0'
        })
        
        # Log to file
        log_file = '/var/log/honeypot/telnet.log'
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

    def handle_client(self, client_socket, client_addr):
        """Handle individual client connection"""
        client_ip = client_addr[0]
        self.stats['total_connections'] += 1
        self.stats['unique_ips'].add(client_ip)
        
        logger.info(f"Telnet connection from {client_ip}")
        
        # Log connection
        connection_event = {
            'event_type': 'connection',
            'source_ip': client_ip,
            'source_port': client_addr[1],
            'destination_port': self.port,
            'protocol': 'telnet',
            'connection_id': f"{client_ip}_{int(time.time())}"
        }
        self.log_event(connection_event)
        
        try:
            # Send welcome banner
            banner = b"Ubuntu 20.04.3 LTS\r\nlogin: "
            client_socket.send(banner)
            
            # Handle login process
            username = self.get_input(client_socket, "login: ")
            if username:
                client_socket.send(b"Password: ")
                password = self.get_input(client_socket, "Password: ", hide=True)
                
                if password:
                    # Log login attempt
                    self.handle_login_attempt(client_ip, username, password)
                    
                    # Send login failed message
                    client_socket.send(b"\r\nLogin incorrect\r\n")
                    time.sleep(2)
                    
                    # Simulate shell for IoT botnet detection
                    self.simulate_shell(client_socket, client_ip, username)
            
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
                'duration': 'unknown'
            }
            self.log_event(disconnect_event)

    def get_input(self, client_socket, prompt, hide=False):
        """Get input from client"""
        try:
            client_socket.settimeout(30)  # 30 second timeout
            data = b""
            
            while True:
                chunk = client_socket.recv(1)
                if not chunk:
                    break
                
                if chunk == b'\r' or chunk == b'\n':
                    break
                elif chunk == b'\x08' or chunk == b'\x7f':  # Backspace
                    if data:
                        data = data[:-1]
                        if not hide:
                            client_socket.send(b'\x08 \x08')
                else:
                    data += chunk
                    if not hide:
                        client_socket.send(chunk)
                    else:
                        client_socket.send(b'*')
            
            return data.decode('utf-8', errors='ignore').strip()
            
        except socket.timeout:
            logger.warning("Client input timeout")
            return None
        except Exception as e:
            logger.error(f"Error getting input: {e}")
            return None

    def handle_login_attempt(self, client_ip, username, password):
        """Handle login attempt"""
        self.stats['login_attempts'] += 1
        self.stats['common_usernames'][username] = self.stats['common_usernames'].get(username, 0) + 1
        self.stats['common_passwords'][password] = self.stats['common_passwords'].get(password, 0) + 1
        
        logger.info(f"Telnet login attempt from {client_ip}: {username}:{password}")
        
        # Detect IoT botnet patterns
        attack_type = 'brute_force'
        threat_level = 'medium'
        
        # Common IoT credentials
        iot_credentials = [
            ('admin', 'admin'), ('root', 'root'), ('admin', 'password'),
            ('root', 'password'), ('admin', '123456'), ('root', '123456'),
            ('user', 'user'), ('guest', 'guest'), ('support', 'support'),
            ('admin', ''), ('root', ''), ('', ''), ('admin', '1234'),
            ('root', 'toor'), ('admin', 'pass')
        ]
        
        if (username, password) in iot_credentials:
            attack_type = 'iot_botnet'
            threat_level = 'high'
        
        # Log authentication attempt
        event_data = {
            'event_type': 'login_attempt',
            'source_ip': client_ip,
            'username': username,
            'password': password,
            'success': False,
            'attack_type': attack_type,
            'threat_level': threat_level,
            'session_id': f"{client_ip}_{int(time.time())}"
        }
        self.log_event(event_data)

    def simulate_shell(self, client_socket, client_ip, username):
        """Simulate shell interaction to capture commands"""
        try:
            # Send fake shell prompt
            prompt = f"{username}@honeypot:~$ "
            client_socket.send(prompt.encode())
            
            while True:
                command = self.get_input(client_socket, prompt)
                if not command:
                    break
                
                # Log command
                self.stats['commands_executed'][command] = self.stats['commands_executed'].get(command, 0) + 1
                
                command_event = {
                    'event_type': 'command_execution',
                    'source_ip': client_ip,
                    'username': username,
                    'command': command,
                    'attack_type': 'command_injection'
                }
                self.log_event(command_event)
                
                logger.info(f"Command from {client_ip}: {command}")
                
                # Simulate command responses
                response = self.simulate_command_response(command)
                client_socket.send(response.encode())
                client_socket.send(prompt.encode())
                
                # Break after a few commands to avoid long sessions
                if len(command.split()) > 10:
                    break
                    
        except Exception as e:
            logger.error(f"Error in shell simulation: {e}")

    def simulate_command_response(self, command):
        """Simulate command responses"""
        cmd = command.lower().strip()
        
        if cmd in ['ls', 'dir']:
            return "\r\nbin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n"
        elif cmd == 'pwd':
            return "\r\n/home/user\r\n"
        elif cmd == 'whoami':
            return "\r\nuser\r\n"
        elif cmd == 'id':
            return "\r\nuid=1000(user) gid=1000(user) groups=1000(user)\r\n"
        elif cmd.startswith('cat '):
            return "\r\ncat: permission denied\r\n"
        elif cmd == 'ps':
            return "\r\n  PID TTY          TIME CMD\r\n 1234 pts/0    00:00:00 bash\r\n"
        elif cmd == 'uname -a':
            return "\r\nLinux honeypot 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\r\n"
        elif cmd in ['exit', 'quit', 'logout']:
            return "\r\nlogout\r\n"
        else:
            return f"\r\n{cmd}: command not found\r\n"

    def start(self):
        """Start the Telnet honeypot server"""
        logger.info(f"Starting Telnet honeypot on {self.host}:{self.port}")
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(100)
            
            logger.info(f"Telnet honeypot listening on {self.host}:{self.port}")
            
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
                    logger.info("Shutting down Telnet honeypot...")
                    break
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to start Telnet honeypot: {e}")
        finally:
            server_socket.close()

def main():
    """Main function"""
    honeypot = TelnetHoneypot()
    
    # Start statistics thread
    def print_stats():
        while True:
            time.sleep(300)  # Every 5 minutes
            logger.info(f"Stats: {honeypot.stats['total_connections']} connections, "
                       f"{honeypot.stats['login_attempts']} login attempts, "
                       f"{len(honeypot.stats['unique_ips'])} unique IPs")
    
    stats_thread = threading.Thread(target=print_stats)
    stats_thread.daemon = True
    stats_thread.start()
    
    # Start honeypot
    honeypot.start()

if __name__ == '__main__':
    main()