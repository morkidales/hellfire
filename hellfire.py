import os
import sys
import re
import time
import json
import sqlite3
import argparse
import subprocess
from collections import defaultdict

class Color:
    RED = '\033[31m'
    BRIGHT_RED = '\033[91m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    PURPLE = '\033[35m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

BANNER = f"""{Color.RED}{Color.BOLD}
 _   _      _ _  __ _          
| | | | ___| | |/ _(_)_ __ ___ 
| |_| |/ _ \\ | | |_| | '__/ _ \\
|  _  |  __/ | |  _| | | |  __/
|_| |_|\\___|_|_|_| |_|_|  \\___|
{Color.RESET}{Color.BRIGHT_RED}[ Advanced Automated Intrusion Prevention Daemon ]
{Color.RESET}"""

DB_PATH = 'hellfire_state.db'

def init_database():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS banned_ips 
                 (ip TEXT PRIMARY KEY, rule TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

class HellfireEngine:
    def __init__(self):
        try:
            with open('config.json', 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"{Color.RED}[CRITICAL] config.json configuration file missing!{Color.RESET}")
            sys.exit(1)
            
        self.log_file = self.config['target_log']
        self.infractions = defaultdict(list)

    def execute_ban(self, ip, rule_name):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute("SELECT ip FROM banned_ips WHERE ip=?", (ip,))
        if c.fetchone():
            conn.close()
            return

        print(f"\n{Color.RED}[ALERT] MALICIOUS ACTIVITY DETECTED | IP: {ip} | Rule Broken: {rule_name}{Color.RESET}")
        command = self.config['firewall_ban_cmd'].replace('{ip}', ip)
        
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            c.execute("INSERT INTO banned_ips (ip, rule) VALUES (?, ?)", (ip, rule_name))
            conn.commit()
            print(f"{Color.GREEN}[SUCCESS] IP {ip} blocked at firewall level and recorded to database.{Color.RESET}")
        except subprocess.CalledProcessError:
            print(f"{Color.YELLOW}[WARNING] Action failed. Root privileges (sudo) required to manipulate firewall rules.{Color.RESET}")
        finally:
            conn.close()

    def execute_unban(self, ip):
        command = self.config['firewall_unban_cmd'].replace('{ip}', ip)
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM banned_ips WHERE ip=?", (ip,))
            conn.commit()
            conn.close()
            print(f"{Color.GREEN}[SUCCESS] Target IP {ip} successfully unbanned from system firewall.{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}[ERROR] Failed to remove firewall restriction: {e}{Color.RESET}")

    def display_status(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM banned_ips")
        records = c.fetchall()
        print(f"{Color.BLUE}[INFO] Active Restricted IP Registry:{Color.RESET}")
        for record in records:
            print(f" - Target: {record[0]} | Triggered Rule: {record[1]} | Timestamp: {record[2]}")
        print(f"{Color.BOLD}Total Restricted Entities: {len(records)}{Color.RESET}")
        conn.close()

    def start_monitoring(self):
        print(f"{Color.YELLOW}[INFO] Initialization successful. Monitoring target stream: {self.log_file}{Color.RESET}")
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    
                    current_time = time.time()
                    for rule in self.config['rules']:
                        regex_pattern = rule['regex'].replace('{ip}', r'((?:\d{1,3}\.){3}\d{1,3})')
                        match = re.search(regex_pattern, line)
                        
                        if match:
                            ip = match.group(1)
                            self.infractions[ip] = [t for t in self.infractions[ip] if current_time - t < rule['time_window']]
                            self.infractions[ip].append(current_time)
                            
                            print(f"{Color.PURPLE}[MONITOR]{Color.RESET} Analyzing IP: {ip} | Rule Matrix: {rule['name']} | Metrics: ({len(self.infractions[ip])}/{rule['max_attempts']})", end='\r')
                            
                            if len(self.infractions[ip]) >= rule['max_attempts']:
                                self.execute_ban(ip, rule['name'])
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}[INFO] Hellfire daemon shutting down. Safe termination initiated.{Color.RESET}")
        except FileNotFoundError:
            print(f"\n{Color.RED}[CRITICAL] Target log system stream not found at: {self.log_file}{Color.RESET}")

def main():
    print(BANNER)
    init_database()
    
    parser = argparse.ArgumentParser(description='Hellfire Automated Intrusion Prevention System CLI')
    parser.add_argument('--watch', action='store_true', help='Launch live daemon engine to process log streams')
    parser.add_argument('--status', action='store_true', help='Fetch current active firewall bans from database')
    parser.add_argument('--unban', type=str, metavar='IP', help='Remove firewall block from the specified IP address')
    
    args = parser.parse_args()
    engine = HellfireEngine()

    if args.watch:
        engine.start_monitoring()
    elif args.status:
        engine.display_status()
    elif args.unban:
        engine.execute_unban(args.unban)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()