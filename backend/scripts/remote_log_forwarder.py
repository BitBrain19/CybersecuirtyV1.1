import argparse
import time
import json
import logging
import platform
import socket
import requests
import os
import re
import subprocess
from datetime import datetime, timedelta
import urllib3

# Configuration
API_ENDPOINT = "http://localhost:8000/api/v1/logs/ingest" 
BATCH_SIZE = 50
POLL_INTERVAL = 10 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("UniversalForwarder")

class BaseForwarder:
    def __init__(self, api_url, api_key=None, skip_verify=False, ca_bundle=None):
        self.api_url = api_url
        self.api_key = api_key
        self.skip_verify = skip_verify
        self.ca_bundle = ca_bundle
        self.computer_name = socket.gethostname()
        self.load_state()
        
        # Suppress SSL warnings if skipping verification
        if skip_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def load_state(self):
        self.state = {}
        try:
            with open("forwarder_state.json", "r") as f:
                self.state = json.load(f)
        except FileNotFoundError:
            pass

    def save_state(self):
        with open("forwarder_state.json", "w") as f:
            json.dump(self.state, f)

    def forward(self, logs):
        if not logs: return
        try:
            # Send flat list of logs directly
            # The backend/pipeline expects a list of dicts
            payload = logs
            headers = {"Content-Type": "application/json"}
            
            # Add API key to Authorization header if provided
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            # Configure TLS verification
            verify = True
            if self.skip_verify:
                verify = False
            elif self.ca_bundle and os.path.exists(self.ca_bundle):
                verify = self.ca_bundle
            
            resp = requests.post(self.api_url, json=payload, timeout=5, headers=headers, verify=verify)
            if resp.status_code == 200:
                logger.info(f"Forwarded {len(logs)} logs.")
                self.save_state()
            else:
                logger.error(f"Failed to forward: {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.error(f"Network error: {e}")

class WindowsForwarder(BaseForwarder):
    def __init__(self, api_url):
        super().__init__(api_url)
        import win32evtlog # Import here to avoid error on Linux
        self.sources = ['System', 'Application', 'Security']
        
    def run(self):
        import win32evtlog
        import win32evtlogutil
        import win32con
        
        while True:
            all_logs = []
            for source in self.sources:
                logs = []
                try:
                    hand = win32evtlog.OpenEventLog(None, source)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    while events:
                        for event in events:
                            if event.RecordNumber <= self.state.get(source, 0):
                                continue
                            
                            self.state[source] = event.RecordNumber
                            
                            try:
                                msg = win32evtlogutil.SafeFormatMessage(event, source)
                            except:
                                msg = "No message"
                                
                            logs.append({
                                "source": source,
                                "message": msg,
                                "event_id": event.EventID,
                                "computer": self.computer_name,
                                "timestamp": datetime.fromtimestamp(event.TimeGenerated).isoformat()
                            })
                            if len(logs) >= BATCH_SIZE: break
                        if len(logs) >= BATCH_SIZE: break
                        events = win32evtlog.ReadEventLog(hand, flags, 0)
                    win32evtlog.CloseEventLog(hand)
                except Exception as e:
                    logger.error(f"Error reading {source}: {e}")
                
                all_logs.extend(logs)
            
            self.forward(all_logs)
            time.sleep(POLL_INTERVAL)

class LinuxForwarder(BaseForwarder):
    def __init__(self, api_url):
        super().__init__(api_url)
        self.log_files = ['/var/log/syslog', '/var/log/auth.log']
        self.file_positions = self.state.get("file_positions", {})

    def run(self):
        while True:
            all_logs = []
            for log_file in self.log_files:
                if not os.path.exists(log_file): continue
                
                pos = self.file_positions.get(log_file, 0)
                # Handle rotation
                if pos > os.path.getsize(log_file): pos = 0
                
                try:
                    with open(log_file, 'r') as f:
                        f.seek(pos)
                        lines = f.readlines()
                        self.file_positions[log_file] = f.tell()
                        
                        for line in lines:
                            all_logs.append({
                                "source": log_file,
                                "message": line.strip(),
                                "computer": self.computer_name,
                                "timestamp": datetime.now().isoformat()
                            })
                except Exception as e:
                    logger.error(f"Read error {log_file}: {e}")
            
            self.state["file_positions"] = self.file_positions
            self.forward(all_logs)
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Universal Log Forwarder for CyberGard")
    parser.add_argument("--url", default=API_ENDPOINT, help="Backend API URL (e.g., https://cybergard.example.com/api/v1/logs/ingest)")
    parser.add_argument("--api-key", help="API key for authorization (sent as Bearer token)")
    parser.add_argument("--skip-verify", action="store_true", help="Skip TLS certificate verification (insecure, use only for testing)")
    parser.add_argument("--ca-bundle", help="Path to CA bundle for TLS verification (optional)")
    args = parser.parse_args()

    system = platform.system()
    logger.info(f"Detected OS: {system}")
    logger.info(f"API endpoint: {args.url}")
    if args.api_key:
        logger.info("Using API key authentication")
    if args.skip_verify:
        logger.warning("TLS verification disabled (insecure)")
    
    if system == "Windows":
        forwarder = WindowsForwarder(args.url, api_key=args.api_key, skip_verify=args.skip_verify, ca_bundle=args.ca_bundle)
    elif system == "Linux":
        forwarder = LinuxForwarder(args.url, api_key=args.api_key, skip_verify=args.skip_verify, ca_bundle=args.ca_bundle)
    else:
        logger.error("Unsupported OS")
        exit(1)
        
    forwarder.run()
