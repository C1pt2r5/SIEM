#!/usr/bin/env python3
"""
SIEM IP Blocker Script
Automatically blocks malicious IPs using iptables (Linux) or Windows Firewall
"""

import os
import sys
import json
import logging
import subprocess
import platform
import requests
from datetime import datetime
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/siem-ip-blocker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IPBlocker:
    """Handles IP blocking across different operating systems"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.blocked_ips_file = "/tmp/siem_blocked_ips.json"
        self.load_blocked_ips()
    
    def load_blocked_ips(self):
        """Load previously blocked IPs from file"""
        try:
            if os.path.exists(self.blocked_ips_file):
                with open(self.blocked_ips_file, 'r') as f:
                    self.blocked_ips = json.load(f)
            else:
                self.blocked_ips = {}
        except Exception as e:
            logger.error(f"Error loading blocked IPs: {e}")
            self.blocked_ips = {}
    
    def save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            with open(self.blocked_ips_file, 'w') as f:
                json.dump(self.blocked_ips, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving blocked IPs: {e}")
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        private_ranges = [
            '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '127.', '169.254.'
        ]
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def block_ip_linux(self, ip: str, reason: str = "SIEM Alert") -> bool:
        """Block IP using iptables on Linux"""
        try:
            # Check if IP is already blocked
            check_cmd = f"iptables -L INPUT -n | grep {ip}"
            result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            
            if ip in result.stdout:
                logger.info(f"IP {ip} is already blocked")
                return True
            
            # Block the IP
            block_cmd = f"iptables -I INPUT -s {ip} -j DROP"
            result = subprocess.run(block_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully blocked IP {ip} - Reason: {reason}")
                
                # Add comment rule for documentation
                comment_cmd = f"iptables -I INPUT -s {ip} -j DROP -m comment --comment 'SIEM-{reason}'"
                subprocess.run(comment_cmd, shell=True, capture_output=True)
                
                return True
            else:
                logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip} on Linux: {e}")
            return False
    
    def block_ip_windows(self, ip: str, reason: str = "SIEM Alert") -> bool:
        """Block IP using Windows Firewall"""
        try:
            rule_name = f"SIEM-Block-{ip}"
            
            # Check if rule already exists
            check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
            result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            
            if "No rules match" not in result.stdout:
                logger.info(f"IP {ip} is already blocked")
                return True
            
            # Create blocking rule
            block_cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            result = subprocess.run(block_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully blocked IP {ip} - Reason: {reason}")
                return True
            else:
                logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip} on Windows: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str = "SIEM Alert", duration: int = 3600) -> bool:
        """Block IP based on operating system"""
        if not ip or self.is_private_ip(ip):
            logger.warning(f"Skipping private/invalid IP: {ip}")
            return False
        
        # Check if already blocked recently
        if ip in self.blocked_ips:
            last_blocked = datetime.fromisoformat(self.blocked_ips[ip]['timestamp'])
            if (datetime.now() - last_blocked).seconds < duration:
                logger.info(f"IP {ip} was recently blocked, skipping")
                return True
        
        success = False
        if self.os_type == 'linux':
            success = self.block_ip_linux(ip, reason)
        elif self.os_type == 'windows':
            success = self.block_ip_windows(ip, reason)
        else:
            logger.error(f"Unsupported operating system: {self.os_type}")
            return False
        
        if success:
            # Record the blocked IP
            self.blocked_ips[ip] = {
                'timestamp': datetime.now().isoformat(),
                'reason': reason,
                'os': self.os_type
            }
            self.save_blocked_ips()
            
            # Send notification
            self.send_notification(ip, reason)
        
        return success
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock IP based on operating system"""
        try:
            if self.os_type == 'linux':
                cmd = f"iptables -D INPUT -s {ip} -j DROP"
            elif self.os_type == 'windows':
                rule_name = f"SIEM-Block-{ip}"
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            else:
                logger.error(f"Unsupported operating system: {self.os_type}")
                return False
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully unblocked IP {ip}")
                if ip in self.blocked_ips:
                    del self.blocked_ips[ip]
                    self.save_blocked_ips()
                return True
            else:
                logger.error(f"Failed to unblock IP {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            return False
    
    def send_notification(self, ip: str, reason: str):
        """Send notification about blocked IP"""
        try:
            # Slack notification (if configured)
            slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
            if slack_webhook:
                payload = {
                    "text": f"🚫 SIEM: Blocked malicious IP `{ip}`\nReason: {reason}\nTime: {datetime.now().isoformat()}"
                }
                requests.post(slack_webhook, json=payload, timeout=10)
            
            logger.info(f"Notification sent for blocked IP: {ip}")
            
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
    
    def list_blocked_ips(self) -> Dict:
        """List all blocked IPs"""
        return self.blocked_ips
    
    def cleanup_old_blocks(self, max_age_hours: int = 24):
        """Remove old blocked IPs"""
        current_time = datetime.now()
        to_remove = []
        
        for ip, info in self.blocked_ips.items():
            blocked_time = datetime.fromisoformat(info['timestamp'])
            if (current_time - blocked_time).total_seconds() > (max_age_hours * 3600):
                to_remove.append(ip)
        
        for ip in to_remove:
            self.unblock_ip(ip)
            logger.info(f"Removed old block for IP: {ip}")

def main():
    """Main function for command-line usage"""
    if len(sys.argv) < 3:
        print("Usage: python ip_blocker.py <action> <ip> [reason]")
        print("Actions: block, unblock, list, cleanup")
        sys.exit(1)
    
    action = sys.argv[1].lower()
    blocker = IPBlocker()
    
    if action == "block":
        ip = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else "Manual block"
        success = blocker.block_ip(ip, reason)
        sys.exit(0 if success else 1)
    
    elif action == "unblock":
        ip = sys.argv[2]
        success = blocker.unblock_ip(ip)
        sys.exit(0 if success else 1)
    
    elif action == "list":
        blocked_ips = blocker.list_blocked_ips()
        print(json.dumps(blocked_ips, indent=2))
    
    elif action == "cleanup":
        max_age = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        blocker.cleanup_old_blocks(max_age)
    
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)

if __name__ == "__main__":
    main()
