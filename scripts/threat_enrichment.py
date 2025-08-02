#!/usr/bin/env python3
"""
SIEM Threat Intelligence Enrichment Script
Enriches security events with threat intelligence from multiple sources
"""

import os
import sys
import json
import time
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/siem-threat-enrichment.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Handles threat intelligence enrichment from multiple sources"""
    
    def __init__(self):
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.cache_file = "/tmp/siem_threat_cache.json"
        self.cache_duration = 3600  # 1 hour cache
        self.load_cache()
    
    def load_cache(self):
        """Load threat intelligence cache"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
            else:
                self.cache = {}
        except Exception as e:
            logger.error(f"Error loading cache: {e}")
            self.cache = {}
    
    def save_cache(self):
        """Save threat intelligence cache"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving cache: {e}")
    
    def is_cache_valid(self, cache_entry: Dict) -> bool:
        """Check if cache entry is still valid"""
        try:
            cached_time = datetime.fromisoformat(cache_entry['timestamp'])
            return (datetime.now() - cached_time).seconds < self.cache_duration
        except:
            return False
    
    def get_cache_key(self, indicator: str, source: str) -> str:
        """Generate cache key for indicator"""
        return hashlib.md5(f"{source}:{indicator}".encode()).hexdigest()
    
    def enrich_ip_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with AbuseIPDB data"""
        if not self.abuseipdb_api_key:
            logger.warning("AbuseIPDB API key not configured")
            return {}
        
        cache_key = self.get_cache_key(ip, 'abuseipdb')
        
        # Check cache first
        if cache_key in self.cache and self.is_cache_valid(self.cache[cache_key]):
            logger.debug(f"Using cached AbuseIPDB data for {ip}")
            return self.cache[cache_key]['data']
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()['data']
                
                # Cache the result
                self.cache[cache_key] = {
                    'timestamp': datetime.now().isoformat(),
                    'data': data
                }
                self.save_cache()
                
                logger.info(f"AbuseIPDB enrichment for {ip}: Confidence {data.get('abuseConfidencePercentage', 0)}%")
                return data
            else:
                logger.error(f"AbuseIPDB API error for {ip}: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error enriching IP {ip} with AbuseIPDB: {e}")
            return {}
    
    def enrich_ip_virustotal(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with VirusTotal data"""
        if not self.virustotal_api_key:
            logger.warning("VirusTotal API key not configured")
            return {}
        
        cache_key = self.get_cache_key(ip, 'virustotal')
        
        # Check cache first
        if cache_key in self.cache and self.is_cache_valid(self.cache[cache_key]):
            logger.debug(f"Using cached VirusTotal data for {ip}")
            return self.cache[cache_key]['data']
        
        try:
            url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
            params = {
                'apikey': self.virustotal_api_key,
                'ip': ip
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Cache the result
                self.cache[cache_key] = {
                    'timestamp': datetime.now().isoformat(),
                    'data': data
                }
                self.save_cache()
                
                detected_urls = data.get('detected_urls', [])
                detected_samples = data.get('detected_communicating_samples', [])
                
                logger.info(f"VirusTotal enrichment for {ip}: {len(detected_urls)} malicious URLs, {len(detected_samples)} malicious samples")
                return data
            else:
                logger.error(f"VirusTotal API error for {ip}: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error enriching IP {ip} with VirusTotal: {e}")
            return {}
    
    def enrich_hash_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """Enrich file hash with VirusTotal data"""
        if not self.virustotal_api_key:
            logger.warning("VirusTotal API key not configured")
            return {}
        
        cache_key = self.get_cache_key(file_hash, 'virustotal_hash')
        
        # Check cache first
        if cache_key in self.cache and self.is_cache_valid(self.cache[cache_key]):
            logger.debug(f"Using cached VirusTotal data for hash {file_hash}")
            return self.cache[cache_key]['data']
        
        try:
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {
                'apikey': self.virustotal_api_key,
                'resource': file_hash
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Cache the result
                self.cache[cache_key] = {
                    'timestamp': datetime.now().isoformat(),
                    'data': data
                }
                self.save_cache()
                
                positives = data.get('positives', 0)
                total = data.get('total', 0)
                
                logger.info(f"VirusTotal enrichment for hash {file_hash}: {positives}/{total} detections")
                return data
            else:
                logger.error(f"VirusTotal API error for hash {file_hash}: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error enriching hash {file_hash} with VirusTotal: {e}")
            return {}
    
    def get_threat_score(self, enrichment_data: Dict[str, Any]) -> float:
        """Calculate threat score based on enrichment data"""
        score = 0.0
        
        # AbuseIPDB scoring
        if 'abuseipdb' in enrichment_data:
            abuse_data = enrichment_data['abuseipdb']
            confidence = abuse_data.get('abuseConfidencePercentage', 0)
            score += confidence / 100.0 * 0.4  # 40% weight
            
            if abuse_data.get('isWhitelisted', False):
                score -= 0.2  # Reduce score for whitelisted IPs
        
        # VirusTotal IP scoring
        if 'virustotal_ip' in enrichment_data:
            vt_data = enrichment_data['virustotal_ip']
            detected_urls = len(vt_data.get('detected_urls', []))
            detected_samples = len(vt_data.get('detected_communicating_samples', []))
            
            if detected_urls > 0 or detected_samples > 0:
                score += min(0.3, (detected_urls + detected_samples) / 100.0)  # 30% weight max
        
        # VirusTotal hash scoring
        if 'virustotal_hash' in enrichment_data:
            vt_hash_data = enrichment_data['virustotal_hash']
            positives = vt_hash_data.get('positives', 0)
            total = vt_hash_data.get('total', 1)
            
            if total > 0:
                detection_ratio = positives / total
                score += detection_ratio * 0.3  # 30% weight
        
        return min(1.0, score)  # Cap at 1.0
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a security event with threat intelligence"""
        enriched_event = event.copy()
        enrichment_data = {}
        
        # Extract indicators from event
        source_ip = event.get('source', {}).get('ip')
        file_hashes = []
        
        # Look for file hashes in various fields
        for field in ['file.hash.md5', 'file.hash.sha1', 'file.hash.sha256']:
            if field in event:
                file_hashes.append(event[field])
        
        # Enrich IP address
        if source_ip:
            logger.info(f"Enriching IP: {source_ip}")
            
            # AbuseIPDB enrichment
            abuseipdb_data = self.enrich_ip_abuseipdb(source_ip)
            if abuseipdb_data:
                enrichment_data['abuseipdb'] = abuseipdb_data
            
            # VirusTotal IP enrichment
            virustotal_ip_data = self.enrich_ip_virustotal(source_ip)
            if virustotal_ip_data:
                enrichment_data['virustotal_ip'] = virustotal_ip_data
            
            # Rate limiting
            time.sleep(1)
        
        # Enrich file hashes
        for file_hash in file_hashes:
            logger.info(f"Enriching hash: {file_hash}")
            
            virustotal_hash_data = self.enrich_hash_virustotal(file_hash)
            if virustotal_hash_data:
                enrichment_data['virustotal_hash'] = virustotal_hash_data
            
            # Rate limiting
            time.sleep(1)
        
        # Calculate threat score
        if enrichment_data:
            threat_score = self.get_threat_score(enrichment_data)
            
            enriched_event['threat'] = {
                'intelligence': enrichment_data,
                'score': threat_score,
                'enriched_at': datetime.now().isoformat()
            }
            
            # Add threat classification
            if threat_score >= 0.8:
                enriched_event['threat']['classification'] = 'high'
            elif threat_score >= 0.5:
                enriched_event['threat']['classification'] = 'medium'
            elif threat_score >= 0.2:
                enriched_event['threat']['classification'] = 'low'
            else:
                enriched_event['threat']['classification'] = 'clean'
            
            logger.info(f"Event enriched with threat score: {threat_score:.2f}")
        
        return enriched_event
    
    def cleanup_cache(self, max_age_hours: int = 24):
        """Clean up old cache entries"""
        current_time = datetime.now()
        to_remove = []
        
        for key, entry in self.cache.items():
            try:
                cached_time = datetime.fromisoformat(entry['timestamp'])
                if (current_time - cached_time).total_seconds() > (max_age_hours * 3600):
                    to_remove.append(key)
            except:
                to_remove.append(key)
        
        for key in to_remove:
            del self.cache[key]
        
        if to_remove:
            self.save_cache()
            logger.info(f"Cleaned up {len(to_remove)} old cache entries")

def main():
    """Main function for command-line usage"""
    if len(sys.argv) < 2:
        print("Usage: python threat_enrichment.py <command> [args]")
        print("Commands:")
        print("  enrich-ip <ip>        - Enrich IP address")
        print("  enrich-hash <hash>    - Enrich file hash")
        print("  enrich-event <json>   - Enrich event from JSON")
        print("  cleanup [hours]       - Clean up cache")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    ti = ThreatIntelligence()
    
    if command == "enrich-ip":
        if len(sys.argv) < 3:
            print("Usage: python threat_enrichment.py enrich-ip <ip>")
            sys.exit(1)
        
        ip = sys.argv[2]
        event = {'source': {'ip': ip}}
        enriched = ti.enrich_event(event)
        print(json.dumps(enriched, indent=2))
    
    elif command == "enrich-hash":
        if len(sys.argv) < 3:
            print("Usage: python threat_enrichment.py enrich-hash <hash>")
            sys.exit(1)
        
        file_hash = sys.argv[2]
        event = {'file.hash.sha256': file_hash}
        enriched = ti.enrich_event(event)
        print(json.dumps(enriched, indent=2))
    
    elif command == "enrich-event":
        if len(sys.argv) < 3:
            print("Usage: python threat_enrichment.py enrich-event '<json>'")
            sys.exit(1)
        
        try:
            event = json.loads(sys.argv[2])
            enriched = ti.enrich_event(event)
            print(json.dumps(enriched, indent=2))
        except json.JSONDecodeError as e:
            print(f"Invalid JSON: {e}")
            sys.exit(1)
    
    elif command == "cleanup":
        max_age = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        ti.cleanup_cache(max_age)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()
