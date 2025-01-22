import re
import logging
from dataclasses import dataclass, field
from typing import Set, List, Dict, Any
from urllib.parse import urlparse
import ipaddress
import hashlib
import requests
from pathlib import Path

from utils.config import Config
from analyzers.static_analyzer import StaticAnalysisResult

@dataclass
class IOCResult:
    """Results of IOC extraction."""
    domains: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    file_hashes: Dict[str, str] = field(default_factory=dict)
    suspicious_files: List[Dict[str, Any]] = field(default_factory=list)
    exfiltration_endpoints: Set[str] = field(default_factory=set)
    c2_servers: Set[str] = field(default_factory=set)

class IOCExtractor:
    """Indicator of Compromise Extractor."""

    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Advanced detection patterns
        self.ip_pattern = re.compile(
            r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        )
        self.domain_pattern = re.compile(
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        )
        self.exfil_patterns = [
            re.compile(r'mail\s*\('),
            re.compile(r'curl\s+.*?http'),
            re.compile(r'file_get_contents\s*\('),
            re.compile(r'upload.*?\.php'),
            re.compile(r'ftp_connect|ssh2_connect')
        ]

    def extract(self, static_results: StaticAnalysisResult) -> IOCResult:
        """Extracts IOCs from static analysis results."""
        result = IOCResult()
        
        # Extraction of domains and IPs from URLs
        for url in static_results.extracted_urls:
            self._process_url(url, result)
            
        # Adding emails
        result.emails.update(static_results.extracted_emails)
        
        # Analysis of suspicious patterns
        for pattern in static_results.suspicious_patterns:
            self._analyze_suspicious_pattern(pattern, result)
            
        # Analysis of obfuscation techniques
        self._analyze_obfuscation_techniques(static_results.obfuscation_techniques, result)
        
        return result

    def _process_url(self, url: str, result: IOCResult) -> None:
        """Processes a URL to extract IOCs."""
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                # Domain extraction
                domain = parsed.netloc.split(':')[0]
                if self._is_ip(domain):
                    result.ips.add(domain)
                else:
                    result.domains.add(domain)
                
                # Adding the complete URL
                result.urls.add(url)
                
                # Detection of exfiltration endpoints
                if self._is_exfiltration_endpoint(url):
                    result.exfiltration_endpoints.add(url)
                
                # Detection of C2 servers
                if self._is_c2_server(url):
                    result.c2_servers.add(domain)
                    
        except Exception as e:
            self.logger.error(f"Error processing URL {url}: {e}")

    def _is_ip(self, host: str) -> bool:
        """Checks if a string is an IP address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _is_exfiltration_endpoint(self, url: str) -> bool:
        """Detects if a URL is a potential exfiltration endpoint."""
        exfil_indicators = [
            'send', 'upload', 'submit', 'post', 'result', 
            'data', 'log', 'store', 'save', 'export'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in exfil_indicators)

    def _is_c2_server(self, url: str) -> bool:
        """Detects if a URL corresponds to a potential C2 server."""
        c2_indicators = [
            'gate', 'panel', 'admin', 'control', 'command',
            'bot', 'update', 'config', 'sync', 'check'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in c2_indicators)

    def _analyze_suspicious_pattern(self, pattern: Dict[str, Any], result: IOCResult) -> None:
        """Analyzes a suspicious pattern to extract IOCs."""
        file_path = pattern.get('file')
        if file_path:
            # Calculating file hashes
            try:
                path = Path(file_path)
                if path.exists():
                    with open(path, 'rb') as f:
                        content = f.read()
                        result.file_hashes[file_path] = {
                            'md5': hashlib.md5(content).hexdigest(),
                            'sha1': hashlib.sha1(content).hexdigest(),
                            'sha256': hashlib.sha256(content).hexdigest()
                        }
                    
                    # Adding to suspicious files if YARA match
                    if pattern.get('rule'):
                        result.suspicious_files.append({
                            'path': file_path,
                            'rule': pattern['rule'],
                            'tags': pattern.get('tags', []),
                            'hashes': result.file_hashes[file_path]
                        })
            except Exception as e:
                self.logger.error(f"Error analyzing file {file_path}: {e}")

    def _analyze_obfuscation_techniques(self, techniques: List[Dict[str, Any]], result: IOCResult) -> None:
        """Analyzes obfuscation techniques to identify potential IOCs."""
        for technique in techniques:
            file_path = technique.get('file')
            if file_path and file_path not in result.file_hashes:
                try:
                    path = Path(file_path)
                    if path.exists():
                        with open(path, 'rb') as f:
                            content = f.read()
                            result.file_hashes[file_path] = {
                                'md5': hashlib.md5(content).hexdigest(),
                                'sha1': hashlib.sha1(content).hexdigest(),
                                'sha256': hashlib.sha256(content).hexdigest()
                            }
                        
                        result.suspicious_files.append({
                            'path': file_path,
                            'technique': technique['technique'],
                            'line_count': technique.get('line_count', 0),
                            'hashes': result.file_hashes[file_path]
                        })
                except Exception as e:
                    self.logger.error(f"Error analyzing obfuscated file {file_path}: {e}")

    def enrich_iocs(self, result: IOCResult) -> None:
        """Enriches IOCs with external data (VirusTotal, etc.)."""
        if not self.config.api_keys.get('virustotal'):
            self.logger.warning("No VirusTotal API key configured")
            return
            
        try:
            headers = {
                'x-apikey': self.config.api_keys['virustotal']
            }
            
            # Enrichment of domains
            for domain in result.domains:
                response = requests.get(
                    f'https://www.virustotal.com/api/v3/domains/{domain}',
                    headers=headers
                )
                if response.status_code == 200:
                    data = response.json()
                    # Processing the results...
                    
            # Enrichment of hashes
            for file_info in result.suspicious_files:
                sha256 = file_info['hashes']['sha256']
                response = requests.get(
                    f'https://www.virustotal.com/api/v3/files/{sha256}',
                    headers=headers
                )
                if response.status_code == 200:
                    data = response.json()
                    # Processing the results...
                    
        except Exception as e:
            self.logger.error(f"Error enriching IOCs: {e}") 