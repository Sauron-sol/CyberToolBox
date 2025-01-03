import nmap
import requests
from typing import Dict
import logging
import warnings
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except Exception as e:
            logging.error(f"Error initializing nmap: {e}")
            print("Make sure nmap is installed on your system:")
            print("brew install nmap")
            raise
        self.logger = logging.getLogger(__name__)

    def scan_ports(self, target: str, ports: str = "1-1000") -> Dict:
        """Basic port scan"""
        try:
            self.logger.info(f"Scanning ports for {target}")
            result = self.nm.scan(target, ports, arguments="-sV -sS")
            return self._parse_nmap_result(result)
        except Exception as e:
            self.logger.error(f"Error scanning ports: {e}")
            return {"error": str(e)}

    def scan_web_vulns(self, url: str) -> Dict:
        """Basic web vulnerability scan"""
        results = {
            "xss_vulns": [],
            "security_headers": {},
            "server_info": {},
            "status_code": None
        }

        try:
            response = requests.get(url, verify=False, timeout=10)
            results["status_code"] = response.status_code
            results["security_headers"] = self._check_security_headers(response.headers)
            results["server_info"] = self._get_server_info(response.headers)
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error scanning web vulnerabilities: {e}")
            results["error"] = str(e)

        return results

    def _check_security_headers(self, headers: Dict) -> Dict:
        """Checks security headers"""
        security_headers = {
            "X-XSS-Protection": "Missing",
            "X-Frame-Options": "Missing",
            "X-Content-Type-Options": "Missing",
            "Strict-Transport-Security": "Missing",
            "Content-Security-Policy": "Missing"
        }

        for header in security_headers.keys():
            if header in headers:
                security_headers[header] = headers[header]

        return security_headers

    def _get_server_info(self, headers: Dict) -> Dict:
        """Extracts server information"""
        return {
            "server": headers.get("Server", "Unknown"),
            "powered_by": headers.get("X-Powered-By", "Unknown"),
            "technology": headers.get("X-AspNet-Version", "Unknown")
        }

    def _parse_nmap_result(self, result: Dict) -> Dict:
        """Parses nmap results"""
        parsed = {"ports": []}
        try:
            for host in result["scan"].values():
                for port, data in host.get("tcp", {}).items():
                    parsed["ports"].append({
                        "port": port,
                        "state": data["state"],
                        "service": data["name"],
                        "version": data.get("version", "unknown")
                    })
        except Exception as e:
            self.logger.error(f"Error parsing nmap result: {e}")
            parsed["error"] = str(e)
        return parsed 