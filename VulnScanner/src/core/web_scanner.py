from typing import Dict, List
import requests
import re
from bs4 import BeautifulSoup
import logging
from .config import USER_AGENT, HEADERS, DEFAULT_TIMEOUT

class WebVulnScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.timeout = DEFAULT_TIMEOUT
        self.payloads = {
            'xss': ['<script>alert(1)</script>', '"><script>alert(1)</script>'],
            'sqli': ["' OR '1'='1", "admin' --", "1' OR '1'='1"],
        }

    def scan(self, target: str, deep: bool = False) -> Dict:
        try:
            response = self.session.get(target, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            results = {
                "forms": [],
                "vulnerabilities": []
            }
            
            for form in forms:
                form_info = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get"),
                    "inputs": [{"name": input.get("name"), "type": input.get("type")} 
                              for input in form.find_all("input")]
                }
                results["forms"].append(form_info)
                
                # Test XSS in forms
                if self._test_form_xss(form_info, target):
                    results["vulnerabilities"].append({
                        "type": "XSS",
                        "location": f"Form: {form_info['action']}"
                    })
            
            return results
        except Exception as e:
            self.logger.error(f"Web scan error: {e}")
            return {}

    def _test_form_xss(self, form: Dict, url: str) -> bool:
        # XSS test simulation - to be implemented securely
        return False 