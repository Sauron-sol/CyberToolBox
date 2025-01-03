import re
import ssl
import requests
import logging
from typing import Dict, List
from datetime import datetime
import concurrent.futures
from urllib.parse import urlparse

class ComplianceChecker:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.password_requirements = {
            "min_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special": True,
            "max_age_days": 90
        }
        self.required_security_headers = {
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-Content-Type-Options": ["nosniff"],
            "Strict-Transport-Security": ["max-age="],
            "Content-Security-Policy": [],
            "X-XSS-Protection": ["1", "1; mode=block"],
            "Referrer-Policy": ["strict-origin", "strict-origin-when-cross-origin"],
            "Permissions-Policy": []
        }
        self.ssl_min_version = ssl.TLSVersion.TLSv1_2

    def _format_url(self, url: str) -> str:
        """Format URL correctly"""
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        return url

    def check_password_policy(self, url: str) -> Dict:
        """Check password policy compliance"""
        url = self._format_url(url)
        results = {
            "compliant": False,
            "findings": [],
            "recommendations": []
        }

        try:
            # Try to find password requirements in common endpoints
            endpoints = ['/register', '/signup', '/password-policy', '/docs']
            password_patterns = {
                "length": r"(?i)password.*?(\d+).*?characters",
                "uppercase": r"(?i).*upper.*case",
                "special": r"(?i)special.*characters",
                "numbers": r"(?i).*numbers"
            }

            for endpoint in endpoints:
                try:
                    response = requests.get(f"{url}{endpoint}", timeout=5, verify=False)
                    content = response.text.lower()

                    # Check for password requirements in response
                    for pattern_name, pattern in password_patterns.items():
                        if re.search(pattern, content):
                            results["findings"].append(f"Found {pattern_name} requirement")
                        else:
                            results["recommendations"].append(f"Add {pattern_name} requirement")

                except requests.RequestException:
                    continue

        except Exception as e:
            self.logger.error(f"Password policy check error: {e}")
            results["error"] = str(e)

        return results

    def check_security_headers(self, url: str) -> Dict:
        """Check security headers compliance"""
        url = self._format_url(url)
        results = {
            "compliant": False,
            "missing_headers": [],
            "incorrect_headers": [],
            "recommendations": []
        }

        try:
            response = requests.get(url, verify=False, timeout=5)
            headers = response.headers

            # Check required headers
            for header, valid_values in self.required_security_headers.items():
                if header not in headers:
                    results["missing_headers"].append(header)
                    results["recommendations"].append(f"Add {header} header")
                elif valid_values:  # If we have specific valid values to check
                    header_value = headers[header]
                    if not any(val in header_value for val in valid_values):
                        results["incorrect_headers"].append({
                            "header": header,
                            "value": header_value,
                            "expected": valid_values
                        })

            results["compliant"] = not (results["missing_headers"] or 
                                      results["incorrect_headers"])

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Security headers check error: {e}")
            results = {
                "compliant": False,
                "missing_headers": [],
                "incorrect_headers": [],
                "recommendations": [],
                "error": str(e)
            }
            return results

        return results

    def check_ssl_compliance(self, hostname: str, port: int = 443) -> Dict:
        """Check SSL/TLS compliance"""
        # Remove port number from hostname if present
        if ':' in hostname:
            hostname, port = hostname.split(':')
            port = int(port)
        results = {
            "compliant": False,
            "findings": [],
            "recommendations": []
        }

        try:
            context = ssl.create_default_context()
            with context.wrap_socket(ssl.socket(), server_hostname=hostname) as sock:
                sock.connect((hostname, port))
                cert = sock.getpeercert()
                cipher = sock.cipher()
                version = sock.version()

                # Check TLS version
                if version < "TLSv1.2":
                    results["findings"].append(f"Outdated TLS version: {version}")
                    results["recommendations"].append("Upgrade to TLS 1.2 or higher")

                # Check certificate
                if cert:
                    not_after = datetime.strptime(cert['notAfter'], 
                                                r'%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        results["findings"].append("Certificate expired")
                    
                    if 'subjectAltName' not in cert:
                        results["findings"].append("Missing Subject Alternative Name")

                # Check cipher strength
                if cipher[2] < 128:
                    results["findings"].append(f"Weak cipher strength: {cipher[2]} bits")

                results["compliant"] = not results["findings"]

        except Exception as e:
            self.logger.error(f"SSL compliance check error: {e}")
            results["error"] = str(e)

        return results

    def check_gdpr_compliance(self, url: str) -> Dict:
        """Basic GDPR compliance check"""
        url = self._format_url(url)
        results = {
            "compliant": False,
            "findings": [],
            "recommendations": []
        }

        try:
            # Check for privacy policy
            privacy_endpoints = ['/privacy', '/privacy-policy', '/gdpr']
            found_privacy = False

            for endpoint in privacy_endpoints:
                try:
                    response = requests.get(f"{url}{endpoint}", timeout=5, verify=False)
                    if response.status_code == 200:
                        found_privacy = True
                        break
                except requests.RequestException:
                    continue

            if not found_privacy:
                results["findings"].append("No privacy policy found")
                results["recommendations"].append("Add GDPR-compliant privacy policy")

            # Check for cookie consent
            response = requests.get(url, verify=False)
            content = response.text.lower()
            if 'cookie' not in content or 'consent' not in content:
                results["findings"].append("No cookie consent mechanism found")
                results["recommendations"].append("Implement cookie consent mechanism")

            results["compliant"] = not results["findings"]

        except Exception as e:
            self.logger.error(f"GDPR compliance check error: {e}")
            results["error"] = str(e)

        return results

    def run_all_checks(self, url: str) -> Dict:
        """Run all compliance checks"""
        all_results = {}
        
        url = self._format_url(url)
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.split(':')[0] or parsed_url.path.split(':')[0]
        port = 443 if url.startswith('https://') else 80

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            password_future = executor.submit(self.check_password_policy, url)
            headers_future = executor.submit(self.check_security_headers, url)
            ssl_future = executor.submit(self.check_ssl_compliance, hostname, port)
            gdpr_future = executor.submit(self.check_gdpr_compliance, url)

            all_results["password_policy"] = password_future.result()
            all_results["security_headers"] = headers_future.result()
            all_results["ssl_compliance"] = ssl_future.result()
            all_results["gdpr_compliance"] = gdpr_future.result()

        return all_results 