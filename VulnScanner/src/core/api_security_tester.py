import jwt
import requests
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import concurrent.futures
from urllib.parse import urljoin, urlparse

class APISecurityTester:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.common_endpoints = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/swagger',
            '/docs',
            '/graphql',
            '/graphiql',
        ]
        self.jwt_test_cases = [
            {'alg': 'none'},
            {'alg': 'HS256', 'typ': 'JWT'},
            {'alg': 'RS256', 'typ': 'JWT'}
        ]

    def test_jwt_vulnerabilities(self, url: str, token: Optional[str] = None) -> Dict:
        """Test JWT token vulnerabilities"""
        results = {
            "vulnerabilities": [],
            "tested_tokens": [],
            "token_analysis": {}
        }

        try:
            # If token provided, analyze it
            if token:
                token_parts = token.split('.')
                if len(token_parts) == 3:
                    try:
                        header = jwt.get_unverified_header(token)
                        results["token_analysis"] = {
                            "algorithm": header.get('alg'),
                            "type": header.get('typ'),
                            "header": header
                        }
                        
                        # Test for algorithm confusion
                        if header.get('alg') == 'HS256':
                            results["vulnerabilities"].append({
                                "type": "potential_alg_confusion",
                                "description": "HS256 algorithm might be vulnerable to algorithm confusion attacks"
                            })
                    except Exception as e:
                        results["token_analysis"]["error"] = str(e)

            # Test token tampering
            for test_case in self.jwt_test_cases:
                try:
                    test_token = jwt.encode(
                        {"user": "test", "exp": datetime.utcnow() + timedelta(days=1)},
                        "test_key",
                        algorithm=test_case['alg'] if test_case['alg'] != 'none' else None
                    )
                    results["tested_tokens"].append({
                        "payload": test_token,
                        "algorithm": test_case['alg']
                    })
                except Exception as e:
                    self.logger.debug(f"Token generation failed for {test_case['alg']}: {e}")

        except Exception as e:
            self.logger.error(f"JWT testing error: {e}")
            results["error"] = str(e)

        return results

    def test_api_endpoints(self, base_url: str) -> Dict:
        """Test API endpoints for common vulnerabilities"""
        results = {
            "discovered_endpoints": [],
            "vulnerabilities": [],
            "methods_allowed": {}
        }

        # Ensure base URL is properly formatted
        if not base_url.startswith(('http://', 'https://')):
            base_url = f"http://{base_url}"

        # Test common endpoints
        for endpoint in self.common_endpoints:
            url = urljoin(base_url, endpoint)
            try:
                # Test OPTIONS method
                options_response = requests.options(url, timeout=5)
                if options_response.status_code != 404:
                    allowed_methods = options_response.headers.get('Allow', '').split(',')
                    results["methods_allowed"][endpoint] = allowed_methods

                    # Test each allowed method
                    for method in ['GET', 'POST', 'PUT', 'DELETE']:
                        try:
                            response = requests.request(method, url, timeout=5)
                            if response.status_code != 404:
                                results["discovered_endpoints"].append({
                                    "endpoint": endpoint,
                                    "method": method,
                                    "status_code": response.status_code
                                })

                                # Check for security headers
                                if not response.headers.get('X-Content-Type-Options'):
                                    results["vulnerabilities"].append({
                                        "type": "missing_security_header",
                                        "header": "X-Content-Type-Options",
                                        "endpoint": endpoint
                                    })

                        except requests.exceptions.RequestException:
                            continue

            except requests.exceptions.RequestException as e:
                self.logger.debug(f"Error testing endpoint {endpoint}: {e}")

        return results

    def check_rate_limiting(self, url: str, requests_count: int = 50) -> Dict:
        """Test for rate limiting"""
        results = {
            "rate_limited": False,
            "threshold": None,
            "response_times": [],
            "status_codes": []
        }

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(requests.get, url, timeout=5)
                    for _ in range(requests_count)
                ]

                for idx, future in enumerate(concurrent.futures.as_completed(futures)):
                    try:
                        response = future.result()
                        results["response_times"].append(response.elapsed.total_seconds())
                        results["status_codes"].append(response.status_code)

                        if response.status_code in [429, 503]:
                            results["rate_limited"] = True
                            results["threshold"] = idx
                            break

                    except Exception as e:
                        self.logger.debug(f"Request {idx} failed: {e}")

            # Analyze results
            if not results["rate_limited"] and len(set(results["status_codes"])) > 1:
                results["vulnerabilities"] = [{
                    "type": "no_rate_limiting",
                    "description": "No effective rate limiting detected"
                }]

        except Exception as e:
            self.logger.error(f"Rate limiting test error: {e}")
            results["error"] = str(e)

        return results

    def run_all_tests(self, url: str, token: Optional[str] = None) -> Dict:
        """Run all API security tests"""
        all_results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            jwt_future = executor.submit(self.test_jwt_vulnerabilities, url, token)
            endpoints_future = executor.submit(self.test_api_endpoints, url)
            rate_future = executor.submit(self.check_rate_limiting, url)

            all_results["jwt_security"] = jwt_future.result()
            all_results["endpoint_security"] = endpoints_future.result()
            all_results["rate_limiting"] = rate_future.result()

        return all_results 