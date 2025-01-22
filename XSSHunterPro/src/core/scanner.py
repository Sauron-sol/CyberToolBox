#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import logging
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import aiohttp
from bs4 import BeautifulSoup

from src.core.payloads import PayloadGenerator
from src.utils.exceptions import ScannerException

class Scanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.payload_gen = PayloadGenerator()
        self.session = None
        self.results = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers={"User-Agent": self.config["user_agent"]},
            timeout=aiohttp.ClientTimeout(total=self.config["timeout"])
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan a single URL for XSS vulnerabilities."""
        if not self.session:
            async with self.__class__(self.config) as scanner:
                return await scanner.scan_url(url)
                
        try:
            logging.info(f"Scanning URL: {url}")
            
            # Initial request
            logging.debug(f"Sending initial request to {url}")
            async with self.session.get(url) as response:
                if response.status != 200:
                    raise ScannerException(f"Failed to fetch {url}: {response.status}")
                
                logging.debug("Retrieving page content")
                content = await response.text()
                
            # Parse the DOM
            logging.debug("Parsing the DOM")
            soup = BeautifulSoup(content, "html.parser")
            
            # Collect results
            results = {
                "url": url,
                "vulnerabilities": [],
                "parameters": [],
                "forms": []
            }
            
            # Analyze input vectors
            logging.info("Starting injection vectors analysis")
            await asyncio.gather(
                self._check_url_parameters(url, results),
                self._check_forms(soup, url, results),
                self._check_dom_xss(soup, url, results)
            )
            
            logging.info(f"Scan completed. {len(results['vulnerabilities'])} vulnerabilities found.")
            return results
            
        except Exception as e:
            logging.error(f"Error scanning {url}: {e}")
            raise ScannerException(f"Scan failed for {url}: {str(e)}")
            
    async def scan_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple URLs in parallel."""
        if not self.session:
            async with self.__class__(self.config) as scanner:
                return await scanner.scan_urls(urls)
                
        tasks = [self.scan_url(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)
        
    async def _check_url_parameters(self, url: str, results: Dict[str, Any]):
        """Check URL parameters for XSS vulnerabilities."""
        parsed = urlparse(url)
        if not parsed.query:
            logging.debug("No URL parameter found")
            return
            
        logging.debug(f"Analyzing URL parameters: {parsed.query}")
        # Test each parameter
        for param in parsed.query.split("&"):
            if "=" not in param:
                continue
                
            name, _ = param.split("=", 1)
            logging.debug(f"Testing parameter: {name}")
            for payload in self.payload_gen.get_payloads():
                test_url = self._inject_payload(url, name, payload)
                
                try:
                    logging.debug(f"Testing payload: {payload}")
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        if self._check_payload_reflection(content, payload):
                            logging.warning(f"XSS Reflected found in parameter {name}")
                            results["vulnerabilities"].append({
                                "type": "reflected_xss",
                                "parameter": name,
                                "payload": payload,
                                "confidence": "high"
                            })
                            break
                except Exception as e:
                    logging.debug(f"Error testing parameter {name}: {e}")
                    
    async def _check_forms(self, soup: BeautifulSoup, base_url: str, results: Dict[str, Any]):
        """Check HTML forms for XSS vulnerabilities."""
        forms = soup.find_all("form")
        for form in forms:
            form_info = {
                "action": urljoin(base_url, form.get("action", "")),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }
            
            # Analyze form inputs
            for input_field in form.find_all(["input", "textarea"]):
                input_type = input_field.get("type", "text")
                input_name = input_field.get("name")
                
                if input_name and input_type not in ["submit", "button", "image"]:
                    form_info["inputs"].append({
                        "name": input_name,
                        "type": input_type
                    })
                    
                    # Test for XSS in form fields
                    for payload in self.payload_gen.get_payloads():
                        try:
                            data = {input_name: payload}
                            
                            if form_info["method"] == "get":
                                async with self.session.get(form_info["action"], params=data) as response:
                                    content = await response.text()
                            else:
                                async with self.session.post(form_info["action"], data=data) as response:
                                    content = await response.text()
                                    
                            if self._check_payload_reflection(content, payload):
                                results["vulnerabilities"].append({
                                    "type": "form_xss",
                                    "form_action": form_info["action"],
                                    "parameter": input_name,
                                    "payload": payload,
                                    "confidence": "high"
                                })
                                break
                                
                        except Exception as e:
                            logging.debug(f"Error testing form input {input_name}: {e}")
                            
            results["forms"].append(form_info)
            
    async def _check_dom_xss(self, soup: BeautifulSoup, url: str, results: Dict[str, Any]):
        """Check for DOM-based XSS vulnerabilities."""
        # Check for dangerous JS sinks
        dangerous_sinks = [
            "eval(",
            "innerHTML",
            "outerHTML",
            "document.write(",
            "document.writeln("
        ]
        
        scripts = soup.find_all("script")
        for script in scripts:
            script_content = script.string
            if script_content:
                for sink in dangerous_sinks:
                    if sink in script_content:
                        results["vulnerabilities"].append({
                            "type": "dom_xss",
                            "sink": sink,
                            "confidence": "medium",
                            "description": f"Potentially dangerous DOM sink found: {sink}"
                        })
                        
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject a payload into a URL parameter."""
        parsed = list(urlparse(url))
        if parsed[4]:  # query string
            params = dict(p.split('=', 1) for p in parsed[4].split('&') if '=' in p)
            params[param] = payload
            parsed[4] = urlencode(params)
        else:
            parsed[4] = urlencode({param: payload})
        return urlunparse(parsed)
        
    def _check_payload_reflection(self, content: str, payload: str) -> bool:
        """Check if a payload is reflected in the response."""
        return payload in content 