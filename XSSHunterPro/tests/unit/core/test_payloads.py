#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
from src.core.payloads import PayloadGenerator
from src.utils.exceptions import PayloadError

@pytest.fixture
def payload_gen():
    return PayloadGenerator()

def test_get_basic_payloads(payload_gen):
    """Test the retrieval of basic payloads."""
    payloads = payload_gen.get_payloads("basic")
    assert len(payloads) > 0
    assert "<script>alert('XSS')</script>" in payloads

def test_get_advanced_payloads(payload_gen):
    """Test the retrieval of advanced payloads."""
    payloads = payload_gen.get_payloads("advanced")
    assert len(payloads) > 0
    assert any("svg" in p for p in payloads)

def test_get_waf_bypass_payloads(payload_gen):
    """Test the retrieval of WAF bypass payloads."""
    payloads = payload_gen.get_payloads("waf")
    assert len(payloads) > 0
    assert any("javascript" in p.lower() for p in payloads)

def test_get_all_payloads(payload_gen):
    """Test the retrieval of all payloads."""
    all_payloads = payload_gen.get_payloads("all")
    basic_payloads = payload_gen.get_payloads("basic")
    advanced_payloads = payload_gen.get_payloads("advanced")
    waf_payloads = payload_gen.get_payloads("waf")
    
    assert len(all_payloads) == len(basic_payloads) + len(advanced_payloads) + len(waf_payloads)

def test_get_random_payload(payload_gen):
    """Test the retrieval of a random payload."""
    payload = payload_gen.get_random_payload()
    assert isinstance(payload, str)
    assert len(payload) > 0

def test_generate_custom_payload(payload_gen):
    """Test the generation of a custom payload."""
    template = "<script>{func}('{msg}')</script>"
    payload = payload_gen.generate_custom_payload(template, func="alert", msg="XSS")
    assert payload == "<script>alert('XSS')</script>"

def test_mutate_payload(payload_gen):
    """Test the mutation of a payload."""
    original = "<script>alert('XSS')</script>"
    mutated = payload_gen.mutate_payload(original)
    assert mutated != original
    assert len(mutated) > 0

@pytest.mark.parametrize("encoding,expected", [
    ("html", "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;"),
    ("hex", "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e"),
    ("unicode", "\\u003c\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003e"),
])
def test_encode_payload(payload_gen, encoding, expected):
    """Test the encoding of payloads."""
    original = "<script>"
    encoded = payload_gen.encode_payload(original, encoding)
    assert encoded.startswith(expected)
