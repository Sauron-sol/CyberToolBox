#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import Mock, patch, AsyncMock
from bs4 import BeautifulSoup
from src.core.scanner import Scanner
from src.utils.exceptions import ScannerException

@pytest.fixture
def scanner_config():
    return {
        "timeout": 30,
        "max_threads": 10,
        "user_agent": "Test User Agent",
        "verify_ssl": True,
        "follow_redirects": True,
        "max_redirects": 5
    }

@pytest.fixture
def scanner(scanner_config):
    return Scanner(scanner_config)

@pytest.mark.asyncio
async def test_scan_url_failure(scanner):
    """Test the scan of a URL with failure."""
    test_url = "http://example.com"
    
    # Mock the session with an error
    mock_response = Mock()
    mock_response.status = 404
    mock_session = Mock()
    mock_session.get = Mock(return_value=mock_response)
    
    with patch('aiohttp.ClientSession', return_value=mock_session):
        scanner.session = mock_session
        with pytest.raises(ScannerException):
            await scanner.scan_url(test_url)

@pytest.mark.asyncio
async def test_check_forms(scanner):
    """Test the verification of forms."""
    test_html = """
    <form action="/search" method="post">
        <input type="text" name="search">
        <input type="submit">
    </form>
    """
    soup = BeautifulSoup(test_html, "html.parser")
    results = {"vulnerabilities": [], "forms": []}
    
    # Mock the session
    mock_response = Mock()
    mock_response.text = Mock(return_value="<script>alert('XSS')</script>")
    mock_session = Mock()
    mock_session.post = Mock(return_value=mock_response)
    
    scanner.session = mock_session
    await scanner._check_forms(soup, "http://example.com", results)
    
    assert len(results["forms"]) == 1
    assert results["forms"][0]["method"] == "post"
    assert len(results["forms"][0]["inputs"]) == 1

def test_check_payload_reflection(scanner):
    """Test the detection of payload reflection."""
    content = "<div>User input: <script>alert('XSS')</script></div>"
    payload = "<script>alert('XSS')</script>"
    
    assert scanner._check_payload_reflection(content, payload) is True
    assert scanner._check_payload_reflection("Safe content", payload) is False

def test_inject_payload(scanner):
    """Test the injection of payload into parameters."""
    url = "http://example.com/search?q=test"
    payload = "<script>alert('XSS')</script>"
    param = "q"
    
    injected_url = scanner._inject_payload(url, param, payload)
    
    # Verify that the URL is correctly formed
    assert "http://example.com/search?" in injected_url
    assert "q=" in injected_url
    
    # Decode the URL to verify that the payload is present
    from urllib.parse import unquote
    decoded_url = unquote(injected_url)
    assert payload in decoded_url
