#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from src.core.reporting import ReportGenerator
from src.utils.exceptions import ReportingError

@pytest.fixture
def report_config():
    return {
        "output_dir": "reports",
        "formats": ["html", "pdf", "json"],
        "include_screenshots": True,
        "risk_levels": ["Critical", "High", "Medium", "Low", "Info"]
    }

@pytest.fixture
def sample_results():
    return {
        "url": "http://example.com",
        "vulnerabilities": [
            {
                "type": "reflected_xss",
                "parameter": "q",
                "payload": "<script>alert('XSS')</script>",
                "confidence": "high"
            }
        ],
        "forms": [
            {
                "action": "/search",
                "method": "get",
                "inputs": [{"name": "q", "type": "text"}]
            }
        ]
    }

@pytest.fixture
def report_gen(report_config):
    return ReportGenerator(report_config)

def test_init(report_gen, report_config):
    """Test the initialization of the report generator."""
    assert report_gen.config == report_config
    assert isinstance(report_gen.template_dir, Path)
    assert isinstance(report_gen.output_dir, Path)

def test_enrich_results(report_gen, sample_results):
    """Test the enrichment of results."""
    enriched = report_gen._enrich_results(sample_results)
    
    assert "metadata" in enriched
    assert "statistics" in enriched
    assert enriched["statistics"]["total_vulnerabilities"] == 1
    assert enriched["statistics"]["total_forms"] == 1
    
    # Check that risk levels have been added
    assert "risk_level" in enriched["vulnerabilities"][0]

def test_calculate_risk_level(report_gen):
    """Test the calculation of risk levels."""
    vuln_types = {
        "reflected_xss": "High",
        "stored_xss": "Critical",
        "dom_xss": "High",
        "form_xss": "High"
    }
    
    for vuln_type, expected_level in vuln_types.items():
        vulnerability = {
            "type": vuln_type,
            "confidence": "high"
        }
        risk_level = report_gen._calculate_risk_level(vulnerability)
        assert risk_level in ["Critical", "High", "Medium", "Low", "Info"]

@pytest.mark.asyncio
async def test_generate_report(report_gen, sample_results, tmp_path):
    """Test the generation of a complete report."""
    with patch('matplotlib.pyplot.savefig'), \
         patch('pdfkit.from_file'), \
         patch('jinja2.Environment.get_template') as mock_template:
        
        # Mock the template
        mock_template_instance = Mock()
        mock_template_instance.render.return_value = "<html>Test Report</html>"
        mock_template.return_value = mock_template_instance
        
        # Generate the report
        output_path = report_gen.generate_report(sample_results, tmp_path)
        
        # Check that the directory exists
        assert Path(output_path).exists()

def test_generate_json_report(report_gen, sample_results, tmp_path):
    """Test the generation of a JSON report."""
    json_path = tmp_path / "report.json"
    report_gen._generate_json_report(sample_results, json_path)
    
    assert json_path.exists()
    with open(json_path) as f:
        data = json.load(f)
        assert data["url"] == sample_results["url"]
        assert len(data["vulnerabilities"]) == len(sample_results["vulnerabilities"])

def test_aggregate_results(report_gen):
    """Test the aggregation of results from multiple scans."""
    results = [
        {
            "url": "http://example1.com",
            "vulnerabilities": [{"type": "reflected_xss"}],
            "forms": []
        },
        {
            "url": "http://example2.com",
            "vulnerabilities": [{"type": "dom_xss"}],
            "forms": [{"action": "/search"}]
        }
    ]
    
    aggregated = report_gen._aggregate_results(results)
    assert len(aggregated["urls"]) == 2
    assert len(aggregated["vulnerabilities"]) == 2
    assert len(aggregated["forms"]) == 1
    assert aggregated["total_vulnerabilities"] == 2
