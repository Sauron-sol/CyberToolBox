#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

import jinja2
import pdfkit
import matplotlib.pyplot as plt
import seaborn as sns

from src.utils.exceptions import ReportingError

class ReportGenerator:
    """Report generator for XSS scan results."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.template_dir = Path("templates")
        self.output_dir = Path(config.get("output_dir", "reports"))
        self.output_dir.mkdir(exist_ok=True)
        
        # Jinja2 configuration
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=True
        )
        
    def generate_report(self, results: Dict[str, Any], output_path: str = None) -> str:
        """Generates a detailed report for a scan."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"report_{timestamp}"
            
        output_path = Path(output_path)
        output_path.mkdir(exist_ok=True)
        
        # Enrich the results
        enriched_results = self._enrich_results(results)
        
        # Generate charts
        self._generate_charts(enriched_results, output_path)
        
        # Generate different report formats
        report_files = []
        
        if "html" in self.config.get("formats", ["html"]):
            html_path = output_path / "report.html"
            self._generate_html_report(enriched_results, html_path)
            report_files.append(html_path)
            
        if "pdf" in self.config.get("formats", []):
            pdf_path = output_path / "report.pdf"
            self._generate_pdf_report(enriched_results, pdf_path)
            report_files.append(pdf_path)
            
        if "json" in self.config.get("formats", []):
            json_path = output_path / "report.json"
            self._generate_json_report(enriched_results, json_path)
            report_files.append(json_path)
            
        return str(output_path)
        
    def generate_batch_report(self, results: List[Dict[str, Any]], output_path: str = None) -> str:
        """Generates a report for multiple scans."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"batch_report_{timestamp}"
            
        output_path = Path(output_path)
        output_path.mkdir(exist_ok=True)
        
        # Aggregate the results
        aggregated_results = self._aggregate_results(results)
        
        # Generate the report
        return self.generate_report(aggregated_results, output_path)
        
    def _enrich_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Enriches the results with metadata and statistics."""
        enriched = results.copy()
        
        # Add metadata
        enriched["metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "tool_version": "1.0.0",
            "scan_duration": results.get("scan_duration", "N/A")
        }
        
        # Calculate statistics
        stats = {
            "total_vulnerabilities": len(results.get("vulnerabilities", [])),
            "total_forms": len(results.get("forms", [])),
            "vulnerability_types": {}
        }
        
        for vuln in results.get("vulnerabilities", []):
            vuln_type = vuln.get("type", "unknown")
            stats["vulnerability_types"][vuln_type] = stats["vulnerability_types"].get(vuln_type, 0) + 1
            
        enriched["statistics"] = stats
        
        # Add risk levels
        for vuln in enriched.get("vulnerabilities", []):
            vuln["risk_level"] = self._calculate_risk_level(vuln)
            
        return enriched
        
    def _generate_charts(self, results: Dict[str, Any], output_path: Path):
        """Generates charts for the report."""
        try:
            # Style configuration
            plt.style.use('default')  # Use the default style instead of seaborn
            
            # Chart for vulnerability types
            vuln_types = results["statistics"]["vulnerability_types"]
            if vuln_types:
                plt.figure(figsize=(10, 6))
                plt.bar(list(vuln_types.keys()), list(vuln_types.values()))
                plt.title("Distribution of Vulnerability Types")
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(output_path / "vulnerabilities_distribution.png")
                plt.close()
                
            # Chart for risk levels
            risk_levels = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for vuln in results.get("vulnerabilities", []):
                risk_levels[vuln["risk_level"]] += 1
                
            if any(risk_levels.values()):
                plt.figure(figsize=(8, 8))
                plt.pie(
                    risk_levels.values(),
                    labels=risk_levels.keys(),
                    autopct='%1.1f%%',
                    colors=['#e74c3c', '#e67e22', '#f1c40f', '#3498db', '#2ecc71']
                )
                plt.title("Distribution of Risk Levels")
                plt.savefig(output_path / "risk_distribution.png")
                plt.close()
                
        except Exception as e:
            logging.error(f"Error generating charts: {e}")
            # Continue despite the error to generate the rest of the report
        
    def _generate_html_report(self, results: Dict[str, Any], output_path: Path):
        """Generates an HTML report."""
        template = self.jinja_env.get_template("report.html")
        html_content = template.render(results=results)
        output_path.write_text(html_content, encoding="utf-8")
        
    def _generate_pdf_report(self, results: Dict[str, Any], output_path: Path):
        """Generates a PDF report."""
        # Generate HTML first
        html_path = output_path.parent / "temp.html"
        self._generate_html_report(results, html_path)
        
        # wkhtmltopdf configuration
        options = {
            'quiet': '',
            'enable-local-file-access': None,
            'disable-smart-shrinking': None,
            'no-outline': None,
            'encoding': 'UTF-8'
        }
        
        # Convert to PDF
        try:
            pdfkit.from_file(str(html_path), str(output_path), options=options)
        except Exception as e:
            logging.error(f"Error generating PDF: {e}")
            # Fallback: keep only the HTML report
            logging.info("Keeping the HTML report as an alternative")
            html_path.rename(output_path.with_suffix('.html'))
        finally:
            if html_path.exists():
                html_path.unlink()
            
    def _generate_json_report(self, results: Dict[str, Any], output_path: Path):
        """Generates a JSON report."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            
    def _calculate_risk_level(self, vulnerability: Dict[str, Any]) -> str:
        """Calculates the risk level of a vulnerability."""
        risk_factors = {
            "reflected_xss": 3,
            "stored_xss": 4,
            "dom_xss": 3,
            "form_xss": 3
        }
        
        base_score = risk_factors.get(vulnerability.get("type", "unknown"), 2)
        
        # Adjust the score based on confidence
        confidence_multiplier = {
            "high": 1.0,
            "medium": 0.7,
            "low": 0.4
        }.get(vulnerability.get("confidence", "medium"), 0.7)
        
        final_score = base_score * confidence_multiplier
        
        # Determine the risk level
        if final_score >= 3.5:
            return "Critical"
        elif final_score >= 2.5:
            return "High"
        elif final_score >= 1.5:
            return "Medium"
        elif final_score >= 0.5:
            return "Low"
        else:
            return "Info"
            
    def _aggregate_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregates the results of multiple scans."""
        aggregated = {
            "urls": [],
            "vulnerabilities": [],
            "forms": [],
            "scan_count": len(results),
            "total_vulnerabilities": 0
        }
        
        for result in results:
            if isinstance(result, Exception):
                continue
                
            aggregated["urls"].append(result.get("url"))
            aggregated["vulnerabilities"].extend(result.get("vulnerabilities", []))
            aggregated["forms"].extend(result.get("forms", []))
            
        aggregated["total_vulnerabilities"] = len(aggregated["vulnerabilities"])
        
        return aggregated 