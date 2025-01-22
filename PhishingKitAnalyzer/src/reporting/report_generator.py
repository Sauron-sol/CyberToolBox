import json
from json import JSONEncoder
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import jinja2
import pdfkit
from dataclasses import asdict
import yara

from utils.config import Config
from analyzers.static_analyzer import StaticAnalysisResult
from extractors.ioc_extractor import IOCResult

class YaraJSONEncoder(JSONEncoder):
    """Custom JSON Encoder to handle YARA objects."""
    def default(self, obj):
        if isinstance(obj, yara.StringMatch):
            return {
                'identifier': obj.identifier,
                'matches': [{
                    'offset': match.offset,
                    'data': match.strings.hex() if hasattr(match, 'strings') else None
                } for match in obj.instances]
            }
        return super().default(obj)

class ReportGenerator:
    """Report generator for phishing kit analysis."""

    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader('templates'),
            autoescape=True
        )

    def generate(
        self,
        path: Path,
        static_results: StaticAnalysisResult,
        iocs: IOCResult,
        dynamic_results: Optional[Dict[str, Any]] = None,
        full_report: bool = False
    ) -> None:
        """Generates reports in configured formats."""
        try:
            report_data = self._prepare_report_data(
                path, static_results, iocs, dynamic_results, full_report
            )
            
            output_dir = self.config.get_output_dir()
            output_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_filename = f"phishing_analysis_{timestamp}"
            
            for format_type in self.config.reporting.formats:
                if format_type == 'json':
                    self._generate_json_report(report_data, output_dir / f"{base_filename}.json")
                elif format_type == 'html':
                    self._generate_html_report(report_data, output_dir / f"{base_filename}.html")
                elif format_type == 'pdf':
                    self._generate_pdf_report(report_data, output_dir / f"{base_filename}.pdf")
                    
        except Exception as e:
            self.logger.error(f"Error generating reports: {e}")
            raise

    def _prepare_report_data(
        self,
        path: Path,
        static_results: StaticAnalysisResult,
        iocs: IOCResult,
        dynamic_results: Optional[Dict[str, Any]],
        full_report: bool
    ) -> Dict[str, Any]:
        """Prepares data for the report."""
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(static_results, iocs)
        
        # Determine threat level
        threat_level = self._determine_threat_level(risk_score)
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'analyzed_path': str(path),
            'risk_score': risk_score,
            'threat_level': threat_level,
            'summary': {
                'total_files': static_results.total_files,
                'total_size': self._format_size(static_results.total_size),
                'suspicious_files': len(iocs.suspicious_files),
                'extracted_urls': len(iocs.urls),
                'extracted_emails': len(iocs.emails),
                'detected_frameworks': static_results.frameworks_detected
            },
            'static_analysis': {
                'file_types': dict(static_results.file_types),
                'obfuscation_techniques': static_results.obfuscation_techniques,
                'suspicious_patterns': static_results.suspicious_patterns
            },
            'iocs': {
                'domains': list(iocs.domains),
                'ips': list(iocs.ips),
                'urls': list(iocs.urls),
                'emails': list(iocs.emails),
                'suspicious_files': iocs.suspicious_files,
                'exfiltration_endpoints': list(iocs.exfiltration_endpoints),
                'c2_servers': list(iocs.c2_servers)
            }
        }
        
        if dynamic_results:
            report_data['dynamic_analysis'] = dynamic_results
            
        if full_report:
            report_data['file_hashes'] = iocs.file_hashes
            
        return report_data

    def _calculate_risk_score(
        self,
        static_results: StaticAnalysisResult,
        iocs: IOCResult
    ) -> int:
        """Calculates a risk score based on the analysis results."""
        score = 0
        
        # Points for obfuscation techniques
        score += len(static_results.obfuscation_techniques) * 10
        
        # Points for suspicious patterns
        score += len(static_results.suspicious_patterns) * 15
        
        # Points for IOCs
        score += len(iocs.c2_servers) * 20
        score += len(iocs.exfiltration_endpoints) * 15
        score += len(iocs.suspicious_files) * 10
        
        # Normalize score (0-100)
        return min(100, score)

    def _determine_threat_level(self, risk_score: int) -> str:
        """Determines the threat level based on the risk score."""
        thresholds = self.config.detection.score_thresholds
        
        if risk_score >= thresholds['high']:
            return 'CRITICAL'
        elif risk_score >= thresholds['medium']:
            return 'HIGH'
        elif risk_score >= thresholds['low']:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _format_size(self, size_in_bytes: int) -> str:
        """Formats a size in bytes into a human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_in_bytes < 1024:
                return f"{size_in_bytes:.2f} {unit}"
            size_in_bytes /= 1024
        return f"{size_in_bytes:.2f} TB"

    def _generate_json_report(self, data: Dict[str, Any], output_path: Path) -> None:
        """Generates a report in JSON format."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False, cls=YaraJSONEncoder)
            self.logger.info(f"JSON report generated: {output_path}")
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")
            raise

    def _generate_html_report(self, data: Dict[str, Any], output_path: Path) -> None:
        """Generates a report in HTML format."""
        try:
            template = self.env.get_template('report.html')
            html_content = template.render(**data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.logger.info(f"HTML report generated: {output_path}")
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            raise

    def _generate_pdf_report(self, data: Dict[str, Any], output_path: Path) -> None:
        """Generates a report in PDF format."""
        try:
            # Check for wkhtmltopdf
            import subprocess
            try:
                subprocess.run(['wkhtmltopdf', '-V'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                self.logger.error(
                    "wkhtmltopdf is not installed. Required installation:\n"
                    "On Ubuntu/Debian: sudo apt-get install wkhtmltopdf\n"
                    "On Windows: Download and install from https://wkhtmltopdf.org/downloads.html"
                )
                return

            # Generate intermediate HTML
            template = self.env.get_template('report.html')
            html_content = template.render(**data)
            
            # Configure pdfkit
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': 'UTF-8',
                'no-outline': None
            }
            
            # Convert to PDF
            import pdfkit
            pdfkit.from_string(html_content, str(output_path), options=options)
            self.logger.info(f"PDF report generated: {output_path}")
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
            # Do not raise the exception to allow generation of other formats 