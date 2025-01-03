import jinja2
import os
import csv
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import base64
import io
import logging
from .config import REPORT_DIR, LOG_FORMAT

class EnhancedReportGenerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.output_dir = REPORT_DIR
        self.risk_weights = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 2,
            'info': 1
        }

    def calculate_risk_score(self, results: dict) -> float:
        """Calculate overall risk score"""
        total_score = 0
        max_score = 0
        
        # Nuclei findings
        if 'nuclei_scan' in results:
            for vuln in results['nuclei_scan'].get('vulnerabilities', []):
                severity = vuln.get('severity', '').lower()
                total_score += self.risk_weights.get(severity, 0)
                max_score += 10  # Maximum possible score per finding

        # Web vulnerabilities
        if 'web_scan' in results:
            for header in results['web_scan'].get('security_headers', {}).values():
                if header == 'Missing':
                    total_score += self.risk_weights['medium']
                    max_score += 10

        # Return normalized score (0-100)
        return (total_score / max_score * 100) if max_score > 0 else 0

    def generate_charts(self, results: dict) -> dict:
        """Generate visualization charts"""
        charts = {}
        
        try:
            # Severity Distribution Pie Chart
            plt.figure(figsize=(8, 8))
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            
            # Count vulnerabilities
            if 'nuclei_scan' in results:
                for vuln in results['nuclei_scan'].get('vulnerabilities', []):
                    severity = vuln.get('severity', 'Info').capitalize()
                    severity_counts[severity] += 1

            # Only create pie chart if we have findings
            if sum(severity_counts.values()) > 0:
                plt.pie(severity_counts.values(), labels=severity_counts.keys(), autopct='%1.1f%%')
                plt.title('Vulnerability Severity Distribution')
            else:
                plt.text(0.5, 0.5, 'No vulnerabilities found', horizontalalignment='center')
                plt.axis('off')
            
            # Save to base64
            buf = io.BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            charts['severity_dist'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close()

        except Exception as e:
            self.logger.error(f"Error generating charts: {e}")
            charts['severity_dist'] = ''

        return charts

    def prioritize_vulnerabilities(self, results: dict) -> list:
        """Prioritize vulnerabilities based on severity and impact"""
        prioritized = []
        
        if 'nuclei_scan' in results:
            for vuln in results['nuclei_scan'].get('vulnerabilities', []):
                priority_score = self.risk_weights.get(vuln['severity'].lower(), 0)
                prioritized.append({
                    'name': vuln['name'],
                    'severity': vuln['severity'],
                    'priority_score': priority_score,
                    'recommendation': self.get_recommendation(vuln)
                })
        
        return sorted(prioritized, key=lambda x: x['priority_score'], reverse=True)

    def get_recommendation(self, vulnerability: dict) -> str:
        """Generate recommendation based on vulnerability type"""
        recommendations = {
            'sqli': 'Implement prepared statements and input validation',
            'xss': 'Implement content security policy and output encoding',
            'rce': 'Review and restrict command execution, implement strict input validation',
            'lfi': 'Implement proper file access controls and input validation',
            # ... autres recommandations ...
        }
        
        for tag in vulnerability.get('tags', []):
            if tag.lower() in recommendations:
                return recommendations[tag.lower()]
        
        return 'Review and patch the vulnerability following security best practices'

    def generate(self, target: str, results: dict) -> dict:
        """Generate enhanced reports in multiple formats"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"scan_report_{target.replace(':', '_')}_{timestamp}"
            report_paths = {}

            # Calculate risk score
            risk_score = self.calculate_risk_score(results)
            
            # Generate charts
            charts = self.generate_charts(results)
            
            # Prioritize vulnerabilities
            prioritized_vulns = self.prioritize_vulnerabilities(results)

            # Generate HTML report
            html_path = os.path.join(self.output_dir, f"{base_filename}.html")
            self._generate_html(html_path, target, results, risk_score, charts, prioritized_vulns)
            report_paths['html'] = html_path

            # Generate CSV summary
            csv_path = os.path.join(self.output_dir, f"{base_filename}.csv")
            self._generate_csv(csv_path, results, prioritized_vulns)
            report_paths['csv'] = csv_path

            self.logger.info(f"Reports generated successfully:")
            self.logger.info(f"HTML report: {html_path}")
            self.logger.info(f"CSV report: {csv_path}")

            return report_paths

        except Exception as e:
            self.logger.error(f"Error generating enhanced report: {e}")
            return None

    def _generate_html(self, html_path: str, target: str, results: dict, risk_score: float, charts: dict, prioritized_vulns: list):
        """Generate HTML report"""
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {{ timestamp }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
                .vulnerability { color: #d63031; }
                .safe { color: #00b894; }
                .warning { color: #fdcb6e; }
                .header { background: #2d3436; color: white; padding: 20px; border-radius: 5px; }
                .risk-score { font-size: 24px; font-weight: bold; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
                th { background: #f5f6fa; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Security Scan Report</h1>
                    <p>Target: {{ target }}</p>
                    <p>Scan Date: {{ timestamp }}</p>
                    <p class="risk-score">Risk Score: {{ "%.1f"|format(risk_score) }}/100</p>
                </div>

                <div class="section">
                    <h2>Executive Summary</h2>
                    <p>Total vulnerabilities found: {{ results.nuclei_scan.total_findings }}</p>
                    <p>Risk Level: {{ "High" if risk_score > 70 else "Medium" if risk_score > 40 else "Low" }}</p>
                    {% if charts.severity_dist %}
                    <img src="data:image/png;base64,{{ charts.severity_dist }}" alt="Severity Distribution">
                    {% endif %}
                </div>

                {% if prioritized_vulns %}
                <div class="section">
                    <h2>Priority Vulnerabilities</h2>
                    <table>
                        <tr>
                            <th>Vulnerability</th>
                            <th>Severity</th>
                            <th>Recommendation</th>
                        </tr>
                        {% for vuln in prioritized_vulns %}
                        <tr>
                            <td>{{ vuln.name }}</td>
                            <td class="{{ 'vulnerability' if vuln.severity in ['critical', 'high'] else 'warning' }}">
                                {{ vuln.severity }}
                            </td>
                            <td>{{ vuln.recommendation }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                {% endif %}

                {% if results.nuclei_scan %}
                <div class="section">
                    <h2>Nuclei Scan Results</h2>
                    {% if results.nuclei_scan.vulnerabilities %}
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Severity</th>
                            <th>Description</th>
                        </tr>
                        {% for vuln in results.nuclei_scan.vulnerabilities %}
                        <tr>
                            <td>{{ vuln.name }}</td>
                            <td>{{ vuln.severity }}</td>
                            <td>{{ vuln.description }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% else %}
                    <p class="safe">No critical vulnerabilities found</p>
                    {% endif %}
                </div>
                {% endif %}

                {% if results.nuclei_scan and results.nuclei_scan.crawl_info %}
                <div class="section">
                    <h2>Crawling Results</h2>
                    <p>URLs discovered: {{ results.nuclei_scan.crawl_info.urls_discovered }}</p>
                    <p>Crawl results file: {{ results.nuclei_scan.crawl_info.crawl_file }}</p>
                </div>
                {% endif %}
            </div>
        </body>
        </html>
        """
        
        try:
            template = jinja2.Template(template)
            html = template.render(
                target=target,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                results=results,
                risk_score=risk_score,
                charts=charts,
                prioritized_vulns=prioritized_vulns
            )
            
            with open(html_path, 'w') as f:
                f.write(html)
                
        except Exception as e:
            self.logger.error(f"Error generating HTML: {e}")
            raise 

    def _generate_csv(self, csv_path: str, results: dict, prioritized_vulns: list):
        """Generate CSV summary"""
        try:
            with open(csv_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Type', 'Name', 'Severity', 'Description'])
                
                # Write Nuclei findings
                if 'nuclei_scan' in results:
                    for vuln in results['nuclei_scan'].get('vulnerabilities', []):
                        writer.writerow([
                            'Nuclei',
                            vuln.get('name', 'Unknown'),
                            vuln.get('severity', 'Unknown'),
                            vuln.get('description', 'No description')
                        ])

                # Write other findings if available
                if 'web_scan' in results:
                    for header, status in results['web_scan'].get('security_headers', {}).items():
                        if status == 'Missing':
                            writer.writerow([
                                'Security Header',
                                header,
                                'Medium',
                                'Missing security header'
                            ])

        except Exception as e:
            self.logger.error(f"Error generating CSV: {e}")
            raise 