from jinja2 import Template
import os
from datetime import datetime
import json

class ReportGenerator:
    def __init__(self):
        self.template = """
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
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
        th { background: #f5f6fa; }
        .docker-container { background: #f1f2f6; padding: 10px; margin: 5px 0; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <p>Target: {{ target }}</p>
            <p>Scan Date: {{ timestamp }}</p>
        </div>

        <div class="section">
            <h2>Port Scan Results</h2>
            {% if results.port_scan.ports %}
            <table>
                <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
                {% for port in results.port_scan.ports %}
                <tr>
                    <td>{{ port.port }}</td>
                    <td>{{ port.state }}</td>
                    <td>{{ port.service }}</td>
                    <td>{{ port.version }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <p class="warning">No open ports found</p>
            {% endif %}
        </div>

        <div class="section">
            <h2>Web Vulnerabilities</h2>
            <h3>Security Headers</h3>
            <table>
                <tr><th>Header</th><th>Status</th></tr>
                {% for header, value in results.web_scan.security_headers.items() %}
                <tr>
                    <td>{{ header }}</td>
                    <td class="{{ 'vulnerability' if value == 'Missing' else 'safe' }}">{{ value }}</td>
                </tr>
                {% endfor %}
            </table>

            <h3>Server Information</h3>
            <table>
                {% for key, value in results.web_scan.server_info.items() %}
                <tr><td>{{ key }}</td><td>{{ value }}</td></tr>
                {% endfor %}
            </table>
        </div>

        {% if results.network_analysis %}
        <div class="section">
            <h2>Network Analysis</h2>
            
            <h3>Docker Containers</h3>
            {% for container in results.network_analysis.live_hosts.docker_containers %}
            <div class="docker-container">
                <strong>{{ container.name }}</strong> ({{ container.id }})<br>
                Status: {{ container.status }}<br>
                {% for network_name, network_info in container.network.items() %}
                Network: {{ network_name }}<br>
                IP: {{ network_info.IPAddress }}<br>
                {% endfor %}
            </div>
            {% endfor %}

            <h3>Network Interfaces</h3>
            <table>
                <tr><th>Interface</th><th>IP</th><th>Type</th></tr>
                {% for node in results.network_analysis.network_topology.nodes %}
                <tr>
                    <td>{{ node.name }}</td>
                    <td>{{ node.ip }}</td>
                    <td>{{ node.type }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if results.compliance %}
        <div class="section">
            <h2>Compliance Check Results</h2>
            
            <h3>Password Policy</h3>
            <div class="subsection">
                <h4>Findings:</h4>
                <ul>
                {% for finding in results.compliance.password_policy.findings %}
                    <li>{{ finding }}</li>
                {% endfor %}
                </ul>
                <h4>Recommendations:</h4>
                <ul>
                {% for rec in results.compliance.password_policy.recommendations %}
                    <li class="warning">{{ rec }}</li>
                {% endfor %}
                </ul>
            </div>

            <h3>Security Headers</h3>
            <div class="subsection">
                <h4>Missing Headers:</h4>
                <ul>
                {% for header in results.compliance.security_headers.missing_headers %}
                    <li class="vulnerability">{{ header }}</li>
                {% endfor %}
                </ul>
            </div>

            <h3>SSL/TLS Compliance</h3>
            <div class="subsection">
                <p class="{{ 'safe' if results.compliance.ssl_compliance.compliant else 'vulnerability' }}">
                    Status: {{ 'Compliant' if results.compliance.ssl_compliance.compliant else 'Non-Compliant' }}
                </p>
                {% if results.compliance.ssl_compliance.findings %}
                <ul>
                {% for finding in results.compliance.ssl_compliance.findings %}
                    <li class="vulnerability">{{ finding }}</li>
                {% endfor %}
                </ul>
                {% endif %}
            </div>

            <h3>GDPR Compliance</h3>
            <div class="subsection">
                <p class="{{ 'safe' if results.compliance.gdpr_compliance.compliant else 'vulnerability' }}">
                    Status: {{ 'Compliant' if results.compliance.gdpr_compliance.compliant else 'Non-Compliant' }}
                </p>
                {% if results.compliance.gdpr_compliance.findings %}
                <ul>
                {% for finding in results.compliance.gdpr_compliance.findings %}
                    <li class="vulnerability">{{ finding }}</li>
                {% endfor %}
                </ul>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if results.nuclei_scan %}
        <div class="section">
            <h2>Nuclei Scan Results</h2>
            
            <div class="subsection">
                <h3>Critical & High Vulnerabilities</h3>
                {% if results.nuclei_scan.vulnerabilities %}
                <table>
                    <tr>
                        <th>Name</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>Tags</th>
                    </tr>
                    {% for vuln in results.nuclei_scan.vulnerabilities %}
                    <tr class="vulnerability">
                        <td>{{ vuln.name }}</td>
                        <td>{{ vuln.severity }}</td>
                        <td>{{ vuln.description }}</td>
                        <td>{{ vuln.tags|join(', ') }}</td>
                    </tr>
                    {% endfor %}
                </table>
                {% else %}
                <p class="safe">No critical vulnerabilities found</p>
                {% endif %}
            </div>

            <div class="subsection">
                <h3>Informational Findings</h3>
                {% if results.nuclei_scan.info_findings %}
                <table>
                    <tr>
                        <th>Name</th>
                        <th>Info</th>
                    </tr>
                    {% for finding in results.nuclei_scan.info_findings %}
                    <tr>
                        <td>{{ finding.name }}</td>
                        <td>{{ finding.info }}</td>
                    </tr>
                    {% endfor %}
                </table>
                {% endif %}
            </div>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

    def generate(self, target: str, results: dict, output_dir: str = "reports"):
        """Generate HTML report from scan results"""
        try:
            # Create reports directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)

            # Clean target name for filename
            clean_target = target.replace('http://', '').replace('https://', '').replace(':', '_').replace('/', '_')
            
            # Generate report
            template = Template(self.template)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            filename = f"scan_report_{clean_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            filepath = os.path.join(output_dir, filename)

            # Ensure all required sections exist
            if "web_scan" not in results:
                results["web_scan"] = {
                    "security_headers": {},
                    "server_info": {}
                }
            
            if "port_scan" not in results:
                results["port_scan"] = {"ports": []}

            if "network_analysis" not in results:
                results["network_analysis"] = {
                    "live_hosts": {"docker_containers": []},
                    "network_topology": {"nodes": []}
                }

            html = template.render(
                target=target,
                timestamp=timestamp,
                results=results
            )

            # Create directory if it doesn't exist (double-check)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)

            return filepath

        except Exception as e:
            print(f"Error generating report: {e}")
            return None 