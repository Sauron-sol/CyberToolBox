import subprocess
import json
import logging
from typing import Dict, List
import os
import tempfile
from datetime import datetime
from .config import NUCLEI_TEMPLATES, KATANA_OPTIONS, CRAWL_DIR

class NucleiScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.output_dir = "crawl_results"

    def check_nuclei_installation(self) -> bool:
        """Check if nuclei is installed"""
        try:
            process = subprocess.run(['nuclei', '-version'], capture_output=True, text=True)
            if process.returncode == 0:
                self.logger.info(f"Nuclei version: {process.stdout.strip()}")
                return True
            return False
        except FileNotFoundError:
            self.logger.error("Nuclei not found. Please install it first:")
            self.logger.error("Linux: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            self.logger.error("MacOS: brew install nuclei")
            return False

    def check_katana_installation(self) -> bool:
        """Check if katana is installed"""
        try:
            process = subprocess.run(['katana', '-version'], capture_output=True, text=True)
            if process.returncode == 0:
                self.logger.info(f"Katana version: {process.stdout.strip()}")
                return True
            return False
        except FileNotFoundError:
            self.logger.error("Katana not found. Please install it:")
            self.logger.error("go install github.com/projectdiscovery/katana/cmd/katana@latest")
            return False

    def run_katana_crawl(self, target: str) -> List[str]:
        """Run katana crawler and return discovered URLs"""
        if not self.check_katana_installation():
            return []

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.output_dir, f"katana_crawl_{timestamp}.txt")

            # Configuration Katana avancée
            cmd = [
                'katana',
                '-u', target,
                '-js-crawl',
                '-jsluice',
                '-silent',
                '-depth', '5',
                '-rate-limit', '500',
                '-parallelism', '500',
                '-concurrency', '500',
                '-o', output_file,
                '-field', 'url'  # Pour ne récupérer que les URLs
            ]

            self.logger.info("Starting Katana crawl...")
            process = subprocess.run(cmd, capture_output=True, text=True)

            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Katana discovered {len(urls)} URLs")
                return urls
            return []

        except Exception as e:
            self.logger.error(f"Katana crawl error: {e}")
            return []

    def run_scan(self, target: str) -> Dict:
        """Run nuclei scan with comprehensive options"""
        results = {
            "vulnerabilities": [],
            "info_findings": [],
            "total_findings": 0,
            "crawl_info": {
                "urls_discovered": 0,
                "crawl_file": None
            },
            "error": None
        }

        try:
            # Format target URL if needed
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"

            # Run Katana first
            discovered_urls = self.run_katana_crawl(target)
            targets_file = None
            
            if discovered_urls:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                targets_file = os.path.join(self.output_dir, f"katana_targets_{timestamp}.txt")
                with open(targets_file, 'w') as f:
                    f.write('\n'.join(discovered_urls))
                results["crawl_info"]["urls_discovered"] = len(discovered_urls)
                results["crawl_info"]["crawl_file"] = targets_file

            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
                # Nuclei command with JSON output
                base_cmd = [
                    'nuclei',
                    '-jsonl',  # Force JSON output
                    '-o', tmp_file.name,
                    '-silent',
                    '-severity', 'critical,high,medium,low,info',
                    '-dast'
                ]

                # Add target based on Katana results
                if targets_file:
                    base_cmd.extend(['-list', targets_file])
                else:
                    base_cmd.extend(['-target', target])

                self.logger.info(f"Running Nuclei scan with command: {' '.join(base_cmd)}")
                process = subprocess.run(base_cmd, capture_output=True, text=True)

                # Parse results from the output file
                if os.path.exists(tmp_file.name) and os.path.getsize(tmp_file.name) > 0:
                    with open(tmp_file.name, 'r') as f:
                        for line in f:
                            try:
                                if line.strip():
                                    finding = json.loads(line)
                                    if finding.get('type') == 'http':  # Ensure it's an HTTP finding
                                        finding_data = {
                                            "name": finding.get('template-id', ''),
                                            "severity": finding.get('info', {}).get('severity', 'unknown'),
                                            "url": finding.get('matched-at', ''),
                                            "template": finding.get('template-id', ''),
                                            "tags": finding.get('info', {}).get('tags', []),
                                            "description": finding.get('info', {}).get('description', ''),
                                            "matcher_name": finding.get('matcher-name', ''),
                                            "extracted_results": finding.get('extracted-results', []),
                                            "curl_command": finding.get('curl-command', '')
                                        }

                                        if finding_data['severity'].lower() in ['critical', 'high', 'medium']:
                                            results["vulnerabilities"].append(finding_data)
                                        else:
                                            results["info_findings"].append(finding_data)

                            except json.JSONDecodeError as e:
                                # Si la ligne n'est pas du JSON, essayons de parser le format texte
                                try:
                                    line = line.strip()
                                    if '[critical]' in line or '[high]' in line or '[medium]' in line:
                                        parts = line.split('] [')
                                        finding_data = {
                                            "name": parts[0].strip('['),
                                            "severity": parts[2].strip('[]'),
                                            "url": parts[3].split()[0] if len(parts) > 3 else "unknown",
                                            "description": ' '.join(parts[3].split()[1:]) if len(parts) > 3 else ""
                                        }
                                        results["vulnerabilities"].append(finding_data)
                                except Exception as parse_error:
                                    self.logger.debug(f"Could not parse line: {line}")
                                    continue

                results["total_findings"] = len(results["vulnerabilities"]) + len(results["info_findings"])

                # Cleanup
                os.unlink(tmp_file.name)

                # Log findings summary
                self.logger.info(f"Found {len(results['vulnerabilities'])} critical/high/medium vulnerabilities")
                self.logger.info(f"Found {len(results['info_findings'])} informational findings")

        except Exception as e:
            self.logger.error(f"Nuclei scan error: {e}")
            results["error"] = str(e)
            import traceback
            self.logger.error(traceback.format_exc())

        return results 