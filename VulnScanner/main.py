from src.core.enhanced_report import EnhancedReportGenerator
from src.core.web_scanner import WebVulnScanner
from src.core.nuclei_scanner import NucleiScanner
from src.core.network_mapper import NetworkMapper
from src.core.vulnerability_detector import VulnerabilityDetector
from src.core.config import LOG_FORMAT, LOG_LEVEL, DEFAULT_PORT_RANGE
import logging
import argparse
import sys

def main():
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format=LOG_FORMAT
    )
    logger = logging.getLogger(__name__)

    # Parse arguments
    parser = argparse.ArgumentParser(description='VulnScanner - A comprehensive security scanner')
    parser.add_argument('target', help='Target to scan (IP, domain, or URL)')
    parser.add_argument('--web', action='store_true', help='Run web vulnerability scan')
    parser.add_argument('--network', help='Network range to scan (CIDR notation)')
    parser.add_argument('--deep', action='store_true', help='Perform deep analysis')
    parser.add_argument('--nuclei', action='store_true', help='Run Nuclei scan')
    parser.add_argument('--ports', default=DEFAULT_PORT_RANGE, help=f'Port range to scan (default: {DEFAULT_PORT_RANGE})')
    args = parser.parse_args()

    results = {}
    
    try:
        # Network Mapping
        if args.network:
            logger.info("Starting network mapping...")
            network_mapper = NetworkMapper()
            results["network_scan"] = network_mapper.scan_network(args.network)

        # Web Vulnerability Scan
        if args.web:
            logger.info("Starting web vulnerability scan...")
            web_scanner = WebVulnScanner()
            results["web_scan"] = web_scanner.scan(args.target, deep=args.deep)

        # Nuclei Scan
        if args.nuclei:
            logger.info("Starting Nuclei scan...")
            nuclei_scanner = NucleiScanner()
            results["nuclei_scan"] = nuclei_scanner.run_scan(args.target)

        # Generate enhanced report
        report_generator = EnhancedReportGenerator()
        report_paths = report_generator.generate(args.target, results)
        
        if report_paths:
            logger.info("\n=== Report Generation ===")
            for report_type, path in report_paths.items():
                if path:
                    logger.info(f"{report_type.upper()} report: {path}")

    except Exception as e:
        logger.error(f"Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
