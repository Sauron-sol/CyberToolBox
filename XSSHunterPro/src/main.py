#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

# Modification des imports pour utiliser les chemins relatifs
from src.core.config import load_config
from src.core.scanner import Scanner
from src.core.reporting import ReportGenerator
from src.utils.logger import setup_logging

async def main():
    parser = argparse.ArgumentParser(description="XSS Hunter Pro - Advanced XSS Detection Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Commande scan
    scan_parser = subparsers.add_parser("scan", help="Scan a URL or a list of URLs")
    scan_parser.add_argument("--url", help="URL to scan")
    scan_parser.add_argument("--file", help="File containing the URLs to scan")
    scan_parser.add_argument("--config", default="config/config.yml", help="Path to the configuration file")
    scan_parser.add_argument("--output", default="reports", help="Output directory for the reports")
    scan_parser.add_argument("--full-report", action="store_true", help="Generate a detailed report")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        logging.error(f"Error loading the configuration: {e}")
        sys.exit(1)
    
    # Setup logging
    setup_logging(config["logging"], args.verbose)
    
    if args.command == "scan":
        # Initialize scanner
        scanner = Scanner(config["scanner"])
        report_gen = ReportGenerator(config["reporting"])
        
        try:
            if args.url:
                # Single URL scan
                logging.info(f"Starting the scan of {args.url}")
                results = await scanner.scan_url(args.url)
                
                # Display a summary of the results
                print("\n=== Scan Results ===")
                print(f"Scanned URL: {args.url}")
                print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
                print(f"Forms analyzed: {len(results['forms'])}")
                
                if results['vulnerabilities']:
                    print("\nDetected vulnerabilities:")
                    for vuln in results['vulnerabilities']:
                        print(f"\n- Type: {vuln['type']}")
                        print(f"  Confidence: {vuln['confidence']}")
                        if 'parameter' in vuln:
                            print(f"  Parameter: {vuln['parameter']}")
                        if 'payload' in vuln:
                            print(f"  Payload: {vuln['payload']}")
                        if 'description' in vuln:
                            print(f"  Description: {vuln['description']}")
                
                if args.full_report:
                    report_path = report_gen.generate_report(results, args.output)
                    print(f"\nFull report generated in: {report_path}")
                
            elif args.file:
                # Batch scan from file
                with open(args.file) as f:
                    urls = [line.strip() for line in f if line.strip()]
                logging.info(f"Starting the batch scan of {len(urls)} URLs")
                results = await scanner.scan_urls(urls)
                
                # Display a summary of the batch results
                print("\n=== Batch Scan Results ===")
                print(f"Scanned URLs: {len(urls)}")
                
                total_vulns = sum(len(r['vulnerabilities']) for r in results if isinstance(r, dict))
                print(f"Total vulnerabilities found: {total_vulns}")
                
                if args.full_report:
                    report_path = report_gen.generate_batch_report(results, args.output)
                    print(f"\nFull batch report generated in: {report_path}")
            
            else:
                scan_parser.print_help()
                sys.exit(1)
                
        except Exception as e:
            logging.error(f"Error during the scan: {e}")
            sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Scan interrupted by the user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)