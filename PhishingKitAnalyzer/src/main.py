#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.logging import RichHandler

from analyzers.static_analyzer import StaticAnalyzer
from analyzers.dynamic_analyzer import DynamicAnalyzer
from extractors.ioc_extractor import IOCExtractor
from reporting.report_generator import ReportGenerator
from utils.config import Config, GeneralConfig, AnalysisConfig, StaticAnalysisConfig, DynamicAnalysisConfig, DatabaseConfig, ReportingConfig, APIConfig, MISPConfig, DetectionConfig
from utils.exceptions import PhishingKitAnalyzerError

console = Console()

def setup_logging(debug: bool = False) -> None:
    """Sets up the logging system."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )

def load_config(config_path: str) -> Config:
    """Loads the configuration from the YAML file."""
    try:
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
            
        # Constructing configuration objects
        general_config = GeneralConfig(**data['general'])
        static_config = StaticAnalysisConfig(**data['analysis']['static'])
        dynamic_config = DynamicAnalysisConfig(**data['analysis']['dynamic'])
        
        analysis_config = AnalysisConfig(
            timeout=data['analysis']['timeout'],
            enabled_modules=data['analysis']['enabled_modules'],
            static=static_config,
            dynamic=dynamic_config
        )
        
        database_config = DatabaseConfig(**data['database'])
        reporting_config = ReportingConfig(**data['reporting'])
        api_config = APIConfig(**data['api'])
        misp_config = MISPConfig(**data['misp'])
        detection_config = DetectionConfig(**data['detection'])
        
        return Config(
            version=data['version'],
            general=general_config,
            analysis=analysis_config,
            api_keys=data['api_keys'],
            database=database_config,
            reporting=reporting_config,
            api=api_config,
            misp=misp_config,
            detection=detection_config
        )
    except Exception as e:
        raise PhishingKitAnalyzerError(f"Error loading configuration: {str(e)}")

def analyze_kit(path: Path, config: Config, full_report: bool = False) -> None:
    """Analyzes a phishing kit."""
    try:
        # Static analysis
        static_analyzer = StaticAnalyzer(config)
        static_results = static_analyzer.analyze(path)
        
        # IOC extraction
        ioc_extractor = IOCExtractor(config)
        iocs = ioc_extractor.extract(static_results)
        
        # Dynamic analysis if enabled
        dynamic_results = None
        if "dynamic_analysis" in config.analysis.enabled_modules:
            dynamic_analyzer = DynamicAnalyzer(config)
            dynamic_results = dynamic_analyzer.analyze(path)
        
        # Report generation
        report_generator = ReportGenerator(config)
        report_generator.generate(
            path=path,
            static_results=static_results,
            dynamic_results=dynamic_results,
            iocs=iocs,
            full_report=full_report
        )
        
    except PhishingKitAnalyzerError as e:
        console.print(f"[red]Analysis error: {str(e)}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
        logging.exception("Unexpected error during analysis")
        sys.exit(1)

def batch_analyze(directory: Path, config: Config) -> None:
    """Analyzes all kits in a directory."""
    try:
        for item in directory.iterdir():
            if item.is_file():
                console.print(f"\n[yellow]Analyzing {item}...[/yellow]")
                analyze_kit(item, config)
    except Exception as e:
        console.print(f"[red]Batch analysis error: {str(e)}[/red]")
        sys.exit(1)

def main() -> None:
    """Main entry point of the program."""
    parser = argparse.ArgumentParser(
        description="PhishingKit Analyzer - Automated phishing kit analysis tool"
    )
    
    parser.add_argument(
        "--config",
        default="config/config.yml",
        help="Path to the configuration file"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a phishing kit")
    analyze_parser.add_argument("--path", required=True, help="Path to the kit to analyze")
    analyze_parser.add_argument("--full-report", action="store_true", help="Generate a full report")
    
    # Batch command
    batch_parser = subparsers.add_parser("batch", help="Analyze multiple kits")
    batch_parser.add_argument("--directory", required=True, help="Directory containing the kits")
    
    args = parser.parse_args()
    
    try:
        config = load_config(args.config)
        setup_logging(config.general.debug)
        
        if args.command == "analyze":
            analyze_kit(Path(args.path), config, args.full_report)
        elif args.command == "batch":
            batch_analyze(Path(args.directory), config)
        else:
            parser.print_help()
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Fatal error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main() 