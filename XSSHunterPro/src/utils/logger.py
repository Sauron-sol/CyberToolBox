#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import logging.handlers
from pathlib import Path
from typing import Dict, Any

def setup_logging(config: Dict[str, Any], verbose: bool = False) -> None:
    """
    Configure the logging system.
    
    Args:
        config: Logging configuration
        verbose: Enable verbose mode
    """
    # Create the log directory if necessary
    log_file = Path(config.get("file", "logs/xsshunterpro.log"))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Log level
    log_level = logging.DEBUG if verbose else getattr(logging, config.get("level", "INFO"))
    
    # Format
    log_format = config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    # Basic configuration
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            # Handler for the console
            logging.StreamHandler(),
            
            # Handler for the file with rotation
            logging.handlers.RotatingFileHandler(
                filename=str(log_file),
                maxBytes=config.get("max_size", 10485760),  # 10MB by default
                backupCount=config.get("backup_count", 5),
                encoding="utf-8"
            )
        ]
    )
    
    # Reduce the log level for certain noisy modules
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("chardet").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING) 