#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from pathlib import Path
from typing import Dict, Any

import yaml

def load_config(config_path: str = None) -> Dict[str, Any]:
    """
    Loads the configuration from the YAML file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dict containing the configuration
    """
    if config_path is None:
        config_path = os.getenv("CONFIG_PATH", "config/config.yml")
        
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file {config_path} does not exist")
        
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            
        # Basic validation
        required_sections = ["app", "security", "database", "scanner", "reporting"]
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Section '{section}' missing in the configuration")
                
        return config
        
    except yaml.YAMLError as e:
        raise ValueError(f"YAML file parsing error: {e}")
    except Exception as e:
        raise Exception(f"Error loading the configuration: {e}") 