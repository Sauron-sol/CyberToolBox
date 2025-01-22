#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class XSSHunterError(Exception):
    """Base class for XSS Hunter Pro exceptions."""
    pass

class ConfigError(XSSHunterError):
    """Error related to the configuration."""
    pass

class ScannerException(XSSHunterError):
    """Error during the scan."""
    pass

class PayloadError(XSSHunterError):
    """Error related to the payloads."""
    pass

class ReportingError(XSSHunterError):
    """Error during report generation."""
    pass 