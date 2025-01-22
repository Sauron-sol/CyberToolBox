"""
Analyzer module for PhishingKit Analyzer.
"""

from .static_analyzer import StaticAnalyzer
from .dynamic_analyzer import DynamicAnalyzer

__all__ = ['StaticAnalyzer', 'DynamicAnalyzer'] 