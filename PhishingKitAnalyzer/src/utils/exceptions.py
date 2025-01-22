class PhishingKitAnalyzerError(Exception):
    """Base exception for PhishingKit Analyzer errors."""
    pass

class ConfigurationError(PhishingKitAnalyzerError):
    """Exception raised for configuration errors."""
    pass

class AnalysisError(PhishingKitAnalyzerError):
    """Exception raised for errors during analysis."""
    pass

class FileError(PhishingKitAnalyzerError):
    """Exception raised for file-related errors."""
    pass

class YaraError(PhishingKitAnalyzerError):
    """Exception raised for YARA-related errors."""
    pass

class ReportingError(PhishingKitAnalyzerError):
    """Exception raised for report generation errors."""
    pass

class ExtractionError(PhishingKitAnalyzerError):
    """Exception raised for IOC extraction errors."""
    pass

class APIError(PhishingKitAnalyzerError):
    """Exception raised for external API errors."""
    pass

class ValidationError(PhishingKitAnalyzerError):
    """Exception raised for validation errors."""
    pass

class DatabaseError(PhishingKitAnalyzerError):
    """Exception raised for database errors."""
    pass 