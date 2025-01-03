"""Configuration settings for VulnScanner"""

# Scanning configurations
DEFAULT_PORT_RANGE = "1-1000"
DEFAULT_TIMEOUT = 30
MAX_THREADS = 10

# Web scanning settings
USER_AGENT = "VulnScanner/1.0"
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Report settings
REPORT_DIR = "reports"
CRAWL_DIR = "crawl_results"

# Logging settings
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"

# Nuclei settings
NUCLEI_TEMPLATES = [
    "cves",
    "vulnerabilities",
    "exposures",
    "misconfiguration",
    "default-logins",
    "takeovers",
    "file",
    "technologies"
]

# Katana settings
KATANA_OPTIONS = {
    "depth": 5,
    "rate_limit": 500,
    "parallelism": 500,
    "concurrency": 500
} 