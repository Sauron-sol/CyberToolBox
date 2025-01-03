# VulnScanner

A modular vulnerability scanner built in Python that combines port analysis, web vulnerability assessment, API analysis, and advanced reporting capabilities.

## Features

- **Port Scan**
  - TCP scan using Nmap
  - Service version detection
  - Customizable port range specification

- **Web Vulnerability Scanner**
  - Analysis and testing of forms
  - Verification of security headers
  - XSS detection
  - SQL injection testing
  - Server information collection
  - Configuration analysis

- **Advanced Web Crawling & Scanning**
  - Katana integration for deep crawling
  - JavaScript analysis
  - Dynamic content discovery
  - Automated form testing
  - Rate-limited scanning

- **Nuclei Integration**
  - Comprehensive template scanning
  - CVE detection
  - Configuration analysis
  - DAST capabilities
  - Custom template support
  - Integration with Katana crawler

- **Advanced Reporting**
  - Interactive HTML reports
  - CSV export
  - Severity-based categorization
  - Visual representations
  - Detailed vulnerability descriptions
  - Remediation recommendations

## Prerequisites

- Python 3.11+
- Nmap
- Nuclei
- Katana
- Python dependencies (see requirements.txt)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/VulnScanner.git
cd VulnScanner

# Install Python dependencies
pip install -r requirements.txt

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Update Nuclei templates
nuclei -update-templates
```

## Configuration

The scanner can be configured by modifying `src/core/config.py`. Key settings include:
- Scanning parameters (ports, timeouts, threads)
- Web crawler settings
- Nuclei and Katana configurations
- Report generation options

## Usage

### Basic Scan
```bash
sudo python main.py example.com
```

### Web and Nuclei Scan with Crawling
```bash
sudo python main.py example.com --web --nuclei
```

### Available Options
- `--web` : Enables web vulnerability scan
- `--nuclei` : Launches Nuclei scan (includes Katana crawling)
- `--deep` : Performs deep analysis
- `--network` : Specifies network range to scan
- `--ports` : Specifies port range (default: 1-1000)

## Output

Reports are generated in the `reports/` directory:
- HTML report with interactive elements
- CSV export of findings
- Crawl results in `crawl_results/`

## Security Note

This tool is intended for authorized security testing only. Ensure you have permission to scan target systems.

