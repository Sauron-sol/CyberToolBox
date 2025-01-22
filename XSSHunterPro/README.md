# XSS Hunter Pro 🕷️

An advanced framework for the automated detection and analysis of XSS (Cross-Site Scripting) vulnerabilities.

## Main Features

- 🔍 **Advanced Detection**
  - Support for modern XSS payloads
  - Detection of WAFs and bypasses
  - Customizable and parameterizable tests
  - Contextual analysis of the DOM

- 🚀 **Automation**
  - Parallel testing
  - Automated reports
  - Real-time vulnerability detection
  - Support for asynchronous testing

- 📦 **Reporting**
  - Detailed reports (HTML/PDF/JSON)
  - Data visualization
  - Distribution graphs of vulnerabilities
  - Risk level assessment

- 🛡️ **Security**
  - Secure payload management
  - Input validation
  - Protection against false positives
  - Non-intrusive tests

## Prerequisites

- Python 3.9+
- wkhtmltopdf (for PDF generation)
- Modern web browser

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/XSSHunterPro.git
cd XSSHunterPro
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

1. Copy the example configuration file:
```bash
cp config/config.example.yml config/config.yml
```

2. Modify the parameters in `config.yml` as needed:
- Scan parameters
- Report configuration
- Custom payloads

## Usage

### Simple Scan
```bash
python src/main.py scan --url https://example.com
```

### Scan with Full Report
```bash
python src/main.py scan --url https://example.com --full-report
```

### Multiple Scan (Batch Mode)
```bash
python src/main.py batch --file urls.txt
```

## Tests

Run unit tests:
```bash
pytest tests/ -v --cov=src --cov-report=html
```

## Project Structure
```
XSSHunterPro/
├── src/
│   ├── core/           # Main engine
│   ├── utils/          # Utilities
│   └── templates/      # Report templates
├── tests/
│   └── unit/          # Unit tests
├── config/            # Configuration
├── reports/          # Generated reports
└── docs/            # Documentation
```

## Security

⚠️ **Important Warnings** :

1. This project is intended ONLY for legitimate security testing.
2. ALWAYS obtain permission before scanning a website.
3. DO NOT store sensitive data in reports.
4. Use an isolated environment for testing.

## Best Practices

1. Always use the latest version of the framework
2. Configure timeouts and limits correctly
3. Verify reports for false positives
4. Follow local security policies

## Disclaimer

The authors are not responsible for the misuse of this tool. 
Use it ethically and legally only. 