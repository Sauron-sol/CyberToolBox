# PhishingKit Analyzer 🎣

An advanced automated phishing kit analysis tool designed for cybersecurity professionals.

## Main Features

- 🔍 **Static Analysis**
  - Extraction of URLs, domains, and email addresses
  - Detection of obfuscation techniques
  - Identification of web frameworks used
  - Analysis of malicious code patterns

- 📦 **Dynamic Analysis**
  - Simulation of execution in a sandbox environment
  - Capture of network requests
  - System modification monitoring
  - Detection of anti-analysis mechanisms

- 🗃️ **IOC Management**
  - Automatic extraction of indicators
  - Classification by threat type
  - Export to MISP format
  - Integration with threat intelligence platforms

- 🚀 **Reporting**
  - Generation of detailed reports (PDF/HTML)
  - Data visualization
  - Danger score calculation
  - Mitigation recommendations

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/PhishingKitAnalyzer.git
cd PhishingKitAnalyzer

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Configuration

1. Create your environment file for API keys and sensitive information:
```bash
cp .env.example .env
```

2. Configure your environment variables in the `.env` file:
- `VIRUSTOTAL_API_KEY` : Your VirusTotal API key
- `URLSCAN_API_KEY` : Your URLScan API key
- `THREATFOX_API_KEY` : Your ThreatFox API key
- `MISP_URL` : URL of your MISP instance
- `MISP_API_KEY` : Your MISP API key

3. Create your configuration file for the application parameters:
```bash
cp config/config.example.yml config/config.yml
```

4. Adjust the application parameters in `config/config.yml` as needed:
- Log levels
- Enabled analysis modules
- Report configuration
- API parameters

⚠️ IMPORTANT: Never commit the files `.env` and `config/config.yml` as they contain sensitive information!

## Usage

### Command-Line Interface

```bash
# Basic analysis of a kit
python src/main.py analyze --path /path/to/kit

# Full analysis with report
python src/main.py analyze --path /path/to/kit --full-report

# Batch mode for multiple kits
python src/main.py batch --directory /path/to/directory
```

### REST API

```bash
# Start the API server
python src/api.py
```

## Project Structure

```
PhishingKitAnalyzer/
├── src/
│   ├── analyzers/        # Analysis modules
│   ├── extractors/       # IOC extractors
│   ├── sandbox/          # Analysis environment
│   ├── reporting/        # Report generation
│   └── api/             # REST API
├── tests/               # Unit tests
├── data/               # Data and models
├── config/             # Configuration files
└── docs/              # Documentation
```

## Security

To report a security vulnerability, please contact us directly rather than opening a public ticket.
