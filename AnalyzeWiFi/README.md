# Analyze WiFi 📡

A cross-platform tool to analyze the security of surrounding WiFi networks.

## Main Features

- 🔍 Scan available WiFi networks
- 🛡️ Network security analysis
- 📊 Detailed report generation
- 🔄 Cross-platform support (Windows/Linux/MacOS)
- 📡 Channel and signal analysis
- 🚨 Vulnerable network detection

## Prerequisites

- Python 3.6+
- Administrator/root privileges for WiFi scanning
- Compatible WiFi interface
- Python dependencies (see requirements.txt)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd AnalyzeWiFi
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Check system permissions:
   - **Linux**: Run with sudo
   - **MacOS**: Allow network interface access
   - **Windows**: Run as administrator

## Usage

1. Launch the analyzer:
   ```bash
   # Linux/MacOS
   sudo python wifi_analyzer.py

   # Windows (admin cmd)
   python wifi_analyzer.py
   ```

2. The program will:
   - Scan available networks
   - Analyze their security
   - Generate a detailed report

## Analyzed Information

- 📶 Signal strength
- 🔐 Security type (WEP/WPA/WPA2/WPA3)
- 📻 Channel and frequency
- 🌐 Network information (SSID, BSSID)
- 🔍 Potential vulnerabilities
- 📊 Performance statistics

## Report Format

The generated report includes:
- System information
- List of detected networks
- Security analysis per network
- Alerts and recommendations
- Detailed statistics

## OS Compatibility

| OS      | Status | Notes |
|---------|--------|-------|
| MacOS   | ✅     | Requires system authorization |
| Linux   | ✅     | Requires sudo |
| Windows | ✅     | Requires admin rights |

## Known Limitations

- Some WiFi cards may not support all features
- In-depth analysis requires elevated privileges
- Hidden networks may not be detected
- Some features are OS-dependent

## Security

⚠️ This tool is intended for educational and testing purposes only.
Usage must comply with local laws and proper authorization.

