# Network Scanner 🔍

Advanced network scanner with graphical interface for network discovery and analysis.

## Features

- 🌐 Local network host discovery
- 🚪 Port scanning and service detection
- 📊 Interactive network mapping
- 📝 Exportable detailed reports
- 🔄 IPv4 and IPv6 support
- 🎯 Service version detection
- 🏃 Multiple scanning modes (quick, complete, stealth)

## Key Capabilities

### Scanning Options
- Quick Scan (ARP): Fast network discovery
- Complete Scan (NMAP): Detailed analysis
- Custom NMAP options support
- Configurable timeout settings

### Detection Features
- Active hosts discovery
- Open ports identification
- Service version detection
- OS fingerprinting
- Network topology mapping

### User Interface
- Clean and intuitive GUI
- Real-time scan progress
- Detailed results view
- Export functionality
- Emergency stop capability

## Requirements

### Windows
- Python 3.8+
- NMAP (optional but recommended)
- Administrator privileges
- WinPcap or Npcap installed

### Linux
- Python 3.8+
- NMAP (optional but recommended)
- Root/sudo privileges
- libpcap installed

### MacOS
- Python 3.8+
- NMAP (optional but recommended)
- Administrator privileges
- libpcap (pre-installed)

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/network-scanner.git
```

2. Navigate to the project directory:
```
cd network-scanner
```

3. Install the required dependencies:
```
pip install -r requirements.txt
```

4. Run the application:
```
python main.py
```

## Usage

### Quick Scan
To perform a quick scan, select the "Quick Scan" option from the main menu. This will perform a fast ARP scan to discover active hosts on the local network.

### Complete Scan
To perform a complete scan, select the "Complete Scan" option from the main menu. This will use NMAP to perform a detailed analysis of the network, including open ports and service detection.

### Custom Scan
To perform a custom scan, select the "Custom Scan" option from the main menu. You can specify custom NMAP options for a tailored network scan.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgements

- NMAP: https://nmap.org/
- WinPcap: https://www.winpcap.org/
- Npcap: https://nmap.org/npcap/
- libpcap: https://www.tcpdump.org/
