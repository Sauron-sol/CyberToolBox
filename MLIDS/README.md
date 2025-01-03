# MLIDS (Machine Learning Intrusion Detection System)

A machine learning-based intrusion detection system using Python to analyze network traffic in real-time.

## Features

- Real-time network packet capture
- Machine learning analysis (Isolation Forest)
- Automatic anomaly detection
- Grafana dashboard visualization
- Prometheus metrics
- Cross-platform support (Linux, macOS, Windows)

## Prerequisites

- Python 3.8+
- Wireshark/tshark
- Docker and Docker Compose (for Grafana and Prometheus)
- Administrator/root privileges

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/MLIDS.git
cd MLIDS
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Start Docker containers:
```bash
docker-compose up -d
```

## Usage

1. Launch the IDS system:
```bash
# Basic monitoring
sudo python3 main.py --interface <interface>

# Monitor specific network
sudo python3 main.py --interface <interface> --network <network_cidr>
# Example: sudo python3 main.py --interface eth0 --network 10.0.0.0/24
```

2. Access the dashboard:
- Open `http://localhost:3000` in your browser
- Login with default credentials (admin/admin)
- Navigate to the "MLIDS" dashboard

## Configuration

- Network interface: use `--interface` to specify the interface to monitor
- Network: use `--network` to specify the network to monitor
- Metrics port: use `--metrics-port` to change the metrics port (default: 8000)

### Important: Prometheus Configuration

Before starting the system, you need to update the Prometheus target in `config/prometheus.yml`:
```yaml
scrape_configs:
  - job_name: "mlids"
    static_configs:
      - targets: ["localhost:8000"]  # Change localhost to your machine's IP address
```

## Project Structure

```
MLIDS/
├── config/                 # Grafana and Prometheus configurations
├── src/                   # Source code
│   ├── core/             # Core components
│   ├── ml/              # Machine learning models
│   └── monitoring/      # Metrics and monitoring
├── models/               # Trained models
└── docker-compose.yml    # Services configuration
```

