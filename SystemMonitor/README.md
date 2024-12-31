# 🖥️ System Monitor

A modern system monitoring tool with real-time web interface.

## 📋 Prerequisites

- Python 3.8 or higher
- Redis (for real-time communication)
- pip (Python package manager)
- Modern web browser

## 🚀 Installation

### 1. Installing Redis

**On MacOS:**
```bash
brew install redis
brew services start redis
```

**On Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install redis-server
sudo systemctl start redis
```

**On Windows:**
Download Redis from [https://github.com/microsoftarchive/redis/releases](https://github.com/microsoftarchive/redis/releases)

### 2. Installing the application

```bash
# Clone the repository
git clone https://github.com/yourusername/CyberToolBox.git
cd CyberToolBox/SystemMonitor

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Unix/MacOS
# or
.\venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements.txt
```

## 🎮 Usage

1. Make sure Redis is running
2. Activate virtual environment if not already done
3. Launch the application:
```bash
python system_monitor.py
```
4. Open your browser and go to: [http://localhost:5000](http://localhost:5000)

## 🎯 Features

### Real-time Dashboard
- CPU monitoring with graph
- Memory usage
- Disk usage
- Upload/Download network traffic

### Process Manager
- List of running processes
- Sort by CPU, memory, name, or PID
- Process search
- Process termination (requires appropriate rights)

### Alerts and Notifications
- Visual alerts for high CPU usage
- Real-time status indicators
- System-wide statistics

## 🔧 Configuration

Default settings:
- Port: 5000
- Host: localhost
- Redis: localhost:6379

To modify these settings, edit the variables in `system_monitor.py`.

## 🔍 Troubleshooting

### Redis not accessible
```bash
# Check if Redis is working
redis-cli ping
# Should return "PONG"

# Restart Redis if needed
sudo systemctl restart redis  # Linux
brew services restart redis   # MacOS
```

### Insufficient rights to terminate processes
Launch the application with administrator rights:
```bash
sudo python system_monitor.py  # Unix/MacOS
# or run as administrator on Windows
```

### Interface not accessible
Check that:
1. Application is properly running (terminal messages)
2. Port 5000 is available
3. You're using a recent browser
4. Redis is running

## 🔐 Security

- Application requires elevated rights for certain features
- Use only in a secure environment
- Do not expose directly to the Internet
- Limit access to authorized users

## 👥 Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.
