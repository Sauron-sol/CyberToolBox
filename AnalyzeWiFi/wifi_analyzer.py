import subprocess
import platform
import re
from datetime import datetime
from abc import ABC, abstractmethod
from typing import List, Dict
import time
import sys
import os
import json
import socket
import uuid
import netifaces
import psutil

class NetworkScanner(ABC):
    @abstractmethod
    def scan(self) -> List[Dict]:
        pass

class MacOSScanner(NetworkScanner):
    def __init__(self):
        self.ui = None
        self.interface = None

    def set_ui(self, ui):
        self.ui = ui
        self.interface = self._get_active_interface()

    def _get_active_interface(self) -> str:
        """Get active WiFi interface name"""
        try:
            output = subprocess.check_output(['networksetup', '-listallhardwareports'], universal_newlines=True)
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if 'Wi-Fi' in line and i + 1 < len(lines):
                    device_line = lines[i + 1]
                    if 'Device: ' in device_line:
                        interface = device_line.split('Device: ')[1].strip()
                        self.ui.print_success(f"Found WiFi interface: {interface}")
                        return interface
        except Exception as e:
            self.ui.print_error(f"Error finding WiFi interface: {str(e)}")
        return 'en0'  # Fallback

    def scan(self) -> List[Dict]:
        try:
            self.ui.print_success("Starting network scan...")
            
            # Initialiser le dictionnaire d'information réseau
            network_info = {
                'ssid': 'Not Connected',
                'interface': self.interface,
                'signal': -1,
                'channel': 'Unknown',
                'security': 'Unknown',
                'is_connected': False,  # Nouveau champ
            }
            
            # Obtenir l'information de connexion WiFi et les détails
            net_info = subprocess.check_output(['networksetup', '-getinfo', 'Wi-Fi'], 
                                            universal_newlines=True)
            self.ui.print_success("Got network details")
            
            # Parser les informations réseau
            has_ip = False
            for line in net_info.split('\n'):
                if ':' in line:
                    key, value = [x.strip() for x in line.split(':', 1)]
                    if 'IP address' in key and value not in ['none', '']:
                        network_info['ip_address'] = value
                        has_ip = True
                    elif 'Subnet mask' in key and value not in ['none', '']:
                        network_info['subnet_mask'] = value
                    elif 'Router' in key and value not in ['none', '']:
                        network_info['router'] = value
                    elif 'Wi-Fi ID' in key and value not in ['none', '']:
                        network_info['mac_address'] = value

            # Marquer comme connecté si nous avons une IP
            network_info['is_connected'] = has_ip
            if has_ip:
                network_info['connection_status'] = 'Active connection with IP'
            else:
                network_info['connection_status'] = 'No active connection'

            # Obtenir les informations système
            sys_info = subprocess.check_output(['system_profiler', 'SPNetworkDataType', '-json'],
                                            universal_newlines=True)
            system_data = json.loads(sys_info)
            
            for interface in system_data.get('SPNetworkDataType', []):
                if interface.get('type') in ['Wi-Fi', 'AirPort']:
                    network_info.update({
                        'hardware': interface.get('hardware', 'Unknown'),
                        'speed': interface.get('speed', 'Unknown'),
                        'dns_servers': interface.get('dns_servers', ['Unknown']),
                        'interface_status': interface.get('status', 'Unknown'),
                    })
                    break

            self.ui.print_success("Network information parsed successfully")
            return [network_info]

        except Exception as e:
            self.ui.print_error(f"Error scanning networks: {str(e)}")
            return []

    def _parse_wifi_info(self, output: str) -> Dict:
        """Parse WiFi information from networksetup output"""
        network = {}
        try:
            for line in output.split('\n'):
                if ':' not in line:
                    continue
                key, value = [x.strip() for x in line.split(':', 1)]
                
                if 'Network Name' in key and value:
                    network['ssid'] = value
                elif 'IP address' in key and value:
                    network['ip_address'] = value
                elif 'Subnet mask' in key and value:
                    network['subnet_mask'] = value
                elif 'Router' in key and value:
                    network['router'] = value
                elif 'Wi-Fi Power' in key:
                    network['wifi_enabled'] = value.lower() == 'on'
                
            if not network.get('ssid'):
                self.ui.print_error("No network name found in WiFi info")
                return {}
                
            # Ajouter des valeurs par défaut nécessaires
            network.update({
                'signal': -50,  # Valeur par défaut pour le réseau connecté
                'channel': 'Auto',
                'security': 'WPA2',  # Valeur commune par défaut
                'is_current': True,
                'address': 'Current Network',
            })
            
            return network
            
        except Exception as e:
            self.ui.print_error(f"Error parsing WiFi info: {str(e)}")
            return {}

    def _parse_system_profiler(self, data: dict) -> Dict:
        """Parse system profiler output"""
        try:
            network_info = {}
            for interface in data.get('SPNetworkDataType', []):
                if interface.get('type') == 'Wi-Fi' or interface.get('type') == 'AirPort':
                    network_info = {
                        'interface': interface.get('interface', self.interface),
                        'hardware': interface.get('hardware', 'Unknown'),
                        'mac_address': interface.get('ethernet', {}).get('mac-address', 'Unknown'),
                        'speed': interface.get('speed', 'Unknown'),
                    }
                    
                    # Extraire les DNS servers s'ils existent
                    if 'dns_servers' in interface:
                        network_info['dns_servers'] = interface['dns_servers']
                    
                    # Ajouter d'autres informations pertinentes
                    if 'ip_address' in interface:
                        network_info['ip_address'] = interface['ip_address'][0] if interface['ip_address'] else 'Unknown'
                    
                    return network_info
            
            self.ui.print_error("No WiFi interface found in system profile")
            return {}
            
        except Exception as e:
            self.ui.print_error(f"Error parsing system profile: {str(e)}")
            return {}

    def _parse_scan_results(self, output: str) -> List[Dict]:
        """Parse airport scan results"""
        networks = []
        lines = output.split('\n')[1:]  # Skip header
        for line in lines:
            if not line.strip():
                continue
            try:
                parts = line.split()
                if len(parts) >= 6:
                    network = {
                        'ssid': parts[0],
                        'address': parts[1],
                        'signal': int(parts[2]),
                        'channel': parts[3],
                        'security': ' '.join(parts[6:]) if len(parts) > 6 else 'NONE'
                    }
                    networks.append(network)
            except (IndexError, ValueError):
                continue
        return networks

    def _parse_diagnostics(self, output: str) -> List[Dict]:
        """Parse wdutil diagnostic output"""
        networks = []
        current_network = {}
        in_network_section = False

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            if "Current Network Information:" in line:
                in_network_section = True
                continue

            if in_network_section and ': ' in line:
                key, value = line.split(': ', 1)
                key = key.strip().lower()
                value = value.strip()

                if 'ssid' in key:
                    if current_network:
                        networks.append(current_network)
                    current_network = {'ssid': value}
                elif 'bssid' in key:
                    current_network['address'] = value
                elif 'channel' in key:
                    current_network['channel'] = value
                    current_network['is_5ghz'] = int(value.split(',')[0]) > 14 if value else False
                elif 'security' in key:
                    current_network['security'] = value
                elif 'rssi' in key:
                    try:
                        current_network['signal'] = int(value)
                    except ValueError:
                        current_network['signal'] = -100

        if current_network:
            networks.append(current_network)
        return networks

    def _merge_network_info(self, system_info: Dict, networks: List[Dict]) -> List[Dict]:
        """Merge system information with network scan results"""
        for network in networks:
            network.update({
                'interface': system_info.get('interface', ''),
                'ip_address': system_info.get('ip_address', ''),
                'subnet_mask': system_info.get('subnet_mask', ''),
                'dns_servers': system_info.get('dns_servers', []),
                'hardware': system_info.get('hardware', ''),
                'speed': system_info.get('speed', '')
            })
        return networks

    def _get_system_info(self) -> Dict:
        """Get system network information"""
        try:
            output = subprocess.check_output(['system_profiler', 'SPNetworkDataType', '-json'], 
                                          universal_newlines=True)
            data = json.loads(output)
            for interface in data.get('SPNetworkDataType', []):
                if interface.get('type') == 'WiFi':
                    return {
                        'interface': self.interface,
                        'ip_address': interface.get('ip_address', ['Unknown'])[0],
                        'subnet_mask': interface.get('subnet_masks', ['Unknown'])[0],
                        'dns_servers': interface.get('dns_servers', []),
                        'hardware': interface.get('hardware', 'Unknown'),
                        'speed': interface.get('speed', 'Unknown')
                    }
        except:
            pass
        return {}

class LinuxScanner(NetworkScanner):
    def scan(self) -> List[Dict]:
        """Scan networks using Linux tools (iwlist or iw)"""
        try:
            # Try iw first (modern tool)
            return self._scan_with_iw() or self._scan_with_iwlist()
        except Exception as e:
            print(f"Error during Linux scan: {str(e)}")
            return []

    def _scan_with_iw(self) -> List[Dict]:
        """Scan using iw tool"""
        try:
            # Get wireless interface name
            interfaces = subprocess.check_output(['iw', 'dev'], universal_newlines=True)
            interface = None
            for line in interfaces.split('\n'):
                if 'Interface' in line:
                    interface = line.split()[-1]
                    break
            
            if not interface:
                return []

            # Scan networks
            output = subprocess.check_output(['iw', interface, 'scan'], universal_newlines=True)
            networks = []
            current_network = {}
            
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if "BSS" in line and "(" in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {
                        'address': line.split('(')[0].split()[-1],
                        'signal': -100,
                        'channel': '',
                        'security': '',
                        'frequency': 'Unknown',
                        'vendor': 'Unknown vendor',
                        'is_5ghz': False
                    }
                
                elif "SSID:" in line:
                    current_network['ssid'] = line.split(':', 1)[1].strip()
                elif "signal:" in line:
                    current_network['signal'] = int(float(line.split()[1]))
                elif "freq:" in line:
                    freq = int(line.split()[1])
                    current_network['frequency'] = f"5 GHz" if freq > 4000 else "2.4 GHz"
                    current_network['is_5ghz'] = freq > 4000
                elif "capability:" in line:
                    caps = line.split(':', 1)[1].strip()
                    if "Privacy" in caps:
                        if "RSN" in output:
                            current_network['security'] = "WPA2"
                        elif "WPA" in output:
                            current_network['security'] = "WPA"
                        else:
                            current_network['security'] = "WEP"
                    else:
                        current_network['security'] = "NONE"
            
            if current_network:
                networks.append(current_network)
            
            return networks
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

    def _scan_with_iwlist(self) -> List[Dict]:
        """Fallback to iwlist if iw is not available"""
        try:
            # Find wireless interface
            interfaces = subprocess.check_output(['iwlist', 'scanning'], universal_newlines=True)
            interface = None
            for dev in ['wlan0', 'wlp2s0', 'wifi0']:
                if dev in interfaces:
                    interface = dev
                    break
            
            if not interface:
                return []

            output = subprocess.check_output(['iwlist', interface, 'scanning'], universal_newlines=True)
            networks = []
            current_network = {}
            
            for line in output.split('\n'):
                line = line.strip()
                
                if "Cell" in line and "Address:" in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {
                        'address': line.split("Address: ")[1],
                        'signal': -100,
                        'channel': '',
                        'security': '',
                        'frequency': 'Unknown',
                        'vendor': 'Unknown vendor',
                        'is_5ghz': False
                    }
                    
                elif "ESSID:" in line:
                    essid = line.split(':', 1)[1].strip('"')
                    current_network['ssid'] = essid
                elif "Quality" in line and "Signal level" in line:
                    signal = line.split("Signal level=")[1].split()[0]
                    try:
                        if 'dBm' in signal:
                            current_network['signal'] = int(signal.replace('dBm', ''))
                        else:
                            # Convert percentage to dBm (approximate)
                            percent = int(signal.replace('%', ''))
                            current_network['signal'] = -100 + percent
                    except:
                        current_network['signal'] = -100
                elif "Frequency:" in line:
                    freq = line.split(':')[1].split()[0]
                    current_network['frequency'] = f"5 GHz" if float(freq) > 4.0 else "2.4 GHz"
                    current_network['is_5ghz'] = float(freq) > 4.0
                elif "Encryption key:" in line:
                    if "off" in line.lower():
                        current_network['security'] = "NONE"
                elif "IE: IEEE 802.11i/WPA2" in line:
                    current_network['security'] = "WPA2"
                elif "IE: WPA Version" in line:
                    current_network['security'] = "WPA"
            
            if current_network:
                networks.append(current_network)
            
            return networks
            
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"iwlist scan failed: {str(e)}")
            return []

class WindowsScanner(NetworkScanner):
    def scan(self) -> List[Dict]:
        try:
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], universal_newlines=True)
            # Basic Windows implementation - can be expanded
            return []
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

class TerminalUI:
    @staticmethod
    def print_progress(progress: int, total: int):
        bar_length = 30
        filled = int(bar_length * progress // total)
        bar = '█' * filled + '-' * (bar_length - filled)
        percent = progress * 100 // total
        print(f'\rScanning: [{bar}] {percent}%', end='', flush=True)

    @staticmethod
    def print_header():
        print("\n" + "="*60)
        print("WiFi Network Security Analyzer")
        print("="*60 + "\n")

    @staticmethod
    def print_error(message: str):
        print(f"\n❌ Error: {message}")

    @staticmethod
    def print_success(message: str):
        print(f"\n✅ {message}")

class WiFiAnalyzer:
    def __init__(self):
        self.networks = []
        self.vulnerabilities = []
        self.ui = TerminalUI()
        self.os_type = self._detect_os()
        self.scanner = self._get_os_scanner()

    def _detect_os(self) -> str:
        """Detect OS and validate WiFi scanning capabilities"""
        os_type = platform.system().lower()
        
        if os_type == 'darwin':
            # Amélioration des messages pour macOS
            airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
            if not os.path.exists(airport_path):
                self.ui.print_error("Airport utility not found on your Mac.")
                sys.exit(1)
            try:
                # Vérifier si l'interface WiFi est active
                subprocess.check_output([airport_path, '-I'], stderr=subprocess.PIPE)
                self.ui.print_success("macOS WiFi interface detected and active")
                return 'macos'  # Utiliser 'macos' au lieu de 'darwin' pour plus de clarté
            except subprocess.CalledProcessError:
                self.ui.print_error("WiFi interface not active. Please enable WiFi on your Mac.")
                sys.exit(1)
        elif os_type == 'linux':
            # Vérifier si les outils Linux sont disponibles
            if self._check_linux_tools():
                return 'linux'
            else:
                self.ui.print_error("Required Linux wireless tools not found. Please install wireless-tools and iw.")
                sys.exit(1)
        elif os_type == 'windows':
            # Vérifier si netsh est disponible
            if self._check_windows_tools():
                return 'windows'
            else:
                self.ui.print_error("Windows wireless tools not found.")
                sys.exit(1)
        else:
            self.ui.print_error(f"Unsupported operating system: {os_type}")
            sys.exit(1)

    def _check_linux_tools(self) -> bool:
        """Check if Linux wireless tools are available"""
        try:
            subprocess.run(['iwconfig'], capture_output=True)
            return True
        except FileNotFoundError:
            return False

    def _check_windows_tools(self) -> bool:
        """Check if Windows wireless tools are available"""
        try:
            subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True)
            return True
        except FileNotFoundError:
            return False

    def _get_os_scanner(self) -> NetworkScanner:
        """Initialize the appropriate scanner based on OS"""
        scanner = None
        if self.os_type == 'macos':
            scanner = MacOSScanner()
            scanner.set_ui(self.ui)  # Initialize UI before using scanner
        elif self.os_type == 'linux':
            scanner = LinuxScanner()
        elif self.os_type == 'windows':
            scanner = WindowsScanner()
        else:
            raise NotImplementedError(f"OS {self.os_type} not supported")
        
        return scanner

    def scan_networks(self):
        self.ui.print_header()
        os_name = "macOS" if self.os_type == 'macos' else self.os_type.capitalize()
        print(f"Detected OS: {os_name}")
        print("Initializing scan...")
        
        # Simulate progress for better UX
        for i in range(1, 11):
            self.ui.print_progress(i, 10)
            time.sleep(0.2)
        
        print("\nScanning networks...")
        self.networks = self.scanner.scan()
        
        if not self.networks:
            self.ui.print_error("No networks found. Make sure your WiFi interface is enabled.")
        else:
            self.ui.print_success(f"Found {len(self.networks)} networks")
        
        return self.networks

    def _parse_security(self, security_info):
        """Parse security information from airport output"""
        security = security_info.upper()
        if 'NONE' in security:
            return 'none'
        elif 'WEP' in security:
            return 'wep'
        elif 'WPA2' in security:
            return 'wpa2'
        elif 'WPA3' in security:
            return 'wpa3'
        elif 'WPA' in security:
            return 'wpa'
        return 'unknown'

    def analyze_security(self):
        """Analyze security of found networks"""
        self.vulnerabilities = []
        for network in self.networks:
            # Vérification de la connexion
            if not network.get('is_connected', False):
                self.vulnerabilities.append("INFO: No active WiFi connection")
                self.vulnerabilities.append("NOTICE: Unable to perform complete security analysis without active connection")
                continue

            # Analyse IP et réseau
            if network.get('ip_address'):
                if network['ip_address'].startswith('192.168.'):
                    self.vulnerabilities.append("INFO: Using private IP range (192.168.x.x)")
                elif network['ip_address'].startswith('10.'):
                    self.vulnerabilities.append("INFO: Using private IP range (10.x.x.x)")
                elif network['ip_address'].startswith('172.'):
                    self.vulnerabilities.append("INFO: Using private IP range (172.16-31.x.x)")

            # Analyse DNS
            dns_servers = network.get('dns_servers', [])
            if not dns_servers or dns_servers == ['Unknown']:
                self.vulnerabilities.append("WARNING: No DNS servers configured")
            else:
                self.vulnerabilities.append(f"INFO: Using {len(dns_servers)} DNS servers")

            # Analyse du routeur
            if not network.get('router'):
                self.vulnerabilities.append("WARNING: No default gateway configured")

            # Autres analyses existantes...
            # ... existing security checks ...

    def generate_report(self):
        """Generate enhanced security report"""
        report = "\n" + "="*60 + "\n"
        report += f"📊 WiFi Security Analysis Report\n"
        report += f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += "="*60 + "\n\n"

        # System Information
        report += "🖥️ System Information:\n"
        report += f"{'─'*40}\n"
        report += f"OS: {platform.system()} {platform.release()}\n"
        report += f"Machine: {platform.machine()}\n"
        report += f"Processor: {platform.processor()}\n"
        
        # Network Information avec statut amélioré
        for i, network in enumerate(self.networks, 1):
            report += f"\n📡 Network #{i}\n"
            report += f"{'─'*40}\n"
            report += f"Connection Status: {network.get('connection_status', 'Unknown')}\n"
            report += f"Interface: {network.get('interface', 'Unknown')} ({network.get('interface_status', 'Unknown')})\n"
            if network.get('is_connected'):
                report += f"Network Configuration:\n"
                report += f"  IP Address: {network.get('ip_address', 'Not assigned')}\n"
                report += f"  Subnet Mask: {network.get('subnet_mask', 'Not assigned')}\n"
                report += f"  Router: {network.get('router', 'Not assigned')}\n"
                report += f"  DNS Servers: {', '.join(network.get('dns_servers', ['Unknown']))}\n"
            report += f"Hardware Information:\n"
            report += f"  Interface: {network.get('mac_address', 'Unknown')}\n"
            report += f"  Adapter: {network.get('hardware', 'Unknown')}\n"
            if network.get('speed'):
                report += f"  Link Speed: {network['speed']}\n"

        # Security Analysis avec groupement amélioré
        if self.vulnerabilities:
            report += "\n🔒 Security Analysis:\n"
            report += "="*40 + "\n"
            
            criticals = [v for v in self.vulnerabilities if v.startswith("CRITICAL")]
            warnings = [v for v in self.vulnerabilities if v.startswith("WARNING")]
            notices = [v for v in self.vulnerabilities if v.startswith("NOTICE")]
            infos = [v for v in self.vulnerabilities if v.startswith("INFO")]
            
            if criticals:
                report += "\n🚨 Critical Issues:\n"
                for vuln in criticals:
                    report += f"❗ {vuln}\n"
            
            if warnings:
                report += "\n⚠️ Warnings:\n"
                for vuln in warnings:
                    report += f"⚠️ {vuln}\n"
            
            if notices:
                report += "\n📢 Notices:\n"
                for vuln in notices:
                    report += f"📢 {vuln}\n"
            
            if infos:
                report += "\n📌 Information:\n"
                for vuln in infos:
                    report += f"ℹ️ {vuln}\n"
        
        return report

if __name__ == "__main__":
    try:
        analyzer = WiFiAnalyzer()
        analyzer.scan_networks()
        analyzer.analyze_security()
        print(analyzer.generate_report())
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
    except Exception as e:
        print(f"\n\nAn error occurred: {str(e)}")
