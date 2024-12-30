import nmap
import socket
import ipaddress
from scapy.all import *
from typing import Dict, List, Optional
from dataclasses import dataclass
import platform
import subprocess
import time
import signal
import psutil

@dataclass
class ScanTarget:
    ip: str
    ports: List[int]
    services: Dict[int, str]
    os: Optional[str] = None
    hostname: Optional[str] = None

class NetworkScanner:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.nm = nmap.PortScanner()
        self.targets: Dict[str, ScanTarget] = {}
        self.timeout = 30  # Global timeout in seconds
        self.current_processes = []
        self.scanning = False

    def is_nmap_available(self) -> bool:
        """Check if NMAP is installed"""
        try:
            if self.os_type == 'windows':
                subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE, shell=True)
            else:
                subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE)
            return True
        except:
            return False

    def discover_hosts(self, network: str, use_nmap: bool = True, nmap_options: str = "") -> List[str]:
        """Discover active hosts on the network, NMAP by default"""
        start_time = time.time()
        try:
            proc = psutil.Process()
            self.current_processes.append(proc)
            # Try NMAP first if available
            if self.is_nmap_available():
                discovered = self._nmap_discover(network, nmap_options)
                if discovered:
                    self.current_processes.remove(proc)
                    return discovered
                if time.time() - start_time > self.timeout:
                    print("Scan timeout reached")
                    self.current_processes.remove(proc)
                    return []

            # Fallback to ARP if NMAP fails or is not available
            result = self._arp_discover(network)
            self.current_processes.remove(proc)
            return result
        except Exception as e:
            print(f"Error in host discovery: {e}")
            return []

    def stop_scan(self):
        """Stop all running scan processes"""
        self.scanning = False
        
        # Stop running NMAP processes
        try:
            if self.os_type == 'windows':
                subprocess.run(['taskkill', '/F', '/IM', 'nmap.exe'], 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE)
            else:
                processes = subprocess.run(['pgrep', 'nmap'], 
                                        stdout=subprocess.PIPE, 
                                        text=True)
                for pid in processes.stdout.split():
                    try:
                        subprocess.run(['kill', '-9', pid], 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE)
                    except:
                        pass
        except:
            pass

        # Stop associated Python processes
        for proc in self.current_processes:
            try:
                proc.kill()
            except:
                pass
        self.current_processes.clear()

    def cleanup(self):
        """Clean up resources before closing"""
        self.stop_scan()
        self.nm = None
        self.targets.clear()

    def _nmap_discover(self, network: str, options: str = "") -> List[str]:
        """Host discovery using NMAP"""
        self.scanning = True
        try:
            if not options:
                # Default optimized options for faster scan
                options = "-sn -T4 --min-rate=300"

            print(f"Starting NMAP scan on {network} with options: {options}")
            
            # Add timeout to NMAP options if not present
            if "--host-timeout" not in options:
                options += f" --host-timeout {self.timeout}s"

            self.nm.scan(hosts=network, arguments=options)
            discovered = []

            while self.scanning and time.time() - start_time <= self.timeout:
                for host in self.nm.all_hosts():
                    try:
                        hostname = socket.gethostbyaddr(host)[0]
                    except:
                        hostname = "Unknown"

                    self.targets[host] = ScanTarget(
                        ip=host,
                        ports=[],
                        services={},
                        hostname=hostname
                    )
                    discovered.append(host)
                    print(f"NMAP discovered: {host} ({hostname})")
                if not self.scanning:
                    print("Scan interrupted by user")
                    break

            return discovered

        except Exception as e:
            print(f"NMAP scan error: {e}")
        finally:
            self.scanning = False
        return discovered

    def _arp_discover(self, network: str) -> List[str]:
        """Host discovery using ARP (original method)"""
        try:
            # Use ARP for local discovery (faster and more reliable)
            discovered = []
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            print(f"Scanning network: {network}")
            result = srp(packet, timeout=3, verbose=0)[0]
            
            for sent, received in result:
                try:
                    ip_addr = received.psrc
                    mac_addr = received.hwsrc
                    try:
                        hostname = socket.gethostbyaddr(ip_addr)[0]
                    except:
                        hostname = "Unknown"

                    self.targets[ip_addr] = ScanTarget(
                        ip=ip_addr,
                        ports=[],
                        services={},
                        hostname=hostname
                    )
                    discovered.append(ip_addr)
                    print(f"Discovered host: {ip_addr} ({hostname}) - MAC: {mac_addr}")
                except Exception as e:
                    print(f"Error processing host: {e}")

            # Complete with an ICMP scan for hosts that do not respond to ARP
            if not discovered:
                print("No hosts found with ARP, trying ICMP...")
                subnet = ipaddress.ip_network(network)
                for ip in subnet.hosts():
                    ip_str = str(ip)
                    if self.ping_host(ip_str):
                        try:
                            hostname = socket.gethostbyaddr(ip_str)[0]
                        except:
                            hostname = "Unknown"
                        self.targets[ip_str] = ScanTarget(
                            ip=ip_str,
                            ports=[],
                            services={},
                            hostname=hostname
                        )
                        discovered.append(ip_str)
                        print(f"Discovered host (ICMP): {ip_str} ({hostname})")

            return discovered

        except Exception as e:
            print(f"Error during host discovery: {e}")
            return []

    def _get_nmap_services(self, host: str) -> Dict[int, str]:
        """Get services detected by NMAP"""
        services = {}
        if host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    service = self.nm[host][proto][port]
                    services[port] = f"{service.get('name', 'unknown')} {service.get('version', '')}"
        return services

    def ping_host(self, ip: str) -> bool:
        """Check if host responds to ping"""
        try:
            # Create an ICMP echo request packet
            ping = IP(dst=ip)/ICMP()
            reply = sr1(ping, timeout=1, verbose=0)
            return reply is not None
        except:
            return False

    def scan_ports(self, target: str, use_nmap: bool = True, nmap_options: str = "") -> Dict[int, str]:
        """Port scanning with timeout"""
        start_time = time.time()
        try:
            if use_nmap and self.is_nmap_available():
                options = nmap_options if nmap_options else f"-sS -sV -T4 --host-timeout {self.timeout}s"
                scan_result = self.nm.scan(target, arguments=options)
                
                if time.time() - start_time > self.timeout:
                    print("Port scan timeout reached")
                    return {}

                if target in self.nm.all_hosts():
                    return self._get_nmap_services(target)

            return {}

        except Exception as e:
            print(f"Error scanning ports: {e}")
            return {}

    def detect_os(self, target: str, use_nmap: bool = True, nmap_options: str = "") -> Optional[str]:
        """OS detection with timeout"""
        start_time = time.time()
        try:
            if use_nmap and self.is_nmap_available():
                options = f"-O --host-timeout {self.timeout}s"
                if nmap_options:
                    options += f" {nmap_options}"

                os_scan = self.nm.scan(target, arguments=options)
                
                if time.time() - start_time > self.timeout:
                    print("OS detection timeout reached")
                    return None

                if target in self.nm.all_hosts():
                    os_matches = self.nm[target].get('osmatch', [])
                    if os_matches:
                        os_name = os_matches[0].get('name', 'Unknown')
                        if target in self.targets:
                            self.targets[target].os = os_name
                        return os_name
            return None
            
        except Exception as e:
            print(f"Error detecting OS: {e}")
            return None

    def export_results(self, format: str = 'json') -> str:
        """Export results in specified format"""
        # TODO: Implement different export formats
        pass
