import nmap
import scapy.all as scapy
from typing import Dict, List
import logging
import platform
import subprocess
import netifaces
import networkx as nx
from concurrent.futures import ThreadPoolExecutor
from .config import DEFAULT_PORT_RANGE, DEFAULT_TIMEOUT, MAX_THREADS

class NetworkMapper:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        self.network_graph = nx.Graph()
        self.timeout = DEFAULT_TIMEOUT
        self.max_threads = MAX_THREADS

    def detect_live_hosts(self, network: str) -> Dict:
        """
        Detect live hosts in the network using ARP and ICMP
        """
        results = {
            "live_hosts": [],
            "total_hosts": 0,
            "docker_containers": []
        }

        try:
            # Check Docker containers first
            try:
                import docker
                client = docker.from_env()
                containers = client.containers.list()
                for container in containers:
                    results["docker_containers"].append({
                        "name": container.name,
                        "id": container.short_id,
                        "status": container.status,
                        "network": container.attrs['NetworkSettings']['Networks']
                    })
            except Exception as e:
                self.logger.warning(f"Docker detection failed: {e}")

            # Continue with normal network scan
            arp_request = scapy.ARP(pdst=network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

            for element in answered_list:
                host_info = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "method": "ARP"
                }
                results["live_hosts"].append(host_info)

        except Exception as e:
            self.logger.error(f"Error in live host detection: {e}")

        results["total_hosts"] = len(results["live_hosts"])
        return results

    def identify_os_versions(self, target: str) -> Dict:
        """
        Identify OS versions using Nmap OS detection
        """
        results = {
            "os_matches": [],
            "accuracy": 0
        }

        try:
            self.nm.scan(target, arguments="-O --osscan-guess")
            if target in self.nm.all_hosts():
                if 'osmatch' in self.nm[target]:
                    for osmatch in self.nm[target]['osmatch']:
                        os_info = {
                            "name": osmatch['name'],
                            "accuracy": osmatch['accuracy'],
                            "line": osmatch.get('line', ''),
                            "type": osmatch.get('osclass', [{}])[0].get('type', 'unknown')
                        }
                        results["os_matches"].append(os_info)
                        results["accuracy"] = max(results["accuracy"], 
                                               int(osmatch['accuracy']))

        except Exception as e:
            self.logger.error(f"Error in OS detection: {e}")
            results["error"] = str(e)

        return results

    def map_network_topology(self, network: str) -> Dict:
        """
        Map network topology and create a network graph
        """
        topology = {
            "nodes": [],
            "links": [],
            "network_info": {}
        }

        try:
            # Get network interfaces
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:  # Only IPv4
                    for addr in addrs[netifaces.AF_INET]:
                        if addr.get('addr'):  # Check if address exists
                            self.network_graph.add_node(addr['addr'], 
                                                      type='interface',
                                                      name=interface)
                            topology["nodes"].append({
                                "ip": addr['addr'],
                                "type": "interface",
                                "name": interface
                            })

            # Detect live hosts and add to graph
            live_hosts = self.detect_live_hosts(network)
            for host in live_hosts["live_hosts"]:
                self.network_graph.add_node(host["ip"], 
                                          type='host',
                                          mac=host["mac"])
                topology["nodes"].append({
                    "ip": host["ip"],
                    "type": "host",
                    "mac": host["mac"]
                })

            # Trace routes to discover links
            for host in live_hosts["live_hosts"]:
                try:
                    traceroute = self._trace_route(host["ip"])
                    prev_hop = None
                    for hop in traceroute:
                        if prev_hop and hop:
                            self.network_graph.add_edge(prev_hop, hop)
                            topology["links"].append({
                                "source": prev_hop,
                                "target": hop
                            })
                        prev_hop = hop
                except Exception as e:
                    self.logger.error(f"Error in traceroute to {host['ip']}: {e}")

        except Exception as e:
            self.logger.error(f"Error mapping network topology: {e}")
            topology["error"] = str(e)

        return topology

    def _trace_route(self, target: str) -> List[str]:
        """
        Perform traceroute to target
        """
        hops = []
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(f"tracert {target}", shell=True)
            else:
                output = subprocess.check_output(f"traceroute -n {target}", shell=True)
            
            # Parse traceroute output
            lines = output.decode().split('\n')
            for line in lines:
                if line.strip() and not line.startswith('traceroute'):
                    ip = line.split()[-1]
                    if ip and ip[0].isdigit():
                        hops.append(ip)
        except Exception as e:
            self.logger.error(f"Traceroute error: {e}")
        
        return hops

    def run_full_network_analysis(self, network: str, target: str = None) -> Dict:
        """
        Run all network mapping functions
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            # Start all tasks
            topology_future = executor.submit(self.map_network_topology, network)
            live_hosts_future = executor.submit(self.detect_live_hosts, network)
            
            if target:
                os_future = executor.submit(self.identify_os_versions, target)
                results["os_detection"] = os_future.result()

            # Get results
            results["network_topology"] = topology_future.result()
            results["live_hosts"] = live_hosts_future.result()

        return results 

    def scan_ports(self, target: str, ports: str = DEFAULT_PORT_RANGE) -> dict:
        try:
            self.logger.info(f"Scanning ports {ports} on {target}")
            result = self.nm.scan(target, ports, arguments=f'-sV -T4 --max-rtt-timeout {self.timeout}s')
            return result
        except Exception as e:
            self.logger.error(f"Port scan error: {e}")
            return {} 