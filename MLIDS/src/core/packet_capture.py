import pyshark
from typing import Callable, Optional, List
import logging
import os
import platform
import subprocess
from pathlib import Path

class PacketCapture:
    def __init__(self, interface: str = "en0"):
        """
        Initialize the packet capture system.
        
        Args:
            interface (str): Network interface to monitor
        """
        self.interface = interface
        self.is_running = False
        self._setup_logging()
        self._check_requirements()
    
    def _setup_logging(self):
        """Configure the logging system."""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
    
    def _check_requirements(self):
        """Check if tshark is installed and we have required permissions."""
        # Check for root/admin privileges
        if platform.system() != "Windows" and os.geteuid() != 0:
            self.logger.error("This program needs to run as root/administrator to capture packets")
            raise PermissionError("Root/Administrator privileges required")
        
        # Check for tshark installation
        try:
            subprocess.run(["tshark", "--version"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            self.logger.error("tshark (Wireshark) is not installed")
            raise RuntimeError("Please install Wireshark/tshark to use this program")
        except FileNotFoundError:
            self.logger.error("tshark (Wireshark) is not found in PATH")
            raise RuntimeError("Please install Wireshark/tshark and ensure it's in your PATH")
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces."""
        try:
            # Use tshark to list interfaces
            capture = pyshark.LiveCapture()
            interfaces = capture.interfaces
            self.logger.info(f"Available interfaces: {interfaces}")
            return interfaces
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {str(e)}")
            return []
    
    def _validate_interface(self):
        """Validate that the interface exists and is usable."""
        available_interfaces = self.get_available_interfaces()
        
        if self.interface not in available_interfaces:
            self.logger.error(f"Interface {self.interface} not found. Available interfaces: {available_interfaces}")
            raise ValueError(f"Interface {self.interface} not found")
    
    def _is_valid_packet(self, packet) -> bool:
        """
        Check if the packet is valid for our analysis.
        Only accept IPv4/IPv6 packets with TCP/UDP.
        """
        try:
            if not packet:
                return False
                
            # Check if packet has IP layer
            if not hasattr(packet, 'ip') and not hasattr(packet, 'ipv6'):
                return False
            
            # Check if packet has TCP or UDP layer
            if not hasattr(packet, 'tcp') and not hasattr(packet, 'udp'):
                return False
                
            # Verify that required attributes exist and are not None
            if hasattr(packet, 'ip'):
                if not hasattr(packet.ip, 'proto'):
                    return False
            elif hasattr(packet, 'ipv6'):
                if not hasattr(packet.ipv6, 'nxt'):
                    return False
                    
            return True
            
        except Exception as e:
            self.logger.debug(f"Error validating packet: {str(e)}")
            return False
    
    def _safe_packet_handler(self, packet) -> None:
        """
        Wrapper around the packet handler to catch any exceptions.
        """
        if not self.is_running:
            return
            
        try:
            if not self._is_valid_packet(packet):
                return
                
            # Convert packet attributes to a safe format
            try:
                # Get basic packet info
                packet_info = {
                    'length': getattr(packet, 'length', 0),
                    'sniff_time': getattr(packet, 'sniff_time', None),
                    'protocol': None
                }
                
                # Get IP layer info
                if hasattr(packet, 'ip'):
                    packet_info['protocol'] = getattr(packet.ip, 'proto', 0)
                elif hasattr(packet, 'ipv6'):
                    packet_info['protocol'] = getattr(packet.ipv6, 'nxt', 0)
                
                # Process the packet with the safe info
                self.packet_callback(packet)
                
            except AttributeError as e:
                self.logger.debug(f"Missing packet attribute: {str(e)}")
                return
                
        except Exception as e:
            self.logger.error(f"Error in packet handler: {str(e)}")
    
    def start_capture(self, packet_callback):
        """
        Start capturing packets on the specified interface.
        
        Args:
            packet_callback: Callback function to handle captured packets
        """
        try:
            self.logger.info(f"Starting capture on {self.interface}")
            
            # Configure capture with supported parameters
            capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter="ip",  # Capture IP traffic only
                use_json=True,
                include_raw=True
            )
            
            # Start the capture
            capture.apply_on_packets(packet_callback)
            
        except Exception as e:
            self.logger.error(f"Capture error: {str(e)}")
            raise
    
    def stop_capture(self):
        """Stop packet capture."""
        self.is_running = False
        self.logger.info("Stopping capture") 