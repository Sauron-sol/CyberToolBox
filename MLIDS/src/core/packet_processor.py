import numpy as np
from typing import Dict, Optional, Union, List
import logging

class PacketProcessor:
    def __init__(self):
        """Initialize the packet processor."""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.WARNING)
        self.features_list = [
            'packet_size',
            'protocol_type',
            'header_length',
            'payload_length',
            'flags',
            'window_size',
            'urgent_pointer'
        ]
        
        # Feature scaling parameters
        self.max_packet_size = 65535
        self.max_protocol_type = 255
        self.max_header_length = 20
        self.max_payload_length = 65515
        self.max_flags = 255
        self.max_window_size = 65535
        self.max_urgent_pointer = 65535
    
    def _safe_get_first_value(self, value: Union[List, str, int, None]) -> Union[str, int, None]:
        """Safely get the first value from a list or return the value itself."""
        if value is None:
            return None
        if isinstance(value, list):
            return value[0] if value else None
        return value
    
    def _safe_get_int(self, value: Union[List, str, int, None], default: int = 0) -> int:
        """Safely convert a value to integer."""
        value = self._safe_get_first_value(value)
        if value is None:
            return default
        try:
            if isinstance(value, str):
                # Handle hexadecimal strings
                if value.startswith('0x'):
                    return int(value, 16)
                # Handle binary strings
                if value.startswith('0b'):
                    return int(value, 2)
            return int(value)
        except (TypeError, ValueError):
            return default
    
    def extract_features(self, packet) -> Optional[Dict]:
        """
        Extract features from a packet for ML analysis.
        
        Args:
            packet: pyshark packet to analyze
            
        Returns:
            Optional[Dict]: Dictionary of features or None if packet is invalid
        """
        features = {
            'packet_size': 0,
            'protocol_type': 0,
            'header_length': 0,
            'payload_length': 0,
            'flags': 0,
            'window_size': 0,
            'urgent_pointer': 0
        }
        
        try:
            # Check if the packet is valid
            if not packet:
                self.logger.warning("Invalid packet received")
                return None

            # Ignore broadcast/multicast packets
            if hasattr(packet, 'eth') and packet.eth.dst.startswith(('01:', '33:', 'ff:')):
                return None

            # Get IP layer (v4 or v6)
            if hasattr(packet, 'ip'):
                ip_layer = packet.ip
            elif hasattr(packet, 'ipv6'):
                ip_layer = packet.ipv6
            else:
                return None
            
            # Basic features with safe extraction
            features['packet_size'] = self._safe_get_int(getattr(packet, 'length', 0))
            features['protocol_type'] = self._safe_get_int(getattr(ip_layer, 'proto', 0))
            
            # Ignore packets that are too small or too large
            if features['packet_size'] < 20 or features['packet_size'] > 9000:
                return None
            
            # Header length (different for IPv4 and IPv6)
            if hasattr(packet, 'ip'):
                features['header_length'] = self._safe_get_int(getattr(ip_layer, 'hdr_len', 0))
            else:
                features['header_length'] = 40  # IPv6 header is fixed
            
            # TCP features
            if hasattr(packet, 'tcp'):
                tcp = packet.tcp
                features['payload_length'] = self._safe_get_int(getattr(tcp, 'len', 0))
                features['flags'] = self._safe_get_int(getattr(tcp, 'flags', 0))
                features['window_size'] = self._safe_get_int(getattr(tcp, 'window_size', 0))
                features['urgent_pointer'] = self._safe_get_int(getattr(tcp, 'urgent_pointer', 0))
                
                # Ignore normal TCP control packets
                if features['flags'] in [2, 17, 20]:  # SYN, ACK, FIN
                    return None
            
            # UDP features
            elif hasattr(packet, 'udp'):
                udp = packet.udp
                features['payload_length'] = self._safe_get_int(getattr(udp, 'length', 0))
                
                # Ignore standard UDP packets (DNS, DHCP, etc.)
                src_port = self._safe_get_int(getattr(udp, 'srcport', 0))
                dst_port = self._safe_get_int(getattr(udp, 'dstport', 0))
                if src_port in [53, 67, 68] or dst_port in [53, 67, 68]:
                    return None
            
            # Final validation of features
            if features['payload_length'] == 0 and features['packet_size'] > 100:
                return None
            
            self.logger.debug(f"Extracted features: {features}")
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
            return None
    
    def normalize_features(self, features: Dict) -> np.ndarray:
        """
        Normalize features for ML processing.
        
        Args:
            features (Dict): Dictionary of features
            
        Returns:
            np.ndarray: Normalized feature vector
        """
        feature_vector = []
        
        try:
            if not isinstance(features, dict):
                self.logger.error(f"Invalid features type: {type(features)}")
                return np.zeros(len(self.features_list), dtype=np.float32)

            for feature in self.features_list:
                # Get raw value with default 0
                raw_value = features.get(feature, 0)
                
                # Handle lists
                if isinstance(raw_value, list):
                    raw_value = raw_value[0] if raw_value else 0
                
                # Convert to float, default to 0.0 if conversion fails
                try:
                    if isinstance(raw_value, str):
                        # Handle hexadecimal strings
                        if raw_value.startswith('0x'):
                            value = float(int(raw_value, 16))
                        # Handle binary strings
                        elif raw_value.startswith('0b'):
                            value = float(int(raw_value, 2))
                        else:
                            value = float(raw_value)
                    else:
                        value = float(raw_value)
                except (TypeError, ValueError):
                    self.logger.debug(f"Could not convert {feature}={raw_value} to float")
                    value = 0.0
                
                # Normalize specific features
                if feature in ['packet_size', 'payload_length', 'window_size']:
                    if value > 0:  # Only normalize positive values
                        value = min(value / 65535.0, 1.0)
                    else:
                        value = 0.0
                elif feature in ['flags', 'protocol_type']:
                    # Normalize flags and protocol type to [0, 1]
                    if value > 0:
                        value = min(value / 255.0, 1.0)
                
                feature_vector.append(value)
            
            self.logger.debug(f"Normalized features: {feature_vector}")
            return np.array(feature_vector, dtype=np.float32)
            
        except Exception as e:
            self.logger.error(f"Error normalizing features: {str(e)}")
            # Return zero vector in case of error
            return np.zeros(len(self.features_list), dtype=np.float32) 