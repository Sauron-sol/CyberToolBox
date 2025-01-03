import argparse
import logging
import sys
import time
from src.core.packet_capture import PacketCapture
from src.core.packet_processor import PacketProcessor
from src.ml.anomaly_detector import AnomalyDetector
from src.monitoring.metrics import MetricsExporter
import numpy as np
from typing import Optional
import os

class MLIDS:
    def __init__(self, interface: str, model_path: Optional[str] = None, metrics_port: int = 8000, network_filter: str = "", monitor_mode: bool = False):
        """
        Initialize the IDS/IPS system.
        
        Args:
            interface (str): Network interface to monitor
            model_path (Optional[str]): Path to a pre-trained model
            metrics_port (int): Port for Prometheus metrics
            network_filter (str): Network filter to apply
            monitor_mode (bool): Enable monitor mode for wireless interfaces
        """
        # Logging setup
        self._setup_logging()
        
        try:
            # Initialize metrics
            self.metrics = MetricsExporter(metrics_port)
            
            # Initialize components
            self.packet_capture = PacketCapture(interface)
            self.packet_processor = PacketProcessor()
            self.anomaly_detector = AnomalyDetector(model_path)
            
            # Learning buffer
            self.feature_buffer = []
            self.buffer_size = 5000
            self.is_training = False
            
            # Seuil de confiance pour les anomalies
            self.anomaly_threshold = 0.8
            
            # Update metrics
            self.metrics.set_model_training(False)
            
        except Exception as e:
            self.logger.error(f"Initialization error: {str(e)}")
            raise
    
    def _setup_logging(self):
        """Configure the logging system."""
        logging.basicConfig(
            level=logging.WARNING,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('mlids.log')
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def packet_handler(self, packet):
        """
        Handle each captured packet.
        
        Args:
            packet: Captured network packet
        """
        start_time = time.time()
        try:
            # Feature extraction
            features = self.packet_processor.extract_features(packet)
            if features is None:
                self.metrics.record_processing_error()
                return
            
            # Record packet size
            self.metrics.observe_packet_size(features.get('packet_size', 0))
            
            # Normalization
            normalized_features = self.packet_processor.normalize_features(features)
            if normalized_features is None:
                self.metrics.record_processing_error()
                return
            
            # Convert to numpy array if needed
            if not isinstance(normalized_features, np.ndarray):
                try:
                    normalized_features = np.array(normalized_features, dtype=np.float32)
                except Exception as e:
                    self.logger.error(f"Error converting features to numpy array: {str(e)}")
                    self.metrics.record_processing_error()
                    return
            
            # Learning mode
            if len(self.feature_buffer) < self.buffer_size and not self.is_training:
                self.feature_buffer.append(normalized_features)
                if len(self.feature_buffer) == self.buffer_size:
                    self.train_model()
            
            # Detection mode
            elif not self.is_training:
                try:
                    # Reshape for prediction
                    features_reshaped = normalized_features.reshape(1, -1)
                    prediction = self.anomaly_detector.predict(features_reshaped)
                    if prediction is not None and prediction[0] == -1:
                        self.logger.warning(f"Anomaly detected! Features: {features}")
                        self.metrics.record_anomaly_detected()
                except Exception as e:
                    self.logger.error(f"Error during prediction: {str(e)}")
                    self.metrics.record_processing_error()
            
            # Record successful processing
            self.metrics.record_packet_processed()
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            self.metrics.record_processing_error()
        finally:
            # Record processing time
            processing_time = time.time() - start_time
            self.metrics.observe_processing_time(processing_time)
    
    def train_model(self):
        """Train the model with collected data."""
        try:
            self.is_training = True
            self.metrics.set_model_training(True)
            self.logger.info("Starting model training...")
            
            # Convert buffer to numpy array
            X = np.array(self.feature_buffer)
            if len(X.shape) != 2:
                self.logger.error(f"Invalid feature shape: {X.shape}")
                return
                
            self.anomaly_detector.train(X)
            self.logger.info("Training completed")
            
            # Save model
            os.makedirs('models', exist_ok=True)
            self.anomaly_detector.save_model('models/anomaly_detector.joblib')
            
        except Exception as e:
            self.logger.error(f"Training error: {str(e)}")
        finally:
            self.is_training = False
            self.metrics.set_model_training(False)
    
    def start(self):
        """Start the IDS/IPS system."""
        self.logger.info("Starting MLIDS system...")
        try:
            # Check if interface is valid before starting
            if not self.packet_capture.interface:
                raise ValueError("Network interface not specified")
            
            self.packet_capture.start_capture(self.packet_handler)
        except KeyboardInterrupt:
            self.logger.info("System shutdown...")
        except Exception as e:
            self.logger.error(f"System error: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description='ML-based IDS/IPS System')
    parser.add_argument('--interface', type=str, required=True,
                      help='Network interface to monitor')
    parser.add_argument('--model', type=str,
                      help='Path to pre-trained model')
    parser.add_argument('--metrics-port', type=int, default=8000,
                      help='Port for Prometheus metrics')
    parser.add_argument('--network', type=str,
                      help='Network to monitor (e.g., 10.0.0.0/24)')
    parser.add_argument('--monitor-mode', action='store_true',
                      help='Enable monitor mode for wireless interfaces')
    
    args = parser.parse_args()
    
    try:
        # Configure network filter if specified
        network_filter = f"net {args.network}" if args.network else ""
        
        ids = MLIDS(
            interface=args.interface,
            model_path=args.model,
            metrics_port=args.metrics_port,
            network_filter=network_filter,
            monitor_mode=args.monitor_mode
        )
        ids.start()
    except KeyboardInterrupt:
        print("\nStopping system...")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 