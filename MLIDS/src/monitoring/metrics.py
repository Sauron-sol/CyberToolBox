from prometheus_client import Counter, Gauge, Histogram, start_http_server
import logging

class MetricsExporter:
    def __init__(self, port: int = 9090):
        """Initialize Prometheus metrics."""
        self.logger = logging.getLogger(__name__)
        
        # Counters
        self.packets_processed = Counter(
            'mlids_packets_processed_total',
            'Total number of packets processed'
        )
        self.anomalies_detected = Counter(
            'mlids_anomalies_detected_total',
            'Total number of anomalies detected'
        )
        self.processing_errors = Counter(
            'mlids_processing_errors_total',
            'Total number of packet processing errors'
        )
        
        # Gauges
        self.active_connections = Gauge(
            'mlids_active_connections',
            'Number of active network connections'
        )
        self.model_training_status = Gauge(
            'mlids_model_training_status',
            'Model training status (1 = training, 0 = idle)'
        )
        
        # Histograms
        self.packet_size = Histogram(
            'mlids_packet_size_bytes',
            'Distribution of packet sizes',
            buckets=(64, 128, 256, 512, 1024, 1500)
        )
        self.processing_time = Histogram(
            'mlids_packet_processing_seconds',
            'Time spent processing each packet',
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
        )
        
        try:
            start_http_server(port)
            self.logger.info(f"Metrics server started on port {port}")
        except Exception as e:
            self.logger.error(f"Failed to start metrics server: {str(e)}")
            raise
    
    def record_packet_processed(self):
        """Record a processed packet."""
        self.packets_processed.inc()
    
    def record_anomaly_detected(self):
        """Record an anomaly detection."""
        self.anomalies_detected.inc()
    
    def record_processing_error(self):
        """Record a processing error."""
        self.processing_errors.inc()
    
    def update_active_connections(self, count: int):
        """Update the number of active connections."""
        self.active_connections.set(count)
    
    def set_model_training(self, is_training: bool):
        """Update model training status."""
        self.model_training_status.set(1 if is_training else 0)
    
    def observe_packet_size(self, size: int):
        """Record a packet size observation."""
        self.packet_size.observe(size)
    
    def observe_processing_time(self, seconds: float):
        """Record packet processing time."""
        self.processing_time.observe(seconds) 