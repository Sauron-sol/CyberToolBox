from PyQt6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox, QTextEdit, QLineEdit, QMessageBox
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
import netifaces
import ipaddress
from ..core.scanner import NetworkScanner

class ScannerThread(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)

    def __init__(self, scanner, interface, use_nmap=False, nmap_options=""):
        super().__init__()
        self.scanner = scanner
        self.interface = interface
        self.use_nmap = use_nmap
        self.nmap_options = nmap_options

    def run(self):
        try:
            # Obtenir l'adresse IP et le masque de l'interface
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip = ip_info['addr']
                netmask = ip_info['netmask']
                
                # Calculer le réseau
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                
                self.progress.emit(f"Scanning network: {network}")
                
                # Découverte des hôtes
                hosts = self.scanner.discover_hosts(str(network), use_nmap=self.use_nmap, nmap_options=self.nmap_options)
                
                results = {}
                for host in hosts:
                    self.progress.emit(f"Scanning ports for {host}")
                    ports = self.scanner.scan_ports(host, use_nmap=self.use_nmap, nmap_options=self.nmap_options)
                    os_type = self.scanner.detect_os(host, use_nmap=self.use_nmap, nmap_options=self.nmap_options)
                    results[host] = {
                        'ports': ports,
                        'os': os_type
                    }
                
                self.finished.emit(results)
        except Exception as e:
            self.progress.emit(f"Error during scan: {str(e)}")

    def stop(self):
        """Properly stop thread and all processes"""
        try:
            self.scanner.stop_scan()  # Nouvelle méthode dans NetworkScanner
            self.requestInterruption()
            # Attendre max 2 secondes pour la fin du thread
            self.wait(2000)
            if self.isRunning():
                self.terminate()  # Force l'arrêt si nécessaire
        except Exception as e:
            print(f"Error stopping scan: {e}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scanner = NetworkScanner()
        self.scanner_thread = None
        self.is_closing = False
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Network Scanner')
        self.setGeometry(100, 100, 800, 600)

        # Central widget setup
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Network interface selection
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.get_network_interfaces())
        layout.addWidget(QLabel("Network Interface:"))
        layout.addWidget(self.interface_combo)

        # Scan type options
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Complete Scan (NMAP)", "Quick Scan (ARP)"])
        layout.addWidget(QLabel("Scan Type:"))
        layout.addWidget(self.scan_type_combo)

        # NMAP advanced options
        self.nmap_options = QLineEdit()
        self.nmap_options.setPlaceholderText("NMAP options (e.g.: -sS -sV)")
        layout.addWidget(QLabel("NMAP Options (advanced):"))
        layout.addWidget(self.nmap_options)

        # Timeout control
        self.timeout_input = QLineEdit()
        self.timeout_input.setPlaceholderText("Timeout in seconds (default: 30)")
        layout.addWidget(QLabel("Timeout:"))
        layout.addWidget(self.timeout_input)

        # Control buttons
        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.start_scan)
        layout.addWidget(scan_button)

        # Export button
        export_button = QPushButton("Export Results")
        export_button.clicked.connect(self.export_results)
        layout.addWidget(export_button)

        # Emergency stop button
        stop_button = QPushButton("Stop Scan")
        stop_button.clicked.connect(self.stop_scan)
        stop_button.setStyleSheet("background-color: #ff4444;")
        layout.addWidget(stop_button)

        # Results display
        self.results_label = QLabel("Waiting for scan...")
        layout.addWidget(self.results_label)

        # Results text area
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)

        layout.addStretch()

    def get_network_interfaces(self):
        """Get list of network interfaces with their IPs"""
        try:
            interfaces = []
            for iface in netifaces.interfaces():
                # Ignore virtual and loopback interfaces
                if iface.startswith(('bridge', 'lo', 'vmnet', 'vbox')):
                    continue
                    
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:  # If interface has IPv4
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    # Add interface with IP
                    interfaces.append(f"{iface} ({ip})")
            return interfaces if interfaces else ["en0 (no IP)"]
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return ["en0 (no IP)"]

    def update_progress(self, message):
        """Update scan progress"""
        self.results_text.append(message)

    def scan_finished(self, results):
        """Process scan results"""
        self.results_text.append("\n=== Scan Results ===\n")
        for host, data in results.items():
            self.results_text.append(f"\nHost: {host}")
            if data['os']:
                self.results_text.append(f"OS: {data['os']}")
            self.results_text.append("Open ports:")
            for port, service in data['ports'].items():
                self.results_text.append(f"  {port}: {service}")
        
        self.results_text.append("\nScan completed!")
        self.scanner_thread = None

    def closeEvent(self, event):
        """Enhanced window close event handler"""
        self.is_closing = True
        
        if self.scanner_thread and self.scanner_thread.isRunning():
            reply = QMessageBox.question(
                self,
                'Confirmation',
                'Un scan est en cours. Voulez-vous vraiment quitter ?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.results_text.append("Arrêt du scan en cours...")
                self.scanner_thread.stop()
                # Attendre brièvement que le thread s'arrête
                QTimer.singleShot(1000, self.force_close)
                event.ignore()
            else:
                self.is_closing = False
                event.ignore()
        else:
            event.accept()

    def force_close(self):
        """Force application closure"""
        if self.is_closing:
            self.scanner.cleanup()  # Nouvelle méthode dans NetworkScanner
            QTimer.singleShot(100, self.close)

    def start_scan(self):
        """Start network scan"""
        if self.scanner_thread is not None:
            self.results_text.append("Scan already in progress...")
            return

        interface = self.interface_combo.currentText().split()[0]
        scan_type = self.scan_type_combo.currentText()
        nmap_opts = self.nmap_options.text() if scan_type == "Complete Scan (NMAP)" else ""

        # Get custom timeout value
        try:
            timeout = int(self.timeout_input.text())
            self.scanner.timeout = timeout
        except ValueError:
            # Keep default timeout if value is invalid
            pass

        self.results_text.clear()
        self.results_text.append(f"Starting {scan_type} on interface {interface}...\n")

        try:
            self.scanner_thread = ScannerThread(
                self.scanner, 
                interface,
                use_nmap=scan_type == "Complete Scan (NMAP)",
                nmap_options=nmap_opts
            )
            self.scanner_thread.progress.connect(self.update_progress)
            self.scanner_thread.finished.connect(self.scan_finished)
            self.scanner_thread.start()
        except Exception as e:
            self.results_text.append(f"Error starting scan: {str(e)}")
            self.scanner_thread = None

    def export_results(self):
        """Export results to text file"""
        if not self.results_text.toPlainText():
            QMessageBox.warning(self, "Attention", "Aucun résultat à exporter.")
            return

        try:
            from datetime import datetime
            filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(self.results_text.toPlainText())
            QMessageBox.information(self, "Succès", f"Résultats exportés dans {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'export : {str(e)}")

    def stop_scan(self):
        """Immediately stop current scan"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            reply = QMessageBox.question(
                self,
                'Confirmation',
                'Voulez-vous vraiment arrêter le scan en cours ?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.results_text.append("\nArrêt du scan demandé...")
                self.scanner_thread.stop()
                self.results_text.append("Scan arrêté.")
