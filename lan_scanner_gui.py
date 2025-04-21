import sys
import subprocess
import socket
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QTextEdit, QLabel, QTableWidget, QTableWidgetItem, QHBoxLayout, QLineEdit,
    QMessageBox, QDialog, QComboBox, QGridLayout, QStackedWidget
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import QThread, pyqtSignal

DEFAULT_COMMAND = "sudo -v && sudo arp-scan --interface=en0 10.0.20.0/24"
DEFAULT_BT_COMMAND = "bluetoothctl scan on"

class ActionWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, action_type, target, **kwargs):
        super().__init__()
        self.action_type = action_type
        self.target = target
        self.kwargs = kwargs
        
    def run(self):
        try:
            if self.action_type == "ping":
                result = subprocess.check_output(f"ping -c 4 {self.target}", shell=True, text=True)
                self.finished.emit(result)
            elif self.action_type == "mac_lookup":
                result = subprocess.check_output(f"curl -s https://api.macvendors.com/{self.target}", shell=True, text=True)
                self.finished.emit(result)
            elif self.action_type == "connect":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, 80))
                sock.close()
                if result == 0:
                    self.finished.emit("✅ Port 80 is open!")
                else:
                    self.finished.emit("❌ Port 80 is closed")
        except subprocess.CalledProcessError as e:
            self.error.emit(str(e.output))
        except Exception as e:
            self.error.emit(str(e))

class MACLookupWindow(QDialog):
    def __init__(self, mac, vendor, parent=None):
        super().__init__(parent)
        self.mac = mac
        self.vendor = vendor
        self.worker = None
        self.setWindowTitle(f"MAC Lookup - {mac}")
        self.setGeometry(400, 400, 500, 400)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # MAC Info
        info_label = QLabel(f"Analyzing MAC: {self.mac}")
        info_label.setFont(QFont("Courier", 12, QFont.Bold))
        layout.addWidget(info_label)

        # Show known vendor info
        if self.vendor and self.vendor != "(Unknown)":
            vendor_label = QLabel(f"Known Vendor: {self.vendor}")
            vendor_label.setFont(QFont("Courier", 10))
            layout.addWidget(vendor_label)

        # Lookup Options
        options_label = QLabel("Lookup Options:")
        options_label.setFont(QFont("Courier", 10))
        layout.addWidget(options_label)

        self.lookup_type = QComboBox()
        self.lookup_type.addItems([
            "Vendor Info",
            "Network Type",
            "Device Type",
            "Full Details"
        ])
        layout.addWidget(self.lookup_type)

        # Output area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Courier", 10))
        layout.addWidget(self.output)

        # Buttons
        button_layout = QHBoxLayout()
        self.lookup_btn = QPushButton("🔎 Lookup")
        self.close_btn = QPushButton("❌ Close")
        button_layout.addWidget(self.lookup_btn)
        button_layout.addWidget(self.close_btn)
        layout.addLayout(button_layout)

        # Connect buttons
        self.lookup_btn.clicked.connect(self.do_lookup)
        self.close_btn.clicked.connect(self.close)

        self.setLayout(layout)

    def do_lookup(self):
        if self.worker and self.worker.isRunning():
            self.output.append("⚠️ A lookup is already running!")
            return
            
        self.output.clear()
        lookup_type = self.lookup_type.currentText()
        self.output.append(f"🔍 Looking up {lookup_type} for {self.mac}...")
        self.lookup_btn.setEnabled(False)
        self.lookup_btn.setText("Looking up...")
        
        # Different API endpoints for different lookup types
        if lookup_type == "Vendor Info":
            url = f"https://api.macvendors.com/{self.mac}"
        elif lookup_type == "Network Type":
            url = f"https://api.macvendors.com/{self.mac}/network"
        elif lookup_type == "Device Type":
            url = f"https://api.macvendors.com/{self.mac}/device"
        else:  # Full Details
            url = f"https://api.macvendors.com/{self.mac}/full"
            
        self.worker = ActionWorker("mac_lookup", url)
        self.worker.finished.connect(self.handle_result)
        self.worker.error.connect(self.handle_error)
        self.worker.start()

    def handle_result(self, result):
        try:
            data = json.loads(result)
            if "errors" in data or result == "Not Found":
                self.output.append("❌ MAC Address not found in online database")
                if self.vendor and self.vendor != "(Unknown)":
                    self.output.append(f"💡 But we know it's from: {self.vendor}")
                self.output.append("💡 Try checking these instead:")
                self.output.append("  • Check if MAC is valid")
                self.output.append("  • Try a different lookup service")
                self.output.append("  • Device might be too new/unknown")
            else:
                lookup_type = self.lookup_type.currentText()
                if lookup_type == "Vendor Info":
                    self.output.append(f"✅ Vendor Info:\n{data.get('vendor', self.vendor or 'Unknown')}")
                elif lookup_type == "Network Type":
                    self.output.append(f"✅ Network Type:\n{data.get('network_type', 'Unknown')}")
                elif lookup_type == "Device Type":
                    self.output.append(f"✅ Device Type:\n{data.get('device_type', 'Unknown')}")
                else:  # Full Details
                    self.output.append("✅ Full Device Details:")
                    for key, value in data.items():
                        self.output.append(f"  • {key}: {value}")
        except json.JSONDecodeError:
            if result == "Not Found" and self.vendor and self.vendor != "(Unknown)":
                self.output.append(f"✅ Known Vendor: {self.vendor}")
            else:
                self.output.append(f"✅ Raw Response:\n{result}")
        
        self.lookup_btn.setEnabled(True)
        self.lookup_btn.setText("🔎 Lookup")

    def handle_error(self, error_msg):
        self.output.append("❌ Error: Could not lookup MAC vendor")
        self.output.append("💡 Try checking your internet connection")
        self.lookup_btn.setEnabled(True)
        self.lookup_btn.setText("🔎 Lookup")

    def show_diagnostics(self, row, col):
        ip = self.output_table.item(row, 0).text()
        mac = self.output_table.item(row, 1).text()
        vendor = self.output_table.item(row, 2).text()
        dialog = DiagnosticWindow(ip, mac, vendor, self)
        dialog.exec_()

    def lookup_mac(self):
        dialog = MACLookupWindow(self.mac, self.vendor, self)
        dialog.exec_()

class DiagnosticWindow(QDialog):
    def __init__(self, ip, mac, vendor, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.worker = None
        self.setWindowTitle(f"Network Diagnostics - {ip}")
        self.setGeometry(400, 400, 600, 400)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Info section
        info_label = QLabel(f"IP: {self.ip}\nMAC: {self.mac}")
        info_label.setFont(QFont("Courier", 10))
        layout.addWidget(info_label)

        # Buttons
        self.ping_btn = QPushButton("🔍 Ping Host")
        self.mac_lookup_btn = QPushButton("🔎 MAC Vendor Lookup")
        self.connect_btn = QPushButton("🔌 Test Connection (Port 80)")
        
        layout.addWidget(self.ping_btn)
        layout.addWidget(self.mac_lookup_btn)
        layout.addWidget(self.connect_btn)

        # Output area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Courier", 10))
        layout.addWidget(self.output)

        # Connect buttons
        self.ping_btn.clicked.connect(self.ping_host)
        self.mac_lookup_btn.clicked.connect(self.lookup_mac)
        self.connect_btn.clicked.connect(self.test_connection)

        self.setLayout(layout)

    def ping_host(self):
        if self.worker and self.worker.isRunning():
            self.output.append("⚠️ A ping is already running!")
            return
            
        self.output.append("🔄 Pinging host...")
        self.ping_btn.setEnabled(False)
        self.ping_btn.setText("Pinging...")
        
        self.worker = ActionWorker("ping", self.ip)
        self.worker.finished.connect(self.handle_ping_result)
        self.worker.error.connect(self.handle_ping_error)
        self.worker.start()

    def handle_ping_result(self, result):
        self.output.append(result)
        self.ping_btn.setEnabled(True)
        self.ping_btn.setText("🔍 Ping Host")

    def handle_ping_error(self, error_msg):
        self.output.append(f"❌ Error: {error_msg}")
        self.ping_btn.setEnabled(True)
        self.ping_btn.setText("🔍 Ping Host")

    def lookup_mac(self):
        dialog = MACLookupWindow(self.mac, self.vendor, self)
        dialog.exec_()

    def test_connection(self):
        if self.worker and self.worker.isRunning():
            self.output.append("⚠️ A connection test is already running!")
            return
            
        self.output.append("🔌 Testing connection...")
        self.connect_btn.setEnabled(False)
        self.connect_btn.setText("Testing...")
        
        self.worker = ActionWorker("connect", self.ip)
        self.worker.finished.connect(self.handle_connect_result)
        self.worker.error.connect(self.handle_connect_error)
        self.worker.start()

    def handle_connect_result(self, result):
        self.output.append(result)
        self.connect_btn.setEnabled(True)
        self.connect_btn.setText("🔌 Test Connection (Port 80)")

    def handle_connect_error(self, error_msg):
        self.output.append(f"❌ Error: {error_msg}")
        self.connect_btn.setEnabled(True)
        self.connect_btn.setText("🔌 Test Connection (Port 80)")

    def show_diagnostics(self, row, col):
        ip = self.output_table.item(row, 0).text()
        mac = self.output_table.item(row, 1).text()
        vendor = self.output_table.item(row, 2).text()
        dialog = DiagnosticWindow(ip, mac, vendor, self)
        dialog.exec_()

class ScanWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, command):
        super().__init__()
        self.command = command
        
    def run(self):
        try:
            print(f"Running command: {self.command}")
            result = subprocess.check_output(self.command, shell=True, stderr=subprocess.STDOUT, text=True)
            print(f"Got result: {result[:100]}...")
            self.finished.emit(result)
        except subprocess.CalledProcessError as e:
            error_msg = str(e.output)
            if "sudo: a password is required" in error_msg:
                error_msg = "Sudo password required! Try running 'sudo arp-scan' in terminal first to cache your password."
            print(f"Error occurred: {error_msg}")
            self.error.emit(error_msg)
        except Exception as e:
            print(f"Unexpected error: {e}")
            self.error.emit(str(e))

class LANScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LAN Scanner - Hacker Mode 🐾")
        self.setGeometry(300, 300, 800, 600)
        self.scan_worker = None
        self.known_devices = set()  # Track known devices
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()

        self.command_label = QLabel("Scan Command:")
        layout.addWidget(self.command_label)

        self.command_input = QLineEdit()
        self.command_input.setText(DEFAULT_COMMAND)
        self.command_input.setFont(QFont("Courier", 10))
        layout.addWidget(self.command_input)

        button_layout = QHBoxLayout()
        self.run_button = QPushButton("Run Scan")
        self.reset_button = QPushButton("Reset to Default")
        button_layout.addWidget(self.run_button)
        button_layout.addWidget(self.reset_button)
        layout.addLayout(button_layout)

        self.output_table = QTableWidget()
        self.output_table.setColumnCount(3)
        self.output_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Vendor"])
        self.output_table.cellClicked.connect(self.show_diagnostics)
        layout.addWidget(self.output_table)

        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.status_text)

        self.run_button.clicked.connect(self.run_scan)
        self.reset_button.clicked.connect(self.reset_command)

        self.setLayout(layout)

    def reset_command(self):
        self.command_input.setText(DEFAULT_COMMAND)
        self.status_text.append("🔁 Reset to default command.")

    def run_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.status_text.append("⚠️ A scan is already running!")
            return
            
        command = self.command_input.text().strip()
        self.status_text.append(f"⚡ Running: {command}")
        self.run_button.setEnabled(False)
        self.run_button.setText("Scanning...")
        
        self.scan_worker = ScanWorker(command)
        self.scan_worker.finished.connect(self.scan_complete)
        self.scan_worker.error.connect(self.scan_error)
        self.scan_worker.start()

    def scan_complete(self, result):
        self.status_text.append("✅ Scan complete.\n")
        self.parse_output(result)
        self.run_button.setEnabled(True)
        self.run_button.setText("Run Scan")
        
    def scan_error(self, error_msg):
        self.status_text.append(f"❌ Error:\n{error_msg}")
        if "sudo: a password is required" in error_msg:
            QMessageBox.warning(self, "Sudo Required", 
                "You need to run 'sudo arp-scan' in terminal first to cache your password.\n\n"
                "This is a one-time setup. After that, the GUI will work without asking for a password!")
        self.run_button.setEnabled(True)
        self.run_button.setText("Run Scan")

    def parse_output(self, output):
        print(f"Parsing output: {output[:100]}...")  # Debug print
        self.output_table.setRowCount(0)
        lines = output.splitlines()
        for line in lines:
            print(f"Processing line: {line}")  # Debug print
            if "\t" in line and line.count("\t") >= 2:
                parts = line.split("\t")
                ip = parts[0]
                mac = parts[1]
                vendor = parts[2] if len(parts) > 2 else "(Unknown)"
                
                # Only mark as suspicious if it's a new device with an unknown vendor
                if mac not in self.known_devices and vendor == "(Unknown)":
                    self.known_devices.add(mac)
                    self.status_text.append(f"WARNING: New unknown device detected: {mac}")
                    
                    # Create custom buttons
                    msg = QMessageBox(self)
                    msg.setWindowTitle("New Device Detected")
                    msg.setText(f"WARNING: A new unknown device was found:\n\nMAC: {mac}\nIP: {ip}\nVendor: {vendor}")
                    
                    # Add custom buttons
                    diagnostics_btn = msg.addButton("🔍 Run Diagnostics", QMessageBox.ActionRole)
                    block_btn = msg.addButton("🚫 Block Device", QMessageBox.ActionRole)
                    ignore_btn = msg.addButton("✅ Ignore", QMessageBox.ActionRole)
                    
                    msg.exec_()
                    
                    # Handle button clicks
                    if msg.clickedButton() == diagnostics_btn:
                        dialog = DiagnosticWindow(ip, mac, vendor, self)
                        dialog.exec_()
                    elif msg.clickedButton() == block_btn:
                        self.status_text.append(f"🚫 Device {mac} marked for blocking (manual block required via router)")
                
                row_pos = self.output_table.rowCount()
                self.output_table.insertRow(row_pos)
                self.output_table.setItem(row_pos, 0, QTableWidgetItem(ip))
                self.output_table.setItem(row_pos, 1, QTableWidgetItem(mac))
                self.output_table.setItem(row_pos, 2, QTableWidgetItem(vendor))

    def show_diagnostics(self, row, col):
        ip = self.output_table.item(row, 0).text()
        mac = self.output_table.item(row, 1).text()
        vendor = self.output_table.item(row, 2).text()
        dialog = DiagnosticWindow(ip, mac, vendor, self)
        dialog.exec_()

class BluetoothScanWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, command):
        super().__init__()
        self.command = command
        
    def run(self):
        try:
            print(f"Running Bluetooth command: {self.command}")
            result = subprocess.check_output(self.command, shell=True, stderr=subprocess.STDOUT, text=True)
            print(f"Got Bluetooth result: {result[:100]}...")
            self.finished.emit(result)
        except subprocess.CalledProcessError as e:
            error_msg = str(e.output)
            print(f"Bluetooth error occurred: {error_msg}")
            self.error.emit(error_msg)
        except Exception as e:
            print(f"Unexpected Bluetooth error: {e}")
            self.error.emit(str(e))

class BluetoothScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.known_devices = set()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()

        self.command_label = QLabel("Bluetooth Scan Command:")
        layout.addWidget(self.command_label)

        self.command_input = QLineEdit()
        self.command_input.setText(DEFAULT_BT_COMMAND)
        self.command_input.setFont(QFont("Courier", 10))
        layout.addWidget(self.command_input)

        button_layout = QHBoxLayout()
        self.run_button = QPushButton("Start Bluetooth Scan")
        self.reset_button = QPushButton("Reset to Default")
        button_layout.addWidget(self.run_button)
        button_layout.addWidget(self.reset_button)
        layout.addLayout(button_layout)

        self.output_table = QTableWidget()
        self.output_table.setColumnCount(3)
        self.output_table.setHorizontalHeaderLabels(["Device Name", "MAC Address", "Signal Strength"])
        self.output_table.cellClicked.connect(self.show_diagnostics)
        layout.addWidget(self.output_table)

        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.status_text)

        self.run_button.clicked.connect(self.run_scan)
        self.reset_button.clicked.connect(self.reset_command)

        self.setLayout(layout)

    def reset_command(self):
        self.command_input.setText(DEFAULT_BT_COMMAND)
        self.status_text.append("Reset to default Bluetooth command.")

    def run_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.status_text.append("A Bluetooth scan is already running!")
            return
            
        command = self.command_input.text().strip()
        self.status_text.append(f"Running Bluetooth scan: {command}")
        self.run_button.setEnabled(False)
        self.run_button.setText("Scanning...")
        
        self.scan_worker = BluetoothScanWorker(command)
        self.scan_worker.finished.connect(self.scan_complete)
        self.scan_worker.error.connect(self.scan_error)
        self.scan_worker.start()

    def scan_complete(self, result):
        self.status_text.append("Bluetooth scan complete.\n")
        self.parse_output(result)
        self.run_button.setEnabled(True)
        self.run_button.setText("Start Bluetooth Scan")
        
    def scan_error(self, error_msg):
        self.status_text.append(f"Error:\n{error_msg}")
        self.run_button.setEnabled(True)
        self.run_button.setText("Start Bluetooth Scan")

    def parse_output(self, output):
        print(f"Parsing Bluetooth output: {output[:100]}...")
        self.output_table.setRowCount(0)
        lines = output.splitlines()
        for line in lines:
            if "Device" in line:
                parts = line.split()
                if len(parts) >= 2:
                    mac = parts[1]
                    name = " ".join(parts[2:]) if len(parts) > 2 else "(Unknown)"
                    signal = "N/A"  # We'll need to parse this from the output
                    
                    if mac not in self.known_devices:
                        self.known_devices.add(mac)
                        self.status_text.append(f"WARNING: New Bluetooth device detected: {name} ({mac})")
                        
                        msg = QMessageBox(self)
                        msg.setWindowTitle("New Bluetooth Device Detected")
                        msg.setText(f"WARNING: A new Bluetooth device was found:\n\nName: {name}\nMAC: {mac}")
                        
                        diagnostics_btn = msg.addButton("Run Diagnostics", QMessageBox.ActionRole)
                        block_btn = msg.addButton("Block Device", QMessageBox.ActionRole)
                        ignore_btn = msg.addButton("Ignore", QMessageBox.ActionRole)
                        
                        msg.exec_()
                        
                        if msg.clickedButton() == block_btn:
                            self.status_text.append(f"Device {mac} marked for blocking")
                    
                    row_pos = self.output_table.rowCount()
                    self.output_table.insertRow(row_pos)
                    self.output_table.setItem(row_pos, 0, QTableWidgetItem(name))
                    self.output_table.setItem(row_pos, 1, QTableWidgetItem(mac))
                    self.output_table.setItem(row_pos, 2, QTableWidgetItem(signal))

    def show_diagnostics(self, row, col):
        name = self.output_table.item(row, 0).text()
        mac = self.output_table.item(row, 1).text()
        dialog = DiagnosticWindow("N/A", mac, name, self)
        dialog.exec_()

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner - Hacker Mode 🐾")
        self.setGeometry(300, 300, 800, 600)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Mode switcher
        mode_layout = QHBoxLayout()
        self.wifi_btn = QPushButton("WiFi Mode")
        self.bluetooth_btn = QPushButton("Bluetooth Mode")
        self.wifi_btn.setCheckable(True)
        self.bluetooth_btn.setCheckable(True)
        self.wifi_btn.setChecked(True)
        mode_layout.addWidget(self.wifi_btn)
        mode_layout.addWidget(self.bluetooth_btn)
        layout.addLayout(mode_layout)
        
        # Stacked widget for switching between modes
        self.stacked_widget = QStackedWidget()
        self.wifi_scanner = LANScanner()
        self.bluetooth_scanner = BluetoothScanner()
        self.stacked_widget.addWidget(self.wifi_scanner)
        self.stacked_widget.addWidget(self.bluetooth_scanner)
        layout.addWidget(self.stacked_widget)
        
        # Connect mode buttons
        self.wifi_btn.clicked.connect(lambda: self.switch_mode(0))
        self.bluetooth_btn.clicked.connect(lambda: self.switch_mode(1))
        
        self.setLayout(layout)
    
    def switch_mode(self, index):
        self.stacked_widget.setCurrentIndex(index)
        self.wifi_btn.setChecked(index == 0)
        self.bluetooth_btn.setChecked(index == 1)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())