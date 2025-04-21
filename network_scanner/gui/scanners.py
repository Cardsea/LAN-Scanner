from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHBoxLayout, QLineEdit,
    QMessageBox
)
from PyQt5.QtGui import QFont
from .components import DiagnosticWindow
from ..workers import ScanWorker, BluetoothScanWorker

DEFAULT_COMMAND = "sudo -v && sudo arp-scan --interface=en0 10.0.20.0/24"
DEFAULT_BT_COMMAND = "bluetoothctl scan on"

class LANScanner(QWidget):
    def __init__(this):
        super().__init__()
        this.scan_worker = None
        this.known_devices = set()
        this.init_ui()
        
    def init_ui(this):
        layout = QVBoxLayout()

        this.command_label = QLabel("Scan Command:")
        layout.addWidget(this.command_label)

        this.command_input = QLineEdit()
        this.command_input.setText(DEFAULT_COMMAND)
        this.command_input.setFont(QFont("Courier", 10))
        layout.addWidget(this.command_input)

        button_layout = QHBoxLayout()
        this.run_button = QPushButton("Run Scan")
        this.reset_button = QPushButton("Reset to Default")
        button_layout.addWidget(this.run_button)
        button_layout.addWidget(this.reset_button)
        layout.addLayout(button_layout)

        this.output_table = QTableWidget()
        this.output_table.setColumnCount(3)
        this.output_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Vendor"])
        this.output_table.cellClicked.connect(this.show_diagnostics)
        layout.addWidget(this.output_table)

        this.status_text = QTextEdit()
        this.status_text.setReadOnly(True)
        this.status_text.setFont(QFont("Courier", 10))
        layout.addWidget(this.status_text)

        this.run_button.clicked.connect(this.run_scan)
        this.reset_button.clicked.connect(this.reset_command)

        this.setLayout(layout)

    def reset_command(this):
        this.command_input.setText(DEFAULT_COMMAND)
        this.status_text.append("Reset to default command.")

    def run_scan(this):
        if this.scan_worker and this.scan_worker.isRunning():
            this.status_text.append("A scan is already running!")
            return
            
        command = this.command_input.text().strip()
        this.status_text.append(f"Running: {command}")
        this.run_button.setEnabled(False)
        this.run_button.setText("Scanning...")
        
        this.scan_worker = ScanWorker(command)
        this.scan_worker.finished.connect(this.scan_complete)
        this.scan_worker.error.connect(this.scan_error)
        this.scan_worker.start()

    def scan_complete(this, result):
        this.status_text.append("Scan complete.\n")
        this.parse_output(result)
        this.run_button.setEnabled(True)
        this.run_button.setText("Run Scan")
        
    def scan_error(this, error_msg):
        this.status_text.append(f"Error:\n{error_msg}")
        if "sudo: a password is required" in error_msg:
            QMessageBox.warning(this, "Sudo Required", 
                "You need to run 'sudo arp-scan' in terminal first to cache your password.\n\n"
                "This is a one-time setup. After that, the GUI will work without asking for a password!")
        this.run_button.setEnabled(True)
        this.run_button.setText("Run Scan")

    def parse_output(this, output):
        print(f"Parsing output: {output[:100]}...")
        this.output_table.setRowCount(0)
        lines = output.splitlines()
        for line in lines:
            print(f"Processing line: {line}")
            if "\t" in line and line.count("\t") >= 2:
                parts = line.split("\t")
                ip = parts[0]
                mac = parts[1]
                vendor = parts[2] if len(parts) > 2 else "(Unknown)"
                
                if mac not in this.known_devices and vendor == "(Unknown)":
                    this.known_devices.add(mac)
                    this.status_text.append(f"WARNING: New unknown device detected: {mac}")
                    
                    msg = QMessageBox(this)
                    msg.setWindowTitle("New Device Detected")
                    msg.setText(f"WARNING: A new unknown device was found:\n\nMAC: {mac}\nIP: {ip}\nVendor: {vendor}")
                    
                    diagnostics_btn = msg.addButton("Run Diagnostics", QMessageBox.ActionRole)
                    block_btn = msg.addButton("Block Device", QMessageBox.ActionRole)
                    ignore_btn = msg.addButton("Ignore", QMessageBox.ActionRole)
                    
                    msg.exec_()
                    
                    if msg.clickedButton() == diagnostics_btn:
                        dialog = DiagnosticWindow(ip, mac, vendor, this)
                        dialog.exec_()
                    elif msg.clickedButton() == block_btn:
                        this.status_text.append(f"Device {mac} marked for blocking")
                
                row_pos = this.output_table.rowCount()
                this.output_table.insertRow(row_pos)
                this.output_table.setItem(row_pos, 0, QTableWidgetItem(ip))
                this.output_table.setItem(row_pos, 1, QTableWidgetItem(mac))
                this.output_table.setItem(row_pos, 2, QTableWidgetItem(vendor))

    def show_diagnostics(this, row, col):
        ip = this.output_table.item(row, 0).text()
        mac = this.output_table.item(row, 1).text()
        vendor = this.output_table.item(row, 2).text()
        dialog = DiagnosticWindow(ip, mac, vendor, this)
        dialog.exec_()

class BluetoothScanner(QWidget):
    def __init__(this):
        super().__init__()
        this.scan_worker = None
        this.known_devices = set()
        this.init_ui()
        
    def init_ui(this):
        layout = QVBoxLayout()

        this.command_label = QLabel("Bluetooth Scan Command:")
        layout.addWidget(this.command_label)

        this.command_input = QLineEdit()
        this.command_input.setText(DEFAULT_BT_COMMAND)
        this.command_input.setFont(QFont("Courier", 10))
        layout.addWidget(this.command_input)

        button_layout = QHBoxLayout()
        this.run_button = QPushButton("Start Bluetooth Scan")
        this.reset_button = QPushButton("Reset to Default")
        button_layout.addWidget(this.run_button)
        button_layout.addWidget(this.reset_button)
        layout.addLayout(button_layout)

        this.output_table = QTableWidget()
        this.output_table.setColumnCount(3)
        this.output_table.setHorizontalHeaderLabels(["Device Name", "MAC Address", "Signal Strength"])
        this.output_table.cellClicked.connect(this.show_diagnostics)
        layout.addWidget(this.output_table)

        this.status_text = QTextEdit()
        this.status_text.setReadOnly(True)
        this.status_text.setFont(QFont("Courier", 10))
        layout.addWidget(this.status_text)

        this.run_button.clicked.connect(this.run_scan)
        this.reset_button.clicked.connect(this.reset_command)

        this.setLayout(layout)

    def reset_command(this):
        this.command_input.setText(DEFAULT_BT_COMMAND)
        this.status_text.append("Reset to default Bluetooth command.")

    def run_scan(this):
        if this.scan_worker and this.scan_worker.isRunning():
            this.status_text.append("A Bluetooth scan is already running!")
            return
            
        command = this.command_input.text().strip()
        this.status_text.append(f"Running Bluetooth scan: {command}")
        this.run_button.setEnabled(False)
        this.run_button.setText("Scanning...")
        
        this.scan_worker = BluetoothScanWorker(command)
        this.scan_worker.finished.connect(this.scan_complete)
        this.scan_worker.error.connect(this.scan_error)
        this.scan_worker.start()

    def scan_complete(this, result):
        this.status_text.append("Bluetooth scan complete.\n")
        this.parse_output(result)
        this.run_button.setEnabled(True)
        this.run_button.setText("Start Bluetooth Scan")
        
    def scan_error(this, error_msg):
        this.status_text.append(f"Error:\n{error_msg}")
        this.run_button.setEnabled(True)
        this.run_button.setText("Start Bluetooth Scan")

    def parse_output(this, output):
        print(f"Parsing Bluetooth output: {output[:100]}...")
        this.output_table.setRowCount(0)
        lines = output.splitlines()
        for line in lines:
            if "Device" in line:
                parts = line.split()
                if len(parts) >= 2:
                    mac = parts[1]
                    name = " ".join(parts[2:]) if len(parts) > 2 else "(Unknown)"
                    signal = "N/A"  # We'll need to parse this from the output
                    
                    if mac not in this.known_devices:
                        this.known_devices.add(mac)
                        this.status_text.append(f"WARNING: New Bluetooth device detected: {name} ({mac})")
                        
                        msg = QMessageBox(this)
                        msg.setWindowTitle("New Bluetooth Device Detected")
                        msg.setText(f"WARNING: A new Bluetooth device was found:\n\nName: {name}\nMAC: {mac}")
                        
                        diagnostics_btn = msg.addButton("Run Diagnostics", QMessageBox.ActionRole)
                        block_btn = msg.addButton("Block Device", QMessageBox.ActionRole)
                        ignore_btn = msg.addButton("Ignore", QMessageBox.ActionRole)
                        
                        msg.exec_()
                        
                        if msg.clickedButton() == block_btn:
                            this.status_text.append(f"Device {mac} marked for blocking")
                    
                    row_pos = this.output_table.rowCount()
                    this.output_table.insertRow(row_pos)
                    this.output_table.setItem(row_pos, 0, QTableWidgetItem(name))
                    this.output_table.setItem(row_pos, 1, QTableWidgetItem(mac))
                    this.output_table.setItem(row_pos, 2, QTableWidgetItem(signal))

    def show_diagnostics(this, row, col):
        name = this.output_table.item(row, 0).text()
        mac = this.output_table.item(row, 1).text()
        dialog = DiagnosticWindow("N/A", mac, name, this)
        dialog.exec_() 