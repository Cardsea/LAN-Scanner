from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHBoxLayout, QLineEdit,
    QMessageBox, QDialog, QComboBox
)
from PyQt5.QtGui import QFont
from ..workers import ActionWorker

class MACLookupWindow(QDialog):
    def __init__(this, mac, vendor, parent=None):
        super().__init__(parent)
        this.mac = mac
        this.vendor = vendor
        this.worker = None
        this.setWindowTitle(f"MAC Lookup - {mac}")
        this.setGeometry(400, 400, 500, 400)
        this.init_ui()

    def init_ui(this):
        layout = QVBoxLayout()

        info_label = QLabel(f"Analyzing MAC: {this.mac}")
        info_label.setFont(QFont("Courier", 12, QFont.Bold))
        layout.addWidget(info_label)

        if this.vendor and this.vendor != "(Unknown)":
            vendor_label = QLabel(f"Known Vendor: {this.vendor}")
            vendor_label.setFont(QFont("Courier", 10))
            layout.addWidget(vendor_label)

        options_label = QLabel("Lookup Options:")
        options_label.setFont(QFont("Courier", 10))
        layout.addWidget(options_label)

        this.lookup_type = QComboBox()
        this.lookup_type.addItems([
            "Vendor Info",
            "Network Type",
            "Device Type",
            "Full Details"
        ])
        layout.addWidget(this.lookup_type)

        this.output = QTextEdit()
        this.output.setReadOnly(True)
        this.output.setFont(QFont("Courier", 10))
        layout.addWidget(this.output)

        button_layout = QHBoxLayout()
        this.lookup_btn = QPushButton("Lookup")
        this.close_btn = QPushButton("Close")
        button_layout.addWidget(this.lookup_btn)
        button_layout.addWidget(this.close_btn)
        layout.addLayout(button_layout)

        this.lookup_btn.clicked.connect(this.do_lookup)
        this.close_btn.clicked.connect(this.close)

        this.setLayout(layout)

    def do_lookup(this):
        if this.worker and this.worker.isRunning():
            this.output.append("A lookup is already running!")
            return
            
        this.output.clear()
        lookup_type = this.lookup_type.currentText()
        this.output.append(f"Looking up {lookup_type} for {this.mac}...")
        this.lookup_btn.setEnabled(False)
        this.lookup_btn.setText("Looking up...")
        
        if lookup_type == "Vendor Info":
            url = f"https://api.macvendors.com/{this.mac}"
        elif lookup_type == "Network Type":
            url = f"https://api.macvendors.com/{this.mac}/network"
        elif lookup_type == "Device Type":
            url = f"https://api.macvendors.com/{this.mac}/device"
        else:  # Full Details
            url = f"https://api.macvendors.com/{this.mac}/full"
            
        this.worker = ActionWorker("mac_lookup", url)
        this.worker.finished.connect(this.handle_result)
        this.worker.error.connect(this.handle_error)
        this.worker.start()

    def handle_result(this, result):
        try:
            data = json.loads(result)
            if "errors" in data or result == "Not Found":
                this.output.append("MAC Address not found in online database")
                if this.vendor and this.vendor != "(Unknown)":
                    this.output.append(f"But we know it's from: {this.vendor}")
                this.output.append("Try checking these instead:")
                this.output.append("  • Check if MAC is valid")
                this.output.append("  • Try a different lookup service")
                this.output.append("  • Device might be too new/unknown")
            else:
                lookup_type = this.lookup_type.currentText()
                if lookup_type == "Vendor Info":
                    this.output.append(f"Vendor Info:\n{data.get('vendor', this.vendor or 'Unknown')}")
                elif lookup_type == "Network Type":
                    this.output.append(f"Network Type:\n{data.get('network_type', 'Unknown')}")
                elif lookup_type == "Device Type":
                    this.output.append(f"Device Type:\n{data.get('device_type', 'Unknown')}")
                else:  # Full Details
                    this.output.append("Full Device Details:")
                    for key, value in data.items():
                        this.output.append(f"  • {key}: {value}")
        except json.JSONDecodeError:
            if result == "Not Found" and this.vendor and this.vendor != "(Unknown)":
                this.output.append(f"Known Vendor: {this.vendor}")
            else:
                this.output.append(f"Raw Response:\n{result}")
        
        this.lookup_btn.setEnabled(True)
        this.lookup_btn.setText("Lookup")

    def handle_error(this, error_msg):
        this.output.append(f"Error: {error_msg}")
        this.lookup_btn.setEnabled(True)
        this.lookup_btn.setText("Lookup")

class DiagnosticWindow(QDialog):
    def __init__(this, ip, mac, vendor, parent=None):
        super().__init__(parent)
        this.ip = ip
        this.mac = mac
        this.vendor = vendor
        this.worker = None
        this.setWindowTitle(f"Network Diagnostics - {ip}")
        this.setGeometry(400, 400, 600, 400)
        this.init_ui()

    def init_ui(this):
        layout = QVBoxLayout()

        info_label = QLabel(f"IP: {this.ip}\nMAC: {this.mac}")
        info_label.setFont(QFont("Courier", 10))
        layout.addWidget(info_label)

        this.ping_btn = QPushButton("Ping Host")
        this.mac_lookup_btn = QPushButton("MAC Vendor Lookup")
        this.connect_btn = QPushButton("Test Connection (Port 80)")
        
        layout.addWidget(this.ping_btn)
        layout.addWidget(this.mac_lookup_btn)
        layout.addWidget(this.connect_btn)

        this.output = QTextEdit()
        this.output.setReadOnly(True)
        this.output.setFont(QFont("Courier", 10))
        layout.addWidget(this.output)

        this.ping_btn.clicked.connect(this.ping_host)
        this.mac_lookup_btn.clicked.connect(this.lookup_mac)
        this.connect_btn.clicked.connect(this.test_connection)

        this.setLayout(layout)

    def ping_host(this):
        if this.worker and this.worker.isRunning():
            this.output.append("A ping is already running!")
            return
            
        this.output.append("Pinging host...")
        this.ping_btn.setEnabled(False)
        this.ping_btn.setText("Pinging...")
        
        this.worker = ActionWorker("ping", this.ip)
        this.worker.finished.connect(this.handle_ping_result)
        this.worker.error.connect(this.handle_ping_error)
        this.worker.start()

    def handle_ping_result(this, result):
        this.output.append(result)
        this.ping_btn.setEnabled(True)
        this.ping_btn.setText("Ping Host")

    def handle_ping_error(this, error_msg):
        this.output.append(f"Error: {error_msg}")
        this.ping_btn.setEnabled(True)
        this.ping_btn.setText("Ping Host")

    def lookup_mac(this):
        dialog = MACLookupWindow(this.mac, this.vendor, this)
        dialog.exec_()

    def test_connection(this):
        if this.worker and this.worker.isRunning():
            this.output.append("A connection test is already running!")
            return
            
        this.output.append("Testing connection...")
        this.connect_btn.setEnabled(False)
        this.connect_btn.setText("Testing...")
        
        this.worker = ActionWorker("connect", this.ip)
        this.worker.finished.connect(this.handle_connect_result)
        this.worker.error.connect(this.handle_connect_error)
        this.worker.start()

    def handle_connect_result(this, result):
        this.output.append(result)
        this.connect_btn.setEnabled(True)
        this.connect_btn.setText("Test Connection (Port 80)")

    def handle_connect_error(this, error_msg):
        this.output.append(f"Error: {error_msg}")
        this.connect_btn.setEnabled(True)
        this.connect_btn.setText("Test Connection (Port 80)") 