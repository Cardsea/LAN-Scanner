from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QHBoxLayout, QStackedWidget
from .scanners import LANScanner, BluetoothScanner

class MainWindow(QWidget):
    def __init__(this):
        super().__init__()
        this.setWindowTitle("Network Scanner - Hacker Mode 🐾")
        this.setGeometry(300, 300, 800, 600)
        this.init_ui()
        
    def init_ui(this):
        layout = QVBoxLayout()
        
        # Mode switcher
        mode_layout = QHBoxLayout()
        this.wifi_btn = QPushButton("WiFi Mode")
        this.bluetooth_btn = QPushButton("Bluetooth Mode")
        this.wifi_btn.setCheckable(True)
        this.bluetooth_btn.setCheckable(True)
        this.wifi_btn.setChecked(True)
        mode_layout.addWidget(this.wifi_btn)
        mode_layout.addWidget(this.bluetooth_btn)
        layout.addLayout(mode_layout)
        
        # Stacked widget for switching between modes
        this.stacked_widget = QStackedWidget()
        this.wifi_scanner = LANScanner()
        this.bluetooth_scanner = BluetoothScanner()
        this.stacked_widget.addWidget(this.wifi_scanner)
        this.stacked_widget.addWidget(this.bluetooth_scanner)
        layout.addWidget(this.stacked_widget)
        
        # Connect mode buttons
        this.wifi_btn.clicked.connect(lambda: this.switch_mode(0))
        this.bluetooth_btn.clicked.connect(lambda: this.switch_mode(1))
        
        this.setLayout(layout)
    
    def switch_mode(this, index):
        this.stacked_widget.setCurrentIndex(index)
        this.wifi_btn.setChecked(index == 0)
        this.bluetooth_btn.setChecked(index == 1) 