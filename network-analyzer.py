import sys
import os
import time
import socket
import psutil
import threading
import subprocess
from datetime import datetime

# --- GUI IMPORTS ---
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QStackedWidget, 
                             QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
                             QProgressBar, QMessageBox, QDialog, QTextEdit, QLineEdit,
                             QScrollArea, QSizePolicy)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QPropertyAnimation, QUrl
from PyQt6.QtGui import QDesktopServices, QColor, QFont, QCursor

# --- SMART IMPORT SYSTEM (Fault Tolerance) ---
# We try to import libraries. If they fail, we note them down but don't crash.
MISSING_LIBS = []

try:
    import requests
except ImportError:
    MISSING_LIBS.append("requests")

try:
    import speedtest
except ImportError:
    MISSING_LIBS.append("speedtest-cli")

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    MISSING_LIBS.append("python-nmap")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, sr1, conf
    conf.verb = 0 # Silence scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    MISSING_LIBS.append("scapy")

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    MISSING_LIBS.append("python-whois")

try:
    from reportlab.pdfgen import canvas
    HAS_PDF = True
except ImportError:
    HAS_PDF = False
    MISSING_LIBS.append("reportlab")


# --- STYLING ---
DARK_THEME = """
QMainWindow { background-color: #1e1e2e; }
QWidget { font-family: 'Segoe UI', sans-serif; font-size: 13px; color: #cdd6f4; }
QFrame#Sidebar { background-color: #11111b; border-right: 1px solid #313244; }
QFrame#Card { background-color: #181825; border-radius: 12px; border: 1px solid #313244; }
QPushButton { background-color: #313244; border: none; padding: 10px; border-radius: 6px; text-align: left; }
QPushButton:hover { background-color: #45475a; }
QPushButton:checked { background-color: #89b4fa; color: #1e1e2e; font-weight: bold; }
QPushButton#ActionButton { background-color: #89b4fa; color: #1e1e2e; font-weight: bold; text-align: center; }
QPushButton#ActionButton:hover { background-color: #b4befe; }
QPushButton#InfoBtn { background-color: transparent; border: 1px solid #585b70; border-radius: 15px; color: #585b70; font-weight: bold; }
QPushButton#InfoBtn:hover { border-color: #89b4fa; color: #89b4fa; }
QLabel#Header { font-size: 22px; font-weight: bold; color: #89b4fa; }
QLabel#SubHeader { font-size: 16px; font-weight: bold; color: #a6adc8; }
QLineEdit { background-color: #313244; border: 1px solid #45475a; border-radius: 5px; padding: 8px; color: white; }
QTextEdit { background-color: #11111b; border: 1px solid #313244; border-radius: 5px; font-family: 'Consolas', monospace; color: #a6e3a1; }
QProgressBar { background-color: #313244; border-radius: 5px; text-align: center; }
QProgressBar::chunk { background-color: #89b4fa; border-radius: 5px; }
QTableWidget { background-color: #181825; gridline-color: #313244; border: none; }
QHeaderView::section { background-color: #313244; padding: 4px; border: none; }
"""

# --- WORKER THREADS ---

class SpeedTestWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    def run(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            d = st.download() / 1_000_000
            u = st.upload() / 1_000_000
            p = st.results.ping
            self.finished.emit({"d": d, "u": u, "p": p})
        except Exception as e: self.error.emit(str(e))

class ScanWorker(QThread):
    finished = pyqtSignal(list)
    def run(self):
        if not HAS_NMAP: return
        nm = nmap.PortScanner()
        # Simple subnet detection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            subnet = ".".join(ip.split('.')[:-1]) + ".0/24"
        except: subnet = "192.168.1.0/24"
        
        try:
            nm.scan(hosts=subnet, arguments='-sn')
            res = []
            for h in nm.all_hosts():
                if 'mac' in nm[h]['addresses']:
                    mac = nm[h]['addresses']['mac']
                    vendor = nm[h]['vendor'].get(mac, "Unknown")
                else: mac, vendor = "Requires Sudo", "-"
                res.append([h, mac, vendor, nm[h]['status']['state']])
            self.finished.emit(res)
        except: self.finished.emit([])

class SnifferWorker(QThread):
    packet_received = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        if not HAS_SCAPY: return
        def callback(pkt):
            if not self.running: return
            try:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    proto = pkt[IP].proto
                    ln = len(pkt)
                    p_name = "TCP" if proto == 6 else "UDP" if proto == 17 else "ICMP" if proto == 1 else str(proto)
                    self.packet_received.emit(f"[{p_name}] {src} -> {dst} | Len: {ln}")
            except: pass
        
        # Sniff on eth0 (standard for ChromeOS container)
        try:
            sniff(iface="eth0", prn=callback, store=0, stop_filter=lambda x: not self.running)
        except:
            self.packet_received.emit("Error: Could not start sniffer. Need Sudo?")

    def stop(self):
        self.running = False

class WhoisWorker(QThread):
    finished = pyqtSignal(str)
    def __init__(self, domain):
        super().__init__()
        self.domain = domain
    def run(self):
        if not HAS_WHOIS: return
        try:
            w = whois.whois(self.domain)
            self.finished.emit(str(w))
        except Exception as e:
            self.finished.emit(f"Lookup failed: {e}")

# --- DIALOGS ---

class DependencyDialog(QDialog):
    def __init__(self, missing_libs):
        super().__init__()
        self.setWindowTitle("Optional Features Missing")
        self.setStyleSheet(DARK_THEME)
        self.setFixedSize(500, 300)
        
        layout = QVBoxLayout(self)
        
        title = QLabel("⚠️ Missing Optional Components")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #fab387;")
        layout.addWidget(title)
        
        msg = QLabel("Some advanced features (Nmap, Sniffer, etc.) are disabled because libraries are missing.\nDon't worry! The app will still work.")
        msg.setWordWrap(True)
        layout.addWidget(msg)
        
        # Command Box
        cmd_box = QFrame()
        cmd_box.setStyleSheet("background-color: #11111b; padding: 10px; border-radius: 5px;")
        cmd_layout = QVBoxLayout(cmd_box)
        
        cmd_str = f"pip install {' '.join(missing_libs)} --break-system-packages"
        if "python-nmap" in missing_libs: cmd_str = cmd_str.replace("python-nmap", "python-nmap") # Just to ensure
        
        lbl_cmd = QLabel(f"Run this to fix:\n\n{cmd_str}")
        lbl_cmd.setStyleSheet("font-family: monospace; color: #a6e3a1;")
        lbl_cmd.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cmd_layout.addWidget(lbl_cmd)
        layout.addWidget(cmd_box)
        
        btn_layout = QHBoxLayout()
        self.btn_skip = QPushButton("Skip (Run App)")
        self.btn_skip.clicked.connect(self.accept)
        
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_skip)
        layout.addLayout(btn_layout)

class AboutDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("About Net Analyzer")
        self.setStyleSheet(DARK_THEME)
        self.setFixedSize(400, 400)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Icon (Text based for simplicity)
        icon = QLabel("🌐")
        icon.setStyleSheet("font-size: 60px;")
        layout.addWidget(icon, alignment=Qt.AlignmentFlag.AlignCenter)
        
        title = QLabel("Net Analyzer")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #89b4fa;")
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)
        
        info_frame = QFrame()
        info_frame.setObjectName("Card")
        info_layout = QVBoxLayout(info_frame)
        
        details = [
            ("Package Type:", "Highly Compatible"),
            ("Version:", "3.2.1"),
            ("Developer:", "M. Farhan Hamim")
        ]
        
        for k, v in details:
            row = QHBoxLayout()
            lbl_k = QLabel(k)
            lbl_k.setStyleSheet("color: #a6adc8; font-weight: bold;")
            lbl_v = QLabel(v)
            lbl_v.setStyleSheet("color: #cdd6f4;")
            row.addWidget(lbl_k)
            row.addStretch()
            row.addWidget(lbl_v)
            info_layout.addLayout(row)
            
        layout.addWidget(info_frame)
        
        comment = QLabel("This is an open source project. Feel free to contribute!")
        comment.setWordWrap(True)
        comment.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(comment)
        
        btn_contrib = QPushButton("Click here to Contribute")
        btn_contrib.setObjectName("ActionButton")
        btn_contrib.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://psbdx.xo.je/net-analyzer/contribute")))
        layout.addWidget(btn_contrib)
        
        footer = QLabel("Made with ❤ by PSBDx")
        footer.setStyleSheet("color: #f38ba8; font-size: 11px;")
        layout.addWidget(footer, alignment=Qt.AlignmentFlag.AlignCenter)

# --- MAIN APPLICATION ---

class NetAnalyzerPro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Net Analyzer v3.2.1 [Pro]")
        self.resize(1100, 750)
        self.setStyleSheet(DARK_THEME)
        
        # Check Dependencies on Load
        if MISSING_LIBS:
            dlg = DependencyDialog(MISSING_LIBS)
            dlg.exec()

        # Layouts
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        self.main_layout = QHBoxLayout(main_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        
        self.setup_sidebar()
        
        # Content Area
        self.stack = QStackedWidget()
        self.main_layout.addWidget(self.stack)
        
        # Initialize Pages
        self.page_dashboard = self.create_dashboard()
        self.page_speed = self.create_speed_page()
        self.page_scan = self.create_scan_page()
        self.page_tools = self.create_tools_page()
        
        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_speed)
        self.stack.addWidget(self.page_scan)
        self.stack.addWidget(self.page_tools)
        
        # Background Tasks
        self.traffic_timer = QTimer()
        self.traffic_timer.timeout.connect(self.update_traffic)
        self.traffic_timer.start(1000)
        self.last_io = psutil.net_io_counters()

    def setup_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(240)
        layout = QVBoxLayout(sidebar)
        layout.setSpacing(10)
        
        # Top Header
        header_layout = QHBoxLayout()
        title = QLabel("NET ANALYZER")
        title.setStyleSheet("font-weight: 900; font-size: 18px; color: #89b4fa;")
        
        # I Button
        btn_info = QPushButton("i")
        btn_info.setObjectName("InfoBtn")
        btn_info.setFixedSize(30, 30)
        btn_info.clicked.connect(self.show_about)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(btn_info)
        layout.addLayout(header_layout)
        
        layout.addSpacing(20)
        
        # Nav Buttons
        self.nav_btns = []
        labels = ["📊 Dashboard", "🚀 Speed Test", "📡 Device Scanner", "🛠️ Pro Tools"]
        for i, txt in enumerate(labels):
            btn = QPushButton(txt)
            btn.setCheckable(True)
            if i == 0: btn.setChecked(True)
            btn.clicked.connect(lambda checked, idx=i, b=btn: self.switch_tab(idx, b))
            layout.addWidget(btn)
            self.nav_btns.append(btn)
            
        layout.addStretch()
        
        # Footer
        footer = QLabel("Made with ❤ by PSBDx")
        footer.setStyleSheet("color: #585b70; font-size: 10px;")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer)
        
        self.main_layout.addWidget(sidebar)

    def switch_tab(self, index, active_btn):
        for btn in self.nav_btns:
            btn.setChecked(False)
        active_btn.setChecked(True)
        self.stack.setCurrentIndex(index)

    def show_about(self):
        dlg = AboutDialog()
        dlg.exec()

    # --- DASHBOARD ---
    def create_dashboard(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        layout.addWidget(QLabel("Network Overview", objectName="Header"))
        
        # Cards Layout
        cards = QHBoxLayout()
        
        # Traffic Card
        t_card = QFrame(objectName="Card")
        t_layout = QVBoxLayout(t_card)
        self.lbl_dl = QLabel("↓ 0.00 KB/s")
        self.lbl_dl.setStyleSheet("font-size: 20px; color: #a6e3a1; font-weight: bold;")
        self.lbl_ul = QLabel("↑ 0.00 KB/s")
        self.lbl_ul.setStyleSheet("font-size: 20px; color: #f38ba8; font-weight: bold;")
        t_layout.addWidget(QLabel("REAL-TIME TRAFFIC"))
        t_layout.addWidget(self.lbl_dl)
        t_layout.addWidget(self.lbl_ul)
        cards.addWidget(t_card)
        
        # IP Card
        i_card = QFrame(objectName="Card")
        i_layout = QVBoxLayout(i_card)
        self.lbl_ip = QLabel("Public IP: Fetching...")
        self.lbl_local = QLabel("Local IP: Fetching...")
        i_layout.addWidget(QLabel("IDENTITY"))
        i_layout.addWidget(self.lbl_ip)
        i_layout.addWidget(self.lbl_local)
        cards.addWidget(i_card)
        
        layout.addLayout(cards)
        layout.addStretch()
        
        # Fetch IP logic
        threading.Thread(target=self.fetch_ip_data, daemon=True).start()
        
        return page

    def update_traffic(self):
        io = psutil.net_io_counters()
        d = io.bytes_recv - self.last_io.bytes_recv
        u = io.bytes_sent - self.last_io.bytes_sent
        self.last_io = io
        self.lbl_dl.setText(f"↓ {d/1024:.2f} KB/s")
        self.lbl_ul.setText(f"↑ {u/1024:.2f} KB/s")

    def fetch_ip_data(self):
        try:
            r = requests.get('http://ip-api.com/json/', timeout=3).json()
            self.lbl_ip.setText(f"Public: {r.get('query')} ({r.get('isp')})")
        except: self.lbl_ip.setText("Public: Offline")
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.lbl_local.setText(f"Local: {s.getsockname()[0]}")
            s.close()
        except: pass

    # --- SPEED TEST ---
    def create_speed_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        layout.addWidget(QLabel("Speed Test", objectName="Header"))
        
        self.btn_run_speed = QPushButton("Start Test")
        self.btn_run_speed.setObjectName("ActionButton")
        self.btn_run_speed.setFixedWidth(200)
        self.btn_run_speed.clicked.connect(self.run_speed)
        
        self.speed_log = QTextEdit()
        self.speed_log.setReadOnly(True)
        self.speed_log.setText("Ready to test...")
        
        layout.addWidget(self.btn_run_speed)
        layout.addWidget(self.speed_log)
        
        return page

    def run_speed(self):
        self.speed_log.setText("Running speedtest... This may take 20 seconds...")
        self.btn_run_speed.setEnabled(False)
        self.sw = SpeedTestWorker()
        self.sw.finished.connect(self.speed_done)
        self.sw.start()

    def speed_done(self, res):
        self.btn_run_speed.setEnabled(True)
        txt = f"=== RESULTS ===\nDOWNLOAD: {res['d']:.2f} Mbps\nUPLOAD:   {res['u']:.2f} Mbps\nPING:     {res['p']} ms"
        self.speed_log.setText(txt)

    # --- SCANNER ---
    def create_scan_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        layout.addWidget(QLabel("Device Scanner (Nmap)", objectName="Header"))
        
        if not HAS_NMAP:
            layout.addWidget(QLabel("⚠️ Nmap library missing. Please install python-nmap to use this.", styleSheet="color: #f38ba8;"))
            layout.addStretch()
            return page

        self.btn_scan = QPushButton("Scan Network")
        self.btn_scan.setObjectName("ActionButton")
        self.btn_scan.clicked.connect(self.run_scan)
        layout.addWidget(self.btn_scan)
        
        self.scan_table = QTableWidget()
        self.scan_table.setColumnCount(4)
        self.scan_table.setHorizontalHeaderLabels(["IP", "MAC", "Vendor", "Status"])
        self.scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.scan_table)
        
        return page

    def run_scan(self):
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("Scanning...")
        self.scan_table.setRowCount(0)
        self.nw = ScanWorker()
        self.nw.finished.connect(self.scan_done)
        self.nw.start()

    def scan_done(self, rows):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("Scan Network")
        self.scan_table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, val in enumerate(row):
                self.scan_table.setItem(i, j, QTableWidgetItem(val))

    # --- PRO TOOLS (Sniffer & Whois) ---
    def create_tools_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        layout.addWidget(QLabel("Pro Tools", objectName="Header"))
        
        # Tools Tabs
        tabs = QStackedWidget()
        
        # 1. Whois Tool
        whois_w = QWidget()
        wl = QVBoxLayout(whois_w)
        wl.addWidget(QLabel("Domain Intelligence", objectName="SubHeader"))
        
        h_inp_layout = QHBoxLayout()
        self.inp_domain = QLineEdit()
        self.inp_domain.setPlaceholderText("Enter domain (e.g., google.com)")
        self.btn_whois = QPushButton("Lookup")
        self.btn_whois.setObjectName("ActionButton")
        self.btn_whois.clicked.connect(self.run_whois)
        h_inp_layout.addWidget(self.inp_domain)
        h_inp_layout.addWidget(self.btn_whois)
        
        self.txt_whois = QTextEdit()
        wl.addLayout(h_inp_layout)
        wl.addWidget(self.txt_whois)
        
        # 2. Sniffer Tool
        sniff_w = QWidget()
        sl = QVBoxLayout(sniff_w)
        sl.addWidget(QLabel("Packet Sniffer (Matrix Mode)", objectName="SubHeader"))
        
        self.btn_sniff = QPushButton("Start Sniffing")
        self.btn_sniff.setObjectName("ActionButton")
        self.btn_sniff.setCheckable(True)
        self.btn_sniff.clicked.connect(self.toggle_sniff)
        
        self.txt_sniff = QTextEdit()
        self.txt_sniff.setStyleSheet("color: #a6e3a1; font-family: monospace; font-size: 11px;")
        
        sl.addWidget(self.btn_sniff)
        sl.addWidget(self.txt_sniff)
        
        # Splitter
        splitter = QFrame()
        splitter.setFrameShape(QFrame.Shape.HLine)
        splitter.setStyleSheet("color: #313244;")
        
        layout.addWidget(whois_w)
        layout.addWidget(splitter)
        layout.addWidget(sniff_w)
        
        return page

    def run_whois(self):
        if not HAS_WHOIS:
            self.txt_whois.setText("Missing 'python-whois' library.")
            return
        d = self.inp_domain.text()
        if not d: return
        self.txt_whois.setText("Looking up...")
        self.ww = WhoisWorker(d)
        self.ww.finished.connect(lambda s: self.txt_whois.setText(s))
        self.ww.start()

    def toggle_sniff(self, checked):
        if not HAS_SCAPY:
            self.txt_sniff.setText("Missing 'scapy' library or sudo permissions.")
            self.btn_sniff.setChecked(False)
            return

        if checked:
            self.btn_sniff.setText("Stop Sniffing")
            self.btn_sniff.setStyleSheet("background-color: #f38ba8; color: #1e1e2e;")
            self.sniffer = SnifferWorker()
            self.sniffer.packet_received.connect(lambda t: self.txt_sniff.append(t))
            self.sniffer.start()
        else:
            self.btn_sniff.setText("Start Sniffing")
            self.btn_sniff.setStyleSheet("")
            if hasattr(self, 'sniffer'): self.sniffer.stop()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetAnalyzerPro()
    window.show()
    sys.exit(app.exec())