#!/usr/bin/env python3
"""
CyberRecon Pro v3.0 — Advanced Cybersecurity Reconnaissance & Vulnerability Platform
─────────────────────────────────────────────────────────────────────────────────────
Advanced Features Added in v3.0:
  • Multi-target batch scanning with queue management
  • CVE database integration with CVSS score lookup
  • SSL/TLS certificate analysis & misconfiguration detection
  • OS fingerprinting & banner grabbing
  • DNS reconnaissance (MX, TXT, NS, SPF, DMARC)
  • Firewall & WAF detection
  • Password policy / default credential checks
  • Compliance mapping (PCI-DSS, HIPAA, NIST, CIS)
  • Risk scoring dashboard with heat-map visualization
  • Timeline view of all scan events
  • Scan history & session management with SQLite
  • Diff comparison between two scans
  • Export to JSON / CSV / Markdown in addition to HTML
  • Live packet capture stats (via nmap timing)
  • Network topology map with hop visualization
  • Port state heatmap chart
  • MITRE ATT&CK technique tagging
  • Dark/Light theme toggle
  • Scan profiles: Quick / Full / Stealth / Custom
  • Console filter & keyword search
  • Notification sound & tray icon when scan completes
"""

import sys, os, re, json, csv, sqlite3, base64, hashlib, socket, ssl
import subprocess, threading
import xml.etree.ElementTree as ET
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.colors import LinearSegmentedColormap
from datetime import datetime
from collections import defaultdict

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QListWidget, QListWidgetItem,
    QProgressBar, QGroupBox, QScrollArea, QSplitter, QFrame, QTabWidget,
    QGraphicsDropShadowEffect, QSizePolicy, QComboBox, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QDialog, QDialogButtonBox,
    QSpinBox, QSlider, QToolButton, QMenu, QAction, QMessageBox,
    QFileDialog, QTreeWidget, QTreeWidgetItem, QStackedWidget, QTextBrowser,
    QAbstractItemView, QSystemTrayIcon
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve,
    QSize, QPoint, QRect, QObject, QRunnable, QThreadPool
)
from PyQt5.QtGui import (
    QFont, QColor, QPalette, QTextCursor, QIcon, QPainter, QLinearGradient,
    QBrush, QPen, QPixmap, QRadialGradient, QConicalGradient, QPolygonF,
    QFontDatabase, QPainterPath
)

# ══════════════════════════════════════════════════════════════════════
#  THEME ENGINE
# ══════════════════════════════════════════════════════════════════════
class Theme:
    DARK = {
        "BG":          "#080C18",
        "PANEL":       "#0C1220",
        "CARD":        "#111827",
        "CARD2":       "#0F172A",
        "CYAN":        "#00E5FF",
        "GREEN":       "#10B981",
        "RED":         "#EF4444",
        "ORANGE":      "#F59E0B",
        "PURPLE":      "#8B5CF6",
        "PINK":        "#EC4899",
        "BLUE":        "#3B82F6",
        "TEXT":        "#F1F5F9",
        "TEXT2":       "#94A3B8",
        "BORDER":      "#1E293B",
        "BORDER2":     "#334155",
        "SELECTED":    "#1D4ED8",
        "CONSOLE_BG":  "#050912",
        "CONSOLE_FG":  "#22D3EE",
    }
    LIGHT = {
        "BG":          "#F8FAFC",
        "PANEL":       "#FFFFFF",
        "CARD":        "#F1F5F9",
        "CARD2":       "#E2E8F0",
        "CYAN":        "#0284C7",
        "GREEN":       "#059669",
        "RED":         "#DC2626",
        "ORANGE":      "#D97706",
        "PURPLE":      "#7C3AED",
        "PINK":        "#DB2777",
        "BLUE":        "#2563EB",
        "TEXT":        "#0F172A",
        "TEXT2":       "#475569",
        "BORDER":      "#CBD5E1",
        "BORDER2":     "#94A3B8",
        "SELECTED":    "#DBEAFE",
        "CONSOLE_BG":  "#1E293B",
        "CONSOLE_FG":  "#22D3EE",
    }
    current = DARK

RESULTS_DIR = "results"
DB_PATH     = os.path.join(RESULTS_DIR, "cyberrecon.db")

# ══════════════════════════════════════════════════════════════════════
#  DATABASE LAYER
# ══════════════════════════════════════════════════════════════════════
class Database:
    def __init__(self):
        os.makedirs(RESULTS_DIR, exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._lock = threading.Lock()
        self._init()

    def _init(self):
        c = self.conn.cursor()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            target    TEXT NOT NULL,
            profile   TEXT,
            started   TEXT,
            finished  TEXT,
            status    TEXT DEFAULT 'running',
            summary   TEXT
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id  INTEGER,
            address  TEXT,
            hostname TEXT,
            os_guess TEXT,
            status   TEXT
        );
        CREATE TABLE IF NOT EXISTS ports (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id  INTEGER,
            host     TEXT,
            port     TEXT,
            proto    TEXT,
            service  TEXT,
            version  TEXT,
            state    TEXT,
            banner   TEXT
        );
        CREATE TABLE IF NOT EXISTS vulns (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER,
            host       TEXT,
            service    TEXT,
            port       TEXT,
            risk       TEXT,
            cve        TEXT,
            cvss       REAL,
            title      TEXT,
            mitre_id   TEXT,
            mitre_tech TEXT,
            compliance TEXT
        );
        CREATE TABLE IF NOT EXISTS timeline (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id  INTEGER,
            ts       TEXT,
            stage    TEXT,
            message  TEXT,
            level    TEXT
        );
        """)
        self.conn.commit()

    def new_scan(self, target: str, profile: str) -> int:
        with self._lock:
            c = self.conn.cursor()
            c.execute("INSERT INTO scans(target,profile,started,status) VALUES(?,?,?,?)",
                      (target, profile, datetime.now().isoformat(), "running"))
            self.conn.commit()
            return c.lastrowid

    def finish_scan(self, scan_id: int, summary: dict):
        with self._lock:
            c = self.conn.cursor()
            c.execute("UPDATE scans SET finished=?,status=?,summary=? WHERE id=?",
                      (datetime.now().isoformat(), "complete",
                       json.dumps(summary), scan_id))
            self.conn.commit()

    def add_host(self, scan_id, addr, hostname="", os_guess="", status="up"):
        with self._lock:
            self.conn.execute(
                "INSERT INTO hosts(scan_id,address,hostname,os_guess,status) VALUES(?,?,?,?,?)",
                (scan_id, addr, hostname, os_guess, status))
            self.conn.commit()

    def add_port(self, scan_id, host, port, proto, service, version, state, banner=""):
        with self._lock:
            self.conn.execute(
                "INSERT INTO ports(scan_id,host,port,proto,service,version,state,banner) VALUES(?,?,?,?,?,?,?,?)",
                (scan_id, host, port, proto, service, version, state, banner))
            self.conn.commit()

    def add_vuln(self, scan_id, host, service, port, risk, cve, cvss, title, mitre_id="", mitre_tech="", compliance=""):
        with self._lock:
            self.conn.execute(
                "INSERT INTO vulns(scan_id,host,service,port,risk,cve,cvss,title,mitre_id,mitre_tech,compliance) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, host, service, port, risk, cve, cvss, title, mitre_id, mitre_tech, compliance))
            self.conn.commit()

    def add_timeline(self, scan_id, stage, message, level="info"):
        with self._lock:
            self.conn.execute(
                "INSERT INTO timeline(scan_id,ts,stage,message,level) VALUES(?,?,?,?,?)",
                (scan_id, datetime.now().isoformat(), stage, message, level))
            self.conn.commit()

    def get_all_scans(self):
        c = self.conn.cursor()
        c.execute("SELECT id,target,profile,started,finished,status FROM scans ORDER BY id DESC")
        return c.fetchall()

    def get_scan_vulns(self, scan_id):
        c = self.conn.cursor()
        c.execute("SELECT * FROM vulns WHERE scan_id=?", (scan_id,))
        return c.fetchall()

    def get_scan_ports(self, scan_id):
        c = self.conn.cursor()
        c.execute("SELECT * FROM ports WHERE scan_id=?", (scan_id,))
        return c.fetchall()

DB = Database()

# ══════════════════════════════════════════════════════════════════════
#  CVE / VULN KNOWLEDGE BASE
# ══════════════════════════════════════════════════════════════════════
CVE_DB = {
    "ftp": [
        {"cve":"CVE-2011-2523","cvss":10.0,"title":"vsftpd 2.3.4 Backdoor RCE",
         "mitre":"T1190","tech":"Exploit Public-Facing Application",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
        {"cve":"CVE-1999-0497","cvss":7.5,"title":"FTP Anonymous Login Enabled",
         "mitre":"T1078","tech":"Valid Accounts",
         "compliance":"PCI-DSS:8.2,CIS:4.1"},
    ],
    "ssh": [
        {"cve":"CVE-2018-15473","cvss":5.3,"title":"OpenSSH Username Enumeration",
         "mitre":"T1592","tech":"Gather Victim Identity Information",
         "compliance":"NIST:IA-3,HIPAA:164.312(d)"},
        {"cve":"CVE-2023-38408","cvss":9.8,"title":"OpenSSH Remote Code Execution via ssh-agent",
         "mitre":"T1021.004","tech":"Remote Services: SSH",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
    ],
    "http": [
        {"cve":"CVE-2021-41773","cvss":9.8,"title":"Apache 2.4.49 Path Traversal & RCE",
         "mitre":"T1190","tech":"Exploit Public-Facing Application",
         "compliance":"PCI-DSS:6.4,OWASP:A01"},
        {"cve":"CVE-2021-42013","cvss":9.8,"title":"Apache 2.4.50 RCE (Bypass of CVE-2021-41773)",
         "mitre":"T1059","tech":"Command and Scripting Interpreter",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
    ],
    "https": [
        {"cve":"CVE-2014-0160","cvss":7.5,"title":"OpenSSL Heartbleed Memory Disclosure",
         "mitre":"T1552","tech":"Unsecured Credentials",
         "compliance":"PCI-DSS:4.2.1,HIPAA:164.312(e)"},
        {"cve":"CVE-2016-2107","cvss":5.9,"title":"OpenSSL AES-NI Padding Oracle (POODLE)",
         "mitre":"T1557","tech":"Adversary-in-the-Middle",
         "compliance":"PCI-DSS:4.2.1"},
    ],
    "mysql": [
        {"cve":"CVE-2012-2122","cvss":7.5,"title":"MySQL Authentication Bypass",
         "mitre":"T1078","tech":"Valid Accounts",
         "compliance":"PCI-DSS:8.3,CIS:5.4"},
        {"cve":"CVE-2016-6662","cvss":9.8,"title":"MySQL Remote Code Execution via Config",
         "mitre":"T1190","tech":"Exploit Public-Facing Application",
         "compliance":"PCI-DSS:6.3.3"},
    ],
    "rdp": [
        {"cve":"CVE-2019-0708","cvss":9.8,"title":"BlueKeep – RDP Pre-Auth RCE",
         "mitre":"T1210","tech":"Exploitation of Remote Services",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
        {"cve":"CVE-2019-1182","cvss":9.8,"title":"DejaBlue – RDP Wormable RCE",
         "mitre":"T1210","tech":"Exploitation of Remote Services",
         "compliance":"PCI-DSS:6.3.3"},
    ],
    "smb": [
        {"cve":"CVE-2017-0144","cvss":9.3,"title":"EternalBlue – SMBv1 RCE (WannaCry)",
         "mitre":"T1210","tech":"Exploitation of Remote Services",
         "compliance":"PCI-DSS:6.3.3,CIS:3.3"},
        {"cve":"CVE-2020-0796","cvss":10.0,"title":"SMBGhost – SMBv3 RCE",
         "mitre":"T1210","tech":"Exploitation of Remote Services",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
    ],
    "http-alt": [
        {"cve":"CVE-2020-1938","cvss":9.8,"title":"Ghostcat – Apache Tomcat AJP File RCE",
         "mitre":"T1190","tech":"Exploit Public-Facing Application",
         "compliance":"PCI-DSS:6.3.3,OWASP:A05"},
    ],
    "telnet": [
        {"cve":"CVE-2011-4862","cvss":10.0,"title":"BSD Telnet Remote Command Execution",
         "mitre":"T1021","tech":"Remote Services",
         "compliance":"PCI-DSS:2.2.1,NIST:CM-7"},
    ],
}

MITRE_TACTICS = {
    "T1190": "Initial Access",  "T1078": "Defense Evasion",
    "T1592": "Reconnaissance",  "T1021.004": "Lateral Movement",
    "T1552": "Credential Access","T1557": "Collection",
    "T1210": "Lateral Movement","T1059": "Execution",
    "T1021": "Lateral Movement",
}

# ══════════════════════════════════════════════════════════════════════
#  SCAN PROFILES
# ══════════════════════════════════════════════════════════════════════
SCAN_PROFILES = {
    "Quick":   {"nmap_flags": ["-sV", "-T4", "--top-ports", "100"], "timeout": 60,  "nikto": False, "desc": "Top 100 ports, fast"},
    "Full":    {"nmap_flags": ["-sV", "-sC", "-T4", "-p-"],         "timeout": 600, "nikto": True,  "desc": "All 65535 ports, scripts"},
    "Stealth": {"nmap_flags": ["-sS", "-T2", "--top-ports", "1000"],"timeout": 300, "nikto": False, "desc": "SYN stealth, slow"},
    "Custom":  {"nmap_flags": ["-sV", "-sC", "-T4", "--top-ports", "1000"], "timeout": 180, "nikto": True, "desc": "Balanced default"},
}

# ══════════════════════════════════════════════════════════════════════
#  STYLESHEET BUILDER
# ══════════════════════════════════════════════════════════════════════
def build_stylesheet(t: dict) -> str:
    return f"""
QMainWindow, QWidget {{
    background-color: {t['BG']};
    color: {t['TEXT']};
    font-family: 'JetBrains Mono','Fira Code','Consolas','Courier New',monospace;
    font-size: 12px;
}}
QGroupBox {{
    border: 1px solid {t['BORDER']};
    border-radius: 6px;
    margin-top: 14px;
    padding-top: 6px;
    background-color: {t['CARD']};
    font-weight: bold;
    font-size: 10px;
    color: {t['CYAN']};
    letter-spacing: 1.5px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: {t['CYAN']};
}}
QLineEdit, QSpinBox, QComboBox {{
    background-color: {t['CARD2']};
    border: 1px solid {t['BORDER2']};
    border-radius: 5px;
    padding: 7px 11px;
    color: {t['TEXT']};
    font-size: 12px;
    selection-background-color: {t['CYAN']};
}}
QLineEdit:focus {{ border-color: {t['CYAN']}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {t['CARD']};
    border: 1px solid {t['BORDER']};
    color: {t['TEXT']};
    selection-background-color: {t['SELECTED']};
}}
QPushButton {{
    border-radius: 5px;
    padding: 8px 14px;
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 0.5px;
    border: none;
}}
QPushButton#startBtn {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {t['CYAN']},stop:1 {t['BLUE']});
    color: #000;
}}
QPushButton#startBtn:hover {{ opacity: 0.85; }}
QPushButton#startBtn:disabled {{ background:{t['BORDER']}; color:{t['TEXT2']}; }}
QPushButton#stopBtn {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {t['RED']},stop:1 #991B1B);
    color: #fff;
}}
QPushButton#exportBtn, QPushButton#histBtn, QPushButton#diffBtn {{
    background: {t['CARD2']};
    color: {t['TEXT']};
    border: 1px solid {t['BORDER2']};
}}
QPushButton#exportBtn:hover, QPushButton#histBtn:hover, QPushButton#diffBtn:hover {{
    border-color: {t['CYAN']};
    color: {t['CYAN']};
}}
QPushButton#reportBtn {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {t['GREEN']},stop:1 #065F46);
    color: #fff;
}}
QPushButton#themeBtn {{
    background: {t['CARD2']};
    color: {t['TEXT2']};
    border: 1px solid {t['BORDER']};
    border-radius: 5px;
    padding: 5px 10px;
    font-size: 11px;
}}
QProgressBar {{
    border: 1px solid {t['BORDER']};
    border-radius: 3px;
    background: {t['CARD2']};
    height: 6px;
    color: transparent;
}}
QProgressBar::chunk {{
    border-radius: 3px;
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {t['CYAN']},stop:1 {t['BLUE']});
}}
QTextEdit {{
    background-color: {t['CONSOLE_BG']};
    border: 1px solid {t['BORDER']};
    border-radius: 6px;
    color: {t['CONSOLE_FG']};
    font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: 11.5px;
    padding: 6px;
    selection-background-color: #1E3A5F;
}}
QListWidget {{
    background-color: {t['CARD2']};
    border: 1px solid {t['BORDER']};
    border-radius: 5px;
    color: {t['TEXT']};
    font-size: 11px;
    padding: 3px;
    outline: none;
}}
QListWidget::item {{
    padding: 5px 8px;
    border-radius: 3px;
    border-bottom: 1px solid {t['BORDER']};
}}
QListWidget::item:selected {{ background:{t['SELECTED']}; color:{t['CYAN']}; }}
QListWidget::item:hover {{ background:{t['CARD']}; }}
QTableWidget {{
    background-color: {t['CARD2']};
    gridline-color: {t['BORDER']};
    border: 1px solid {t['BORDER']};
    border-radius: 5px;
    color: {t['TEXT']};
    font-size: 11px;
    outline: none;
}}
QTableWidget::item {{ padding: 5px 8px; }}
QTableWidget::item:selected {{ background:{t['SELECTED']}; color:{t['CYAN']}; }}
QHeaderView::section {{
    background: {t['CARD']};
    color: {t['CYAN']};
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid {t['BORDER']};
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 1px;
}}
QScrollBar:vertical {{
    background: {t['CARD2']};
    width: 7px;
    border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: {t['BORDER2']};
    border-radius: 3px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{ background:{t['CYAN']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0px; }}
QSplitter::handle {{ background:{t['BORDER']}; }}
QTabWidget::pane {{
    border: 1px solid {t['BORDER']};
    background: {t['CARD']};
    border-radius: 0 6px 6px 6px;
}}
QTabBar::tab {{
    background: {t['CARD2']};
    color: {t['TEXT2']};
    padding: 6px 14px;
    border: 1px solid {t['BORDER']};
    border-bottom: none;
    border-radius: 5px 5px 0 0;
    font-size: 10px;
    letter-spacing: 0.8px;
    min-width: 70px;
}}
QTabBar::tab:selected {{ background:{t['CARD']}; color:{t['CYAN']}; border-color:{t['CYAN']}; }}
QTabBar::tab:hover {{ color:{t['TEXT']}; }}
QTreeWidget {{
    background: {t['CARD2']};
    border: 1px solid {t['BORDER']};
    border-radius: 5px;
    color: {t['TEXT']};
    font-size: 11px;
    outline: none;
}}
QTreeWidget::item {{ padding: 4px; }}
QTreeWidget::item:selected {{ background:{t['SELECTED']}; color:{t['CYAN']}; }}
QCheckBox {{ color:{t['TEXT2']}; font-size:11px; spacing: 6px; }}
QCheckBox::indicator {{ width:14px; height:14px; border-radius:3px;
    border:1px solid {t['BORDER2']}; background:{t['CARD2']}; }}
QCheckBox::indicator:checked {{ background:{t['CYAN']}; border-color:{t['CYAN']}; }}
QToolTip {{
    background:{t['CARD']};
    color:{t['TEXT']};
    border:1px solid {t['BORDER']};
    padding:5px;
    border-radius:4px;
}}
"""

# ══════════════════════════════════════════════════════════════════════
#  ADVANCED SCAN ENGINE
# ══════════════════════════════════════════════════════════════════════
class ScanEngine(QThread):
    log_signal      = pyqtSignal(str, str)    # (message, level)
    progress_signal = pyqtSignal(str, int)
    result_signal   = pyqtSignal(str, str, str)  # (container, item, color)
    stage_signal    = pyqtSignal(str)
    chart_signal    = pyqtSignal(dict)
    scan_complete   = pyqtSignal(dict)
    stopped         = pyqtSignal()

    def __init__(self, target: str, profile: str = "Custom", options: dict = None):
        super().__init__()
        self.target   = target
        self.profile  = profile
        self.opts     = options or {}
        self._stop    = False
        self.scan_id  = DB.new_scan(target, profile)
        self.cfg      = SCAN_PROFILES.get(profile, SCAN_PROFILES["Custom"])
        self.data = {
            "scan_id":   self.scan_id,
            "target":    target,
            "profile":   profile,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hosts": [], "services": [], "versions": [], "banners": [],
            "os_guesses": [], "dns_records": [], "ssl_issues": [],
            "vulnerabilities": [], "exploits": [], "attack_paths": [],
            "recommendations": [], "compliance": [],
            "port_states": {}, "risk_counts": {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0},
            "mitre_techniques": [],
        }
        os.makedirs(RESULTS_DIR, exist_ok=True)

    def stop(self):
        self._stop = True

    def log(self, msg, level="info"):
        if self._stop: return
        DB.add_timeline(self.scan_id, self.current_stage if hasattr(self,'current_stage') else "init", msg, level)
        self.log_signal.emit(msg, level)

    def prog(self, bar, val):
        self.progress_signal.emit(bar, val)

    def run_cmd(self, cmd, timeout=120):
        if self._stop: return ""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors='replace')
            return r.stdout + r.stderr
        except FileNotFoundError:
            return f"__NOTFOUND__{cmd[0]}"
        except subprocess.TimeoutExpired:
            return "__TIMEOUT__"
        except Exception as e:
            return f"__ERROR__{e}"

    # ── SSL/TLS Analysis ──────────────────────
    def stage_ssl_analysis(self, hosts):
        self.current_stage = "ssl"
        self.log("━━━ SSL/TLS CERTIFICATE ANALYSIS ━━━", "stage")
        self.stage_signal.emit("SSL/TLS Analysis")
        issues = []

        for host in hosts:
            for port in [443, 8443, 8080]:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            cert = ssock.getpeercert()
                            cipher = ssock.cipher()
                            proto  = ssock.version()

                            # Expiry check
                            if cert and 'notAfter' in cert:
                                exp_str = cert['notAfter']
                                try:
                                    exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                                    days_left = (exp - datetime.utcnow()).days
                                    if days_left < 0:
                                        issues.append(f"⛔ EXPIRED CERT on {host}:{port} (expired {-days_left}d ago)")
                                        self.result_signal.emit("SSL Issues", f"⛔ EXPIRED: {host}:{port}", "#EF4444")
                                    elif days_left < 30:
                                        issues.append(f"⚠ CERT EXPIRING SOON: {host}:{port} ({days_left}d)")
                                        self.result_signal.emit("SSL Issues", f"⚠ EXPIRING: {host}:{port} in {days_left}d", "#F59E0B")
                                    else:
                                        self.log(f"  SSL cert valid: {host}:{port}, {days_left}d remaining", "good")
                                except:
                                    pass

                            # Weak cipher
                            if cipher and cipher[0]:
                                cipher_name = cipher[0]
                                weak = any(x in cipher_name.upper() for x in ["RC4","DES","EXPORT","NULL","ANON"])
                                if weak:
                                    issues.append(f"⚠ WEAK CIPHER on {host}:{port}: {cipher_name}")
                                    self.result_signal.emit("SSL Issues", f"⚠ WEAK CIPHER: {cipher_name}", "#F59E0B")

                            # Old TLS version
                            if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                                issues.append(f"⛔ OLD TLS on {host}:{port}: {proto}")
                                self.result_signal.emit("SSL Issues", f"⛔ OLD PROTOCOL: {host}:{port} {proto}", "#EF4444")

                            self.log(f"  SSL {host}:{port} → {proto}, cipher={cipher[0] if cipher else '?'}", "info")
                except (ConnectionRefusedError, socket.timeout, OSError):
                    pass
                except Exception as e:
                    self.log(f"  SSL check {host}:{port} → {e}", "muted")

        self.data["ssl_issues"] = issues
        if issues:
            for iss in issues:
                self.data["vulnerabilities"].append(iss)
        return issues

    # ── DNS Reconnaissance ────────────────────
    def stage_dns_recon(self):
        self.current_stage = "dns"
        self.log("━━━ DNS RECONNAISSANCE ━━━", "stage")
        self.stage_signal.emit("DNS Recon")
        self.prog("misc", 10)
        is_domain = not re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', self.target)
        records = []

        if not is_domain:
            self.log("  Target is IP – skipping DNS recon", "muted")
            self.prog("misc", 40)
            return records

        record_types = ["A","AAAA","MX","NS","TXT","CNAME","SOA"]
        for rtype in record_types:
            out = self.run_cmd(["dig", "+short", rtype, self.target], timeout=10)
            if "__NOTFOUND__" in out:
                out = self.run_cmd(["nslookup", f"-type={rtype}", self.target], timeout=10)
            if out and "__" not in out:
                for line in out.splitlines():
                    line = line.strip()
                    if line:
                        entry = f"{rtype}: {line}"
                        records.append(entry)
                        self.log(f"  DNS {entry}", "info")
                        self.result_signal.emit("DNS Records", entry, Theme.current["TEXT"])
                        # SPF / DMARC / DKIM checks
                        if rtype == "TXT":
                            if "v=spf1" in line.lower():
                                self.result_signal.emit("DNS Records", "  ✓ SPF record found", Theme.current["GREEN"])
                            if "v=dmarc1" in line.lower():
                                self.result_signal.emit("DNS Records", "  ✓ DMARC policy found", Theme.current["GREEN"])
                            if "v=dkim1" in line.lower():
                                self.result_signal.emit("DNS Records", "  ✓ DKIM record found", Theme.current["GREEN"])
                            if "v=spf1" not in line.lower() and rtype == "TXT" and len(records) > 3:
                                pass  # not a SPF warn here

        # Check missing SPF / DMARC
        has_spf   = any("v=spf1" in r.lower() for r in records)
        has_dmarc = any("v=dmarc1" in r.lower() for r in records)
        if not has_spf:
            records.append("⚠ NO SPF RECORD – email spoofing possible")
            self.result_signal.emit("DNS Records", "⚠ NO SPF – email spoofing risk", Theme.current["ORANGE"])
            self.data["vulnerabilities"].append("⚠ [MEDIUM] Missing SPF record – email spoofing possible")
        if not has_dmarc:
            records.append("⚠ NO DMARC RECORD – phishing risk")
            self.result_signal.emit("DNS Records", "⚠ NO DMARC – phishing risk", Theme.current["ORANGE"])

        self.data["dns_records"] = records
        self.prog("misc", 40)
        return records

    # ── Subdomain Discovery ───────────────────
    def stage_subdomain_discovery(self):
        self.current_stage = "subdomain"
        self.log("━━━ STAGE 1: SUBDOMAIN DISCOVERY ━━━", "stage")
        self.stage_signal.emit("Subdomain Discovery")
        self.prog("host", 5)

        is_domain = not re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', self.target)
        if not is_domain:
            self.log("  IP target – skipping subdomain enum", "muted")
            return [self.target]

        out = self.run_cmd(["subfinder", "-d", self.target, "-silent", "-t", "50"], timeout=60)
        if "__NOTFOUND__" in out:
            self.log("  subfinder not found – using target only", "warn")
            # Fallback: try common subdomains via DNS
            subs = self._brute_common_subdomains()
        else:
            subs = [s.strip() for s in out.splitlines() if s.strip() and "." in s]
            if not subs:
                subs = self._brute_common_subdomains()

        for s in subs[:25]:
            self.log(f"  ▸ Subdomain: {s}", "info")
            self.result_signal.emit("Subdomains", s, Theme.current["PURPLE"])

        self.prog("host", 15)
        return list(dict.fromkeys([self.target] + subs))

    def _brute_common_subdomains(self):
        common = ["www","mail","ftp","vpn","api","dev","staging","admin","portal","remote"]
        found = []
        for sub in common:
            fqdn = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(fqdn)
                found.append(fqdn)
                self.log(f"  ▸ Resolved: {fqdn}", "info")
            except:
                pass
        return found

    # ── Host Discovery ────────────────────────
    def stage_host_discovery(self, targets):
        self.current_stage = "host"
        self.log("━━━ STAGE 2: HOST DISCOVERY ━━━", "stage")
        self.stage_signal.emit("Host Discovery")
        live = []

        for i, t in enumerate(targets):
            if self._stop: break
            self.log(f"  Probing {t}...", "muted")
            out = self.run_cmd(["nmap", "-sn", "-T4", "--open", t], timeout=25)
            if "__NOTFOUND__" in out:
                self.log("  nmap not found – assuming target live", "warn")
                live.append(t)
                DB.add_host(self.scan_id, t, status="assumed")
                self.result_signal.emit("Hosts", f"✦ {t}  [assumed live]", Theme.current["ORANGE"])
                self.data["hosts"].append(t)
                break

            if "Host is up" in out or "1 host up" in out.lower():
                # Try OS guess from nmap
                os_match = re.search(r'OS details: (.+)', out)
                os_str = os_match.group(1).strip() if os_match else ""
                # Hostname resolution
                try:
                    hostname = socket.gethostbyaddr(t)[0]
                except:
                    hostname = ""
                live.append(t)
                DB.add_host(self.scan_id, t, hostname=hostname, os_guess=os_str, status="up")
                label = f"✦ {t}" + (f"  ({hostname})" if hostname else "") + (f"  [{os_str[:30]}]" if os_str else "  [UP]")
                self.result_signal.emit("Hosts", label, Theme.current["GREEN"])
                self.data["hosts"].append(t)
                if os_str:
                    self.data["os_guesses"].append(f"{t} → {os_str}")
                    self.result_signal.emit("OS Fingerprint", f"◈ {t}: {os_str}", Theme.current["CYAN"])
                self.log(f"  ✓ UP: {t}" + (f" ({hostname})" if hostname else ""), "good")
            else:
                self.log(f"  ✗ DOWN/filtered: {t}", "muted")

            self.prog("host", 15 + int((i+1)/max(len(targets),1)*35))

        if not live:
            live = [self.target]
            self.data["hosts"].append(self.target)
            DB.add_host(self.scan_id, self.target, status="forced")
            self.result_signal.emit("Hosts", f"✦ {self.target}  [forced]", Theme.current["ORANGE"])

        self.prog("host", 100)
        return live

    # ── Port / Service / Version Scan ─────────
    def stage_port_scan(self, hosts):
        self.current_stage = "portscan"
        self.log("━━━ STAGE 3-5: PORT / SERVICE / VERSION / OS SCAN ━━━", "stage")
        self.stage_signal.emit("Port + Service Scan")
        services = []

        for idx, host in enumerate(hosts):
            if self._stop: break
            self.log(f"  nmap {self.profile} scan → {host}", "info")
            self.prog("port", 10 + idx * 5)

            flags = self.cfg["nmap_flags"].copy()
            if self.opts.get("os_detect"): flags += ["-O"]
            if self.opts.get("scripts"):   flags += ["--script", "vuln,auth,default"]

            xml_out = os.path.join(RESULTS_DIR, f"nmap_{host.replace('/','_')}.xml")
            cmd = ["nmap"] + flags + ["-oX", xml_out, host]
            out = self.run_cmd(cmd, timeout=self.cfg["timeout"])

            if "__NOTFOUND__" in out:
                self.log("  nmap not found – using mock data", "warn")
                services.extend(self._mock_services(host))
            else:
                parsed = self._parse_nmap_xml(xml_out, host)
                if not parsed:
                    parsed = self._parse_nmap_text(out, host)
                services.extend(parsed)

                # Banner grabbing from nmap output
                self._extract_banners(out, host)

            self.prog("port", 30 + idx * 15)

        # Port state heatmap data
        state_counts = defaultdict(int)
        for s in services:
            state_counts[s.get("service","unknown")] += 1
        self.data["port_states"] = dict(state_counts)

        for svc in services:
            DB.add_port(self.scan_id, svc["host"], svc["port"], svc["proto"],
                        svc["service"], svc["version"], "open", svc.get("banner",""))
            self.result_signal.emit("Services",
                f"⬡ {svc['port']}/{svc['proto']}  {svc['service']}", Theme.current["CYAN"])
            self.result_signal.emit("Versions",
                f"◈ {svc['service']}  {svc['version']}", Theme.current["TEXT"])
            self.data["services"].append(f"{svc['port']}/{svc['proto']} {svc['service']}")
            self.data["versions"].append(f"{svc['service']} {svc['version']}")

        self.prog("port", 100)
        self.prog("service", 100)
        return services

    def _extract_banners(self, nmap_output: str, host: str):
        for line in nmap_output.splitlines():
            if "Service Info:" in line or "| banner:" in line or "_http-title:" in line:
                clean = line.strip()
                if clean:
                    self.data["banners"].append(f"{host}: {clean}")
                    self.result_signal.emit("Banners", f"◉ {host}: {clean[:70]}", Theme.current["TEXT2"])

    def _parse_nmap_xml(self, xml_path: str, host: str):
        if not os.path.exists(xml_path): return []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            results = []
            for h in root.findall("host"):
                addr_el = h.find("address[@addrtype='ipv4']") or h.find("address")
                addr = addr_el.get("addr", host) if addr_el is not None else host
                # OS detection
                osmatch = h.find(".//osmatch")
                if osmatch is not None:
                    os_str = osmatch.get("name","")
                    if os_str and addr not in str(self.data["os_guesses"]):
                        self.data["os_guesses"].append(f"{addr} → {os_str}")
                        self.result_signal.emit("OS Fingerprint", f"◈ {addr}: {os_str}", Theme.current["CYAN"])
                for port_el in h.findall(".//port"):
                    state = port_el.find("state")
                    if state is None or state.get("state") != "open": continue
                    svc_el = port_el.find("service")
                    svc_name = svc_el.get("name","unknown") if svc_el is not None else "unknown"
                    svc_ver  = ""
                    if svc_el is not None:
                        parts = [svc_el.get("product",""), svc_el.get("version",""), svc_el.get("extrainfo","")]
                        svc_ver = " ".join(p for p in parts if p).strip()
                    # Scripts (banner, vuln notes)
                    banner = ""
                    for script in port_el.findall("script"):
                        out_val = script.get("output","")[:200]
                        if out_val: banner = out_val; break
                    results.append({
                        "host": addr, "port": port_el.get("portid","?"),
                        "proto": port_el.get("protocol","tcp"),
                        "service": svc_name, "version": svc_ver, "banner": banner,
                    })
            return results
        except Exception as e:
            self.log(f"  XML parse error: {e}", "warn")
            return []

    def _parse_nmap_text(self, text: str, host: str):
        results = []
        for line in text.splitlines():
            m = re.match(r'\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
            if m:
                results.append({
                    "host": host, "port": m.group(1), "proto": m.group(2),
                    "service": m.group(3), "version": m.group(4).strip(), "banner": "",
                })
        return results

    def _mock_services(self, host: str):
        return [
            {"host":host,"port":"22",  "proto":"tcp","service":"ssh",    "version":"OpenSSH 8.4p1","banner":"SSH-2.0-OpenSSH_8.4"},
            {"host":host,"port":"80",  "proto":"tcp","service":"http",   "version":"Apache httpd 2.4.49","banner":"Apache/2.4.49 (Unix)"},
            {"host":host,"port":"443", "proto":"tcp","service":"https",  "version":"nginx 1.21.3","banner":"nginx/1.21.3"},
            {"host":host,"port":"21",  "proto":"tcp","service":"ftp",    "version":"vsftpd 3.0.3","banner":"220 (vsFTPd 3.0.3)"},
            {"host":host,"port":"3306","proto":"tcp","service":"mysql",  "version":"MySQL 5.7.36","banner":"5.7.36-log"},
            {"host":host,"port":"8080","proto":"tcp","service":"http-alt","version":"Apache Tomcat 9.0.54","banner":""},
            {"host":host,"port":"25",  "proto":"tcp","service":"smtp",   "version":"Postfix smtpd","banner":"220 mail ESMTP Postfix"},
            {"host":host,"port":"3389","proto":"tcp","service":"rdp",    "version":"Microsoft Terminal Services","banner":""},
        ]

    # ── WAF / Firewall Detection ──────────────
    def stage_waf_detection(self, services):
        self.current_stage = "waf"
        self.log("━━━ WAF / FIREWALL DETECTION ━━━", "stage")
        self.stage_signal.emit("WAF Detection")
        web_svcs = [s for s in services if s["service"] in ("http","https","http-alt")]

        for svc in web_svcs[:2]:
            host = svc["host"]; port = svc["port"]
            out = self.run_cmd(["wafw00f", f"http://{host}:{port}", "-a"], timeout=30)
            if "__NOTFOUND__" in out:
                # Manual WAF detection via nmap http headers
                out2 = self.run_cmd(["curl","-sk","-I",f"http://{host}:{port}",
                                     "--max-time","5"], timeout=10)
                if "__NOTFOUND__" not in out2 and out2:
                    waf_headers = ["x-sucuri","x-firewall","x-waf","cf-ray","server: cloudflare",
                                   "x-amz","akamai","incapsula","imperva","barracuda"]
                    detected = [h for h in waf_headers if h in out2.lower()]
                    if detected:
                        msg = f"WAF detected on {host}:{port}: {', '.join(detected)}"
                        self.log(f"  🛡 {msg}", "good")
                        self.result_signal.emit("WAF/Firewall", f"🛡 {msg}", Theme.current["GREEN"])
                    else:
                        self.result_signal.emit("WAF/Firewall", f"⚠ No WAF on {host}:{port} – unprotected", Theme.current["ORANGE"])
                        self.data["vulnerabilities"].append(f"[MEDIUM] No WAF detected on {host}:{port}")
            elif "No WAF detected" in out:
                self.result_signal.emit("WAF/Firewall", f"⚠ No WAF: {host}:{port}", Theme.current["ORANGE"])
            elif out.strip():
                self.log(f"  wafw00f: {out[:100]}", "info")
                self.result_signal.emit("WAF/Firewall", f"🛡 {out[:80]}", Theme.current["GREEN"])

    # ── Web Vulnerability Scan ────────────────
    def stage_web_scan(self, services):
        self.current_stage = "nikto"
        self.log("━━━ STAGE 6: WEB VULNERABILITY SCAN (NIKTO) ━━━", "stage")
        self.stage_signal.emit("Web Vuln Scan")
        self.prog("vuln", 10)
        findings = []
        web_svcs = [s for s in services if s["service"] in ("http","https","http-alt")]

        if not web_svcs:
            self.log("  No HTTP services – skipping Nikto", "muted")
            self.prog("vuln", 35)
            return findings

        if not self.cfg["nikto"]:
            self.log("  Nikto disabled in current profile", "muted")
            self.prog("vuln", 35)
            return findings

        for svc in web_svcs[:2]:
            if self._stop: break
            proto = "https" if svc["service"]=="https" else "http"
            url = f"{proto}://{svc['host']}:{svc['port']}"
            self.log(f"  nikto → {url}", "info")
            out = self.run_cmd(["nikto", "-h", url, "-nointeractive",
                                "-Tuning","1234578", "-maxtime","120s"], timeout=140)
            if "__NOTFOUND__" in out:
                self.log("  nikto not found – skipping", "warn")
                break
            for line in out.splitlines():
                if re.match(r'\+ ', line) and "OSVDB" not in line:
                    clean = line.strip().lstrip("+ ")
                    if len(clean) > 10:
                        findings.append(clean)
                        self.log(f"  Nikto: {clean[:80]}", "warn")

        self.prog("vuln", 35)
        return findings

    # ── Exploit Lookup ────────────────────────
    def stage_exploit_lookup(self, services):
        self.current_stage = "exploit"
        self.log("━━━ STAGE 7: EXPLOIT LOOKUP ━━━", "stage")
        self.stage_signal.emit("Exploit Lookup")
        self.prog("vuln", 40)
        exploits = []
        searched = set()

        for svc in services:
            if self._stop: break
            sname = svc["service"].lower()
            ver   = svc["version"].split()[0] if svc["version"] else ""
            query = f"{sname} {ver}".strip() if ver else sname
            if query in searched: continue
            searched.add(query)

            self.log(f"  searchsploit: '{query}'", "muted")
            out = self.run_cmd(["searchsploit", "--color", query], timeout=25)

            if "__NOTFOUND__" in out:
                self.log("  searchsploit not found – using CVE DB", "warn")
                # Use internal CVE database
                for cve_entry in CVE_DB.get(sname, []):
                    exploits.append({"service":sname, **cve_entry})
                    label = f"⚡ [{cve_entry['cve']}] CVSS:{cve_entry['cvss']} {cve_entry['title']}"
                    self.result_signal.emit("Exploit Suggestions", label, Theme.current["RED"])
                    self.data["exploits"].append(label)
                    DB.add_vuln(self.scan_id, svc["host"], sname, svc["port"],
                                "CRITICAL" if cve_entry["cvss"]>=9 else "HIGH" if cve_entry["cvss"]>=7 else "MEDIUM",
                                cve_entry["cve"], cve_entry["cvss"], cve_entry["title"],
                                cve_entry.get("mitre",""), cve_entry.get("tech",""),
                                cve_entry.get("compliance",""))
                continue

            if "Exploits: No Results" in out: continue
            for line in out.splitlines():
                if "|" in line and "Path" not in line and "---" not in line:
                    clean = re.sub(r'\x1b\[[0-9;]*m','',line).strip()
                    if clean and len(clean)>10:
                        exploits.append({"service":sname,"title":clean})
                        self.result_signal.emit("Exploit Suggestions", f"⚡ {clean[:90]}", Theme.current["RED"])
                        self.data["exploits"].append(clean[:120])

        self.prog("vuln", 60)
        return exploits

    # ── AI Vulnerability Ranking ──────────────
    def stage_ai_ranking(self, services, nikto_findings):
        self.current_stage = "ai"
        self.log("━━━ STAGE 8: AI VULNERABILITY RANKING + CVSS ━━━", "stage")
        self.stage_signal.emit("AI Ranking")
        self.prog("ai", 10)

        RISK_MATRIX = {
            # (service, base_risk, base_cvss)
            "ftp":      ("CRITICAL", 9.0), "telnet":  ("CRITICAL", 9.5),
            "rdp":      ("CRITICAL", 9.8), "smb":     ("CRITICAL", 9.3),
            "vnc":      ("CRITICAL", 8.8), "mysql":   ("HIGH",     7.5),
            "mssql":    ("HIGH",     7.5), "oracle":  ("HIGH",     7.5),
            "ssh":      ("HIGH",     6.5), "mongodb": ("HIGH",     7.8),
            "redis":    ("HIGH",     7.5), "elastic":  ("HIGH",    7.5),
            "http":     ("MEDIUM",   5.3), "https":    ("MEDIUM",  5.0),
            "http-alt": ("MEDIUM",   5.5), "smtp":     ("MEDIUM",  4.3),
            "dns":      ("MEDIUM",   5.0), "snmp":     ("HIGH",    7.5),
        }

        vulns = []
        for svc in services:
            if self._stop: break
            sname = svc["service"].lower()
            base_risk, base_cvss = RISK_MATRIX.get(sname, ("LOW", 3.0))

            # Context scoring
            score_adj = 0.0
            if svc["port"] in ("21","23","3389","5900"): score_adj += 0.5
            if not svc["version"]: score_adj += 0.3   # unknown version = risk
            if "anonymous" in svc.get("banner","").lower(): score_adj += 1.0
            final_cvss = min(10.0, base_cvss + score_adj)
            if   final_cvss >= 9.0: final_risk = "CRITICAL"
            elif final_cvss >= 7.0: final_risk = "HIGH"
            elif final_cvss >= 4.0: final_risk = "MEDIUM"
            else:                   final_risk = "LOW"

            # CVE lookup
            cves = CVE_DB.get(sname, [])
            cve_str = ", ".join(c["cve"] for c in cves[:2]) if cves else "—"
            mitre  = cves[0].get("mitre","") if cves else ""
            tech   = cves[0].get("tech","") if cves else ""
            compliance = cves[0].get("compliance","") if cves else ""
            tactic = MITRE_TACTICS.get(mitre,"") if mitre else ""

            # Add to MITRE tracking
            if mitre and mitre not in [m["id"] for m in self.data["mitre_techniques"]]:
                self.data["mitre_techniques"].append({"id":mitre,"tactic":tactic,"tech":tech,"service":sname})
                self.result_signal.emit("MITRE ATT&CK",
                    f"[{mitre}] {tactic} – {tech} ({sname})", Theme.current["PURPLE"])

            risk_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(final_risk,"⚪")
            label = (f"{risk_icon} [{final_risk:8s}] CVSS:{final_cvss:.1f}  "
                     f"{svc['service']:12s} :{svc['port']:5s}  {cve_str}")
            compliance_short = compliance.split(",")[0] if compliance else ""
            if compliance_short:
                label += f"  [{compliance_short}]"

            vulns.append({"service":sname,"port":svc["port"],"risk":final_risk,
                          "cvss":final_cvss,"cve":cve_str,"mitre":mitre})
            self.result_signal.emit("Ranked Vulnerabilities", label,
                Theme.current["RED"] if final_risk=="CRITICAL" else
                Theme.current["ORANGE"] if final_risk=="HIGH" else
                Theme.current["TEXT"])
            self.data["vulnerabilities"].append(label)
            self.data["risk_counts"][final_risk] = self.data["risk_counts"].get(final_risk,0)+1

            DB.add_vuln(self.scan_id, svc["host"], sname, svc["port"],
                        final_risk, cve_str, final_cvss, f"Service: {sname} on :{svc['port']}",
                        mitre, tech, compliance)

        # Nikto findings
        for f in nikto_findings[:10]:
            label = f"🟡 [MEDIUM  ] CVSS:4.0  web vulnerability – {f[:55]}"
            vulns.append({"service":"web","risk":"MEDIUM","cvss":4.0})
            self.result_signal.emit("Ranked Vulnerabilities", label, Theme.current["TEXT"])
            self.data["vulnerabilities"].append(label)
            self.data["risk_counts"]["MEDIUM"] = self.data["risk_counts"].get("MEDIUM",0)+1

        vulns.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["risk"],4))
        self.chart_signal.emit({"risk_counts": self.data["risk_counts"],
                                "port_states": self.data["port_states"]})
        self.prog("ai", 100)
        return vulns

    # ── Compliance Mapping ────────────────────
    def stage_compliance(self, vulns):
        self.current_stage = "compliance"
        self.log("━━━ COMPLIANCE MAPPING ━━━", "stage")
        self.stage_signal.emit("Compliance Check")

        frameworks = {
            "PCI-DSS": [],
            "HIPAA":   [],
            "NIST":    [],
            "CIS":     [],
            "OWASP":   [],
        }
        for cve_list in CVE_DB.values():
            for entry in cve_list:
                comp = entry.get("compliance","")
                for item in comp.split(","):
                    item = item.strip()
                    for fw in frameworks:
                        if fw in item:
                            control = item.split(":")[1] if ":" in item else item
                            if control not in frameworks[fw]:
                                frameworks[fw].append(control)

        for fw, controls in frameworks.items():
            if controls:
                failing = len([v for v in vulns if v.get("risk") in ("CRITICAL","HIGH")])
                status = "⛔ FAIL" if failing > 0 else "✓ PASS"
                label = f"{status}  {fw}: {len(controls)} controls affected"
                color = Theme.current["RED"] if failing else Theme.current["GREEN"]
                self.result_signal.emit("Compliance", label, color)
                self.data["compliance"].append(label)
                for ctrl in controls[:5]:
                    self.result_signal.emit("Compliance", f"    ↳ Control {ctrl}", Theme.current["TEXT2"])

    # ── Attack Paths ──────────────────────────
    def stage_attack_paths(self, services):
        self.current_stage = "paths"
        self.log("━━━ STAGE 9: ATTACK PATH GENERATION ━━━", "stage")
        self.stage_signal.emit("Attack Paths")

        chains = {
            "ftp":     [
                "External Attacker → Internet → FTP(21) → Anonymous Login → File Exfiltration → Data Breach",
                "External Attacker → Internet → FTP(21) → Brute-Force Creds → Upload PHP Shell → RCE",
            ],
            "ssh":     [
                "External Attacker → Internet → SSH(22) → Password Spray → Shell Access → Privilege Escalation",
                "Insider Threat → LAN → SSH(22) → Stolen Key → Persistence → Lateral Movement",
            ],
            "http":    [
                "External → HTTP(80) → SQLi → DB Dump → Credential Harvest → Account Takeover",
                "External → HTTP(80) → XSS → Session Hijack → Authenticated Actions",
                "External → HTTP(80) → Path Traversal → /etc/passwd → Recon → RCE",
                "External → HTTP(80) → File Upload Bypass → Webshell → OS Access",
            ],
            "https":   [
                "External → HTTPS(443) → TLS Downgrade → MitM → Data Intercept",
                "External → HTTPS(443) → Web App Vuln → SSRF → Internal Network Access",
            ],
            "http-alt":[
                "External → Tomcat(8080) → AJP Ghostcat → File Read → Config Leak → RCE",
                "External → Tomcat(8080) → Default Creds (admin/admin) → WAR Deploy → Shell",
            ],
            "mysql":   [
                "External → MySQL(3306) → Default Root No-Password → Full DB Access → Data Exfil",
                "Internal → MySQL(3306) → SQLi in App → DB Compromise → Load_File RCE",
            ],
            "rdp":     [
                "External → RDP(3389) → BlueKeep (CVE-2019-0708) → SYSTEM Shell → AD Compromise",
                "External → RDP(3389) → Credential Spray → Desktop Access → Persistence",
            ],
            "smb":     [
                "External → SMB(445) → EternalBlue (MS17-010) → SYSTEM → Ransomware Deploy",
                "Internal → SMB(445) → Null Session → User/Share Enum → Credential Relay → Domain Admin",
            ],
            "smtp":    [
                "External → SMTP(25) → Open Relay → Spam Campaign → Reputation Damage",
                "External → SMTP(25) → VRFY/EXPN → User Enum → Targeted Phishing",
            ],
        }

        seen = set()
        for svc in services:
            for path in chains.get(svc["service"].lower(), [
                f"External → {svc['service'].upper()}({svc['port']}) → Service Exploit → System Compromise"
            ]):
                if path not in seen:
                    seen.add(path)
                    self.result_signal.emit("Attack Paths", f"⟶ {path}", Theme.current["ORANGE"])
                    self.log(f"  Path: {path[:80]}", "info")
                    self.data["attack_paths"].append(path)

    # ── Recommendations ───────────────────────
    def stage_recommendations(self, vulns):
        self.current_stage = "recs"
        self.log("━━━ SECURITY RECOMMENDATIONS ━━━", "stage")
        self.stage_signal.emit("Recommendations")

        specific = {
            "ftp":     "CRITICAL: Disable FTP entirely. Replace with SFTP/SCP. Block port 21 at perimeter. If needed, enforce TLS (FTPS) with auth.",
            "telnet":  "CRITICAL: Disable Telnet immediately. Use SSH with key-based auth only. Telnet transmits all data in cleartext.",
            "ssh":     "HIGH: Disable password auth; enforce key-based. Restrict SSH to trusted IPs via firewall. Enable MFA. Audit authorized_keys.",
            "http":    "HIGH: Force HTTPS redirect (301). Implement HSTS. Deploy WAF. Enable CSP headers. Input validation against XSS/SQLi.",
            "https":   "MEDIUM: Enforce TLS 1.2+, disable TLS 1.0/1.1. Use HSTS with preloading. Rotate certificates. Audit cipher suites.",
            "http-alt":"HIGH: Disable AJP connector (server.xml). Use strong admin credentials. Restrict management interface to localhost.",
            "mysql":   "CRITICAL: Bind MySQL to 127.0.0.1. Remove anonymous user. Change root password. Enable SSL. Apply principle of least privilege.",
            "rdp":     "CRITICAL: Patch BlueKeep (KB4499175). Enable NLA. Restrict RDP via VPN only. Enforce MFA. Implement account lockout.",
            "smb":     "CRITICAL: Apply MS17-010 patches. Disable SMBv1. Block 445 at internet boundary. Disable null sessions. Enable SMB signing.",
            "smtp":    "MEDIUM: Disable open relay. Configure SPF/DKIM/DMARC. Limit VRFY/EXPN commands. Enable TLS for SMTP.",
            "snmp":    "HIGH: Change default community strings. Use SNMPv3 with auth/encryption. Restrict SNMP to management hosts only.",
        }
        generic = [
            "◉ Implement network segmentation and micro-segmentation (zero-trust architecture).",
            "◉ Enable comprehensive logging and SIEM integration (Splunk/ELK/Wazuh).",
            "◉ Deploy EDR/XDR on all endpoints (CrowdStrike/SentinelOne/Defender).",
            "◉ Enforce principle of least privilege across all accounts and services.",
            "◉ Implement automated patch management with SLA: Critical <24h, High <7d.",
            "◉ Conduct regular penetration testing (quarterly) and vulnerability assessments.",
            "◉ Implement multi-factor authentication on all external-facing services.",
            "◉ Establish incident response plan with tabletop exercises.",
            "◉ Regular security awareness training for all staff.",
        ]

        seen_recs = set()
        for vuln in vulns:
            svc = vuln.get("service","").lower()
            if svc in specific and svc not in seen_recs:
                seen_recs.add(svc)
                rec = specific[svc]
                risk = vuln.get("risk","MEDIUM")
                icon = "🔴" if risk=="CRITICAL" else "🟠" if risk=="HIGH" else "🟡"
                self.result_signal.emit("Security Recommendations", f"{icon} {rec}", Theme.current["GREEN"])
                self.data["recommendations"].append(rec)

        for g in generic:
            self.result_signal.emit("Security Recommendations", g, Theme.current["TEXT2"])
            self.data["recommendations"].append(g)

    # ── Network Attack Graph ──────────────────
    def stage_attack_graph(self, services):
        self.current_stage = "graph"
        self.log("━━━ STAGE 10: NETWORK ATTACK GRAPH ━━━", "stage")
        self.stage_signal.emit("Attack Graph")

        fig = plt.figure(figsize=(20, 13), facecolor="#080C18")
        gs  = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

        # ── Main attack graph ────────
        ax1 = fig.add_subplot(gs[:, :2])
        ax1.set_facecolor("#080C18")

        G = nx.DiGraph()
        node_meta = {}

        G.add_node("ATTACKER",        meta=("attacker",  "#EF4444", 3200))
        G.add_node("INTERNET",        meta=("net",       "#475569", 2000))
        G.add_node("FIREWALL",        meta=("fw",        "#F59E0B", 2000))
        target_node = f"TARGET\n{self.target[:15]}"
        G.add_node(target_node,       meta=("target",    "#00E5FF", 2800))

        G.add_edge("ATTACKER",   "INTERNET",    label="probe")
        G.add_edge("INTERNET",   "FIREWALL",    label="bypass")
        G.add_edge("FIREWALL",   target_node,   label="access")

        svc_colors = {
            "ftp":"#EF4444","telnet":"#EF4444","rdp":"#EF4444","smb":"#EF4444",
            "ssh":"#F59E0B","mysql":"#F59E0B","mssql":"#F59E0B","mongodb":"#F59E0B",
            "http":"#00E5FF","https":"#8B5CF6","http-alt":"#F59E0B",
            "smtp":"#10B981","dns":"#10B981",
        }

        for svc in services[:12]:
            sname  = svc["service"].upper()
            sport  = svc["port"]
            snode  = f"{sname}\n:{sport}"
            enode  = f"EXPLOIT\n{sname}"
            G.add_node(snode, meta=("service", svc_colors.get(svc["service"].lower(),"#10B981"), 1800))
            G.add_node(enode, meta=("exploit", "#EF4444", 1400))
            G.add_edge(target_node, snode, label="exposes")
            G.add_edge(snode, enode, label="vuln")
            G.add_edge("ATTACKER", enode, label="exploits", style="dashed")

        try:
            pos = nx.kamada_kawai_layout(G)
        except:
            pos = nx.spring_layout(G, seed=42, k=3.0)

        colors = []
        sizes  = []
        for n in G.nodes():
            meta = G.nodes[n].get("meta", ("x","#64748B",1600))
            colors.append(meta[1])
            sizes.append(meta[2])

        # Draw edges with different styles
        solid_edges  = [(u,v) for u,v,d in G.edges(data=True) if d.get("style") != "dashed"]
        dashed_edges = [(u,v) for u,v,d in G.edges(data=True) if d.get("style") == "dashed"]

        nx.draw_networkx_edges(G, pos, edgelist=solid_edges,
            edge_color="#1E3A5F", arrows=True, arrowsize=18,
            width=1.8, alpha=0.9, connectionstyle="arc3,rad=0.08", ax=ax1)
        nx.draw_networkx_edges(G, pos, edgelist=dashed_edges,
            edge_color="#EF444440", arrows=True, arrowsize=14,
            width=1.0, alpha=0.5, style="dashed",
            connectionstyle="arc3,rad=-0.12", ax=ax1)
        nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=sizes,
            alpha=0.93, ax=ax1)
        nx.draw_networkx_labels(G, pos, font_color="#F1F5F9",
            font_size=6.5, font_weight="bold", ax=ax1)
        edge_labels = {(u,v): d["label"] for u,v,d in G.edges(data=True) if "label" in d and d.get("style")!="dashed"}
        nx.draw_networkx_edge_labels(G, pos, edge_labels,
            font_color="#64748B", font_size=5.5, ax=ax1)

        patches = [
            mpatches.Patch(color="#EF4444", label="Critical / Attacker"),
            mpatches.Patch(color="#F59E0B", label="High Risk"),
            mpatches.Patch(color="#00E5FF", label="Target / HTTP"),
            mpatches.Patch(color="#8B5CF6", label="HTTPS"),
            mpatches.Patch(color="#10B981", label="Low Risk"),
            mpatches.Patch(color="#475569", label="Infrastructure"),
        ]
        ax1.legend(handles=patches, loc="lower left",
            facecolor="#0C1220", edgecolor="#1E293B", labelcolor="#E2E8F0",
            fontsize=7.5, framealpha=0.9)
        ax1.set_title(f"ATTACK GRAPH  —  {self.target}",
            color="#00E5FF", fontsize=13, fontweight="bold", fontfamily="monospace", pad=10)
        ax1.axis("off")

        # ── Risk donut chart ─────────
        ax2 = fig.add_subplot(gs[0, 2])
        ax2.set_facecolor("#080C18")
        risk_counts = self.data["risk_counts"]
        labels = [k for k,v in risk_counts.items() if v > 0]
        sizes2 = [v for v in risk_counts.values() if v > 0]
        pie_colors = {"CRITICAL":"#EF4444","HIGH":"#F59E0B","MEDIUM":"#EAB308","LOW":"#10B981"}
        colors2 = [pie_colors.get(l,"#64748B") for l in labels]
        if sizes2:
            wedges, texts, autotexts = ax2.pie(
                sizes2, labels=labels, colors=colors2, autopct="%1.0f%%",
                startangle=90, pctdistance=0.7, wedgeprops={"width":0.55,"edgecolor":"#080C18","linewidth":2})
            for t in texts: t.set_color("#94A3B8"); t.set_fontsize(8)
            for at in autotexts: at.set_color("#fff"); at.set_fontsize(8); at.set_fontweight("bold")
        else:
            ax2.text(0.5, 0.5, "No vulns", ha="center", va="center", color="#64748B")
        ax2.set_title("Risk Distribution", color="#00E5FF", fontsize=10, fontweight="bold", pad=5)

        # ── Service heatbar ──────────
        ax3 = fig.add_subplot(gs[1, 2])
        ax3.set_facecolor("#080C18")
        port_data = self.data["port_states"]
        if port_data:
            svc_names  = list(port_data.keys())[:10]
            svc_counts = [port_data[s] for s in svc_names]
            risk_vals  = [CVE_DB.get(s,[{"cvss":3.0}])[0].get("cvss",3.0) for s in svc_names]
            bar_colors = [plt.cm.RdYlGn_r(v/10.0) for v in risk_vals]
            bars = ax3.barh(svc_names, svc_counts, color=bar_colors, alpha=0.85, height=0.6)
            ax3.set_facecolor("#080C18")
            ax3.tick_params(colors="#94A3B8", labelsize=7)
            ax3.spines[:].set_color("#1E293B")
            ax3.set_xlabel("Count", color="#64748B", fontsize=7)
            for bar, rv in zip(bars, risk_vals):
                ax3.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height()/2,
                         f"CVSS:{rv}", va="center", color="#94A3B8", fontsize=6)
        else:
            ax3.text(0.5, 0.5, "No services", ha="center", va="center", color="#64748B", transform=ax3.transAxes)
        ax3.set_title("Service Risk Heatmap", color="#00E5FF", fontsize=10, fontweight="bold", pad=5)

        fig.text(0.5, 0.01, f"CyberRecon Pro v3.0  |  {self.data['timestamp']}  |  CONFIDENTIAL",
            ha="center", color="#334155", fontsize=8, fontfamily="monospace")

        graph_path = os.path.join(RESULTS_DIR, "attack_graph_v3.png")
        plt.savefig(graph_path, dpi=150, bbox_inches="tight", facecolor="#080C18")
        plt.close()
        self.log(f"  Attack graph → {graph_path}", "good")
        return graph_path

    # ── HTML Report ───────────────────────────
    def stage_report(self, graph_path: str):
        self.current_stage = "report"
        self.log("━━━ STAGE 11: GENERATING PENTEST REPORT ━━━", "stage")

        ts  = self.data["timestamp"]
        tgt = self.data["target"]
        rc  = self.data["risk_counts"]
        total_risk = rc.get("CRITICAL",0)+rc.get("HIGH",0)+rc.get("MEDIUM",0)+rc.get("LOW",0)
        risk_score = min(10.0, round(
            (rc.get("CRITICAL",0)*10 + rc.get("HIGH",0)*7 + rc.get("MEDIUM",0)*4 + rc.get("LOW",0)*2)
            / max(total_risk,1), 1))

        def ul(items, empty="<li>None found</li>"):
            return "".join(f"<li>{i}</li>" for i in items) if items else empty

        def risk_badge(text):
            if "CRITICAL" in text: cls="crit"
            elif "HIGH"    in text: cls="high"
            elif "MEDIUM"  in text: cls="med"
            else: cls="low"
            return f'<span class="badge {cls}">{text.split("]")[0].replace("[","")}</span> {text.split("]")[-1] if "]" in text else text}'

        vuln_rows = "\n".join(
            f'<tr><td class="risk-cell">{risk_badge(v)}</td></tr>'
            for v in self.data["vulnerabilities"]
        )

        img_tag = ""
        if os.path.exists(graph_path):
            with open(graph_path,"rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            img_tag = f'<img src="data:image/png;base64,{b64}" style="width:100%;border-radius:8px;">'

        mitre_rows = "\n".join(
            f'<tr><td style="color:#8B5CF6">{m["id"]}</td><td>{m["tactic"]}</td><td>{m["tech"]}</td><td style="color:#94A3B8">{m["service"]}</td></tr>'
            for m in self.data["mitre_techniques"]
        ) or '<tr><td colspan="4" style="color:#64748B">None detected</td></tr>'

        compliance_rows = "\n".join(f'<li>{c}</li>' for c in self.data["compliance"])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberRecon Pro v3.0 — Pentest Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
:root{{
  --bg:#080C18;--panel:#0C1220;--card:#111827;
  --cyan:#00E5FF;--green:#10B981;--red:#EF4444;
  --orange:#F59E0B;--purple:#8B5CF6;--blue:#3B82F6;
  --text:#F1F5F9;--text2:#94A3B8;--border:#1E293B;
}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:var(--bg);color:var(--text);font-family:'Space Grotesk',sans-serif;font-size:14px;line-height:1.7;}}
a{{color:var(--cyan);text-decoration:none;}}
.hero{{
  background:linear-gradient(135deg,#0C1220 0%,#080C18 50%,#0D0A1F 100%);
  padding:56px 64px 48px;border-bottom:1px solid var(--border);position:relative;overflow:hidden;
}}
.hero::before{{
  content:'';position:absolute;top:-20%;right:-10%;width:50%;height:150%;
  background:radial-gradient(ellipse,rgba(0,229,255,.05) 0%,transparent 65%);
}}
.hero::after{{
  content:'';position:absolute;bottom:-30%;left:5%;width:40%;height:120%;
  background:radial-gradient(ellipse,rgba(139,92,246,.04) 0%,transparent 65%);
}}
.badge-hero{{display:inline-flex;align-items:center;gap:8px;
  background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.25);
  color:var(--cyan);font-family:'JetBrains Mono',monospace;font-size:11px;
  letter-spacing:3px;padding:5px 14px;border-radius:4px;margin-bottom:20px;}}
h1{{font-size:44px;font-weight:700;letter-spacing:-0.5px;color:#fff;}}
h1 em{{color:var(--cyan);font-style:normal;}}
.hero-meta{{color:var(--text2);font-family:'JetBrains Mono',monospace;font-size:11px;
  margin-top:14px;letter-spacing:1px;display:flex;gap:24px;flex-wrap:wrap;}}
.hero-meta strong{{color:var(--cyan);}}
.stats{{display:flex;gap:20px;margin-top:36px;flex-wrap:wrap;}}
.stat{{
  background:rgba(255,255,255,.02);border:1px solid var(--border);
  border-radius:10px;padding:18px 26px;text-align:center;
  position:relative;overflow:hidden;min-width:110px;
}}
.stat::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;}}
.stat.s-crit::before{{background:var(--red);}}
.stat.s-high::before{{background:var(--orange);}}
.stat.s-med::before{{background:#EAB308;}}
.stat.s-low::before{{background:var(--green);}}
.stat.s-blue::before{{background:var(--blue);}}
.stat .num{{font-size:34px;font-weight:700;font-family:'JetBrains Mono',monospace;}}
.stat.s-crit .num{{color:var(--red);}}
.stat.s-high .num{{color:var(--orange);}}
.stat.s-med  .num{{color:#EAB308;}}
.stat.s-low  .num{{color:var(--green);}}
.stat.s-blue .num{{color:var(--cyan);}}
.stat .lbl{{font-size:10px;color:var(--text2);letter-spacing:2px;margin-top:3px;font-weight:600;}}
.risk-score{{
  display:inline-flex;align-items:center;gap:12px;
  background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.3);
  border-radius:8px;padding:12px 20px;margin-top:24px;
}}
.risk-score .score-num{{font-size:28px;font-weight:700;color:var(--red);font-family:'JetBrains Mono',monospace;}}
.risk-score .score-lbl{{color:var(--text2);font-size:12px;}}
main{{max-width:1100px;margin:0 auto;padding:48px 64px;}}
section{{margin-bottom:52px;}}
h2{{
  font-size:13px;font-weight:700;letter-spacing:3px;text-transform:uppercase;
  color:var(--cyan);border-bottom:1px solid var(--border);
  padding-bottom:10px;margin-bottom:22px;font-family:'JetBrains Mono',monospace;
  display:flex;align-items:center;gap:10px;
}}
h2 .sec-num{{
  background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.2);
  color:var(--cyan);font-size:10px;padding:2px 8px;border-radius:3px;
}}
.card{{
  background:var(--card);border:1px solid var(--border);
  border-radius:10px;padding:22px 26px;margin-bottom:14px;
}}
.exec-card{{
  background:linear-gradient(135deg,#0C1220,#0D0A1F);
  border:1px solid var(--border);border-radius:10px;padding:28px 32px;
}}
.exec-card p{{color:#CBD5E1;font-size:14px;line-height:1.9;margin-bottom:14px;}}
ul{{list-style:none;padding:0;}}
ul li{{
  padding:8px 12px;border-bottom:1px solid var(--border);
  font-size:13px;color:var(--text);font-family:'JetBrains Mono',monospace;
}}
ul li::before{{content:"▸ ";color:var(--cyan);}}
ul li:last-child{{border-bottom:none;}}
.badge{{
  display:inline-block;padding:2px 8px;border-radius:4px;
  font-size:11px;font-weight:700;font-family:'JetBrains Mono',monospace;
  margin-right:6px;
}}
.badge.crit{{background:rgba(239,68,68,.15);color:#EF4444;border:1px solid rgba(239,68,68,.3);}}
.badge.high{{background:rgba(245,158,11,.15);color:#F59E0B;border:1px solid rgba(245,158,11,.3);}}
.badge.med {{background:rgba(234,179,8,.15);color:#EAB308;border:1px solid rgba(234,179,8,.3);}}
.badge.low {{background:rgba(16,185,129,.15);color:#10B981;border:1px solid rgba(16,185,129,.3);}}
table{{width:100%;border-collapse:collapse;}}
td,th{{padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;text-align:left;}}
th{{color:var(--cyan);font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:1.5px;background:var(--panel);}}
.risk-cell{{font-family:'JetBrains Mono',monospace;font-size:12px;}}
.mitre-table td:first-child{{color:var(--purple);font-weight:600;}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:16px;}}
@media(max-width:768px){{.two-col{{grid-template-columns:1fr;}}.hero{{padding:32px 24px;}}.stats{{gap:12px;}}main{{padding:32px 24px;}}}}
footer{{
  text-align:center;padding:28px;color:var(--text2);
  font-family:'JetBrains Mono',monospace;font-size:10px;
  border-top:1px solid var(--border);letter-spacing:1px;
}}
</style>
</head>
<body>
<div class="hero">
  <div class="badge-hero">⬡ CONFIDENTIAL // PENTEST REPORT // v3.0</div>
  <h1>Cyber<em>Recon</em> Pro</h1>
  <div class="hero-meta">
    <span>TARGET: <strong>{tgt}</strong></span>
    <span>DATE: <strong>{ts}</strong></span>
    <span>PROFILE: <strong>{self.profile}</strong></span>
    <span>SCAN-ID: <strong>#{self.scan_id}</strong></span>
  </div>
  <div class="stats">
    <div class="stat s-blue"><div class="num">{len(self.data['hosts'])}</div><div class="lbl">HOSTS</div></div>
    <div class="stat s-blue"><div class="num">{len(self.data['services'])}</div><div class="lbl">SERVICES</div></div>
    <div class="stat s-crit"><div class="num">{rc.get('CRITICAL',0)}</div><div class="lbl">CRITICAL</div></div>
    <div class="stat s-high"><div class="num">{rc.get('HIGH',0)}</div><div class="lbl">HIGH</div></div>
    <div class="stat s-med"><div class="num">{rc.get('MEDIUM',0)}</div><div class="lbl">MEDIUM</div></div>
    <div class="stat s-low"><div class="num">{rc.get('LOW',0)}</div><div class="lbl">LOW</div></div>
    <div class="stat s-blue"><div class="num">{len(self.data['exploits'])}</div><div class="lbl">EXPLOITS</div></div>
    <div class="stat s-blue"><div class="num">{len(self.data['attack_paths'])}</div><div class="lbl">ATTACK PATHS</div></div>
  </div>
  <div class="risk-score">
    <div class="score-num">{risk_score}/10</div>
    <div class="score-lbl">OVERALL RISK SCORE<br><span style="font-size:10px;color:#EF4444;">{'CRITICAL' if risk_score>=8 else 'HIGH' if risk_score>=6 else 'MEDIUM' if risk_score>=4 else 'LOW'}</span></div>
  </div>
</div>

<main>
<section>
  <h2><span class="sec-num">01</span> EXECUTIVE SUMMARY</h2>
  <div class="exec-card">
    <p>This report presents findings of an automated reconnaissance and vulnerability assessment
    conducted against <strong style="color:var(--cyan)">{tgt}</strong> on {ts} using CyberRecon Pro v3.0
    with the <strong>{self.profile}</strong> scan profile.</p>
    <p>The assessment identified <strong style="color:var(--red)">{len(self.data['vulnerabilities'])} vulnerabilities</strong>
    across {len(self.data['services'])} exposed services on {len(self.data['hosts'])} live hosts.
    The overall risk score is <strong style="color:var(--red)">{risk_score}/10</strong>.
    {rc.get('CRITICAL',0)} CRITICAL and {rc.get('HIGH',0)} HIGH severity findings require immediate remediation.</p>
    <p>Exploit references are mapped to CVE identifiers, CVSS scores, and MITRE ATT&CK techniques.
    Compliance gaps identified against PCI-DSS, HIPAA, NIST SP 800-53, and CIS Controls are documented below.</p>
  </div>
</section>

<section>
  <h2><span class="sec-num">02</span> INFRASTRUCTURE DISCOVERY</h2>
  <div class="two-col">
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">HOSTS DISCOVERED</h3>
    <ul>{ul(self.data['hosts'])}</ul></div>
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">OS FINGERPRINTS</h3>
    <ul>{ul(self.data['os_guesses'])}</ul></div>
  </div>
  <div class="two-col">
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">DNS RECORDS</h3>
    <ul>{ul(self.data['dns_records'])}</ul></div>
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">SSL/TLS ISSUES</h3>
    <ul>{ul(self.data['ssl_issues'])}</ul></div>
  </div>
</section>

<section>
  <h2><span class="sec-num">03</span> SERVICES & VERSIONS</h2>
  <div class="two-col">
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">OPEN SERVICES</h3>
    <ul>{ul(self.data['services'])}</ul></div>
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">VERSIONS</h3>
    <ul>{ul(self.data['versions'])}</ul></div>
  </div>
</section>

<section>
  <h2><span class="sec-num">04</span> RANKED VULNERABILITIES</h2>
  <div class="card">
    <table><tbody>{vuln_rows or '<tr><td style="color:var(--text2)">No vulnerabilities found</td></tr>'}</tbody></table>
  </div>
</section>

<section>
  <h2><span class="sec-num">05</span> MITRE ATT&CK MAPPING</h2>
  <div class="card">
    <table class="mitre-table">
      <thead><tr><th>TECHNIQUE ID</th><th>TACTIC</th><th>TECHNIQUE</th><th>SERVICE</th></tr></thead>
      <tbody>{mitre_rows}</tbody>
    </table>
  </div>
</section>

<section>
  <h2><span class="sec-num">06</span> EXPLOIT REFERENCES</h2>
  <div class="card"><ul>{ul(self.data['exploits'])}</ul></div>
</section>

<section>
  <h2><span class="sec-num">07</span> ATTACK PATHS</h2>
  <div class="card"><ul>{ul(self.data['attack_paths'])}</ul></div>
</section>

<section>
  <h2><span class="sec-num">08</span> COMPLIANCE STATUS</h2>
  <div class="card"><ul>{compliance_rows or '<li style="color:var(--text2)">No compliance data generated</li>'}</ul></div>
</section>

<section>
  <h2><span class="sec-num">09</span> SECURITY RECOMMENDATIONS</h2>
  <div class="card"><ul>{ul(self.data['recommendations'])}</ul></div>
</section>

<section>
  <h2><span class="sec-num">10</span> NETWORK ATTACK GRAPH</h2>
  <div class="card">{img_tag or '<p style="color:var(--text2)">Graph not generated</p>'}</div>
</section>
</main>

<footer>CYBERRECON PRO v3.0 &nbsp;|&nbsp; SCAN #{self.scan_id} &nbsp;|&nbsp; {ts}
&nbsp;|&nbsp; FOR AUTHORIZED PENETRATION TESTING ONLY &nbsp;|&nbsp; DO NOT DISTRIBUTE</footer>
</body></html>"""

        report_path = os.path.join(RESULTS_DIR, "report_v3.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        self.log(f"  HTML report → {report_path}", "good")
        return report_path

    # ── Export helpers ────────────────────────
    def export_json(self):
        path = os.path.join(RESULTS_DIR, f"scan_{self.scan_id}.json")
        with open(path,"w") as f:
            json.dump(self.data, f, indent=2)
        return path

    def export_csv(self):
        path = os.path.join(RESULTS_DIR, f"vulns_{self.scan_id}.csv")
        rows = DB.get_scan_vulns(self.scan_id)
        with open(path,"w",newline="") as f:
            w = csv.writer(f)
            w.writerow(["id","scan_id","host","service","port","risk","cve","cvss","title","mitre","technique","compliance"])
            w.writerows(rows)
        return path

    def export_markdown(self):
        d = self.data
        lines = [
            f"# CyberRecon Pro — Pentest Report",
            f"**Target:** {d['target']}  **Date:** {d['timestamp']}  **Profile:** {d['profile']}",
            "", "---", "",
            "## Executive Summary",
            f"- Hosts: {len(d['hosts'])}  Services: {len(d['services'])}  Vulns: {len(d['vulnerabilities'])}",
            "", "## Vulnerabilities",
        ]
        for v in d["vulnerabilities"]:
            lines.append(f"- {v}")
        lines += ["", "## Attack Paths"]
        for p in d["attack_paths"]:
            lines.append(f"- {p}")
        lines += ["", "## Recommendations"]
        for r in d["recommendations"]:
            lines.append(f"- {r}")
        path = os.path.join(RESULTS_DIR, f"report_{self.scan_id}.md")
        with open(path,"w") as f:
            f.write("\n".join(lines))
        return path

    # ── MAIN RUN ──────────────────────────────
    def run(self):
        self.current_stage = "init"
        self.log(f"🚀 CyberRecon Pro v3.0 — Scan started on {self.target}", "stage")
        self.log(f"   Profile: {self.profile} | Scan ID: #{self.scan_id}", "info")
        self.log(f"   Results: {os.path.abspath(RESULTS_DIR)}", "muted")

        try:
            # DNS Recon (parallel to subdomain)
            dns_records    = self.stage_dns_recon()

            # 1. Subdomain
            if self._stop: return
            subdomains     = self.stage_subdomain_discovery()

            # 2. Host discovery
            if self._stop: return
            live_hosts     = self.stage_host_discovery(subdomains)

            # SSL analysis
            if self._stop: return
            ssl_issues     = self.stage_ssl_analysis(live_hosts)

            # 3-5. Port/Service/Version
            if self._stop: return
            services       = self.stage_port_scan(live_hosts)

            # WAF detection
            if self._stop: return
            self.stage_waf_detection(services)

            # 6. Web scan
            if self._stop: return
            nikto_findings = self.stage_web_scan(services)

            # 7. Exploit lookup
            if self._stop: return
            self.stage_exploit_lookup(services)

            # 8. AI ranking
            if self._stop: return
            vulns          = self.stage_ai_ranking(services, nikto_findings)

            # Compliance
            if self._stop: return
            self.stage_compliance(vulns)

            # 9. Attack paths
            if self._stop: return
            self.stage_attack_paths(services)

            # 10. Recommendations
            if self._stop: return
            self.stage_recommendations(vulns)

            # 11. Graph
            if self._stop: return
            graph_path     = self.stage_attack_graph(services)
            self.prog("vuln", 100)

            # 12. Report
            if self._stop: return
            report_path    = self.stage_report(graph_path)
            json_path      = self.export_json()
            csv_path       = self.export_csv()
            md_path        = self.export_markdown()

            self.data["report_path"] = report_path
            self.data["graph_path"]  = graph_path
            self.data["json_path"]   = json_path

            DB.finish_scan(self.scan_id, {
                "hosts": len(self.data["hosts"]),
                "services": len(self.data["services"]),
                "vulns": len(self.data["vulnerabilities"]),
            })

            self.log("━━━ SCAN COMPLETE ━━━", "stage")
            self.log(f"📄 HTML Report: {os.path.abspath(report_path)}", "good")
            self.log(f"📊 JSON Export: {os.path.abspath(json_path)}", "good")
            self.log(f"📋 CSV Export:  {os.path.abspath(csv_path)}", "good")
            self.log(f"📝 Markdown:    {os.path.abspath(md_path)}", "good")

            if not self._stop:
                self.scan_complete.emit(self.data)

        except Exception as e:
            self.log(f"Scan error: {e}", "error")
            import traceback
            self.log(traceback.format_exc(), "muted")

        if self._stop:
            self.stopped.emit()


# ══════════════════════════════════════════════════════════════════════
#  MINI WIDGETS
# ══════════════════════════════════════════════════════════════════════
class LabeledProgress(QWidget):
    def __init__(self, label, parent=None):
        super().__init__(parent)
        t = Theme.current
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,3); lay.setSpacing(2)
        hdr = QHBoxLayout()
        self.lbl = QLabel(label)
        self.lbl.setStyleSheet(f"color:{t['TEXT2']};font-size:9px;letter-spacing:1.2px;")
        self.pct = QLabel("0%")
        self.pct.setStyleSheet(f"color:{t['CYAN']};font-size:9px;font-family:monospace;")
        hdr.addWidget(self.lbl); hdr.addStretch(); hdr.addWidget(self.pct)
        self.bar = QProgressBar(); self.bar.setRange(0,100); self.bar.setValue(0)
        self.bar.setFixedHeight(6); self.bar.setTextVisible(False)
        lay.addLayout(hdr); lay.addWidget(self.bar)

    def set_value(self, v):
        self.bar.setValue(v); self.pct.setText(f"{v}%")
        t = Theme.current
        if v == 100:
            self.bar.setStyleSheet(f"QProgressBar::chunk{{background:{t['GREEN']};border-radius:3px;}}")

    def reset(self):
        self.bar.setValue(0); self.pct.setText("0%")
        self.bar.setStyleSheet("")


class ResultContainer(QWidget):
    def __init__(self, title, icon="◈", parent=None):
        super().__init__(parent)
        t = Theme.current
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(3)
        hdr = QHBoxLayout()
        lbl = QLabel(f"  {icon}  {title}")
        lbl.setStyleSheet(f"color:{t['CYAN']};font-size:9.5px;font-weight:bold;letter-spacing:1.5px;padding:3px 0;")
        self.cnt = QLabel("0")
        self.cnt.setStyleSheet(f"color:{t['GREEN']};font-size:9px;font-family:monospace;padding-right:3px;")
        hdr.addWidget(lbl); hdr.addStretch(); hdr.addWidget(self.cnt)
        self.list = QListWidget(); self.list.setMinimumHeight(70)
        lay.addLayout(hdr); lay.addWidget(self.list)

    def add_item(self, text, color=None):
        item = QListWidgetItem(text)
        item.setForeground(QColor(color or Theme.current["TEXT"]))
        self.list.addItem(item)
        self.list.scrollToBottom()
        self.cnt.setText(str(self.list.count()))

    def clear(self):
        self.list.clear(); self.cnt.setText("0")


class StageIndicator(QWidget):
    """Animated current-stage badge."""
    def __init__(self, parent=None):
        super().__init__(parent)
        t = Theme.current
        lay = QHBoxLayout(self); lay.setContentsMargins(0,0,0,0)
        self.dot = QLabel("●")
        self.dot.setStyleSheet(f"color:{t['TEXT2']};font-size:10px;")
        self.lbl = QLabel("IDLE")
        self.lbl.setStyleSheet(f"color:{t['TEXT2']};font-size:10px;font-family:monospace;letter-spacing:1px;")
        lay.addWidget(self.dot); lay.addWidget(self.lbl); lay.addStretch()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._blink)
        self._on = False

    def set_stage(self, stage_name):
        t = Theme.current
        self.lbl.setText(stage_name.upper())
        self.lbl.setStyleSheet(f"color:{t['CYAN']};font-size:10px;font-family:monospace;letter-spacing:1px;")
        self._timer.start(600)

    def _blink(self):
        t = Theme.current
        self._on = not self._on
        self.dot.setStyleSheet(
            f"color:{''+t['CYAN'] if self._on else t['TEXT2']};font-size:10px;"
        )

    def stop(self):
        self._timer.stop()
        t = Theme.current
        self.dot.setStyleSheet(f"color:{t['GREEN']};font-size:10px;")
        self.lbl.setText("COMPLETE")
        self.lbl.setStyleSheet(f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;")


class ConsoleSearchBar(QWidget):
    def __init__(self, console: QTextEdit, parent=None):
        super().__init__(parent)
        t = Theme.current
        lay = QHBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(6)
        self.input = QLineEdit(); self.input.setPlaceholderText("Filter console...")
        self.input.setFixedHeight(26)
        self.input.setStyleSheet(f"background:{t['CARD']};border:1px solid {t['BORDER']};border-radius:4px;color:{t['TEXT']};padding:2px 8px;font-size:11px;")
        btn = QPushButton("⌕"); btn.setFixedSize(26,26)
        btn.setStyleSheet(f"background:{t['CARD']};border:1px solid {t['BORDER']};border-radius:4px;color:{t['CYAN']};")
        btn.clicked.connect(self._search)
        self.input.returnPressed.connect(self._search)
        lay.addWidget(self.input); lay.addWidget(btn)
        self.console = console
        self._orig_html = ""

    def _search(self):
        term = self.input.text().strip()
        if not term: return
        cursor = self.console.document().find(term)
        if not cursor.isNull():
            self.console.setTextCursor(cursor)
            self.console.ensureCursorVisible()


# ══════════════════════════════════════════════════════════════════════
#  SCAN HISTORY DIALOG
# ══════════════════════════════════════════════════════════════════════
class HistoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        t = Theme.current
        self.setWindowTitle("Scan History")
        self.resize(820, 460)
        self.setStyleSheet(build_stylesheet(t))
        lay = QVBoxLayout(self)

        lbl = QLabel("◈  SCAN HISTORY")
        lbl.setStyleSheet(f"color:{t['CYAN']};font-size:11px;font-weight:bold;letter-spacing:2px;padding:4px 0;")
        lay.addWidget(lbl)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID","TARGET","PROFILE","STARTED","FINISHED","STATUS"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        lay.addWidget(self.table)

        btn_box = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_box.addStretch(); btn_box.addWidget(close_btn)
        lay.addLayout(btn_box)

        self._load()

    def _load(self):
        rows = DB.get_all_scans()
        self.table.setRowCount(len(rows))
        status_colors = {"complete": "#10B981", "running": "#F59E0B", "failed": "#EF4444"}
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                item = QTableWidgetItem(str(val or "—"))
                if c == 5:
                    item.setForeground(QColor(status_colors.get(str(val),"#94A3B8")))
                self.table.setItem(r, c, item)


# ══════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════
class CyberReconMain(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberRecon Pro v3.0  —  Advanced Vulnerability Analysis Platform")
        self.setMinimumSize(1480, 900)
        self.resize(1700, 1000)
        self.scan_thread = None
        self.scan_data   = None
        self._theme_dark = True
        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._blink_indicator)
        self._blink_on = False

        self._apply_theme()
        self._build_ui()

    def _apply_theme(self):
        Theme.current = Theme.DARK if self._theme_dark else Theme.LIGHT
        self.setStyleSheet(build_stylesheet(Theme.current))

    # ── UI BUILD ────────────────────────────
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        root.addWidget(self._make_header())

        splitter = QSplitter(Qt.Horizontal); splitter.setHandleWidth(1)
        root.addWidget(splitter, stretch=1)

        splitter.addWidget(self._make_left_panel())
        splitter.addWidget(self._make_center_panel())
        splitter.addWidget(self._make_right_panel())
        splitter.setSizes([310, 720, 670])

        t = Theme.current
        self.statusBar().setStyleSheet(
            f"background:{t['PANEL']};color:{t['TEXT2']};font-size:10px;"
            f"font-family:monospace;border-top:1px solid {t['BORDER']};"
        )
        self.statusBar().showMessage("  ●  CyberRecon Pro v3.0  |  Ready")

    # ── HEADER ──────────────────────────────
    def _make_header(self):
        t = Theme.current
        frame = QFrame(); frame.setFixedHeight(58)
        frame.setStyleSheet(
            f"QFrame{{background:{t['PANEL']};border-bottom:1px solid {t['BORDER']};}}")
        lay = QHBoxLayout(frame); lay.setContentsMargins(20,0,20,0)

        logo = QLabel("⬡  CYBERRECON PRO")
        logo.setStyleSheet(f"color:{t['CYAN']};font-size:18px;font-weight:bold;letter-spacing:4px;font-family:monospace;")
        ver  = QLabel("v3.0")
        ver.setStyleSheet(f"color:{t['TEXT2']};font-size:10px;font-family:monospace;margin-left:6px;margin-bottom:2px;")
        sub  = QLabel("ADVANCED VULNERABILITY ANALYSIS PLATFORM")
        sub.setStyleSheet(f"color:{t['TEXT2']};font-size:9px;letter-spacing:2.5px;font-family:monospace;")

        self.clock = QLabel()
        self.clock.setStyleSheet(f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;")
        timer = QTimer(self); timer.timeout.connect(self._tick); timer.start(1000); self._tick()

        self.theme_btn = QPushButton("☀ LIGHT" if self._theme_dark else "☾ DARK")
        self.theme_btn.setObjectName("themeBtn")
        self.theme_btn.setFixedSize(80, 26)
        self.theme_btn.clicked.connect(self._toggle_theme)

        lay.addWidget(logo); lay.addWidget(ver); lay.addSpacing(20)
        lay.addWidget(sub); lay.addStretch()
        lay.addWidget(self.clock); lay.addSpacing(16); lay.addWidget(self.theme_btn)
        return frame

    def _tick(self):
        self.clock.setText(datetime.now().strftime("⏱  %Y-%m-%d  %H:%M:%S"))

    def _toggle_theme(self):
        self._theme_dark = not self._theme_dark
        self._apply_theme()
        self.theme_btn.setText("☀ LIGHT" if self._theme_dark else "☾ DARK")
        self.statusBar().showMessage("  Theme switched")

    # ── LEFT PANEL ──────────────────────────
    def _make_left_panel(self):
        t = Theme.current
        panel = QWidget(); panel.setFixedWidth(315)
        panel.setStyleSheet(f"background:{t['PANEL']};border-right:1px solid {t['BORDER']};")
        lay = QVBoxLayout(panel); lay.setContentsMargins(12,14,12,14); lay.setSpacing(12)

        # ── Target & Profile ─
        tgt_grp = QGroupBox("TARGET CONFIGURATION"); tgt_lay = QVBoxLayout(tgt_grp); tgt_lay.setSpacing(7)

        tgt_lay.addWidget(QLabel("Target (IP / Domain / CIDR):"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 192.168.1.1  or  example.com")
        self.target_input.returnPressed.connect(self._start_scan)
        tgt_lay.addWidget(self.target_input)

        tgt_lay.addWidget(QLabel("Scan Profile:"))
        self.profile_combo = QComboBox()
        for k, v in SCAN_PROFILES.items():
            self.profile_combo.addItem(f"{k}  —  {v['desc']}", k)
        self.profile_combo.setCurrentIndex(3)  # Custom
        tgt_lay.addWidget(self.profile_combo)

        # Options checkboxes
        opt_lay = QHBoxLayout()
        self.chk_os      = QCheckBox("OS Detect")
        self.chk_scripts = QCheckBox("Scripts")
        self.chk_stealth = QCheckBox("Low Noise")
        for c in (self.chk_os, self.chk_scripts, self.chk_stealth):
            opt_lay.addWidget(c)
        tgt_lay.addLayout(opt_lay)
        lay.addWidget(tgt_grp)

        # ── Buttons ─
        btn_grp = QGroupBox("ACTIONS"); btn_lay = QVBoxLayout(btn_grp); btn_lay.setSpacing(7)

        self.start_btn = QPushButton("▶  START SCAN"); self.start_btn.setObjectName("startBtn")
        self.start_btn.setFixedHeight(36); self.start_btn.clicked.connect(self._start_scan)

        self.stop_btn = QPushButton("■  STOP SCAN"); self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setFixedHeight(30); self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)

        row1 = QHBoxLayout()
        self.report_btn = QPushButton("⬇ Report"); self.report_btn.setObjectName("reportBtn")
        self.report_btn.setFixedHeight(28); self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self._open_report)

        self.export_btn = QPushButton("⇣ Export"); self.export_btn.setObjectName("exportBtn")
        self.export_btn.setFixedHeight(28); self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._show_export_menu)

        row1.addWidget(self.report_btn); row1.addWidget(self.export_btn)

        row2 = QHBoxLayout()
        self.hist_btn = QPushButton("◔ History"); self.hist_btn.setObjectName("histBtn")
        self.hist_btn.setFixedHeight(28)
        self.hist_btn.clicked.connect(self._show_history)

        clear_btn = QPushButton("✕ Clear"); clear_btn.setObjectName("exportBtn")
        clear_btn.setFixedHeight(28); clear_btn.clicked.connect(self._clear)
        row2.addWidget(self.hist_btn); row2.addWidget(clear_btn)

        btn_lay.addWidget(self.start_btn); btn_lay.addWidget(self.stop_btn)
        btn_lay.addLayout(row1); btn_lay.addLayout(row2)
        lay.addWidget(btn_grp)

        # ── Stage indicator ─
        stage_grp = QGroupBox("CURRENT STAGE"); stage_lay = QVBoxLayout(stage_grp)
        self.stage_indicator = StageIndicator()
        stage_lay.addWidget(self.stage_indicator)
        lay.addWidget(stage_grp)

        # ── Progress bars ─
        prog_grp = QGroupBox("SCAN PROGRESS"); prog_lay = QVBoxLayout(prog_grp); prog_lay.setSpacing(9)
        self.prog_host    = LabeledProgress("HOST DISCOVERY")
        self.prog_port    = LabeledProgress("PORT SCANNING")
        self.prog_service = LabeledProgress("SERVICE DETECT")
        self.prog_vuln    = LabeledProgress("VULN SCANNING")
        self.prog_ai      = LabeledProgress("AI RANKING")
        self.prog_misc    = LabeledProgress("DNS / SSL / MISC")
        for pb in (self.prog_host,self.prog_port,self.prog_service,
                   self.prog_vuln,self.prog_ai,self.prog_misc):
            prog_lay.addWidget(pb)
        lay.addWidget(prog_grp)

        # ── Tool Status ─
        tools_grp = QGroupBox("TOOL STATUS"); tools_lay = QVBoxLayout(tools_grp); tools_lay.setSpacing(4)
        for tool, desc in [("nmap","Port Scanner"),("searchsploit","Exploit DB"),
                           ("subfinder","Subdomain"),("nikto","Web Scanner"),
                           ("wafw00f","WAF Detect"),("dig","DNS Recon")]:
            r = QHBoxLayout()
            tl = QLabel(f"◈ {tool}"); tl.setStyleSheet(f"color:{t['CYAN']};font-size:9px;font-family:monospace;")
            dl = QLabel(desc); dl.setStyleSheet(f"color:{t['TEXT2']};font-size:9px;")
            r.addWidget(tl); r.addStretch(); r.addWidget(dl)
            tools_lay.addLayout(r)
        lay.addWidget(tools_grp)
        lay.addStretch()

        self.status_pill = QLabel("● READY")
        self.status_pill.setStyleSheet(
            f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        lay.addWidget(self.status_pill, alignment=Qt.AlignCenter)
        return panel

    # ── CENTER PANEL ────────────────────────
    def _make_center_panel(self):
        t = Theme.current
        panel = QWidget(); panel.setStyleSheet(f"background:{t['BG']};")
        lay = QVBoxLayout(panel); lay.setContentsMargins(10,10,10,10); lay.setSpacing(6)

        hdr = QHBoxLayout()
        console_lbl = QLabel("◈  LIVE RECONNAISSANCE CONSOLE")
        console_lbl.setStyleSheet(
            f"color:{t['CYAN']};font-size:10px;font-weight:bold;letter-spacing:2px;font-family:monospace;")
        self.indicator = QLabel("●")
        self.indicator.setStyleSheet(f"color:{t['TEXT2']};font-size:13px;")
        hdr.addWidget(console_lbl); hdr.addStretch(); hdr.addWidget(self.indicator)
        lay.addLayout(hdr)

        self.console = QTextEdit(); self.console.setReadOnly(True)
        lay.addWidget(self.console, stretch=1)

        self.search_bar = ConsoleSearchBar(self.console)
        lay.addWidget(self.search_bar)

        self._console_welcome()
        return panel

    def _console_welcome(self):
        t = Theme.current
        self.console.setHtml(f"""
        <div style="color:{t['TEXT2']};font-family:monospace;font-size:11.5px;padding:6px;">
        <div style="color:{t['CYAN']};font-size:13px;font-weight:bold;margin-bottom:10px;">
          ⬡  CyberRecon Pro v3.0 — Advanced Pentest Engine
        </div>
        <div style="color:{t['BORDER2']};">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</div>
        <br>
        <div style="color:{t['TEXT']};">NEW IN v3.0:</div>
        <div style="color:{t['GREEN']};margin:6px 0 6px 12px;line-height:1.9;">
          ◈ SSL/TLS cert analysis &amp; cipher/protocol detection<br>
          ◈ DNS recon with SPF/DMARC/DKIM validation<br>
          ◈ OS fingerprinting &amp; banner grabbing<br>
          ◈ WAF / Firewall detection<br>
          ◈ CVE DB with CVSS scores &amp; MITRE ATT&amp;CK mapping<br>
          ◈ Compliance mapping (PCI-DSS, HIPAA, NIST, CIS)<br>
          ◈ Subdomain brute-forcing fallback<br>
          ◈ Multi-format export: HTML + JSON + CSV + Markdown<br>
          ◈ Scan history stored in SQLite<br>
          ◈ Stop scan mid-execution<br>
          ◈ Console keyword search / filter<br>
          ◈ Dark/Light theme toggle<br>
          ◈ Scan profiles: Quick / Full / Stealth / Custom<br>
          ◈ Risk donut + service heatmap in attack graph
        </div>
        <br>
        <div style="color:{t['ORANGE']};">⚠  Authorized use only. Run only against targets you own or have written permission to test.</div>
        <br>
        <div style="color:{t['TEXT2']};">Enter a target and select a scan profile, then click ▶ START SCAN</div>
        </div>""")

    # ── RIGHT PANEL ─────────────────────────
    def _make_right_panel(self):
        t = Theme.current
        panel = QWidget()
        panel.setStyleSheet(f"background:{t['PANEL']};border-left:1px solid {t['BORDER']};")
        lay = QVBoxLayout(panel); lay.setContentsMargins(10,10,10,10); lay.setSpacing(0)

        hdr = QLabel("◈  SCAN RESULTS")
        hdr.setStyleSheet(
            f"color:{t['CYAN']};font-size:10px;font-weight:bold;letter-spacing:2px;font-family:monospace;padding:3px 0 7px 0;")
        lay.addWidget(hdr)

        tabs = QTabWidget(); lay.addWidget(tabs, stretch=1)

        # Tab: DISCOVERY
        disc = QWidget(); dl = QVBoxLayout(disc); dl.setSpacing(8)
        self.c_hosts    = ResultContainer("HOSTS DISCOVERED",  "✦")
        self.c_services = ResultContainer("OPEN SERVICES",     "⬡")
        self.c_versions = ResultContainer("VERSIONS",          "◈")
        self.c_os       = ResultContainer("OS FINGERPRINT",    "🖥")
        scroll1 = QScrollArea(); scroll1.setWidgetResizable(True)
        inner1  = QWidget(); il1 = QVBoxLayout(inner1); il1.setSpacing(8)
        for c in (self.c_hosts,self.c_services,self.c_versions,self.c_os):
            il1.addWidget(c)
        il1.addStretch()
        scroll1.setWidget(inner1); dl.addWidget(scroll1)
        tabs.addTab(disc, "DISCOVERY")

        # Tab: NETWORK
        net = QWidget(); nl = QVBoxLayout(net); nl.setSpacing(8)
        self.c_dns      = ResultContainer("DNS RECORDS",       "⛁")
        self.c_ssl      = ResultContainer("SSL/TLS ISSUES",    "🔒")
        self.c_waf      = ResultContainer("WAF / FIREWALL",    "🛡")
        self.c_banners  = ResultContainer("SERVICE BANNERS",   "◉")
        self.c_subs     = ResultContainer("SUBDOMAINS",        "◍")
        scroll2 = QScrollArea(); scroll2.setWidgetResizable(True)
        inner2  = QWidget(); il2 = QVBoxLayout(inner2); il2.setSpacing(8)
        for c in (self.c_dns,self.c_ssl,self.c_waf,self.c_banners,self.c_subs):
            il2.addWidget(c)
        il2.addStretch()
        scroll2.setWidget(inner2); nl.addWidget(scroll2)
        tabs.addTab(net, "NETWORK")

        # Tab: THREATS
        thr = QWidget(); tl2 = QVBoxLayout(thr); tl2.setSpacing(8)
        self.c_vulns    = ResultContainer("RANKED VULNERABILITIES","⚠")
        self.c_exploits = ResultContainer("EXPLOIT SUGGESTIONS",   "⚡")
        self.c_mitre    = ResultContainer("MITRE ATT&CK",          "⬡")
        scroll3 = QScrollArea(); scroll3.setWidgetResizable(True)
        inner3  = QWidget(); il3 = QVBoxLayout(inner3); il3.setSpacing(8)
        for c in (self.c_vulns,self.c_exploits,self.c_mitre):
            il3.addWidget(c)
        il3.addStretch()
        scroll3.setWidget(inner3); tl2.addWidget(scroll3)
        tabs.addTab(thr, "THREATS")

        # Tab: ATTACK
        atk = QWidget(); al = QVBoxLayout(atk); al.setSpacing(8)
        self.c_paths    = ResultContainer("ATTACK PATHS",     "⟶")
        self.c_recs     = ResultContainer("RECOMMENDATIONS",  "✅")
        self.c_comply   = ResultContainer("COMPLIANCE",       "📋")
        scroll4 = QScrollArea(); scroll4.setWidgetResizable(True)
        inner4  = QWidget(); il4 = QVBoxLayout(inner4); il4.setSpacing(8)
        for c in (self.c_paths,self.c_recs,self.c_comply):
            il4.addWidget(c)
        il4.addStretch()
        scroll4.setWidget(inner4); al.addWidget(scroll4)
        tabs.addTab(atk, "ATTACK / COMPLIANCE")

        return panel

    # ── SIGNAL HANDLERS ─────────────────────
    def _append_log(self, msg: str, level: str):
        t = Theme.current
        ts   = datetime.now().strftime("%H:%M:%S")
        colors = {
            "stage":  t["CYAN"],
            "good":   t["GREEN"],
            "warn":   t["ORANGE"],
            "error":  t["RED"],
            "info":   t["TEXT"],
            "muted":  t["TEXT2"],
        }
        mc = colors.get(level, t["TEXT"])
        prefix_colors = {
            "stage":  t["PURPLE"],
            "error":  t["RED"],
            "warn":   t["ORANGE"],
        }
        pc = prefix_colors.get(level, t["TEXT2"])

        cursor = self.console.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(
            f'<span style="color:{t["TEXT2"]}">[{ts}]</span> '
            f'<span style="color:{mc}">{msg}</span><br>'
        )
        self.console.setTextCursor(cursor)
        self.console.ensureCursorVisible()

    def _update_progress(self, bar: str, val: int):
        mapping = {
            "host":    self.prog_host,
            "port":    self.prog_port,
            "service": self.prog_service,
            "vuln":    self.prog_vuln,
            "ai":      self.prog_ai,
            "misc":    self.prog_misc,
        }
        if bar in mapping:
            mapping[bar].set_value(val)

    def _add_result(self, container: str, item: str, color: str):
        mapping = {
            "Hosts":                    self.c_hosts,
            "Services":                 self.c_services,
            "Versions":                 self.c_versions,
            "OS Fingerprint":           self.c_os,
            "DNS Records":              self.c_dns,
            "SSL Issues":               self.c_ssl,
            "WAF/Firewall":             self.c_waf,
            "Banners":                  self.c_banners,
            "Subdomains":               self.c_subs,
            "Ranked Vulnerabilities":   self.c_vulns,
            "Exploit Suggestions":      self.c_exploits,
            "MITRE ATT&CK":             self.c_mitre,
            "Attack Paths":             self.c_paths,
            "Security Recommendations": self.c_recs,
            "Compliance":               self.c_comply,
        }
        if container in mapping:
            mapping[container].add_item(item, color)

    def _update_stage(self, stage: str):
        self.stage_indicator.set_stage(stage)
        self.statusBar().showMessage(f"  ⟳  {stage} ...")

    def _update_charts(self, data: dict):
        pass  # charts are embedded in attack graph

    def _scan_done(self, data: dict):
        self.scan_data = data
        self.stage_indicator.stop()
        self._blink_timer.stop()
        t = Theme.current
        self.indicator.setStyleSheet(f"color:{t['GREEN']};font-size:13px;")
        self.status_pill.setText("● COMPLETE")
        self.status_pill.setStyleSheet(
            f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.report_btn.setEnabled(True)
        self.export_btn.setEnabled(True)

        rc = data.get("risk_counts", {})
        self.statusBar().showMessage(
            f"  ✓  Scan complete  |  {len(data['hosts'])} hosts  |  "
            f"{len(data['services'])} services  |  "
            f"CRIT:{rc.get('CRITICAL',0)}  HIGH:{rc.get('HIGH',0)}  "
            f"MED:{rc.get('MEDIUM',0)}  |  Report: results/report_v3.html"
        )

        # System notification
        try:
            if sys.platform == "linux":
                subprocess.Popen(["notify-send", "CyberRecon Pro",
                                  f"Scan complete: {data['target']}"])
            elif sys.platform == "darwin":
                tgt_name = data.get("target","")
                subprocess.Popen(["osascript", "-e",
                    f'display notification "Scan complete: {tgt_name}" with title "CyberRecon Pro"'])
        except:
            pass

    def _scan_stopped(self):
        t = Theme.current
        self.status_pill.setText("● STOPPED")
        self.status_pill.setStyleSheet(
            f"color:{t['ORANGE']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._blink_timer.stop()
        self.stage_indicator.stop()

    def _blink_indicator(self):
        t = Theme.current
        self._blink_on = not self._blink_on
        self.indicator.setStyleSheet(
            f"color:{t['CYAN'] if self._blink_on else t['TEXT2']};font-size:13px;")

    # ── ACTIONS ─────────────────────────────
    def _start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.statusBar().showMessage("  ⚠  Enter a target first."); return
        if self.scan_thread and self.scan_thread.isRunning():
            self.statusBar().showMessage("  ⚠  Scan already running."); return

        self._reset_ui()
        profile = self.profile_combo.currentData()
        options = {
            "os_detect": self.chk_os.isChecked(),
            "scripts":   self.chk_scripts.isChecked(),
            "stealth":   self.chk_stealth.isChecked(),
        }

        t = Theme.current
        self.status_pill.setText("● SCANNING")
        self.status_pill.setStyleSheet(
            f"color:{t['ORANGE']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.report_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self._blink_timer.start(500)

        self.scan_thread = ScanEngine(target, profile, options)
        self.scan_thread.log_signal.connect(self._append_log)
        self.scan_thread.progress_signal.connect(self._update_progress)
        self.scan_thread.result_signal.connect(self._add_result)
        self.scan_thread.stage_signal.connect(self._update_stage)
        self.scan_thread.chart_signal.connect(self._update_charts)
        self.scan_thread.scan_complete.connect(self._scan_done)
        self.scan_thread.stopped.connect(self._scan_stopped)
        self.scan_thread.start()

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.statusBar().showMessage("  ■  Stop signal sent...")

    def _clear(self):
        self.console.clear(); self._console_welcome()
        for c in (self.c_hosts,self.c_services,self.c_versions,self.c_os,
                  self.c_dns,self.c_ssl,self.c_waf,self.c_banners,self.c_subs,
                  self.c_vulns,self.c_exploits,self.c_mitre,
                  self.c_paths,self.c_recs,self.c_comply):
            c.clear()
        for pb in (self.prog_host,self.prog_port,self.prog_service,
                   self.prog_vuln,self.prog_ai,self.prog_misc):
            pb.reset()
        t = Theme.current
        self.status_pill.setText("● READY")
        self.status_pill.setStyleSheet(
            f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        self.stage_indicator.lbl.setText("IDLE")

    def _reset_ui(self):
        self._clear()

    def _open_report(self):
        path = os.path.abspath(os.path.join(RESULTS_DIR, "report_v3.html"))
        if os.path.exists(path):
            import webbrowser; webbrowser.open(f"file://{path}")
        else:
            self.statusBar().showMessage("  ⚠  Report not found. Run a scan first.")

    def _show_export_menu(self):
        if not self.scan_data: return
        menu = QMenu(self)
        t = Theme.current
        menu.setStyleSheet(f"QMenu{{background:{t['CARD']};color:{t['TEXT']};border:1px solid {t['BORDER']};border-radius:5px;padding:4px;}}"
                           f"QMenu::item{{padding:7px 20px;}}"
                           f"QMenu::item:selected{{background:{t['SELECTED']};color:{t['CYAN']};}}")
        a_html = menu.addAction("⬇  Open HTML Report")
        a_json = menu.addAction("⬇  Export JSON")
        a_csv  = menu.addAction("⬇  Export CSV")
        a_md   = menu.addAction("⬇  Export Markdown")
        a_graph= menu.addAction("⬇  Open Attack Graph")

        action = menu.exec_(self.export_btn.mapToGlobal(QPoint(0, self.export_btn.height())))
        import webbrowser
        if action == a_html:
            p = os.path.abspath(os.path.join(RESULTS_DIR,"report_v3.html"))
            if os.path.exists(p): webbrowser.open(f"file://{p}")
        elif action == a_json:
            p = self.scan_data.get("json_path","")
            if p and os.path.exists(p): webbrowser.open(f"file://{p}")
        elif action == a_csv:
            if self.scan_thread:
                p = self.scan_thread.export_csv()
                self.statusBar().showMessage(f"  CSV exported → {p}")
        elif action == a_md:
            if self.scan_thread:
                p = self.scan_thread.export_markdown()
                self.statusBar().showMessage(f"  Markdown exported → {p}")
        elif action == a_graph:
            p = os.path.abspath(os.path.join(RESULTS_DIR,"attack_graph_v3.png"))
            if os.path.exists(p): webbrowser.open(f"file://{p}")

    def _show_history(self):
        dlg = HistoryDialog(self); dlg.exec_()


# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    app = QApplication(sys.argv)
    app.setApplicationName("CyberRecon Pro")
    app.setApplicationVersion("3.0")
    app.setStyle("Fusion")

    # Dark palette for non-styled elements
    pal = QPalette()
    pal.setColor(QPalette.Window,       QColor("#080C18"))
    pal.setColor(QPalette.WindowText,   QColor("#F1F5F9"))
    pal.setColor(QPalette.Base,         QColor("#0C1220"))
    pal.setColor(QPalette.Text,         QColor("#F1F5F9"))
    pal.setColor(QPalette.Highlight,    QColor("#00E5FF"))
    pal.setColor(QPalette.HighlightedText, QColor("#000000"))
    app.setPalette(pal)

    win = CyberReconMain()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
