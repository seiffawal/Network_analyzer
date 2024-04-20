from PyQt5.QtWidgets import QMainWindow, QAction, QMessageBox, QFileDialog, QTableWidget, QTableWidgetItem, QTextEdit, QWidget, QVBoxLayout, QPushButton
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from scapy.all import *

from API_request import is_private_ip
from packet_capture_thread import PacketCaptureThread
from pcap_worker import PcapWorker
from nmap_detection_worker import NmapDetectionWorker
from utils import extract_packet_info, detect_directory_fuzzing, read_fuzzing_patterns
import sys
import re
import logging
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QObject
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QTableWidgetItem, QTableWidget, QVBoxLayout, \
    QWidget, QHBoxLayout, QTextEdit, QAction, QHeaderView, QMessageBox, QDialog, QFormLayout, QLineEdit, QPushButton, QProgressDialog
from PyQt5.QtGui import QColor
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6
from API_request import *

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PCAP Analyzer")
        self.setGeometry(100, 100, 800, 600)
        self.dark_mode = False

        file_menu = self.menuBar().addMenu("&File")
        edit_menu = self.menuBar().addMenu("&Edit")
        view_menu = self.menuBar().addMenu("&View")
        capture_menu = self.menuBar().addMenu("&Capture")
        analyze_menu = self.menuBar().addMenu("&Analyze")
        preferences_menu = self.menuBar().addMenu("&Preferences")

        load_action = self.create_action("&Load PCAP", self.load_pcap)
        file_menu.addAction(load_action)

        save_pcap_action = self.create_action("Save as PCAP", self.save_as_pcap)
        file_menu.addAction(save_pcap_action)

        dark_mode_action = self.create_action("Dark Mode", self.toggle_dark_mode)
        preferences_menu.addAction(dark_mode_action)

        self.start_capture_action = self.create_action("&Start Capture", self.start_capture)
        self.stop_capture_action = self.create_action("&Stop Capture", self.stop_capture)
        self.stop_capture_action.setEnabled(False)  # Initially disable stop capture action
        capture_menu.addAction(self.start_capture_action)
        capture_menu.addAction(self.stop_capture_action)

        self.os_detection_action = self.create_action("OS Detection", self.os_detection_action)
        analyze_menu.addAction(self.os_detection_action)

        analyze_menu.addAction(self.create_action("Email Extraction", self.extract_emails_action))

        self.fuzzy_detection_action = self.create_action("Fuzzy Detection", self.fuzzy_detection_action)
        analyze_menu.addAction(self.fuzzy_detection_action)

        threat_intel_action = self.create_action("Threat Intelligence", self.threat_intelligence_action)
        analyze_menu.addAction(threat_intel_action)

        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        self.tableWidget = QTableWidget()
        main_layout.addWidget(self.tableWidget)

        self.box_widget = QTextEdit()
        main_layout.addWidget(self.box_widget)
        self.box_widget.setReadOnly(True)

        self.packets = []
        self.capturing = False
        self.packetCaptureThread = None

        self.tableWidget.cellClicked.connect(self.select_entire_row)

        self.nmap_detection_thread = QThread()
        self.nmap_detection_thread.start()

        self.nmap_detection_worker = NmapDetectionWorker()
        self.nmap_detection_worker.moveToThread(self.nmap_detection_thread)
        self.nmap_detection_worker.resultReady.connect(self.update_box_widget)

    def create_action(self, text, handler):
        action = QAction(text, self)
        action.triggered.connect(handler)
        return action

    def start_capture(self):
        if not self.capturing:
            self.capturing = True
            self.start_capture_action.setEnabled(False)
            self.stop_capture_action.setEnabled(True)
            self.packetCaptureThread = PacketCaptureThread()
            self.packetCaptureThread.packetCaptured.connect(self.handle_packet_capture)
            self.packetCaptureThread.start()

    def stop_capture(self):
        if self.capturing:
            self.capturing = False
            self.start_capture_action.setEnabled(True)
            self.stop_capture_action.setEnabled(False)
            if self.packetCaptureThread:
                self.packetCaptureThread.terminate()  # Terminate the packet capture thread

    def handle_packet_capture(self, packet_info):
        if self.capturing:
            self.packets.append(packet_info)
            self.display_captured_packet_data()

    def load_pcap(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PCAP File", "", "PCAP Files (*.pcap)")
        if file_path:
            self.clear_box_widget()  # Clear the box widget
            self.load_packets(file_path)

    def load_packets(self, file_path):
        with ThreadPoolExecutor() as executor:
            worker = PcapWorker(file_path)
            if executor.submit(worker.load_packets).result():
                self.packets = worker.packets
                self.display_packet_data()

    def display_packet_data(self):
        self.tableWidget.clear()
        self.tableWidget.setRowCount(len(self.packets))
        self.tableWidget.setColumnCount(6)  # Decrease column count as IP version column is removed
        headers = ['Time', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Load']
        self.tableWidget.setHorizontalHeaderLabels(headers)

        header = self.tableWidget.horizontalHeader()

        for i, packet in enumerate(self.packets):
            packet_info = extract_packet_info(packet)
            payload = self.extract_payload(packet)
            self.add_packet_to_table(i, packet_info, payload)

    def display_captured_packet_data(self):
        self.tableWidget.clear()
        self.tableWidget.setRowCount(len(self.packets))
        self.tableWidget.setColumnCount(6)  # Decrease column count as IP version column is removed
        headers = ['Time', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Load']
        self.tableWidget.setHorizontalHeaderLabels(headers)

        header = self.tableWidget.horizontalHeader()

        for i, packet_info in enumerate(self.packets):
            payload = self.extract_payload(packet_info)
            self.add_packet_to_table(i, packet_info, payload)

    def save_as_pcap(self):
        if self.packets:
            file_path, _ = QFileDialog.getSaveFileName(self, "Save PCAP File", "", "PCAP Files (*.pcap)")
            if file_path:
                try:
                    wrpcap(file_path, self.packets)
                    QMessageBox.information(self, "Save Successful", "PCAP file saved successfully.")
                except Exception as e:
                    QMessageBox.warning(self, "Save Error", f"An error occurred while saving the PCAP file: {str(e)}")
        else:
            QMessageBox.warning(self, "No Packets", "No captured packets to save.")

    def add_packet_to_table(self, row, packet_info, payload):
        self.tableWidget.setItem(row, 0, QTableWidgetItem(str(packet_info.get('time', ''))))
        self.tableWidget.setItem(row, 1, QTableWidgetItem(packet_info.get('source_ip', '')))
        self.tableWidget.setItem(row, 2, QTableWidgetItem(packet_info.get('destination_ip', '')))
        self.tableWidget.setItem(row, 3, QTableWidgetItem(packet_info.get('protocol_name', '')))
        self.tableWidget.setItem(row, 4, QTableWidgetItem(str(packet_info.get('packet_length', ''))))
        self.tableWidget.setItem(row, 5, QTableWidgetItem(payload))

        for col in range(6):
            item = self.tableWidget.item(row, col)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)  # Disable editing

        if row % 2 == 0:
            color = QColor(240, 240, 240)  # Light color
        else:
            color = QColor(200, 200, 200)  # Dark color
        for col in range(6):  # Adjusted the loop range
            self.tableWidget.item(row, col).setBackground(color)

        # Set width of payload column
        self.tableWidget.setColumnWidth(0, 101)
        self.tableWidget.setColumnWidth(3, 50)
        self.tableWidget.setColumnWidth(4, 50)
        self.tableWidget.setColumnWidth(5, 340)

    def extract_payload(self, packet):
        payload = ""
        try:
            if Raw in packet:
                payload = packet[Raw].load.decode(errors='ignore')
        except Exception as e:
            print("Error extracting payload:", e)
        return payload

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            # Dark Mode
            self.setStyleSheet("""
                background-color: #222;
                color: #fff;
            """)
            self.tableWidget.setStyleSheet("background-color: #fff; color: #000;")
            self.box_widget.setStyleSheet("background-color: #fff")
        else:
            self.setStyleSheet("")
            self.tableWidget.setStyleSheet("")

    def select_entire_row(self, row, col):
        self.tableWidget.selectRow(row)

    def update_box_widget(self, result):
        self.box_widget.append(result)

    def clear_box_widget(self):
        self.box_widget.clear()

    def extract_emails_action(self):
        if not self.packets:
            QMessageBox.warning(self, "No PCAP Loaded", "Load a PCAP file first.")
            return

        email_results = []

        # Regular expression pattern to match email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        # Iterate through each packet
        for i, packet in enumerate(self.packets):
            try:
                # Check if the packet has a Raw layer
                if Raw in packet:
                    # Extract payload (load) from the packet
                    payload = packet[Raw].load.decode(errors='ignore')

                    # Search for email addresses in the payload
                    emails = re.findall(email_pattern, payload)

                    # Print the email addresses found in the payload
                    if emails:
                        for email in emails:
                            email_results.append(email)

            except Exception as e:
                print(f"Error processing packet {i + 1}: {str(e)}")

        # Display the email extraction results in a pop-up window
        if email_results:
            email_text = "\n".join(email_results)
            QMessageBox.information(self, "Email Addresses Found", email_text)
        else:
            QMessageBox.information(self, "No Email Addresses Found", "No email addresses found in the captured packets.")

    def os_detection_action(self):
        if not self.packets:
            QMessageBox.warning(self, "No PCAP Loaded", "Load a PCAP file first.")
            return

        reply = QMessageBox.question(self, "Save Log?", "Do you want to save the log?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            options = QFileDialog.Options()
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Log File", "", "Text Files (*.txt)", options=options)
            if file_path:
                self.nmap_detection_worker.detect_nmap_fingerprinting(self.packets, file_path)
        else:
            self.nmap_detection_worker.detect_nmap_fingerprinting(self.packets, None)

    def fuzzy_detection_action(self):
        if not self.packets:
            QMessageBox.warning(self, "No PCAP Loaded", "Load a PCAP file first.")
            return

        # Get the HTTP traffic from the loaded packets
        http_traffic = [pkt for pkt in self.packets if pkt.haslayer(HTTPRequest)]

        # Load fuzzing patterns from a file
        patterns_file, _ = QFileDialog.getOpenFileName(self, "Select Patterns File", "", "Text Files (*.txt)")
        if not patterns_file:
            QMessageBox.warning(self, "No Patterns File Selected", "Please select a patterns file.")
            return

        fuzzing_patterns = read_fuzzing_patterns(patterns_file)

        # Perform directory fuzzing detection
        result = detect_directory_fuzzing(http_traffic, fuzzing_patterns)

        # Display the result in the box widget
        self.box_widget.append(result)

    def threat_intelligence_action(self):
        # Check if there are packets loaded
        if not self.packets:
            self.box_widget.append("No PCAP Loaded: Load a PCAP file first.")
            return

        # Create a progress dialog
        progress_dialog = QProgressDialog("Threat Intelligence is running, please wait...", "Cancel", 0, 0, self)
        progress_dialog.setWindowModality(Qt.WindowModal)
        progress_dialog.show()

        # Track malicious IPs and domains
        malicious_ips = set()
        malicious_domains = set()

        # Track checked IPs and domains
        checked_ips = set()
        checked_domains = set()

        # Track indices for coloring rows in the table widget
        malicious_ip_indices = []
        malicious_domain_indices = []

        # Iterate through loaded packets
        for i, packet in enumerate(self.packets):
            # Check if the progress dialog was canceled
            if progress_dialog.wasCanceled():
                progress_dialog.close()
                return

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Check source IP
                if not is_private_ip(src_ip) and src_ip not in checked_ips:
                    self.box_widget.append(f"Checking VirusTotal for source IP: {src_ip}")
                    src_result = check_ip(ip=src_ip)
                    if src_result and src_result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                        self.box_widget.append(f"Malicious IP Detected: {src_ip}")
                        malicious_ips.add(src_ip)
                        malicious_ip_indices.append(i)
                    checked_ips.add(src_ip)

                # Check destination IP
                if not is_private_ip(dst_ip) and dst_ip not in checked_ips:
                    self.box_widget.append(f"Checking VirusTotal for destination IP: {dst_ip}")
                    dst_result = check_ip(ip=dst_ip)
                    if dst_result and dst_result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                        self.box_widget.append(f"Malicious IP Detected: {dst_ip}")
                        malicious_ips.add(dst_ip)
                        malicious_ip_indices.append(i)
                    checked_ips.add(dst_ip)

            # Handle DNS packets
            if DNS in packet:
                # Extract domain and check with VirusTotal if not already checked
                domain = packet[DNSQR].qname.decode('utf-8')
                self.box_widget.append(f"Domain: {domain}")

                if domain not in checked_domains:
                    domain_result = check_domains(domain=domain)
                    if domain_result:
                        if domain_result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                            self.box_widget.append(f"Suspicious/Malicious Domain Detected: {domain}")
                            malicious_domains.add(domain)
                            malicious_domain_indices.append(i)
                        else:
                            self.box_widget.append(f"Non-malicious Domain: {domain}")
                    checked_domains.add(domain)

            # Update progress dialog
            progress_dialog.setValue(i + 1)  # Update progress bar position
            QApplication.processEvents()  # Keep the application responsive during the loop

        # Close the progress dialog once the operation is completed
        progress_dialog.close()

        # Color rows in the table widget for malicious IPs and domains
        for index in malicious_ip_indices + malicious_domain_indices:
            for col in range(self.tableWidget.columnCount()):
                item = self.tableWidget.item(index, col)
                if item:
                    item.setBackground(QColor(255, 0, 0))  # Red color for malicious activity

        # Display final message box with analysis results
        if malicious_ips or malicious_domains:
            result_text = f"Malicious IPs Detected: {', '.join(malicious_ips)}\n" \
                          f"Malicious Domains Detected: {', '.join(malicious_domains)}"
            QMessageBox.information(self, "Threat Intelligence Analysis", result_text)
        else:
            QMessageBox.information(self, "Threat Intelligence Analysis", "No malicious IPs or domains detected.")


