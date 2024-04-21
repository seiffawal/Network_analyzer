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
from PyQt5.QtGui import QColor, QPixmap, QPalette, QBrush, QTransform
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6
from API_request import *
from port_scanning import *
from DDOS_detection import *
from injections import *

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Analyzer")
        self.setGeometry(100, 100, 800, 600)
        self.dark_mode = False

        # Load the image file
        self.image_path = "uhd-6686654.jpg"  # Replace with the path to your image file

        # # Create a QPixmap from the image file
        # pixmap = QPixmap(image_path)
        #
        # # Convert QPixmap to QBrush
        # brush = QBrush(pixmap)
        #
        # # Create a palette and set the background brush to the pixmap
        # palette = self.palette()
        # palette.setBrush(QPalette.Window, brush)
        #
        # # Set the palette to the main window
        # self.setPalette(palette)

        self.set_background_image()

        file_menu = self.menuBar().addMenu("&File")
        edit_menu = self.menuBar().addMenu("&Edit")
        view_menu = self.menuBar().addMenu("&View")
        capture_menu = self.menuBar().addMenu("&Capture")
        analyze_menu = self.menuBar().addMenu("&Analyze")
        preferences_menu = self.menuBar().addMenu("&Preferences")

        load_action = self.create_action("&Load PCAP", self.load_pcap)
        file_menu.addAction(load_action)

        load_pcapng_action = self.create_action("&Load PCAPNG", self.load_pcapng)
        file_menu.addAction(load_pcapng_action)

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

        ddos_detection_action = self.create_action("DDOS Detection", self.ddos_detection_action)
        analyze_menu.addAction(ddos_detection_action)

        analyze_menu.addAction(self.create_action("Port Scan", self.port_scan_action))

        sql_injection_action = self.create_action("Injection", self.sql_injection_action)
        analyze_menu.addAction(sql_injection_action)



        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        self.tableWidget = QTableWidget()
        main_layout.addWidget(self.tableWidget)
        self.tableWidget.setStyleSheet("QTableWidget { background: rgba(255, 255, 255, 0); }")  # Transparent

        self.box_widget = QTextEdit()
        main_layout.addWidget(self.box_widget)
        self.box_widget.setReadOnly(True)
        self.box_widget.setStyleSheet("QTextEdit { background: rgba(255, 255, 255, 0); }")  # Transparent


        self.packets = []
        self.capturing = False
        self.packetCaptureThread = None

        self.tableWidget.cellClicked.connect(self.select_entire_row)

        self.nmap_detection_thread = QThread()
        self.nmap_detection_thread.start()

        self.nmap_detection_worker = NmapDetectionWorker()
        self.nmap_detection_worker.moveToThread(self.nmap_detection_thread)
        self.nmap_detection_worker.resultReady.connect(self.update_box_widget)

    def set_background_image(self):
        """Sets the background image of the main window."""
        # Create a QPixmap from the image file
        pixmap = QPixmap(self.image_path)

        # Resize the pixmap to the window size
        pixmap = pixmap.scaled(self.size(), Qt.IgnoreAspectRatio, Qt.SmoothTransformation)

        # Create a QBrush with the pixmap
        brush = QBrush(pixmap)

        # Set the brush as the background of the window
        palette = self.palette()
        palette.setBrush(QPalette.Window, brush)
        self.setPalette(palette)

    def print_header_message(self, analysis_name):
        # Define the number of asterisks on each side
        asterisks_count = 30

        # Create the header message with asterisks on each side and the analysis name in the middle
        header_message = f"{'*' * asterisks_count} {analysis_name} {'*' * asterisks_count}"

        # Print the header message to the box_widget
        self.box_widget.append(header_message)
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
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng)")  # Adjusted filter
        if file_path:
            self.clear_box_widget()  # Clear the box widget
            self.load_packets(file_path)

    def load_pcapng(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PCAPNG File", "", "PCAPNG Files (*.pcapng)")  # Filter for pcapng files
        if file_path:
            self.clear_box_widget()  # Clear the box widget
            self.load_packets(file_path)

    def load_packets(self, file_path):
        with ThreadPoolExecutor() as executor:
            worker = PcapWorker(file_path)
            if executor.submit(worker.load_packets).result():
                self.packets = worker.packets
                self.display_packet_data()
                # Set table widget to full visibility when PCAP is loaded
                self.tableWidget.setStyleSheet("QTableWidget { background: rgba(255, 255, 255, 1.0); }")

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
                        QMainWindow {
                            background-color: #222;
                            color: #fff;
                        }
                        QTableWidget {
                            background-color: #fff;
                            color: #000;
                        }
                        QTextEdit {
                            background-color: #333;
                            color: #fff;
                        }
                        QMenu {
                            background-color: #333;
                            color: #fff;
                            selection-background-color: #555;  # Lighter gray for the highlight
                            selection-color: #fff;
                        }
                        QAction {
                            selection-background-color: #555;  # Lighter gray for the highlight
                        }
                    """)
        else:
            # Reset to default styles in light mode
            self.setStyleSheet("")
            self.tableWidget.setStyleSheet("")
            # Resetting the box_widget style to default
            self.box_widget.setStyleSheet("")

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

        # Set box_widget to full visibility when an analysis action is used
        self.box_widget.setStyleSheet("QTextEdit { background: rgba(255, 255, 255, 1.0); }")

        # Print header message
        self.print_header_message("Email Extraction")

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

                    # Append the email addresses found in the payload to the email_results list
                    if emails:
                        email_results.extend(emails)

            except Exception as e:
                print(f"Error processing packet {i + 1}: {str(e)}")

        # Display the email extraction results in the box_widget
        if email_results:
            self.box_widget.append("\nEmail Addresses Found:")
            for email in email_results:
                self.box_widget.append(email)
        else:
            # Show a QMessageBox if no email addresses are found
            QMessageBox.information(self, "No Email Addresses Found",
                                    "No email addresses found in the captured packets.")

    def os_detection_action(self):
        if not self.packets:
            QMessageBox.warning(self, "No Patterns File Selected", "Please select a patterns file.")
            return

        reply = QMessageBox.question(self, "Save Log?", "Do you want to save the log?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        # Set box_widget to full visibility when an analysis action is used
        self.box_widget.setStyleSheet("QTextEdit { background: rgba(255, 255, 255, 1.0); }")

        # Print header message
        self.print_header_message("OS Detection")

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

        # Set box_widget to full visibility when an analysis action is used
        self.box_widget.setStyleSheet("QTextEdit { background: rgba(255, 255, 255, 1.0); }")

        # Print header message
        self.print_header_message("Fuzzy Detection")

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
            QMessageBox.warning(self, "No Patterns File Selected", "Please select a patterns file.")
            return

        # Set box_widget to full visibility when an analysis action is used
        self.box_widget.setStyleSheet("QTextEdit { background: rgba(255, 255, 255, 1.0); }")

        # Print header message
        self.print_header_message("Threat Intelligence")

        # Create a progress dialog
        progress_dialog = QProgressDialog("Threat Intelligence is running, please wait...", "Cancel", 0, 0, self)
        progress_dialog.setWindowTitle("Loading")
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

    def port_scan_action(self):
        # Check if there are packets loaded
        if not self.packets:
            QMessageBox.warning(self, "No PCAP Loaded", "Please load a PCAP file first.")
            return

        # Set box_widget to full visibility when an analysis action is used
        self.box_widget.setStyleSheet("QTextEdit { background: rgba(255, 255, 255, 1.0); }")

        self.print_header_message("Port Scan")

        # Display header for Port Scan Analysis
        self.box_widget.append("\nPort Scan Analysis")

        # Call the detect_port_scan function and pass self.box_widget.append as the display function
        self.box_widget.append("\nBasic Port Scan Detection:")
        detect_port_scan(self.packets, self.box_widget.append)

        # Call the detect_port_scan2 function and pass self.box_widget.append as the display function
        self.box_widget.append("\nAdvanced Port Scan Detection:")
        detect_port_scan2(self.packets, self.box_widget.append)

    def ddos_detection_action(self):
        # Check if there are packets loaded
        if not self.packets:
            QMessageBox.warning(self, "No PCAP Loaded", "Please load a PCAP file first.")
            return

        # Set box_widget to full visibility when an analysis action is used
        self.box_widget.setStyleSheet("QTextEdit { background: rgba(255, 255, 255, 1.0); }")

        # Print header message
        self.print_header_message("DDOS Detection")

        try:
            # Call the DDOS detection function with the loaded packets
            results = process_pcap(self.packets)  # Pass self.packets to process_pcap

            # Display the results in the box widget
            if results:
                for result in results:
                    self.box_widget.append(result)
            else:
                self.box_widget.append("No DDOS attacks detected in the loaded PCAP.")

        except Exception as e:
            QMessageBox.warning(self, "DDOS Detection Error", f"An error occurred during DDOS detection: {str(e)}")

    def sql_injection_action(self):
        # Check if there are packets loaded
        if not self.packets:
            QMessageBox.warning(self, "No PCAP Loaded", "Please load a PCAP file first.")
            return

        # Set box_widget to full visibility when an analysis action is used
        self.box_widget.setStyleSheet("QTextEdit { background: rgba(255, 255, 255, 1.0); }")

        # Print header message
        self.print_header_message("Injection Detection")

        # Extract payloads from the packets
        payloads = [pkt[Raw].load for pkt in self.packets if Raw in pkt]

        # Detect SQL injections in the extracted payloads
        detected_injections = detect_sql_injection(payloads)

        # Detect XSS attacks in the extracted payloads
        detected_xss_attacks = detect_xss(payloads)

        # Display detected SQL injections in the box_widget
        if detected_injections:
            self.box_widget.append("\nDetected SQL Injections:")
            for idx, payload_str in detected_injections:
                self.box_widget.append(f"Payload {idx}: {payload_str}")
        else:
            self.box_widget.append("\nNo SQL Injections detected.")

        # Display detected XSS attacks in the box_widget
        if detected_xss_attacks:
            self.box_widget.append("\nDetected XSS Attacks:")
            for idx, payload_hex in detected_xss_attacks:
                self.box_widget.append(f"Payload {idx}: {payload_hex}")
        else:
            self.box_widget.append("\nNo XSS Attacks detected.")





