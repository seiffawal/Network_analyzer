from PyQt5.QtCore import QObject, pyqtSignal
import logging
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.inet import *
class NmapDetectionWorker(QObject):
    resultReady = pyqtSignal(str)

    def detect_nmap_fingerprinting(self, packets, log_file_path):
        # Configure logging if log_file_path is provided
        if log_file_path:
            logging.basicConfig(filename=log_file_path, level=logging.DEBUG,
                                format='%(asctime)s - %(levelname)s - %(message)s')

        def nmap_worker():
            logging.info("Starting Nmap fingerprint detection...")
            nmap_os_db_file = r"db/nmap-os-db"
            logging.info("Loading Nmap OS database file...")
            with open(nmap_os_db_file, 'r', encoding='utf-8') as f:  # Specify UTF-8 encoding
                nmap_os_db_content = f.read()
            logging.info("Nmap OS database file loaded.")

            # Extract Nmap signature patterns
            nmap_signatures = []
            logging.info("Extracting Nmap signature patterns...")
            for line in nmap_os_db_content.split('\n'):
                if not line.startswith('#') and line.strip() != "":
                    nmap_signatures.append(line.split()[0])  # Extract first token (Nmap signature)
            logging.info("Nmap signature patterns extracted.")

            # Initialize counters
            nmap_packets_count = 0
            detected_packets_count = 0
            detected_signatures = set()

            # Analyze packets
            logging.info("Analyzing packets...")
            for packet in packets:
                if TCP in packet:
                    # Check for each match point
                    match_points = [
                        packet[TCP].window,
                        packet[TCP].options,
                        packet[TCP].flags
                    ]
                    if all(match_points):  # Check if all match points are present
                        # Add the signature to the detected signatures set
                        detected_signatures.add("Nmap OS detection attempt")
                        detected_packets_count += 1
                        logging.info("Nmap signature detected in packet.")
                # Increment packet count regardless of the conditions above
                nmap_packets_count += 1
                logging.info(f"Processed {nmap_packets_count} packets")

            # Calculate percentage of packets with Nmap signatures
            percentage = (detected_packets_count / nmap_packets_count) * 100

            logging.info("Packet analysis completed.")

            # Print results
            result = "Total packets analyzed: {}\n".format(nmap_packets_count)
            result += "Detected Nmap packets: {}\n".format(detected_packets_count)
            result += "Percentage of packets with Nmap signatures: {} %\n".format(percentage)
            if detected_signatures:
                result += "Detected Nmap signatures:\n"
                for signature in detected_signatures:
                    result += "- {}\n".format(signature)
                result += "Potential OS detection attempt detected!\n"
            else:
                result += "No Nmap signatures detected.\n"

            self.resultReady.emit(result)

        with ThreadPoolExecutor() as executor:
            executor.submit(nmap_worker)
