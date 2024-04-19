# packet_capture_thread.py

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff

from utils import extract_packet_info


class PacketCaptureThread(QThread):
    packetCaptured = pyqtSignal(object)

    def run(self):
        try:
            sniff(prn=self.process_packet)  # Capture packets and process them one by one
        except Exception as e:
            print("Error capturing packets:", e)

    def process_packet(self, packet):
        packet_info = extract_packet_info(packet)
        self.packetCaptured.emit(packet_info)
