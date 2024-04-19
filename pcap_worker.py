from scapy.all import rdpcap

class PcapWorker:
    def __init__(self, file_path):
        self.file_path = file_path
        self.packets = []

    def load_packets(self):
        try:
            self.packets = rdpcap(self.file_path)
            return True
        except Exception as e:
            print("Error loading PCAP file:", e)
            return False
