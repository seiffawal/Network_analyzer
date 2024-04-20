
from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP, ICMP
from scapy.layers.dns import DNSQR, DNS
import yaml

# Define the path to your attack pattern YAML file
ATTACK_PATTERN_FILE = r"db/pattern.yml"

def load_attack_patterns():
    with open(ATTACK_PATTERN_FILE, 'r') as file:
        return yaml.safe_load(file)['attacks']

def detect_attack(packet, attack_pattern):
    protocol = attack_pattern['protocol']

    if protocol == 'TCP' and packet.haslayer(TCP):
        for condition in attack_pattern['conditions']:
            if 'flags' in condition:
                if all(flag in packet[TCP].flags for flag in condition['flags']):
                    return True
            if 'options' in condition:
                if all(opt in str(packet[TCP].options) for opt in condition['options']):
                    return True
        # Add more conditions for TCP patterns if needed

    elif protocol == 'UDP' and packet.haslayer(UDP):
        for condition in attack_pattern['conditions']:
            if 'dport' in condition and packet[UDP].dport == condition['dport']:
                return True
            # Add more conditions for UDP patterns if needed

    # Add logic for other protocols if needed

    return False

def packet_callback(packet, attack_patterns):
    for attack_pattern in attack_patterns:
        if detect_attack(packet, attack_pattern):
            print(f"Detected {attack_pattern['name']} attack:", packet.summary())

def process_pcap(file_path):
    attack_patterns = load_attack_patterns()
    pcap = PcapReader(file_path)
    for packet in pcap:
        packet_callback(packet, attack_patterns)
