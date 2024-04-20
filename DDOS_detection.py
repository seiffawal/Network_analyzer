from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP, ICMP
from scapy.layers.dns import DNSQR, DNS
import yaml

# Define the path to your attack pattern YAML file
ATTACK_PATTERN_FILE = r"db/pattern.yml"


def load_attack_patterns():
    # Load attack patterns from the YAML file
    with open(ATTACK_PATTERN_FILE, 'r') as file:
        return yaml.safe_load(file)['attacks']


def detect_attack(packet, attack_pattern):
    # Determine the protocol of the attack pattern
    protocol = attack_pattern['protocol']

    if protocol == 'TCP' and packet.haslayer(TCP):
        for condition in attack_pattern['conditions']:
            # Check flags in the packet
            if 'flags' in condition and all(flag in packet[TCP].flags for flag in condition['flags']):
                return True
            # Check options in the packet
            if 'options' in condition and all(opt in str(packet[TCP].options) for opt in condition['options']):
                return True

    elif protocol == 'UDP' and packet.haslayer(UDP):
        for condition in attack_pattern['conditions']:
            # Check destination port in the packet
            if 'dport' in condition and packet[UDP].dport == condition['dport']:
                return True
            # Add more conditions for UDP patterns if needed

    # Add logic for other protocols if needed

    return False


def packet_callback(packet, attack_patterns):
    results = []
    for attack_pattern in attack_patterns:
        if detect_attack(packet, attack_pattern):
            result = f"Detected {attack_pattern['name']} attack: {packet.summary()}"
            results.append(result)
    return results


def process_pcap(packets):
    # Load attack patterns from the YAML file
    attack_patterns = load_attack_patterns()
    results = []

    # Iterate through the list of packets and check each packet for attacks
    for packet in packets:
        results.extend(packet_callback(packet, attack_patterns))

    return results  # Return a list of results from the packet analysis
