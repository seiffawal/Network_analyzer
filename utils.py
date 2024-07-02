import re

from scapy.layers.http import HTTPRequest
from scapy.layers.inet import *
from scapy.layers.inet6 import IPv6
from datetime import datetime

protocol_names = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}

def convert_timestamp(ts):
    # Convert Scapy's EDecimal to float explicitly
    ts_float = float(ts)
    return datetime.fromtimestamp(ts_float).strftime('%d/%m/%Y %H:%M:%S')

def extract_packet_info(packet):
    packet_info = {}
    try:
        if IP in packet:
            packet_info['time'] = convert_timestamp(packet.time)
            packet_info['source_ip'] = packet[IP].src
            packet_info['destination_ip'] = packet[IP].dst
            packet_info['protocol_number'] = packet[IP].proto
            packet_info['protocol_name'] = protocol_names.get(packet[IP].proto, 'Unknown')
            packet_info['packet_length'] = len(packet)
        elif IPv6 in packet:
            packet_info['time'] = packet.time
            packet_info['source_ip'] = packet[IPv6].src
            packet_info['destination_ip'] = packet[IPv6].dst
            packet_info['protocol_number'] = packet[IPv6].nh
            packet_info['protocol_name'] = protocol_names.get(packet[IPv6].nh, 'Unknown')
            packet_info['packet_length'] = len(packet)
    except Exception as e:
        print("Error extracting packet information:", e)
    return packet_info

def read_fuzzing_patterns(patterns_file):
    with open(patterns_file, 'r') as file:
        patterns = [line.strip() for line in file if line.strip()]
    return patterns

def detect_directory_fuzzing(http_traffic, fuzzing_patterns):
    count = 0
    for pkt in http_traffic:
        if pkt.haslayer(HTTPRequest):
            url = pkt[HTTPRequest].Path.decode()
            for pattern in fuzzing_patterns:
                if re.search(pattern, url):
                    count += 1
                    # Break the loop if a pattern matches
                    break
    # Return the result as a string
    result = f"Potential directory fuzzing detected: Count of {count}" if count >= 650 else "No significant directory fuzzing detected"
    return result
