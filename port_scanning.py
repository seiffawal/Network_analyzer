from scapy.all import *
from scapy.layers.inet import *


def detect_port_scan2(pcap_file):
    # Dictionary to store counts of unique destination ports per source IP
    port_counts = {}

    # Load the pcap file
    packets = rdpcap(pcap_file) #pcapreader

    # Loop through each packet in the pcap file
    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if TCP in packet:
                # If packet is TCP, extract destination port
                dst_port = packet[TCP].dport
            elif UDP in packet:
                # If packet is UDP, extract destination port
                dst_port = packet[UDP].dport
            else:
                # Skip non-TCP and non-UDP packets
                continue

            # Count destination ports per source IP
            if ip_src in port_counts:
                port_counts[ip_src].add(dst_port)
            else:
                port_counts[ip_src] = {dst_port}

    # Check for port scanning activity
    for ip_src, ports in port_counts.items():
        # If more than a threshold (e.g., 10) unique ports are targeted
        if len(ports) > 10:
            print(f"Port scanning detected from {ip_src}: {len(ports)} unique ports targeted")


def detect_port_scan(pcap_file):
    # Load the pcap file
    packets = rdpcap(pcap_file)

    # Define patterns to detect
    patterns = [
        {
            "name": "TCP ACK Scan",
            "signature": {
                "flags": {"A": 1}
            }
        },
        {
            "name": "TCP Christmas Scan",
            "signature": {
                "flags": {"F": 1, "P": 1, "U": 1}
            }
        },
        {
            "name": "TCP FIN Scan",
            "signature": {
                "flags": {"F": 1}
            }
        },
        {
            "name": "TCP SYN (Stealth) Scan",
            "description": "SYN scan is the default and most popular scan option for good reason. It can be performed quickly, scanning thousands of ports per second on a fast network not hampered by intrusive firewalls. SYN scan is relatively unobtrusive and stealthy, since it never completes TCP connections. It also works against any compliant TCP stack rather than depending on idiosyncrasies of specific platforms as Nmap's FIN/NULL/Xmas, Maimon and idle scans do. It also allows clear, reliable differentiation between open, closed, and filtered states.",
            "signature": {
                "flags": {"S": 1}
            }
        },
        {
            "name": "TCP Connect() Scan",
            "description": "TCP Connect() scan",
            "signature": {
                "flags": {"S": 1, "A": 1}
            }
        },
        {
            "name": "TCP Window Scan",
            "description": "TCP Window Scan",
            "signature": {
                "flags": {"W": 1}
            }
        },
        {
            "name": "TCP Maimon Scan",
            "description": "TCP Maimon Scan",
            "signature": {
                "flags": {"M": 1}
            }
        },
        {
            "name": "UDP Scan",
            "description": "UDP Scan",
            "signature": {
                "protocol": "UDP"
            }
        },
        {
            "name": "TCP Null Scan",
            "description": "TCP Null Scan",
            "signature": {
                "flags": {}
            }
        },
        {
            "name": "TCP Xmas Scan",
            "description": "TCP Xmas Scan",
            "signature": {
                "flags": {"F": 1, "P": 1, "U": 1}
            }
        },
        # Add more patterns as needed...
    ]

    # Loop through each packet in the pcap file
    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if TCP in packet:
                protocol = "TCP"
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
            elif UDP in packet:
                protocol = "UDP"
                dst_port = packet[UDP].dport
                flags = None  # UDP packets do not have flags
            else:
                # Skip non-TCP and non-UDP packets
                continue

            # Check against each pattern
            for pattern in patterns:
                if "protocol" in pattern["signature"]:
                    if protocol == pattern["signature"]["protocol"]:
                        print(f"Detected {pattern['name']} from {ip_src} to {ip_dst}, port {dst_port}")
                        break
                elif protocol == "TCP":
                    # Check TCP flags
                    if pattern["signature"]["flags"] == "any":
                        # For TCP Mask Scan
                        print(f"Detected {pattern['name']} from {ip_src} to {ip_dst}, port {dst_port}")
                        break
                    elif all(getattr(flags, flag, 0) == value for flag, value in pattern["signature"]["flags"].items()):
                        print(f"Detected {pattern['name']} from {ip_src} to {ip_dst}, port {dst_port}")
                        break
                elif protocol == "UDP" and "TCP UDP Scan" in pattern["name"]:
                    # Special handling for TCP UDP Scan
                    print(f"Detected {pattern['name']} from {ip_src} to {ip_dst}, port {dst_port}")
                    break