import re
from scapy.all import *

def extract_payloads(pcap_file):
    payloads = []

    # Load the pcap file
    packets = rdpcap(pcap_file)

    # Iterate through each packet
    for packet in packets:
        # Check if the packet has a payload
        if packet.haslayer(Raw):
            # Extract the payload and append it to the list
            payload = packet[Raw].load
            payloads.append(payload)

    return payloads

def detect_sql_injection(payloads):
    sql_injections = []

    # Regular expression patterns for SQL injection detection
    sql_patterns = [
        r"(?i)\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|DROP TABLE|CREATE TABLE|ALTER TABLE)\b",
        r"\b(OR|AND)\b",
        r"\b(UNION)\b",
        r"\b(--)\b",
        r"\b(SLEEP)\b",
        r"\b(GROUP BY)\b",
        r"\b(EXEC)\b",
        r"\b(EXECUTE)\b",
        r"\b(DECLARE)\b",
        r"\b(CAST)\b",
        r"\b(ASCII)\b",
        r"\b(CHAR)\b",
        r"\b(COALESCE)\b",
        r"\b(EXISTS)\b",
        r"\b(ALL)\b",
        r"\b(ANY)\b",
        r"\b(CASE)\b",
        r"\b(INTERSECT)\b",
        r"\b(EXCEPT)\b",
        r"\b(INSERT INTO SELECT)\b",
        r"\b(SELECT FROM)\b",
        r"\b(SELECT * FROM)\b",
        r"\b(SELECT COUNT FROM)\b",
        r"\b(SELECT DISTINCT FROM)\b"
    ]

    # Iterate through each payload
    for idx, payload in enumerate(payloads):
        # Convert payload from bytes to string
        payload_str = payload.decode('utf-8', errors='ignore')
        # Check for each SQL injection pattern
        for pattern in sql_patterns:
            # Search for SQL injection patterns
            if re.search(pattern, payload_str):
                sql_injections.append((idx + 1, payload_str))
                break  # Break out of the loop if any pattern is found

    return sql_injections


def detect_xss(payloads):
    xss_attacks = []

    # Regular expression patterns for XSS detection
    xss_patterns = [
        r"<script>",
        r"</script>",
        r"<img src=",
        r"onmouseover=",
        r"onerror=",
        r"alert\(",
        r"document.cookie",
        r"document.location",
        r"window.location",
        r"eval\(",
        r"setTimeout\(",
        r"setInterval\("
    ]

    # Iterate through each payload
    for idx, payload in enumerate(payloads):
        # Convert payload from bytes to string
        payload_str = payload.decode('utf-8', errors='ignore')
        # Check for each XSS pattern
        for pattern in xss_patterns:
            # Search for XSS patterns
            if re.search(pattern, payload_str):
                # Append the index and the payload as a plain string
                xss_attacks.append((idx + 1, payload_str))
                break  # Break out of the loop if any pattern is found

    return xss_attacks










