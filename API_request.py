import requests
from scapy.all import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import TCP, UDP, IP
#from cap import *



# API handling
#DEFAULT_API_KEY = '73b572bcb4392e4b9bbb09b969726c36ec11d098e232886ad58bfc4c770704a8'
DEFAULT_API_KEY='9237709c6ff87717bbcc802a491426791cb195bfde12906c078b50cd7991f4dd'
# Seif:66cc85e83423da3f5cf7ecd3bf5a5c00a1de9c2c3d556730edcc0977be164e73
# aser:c74afb87c3ab52f560c275a8118920e00eac805daf5e36101a44c5808f6b589e
# seb:73b572bcb4392e4b9bbb09b969726c36ec11d098e232886ad58bfc4c770704a8 --> in use

def check_ip(api_key=None, ip=None):
    if not api_key:
        api_key = DEFAULT_API_KEY

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'x-apikey': api_key,
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return None

def check_domains(api_key=None, domain=None):
    if not api_key:
        api_key = DEFAULT_API_KEY

    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {
        'x-apikey': api_key,
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return None

def extract_domains(packet):
    if DNSQR in packet:
        # Extract domain name from DNS query
        domain = packet[DNSQR].qname.decode('utf-8')
        print("Domain:", domain)
        result = check_domains(domain=domain)
        if result:
            if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                print(f"Suspicious/Malicious Domain Detected: {domain}")
                return True
            else:
                print(f"Non-malicious Domain: {domain}")
                return False


def is_private_ip(src_ip):
    return src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.')

