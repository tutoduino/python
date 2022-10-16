#!/usr/bin/python3
# coding: utf-8
import string
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest

# Analyse PCAP file 
# Process only HTTP POST methods 
# with content type application/x-www-form-urlencoded
# from the IP adress "interesting_ip"
interesting_ip = '192.168.1.1'
pcap_file_name = "my_file.pcap"

def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        ether_pkt = Ether(pkt_data)

        if not ether_pkt.haslayer(TCP):
            continue

        if (ether_pkt[IP].src != interesting_ip) and (ether_pkt[IP].dst != interesting_ip):
            # Uninteresting IP address
            continue

        if not ether_pkt.haslayer(HTTPRequest):
            # Uninteresting HTTP msg
            continue

        if ether_pkt[HTTPRequest].Method.decode() != 'POST':
            # Uninteresting HTTP request method
            continue

        if ether_pkt[HTTPRequest].Content_Type.decode() != 'application/x-www-form-urlencoded':
            # Uninteresting content type
            continue

        print("packet found")
        # Process packet here


if __name__ == '__main__':
    """
    Process the pcap file
    """
    print("Program started")
    process_pcap(pcap_file_name)
    print("Program completed")
  