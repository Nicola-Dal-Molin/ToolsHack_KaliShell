#!/usr/bin/env python

import subprocess
import argparse
import re
import sys

def check_root():
    """Verifica se lo script è eseguito con privilegi di root."""
    if not subprocess.getoutput("id -u") == "0":
        sys.exit("[KO] Esegui questo script con privilegi di root (sudo).")

def set_nic_mac(nic, mac):
    """Cambia l'indirizzo MAC della scheda di rete."""
    print(f"[OK] Changing MAC for {nic} to {mac}...")
    try:
        subprocess.run(["ifconfig", nic, "down"], check=True)
        subprocess.run(["ifconfig", nic, "hw", "ether", mac], check=True)
        subprocess.run(["ifconfig", nic, "up"], check=True)
    except subprocess.CalledProcessError:
        sys.exit("[KO] Errore nel cambio del MAC. Verifica il nome della scheda di rete.")

def get_cli_arguments():
    """Ottiene gli argomenti della riga di comando."""
    parser = argparse.ArgumentParser(description="Change MAC Address Tool")
    parser.add_argument("-n", "--nic", required=True, help="Interfaccia di rete (es. eth0, wlan0)")
    parser.add_argument("-m", "--mac", required=True, help="Nuovo MAC address (es. 00:11:22:33:44:55)")
    args = parser.parse_args()
    
    # Verifica se il MAC address fornito è valido
    if not re.match(r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$", args.mac):
        sys.exit("[KO] Formato MAC non valido! Usa il formato XX:XX:XX:XX:XX:XX")
    
    return args

def get_nic_mac(nic):
    """Recupera l'indirizzo MAC attuale della scheda di rete."""
    try:
        ifconfig_dump = subprocess.check_output(["ifconfig", nic]).decode("utf-8")
    except subprocess.CalledProcessError:
        sys.exit("[KO] Interfaccia non trovata. Verifica il nome della scheda di rete.")

    mac_match = re.search(r"(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", ifconfig_dump)
    if mac_match:
        return mac_match.group(0)
    else:
        sys.exit("[KO] Impossibile recuperare l'indirizzo MAC!")

if __name__ == "__main__":
    check_root()
    options = get_cli_arguments()
    
    print(f"[+] Indirizzo MAC attuale di {options.nic}: {get_nic_mac(options.nic)}")
    set_nic_mac(options.nic, options.mac)
    
    mac_set = get_nic_mac(options.nic)
    if mac_set.lower() == options.mac.lower():
        print(f"[OK] MAC cambiato con successo a {mac_set}")
    else:
        sys.exit("[KO] Fallimento nel cambio del MAC.")
