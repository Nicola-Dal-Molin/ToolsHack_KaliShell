#!/usr/bin/env python

import re
import sys
import os

def check_root():
    """Verifica se lo script è eseguito con privilegi di root."""
    if os.geteuid() != 0:
        sys.exit("[KO] Esegui questo script con privilegi di root (sudo).")

def set_nic_mac(nic, mac):
    """Cambia l'indirizzo MAC della scheda di rete utilizzando 'ifconfig' o 'ip'."""
    print(f"[OK] Cambiando il MAC della scheda {nic} a {mac}...")

    # Verifica se 'ifconfig' è disponibile
    if os.system("which ifconfig > /dev/null 2>&1") == 0:
        command = f"ifconfig {nic} down && ifconfig {nic} hw ether {mac} && ifconfig {nic} up"
    # Verifica se 'ip' è disponibile
    elif os.system("which ip > /dev/null 2>&1") == 0:
        command = f"ip link set dev {nic} down && ip link set dev {nic} address {mac} && ip link set dev {nic} up"
    else:
        sys.exit("[KO] Né 'ifconfig' né 'ip' sono disponibili. Installa uno dei due strumenti.")

    # Esegui il comando
    if os.system(command) != 0:
        sys.exit("[KO] Errore nel cambio del MAC.")

def validate_mac(mac):
    """Verifica se il MAC address fornito è valido."""
    if not re.match(r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$", mac):
        sys.exit("[KO] Formato MAC non valido! Usa il formato XX:XX:XX:XX:XX:XX")

def get_inputs():
    """Richiede input manuale dall'utente."""
    print("[+] Strumento per il cambio del MAC Address")
    nic = input("Inserisci il nome della scheda di rete (es. eth0, wlan0): ").strip()
    mac = input("Inserisci il nuovo MAC Address (es. 00:11:22:33:44:55): ").strip()
    validate_mac(mac)  # Valida il formato del MAC.
    return nic, mac

def run():
    """Funzione principale per eseguire il cambio del MAC address."""
    check_root()  # Verifica i privilegi di root.
    nic, mac = get_inputs()  # Ottieni i dati richiesti dall'utente.

    # Imposta il nuovo MAC Address.
    set_nic_mac(nic, mac)
    
    # Conferma il cambio del MAC.
    print(f"[OK] MAC Address della scheda {nic} cambiato con successo a {mac}.")

if __name__ == "__main__":
    run()  # Esegui la funzione run()
