import threading
import queue
from scapy.all import ARP, Ether, srp
import socket
import subprocess
import re
import sys
import signal

# Controllo permessi di root
def check_root():
    if subprocess.getoutput("id -u") != "0":
        sys.exit("[ERRORE] Esegui questo script con privilegi di root (sudo).")

# Ottenere la rete attiva
def get_network():
    try:
        result = subprocess.check_output(["ip", "route"], text=True)
        match = re.search(r"default via [\d\.]+ dev (\S+)", result)
        if match:
            interface = match.group(1)
            ip_result = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show", interface], text=True)
            ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", ip_result)
            if ip_match:
                return ip_match.group(1)
        print("[ERRORE] Nessuna rete attiva rilevata.")
    except subprocess.CalledProcessError:
        print("[ERRORE] Impossibile ottenere la rete. Verifica la connessione.")
    return None

# Scansione della rete con ARP
def scan_network(ip_range):
    print(f"[+] Scansione in corso sulla rete: {ip_range}")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    try:
        answered = srp(packet, timeout=1, verbose=0)[0]
        active_hosts = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in answered]
        return active_hosts
    except Exception as e:
        print(f"[ERRORE] Scansione ARP fallita: {e}")
        return []

# Ottenere il banner del servizio da una porta
def get_service_banner(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((host, port))
            if port in [80, 443]:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                server_line = [line for line in banner.split("\r\n") if "Server" in line]
                return server_line[0].split(": ")[1].strip() if server_line else "HTTP Server (unknown)"
            return "Unknown Service"
    except Exception:
        return None

# Scansione porte sugli host
def scan_ports(host, port_queue, open_ports):
    while not port_queue.empty():
        port = port_queue.get()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                if result == 0:
                    banner = get_service_banner(host, port)
                    open_ports.append((port, banner or "Unknown Service"))
        except Exception:
            pass
        finally:
            port_queue.task_done()

# Funzione per ottenere gli input dell'utente
def get_user_inputs():
    """Chiede all'utente di inserire l'intervallo delle porte e il numero di thread."""
    print("[+] Strumento di scansione di rete e porte")

    port_range = input("Inserisci l'intervallo delle porte (es. 1-1024): ").strip()
    try:
        port_start, port_end = map(int, port_range.split("-"))
        if port_start < 1 or port_end > 65535 or port_start > port_end:
            raise ValueError
    except ValueError:
        print("[ERRORE] Formato dell'intervallo porte non valido. Usa il formato '1-65535'.")
        sys.exit(1)

    threads = int(input("Inserisci il numero di thread da utilizzare (predefinito: 10): ").strip())
    if threads < 1:
        threads = 10  # Valore di default

    return (port_start, port_end), threads

# Funzione per gestire l'interruzione tramite Ctrl+C
def handle_interruption(signum, frame):
    print("\n[INFO] Esecuzione interrotta. Uscita in corso...")
    sys.exit(0)

# Funzione principale per l'esecuzione
def run():
    # Impostiamo il gestore per l'interruzione (Ctrl+C)
    signal.signal(signal.SIGINT, handle_interruption)

    # Controlla i permessi di root
    check_root()

    # Ottieni l'intervallo delle porte e il numero di thread
    port_range, num_threads = get_user_inputs()

    # Ottieni la rete attiva
    ip_range = get_network()
    if not ip_range:
        print("[ERRORE] Nessuna rete rilevata. Uscita.")
        return

    # Scansione degli host attivi
    hosts = scan_network(ip_range)
    if not hosts:
        print("[INFO] Nessun host attivo trovato sulla rete.")
        return

    print("\n[+] Host attivi rilevati:")
    print("-------------------------------------------------")
    for host in hosts:
        print(f"IP: {host['ip']} \t MAC: {host['mac']}")
    print("-------------------------------------------------")

    # Scansione delle porte per ogni host attivo
    print("\n[+] Inizio scansione delle porte sugli host attivi...")
    for host in hosts:
        print(f"\n[ Scansione su {host['ip']} ]")
        port_queue = queue.Queue()
        open_ports = []

        for port in range(port_range[0], port_range[1] + 1):
            port_queue.put(port)

        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=scan_ports, args=(host['ip'], port_queue, open_ports))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        if open_ports:
            print(f"[+] Porte aperte su {host['ip']}:")
            for port, service in open_ports:
                print(f"  Porta {port} - Servizio: {service}")
        else:
            print(f"[-] Nessuna porta aperta rilevata su {host['ip']}.")

if __name__ == "__main__":
    run()
