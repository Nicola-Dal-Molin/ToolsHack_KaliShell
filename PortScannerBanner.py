import threading
import queue
from scapy.all import ARP, Ether, srp
import socket
import subprocess
import re

# Funzione per ottenere la rete dalla scheda attiva
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
        print("[Errore] Nessuna rete attiva rilevata.")
    except Exception as e:
        print(f"[Errore] Impossibile ottenere la rete: {e}")
    return None

# Funzione per trovare gli host attivi nella rete
def scan_network(ip_range):
    print(f"Scanning network: {ip_range}")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered = srp(packet, timeout=2, verbose=0)[0]
    active_hosts = []

    for sent, received in answered:
        active_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

    return active_hosts

# Funzione per ottenere il banner del servizio da una porta
def get_service_banner(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((host, port))
            # Se la porta è HTTP (80 o 443), invia una richiesta HTTP minima
            if port == 80 or port == 443:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                # Cerca nell'header 'Server' per ottenere il nome del servizio
                if 'Server' in banner:
                    server_line = [line for line in banner.split('\r\n') if line.startswith('Server')]
                    if server_line:
                        return server_line[0].split(":")[1].strip()
                return "HTTP Server (unknown)"
            else:
                return "Service Banner not detected"
    except Exception:
        return None

# Funzione per controllare le porte aperte su un host e associare i servizi
def scan_ports(host, port_queue, open_ports):
    while not port_queue.empty():
        port = port_queue.get()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                if result == 0:  # Porta aperta
                    # Proviamo a ottenere il banner del servizio
                    service_banner = get_service_banner(host, port)
                    if service_banner:
                        open_ports.append((port, service_banner))
        except Exception as e:
            pass
        finally:
            port_queue.task_done()

# Funzione principale per la scansione
def main(port_range, num_threads):
    # Step 1: Ottenere la rete attiva
    ip_range = get_network()
    if not ip_range:
        print("Nessuna rete rilevata. Uscita.")
        return

    # Step 2: Scansione degli host attivi nella rete
    hosts = scan_network(ip_range)
    if not hosts:
        print("No active hosts found in the network.")
        return

    print("\nActive hosts:")
    for host in hosts:
        print(f"IP: {host['ip']}, MAC: {host['mac']}")

    # Step 3: Scansione delle porte sugli host attivi
    print("\nScanning ports on active hosts...")
    for host in hosts:
        print(f"\nScanning {host['ip']}...")
        port_queue = queue.Queue()
        open_ports = []

        # Riempire la coda con le porte da controllare
        for port in range(port_range[0], port_range[1] + 1):
            port_queue.put(port)

        # Creare i thread per la scansione
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=scan_ports, args=(host['ip'], port_queue, open_ports))
            thread.start()
            threads.append(thread)

        # Aspettare che tutti i thread finiscano
        for thread in threads:
            thread.join()

        # Risultati
        if open_ports:
            print(f"Open ports on {host['ip']}:")
            for port, service in open_ports:
                print(f"  Port {port} - Service: {service}")
        else:
            print(f"No open ports found on {host['ip']}.")

if __name__ == "__main__":
    import argparse

    # Parser degli argomenti CLI
    parser = argparse.ArgumentParser(description="Scansione di rete e porte.")
    parser.add_argument("port_range", help="Intervallo di porte (es. 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Numero di thread (predefinito: 10)")

    args = parser.parse_args()

    # Parsing intervallo porte
    try:
        port_start, port_end = map(int, args.port_range.split("-"))
        if port_start < 1 or port_end > 65535 or port_start > port_end:
            raise ValueError
    except ValueError:
        print("Errore: intervallo porte non valido. Usa il formato '1-65535'.")
        exit(1)

    main((port_start, port_end), args.threads)
