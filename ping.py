from scapy.all import ICMP, IP, sr1
import optparse
import time
from concurrent.futures import ThreadPoolExecutor
import re

def send_ping(destination_ip, timeout=2):
    """
    Invia un pacchetto ICMP Echo Request all'IP di destinazione.

    Args:
        destination_ip (str): L'indirizzo IP di destinazione.
        timeout (int): Tempo massimo di attesa per una risposta (in secondi).

    Returns:
        dict: Dizionario con i dettagli del ping oppure None se non c'è risposta.
    """
    print(f"[INFO] Ping in corso verso {destination_ip}...")

    packet = IP(dst=destination_ip) / ICMP()

    try:
        start_time = time.time()
        response = sr1(packet, timeout=timeout, verbose=0)
        end_time = time.time()

        if response:
            rtt = (end_time - start_time) * 1000  # RTT in millisecondi
            return {
                "ip": response.src,
                "ttl": response.ttl,
                "rtt": f"{rtt:.2f} ms"
            }
        else:
            return None
    except Exception as e:
        print(f"[ERRORE] Problema durante il ping: {e}")
        return None

def validate_ip(ip):
    """Verifica se un indirizzo IP fornito è valido."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip) and all(0 <= int(octet) <= 255 for octet in ip.split('.'))

def get_cli_arguments():
    """Analizza gli argomenti della riga di comando."""
    parser = optparse.OptionParser()
    parser.add_option("-n", "--number", dest="number", type="int", 
                      help="Numero di ping da inviare (es. 5).")
    parser.add_option("-i", "--ip", dest="target_ip", type="string", 
                      help="Indirizzo IP di destinazione (es. 8.8.8.8).")
    parser.add_option("-t", "--timeout", dest="timeout", type="int", default=2,
                      help="Timeout per ciascun ping (default: 2s).")
    parser.add_option("-w", "--workers", dest="workers", type="int", default=5,
                      help="Numero massimo di thread (default: 5).")

    (options, arguments) = parser.parse_args()

    if not options.number or options.number <= 0:
        parser.error("[KO] Specificare un numero valido di ping (>0)!")
    if not options.target_ip or not validate_ip(options.target_ip):
        parser.error("[KO] Specificare un indirizzo IP valido!")
    if options.workers < 1 or options.workers > 50:
        parser.error("[KO] Specificare un numero di thread compreso tra 1 e 50!")
        
    return options

def run():
    options = get_cli_arguments()

    with ThreadPoolExecutor(max_workers=options.workers) as executor:
        futures = [executor.submit(send_ping, options.target_ip, options.timeout) for _ in range(options.number)]

        for idx, future in enumerate(futures, start=1):
            result = future.result()
            if result:
                print(f"[{idx}/{options.number}] Risposta da {result['ip']} - TTL={result['ttl']} - Tempo={result['rtt']}")
            else:
                print(f"[{idx}/{options.number}] Nessuna risposta ricevuta.")

if __name__ == "__main__":
    run()
