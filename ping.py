from scapy.all import ICMP, IP, sr1
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

def get_user_inputs():
    """Ottieni gli input dall'utente per l'indirizzo IP, il numero di ping, e altre opzioni."""
    print("[+] Strumento di Ping")
    
    target_ip = input("Inserisci l'indirizzo IP di destinazione (es. 8.8.8.8): ").strip()
    while not validate_ip(target_ip):
        print("[KO] Indirizzo IP non valido. Riprova.")
        target_ip = input("Inserisci l'indirizzo IP di destinazione (es. 8.8.8.8): ").strip()
    
    number = int(input("Inserisci il numero di ping da inviare (es. 5): ").strip())
    timeout = int(input("Inserisci il timeout per ogni ping (es. 2 secondi): ").strip())
    workers = int(input("Inserisci il numero di thread per il ping (1-50): ").strip())
    
    # Verifica i limiti dei thread
    if workers < 1 or workers > 50:
        print("[KO] Numero di thread non valido. Usiamo 5 come valore predefinito.")
        workers = 5
    
    return target_ip, number, timeout, workers

def run():
    # Ottieni gli input dall'utente
    target_ip, number, timeout, workers = get_user_inputs()

    # Esegui il ping in parallelo utilizzando i thread
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(send_ping, target_ip, timeout) for _ in range(number)]

        for idx, future in enumerate(futures, start=1):
            result = future.result()
            if result:
                print(f"[{idx}/{number}] Risposta da {result['ip']} - TTL={result['ttl']} - Tempo={result['rtt']}")
            else:
                print(f"[{idx}/{number}] Nessuna risposta ricevuta.")

if __name__ == "__main__":
    run()
