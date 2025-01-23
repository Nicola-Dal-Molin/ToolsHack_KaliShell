from scapy.all import ICMP, IP, sr1
import optparse
import time
import threading
from concurrent.futures import ThreadPoolExecutor

def send_ping(destination_ip, timeout=2):
    """
    Invia un ping ICMP a un indirizzo IP specificato.

    Args:
        destination_ip (str): L'indirizzo IP di destinazione.
        timeout (int, optional): Tempo massimo di attesa per una risposta (in secondi). 

    Returns:
        Scapy.layers.l2.Ether: Il pacchetto di risposta ICMP ricevuto, 
                               oppure None se nessuna risposta è stata ricevuta.
    """

    print(f"Invio di un ping a {destination_ip}...")

    # Crea il pacchetto ICMP Echo Request
    packet = IP(dst=destination_ip) / ICMP()

    try:
        # Invia il pacchetto e attendi una risposta
        response = sr1(packet, timeout=timeout, verbose=0)

        if response:
            print(f"Risposta ricevuta da {response.src}: TTL={response.ttl} Tempo={(response.time - packet.sent_time):.6f}s")
            return response
        else:
            print("Nessuna risposta ricevuta.")
            return None
    except Exception as e:
        print(f"Errore durante l'invio del pacchetto: {e}")
        return None

def get_cli_arguments():
    """
    Analizza gli argomenti della riga di comando.

    Returns:
        optparse.Values: Un oggetto contenente le opzioni specificate dall'utente.
    """
    parser = optparse.OptionParser()
    parser.add_option("-n", "--number", dest="number", type="int", 
                      help="Specifica il numero di ping da inviare.")
    (options, arguments) = parser.parse_args()
    if not options.number:
        parser.error("[KO] Si prega di specificare il numero di ping!")
    return options

if __name__ == "__main__":
    options = get_cli_arguments()
    target_ip = "8.8.8.8"

    # Crea una pool di thread con un numero massimo di thread (ad esempio, 5)
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Invia i ping in modo concorrente
        futures = [executor.submit(send_ping, target_ip) for _ in range(options.number)]

        # Attendi il completamento di tutti i thread
        for future in futures:
            response = future.result()
            if response:
                print("Dettagli della risposta:")
                print(response.summary())
                time.sleep(2)