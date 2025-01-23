#!/usr/bin/env python

"""
Firt Hack Tools - Educational Purposes Only
Author: [Dal Molin Nicola]
Disclaimer: This script is intended for educational and authorized penetration testing purposes only.
Unauthorized use of this script on networks you do not own or have permission to test is illegal.
"""

import importlib
import sys

# Funzione per stampare il menu
def print_menu():
    print(r""" 

'####:'########::'######::'########::'#######:::'#######::'##::::::::'######:::
. ##::... ##..::'##... ##:... ##..::'##.... ##:'##.... ##: ##:::::::'##... ##::
: ##::::: ##:::: ##:::..::::: ##:::: ##:::: ##: ##:::: ##: ##::::::: ##:::..:::
: ##::::: ##::::. ######::::: ##:::: ##:::: ##: ##:::: ##: ##:::::::. ######:::
: ##::::: ##:::::..... ##:::: ##:::: ##:::: ##: ##:::: ##: ##::::::::..... ##::
: ##::::: ##::::'##::: ##:::: ##:::: ##:::: ##: ##:::: ##: ##:::::::'##::: ##::
'####:::: ##::::. ######::::: ##::::. #######::. #######:: ########:. ######:::
....:::::..::::::......::::::..::::::.......::::.......:::........:::......::::


                                     @@@@@@@@@                         
                                    @@@@@@@@@@@                        
                                  /@@@@@@@@@@@@@,                      
                      @@@@@@.#@@@@@@@@@@@@@@@@@@@@@@@*,@@@@@@          
                    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        
                  .@@@@@@@@@@@@@@@@%           &@@@@@@@@@@@@@@@@       
                    @@@@@@@@@@@@                   @@@@@@@@@@@@        
                    @@@@@@@@@                       @@@@@@@@&         
                    ,@@@@@@@                          .@@@@@@@         
                   @@@@@@@&                           @@@@@@@@        
                  (@@@@@@@@                             @@@@@@@@,      
                @@@@@@@@@@@@                            *@@@@@@@@@@@@   
                ,@@@@@@@@@@@@                           @@@@@@@@@@@@    
                @@@@@@@@@@@@@                         @@@@@@@@@@@@@    
                @@@@@@@@@@@@@@                     @@@@@@@@@@@@@@     
                       /@@@@@@@@@@               @@@@@@@@@@            
                        %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,             
                          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
                         %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
                          @@@@@@@@@@         @@@@@@@@@@                
                               @@@             @@@      

***************************************************************
*                         TOOLS MENU                          *
***************************************************************
*  1. ARPSpoofV2                                              *
*  2. Change MAC Address                                      *
*  3. Ping                                                    *
*  4. Port Scanner & Banner                                   *
*  5. Exit                                                    *
***************************************************************
""")

# Funzione per caricare ed eseguire gli script
def load_script(script_name):
    try:
        module = importlib.import_module(script_name)  # Importa lo script
        module.run()  # Esegue la funzione 'run' di ogni script
    except ModuleNotFoundError:
        print(f"[!] Script {script_name} non trovato!")
    except AttributeError:
        print(f"[!] Lo script {script_name} non ha una funzione 'run' valida.")

def main():
    while True:
        print_menu()  # Mostra il menu
        choice = input("Seleziona un'opzione: ")
        
        if choice == "1":
            load_script("ARPSpoofV2")
        elif choice == "2":
            load_script("changeMAC")
        elif choice == "3":
            load_script("ping")
        elif choice == "4":
            load_script("PortScannerBanner")
        elif choice == "5":
            print("Uscita...")
            sys.exit(0)
        else:
            print("[!] Scelta non valida. Riprova.")

if __name__ == "__main__":
    main()
