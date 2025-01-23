# ifconfig eth0  down
# ifconfig eth0 hw ether 00:99:88:77:66:55
# ifconfig eth0 up
# original MAC eth0 00:1c:42:d2:23:ac     
# subprocess.call("sudo ifconfig eth0 down", shell=True)
# subprocess.call("sudo ifconfig eth0 hw ether  22:33:44:55:66:88", shell=True)
# subprocess.call("sudo ifconfig eth0 up", shell=True)


import subprocess
import optparse
import re


def set_nic_mac(nic, mac):
    print(" [0K] Changing MAC for " + nic + " with " + mac)
    subprocess.call(["ifconfig", nic, "down"])
    subprocess.call(["ifconfig", nic, "hw", "ether", mac])
    subprocess.call(["ifconfig", nic, "up"])
    
def get_cli_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-n", "--nic", dest="nic", help="pass the Nic name")
    parser.add_option("-m", "--mac", dest="mac", help="New Mac to set")
    (options, arguments) = parser.parse_args()
    if not options.nic:
        parser.error("[KO] Please specify the NIC!")
    elif not options.mac:
        parser.error("[KO] Please specify the MAC!")
    return options

def get_nic_mac(nic):
    ifconfig_dump = subprocess.check_output(["ifconfig",nic])
    ifconfig_dump = ifconfig_dump.decode("utf-8")
    mac_dumped = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_dump))
    
    if mac_dumped:
        return mac_dumped.group(0)
    else:
        print("[KO] MAC not found!")


options = get_cli_arguments()
set_nic_mac(options.nic, options.mac)
mac_set = get_nic_mac(options.nic)

if mac_set == options.mac:
    print("[OK] MAC " + mac_set + " correctly changed")
else:
    print("[KO] MAC change failed!") 