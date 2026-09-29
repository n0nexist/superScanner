import ipaddress
import subprocess
from threading import Thread
from time import sleep
from colorama import Fore, Style
import socket
import re
from os import system
from mac_vendor_lookup import MacLookup

_lookup = MacLookup()

system("clear")

print(f"""{Fore.CYAN}
 ╔═════════════════════════╗
 ║ S U P E R S C A N N E R ║
 ╚═════════════════════════╝{Fore.RESET}""")

def iterate_subnet(cidr):
    """
    ENUMERA TUTTI GLI HOST POSSIBILI IN UNA SUBNET
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"{Fore.RED}[!]{Fore.RESET} CIDR non valido: {e}")
        return None

    print(f"{Fore.GREEN}[+]{Fore.RESET} Host da controllare: {Fore.LIGHTMAGENTA_EX}{net.num_addresses - 2}{Fore.RESET}")  # esclude network e broadcast
    return net.hosts()

aliveips = []

def getMacAddress(IP):
    """
    OTTIENE L'INDIRIZZO MAC DI UN IP
    !!!!!!!!! (FUNZIONANTE SOLO DOPO CHE L'IP E' STATO PINGATO)
    """
    with open("/proc/net/arp") as f:
        next(f)
        for line in f:
            p = line.split()
            if p[0] == IP:
                return p[3].lower()
    return None

def getMacVendor(mac):
    """
    OTTIENE IL MAC VENDOR DI UN MAC
    """
    mac = re.sub(r'[^0-9a-fA-F]', '', mac)
    if len(mac) != 12:
        return None
    # bit LAA (secondo bit del primo byte) → nessun vendor registrato
    if int(mac[0:2], 16) & 0x02:
        return None
    try:
        return _lookup.lookup(mac)
    except Exception:
        return None

def get_my_ip():
    """
    TROVA IL MIO IP
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Non serve che sia raggiungibile, serve solo per far scegliere un'interfaccia
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def getTTL(ip):
    """
    OTTIENI IL TTL DI UN PING VERSO UN HOST
    """
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "2", str(ip)],
            capture_output=True, text=True, timeout=3
        ).stdout
        m = re.search(r"ttl=(\d+)", out, re.I)
        return int(m.group(1)) if m else None
    except Exception:
        return None

def guessOS(ttl):
    """
    CERCA DI OTTENERE INFO SUL SISTEMA OPERATIVO
    """
    if ttl is None: return None
    if ttl <= 64:  return "Linux/Unix/macOS"
    if ttl <= 128: return "Windows"
    return "Router/Network device"

def isMyIP(ip):
    """
    IMPEDISCE AUTOPING
    """
    return str(ip) == get_my_ip()

def pingIP(ip):
    """
    PINGA UN IP E VEDE SE E ONLINE
    """
    if isMyIP(ip):
        return
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", str(ip)],  # <-- str(ip) è fondamentale
            capture_output=True,
            text=True,
            timeout=3
        )
        if result.returncode == 0:
            aliveips.append(str(ip))
            print(f"  {Fore.GREEN}[+] {Fore.LIGHTCYAN_EX}{Style.BRIGHT}{ip}{Fore.RESET} online")
    except (subprocess.TimeoutExpired, Exception):
        pass

def grabBanner(ip, port):
    """
    CONTROLLA IL BANNER E LO STATO DI UNA PORTA
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((str(ip), int(port)))

        # Prova a ricevere il banner (come fa nmap)
        banner = sock.recv(1024)
        sock.close()

        print(f"    {Fore.LIGHTYELLOW_EX}→ {Fore.GREEN}{port}/tcp open{Fore.RESET}{" "*40}")

        if banner:
            banner = banner.decode(errors="ignore").strip()
            print(f"      {Fore.YELLOW}{banner}{Fore.RESET}")
            print()  # riga vuota per leggibilità

    except (socket.timeout, ConnectionRefusedError, OSError):
        # Porta chiusa / filtrata → non dire nulla
        return

def processPORTS(ip):
    """
    CONTROLLA LE 1000 PORTE COMUNI APERTE
    """
    threads = []

    with open("ports.txt", "r") as f:
        ports = [port.strip() for port in f if port.strip()]

    for port in ports:
        print(f"{Fore.LIGHTYELLOW_EX}[*]{Fore.RESET} Checking {Fore.LIGHTMAGENTA_EX}{ip}{Fore.RESET}:{Fore.LIGHTGREEN_EX}{port}{Fore.RESET}", end="\r")
        
        t = Thread(target=grabBanner, args=(ip, int(port)))
        t.start()
        threads.append(t)

    # Aspetta che TUTTI i thread finiscano
    for t in threads:
        t.join()

    print(" "*40 + "\n")  # va a capo dopo l'ultimo \r

def processIPS():
    """
    CONTROLLA SE UN IP E' VIVO
    """
    print(f"\n{Fore.LIGHTGREEN_EX}[+]{Fore.RESET} Numero di IP online: {Fore.MAGENTA}{Style.DIM}{len(aliveips)}{Fore.RESET}{Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}[*]{Fore.RESET} IP online trovati:")
    for aliveIP in aliveips:
        mac = getMacAddress(aliveIP)
        vendor = getMacVendor(mac)
        os = guessOS(getTTL(aliveIP))
        print(f"  {Fore.YELLOW}→ {Fore.LIGHTRED_EX}{aliveIP}{Fore.WHITE}{Style.DIM} | {Style.RESET_ALL}{Fore.LIGHTRED_EX}{mac} {Fore.WHITE}{Style.DIM}({Style.RESET_ALL}{Fore.LIGHTBLUE_EX}{vendor}{Fore.WHITE}{Style.DIM}){Style.RESET_ALL}{Fore.RESET}\n  {Fore.YELLOW}→ {Fore.LIGHTGREEN_EX}{os}{Fore.RESET}")
        processPORTS(aliveIP)

def main():
    print(f"\n{Fore.LIGHTGREEN_EX}[+]{Fore.RESET} Il mio IP: {Fore.MAGENTA}{Style.DIM}{get_my_ip()}{Fore.RESET}{Style.RESET_ALL}")
    
    defaultSubnet = f"{get_my_ip()}/24"
    subnetToScan = input(f"Subnet [{defaultSubnet}]: ")

    if subnetToScan.replace(' ', '') == "":
        subnetToScan = defaultSubnet
    
    subnet = iterate_subnet(subnetToScan)
    if subnet is None:
        return

    print(f"{Fore.MAGENTA}[*]{Fore.RESET} Cerco gli IP online nella rete...")
    for ip in subnet:
        Thread(target=pingIP, args=(ip,)).start()

    sleep(3)

    processIPS()

if __name__ == "__main__":
    main()
