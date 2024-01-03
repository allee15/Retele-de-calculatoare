import json
import socket
import struct
import sys
import requests


class Request:
    def __init__(self, current_addr):
        self.current_addr = current_addr  # -> adresa IP curentă

    def read_info_about_addr(self):
        ip_info = requests.get(f"http://ip-api.com/json/{self.current_addr}?fields=city,regionName,country").json()
        # se folosește biblioteca "requests" pentru a efectua o cerere GET către API-ul "http://ip-api.com/json/"
        # pentru a obține informații despre adresa IP specificată prin "current_addr". Rezultatul răspunsului API-ului
        # este convertit în format JSON.

        print(f"{ip_info['city']}, {ip_info['regionName']}, {ip_info['country']}")
        # Se afișează informațiile despre oraș, regiune și țară obținute din răspunsul API-ului, utilizând cheile
        # 'city', 'regionName' și 'country' din dicționarul "ip_info".

        data = {
            'current_addr': self.current_addr,
            'city': ip_info['city'],
            'country': ip_info['country']
        }
        # Se creează un dicționar numit "data" care conține următoarele chei și valori:
        #
        # 'current_addr': valoarea parametrului "current_addr" primit în constructor.
        # 'city': valoarea orașului obținută din răspunsul API-ului.
        # 'country': valoarea țării obținute din răspunsul API-ului.

        with open("locations.json", 'w') as file:
            json.dump(data, file)  # salvam dicționarul "data" în format JSON în fișier.


class TraceRouteSocket:
    def __init__(self, target_port, max_hops, ttl, is_target):
        self.target_port = target_port  # portul tinta
        self.max_hops = max_hops  # nr maxim de sarituri
        self.ttl = ttl  # valoarea câmpului TTL pentru pachetele IP
        self.is_target = is_target  # o variabilă booleană care indică dacă adresa IP țintă a fost atinsă

    def check_hostname_address(self, target_addr, current_addr, current_name, current_host):
        # establish UDP and ICMP sockets for sending and receiving respectively
        udp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # udp_send_socket -> pentru trimiterea de pachete UDP
        icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # icmp_recv_socket -> pentru primirea pachetelor icmp

        udp_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
        # Pentru socketul "udp_send_socket", se setează opțiunea "IP_TTL" cu valoarea "ttl" specificată în constructor,
        # pentru a seta câmpul TTL în pachetele IP trimise.
        icmp_recv_socket.settimeout(0.5)
        # Se setează un timeout de 0.5 secunde pentru socketul "icmp_recv_socket" pentru a limita timpul de așteptare
        # a pachetelor ICMP primite
        icmp_recv_socket.bind(('', self.target_port))
        #  "icmp_recv_socket" este legat la o interfață locală și un port specificat de "target_port".
        udp_send_socket.sendto(b'', (target_addr[2][0], self.target_port))
        # Se trimite un pachet UDP goală către adresa IP țintă utilizând socketul "udp_send_socket".

        try:
            data, addr = icmp_recv_socket.recvfrom(512)  # recv ICMP packet
            current_addr = addr[0]  # pull current IP address
            # Se încearcă primirea unui pachet ICMP de la socketul "icmp_recv_socket" cu o dimensiune maximă de 512
            # octeți. Adresa IP curentă este extrasă din pachetul ICMP primit și atribuită variabilei "current_addr"

            # Cerinta 2
            req = Request(current_addr)
            req.read_info_about_addr()
            # Se crează un obiect de tip "Request" cu adresa IP curentă și se apelează metoda "read_info_about_addr"
            # pentru a obține informații despre adresa IP curentă.

            icmp_header = data[20:28]  # pull ICMP header from packet

            # check ICMP type and code fields for Dest. Port Unreachable
            icmp_type = struct.unpack("bbHHh", icmp_header)[0]
            icmp_code = struct.unpack("bbHHh", icmp_header)[1]
            # Se extrage antetul ICMP din pachetul recepționat pentru a verifica câmpurile de tip și cod. Dacă câmpurile
            # sunt egale cu (3, 3) (adică Dest. Port Unreachable), înseamnă că s-a ajuns la gazda țintă.

            if (icmp_type, icmp_code) == (3, 3):  # arrived at target host
                is_target = True
                # În cazul în care s-a ajuns la gazda țintă, variabila "is_target" este setată la True

            try:
                # Se încearcă rezolvarea adresei IP curente într-un nume de gazdă utilizând funcția
                # "socket.gethostbyaddr". În cazul în care nu se găsește un nume de gazdă, se atribuie adresa IP curentă
                # variabilei "current_name". Dacă apare o eroare de socket, se afișează un mesaj de eroare și se încheie
                # programul.
                current_name = socket.gethostbyaddr(current_addr)[0]
            except socket.error as e:
                if isinstance(e, socket.herror):  # no host name found
                    current_name = current_addr  # set host name to IP address
                else:
                    print(" * * * Error: %d, %s") % (e.errno, e.strerror)
                    sys.exit()
            current_host = "%s : %s" % (current_addr, current_name)
            # Variabila "current_host" este formată prin combinarea adresei IP curente și numele gazdei curente într-un
            # șir de caractere
        except IOError as e:
            if isinstance(e, socket.timeout):  # no ICMP message received
                current_host = "* * * Request timed out"
            elif isinstance(e, socket.error):  # non timeout error raised
                print(" * * * Error: %d, %s") % (e.errno, e.strerror)
                sys.exit()
            # În cazul în care apare o eroare de tip IOError, se verifică dacă aceasta este o eroare de timeout
            # (socket.timeout), caz în care se atribuie șirul de caractere "* * * Request timed out" variabilei
            # "current_host". Dacă apare o eroare de tip socket.error, se afișează un mesaj de eroare și se încheie
            # programul.
        finally:
            # inchidem socket-urile si returnam valoarea din current_host
            udp_send_socket.close()
            icmp_recv_socket.close()
            return current_host


# Metoda "traceroute" este un ciclu continuu care efectuează urmărirea traseului către o adresă IP țintă, utilizând
# obiectul "TraceRouteSocket" și afișând informațiile relevante pe măsură ce avansează. Ciclul se oprește atunci când
# adresa IP țintă este atinsă sau valoarea TTL depășește numărul maxim de sărituri permis.
def traceroute(target_ip):
    # resolve host name to ip
    try:
        target_addr = socket.gethostbyaddr(target_ip)
        #  se folosește funcția "socket.gethostbyaddr" pentru a obține numele gazdei corespunzător unei adrese IP
        #  specifice. Funcția "gethostbyaddr" este utilizată pentru a realiza o căutare inversă a unei adrese IP în
        #  sistemul DNS și pentru a obține numele gazdei asociate acelei adrese IP.
        # adresa IP țintă este transmisă ca argument către funcția "gethostbyaddr". Dacă adresa IP poate fi rezolvată
        # într-un nume de gazdă valid în sistemul DNS, atunci funcția va returna acest nume de gazdă. Acest lucru este
        # util pentru a obține o denumire mai ușor de înțeles sau mai descriptivă pentru adresa IP țintă și pentru a
        # afișa această denumire în rezultatele urmăririi traseului. Dacă adresa IP nu poate fi rezolvată într-un nume
        # de gazdă valid, funcția poate genera o excepție de tip "socket.error", indicând că adresa IP sau numele gazdei
        # introduse sunt nevalide sau nu pot fi rezolvate.
    except socket.error as e:  # invalid IP or host entered
        print("[ERROR-IP]: The entered IP/host is invalid - %d, %s") % (e.errno, e.strerror)
        sys.exit()

    tr_socket = TraceRouteSocket(36789, 30, 1, False)
    # Se creează un obiect de tip "TraceRouteSocket" cu parametrii specificați: "target_port" = 36789, "max_hops" = 30,
    # "ttl" = 1 și "is_target" = False. Acest obiect va fi utilizat pentru a efectua urmărirea traseului.

    while True:
        #  se inițializează variabilele pentru adresa IP curentă, numele gazdei curente și gazda curentă.
        current_addr = None
        current_name = None
        current_host = None

        result_host = tr_socket.check_hostname_address(target_addr, current_addr, current_name, current_host)
        # Se apelează metoda "check_hostname_address" a obiectului "tr_socket" pentru a verifica adresa IP și numele
        # gazdei curente. Rezultatul este salvat în variabila "result_host".

        print("%d\t%s" % (tr_socket.ttl, result_host))  # Se afișează valoarea TTL și gazda curentă utilizând

        # Dacă adresa IP țintă a fost atinsă sau valoarea TTL a depășit numărul maxim de sărituri permis, se întrerupe
        # while-ul și se iese din metoda "traceroute"
        if tr_socket.is_target or (tr_socket.ttl > tr_socket.max_hops):
            break

        tr_socket.ttl += 1  # În caz contrar, se incrementează valoarea TTL cu 1 pentru a urmări următorul router hop.


traceroute("193.226.51.11")
