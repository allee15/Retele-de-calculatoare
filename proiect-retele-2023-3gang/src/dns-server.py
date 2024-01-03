# https://gist.github.com/pklaus/b5a7876d4d2cf7271873
import argparse
import datetime
import sys
import threading
import traceback
import socketserver

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

# List of domains to be blocked
BLOCKED_DOMAINS = ['ad.example.com', 'ads.example.com', 'banner.example.com']


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


# Function to create the DNS server's response configuration
def createConfig(qn):
    D = DomainName(qn)
    IP = '127.0.0.1'  # The IP address to be assigned to the requested domain
    TTL = 60 * 5  # Time to live for the DNS response

    # Create the Start of Authority (SOA) record
    soa_record = SOA(
        mname=D.ns1,  # primary name server
        rname=D.gang3,  # email of the domain administrator
        times=(
            201307231,  # serial number
            60 * 60 * 1,  # refresh
            60 * 60 * 3,  # retry
            60 * 60 * 24,  # expire
            60 * 60 * 1,  # minimum
        )
    )

    ns_records = [NS(D.ns1), NS(D.ns2)]  # List of name server records

    # Dictionary to hold the DNS response records
    records = {
        D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
        D.ns1: [A(IP)],
        D.ns2: [A(IP)],
        D.mail: [A(IP)],
        D.gang3: [CNAME(D)],
    }

    return (D, IP, TTL, soa_record, ns_records, records)


# Function to handle DNS requests and generate a DNS response
def dns_response(data):
    request = DNSRecord.parse(data)  # Parse the DNS request

    # Ne cream raspunsul oferit de DNS server si configuram header-ul raspunsului
    # id = identificatorul cererii initiale care o sa fie acelasi ca la request
    # qr = specifica daca acesta este un raspuns sau nu (1 - true)
    # aa = specifica daca acest domeniu este autorativ
    # ra = specifica daca serverul suporta recurenta
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)  # Create the DNS response header

    qname = request.q.qname  # Extract the queried domain name
    qn = str(qname)
    qtype = request.q.qtype  # Extract the query type
    qt = QTYPE[qtype]

    # Create the DNS response configuration
    (D, IP, TTL, soa_record, ns_records, records) = createConfig(qn)

    if qn in BLOCKED_DOMAINS:
        # Return a negative response for blocked domains
        reply.header.rcode = RCODE.NXDOMAIN
        reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A('0.0.0.0')))
        print("---- Reply:\n", reply)
        return reply.pack()
    else:
        try:
            ip_address = socket.gethostbyname(qn)
            reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(ip_address)))
        except socket.gaierror:
            # Return a negative response for blocked domains
            reply.header.rcode = RCODE.NXDOMAIN
            reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A('0.0.0.0')))
            print("---- Reply:\n", reply)
            return reply.pack()

    # Add the name server records to the response
    for rdata in ns_records:
        # Add additional records
        reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

    # Add the Start of Authority (SOA) record to the response
    reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    print("---- Reply:\n", reply)

    # Prin apelarea funcției reply.pack(), obiectul reply este transformat într-o reprezentare binară compatibilă cu
    # protocolul DNS. Acest șir de octeți conține informațiile necesare pentru a transmite răspunsul DNS către
    # client, inclusiv header-ul și recordurile DNS corespunzătoare.
    return reply.pack()

# Clasa BaseRequestHandler este o clasă de bază definită în modulul socketserver și este
# utilizată pentru a gestiona cererile primite de la clienți în cadrul unui server.
class BaseRequestHandler(socketserver.BaseRequestHandler):
    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                              self.client_address[1]))
        try:
            data = self.get_data()
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


# Clasa UDPRequestHandler este o subclasă a clasei BaseRequestHandler și implementează metodele abstracte get_data, send_data și handle.
# Metoda get_data extrage datele primite în cerere, curățându-le de spații suplimentare.
# Metoda send_data trimite datele de răspuns către client utilizând adresa clientului și un obiect socket.
class UDPRequestHandler(BaseRequestHandler):
    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--udp', default=True, action='store_true', help='Listen to UDP datagrams.')

    args = parser.parse_args()
    if not args.udp: parser.error("UDP flag has been added to your command by default.")

    print("Starting nameserver...")

    # Clasa ThreadingUDPServer este o clasă din modulul socketserver care implementează un server UDP bazat pe fire de execuție (threaded).
    # Prin intermediul acestei clase, serverul DNS poate accepta conexiuni și trata cereri DNS primite prin pachete UDP.
    # Parametrul ('', args.port) specifică adresa IP și portul pe care serverul DNS va asculta. '' reprezintă adresa IP a serverului curent,
    # iar args.port este portul specificat de utilizator.
    # Parametrul UDPRequestHandler reprezintă clasa care gestionează cererile primite de la clienți.
    # Aceasta este utilizată pentru a procesa cererile DNS și a genera răspunsurile corespunzătoare.
    server = socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler)
    thread = threading.Thread(target=server.serve_forever)  # Start a new thread for each request
    thread.daemon = True  # Exit the server thread when the main thread terminates
    thread.start()
    print("%s server loop running in thread: %s" % (server.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown() # Shutdown the DNS server instance


if __name__ == '__main__':
    main()