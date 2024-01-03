import socket
import logging
import time
import random
import string

logging.basicConfig(format=u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s] %(message)s', level=logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = 'localhost'
server_address = (adresa, port)

try:
    logging.info('Handshake cu %s', str(server_address))
    sock.connect(server_address)

    while True:
        lungime = 10  # Lungimea șirului aleatoriu
        caractere = string.ascii_lowercase  # Literele mici din alfabetul englez

        sir_aleatoriu = ''.join(random.choice(caractere) for _ in range(lungime))
        sock.send(sir_aleatoriu.encode('utf-8'))

        data = sock.recv(1024)
        if data:
            logging.info('Content primit de la server: "%s"', data)

        time.sleep(1)

finally:
    logging.info('closing socket')
    sock.close()