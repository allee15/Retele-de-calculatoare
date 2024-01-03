import socket
import logging
import string
import random

logging.basicConfig(format=u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s] %(message)s', level=logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = 'localhost'
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit pe %s și portul %d", adresa, port)
sock.listen(5)

while True:
    logging.info('Asteptam conexiune...')
    conexiune, address = sock.accept()
    logging.info("Handshake cu %s", address)

    while True:
        data = conexiune.recv(1024).decode('utf-8')
        logging.info('Content primit de la client: "%s"', data)

        lungime = 10  # Lungimea șirului aleatoriu
        caractere = string.ascii_lowercase  # Literele mici din alfabetul englez

        sir_aleatoriu = ''.join(random.choice(caractere) for _ in range(lungime))
        conexiune.send(sir_aleatoriu.encode('utf-8'))

    conexiune.close()

sock.close()