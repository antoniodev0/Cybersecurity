#!/usr/bin/env python3
import socket, ssl

# Configurazione dell'indirizzo e porta del server
HOST = '127.0.0.1'
PORT = 65432

def main():
    # 1) Configurazione del contesto TLS in modalità server
    # TLS (Transport Layer Security) è il successore di SSL e fornisce
    # comunicazione sicura su rete attraverso crittografia
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Carichiamo il certificato e la chiave privata del server
    # Il certificato (.crt) contiene la chiave pubblica e l'identità del server
    # La chiave privata (.key) deve rimanere segreta e viene usata per l'autenticazione
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')

    # 2) Creazione del socket TCP non cifrato
    # Questo è un normale socket TCP che verrà successivamente "avvolto" con TLS
    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    bindsock.bind((HOST, PORT))
    bindsock.listen(5)  # Accetta fino a 5 connessioni in coda
    print(f"[+] TLS server in ascolto su {HOST}:{PORT}")

    # Loop principale del server
    while True:
        # Accetta una nuova connessione TCP
        newsock, addr = bindsock.accept()
        ssock = None
        
        # 3) Esecuzione dell'handshake TLS: wrap del socket
        try:
            # Avvolge il socket TCP con il contesto TLS
            # server_side=True indica che questo è il lato server dell'handshake
            ssock = context.wrap_socket(newsock, server_side=True)
            print(f"[+] TLS handshake completato con {addr}")
            
            # 4) Loop di echo cifrato
            # I dati sono automaticamente cifrati/decifrati dal layer TLS
            while True:
                data = ssock.recv(4096)
                if not data:
                    # Connessione chiusa dal client
                    break
                # Invia indietro gli stessi dati (echo)
                ssock.sendall(data)
        except ssl.SSLError as e:
            # Gestisce errori durante l'handshake o la comunicazione TLS
            print(f"[!] Errore TLS: {e}")
        finally:
            # Garantisce che il socket venga chiuso anche in caso di errori
            if ssock:
                ssock.close()

# Punto di ingresso dello script
if __name__ == '__main__':
    main()

"""openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt \
  -days 365 \
  -subj "/C=IT/ST=MI/L=Milan/O=Uni/CN=localhost"
""" #(Comando da terminale per generare un certificato autofirmato e una chiave RSA)
# Il comando genera:
# 1. Un certificato X.509 autofirmato valido per 365 giorni
# 2. Una chiave RSA da 2048 bit non protetta da password (-nodes)
# 3. Informazioni di base nel certificato (paese, stato, città, organizzazione, nome comune)