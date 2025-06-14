#!/usr/bin/env python3
import socket
from cryptography.hazmat.primitives.asymmetric import dh
from common import derive_key, send_encrypted, recv_decrypted
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configurazione dell'indirizzo e porta del server
HOST = '127.0.0.1'
# Utilizziamo una porta non privilegiata (>1024) che non richiede permessi elevati
PORT = 65432

def main():
    # 1) Generazione parametri Diffie-Hellman
    # DH permette a due parti di stabilire una chiave segreta condivisa
    # attraverso un canale insicuro, senza mai trasmettere la chiave stessa
    # Usiamo generator=2 (valore standard sicuro) e key_size=2048 (raccomandato da NIST)
    # La dimensione di 2048 bit offre un livello di sicurezza adeguato
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    
    # Generiamo la chiave privata del server (b)
    server_priv = parameters.generate_private_key()
    
    # Calcoliamo la chiave pubblica del server (g^b mod p)
    server_pub = server_priv.public_key().public_numbers().y
    
    # Estraiamo p (modulo primo) e g (generatore) dai parametri DH
    # Questi valori saranno condivisi con il client
    params = parameters.parameter_numbers()
    p, g = params.p, params.g

    # 2) Configurazione della connessione TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Associa il socket all'indirizzo e porta specificati
        s.bind((HOST, PORT))
        
        # Mette il server in ascolto, accettando una connessione alla volta
        # (1 come backlog per una comunicazione one-to-one)
        s.listen(1)
        
        # Imposta un timeout di 5 minuti per l'operazione accept()
        # evita che il server rimanga bloccato indefinitamente 
        s.settimeout(300)
        
        print(f"[+] Server in ascolto su {HOST}:{PORT}")
        
        # Attende e accetta una connessione dal client
        conn, addr = s.accept()
        
        with conn:
            # Imposta timeout sulla connessione per le operazioni di ricezione
            conn.settimeout(300)
            print(f"[+] Connessione da {addr}")

            # 3) Scambio Diffie-Hellman: inviamo p, g e la chiave pubblica del server
            # il client ha bisogno di questi valori per generare la sua chiave
            # e calcolare lo stesso segreto condiviso
            conn.sendall(f"{p},{g},{server_pub}".encode())

            # 4) Ricezione della chiave pubblica del client (g^a mod p)
            # Utilizziamo un buffer sufficientemente grande per ospitare numeri DH di 2048 bit
            data = conn.recv(8192)
            
            # Convertiamo la stringa ricevuta in un intero (la chiave pubblica del client)
            client_pub_int = int(data.decode())

            # 5) Calcolo del segreto condiviso
            # DH permette che entrambe le parti possono 
            # calcolare lo stesso segreto g^(ab) mod p senza mai trasmettere tale valore
            
            # Ricostruiamo l'oggetto chiave pubblica del client
            client_pub_nums = dh.DHPublicNumbers(client_pub_int, params)
            client_pub_key = client_pub_nums.public_key()
            
            # Calcoliamo il segreto condiviso: (g^a)^b mod p = g^(ab) mod p
            shared_key = server_priv.exchange(client_pub_key)
            print("[*] Shared key derivata")

            # 6) Derivazione della chiave AES e setup del cifrario
            # la shared_key DH non è utilizzabile direttamente,
            # quindi deriviamo una chiave adatta per AES usando una KDF
            key = derive_key(shared_key)
        
            # Inizializziamo AES-GCM con la chiave derivata
            # AES-GCM è un cifrario AEAD che fornisce sia
            # confidenzialità che autenticità dei messaggi
            aesgcm = AESGCM(key)

            # 7) Loop di chat cifrata (echo server)
            # Il server riceve messaggi cifrati, li decifra, li mostra e li rimanda al client
            try:
                while True:
                    # Ricezione e decifratura del messaggio dal client
                    # La funzione recv_decrypted gestisce anche il nonce e la verifica dell'integrità
                    msg = recv_decrypted(conn, aesgcm)
                    
                    # Mostra il messaggio ricevuto (decodificato in stringa)
                    print(f"[Client] {msg.decode()!r}")
                    
                    # Cifra e invia lo stesso messaggio al client (echo)
                    # La funzione send_encrypted gestisce la generazione del nonce e la cifratura
                    send_encrypted(conn, aesgcm, msg)
                    
            except (EOFError, socket.timeout):
                # Gestione della terminazione della connessione o timeout
                print("[!] Connessione terminata")
            finally:
                # Garantisce la chiusura della connessione in ogni caso
                conn.close()

# Punto di ingresso dello script
if __name__ == '__main__':
    main()
