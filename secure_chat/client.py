#!/usr/bin/env python3
import socket
from cryptography.hazmat.primitives.asymmetric import dh
from common import derive_key, send_encrypted, recv_decrypted
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configurazione dell'indirizzo e porta del server a cui connettersi
HOST = '127.0.0.1'
# Utilizziamo la porta 65433, assicurandoci che corrisponda a quella su cui ascolta il server
PORT = 65433

def main():
    # 1) Configurazione della connessione TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Impostiamo un timeout di 5 minuti per evitare blocchi indefiniti
        s.settimeout(300)
        # Iniziamo la connessione al server
        s.connect((HOST, PORT))
        print(f"[+] Connesso a {HOST}:{PORT}")

        # 2) Ricezione parametri Diffie-Hellman dal server
        # Il server invia i parametri necessari (p, g) e la sua chiave pubblica
        data = s.recv(8192).decode()
        p_str, g_str, server_pub_str = data.split(',')
        # Convertiamo le stringhe ricevute nei rispettivi valori interi
        p, g = int(p_str), int(g_str)
        server_pub_int = int(server_pub_str)
        print("[<] Ricevuti p, g e g^b mod p dal server")

        # 3) Ricostruzione parametri e generazione chiavi
        # Ricostruiamo gli oggetti dei parametri DH usando i valori ricevuti
        params_nums = dh.DHParameterNumbers(p, g)
        parameters = params_nums.parameters()
        # Generiamo la chiave privata del client (a)
        client_priv = parameters.generate_private_key()
        # Calcoliamo la chiave pubblica del client (g^a mod p)
        client_pub  = client_priv.public_key().public_numbers().y

        # 4) Invio della chiave pubblica al server
        # Il server ha bisogno della nostra chiave pubblica per calcolare il segreto condiviso
        s.sendall(str(client_pub).encode())
        print("[>] Inviato g^a mod p al server")

        # 5) Calcolo del segreto condiviso
        # Ricostruiamo l'oggetto della chiave pubblica del server
        server_pub_nums = dh.DHPublicNumbers(server_pub_int, params_nums)
        server_pub_key  = server_pub_nums.public_key()
        # Calcoliamo il segreto condiviso: (g^b)^a mod p = g^(ab) mod p
        # DH permette ad entrambe le parti di calcolare lo stesso segreto
        # senza mai trasmetterlo in chiaro sul canale
        shared_key = client_priv.exchange(server_pub_key)
        print("[*] Shared key derivata")

        # 6) Derivazione chiave AES e setup del cifrario
        # La shared_key non è utilizzabile direttamente per la crittografia
        # Deriviamo una chiave adatta usando una KDF (Key Derivation Function)
        key = derive_key(shared_key)
        # Inizializziamo l'algoritmo AES-GCM che fornisce
        # sia confidenzialità che autenticità dei messaggi
        aesgcm = AESGCM(key)

        # 7) Loop di chat cifrata
        # Il client invia messaggi cifrati al server e riceve risposte
        try:
            while True:
                # Input dell'utente da inviare al server
                text = input(">> ").encode()
                # Usciamo dal loop se l'utente ha inserito una stringa vuota
                if not text:
                    break
                # Cifriamo e inviamo il messaggio al server
                # La funzione gestisce la generazione del nonce e la cifratura
                send_encrypted(s, aesgcm, text)
                # Riceviamo e decifriamo la risposta del server
                # recv_decrypted gestisce l'estrazione del nonce e la verifica dell'integrità
                resp = recv_decrypted(s, aesgcm)
                # Visualizziamo la risposta ricevuta
                print(f"[Server] {resp.decode()!r}")
        except (EOFError, socket.timeout):
            # Gestione della terminazione della connessione o timeout
            print("[!] Connessione terminata")
        finally:
            # Garantisce la chiusura della connessione in ogni caso
            s.close()

# Punto di ingresso dello script
if __name__ == '__main__':
    main()
