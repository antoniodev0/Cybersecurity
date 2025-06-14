#!/usr/bin/env python3
import socket, ssl

# Configurazione dell'indirizzo e porta del server TLS
HOST = '127.0.0.1'
PORT = 65433

def main():
    # 1) Configurazione del contesto TLS in modalità client
    # Creiamo un contesto TLS configurato per l'autenticazione del server
    # ssl.Purpose.SERVER_AUTH indica che il client verificherà l'identità del server
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # Per test locale con certificato autofirmato:
    # Disabilita la verifica del nome host nel certificato
    context.check_hostname = False
    # Disabilita la verifica del certificato contro una CA fidata
    context.verify_mode = ssl.CERT_NONE
    # NOTA: In un ambiente di produzione, queste impostazioni NON sono sicure.
    # Normalmente, si dovrebbe usare context.load_verify_locations() per specificare i certificati CA fidati
    # E mantenere la verifica del nome host e della catena di certificati attivata

    # 2) Apertura del socket TCP e wrapping con TLS
    # Creiamo prima una connessione TCP standard
    with socket.create_connection((HOST, PORT)) as sock:
        # Avvolgiamo il socket con TLS, specificando il nome host atteso nel certificato
        # Questo attiva l'handshake TLS e la crittografia automatica
        with context.wrap_socket(sock, server_hostname='localhost') as ssock:
            print(f"[+] TLS handshake completato con {HOST}:{PORT}")
            
            # 3) Loop echo cifrato
            # I dati inviati/ricevuti sono automaticamente gestiti dal layer TLS
            while True:
                # Richiedi input dall'utente
                msg = input(">> ").encode()
                if not msg:
                    # Esci se l'utente inserisce una stringa vuota
                    break
                
                # Invia il messaggio al server (automaticamente cifrato)
                ssock.sendall(msg)
                
                # Ricevi la risposta dal server (automaticamente decifrata)
                data = ssock.recv(4096)
                if not data:
                    # Il server ha chiuso la connessione
                    break
                
                # Mostra la risposta ricevuta
                print(f"[Server] {data.decode()!r}")

# Punto di ingresso dello script
if __name__ == '__main__':
    main()
