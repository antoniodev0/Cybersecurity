import socket
import os
import struct
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(shared_key: bytes) -> bytes:
    """
    Deriva una chiave AES-256 da raw shared_key usando HKDF-SHA256.
    """
    # 1) Derivazione della chiave crittografica
    # HKDF (HMAC-based Key Derivation Function) è un algoritmo di derivazione 
    # chiavi standardizzato (RFC 5869) che permette di estrarre materiale
    # chiave da una fonte di entropia (shared_key) e distribuirlo
    # Usiamo SHA-256 come algoritmo di hash interno per sicurezza adeguata
    hkdf = HKDF(
        algorithm=hashes.SHA256(),  # Algoritmo di hash sicuro
        length=32,                  # 256 bit (32 byte) per AES-256
        salt=None,                  # Nessun sale aggiuntivo 
        info=b'handshake data',     # Contesto specifico dell'applicazione
    )
    # Deriviamo la chiave effettiva dalla chiave condivisa DH
    return hkdf.derive(shared_key)

def recvn(conn: socket.socket, n: int) -> bytes:
    """
    Riceve esattamente n byte dal socket; solleva EOFError se la connessione si chiude.
    """
    # 2) Funzione di utilità per ricevere un numero esatto di byte
    # Questa funzione è necessaria perché socket.recv() potrebbe 
    # restituire meno byte di quelli richiesti in una singola chiamata
    data = b''
    while len(data) < n:
        # Richiedi solo i byte rimanenti ad ogni iterazione
        packet = conn.recv(n - len(data))
        # Se non riceviamo dati, la connessione è stata chiusa
        if not packet:
            raise EOFError("Connection closed")
        # Accumula i byte ricevuti
        data += packet
    return data

def send_encrypted(conn: socket.socket, aesgcm: AESGCM, plaintext: bytes) -> None:
    """
    Cifra e invia [4-byte big-endian length][nonce||ciphertext] usando AES-GCM.
    """
    # 3) Funzione per cifrare e inviare messaggi in modo sicuro
    # Genera un nonce (numero usato una sola volta) di 12 byte
    # IMPORTANTE: ogni nonce deve essere unico per ogni messaggio con la stessa chiave
    nonce = os.urandom(12)
    
    # Cifra il messaggio usando AES-GCM con il nonce generato
    # AES-GCM è un AEAD (Authenticated Encryption with Associated Data)
    # che fornisce sia confidenzialità che autenticità
    ct = aesgcm.encrypt(nonce, plaintext, None)
    
    # Combina nonce e testo cifrato in un unico blob
    # Il nonce deve essere trasmesso insieme al testo cifrato
    # per consentire la decifratura, ma non deve essere segreto
    blob = nonce + ct
    
    # Prepara un header che indica la lunghezza del messaggio (4 byte, big-endian)
    # Questo permette al ricevitore di sapere quanti byte aspettarsi
    header = struct.pack('>I', len(blob))
    
    # Invia l'header seguito dal blob contenente nonce e testo cifrato
    conn.sendall(header + blob)

def recv_decrypted(conn: socket.socket, aesgcm: AESGCM) -> bytes:
    """
    Riceve e decifra un messaggio strutturato come in send_encrypted.
    """
    # 4) Funzione per ricevere e decifrare messaggi
    # Legge prima i 4 byte dell'header che contengono la lunghezza
    raw_len = recvn(conn, 4)
    (msg_len,) = struct.unpack('>I', raw_len)
    
    # Riceve esattamente msg_len byte (il blob completo)
    blob = recvn(conn, msg_len)
    
    # Estrae il nonce (primi 12 byte) e il testo cifrato (resto del blob)
    nonce, ct = blob[:12], blob[12:]
    
    # Decifra il messaggio usando AES-GCM
    # La decifratura verificherà automaticamente l'autenticità del messaggio
    # Se il messaggio è stato manomesso o corrotto, solleverà un'eccezione
    return aesgcm.decrypt(nonce, ct, None)
