- Per attivare l'ambiente, dentro la cartella del progetto aprire il terminale e lanciare:
""python3 -m venv venv
source venv/bin/activate
pip install cryptography
pip freeze > requirements.txt
""
- Quindi la struttura delle cartelle sarà: 
Cyberproject/           ← cartella principale del tuo progetto
│
├── venv/               ← il tuo virtualenv (non ci metti dentro il codice!)
│
├── requirements.txt    ← elenco delle dipendenze, al livello del progetto
│
└── secure_chat/        ← qui dentro metti client.py, server.py, ecc.
    ├── client.py
    └── server.py
requirements.txt rimane nel root di Cyberproject/ in modo che, da linea di comando, si possa lanciare pip install -r requirements.txt senza doversi spostare dentro le sottocartelle.
- per eseguire il test e dimostrare la vulnerabilità della comunicazione, lanciare prima il codice del server, successivamente quello del "mitm_proxy" e infine quello del client. Si avranno tre terminali aperti e nel codice del client bisognerà settare la porta del mitm per test.
- per eseguire il secondo test, con TLS, generare prima i certificati e da terminale lanciare:
""openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt \
  -days 365 \
  -subj "/C=IT/ST=MI/L=Milan/O=Uni/CN=localhost"
""
Successivamente lanciare prima il codice del server, poi quello del MITM e infine quello del client, settando sempre come porta quella del MITM. Una volta avviati i terminali si potrà vedere che andrà in errore. Questo è quello che ci aspettiamo perchè effettivamente il server al quale si sta cercando di connettere il client non è certificato.