# Password-strength-analyzer

Uno strumento da riga di comando scritto in Python che analizza la sicurezza di una password e suggerisce come migliorarla, con un generatore integrato di password sicure.

Obiettivo del Progetto
Creare uno strumento pratico per valutare la robustezza delle password secondo criteri tecnici reali — lunghezza, varieta di caratteri, assenza di pattern comuni ed entropia — e aiutare l'utente a scegliere credenziali piu sicure.
Questo e il primo progetto nel percorso di Cybersecurity e Network Administration.

Funzionalita Implementate

Analisi della password su quattro criteri: lunghezza, varieta caratteri, pattern comuni ed entropia
Punteggio da 0 a 100 con barra visiva e giudizio (DEBOLE / MEDIA / FORTE)
Indicazione dei punti deboli con suggerimenti specifici
Calcolo dell entropia in bit (formula crittografica reale)
Messaggio con i punti mancanti per raggiungere il livello successivo
Generatore di password casuale crittograficamente sicuro (modulo secrets)
Generatore di passphrase stile Diceware con parole italiane
Input nascosto con getpass per proteggere la password durante la digitazione
Validazione completa di tutti gli input con loop — nessun crash per input errati
Gestione Ctrl+C con messaggio pulito
Compatibile con Windows, Linux e macOS


Tecnologie Utilizzate

Python 3.10+
secrets (generazione crittograficamente sicura)
re (analisi pattern con espressioni regolari)
math (calcolo entropia)
threading (animazione spinner durante l analisi)
getpass (input password nascosto)
colorama (output colorato nel terminale)


Installazione e Utilizzo
Setup
bashgit clone https://github.com/tuo-username/password-strength-analyzer.git
cd password-strength-analyzer
pip install colorama
Utilizzo
bash# Modalita interattiva
python analyzer_final.py

# Modalita da riga di comando
python analyzer_final.py miapassword

Esempio di Output
=============================================
          ANALIZZATORE DI PASSWORD
=============================================

  [1] Input nascosto (consigliato)
  [2] Input visibile

  Scegli (1-2) [1]: 1
  Password: ****

  OK Controllo sicurezza completato!

=============================================
  Password analizzata: **********
  Lunghezza: 10 caratteri
  Entropia:  65.5 bit
=============================================

  [!] Punteggio: 40/100 -- DEBOLE
  [##########..........]

  Ti mancano 5 punti per raggiungere il livello MEDIO.

  Dettagli:

  Problemi rilevati:
    * Mancano caratteri speciali (es. !@#$%)
    * Contiene sequenza ovvia: '123'

  Vuoi una password piu forte? (s/n): s

  Che tipo di password preferisci?

  [1] Casuale     (es. X7#kLm!9pQrT2@vB)  -- massima sicurezza
  [2] Passphrase  (es. Cavallo$Nuvola42)  -- piu facile da ricordare
  [3] Entrambe    (te ne mostro una per tipo)

  Scegli (1-3) [1]: 3

  =============================================
              PASSWORD SUGGERITE
  =============================================

  [Casuale]
  pFqx6A#81o%lBCBvt2
  Punteggio: 100/100  |  Entropia: 120.4 bit
  [####################]

  [Passphrase]
  Drago=Foresta+Fulmine?Lago584
  Punteggio: 100/100  |  Entropia: 190.1 bit
  [####################]

  Consiglio: copiala subito in un password manager!
  =============================================

Concetti di Sicurezza Applicati
Entropia — misura matematica dell imprevedibilita di una password. Calcolata come lunghezza x log2(charset). Piu e alta, piu tempo richiede un attacco brute force.
Diceware — metodo raccomandato dal NIST per la generazione di passphrase. Combina parole casuali per ottenere password facili da ricordare ma difficili da indovinare.
CSPRNG — Cryptographically Secure Pseudo-Random Number Generator. Il modulo secrets usa il generatore del sistema operativo, a differenza di random che e deterministico e non adatto a scopi crittografici.

Struttura del Progetto
password-strength-analyzer/
  analyzer_final.py   # Codice principale
  README.md


Note Legali
Questo strumento e pensato per uso personale e educativo. Non utilizzarlo per violare la privacy altrui o accedere a sistemi non autorizzati.
