import re
import math
import sys
import time
import secrets
import threading
import string
from colorama import Fore, Style, init

# Abilita i codici colore ANSI sul terminale
init(autoreset=True)

# Su Windows forziamo l'encoding UTF-8 per evitare crash
# con caratteri non supportati dal terminale di sistema
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Variabile globale condivisa tra il thread principale e quello dello spinner
animazione_attiva = False


# ══════════════════════════════════════════════
# SEZIONE 1: ANIMAZIONE
# ══════════════════════════════════════════════

def animazione_caricamento(testo):
    """
    Eseguita in un thread separato: stampa uno spinner ASCII
    a rotazione finche animazione_attiva rimane True.
    I 20 spazi finali sovrascrivono i residui della riga precedente.
    """
    global animazione_attiva
    frames = ['-', '\\', '|', '/']
    i = 0
    while animazione_attiva:
        print(f"\r  {frames[i % len(frames)]} {testo}...", end='', flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r  OK {testo} completato!{' ' * 20}")


def avvia_animazione(testo):
    """
    Avvia lo spinner in background come thread daemon.
    I thread daemon vengono terminati automaticamente
    quando il programma principale termina.
    """
    global animazione_attiva
    animazione_attiva = True
    thread = threading.Thread(target=animazione_caricamento, args=(testo,))
    thread.daemon = True
    thread.start()
    return thread


def ferma_animazione(thread):
    """
    Segnala al thread dello spinner di fermarsi
    e attende che termini prima di proseguire.
    """
    global animazione_attiva
    animazione_attiva = False
    thread.join()


# ══════════════════════════════════════════════
# SEZIONE 2: OUTPUT
# ══════════════════════════════════════════════

def barra_punteggio(punti, massimo=20):
    """
    Restituisce una barra ASCII proporzionale al punteggio (0-100).
    I caratteri '#' rappresentano il riempimento,
    i '.' il vuoto rimanente fino al massimo.
    Esempio: punti=60, massimo=20 -> '############........'
    """
    riempimento = int((punti / 100) * massimo)
    vuoto = massimo - riempimento
    return "#" * riempimento + "." * vuoto


def calcola_punti_mancanti(punti):
    """
    Restituisce un messaggio che indica quanti punti mancano
    per raggiungere il livello di sicurezza successivo.
    Le soglie sono: 45 per MEDIO, 75 per FORTE.
    """
    if punti < 45:
        return f"  Ti mancano {45 - punti} punti per raggiungere il livello MEDIO."
    elif punti < 75:
        return f"  Ti mancano {75 - punti} punti per raggiungere il livello FORTE."
    else:
        return "  Hai raggiunto il livello massimo!"


def stampa_risultato(password, punti, problemi, entropia):
    """
    Stampa il riepilogo completo dell analisi:
    statistiche della password, punteggio con barra visiva,
    obiettivo successivo e lista dei problemi rilevati.
    """
    print("\n" + "=" * 45)
    print(f"  Password analizzata: {'*' * min(len(password), 20)}")
    print(f"  Lunghezza: {len(password)} caratteri")
    print(f"  Entropia:  {entropia} bit")
    print("=" * 45)

    barra = barra_punteggio(punti)

    if punti >= 75:
        colore   = Fore.GREEN
        giudizio = "FORTE"
        simbolo  = "[+]"
    elif punti >= 45:
        colore   = Fore.YELLOW
        giudizio = "MEDIA"
        simbolo  = "[~]"
    else:
        colore   = Fore.RED
        giudizio = "DEBOLE"
        simbolo  = "[!]"

    print(f"\n  {simbolo} Punteggio: {colore}{punti}/100 -- {giudizio}{Style.RESET_ALL}")
    print(f"  [{colore}{barra}{Style.RESET_ALL}]")
    print(f"\n{Fore.CYAN}{calcola_punti_mancanti(punti)}{Style.RESET_ALL}")

    print(f"\n  Dettagli:")
    if problemi:
        print(f"\n  {Fore.YELLOW}Problemi rilevati:{Style.RESET_ALL}")
        for p in problemi:
            print(f"    * {p}")
    else:
        print(f"\n  {Fore.GREEN}Nessun problema rilevato! Password eccellente.{Style.RESET_ALL}")
    print()


# ══════════════════════════════════════════════
# SEZIONE 3: CALCOLI DI SICUREZZA
# ══════════════════════════════════════════════

def calcola_entropia(password):
    """
    Calcola l entropia della password in bit usando la formula:
        entropia = lunghezza x log2(dimensione_charset)

    Il charset viene determinato dinamicamente in base alle categorie
    di caratteri presenti: minuscole (26), maiuscole (26),
    cifre (10), simboli (32). Piu categorie sono presenti,
    piu grande e lo spazio delle possibili combinazioni.
    """
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32

    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 1)


def analizza_password(password):
    """
    Analizza la password su quattro criteri: lunghezza, varieta
    di caratteri, assenza di pattern comuni ed entropia.

    Restituisce una tupla:
      - punti    (int, 0-100): punteggio di sicurezza complessivo
      - problemi (list[str]):  descrizione dei punti deboli trovati
      - entropia (float):      entropia calcolata in bit
    """
    problemi = []
    punti = 0

    # Lunghezza: ogni carattere aggiuntivo moltiplica esponenzialmente
    # il numero di combinazioni da testare in un attacco brute force
    if len(password) >= 16:
        punti += 30
    elif len(password) >= 12:
        punti += 20
    elif len(password) >= 8:
        punti += 10
    else:
        problemi.append("Troppo corta (minimo 12 caratteri consigliato)")

    # Varieta dei caratteri: ogni categoria aggiunge un intero
    # insieme di simboli al pool, aumentando lo spazio di ricerca
    if re.search(r'[a-z]', password):
        punti += 10
    else:
        problemi.append("Mancano lettere minuscole")

    if re.search(r'[A-Z]', password):
        punti += 10
    else:
        problemi.append("Mancano lettere maiuscole")

    if re.search(r'[0-9]', password):
        punti += 10
    else:
        problemi.append("Mancano numeri")

    # Gli spazi (\s) non vengono contati come simboli sicuri
    if re.search(r'[^a-zA-Z0-9\s]', password):
        punti += 20
    else:
        problemi.append("Mancano caratteri speciali (es. !@#$%)")

    # Pattern comuni: sequenze presenti in ogni dizionario di attacco.
    # Il break limita la penalita a un solo match per esecuzione
    pattern_comuni = [
        '123', 'abc', 'qwerty', 'password',
        'admin', '000', 'letmein', 'iloveyou'
    ]
    for pattern in pattern_comuni:
        if pattern.lower() in password.lower():
            punti -= 20
            problemi.append(f"Contiene sequenza ovvia: '{pattern}'")
            break

    # Bonus entropia: premia password con alta imprevedibilita statistica
    entropia = calcola_entropia(password)
    if entropia >= 60:
        punti += 20
    elif entropia >= 40:
        punti += 10

    # Blocca il punteggio nell intervallo [0, 100]
    punti = max(0, min(100, punti))
    return punti, problemi, entropia


# ══════════════════════════════════════════════
# SEZIONE 4: GENERATORE DI PASSWORD
# ══════════════════════════════════════════════

# Vocabolario italiano per il metodo passphrase (Diceware)
PAROLE = [
    "cavallo", "nuvola", "fiume", "bosco", "pietra", "vento", "stelle",
    "fulmine", "tigre", "oceano", "monte", "fiamma", "nebbia", "roccia",
    "aquila", "torre", "spada", "chiave", "porta", "isola", "luna",
    "drago", "foresta", "castello", "strada", "ponte", "cielo", "lago"
]

# Simboli usati come separatori nella passphrase
SEPARATORI = ["!", "@", "#", "$", "%", "&", "*", "?", "=", "+"]

# Lunghezza minima garantita per la password casuale
_MIN_LUNGHEZZA = 12


def genera_casuale(lunghezza=18):
    """
    Genera una password casuale crittograficamente sicura.

    Usa il modulo 'secrets', che si appoggia al generatore
    di numeri casuali del sistema operativo (CSPRNG). A differenza
    di 'random', che e deterministico, secrets e adatto a scopi
    crittografici come la generazione di password e token.

    La lunghezza viene forzata al minimo di _MIN_LUNGHEZZA.
    Vengono inseriti almeno 2 caratteri per ogni categoria
    (minuscole, maiuscole, cifre, simboli) prima di riempire il resto,
    assicurando che la password superi sempre tutti i controlli.
    Il mescolamento finale usa secrets.SystemRandom() per mantenere
    la casualita crittografica anche nella fase di shuffle.
    """
    lunghezza = max(lunghezza, _MIN_LUNGHEZZA)

    minuscole = string.ascii_lowercase
    maiuscole = string.ascii_uppercase
    numeri    = string.digits
    simboli   = "!@#$%&*?=+"
    tutti     = minuscole + maiuscole + numeri + simboli

    obbligatori = (
        [secrets.choice(minuscole) for _ in range(2)] +
        [secrets.choice(maiuscole) for _ in range(2)] +
        [secrets.choice(numeri)    for _ in range(2)] +
        [secrets.choice(simboli)   for _ in range(2)]
    )

    n_resto = lunghezza - len(obbligatori)
    resto = [secrets.choice(tutti) for _ in range(n_resto)]

    tutti_i_caratteri = obbligatori + resto
    secrets.SystemRandom().shuffle(tutti_i_caratteri)

    return ''.join(tutti_i_caratteri)


def genera_passphrase(num_parole=4):
    """
    Genera una passphrase stile Diceware con parole italiane.

    Il metodo Diceware combina piu parole casuali per ottenere
    una password facile da ricordare ma difficile da indovinare
    grazie alla lunghezza totale e all imprevedibilita della combinazione.

    Usa secrets.SystemRandom().sample() per estrarre parole senza
    ripetizioni. num_parole viene limitato alla dimensione del
    vocabolario disponibile. Simboli separatori e un numero finale
    a tre cifre aumentano ulteriormente l entropia complessiva.
    """
    num_parole = min(num_parole, len(PAROLE))

    parole_scelte = [p.capitalize() for p in secrets.SystemRandom().sample(PAROLE, num_parole)]
    separatori_scelti = [secrets.choice(SEPARATORI) for _ in range(num_parole - 1)]

    # Numero a tre cifre aggiunto in fondo per aumentare l entropia
    numero = secrets.randbelow(900) + 100

    risultato = ""
    for i, parola in enumerate(parole_scelte):
        risultato += parola
        if i < len(separatori_scelti):
            risultato += separatori_scelti[i]
    risultato += str(numero)

    return risultato


def chiedi_e_genera_password():
    """
    Chiede all utente se desidera una password suggerita,
    poi quale tipo preferisce tra casuale, passphrase o entrambe.

    Tutti gli input sono validati con loop while: il programma
    non prosegue finche l utente non inserisce un valore accettato.
    """
    # Accetta solo 's' o 'n' — ri-chiede in caso di input non valido
    while True:
        try:
            risposta = input(
                f"\n  {Fore.CYAN}Vuoi una password piu' forte? (s/n): {Style.RESET_ALL}"
            ).strip().lower()
        except EOFError:
            return
        if risposta in ('s', 'n'):
            break
        print(f"  {Fore.RED}Risposta non valida. Inserisci 's' per si' o 'n' per no.{Style.RESET_ALL}")

    if risposta != 's':
        return

    print(f"\n  Che tipo di password preferisci?\n")
    print(f"  [{Fore.GREEN}1{Style.RESET_ALL}] Casuale     (es. X7#kLm!9pQrT2@vB)  -- massima sicurezza")
    print(f"  [{Fore.YELLOW}2{Style.RESET_ALL}] Passphrase  (es. Cavallo$Nuvola42)  -- piu' facile da ricordare")
    print(f"  [{Fore.CYAN}3{Style.RESET_ALL}] Entrambe    (te ne mostro una per tipo)")

    # Accetta solo 1, 2 o 3 — ri-chiede in caso di input non valido
    while True:
        scelta_generatore = input(f"\n  Scegli (1-3) [1]: ").strip() or "1"
        if scelta_generatore in ("1", "2", "3"):
            break
        print(f"  {Fore.RED}Scelta non valida. Inserisci 1, 2 o 3.{Style.RESET_ALL}")

    print()
    print("  " + "=" * 45)
    print(f"  {'PASSWORD SUGGERITE':^43}")
    print("  " + "=" * 45)

    if scelta_generatore in ("1", "3"):
        pwd_casuale = genera_casuale(lunghezza=18)
        punti_c, _, entropia_c = analizza_password(pwd_casuale)
        barra_c = barra_punteggio(punti_c)
        print(f"\n  [Casuale]")
        print(f"  {Fore.GREEN}{pwd_casuale}{Style.RESET_ALL}")
        print(f"  Punteggio: {punti_c}/100  |  Entropia: {entropia_c} bit")
        print(f"  [{Fore.GREEN}{barra_c}{Style.RESET_ALL}]")

    if scelta_generatore in ("2", "3"):
        pwd_frase = genera_passphrase(num_parole=4)
        punti_f, _, entropia_f = analizza_password(pwd_frase)
        barra_f = barra_punteggio(punti_f)
        print(f"\n  [Passphrase]")
        print(f"  {Fore.YELLOW}{pwd_frase}{Style.RESET_ALL}")
        print(f"  Punteggio: {punti_f}/100  |  Entropia: {entropia_f} bit")
        print(f"  [{Fore.YELLOW}{barra_f}{Style.RESET_ALL}]")

    print()
    print(f"  {Fore.CYAN}Consiglio: copiala subito in un password manager!{Style.RESET_ALL}")
    print("  " + "=" * 45)


# ══════════════════════════════════════════════
# SEZIONE 5: AVVIO DEL PROGRAMMA
# ══════════════════════════════════════════════

if __name__ == "__main__":

    # Il KeyboardInterrupt (Ctrl+C) viene intercettato globalmente
    # per uscire con un messaggio pulito invece del traceback di Python
    try:

        print(f"\n{Fore.CYAN}{'=' * 45}")
        print(f"{'ANALIZZATORE DI PASSWORD':^45}")
        print(f"{'=' * 45}{Style.RESET_ALL}\n")

        # Modalita argomento: la password viene passata direttamente
        # da riga di comando (es: py analyzer.py miapassword)
        if len(sys.argv) > 1:
            password = sys.argv[1].strip()
            if not password:
                print(f"\n  {Fore.RED}Errore: password vuota!{Style.RESET_ALL}\n")
                sys.exit(1)

        # Modalita interattiva: l utente sceglie se nascondere
        # l input durante la digitazione (consigliato per sicurezza)
        else:
            print(f"  {Fore.CYAN}{'─' * 30}{Style.RESET_ALL}")
            print(f"  Inserisci la password da analizzare\n")
            print(f"  [1] Input nascosto (consigliato)")
            print(f"  [2] Input visibile")

            # Accetta solo 1 o 2 — ri-chiede in caso di input non valido
            while True:
                scelta_input = input(f"\n  Scegli (1-2) [1]: ").strip() or "1"
                if scelta_input in ("1", "2"):
                    break
                print(f"  {Fore.RED}Scelta non valida. Inserisci 1 o 2.{Style.RESET_ALL}")

            if scelta_input == "1":
                try:
                    from getpass import getpass
                    password = getpass(prompt="\n  Password: ")
                except Exception:
                    # getpass non disponibile in alcuni ambienti (es. IDE integrati)
                    password = input("\n  Password: ")
            else:
                password = input("\n  Password: ")

        # Una password vuota o composta solo da spazi non e analizzabile
        if not password or not password.strip():
            print(f"\n  {Fore.RED}Errore: nessuna password inserita!{Style.RESET_ALL}\n")
            sys.exit(1)

        # Avvia l analisi con animazione visiva in background
        print(f"\n  {Fore.CYAN}Analisi in corso...{Style.RESET_ALL}")
        thread = avvia_animazione("Controllo sicurezza")
        time.sleep(1.2)

        punti, problemi, entropia = analizza_password(password)
        ferma_animazione(thread)

        stampa_risultato(password, punti, problemi, entropia)

        # Proposta opzionale di generazione password sicura
        chiedi_e_genera_password()

        input(f"\n  {Fore.CYAN}Premi INVIO per chiudere...{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}Interruzione rilevata. Arrivederci!{Style.RESET_ALL}\n")
        sys.exit(0)
