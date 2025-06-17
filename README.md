# OneTimeXOR

**OneTimeXor** è uno strumento a riga di comando, scritto in C, per la cifratura e l'autenticazione sicura di file. Si ispira a cifrari OTP come Vernam, rendendone l'implementazione più pratica attraverso algoritmi crittografici moderni per garantire la confidenzialità, l'integrità e l'autenticità dei dati.

## Funzionalità principali

* **Cifratura robusta**: I dati vengono cifrati usando l'algoritmo **AES-256 in modalità CTR (Counter)** per generare una sequenza di bit pseudocasuali. Questo lo trasforma in un cifrario a flusso che non richiede padding e ha eccellenti performance perchè la generazione di bit casuali è parallelizzabile. Una volta ottenuto questo keystream viene usato per cifrare byte a byte il file in chiaro con il semplice XOR logico.
* **Autenticazione forte**: Implementa lo schema **Encrypt-then-MAC**. Dopo la cifratura, un "sigillo" di autenticazione viene generato usando **HMAC-SHA256**, rendendo impossibile per un malintenzionato modificare il file cifrato o il sigillo senza essere scoperto.
* **Derivazione sicura della chiave**: Le chiavi di cifratura non vengono mai derivate direttamente dalla password. Si utilizza l'algoritmo **PBKDF2** con **600 mila iterazioni** e un `salt` casuale per ogni file, rendendo gli attacchi a forza bruta sulla password estremamente lenti e costosi.
* **Protezione da errori utente**:
    * Chiede conferma prima di **sovrascrivere** un file esistente.
    * Richiede l'**inserimento doppio della password** in fase di cifratura per prevenire errori di battitura che renderebbero il file irrecuperabile.
* **Sicurezza della memoria**: Le chiavi crittografiche e le password vengono cancellate in modo sicuro dalla RAM dopo l'uso, utilizzando `OPENSSL_cleanse` per ridurre il rischio di esposizione. Inoltre possono essere gestiti file senza limiti di grandezza (se non quelli del filesystem) attraverso la segmentazione in chunk.
* **Facilità d'uso**:
    * Supporta sia una **modalità interattiva** guidata che una **modalità a riga di comando (CLI)** per l'uso in script.
* **Personalizzabile**:
    * Il codice è pensato per essere facilmente ispezionabile e modificabile per variarne i parametri di funzionamento a piacimento, come le interazioni del PBKDF2 (NOTA BENE: modificare questo valore rende il programma non retrocompatibile con file cifrati con il valore di default).

## Come Funziona

Il programma segue un flusso logico e sicuro e noto in letteratura per proteggere i dati.

### Processo di Cifratura

1.  **Generazione casuale**: Vengono generati un `salt` (16 byte) e un `nonce` (16 byte) unici per questa operazione.
2.  **Derivazione chiavi**: La password dell'utente e il `salt` vengono usati da PBKDF2 per generare due chiavi distinte: una per la cifratura (`enc_key`) e una per l'autenticazione (`mac_key`).
3.  **Scrittura intestazione**: `salt` e `nonce` vengono scritti all'inizio del file di output (devono essere pubblici per ricostruire il keystream).
4.  **Cifratura a flusso**: Il contenuto del file originale viene letto in blocchi di lunghezza CHUNK (per non avere problemi su file di dimensioni qualsiasi) e cifrato tramite **XOR** logico con il *keystream* generato da AES-256-CTR (usando `enc_key` e `nonce`).
5.  **Calcolo del MAC**: Man mano che i dati vengono cifrati, vengono anche passati a HMAC-SHA256 (usando `mac_key`). Anche `salt` e `nonce` fanno parte del calcolo.
6.  **Aggiunta del sigillo**: Alla fine, il risultato del calcolo HMAC, chiamato **tag** (32 byte), viene aggiunto in coda al file cifrato.

Il file finale ha la seguente struttura: `[SALT][NONCE][TESTO CIFRATO][TAG]`.

### Processo di Decifratura

1.  **Lettura metadati**: Vengono letti `salt`, `nonce` e `tag` dal file di input.
2.  **Derivazione chiavi**: Le chiavi vengono rigenerate usando la password fornita e il `salt` letto dal file.
3.  **Verifica del sigillo (fase 1)**: **Prima di decifrare**, il programma ricalcola il tag HMAC sul `salt`, `nonce` e su tutto il testo cifrato. Se il tag calcolato non corrisponde a quello letto dal file l'esecuzione termina. Questo garantisce che il file non sia stato manomesso e che la password sia corretta, ma soprattutto che non vengano processati dati potenzialmente pericolosi.
4.  **Decifratura (fase 2)**: Solo se la verifica ha successo il programma procede a decifrare i dati, applicando la stessa operazione di XOR con lo stesso keystream usato per la cifratura.

## Prerequisiti

Per compilare ed eseguire il programma, sono necessari:
* Un compilatore C come `gcc`.
* Le librerie di sviluppo di **OpenSSL**.

Su sistemi Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev
```

Su sistemi Fedora/CentOS/RHEL:
```bash
sudo dnf install gcc openssl-devel
```

## Compilazione

Il progetto include un `makefile` che semplifica la compilazione. Posizionarsi nella directory del progetto e lanciare il comando:

```bash
make
```

Questo comando creerà un file eseguibile chiamato `onetime`. Per pulire i file generati, usare `make clean`.

## Utilizzo

Il programma può essere usato in due modalità.

### 1. Modalità interattiva

Per avviare il menu guidato, eseguire il comando senza argomenti:

```bash
./onetimexor
```
Il programma farà delle domande per guidare l'utente attraverso la cifratura o la decifratura.

### 2. Modalità a riga di comando (CLI)

Questa modalità è ideale per l'automazione e l'uso in script.

#### **Per cifrare:**

```bash
./onetimexor encrypt -i <file_input> -o <file_output>
```
**Esempio:**
```bash
./onetimexor encrypt -i documento_segreto.txt -o documento.dat
```

#### **Per decifrare:**

```bash
./onetimexor decrypt -i <file_cifrato> -o <file_decrifrato>
```
**Esempio:**
```bash
./onetimexor decrypt -i documento.dat -o documento_segreto.txt
```

In entrambi i casi, verrà richiesta la password in modo sicuro (l'input non sarà visibile a schermo).

## Considerazioni sulla sicurezza

* **Password**: La sicurezza dell'intero sistema dipende in modo critico dalla **robustezza della password** scelta. Usare password lunghe, complesse e uniche.
* **Metadati**: Questo programma cifra solo il *contenuto* dei file. Il nome del file, la sua dimensione e le date di modifica/creazione non vengono nascosti.
* **Futuri upgrade**:
  * Creazione e gestione di keyfile per l'uso del programma in pipeline, automatizzando tramite script tutte le operazioni.
  * Crittografia negabile
