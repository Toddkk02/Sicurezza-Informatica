# Web Security Lab

## Introduzione

Benvenuto nel **Web Security Lab**, un progetto dedicato all'apprendimento pratico delle principali vulnerabilità delle applicazioni web. Questo repository contiene documentazione dettagliata, esercitazioni pratiche e analisi approfondite di due delle vulnerabilità web più critiche e diffuse: **Cross-Site Scripting (XSS)** e **File Upload Vulnerabilities**.

Il laboratorio è progettato per fornire una comprensione teorica e pratica di come queste vulnerabilità possano essere sfruttate, come rilevarle e, soprattutto, come difendersi efficacemente da esse. Ogni sezione include esempi di codice, payload di test, tecniche di bypass e strategie di mitigazione basate su standard industriali.

---

## 📚 Indice delle Vulnerabilità

### 🎯 [Cross-Site Scripting (XSS)](xss-and-session-hijacking.md)
Analisi completa delle vulnerabilità XSS, dalle basi teoriche alle tecniche di exploitation avanzate.

### 📁 [File Upload Vulnerabilities](file_upload_documentation.md)
Studio approfondito delle vulnerabilità di caricamento file, con focus su bypass delle protezioni e Remote Code Execution.

---

## 🔍 Panoramica delle Vulnerabilità

### Cross-Site Scripting (XSS)

Il **Cross-Site Scripting** è una delle vulnerabilità web più diffuse e pericolose, che consente agli attaccanti di iniettare codice JavaScript malevolo all'interno di pagine web legittime. Quando un utente visita una pagina compromessa, il codice dell'attaccante viene eseguito nel contesto del browser della vittima, permettendo potenzialmente di:

- **Rubare cookie di sessione** e impersonare utenti legittimi
- **Modificare il contenuto delle pagine** in tempo reale
- **Reindirizzare gli utenti** verso siti malevoli
- **Eseguire azioni non autorizzate** per conto dell'utente
- **Raccogliere informazioni sensibili** come credenziali o dati personali

#### Tipologie di XSS Analizzate:
- **Stored XSS**: Payload permanenti salvati nel database
- **Reflected XSS**: Exploit che si attivano tramite link malevoli
- **DOM-based XSS**: Attacchi che manipolano il Document Object Model

#### Scenari di Testing:
- Bypass di filtri di sicurezza
- Tecniche di encoding e obfuscation
- Cookie stealing e session hijacking
- Content Security Policy (CSP) evasion

---

### File Upload Vulnerabilities

Le **vulnerabilità di File Upload** rappresentano uno dei vettori di attacco più critici nelle applicazioni web moderne. Quando un'applicazione permette agli utenti di caricare file senza implementare controlli di sicurezza adeguati, gli attaccanti possono sfruttare questa funzionalità per:

- **Ottenere Remote Code Execution (RCE)** caricando script eseguibili
- **Bypassare le protezioni** attraverso tecniche di file manipulation
- **Compromettere l'intero server** e ottenere accesso privilegiato
- **Installare backdoor persistenti** per mantenere l'accesso
- **Rubare dati sensibili** dal sistema target

#### Tecniche di Bypass Documentate:
- **Extension-based bypasses**: Utilizzo di estensioni alternative (.phtml, .php5)
- **MIME type spoofing**: Manipolazione degli header HTTP
- **Content injection**: Embedding di payload in file apparentemente legittimi
- **EXIF metadata injection**: Iniezione di codice nei metadati delle immagini

#### Livelli di Protezione Testati:
- **LOW**: Nessuna protezione (baseline)
- **MEDIUM**: Filtri blacklist e controlli MIME type
- **HIGH**: Validazione rigorosa con getimagesize() e whitelist

---

## 🛡️ Approccio alla Sicurezza

### Metodologia di Testing

Ogni vulnerabilità è analizzata seguendo un approccio metodico che include:

1. **Analisi teorica** - Comprensione dei meccanismi sottostanti
2. **Reconnaissance** - Identificazione dei punti di attacco
3. **Exploitation** - Sviluppo e test dei payload
4. **Bypass techniques** - Evasione delle protezioni implementate
5. **Detection** - Identificazione degli indicatori di compromissione
6. **Mitigation** - Implementazione di controlli di sicurezza efficaci

### Ambiente di Laboratorio

I test sono condotti in un ambiente controllato che include:

- **DVWA (Damn Vulnerable Web Application)** - Piattaforma di testing
- **Kali Linux** - Distribuzione per penetration testing
- **Ubuntu Server** - Target system per exploitation
- **Network isolation** - Ambiente sicuro e controllato

### Considerazioni Etiche

⚠️ **IMPORTANTE**: Tutte le tecniche documentate sono testate esclusivamente su:
- Sistemi di proprietà personale
- Ambienti di laboratorio isolati
- Applicazioni progettate per il testing di sicurezza

L'utilizzo di queste informazioni su sistemi non autorizzati costituisce attività illegale. Il materiale è fornito esclusivamente per scopi educativi e per il miglioramento delle difese di sicurezza.

---

## 🎓 Obiettivi di Apprendimento

Al termine dello studio di entrambe le sezioni, sarai in grado di:

### Competenze Offensive
- Identificare e sfruttare vulnerabilità XSS in diverse configurazioni
- Bypassare sistemi di file upload protection
- Sviluppare payload custom per scenari specifici
- Combinare vulnerabilità multiple per attack chain complesse

### Competenze Difensive
- Implementare controlli di input validation efficaci
- Configurare Content Security Policy (CSP) robuste
- Progettare sistemi di file upload sicuri
- Sviluppare sistemi di detection e monitoring

### Competenze Analitiche
- Analizzare codice sorgente per identificare vulnerabilità
- Interpretare log di sicurezza e identificare attacchi
- Valutare l'efficacia delle misure di sicurezza implementate
- Documentare findings in report tecnici professionali

---

## 📋 Prerequisiti

Per seguire efficacemente questo laboratorio, è consigliabile avere:

- **Conoscenze di base** di HTML, JavaScript e PHP
- **Familiarità** con i protocolli HTTP/HTTPS
- **Esperienza** nell'uso di strumenti di testing web (Burp Suite, curl)
- **Comprensione** dei concetti base di networking e sicurezza informatica

---

## 🚀 Come Iniziare

1. **Studia la teoria** presente in ciascuna sezione
2. **Configura l'ambiente** di laboratorio seguendo le guide
3. **Esegui i test** step-by-step secondo la documentazione
4. **Sperimenta** con variazioni dei payload proposti
5. **Implementa** le misure di sicurezza suggerite
6. **Documenta** i tuoi findings e scoperte

---

## 📖 Risorse Aggiuntive

### Standard e Framework di Riferimento
- **OWASP Top 10** - Lista delle vulnerabilità web più critiche
- **OWASP Testing Guide** - Metodologie di testing standardizzate
- **NIST Cybersecurity Framework** - Linee guida per la sicurezza
- **CWE/SANS Top 25** - Debolezze software più pericolose

### Tools Consigliati
- **Burp Suite** - Web application security testing
- **OWASP ZAP** - Security scanner open source
- **SQLMap** - Automated SQL injection testing
- **XSSHunter** - Blind XSS detection platform

### Community e Learning
- **OWASP Local Chapters** - Community locali di sicurezza
- **Bug Bounty Platforms** - Practical experience su target reali
- **CTF Competitions** - Competizioni di cybersecurity
- **Security Conferences** - Aggiornamenti su nuove tecniche

---

## 📄 Licenza e Disclaimer

### Licenza
Questo materiale è distribuito sotto licenza educativa per l'apprendimento della cybersecurity.

### Disclaimer Legale
L'autore non si assume responsabilità per l'uso improprio delle informazioni contenute in questo repository. Le tecniche documentate devono essere utilizzate esclusivamente per:
- Formazione personale
- Testing di sistemi autorizzati
- Miglioramento delle difese di sicurezza
- Ricerca accademica

### Contributi
Contributi, correzioni e suggerimenti sono benvenuti attraverso pull request o issue del repository.

---

*Documentazione creata come parte del percorso "90 giorni da Ethical Hacker a Senior Security Professional" - Una risorsa per la community italiana di cybersecurity.*
