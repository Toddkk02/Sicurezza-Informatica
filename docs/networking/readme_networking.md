# Networking e Sicurezza - Documentazione Completa

Documentazione tecnica completa su networking, analisi protocolli, packet capture e attack vectors. Include analisi pratica di traffico di rete, ARP spoofing, MITM attacks e tecniche di reconnaissance con tools professionali.

## Indice

- [Packet Analysis](#packet-analysis)
- [Three-Way Handshake](#three-way-handshake)
- [Subnetting](#subnetting)
- [Port Scanning](#port-scanning)
- [Network Discovery](#network-discovery)
- [ARP Spoofing & Man-in-the-Middle Attack](#arp-spoofing--man-in-the-middle-attack)
- [Protocol Vulnerabilities](#protocol-vulnerabilities)
- [Best Practices](#best-practices)

## Packet Analysis

### tshark - Network Protocol Analyzer

#### Setup e Configurazione

```bash
# Verifica installazione
tshark -v
# TShark (Wireshark) 3.6.2

# Lista interfacce disponibili
tshark -D
# 1. eth0
# 2. wlan0
# 3. lo (Loopback)
```

#### Cattura Base

```bash
# Cattura tutto il traffico
sudo tshark

# Cattura su interfaccia specifica
sudo tshark -i wlan0

# Salvataggio in file
sudo tshark -w capture.pcap

# Lettura da file
tshark -r capture.pcap
```

#### Esempio Traffico Catturato (176 pacchetti)

```
146 10.527487448 192.168.x.x → 192.168.130.187 DNS 76 Standard query 0x0a89 A ping.manjaro.org
147 10.527501668 192.168.x.x → 192.168.130.187 DNS 76 Standard query 0xcab7 AAAA ping.manjaro.org
148 10.530278726 192.168.130.187 → 192.168.x.x DNS 92 Standard query response 0x0a89 A ping.manjaro.org A 116.203.91.91
149 10.530517532 192.168.130.187 → 192.168.x.x DNS 104 Standard query response 0xcab7 AAAA ping.manjaro.org AAAA 2a01:4f8:c0c:51f3::1
150 12.360664754 [MAC_1] → [MAC_2] ARP 42 Who has 192.168.x.x? Tell 192.168.130.187
151 12.360679494 [MAC_2] → [MAC_1] ARP 42 192.168.x.x is at [MAC_2]
152 16.555285247 192.168.x.x → 18.97.36.75 TLSv1.2 307 Application Data
153 16.579458804 192.168.x.x → 239.255.255.250 SSDP 210 M-SEARCH * HTTP/1.1
```

#### Analisi Traffico Identificato

**DNS Queries**:
- **A record** (IPv4): ping.manjaro.org → 116.203.91.91
- **AAAA record** (IPv6): ping.manjaro.org → 2a01:4f8:c0c:51f3::1
- **Funzione**: Risoluzione nomi di dominio

**ARP (Address Resolution Protocol)**:
- **Scopo**: Mappatura IP → MAC address
- **Rete locale**: 192.168.x.x discovery
- **Frequenza**: Ogni pochi secondi per host attivi

**SSDP (Simple Service Discovery Protocol)**:
- **IP multicast**: 239.255.255.250
- **Protocollo**: HTTP-like su UDP
- **Funzione**: Scoperta dispositivi UPnP

**TLS Traffic**:
- **Versione**: TLSv1.2
- **Porte**: 443 (HTTPS)
- **Data**: Application Data encrypted

### tcpdump - Command Line Packet Analyzer

#### Sintassi Base

```bash
# Cattura base
sudo tcpdump

# Interfaccia specifica
sudo tcpdump -i eth0

# Host specifico
sudo tcpdump host 8.8.8.8

# Porta specifica
sudo tcpdump port 80

# Protocollo specifico
sudo tcpdump tcp
```

#### Filtri Avanzati

```bash
# TCP traffico verso Google
sudo tcpdump -i any -n -v 'tcp and host google.com'

# Parametri spiegati:
# -i any     = tutte le interfacce
# -n         = no DNS resolution
# -v         = verbose mode
# 'tcp and host google.com' = filtro BPF
```

#### Test Pratico con Google

**Trigger**: `curl -I http://google.com`

**Output catturato**:
```
10:18:35.954106 enpX Out IP 192.168.x.x.59416 > 216.58.x.x.80: Flags [S], seq [...], length 0
10:18:36.001373 enpX In  IP 216.58.x.x.80 > 192.168.x.x.59416: Flags [S.], seq [...], ack [...], length 0
10:18:36.001385 enpX Out IP 192.168.x.x.59416 > 216.58.x.x.80: Flags [.], ack 1, length 0

10:18:36.001409 enpX Out IP 192.168.x.x.59416 > 216.58.x.x.80: Flags [P.], length 75: HTTP
    HEAD / HTTP/1.1
    Host: google.com
    User-Agent: curl/8.14.1
    Accept: */*

10:18:36.134911 enpX In  IP 216.58.x.x.80 > 192.168.x.x.59416: Flags [P.], length 554: HTTP
    HTTP/1.1 301 Moved Permanently
    Location: http://www.google.com/
    Content-Type: text/html; charset=UTF-8
    Server: gws
```

#### Analisi Dettagliata

**Timing Analysis**:
- **Latenza**: ~47ms verso Google
- **RTT**: Round-trip time accettabile
- **Possibile vulnerability**: SYN flood (porte client predicibili)

**Flag TCP**:
- **[S]**: SYN (sincronizzazione)
- **[S.]**: SYN-ACK (sincronizzazione + acknowledgment)
- **[.]**: ACK (acknowledgment)
- **[P.]**: PSH (push data immediately)
- **[F.]**: FIN (fine connessione)

**User-Agent Disclosure**:
- **curl/8.14.1**: Versione software esposta
- **Rischio**: Fingerprinting e vulnerability targeting

**Security Headers Missing**:
- **X-XSS-Protection**: 0 (disabled)
- **Potenziale vulnerability**: XSS attacks

## Three-Way Handshake

### Concetti Base

Il three-way handshake è il processo di stabilimento connessione TCP.

**Fasi**:
1. **Client → Server**: SYN (synchronize)
2. **Server → Client**: SYN-ACK (synchronize-acknowledge)
3. **Client → Server**: ACK (acknowledge)

### Cattura Handshake

#### Setup tcpdump per Handshake

```bash
# Filtro per catturare solo SYN/ACK flags
sudo tcpdump -i interface 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'

# Parametri spiegati:
# tcp[tcpflags]           = byte dei flag TCP
# tcp-syn|tcp-ack         = flag SYN o ACK
# != 0                    = almeno uno dei flag settato
```

#### Test con telnet

```bash
# Trigger handshake
telnet example.com 80
```

#### Risultato Catturato

```
11:01:40.925898 IP [CLIENT] > [SERVER]: Flags [S], seq ..., win ..., length 0
11:01:41.141589 IP [SERVER] > [CLIENT]: Flags [S.], seq ..., ack ..., length 0
11:01:41.141604 IP [CLIENT] > [SERVER]: Flags [.], ack ..., length 0
```

### Analisi Sequenza Numbers

**Dettagli tecnici**:
```
1. Client → Server: SYN (seq=X, flags=S)
2. Server → Client: SYN-ACK (seq=Y, ack=X+1, flags=SA)
3. Client → Server: ACK (seq=X+1, ack=Y+1, flags=A)
```

**Security Implications**:
- **Sequence prediction**: Difficoltà 259 (alta sicurezza)
- **SYN flood attack**: Possibile saturare half-open connections
- **RST injection**: Possibile se sequence numbers predicibili

## Subnetting

### Concetti Base

La subnet mask definisce quanti host sono disponibili in una rete.

**Formula**: Host disponibili = 2^(32-CIDR) - 2
- **-2**: Network address e Broadcast address non utilizzabili

### ipcalc - Network Calculator

#### Rete Standard /24

```bash
ipcalc 192.168.1.0/24
```

**Output**:
```
Address:   192.168.1.0          11000000.10101000.00000001. 00000000
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
=>
Network:   192.168.1.0/24       11000000.10101000.00000001. 00000000
HostMin:   192.168.1.1          11000000.10101000.00000001. 00000001
HostMax:   192.168.1.254        11000000.10101000.00000001. 11111110
Broadcast: 192.168.1.255        11000000.10101000.00000001. 11111111
Hosts/Net: 254                   Class C, Private Internet
```

#### Rete Piccola /28

```bash
ipcalc 192.168.1.0/28
```

**Output**:
```
Address:   192.168.1.0          11000000.10101000.00000001.0000 0000
Netmask:   255.255.255.240 = 28 11111111.11111111.11111111.1111 0000
Wildcard:  0.0.0.15             00000000.00000000.00000000.0000 1111
=>
Network:   192.168.1.0/28       11000000.10101000.00000001.0000 0000
HostMin:   192.168.1.1          11000000.10101000.00000001.0000 0001
HostMax:   192.168.1.14         11000000.10101000.00000001.0000 1110
Broadcast: 192.168.1.15         11000000.10101000.00000001.0000 1111
Hosts/Net: 14                    Class C, Private Internet
```

**Calcolo manuale /28**:
- 32 - 28 = 4 bit per host
- 2^4 = 16 indirizzi totali
- 16 - 2 = 14 host utilizzabili

### Classi di Indirizzi IP

#### Classe A - Large Networks

```bash
ipcalc 1.0.0.0/8
```

| Parametro | Valore |
|-----------|--------|
| **Range** | 1.0.0.0 - 126.255.255.255 |
| **CIDR** | /8 |
| **Subnet Mask** | 255.0.0.0 |
| **Host Max** | 16,777,214 |
| **Uso tipico** | ISP, grandi corporation |

#### Classe B - Medium Networks

```bash
ipcalc 128.0.0.0/16
```

| Parametro | Valore |
|-----------|--------|
| **Range** | 128.0.0.0 - 191.255.255.255 |
| **CIDR** | /16 |
| **Subnet Mask** | 255.255.0.0 |
| **Host Max** | 65,534 |
| **Uso tipico** | Università, aziende medie |

#### Classe C - Small Networks

```bash
ipcalc 192.0.0.0/24
```

| Parametro | Valore |
|-----------|--------|
| **Range** | 192.0.0.0 - 223.255.255.255 |
| **CIDR** | /24 |
| **Subnet Mask** | 255.255.255.0 |
| **Host Max** | 254 |
| **Uso tipico** | Piccole aziende, home network |

### VLSM (Variable Length Subnet Masking)

#### Esempio Pratico

**Scenario**: Azienda con diversi dipartimenti

| Dipartimento | Host Richiesti | CIDR Ottimale | Range |
|--------------|----------------|---------------|--------|
| **IT** | 50 | /26 (62 host) | 192.168.1.0/26 |
| **HR** | 20 | /27 (30 host) | 192.168.1.64/27 |
| **Finance** | 10 | /28 (14 host) | 192.168.1.96/28 |
| **Guest** | 5 | /29 (6 host) | 192.168.1.112/29 |

**Vantaggi VLSM**:
- Ottimizzazione spazio indirizzi
- Riduzione broadcast domain
- Migliore sicurezza (segregazione)

## Port Scanning

### nmap - Network Mapper

#### Installazione e Verifica

```bash
# Verifica versione
nmap -v
# Starting Nmap 7.97 ( https://nmap.org )

# Help completo
nmap --help | less
```

#### Sintassi Base

```bash
# Host singolo
nmap 192.168.1.100

# Subnet completa
nmap 192.168.1.0/24

# Lista da file
nmap -iL targets.txt

# DNS resolution
nmap www.google.com
```

#### Tipi di Scan

| Parametro | Tipo Scan | Descrizione |
|-----------|-----------|-------------|
| **-sS** | SYN Stealth | Half-open, stealth |
| **-sT** | TCP Connect | Full connection |
| **-sU** | UDP Scan | UDP ports |
| **-sN** | NULL Scan | No flags set |
| **-sF** | FIN Scan | FIN flag only |
| **-sX** | Xmas Scan | FIN+PSH+URG flags |

#### Windows 11 Target Scan

**Problema iniziale**:
```bash
nmap 192.168.130.234
# Host seems down. If it is really up, but blocking our ping probes, try -Pn
```

**Soluzione Windows Firewall**:
1. Abilitare regola: "File And Printer Sharing (Echo Request - ICMPv4-In)"
2. Oppure usare `-Pn` per saltare ping discovery

**Scan riuscito**:
```bash
nmap 192.168.130.234

PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

#### Scan Completo Stealth

```bash
sudo nmap -sS -p- -O -sV -vv -T5 192.168.130.234
```

**Parametri spiegati**:
- **-sS**: SYN stealth scan
- **-p-**: Tutte le 65535 porte
- **-O**: OS detection
- **-sV**: Service version detection
- **-vv**: Very verbose
- **-T5**: Timing template (insane speed)

**Risultati Windows 11**:
```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?    Windows Delivery Optimization
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
[... più porte RPC ...]

MAC Address: 08:00:27:10:C6:E5 (Oracle VirtualBox virtual NIC)
OS fingerprint: Microsoft Windows 10 1703 or Windows 11 21H2 (99%)
TCP Sequence Prediction: Difficulty=259 (Good luck!)
```

#### Porte ad Alto Rischio Identificate

| Porta | Servizio | Rischio | Vulnerabilità Note |
|-------|----------|---------|-------------------|
| **135** | MS-RPC | 🔴 Alto | RPC endpoint mapper |
| **139** | NetBIOS-SSN | 🟡 Medio | Legacy sharing |
| **445** | Microsoft-DS | 🔴 Critico | EternalBlue, SMBGhost |
| **7680** | Delivery Opt | 🟢 Basso | Windows Update P2P |

#### Vulnerability Scanning

```bash
# Script vulnerabilità
nmap --script=vuln 192.168.130.234
```

**Risultato Windows 11**:
```
Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
```

**Analisi**:
- **ms10-061**: Non vulnerabile (sistema aggiornato)
- **ms10-054**: Non vulnerabile
- **Errori connessione**: SMB hardening efficace

## Network Discovery

### netdiscover - ARP Scanner

#### Funzionalità Base

```bash
# Scan subnet locale
netdiscover -r 192.168.1.0/24

# Passive mode (solo listening)
netdiscover -p

# Output in file
netdiscover -r 192.168.1.0/24 > network_map.txt
```

#### Esempio Output Reale

```
Currently scanning: 192.168.0.0/16   |   Screen View: Unique Hosts

13 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 714
_____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.X.1      aa:bb:cc:11:22:33      5     280  [Firewall] Fortinet, Inc.
192.168.X.2      dd:ee:ff:44:55:66      2     112  [Smart TV] Vestel Elektronik
192.168.X.3      77:88:99:00:aa:bb      1      42  [Smart TV] Vestel Elektronik
192.168.X.4      cc:dd:ee:ff:00:11      5     280  [Dispositivo sconosciuto]
```

#### Analisi MAC Address Vendors

**Informazioni ottenute**:
- **Fortinet**: Firewall enterprise
- **Vestel**: Smart TV manufacturer
- **Dispositivo sconosciuto**: Possibile target interessante

**Security Implications**:
- Fingerprinting dispositivi di rete
- Identificazione infrastruttura critica
- Target selection per penetration testing

## ARP Spoofing & Man-in-the-Middle Attack

### Teoria del Protocollo ARP

#### Cos'è ARP (Address Resolution Protocol)
- **Funzione**: Mappa indirizzi IP → MAC address nella rete locale (LAN)
- **Meccanismo**: Quando un host vuole comunicare con un IP, invia broadcast ARP "Chi ha questo IP?"
- **Risposta**: L'host con quell'IP risponde con il suo MAC address
- **Cache**: Il MAC viene salvato nella ARP table per uso futuro

#### Vulnerabilità Intrinseche di ARP
1. **Stateless Protocol**: Nessuna verifica dell'identità
2. **Broadcast Domain**: Tutti nella LAN ricevono pacchetti ARP
3. **Cache Poisoning**: Accetta aggiornamenti ARP senza autenticazione
4. **Trust-based**: Si fida di qualsiasi risposta ARP ricevuta

### ARP Spoofing Implementation

#### Installazione Dipendenze
```bash
# Installa Scapy per Python
pip install scapy --break-system-packages

# Verifica installazione
python3 -c "import scapy.all as scapy; print('Scapy OK')"
```

#### Script ARP Spoofer

**📄 Script completo**: [`scripts/networking/mitm_spoofer.py`](../../scripts/networking/mitm_spoofer.py)

**Funzionalità principali**:
- ARP spoofing bidirezionale (target ↔ gateway)
- Intercettazione traffico HTTP in tempo reale
- Estrazione automatica credenziali da form POST
- IP forwarding e configurazione iptables automatica
- Cleanup completo all'interruzione

**Uso**:
```bash
# Sintassi base
sudo python3 scripts/networking/mitm_spoofer.py <target_ip> <gateway_ip> [interface]

# Esempio pratico
sudo python3 scripts/networking/mitm_spoofer.py 192.168.1.100 192.168.1.1 wlan0
```

### Network Discovery Pre-Attack

#### Scoprire Target e Gateway
```bash
# Identifica la tua interfaccia di rete
ip addr show

# Trova il gateway predefinito  
ip route show | grep default
# Output: default via 192.168.1.1 dev wlan0

# Scansiona la rete locale
netdiscover -r 192.168.1.0/24
# O alternativamente:
nmap -sn 192.168.1.0/24
```

### Esecuzione Attacco MITM

#### Output Attacco Reale
```
🎯 Advanced MITM ARP Spoofer v2.0
=================================
⚠️  Solo per scopi educativi e test di sicurezza

[+] Risolvendo MAC address per 192.168.x.58...
[+] MAC di 192.168.x.58 è 08:00:27:2f:36:a6
[+] Risolvendo MAC address per 192.168.x.141...
[+] MAC di 192.168.x.141 è 2a:42:c4:38:b7:66
[+] Abilitando IP forwarding...
[+] Configurando iptables...
[+] Avviando cattura pacchetti HTTP...

🎯 Iniziando MITM attack:
    Target: 192.168.x.58 (08:00:27:2f:36:a6)
    Gateway: 192.168.x.141 (2a:42:c4:38:b7:66)
    Interface: wlo1

📡 ARP spoofing attivo (modalità silenziosa)
🕵️  Monitorando traffico HTTP...

🌐 [14:30:30] HTTP GET Request
    From: 192.168.x.58 → To: 146.190.62.39
    URL: http://httpforever.com/

📡 [14:30:30] HTTP Response
    From: 146.190.62.39 → To: 192.168.x.58
    Status: 200

🌐 [14:30:31] HTTP POST Request
    From: 192.168.x.58 → To: 216.58.205.35
    URL: http://o.pki.goog/wr2
    POST Data: 0R0P0N0L0J0...

📊 Pacchetti ARP inviati: 150+ | Dati intercettati: 25
```

### Risultati e Implicazioni

#### Traffico Intercettato con Successo
- **HTTP GET Requests**: Tutti i siti web visitati
- **HTTP POST Requests**: Dati di form, login, ricerche
- **Response Status**: 200 (OK), 304 (Not Modified)
- **Invisibilità Completa**: Vittima ignara dell'attacco

#### Dati Sensibili Intercettabili
1. **Credenziali HTTP**: Username/password in chiaro
2. **Session Cookies**: Per session hijacking
3. **Dati Personali**: Form submissions, ricerche  
4. **File Downloads**: Modificabili in tempo reale
5. **DNS Queries**: Domini visitati

#### Limitazioni dell'Attacco
- **HTTPS Traffic**: Protetto da crittografia (solo metadata visibili)
- **HSTS Sites**: HTTP Strict Transport Security impedisce downgrade
- **Certificate Pinning**: App mobili con pinning resistono a MITM

### Protezioni Anti-ARP Spoofing

#### Configurazioni Difensive
```bash
# Static ARP entries (impedisce spoofing del gateway)
sudo arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff

# Monitoring ARP anomalies
arp-scan -l | grep "DUP"  # Cerca duplicati sospetti

# ARP table monitoring
watch -n 5 'arp -a'  # Monitora cambiamenti ARP

# Network monitoring con tcpdump
sudo tcpdump -i wlan0 arp and ether src aa:bb:cc:dd:ee:ff
```

#### Network Hardening
```bash
# Enable ARP filtering (Linux)
echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter

# DHCP snooping (managed switches)
# Port security con MAC address binding
# VLAN segmentation per isolare traffico critico
```

### Lezioni di Sicurezza Apprese

#### Riflessione sull'Attacco
> **"Oggi ho capito davvero cosa significa 'man in the middle'"**
> 
> Non è solo teoria - è una cosa che funziona davvero e fa paura quanto sia semplice. Con poche righe di Python sono riuscito a mettermi nel mezzo delle comunicazioni di una macchina senza che se ne accorgesse minimamente.
> 
> La vittima navigava tranquilla su httpforever.com mentre io vedevo tutto il suo traffico HTTP passarmi davanti agli occhi. **L'invisibilità dell'attacco è la cosa più spaventosa** - nessun rallentamento, errore o avviso.

#### Vulnerabilità Fondamentale di ARP
- **Design Flaw**: ARP si basa sulla "fiducia cieca"
- **Analogia**: Come gridare "sono il postino" e tutti ti danno le lettere senza verifica
- **Impatto**: Rende insicura ogni rete locale non hardened

#### Importanza di HTTPS
- **Unica Protezione Reale**: Solo HTTPS protegge i dati in MITM
- **Educazione**: La maggior parte degli utenti non capisce la differenza HTTP/HTTPS
- **Responsibility**: Sviluppatori devono forzare HTTPS sempre

### ARP Spoofing Detection

#### Monitoring ARP Table

```bash
# ARP table corrente
arp -a
# gateway (192.168.1.1) at aa:bb:cc:11:22:33 [ether] on eth0

# Monitoring continuo
watch -n 1 'arp -a'

# Log ARP changes
tcpdump -i eth0 arp > arp_monitoring.log
```

#### Rilevazione Anomalie

**Indicatori di ARP spoofing**:
- MAC address duplicati per IP diversi
- Cambi frequenti MAC per stesso IP
- MAC vendor inconsistenti con dispositivo atteso

## Protocol Vulnerabilities

### DNS Analysis

#### DNS Query Types Identificati

```bash
# Monitor DNS queries
sudo tcpdump -i any port 53
```

**Query types osservati**:
- **A**: IPv4 address lookup
- **AAAA**: IPv6 address lookup
- **PTR**: Reverse DNS lookup
- **MX**: Mail exchange records

#### DNS Security Issues

**Vulnerabilities identificate**:
- **DNS poisoning**: Possible con DNS non autenticato
- **DNS tunneling**: Possibile data exfiltration
- **Information disclosure**: Query pattern analysis

### ARP Protocol Weaknesses

#### ARP Spoofing Potential

**Vulnerabilità ARP**:
- Nessuna autenticazione
- Broadcast-based
- Last response wins

**Test spoofing (ambiente controllato)**:
```bash
# Invio ARP gratuito falso
arping -c 1 -A -I eth0 192.168.1.1
echo "Sent gratuitous ARP for gateway"
```

### Legacy Protocol Risks

#### NetBIOS/SMB Analysis

**Porte legacy identificate**:
- **137/udp**: NetBIOS Name Service
- **138/udp**: NetBIOS Datagram Service  
- **139/tcp**: NetBIOS Session Service
- **445/tcp**: SMB over TCP

**Rischi associati**:
- Information disclosure (null sessions)
- Brute force attacks
- Pass-the-hash attacks
- Relay attacks

## Best Practices

### Network Monitoring

#### Continuous Packet Capture

**📄 Script completo**: [`scripts/networking/network_monitor.sh`](../../scripts/networking/network_monitor.sh)

```bash
#!/bin/bash
# Script monitoring rete continuo
INTERFACE="eth0"
CAPTURE_DIR="/var/log/network"
ROTATION_SIZE="100M"

# Rotazione automatica
tcpdump -i $INTERFACE -C $ROTATION_SIZE -W 10 -w $CAPTURE_DIR/capture.pcap
```

#### Anomaly Detection

**📄 Script completo**: [`scripts/networking/scan_detection.sh`](../../scripts/networking/scan_detection.sh)

**Funzionalità**:
- Monitoring SYN packets anomali
- Alert automatici per possibili port scan
- Logging centralizzato
- Email notifications

### Defensive Measures

#### Port Hardening

```bash
# Chiusura porte non necessarie
sudo ufw deny 135
sudo ufw deny 139
sudo ufw deny 445

# Rate limiting per SSH
sudo ufw limit ssh

# Log delle connessioni negate
sudo ufw logging on
```

#### Network Segmentation

```bash
# VLAN configuration esempio
# VLAN 10: Management
# VLAN 20: Users  
# VLAN 30: Servers
# VLAN 99: DMZ

# iptables rules tra VLAN
iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.20.0/24 -j DROP
iptables -A FORWARD -s 192.168.20.0/24 -d 192.168.30.0/24 -p tcp --dport 80,443 -j ACCEPT
```

### Offensive Reconnaissance

#### Target Enumeration

**📄 Script completo**: [`scripts/networking/reconnaissance.sh`](../../scripts/networking/reconnaissance.sh)

**Funzionalità**:
- Host discovery automatizzato
- Port scanning parallelo
- Service enumeration
- Vulnerability assessment
- Report generation

**Uso**:
```bash
# Reconnaissance completo di una rete
./scripts/networking/reconnaissance.sh 192.168.1.0/24

# Output generato:
# - live_hosts.txt
# - scan_[IP].txt per ogni host
# - detailed_scan.txt
# - vuln_scan.txt
```

#### Stealth Techniques

```bash
# Scan stealth con timing random
nmap -sS -T1 --randomize-hosts target_network

# Decoy scanning
nmap -D RND:10 target_host

# Fragment packets
nmap -f target_host

# Source port spoofing
nmap --source-port 53 target_host
```

### Performance Optimization

#### Large Network Scanning

```bash
# Scan parallelo per grandi reti
echo "192.168.0.0/16" | masscan -p80,443,22,21,25,53,110,995,993,143 --rate=1000
```

#### Traffic Analysis Optimization

```bash
# Buffer size optimization per tcpdump
tcpdump -B 4096 -i any -w capture.pcap

# Ring buffer per continuous capture
tcpdump -i any -C 100 -W 50 -w rotating_capture.pcap
```

### Advanced Monitoring Techniques

#### Real-time Traffic Analysis

**📄 Script completo**: [`scripts/networking/traffic_analyzer.py`](../../scripts/networking/traffic_analyzer.py)

**Funzionalità**:
- Real-time packet analysis
- Protocol distribution statistics
- Anomaly detection algorithms
- Automated threat identification
- Dashboard generation

#### Network Baseline Creation

**📄 Script completo**: [`scripts/networking/network_baseline.sh`](../../scripts/networking/network_baseline.sh)

```bash
# Crea baseline del traffico normale
./scripts/networking/network_baseline.sh

# Genera:
# - normal_traffic_patterns.json
# - baseline_metrics.txt
# - protocol_distribution.csv
```

### Incident Response

#### Network Forensics

**📄 Script completo**: [`scripts/networking/network_forensics.sh`](../../scripts/networking/network_forensics.sh)

**Capabilities**:
- Automatic evidence collection
- Timeline reconstruction
- IOC (Indicators of Compromise) extraction
- Report generation for legal purposes

#### Emergency Response Procedures

```bash
# Isolamento immediato host compromesso
iptables -A INPUT -s [COMPROMISED_IP] -j DROP
iptables -A OUTPUT -d [COMPROMISED_IP] -j DROP

# Cattura traffico per analisi
tcpdump -i any -w incident_$(date +%Y%m%d_%H%M%S).pcap host [COMPROMISED_IP]

# Backup configurazioni critiche
cp /etc/iptables/rules.v4 /backup/iptables_backup_$(date +%Y%m%d)
```

### Commands Reference Quick

```bash
# Network discovery
ip route show | grep default
netdiscover -r 192.168.1.0/24
nmap -sn 192.168.1.0/24

# ARP table inspection  
arp -a
arp -s <ip> <mac>  # Static entry
watch -n 5 'arp -a'  # Monitoring

# Traffic monitoring
sudo tcpdump -i wlan0 arp
sudo tcpdump -i wlan0 'tcp port 80'
sudo tshark -i interface

# MITM Attack
sudo python3 scripts/networking/mitm_spoofer.py <target> <gateway>

# Port scanning
nmap -sS -p- -O -sV target
nmap --script=vuln target
nmap -sS -T1 --randomize-hosts target  # Stealth

# Packet analysis
tshark -r capture.pcap
tcpdump -r capture.pcap 'filter'

# Network monitoring
./scripts/networking/network_monitor.sh
./scripts/networking/scan_detection.sh

# Reconnaissance
./scripts/networking/reconnaissance.sh 192.168.1.0/24

# Forensics
./scripts/networking/network_forensics.sh
```

### Security Assessment Checklist

#### Pre-Assessment Phase
- [ ] Obtain proper authorization
- [ ] Define scope and limitations
- [ ] Prepare isolated test environment
- [ ] Backup critical configurations
- [ ] Establish communication protocols

#### Discovery Phase
- [ ] Network topology mapping
- [ ] Host enumeration (netdiscover/nmap)
- [ ] Service identification
- [ ] OS fingerprinting
- [ ] Vulnerability assessment

#### Testing Phase
- [ ] ARP spoofing feasibility
- [ ] MITM attack simulation
- [ ] Traffic interception verification
- [ ] Protocol vulnerability testing
- [ ] Evasion technique validation

#### Documentation Phase
- [ ] Detailed methodology documentation
- [ ] Evidence collection and preservation
- [ ] Risk assessment and impact analysis
- [ ] Remediation recommendations
- [ ] Executive summary preparation

### Remediation Strategies

#### Network Hardening

**Immediate Actions**:
```bash
# Disable unused network services
systemctl disable telnet
systemctl disable ftp
systemctl disable rsh

# Enable secure protocols only
systemctl enable ssh
systemctl enable https

# Configure firewall rules
ufw enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw limit ssh
```

**Long-term Solutions**:
- Network segmentation with VLANs
- Implement network access control (NAC)
- Deploy intrusion detection systems (IDS)
- Regular security assessments
- Staff security awareness training

#### Monitoring Implementation

**📄 Configuration files**: [`configs/networking/`](../../configs/networking/)

**Includes**:
- `iptables_secure.rules` - Hardened firewall configuration
- `snort.conf` - IDS configuration
- `rsyslog_network.conf` - Centralized logging
- `nagios_network.cfg` - Network monitoring

### Legal and Ethical Considerations

#### Important Disclaimers

**⚠️ LEGAL WARNING**: 
- Use these techniques ONLY on networks you own or have explicit written permission to test
- Unauthorized network attacks are illegal in most jurisdictions
- Always follow responsible disclosure practices
- Document all testing activities for legal protection

#### Ethical Guidelines

**Best Practices**:
- Obtain proper authorization before testing
- Minimize impact on production systems
- Protect confidentiality of discovered information
- Provide constructive remediation guidance
- Follow industry ethical standards (EC-Council, SANS, etc.)

#### Compliance Considerations

**Regulatory Frameworks**:
- GDPR: Data protection during network testing
- HIPAA: Healthcare network security requirements
- PCI DSS: Payment card industry standards
- SOX: Financial data protection requirements

---

**Conclusioni Networking e Sicurezza**:

### Key Takeaways

1. **ARP Vulnerability is Fundamental**: Il protocollo ARP rimane intrinsecamente insicuro per design, rendendo ogni rete locale potenzialmente vulnerabile a MITM attacks.

2. **HTTPS è l'Unica Protezione Reale**: Contro attacchi MITM, solo HTTPS fornisce protezione effettiva dei dati in transito.

3. **Invisibilità degli Attacchi**: Gli attacchi ARP spoofing sono completamente invisibili alle vittime, rendendo la detection proattiva essenziale.

4. **Windows 11 Security Improvements**: Le versioni moderne di Windows mostrano significativi miglioramenti nella security posture rispetto alle versioni precedenti.

5. **Network Monitoring è Critico**: Il monitoraggio continuo del traffico di rete è essenziale per early warning e incident response.

6. **Defense in Depth**: Nessuna singola tecnologia di sicurezza è sufficiente; serve un approccio stratificato.

### Lessons Learned

**Technical Insights**:
- Port scanning rimane una tecnica fondamentale di reconnaissance
- La comprensione dei protocolli è essenziale per identificare vulnerabilità
- Network segmentation e monitoring continuo sono pilastri della difesa
- L'automazione degli assessment accelera significativamente il processo

**Security Implications**:
- Le reti locali non sono intrinsecamente sicure
- L'educazione degli utenti su HTTPS è cruciale
- La visibility del traffico di rete è fondamentale per la sicurezza
- Gli attacchi moderni richiedono tecniche di detection sofisticate

**Operational Impact**:
- Gli strumenti open source sono potenti quanto le soluzioni commerciali
- La documentazione dettagliata è essenziale per incident response
- L'approccio systematico supera sempre gli attacchi "spray and pray"
- La collaboration tra team offensivi e difensivi migliora la security posture complessiva

### Future Research Directions

**Areas of Interest**:
- IoT device security in modern networks
- AI/ML-based network anomaly detection
- Zero-trust network architecture implementation
- Advanced persistent threat (APT) detection techniques
- Container and cloud network security

**Tool Development**:
- Enhanced MITM detection algorithms
- Automated vulnerability assessment frameworks
- Real-time network visualization tools
- Integrated threat intelligence platforms

---

**Repository Structure for Scripts**:
```
scripts/networking/
├── mitm_spoofer.py           # Advanced MITM ARP Spoofer
├── network_monitor.sh        # Continuous packet capture
├── scan_detection.sh         # Anomaly detection
├── reconnaissance.sh         # Automated target enumeration
├── traffic_analyzer.py       # Real-time traffic analysis
├── network_baseline.sh       # Baseline creation
└── network_forensics.sh      # Incident response forensics

configs/networking/
├── iptables_secure.rules     # Hardened firewall configuration
├── snort.conf               # IDS configuration
├── rsyslog_network.conf     # Centralized logging
└── nagios_network.cfg       # Network monitoring
```

Questa documentazione rappresenta un percorso completo attraverso le tecniche moderne di network security assessment, bilanciando aspetti offensivi e difensivi con un forte focus sull'etica e sulla legalità.
[← Linux Security](../linux-security/README.md) | [Defensive Security →](../defensive-security/README.md)# Networking e Sicurezza - Documentazione Completa

Documentazione tecnica completa su networking, analisi protocolli, packet capture e attack vectors. Include analisi pratica di traffico di rete, ARP spoofing, MITM attacks e tecniche di reconnaissance con tools professionali.

## Indice

- [Packet Analysis](#packet-analysis)
- [Three-Way Handshake](#three-way-handshake)
- [Subnetting](#subnetting)
- [Port Scanning](#port-scanning)
- [Network Discovery](#network-discovery)
- [ARP Spoofing & Man-in-the-Middle Attack](#arp-spoofing--man-in-the-middle-attack)
- [Protocol Vulnerabilities](#protocol-vulnerabilities)
- [Best Practices](#best-practices)

## Packet Analysis

### tshark - Network Protocol Analyzer

#### Setup e Configurazione

```bash
# Verifica installazione
tshark -v
# TShark (Wireshark) 3.6.2

# Lista interfacce disponibili
tshark -D
# 1. eth0
# 2. wlan0
# 3. lo (Loopback)
```

#### Cattura Base

```bash
# Cattura tutto il traffico
sudo tshark

# Cattura su interfaccia specifica
sudo tshark -i wlan0

# Salvataggio in file
sudo tshark -w capture.pcap

# Lettura da file
tshark -r capture.pcap
```

#### Esempio Traffico Catturato (176 pacchetti)

```
146 10.527487448 192.168.x.x → 192.168.130.187 DNS 76 Standard query 0x0a89 A ping.manjaro.org
147 10.527501668 192.168.x.x → 192.168.130.187 DNS 76 Standard query 0xcab7 AAAA ping.manjaro.org
148 10.530278726 192.168.130.187 → 192.168.x.x DNS 92 Standard query response 0x0a89 A ping.manjaro.org A 116.203.91.91
149 10.530517532 192.168.130.187 → 192.168.x.x DNS 104 Standard query response 0xcab7 AAAA ping.manjaro.org AAAA 2a01:4f8:c0c:51f3::1
150 12.360664754 [MAC_1] → [MAC_2] ARP 42 Who has 192.168.x.x? Tell 192.168.130.187
151 12.360679494 [MAC_2] → [MAC_1] ARP 42 192.168.x.x is at [MAC_2]
152 16.555285247 192.168.x.x → 18.97.36.75 TLSv1.2 307 Application Data
153 16.579458804 192.168.x.x → 239.255.255.250 SSDP 210 M-SEARCH * HTTP/1.1
```

#### Analisi Traffico Identificato

**DNS Queries**:
- **A record** (IPv4): ping.manjaro.org → 116.203.91.91
- **AAAA record** (IPv6): ping.manjaro.org → 2a01:4f8:c0c:51f3::1
- **Funzione**: Risoluzione nomi di dominio

**ARP (Address Resolution Protocol)**:
- **Scopo**: Mappatura IP → MAC address
- **Rete locale**: 192.168.x.x discovery
- **Frequenza**: Ogni pochi secondi per host attivi

**SSDP (Simple Service Discovery Protocol)**:
- **IP multicast**: 239.255.255.250
- **Protocollo**: HTTP-like su UDP
- **Funzione**: Scoperta dispositivi UPnP

**TLS Traffic**:
- **Versione**: TLSv1.2
- **Porte**: 443 (HTTPS)
- **Data**: Application Data encrypted

### tcpdump - Command Line Packet Analyzer

#### Sintassi Base

```bash
# Cattura base
sudo tcpdump

# Interfaccia specifica
sudo tcpdump -i eth0

# Host specifico
sudo tcpdump host 8.8.8.8

# Porta specifica
sudo tcpdump port 80

# Protocollo specifico
sudo tcpdump tcp
```

#### Filtri Avanzati

```bash
# TCP traffico verso Google
sudo tcpdump -i any -n -v 'tcp and host google.com'

# Parametri spiegati:
# -i any     = tutte le interfacce
# -n         = no DNS resolution
# -v         = verbose mode
# 'tcp and host google.com' = filtro BPF
```

#### Test Pratico con Google

**Trigger**: `curl -I http://google.com`

**Output catturato**:
```
10:18:35.954106 enpX Out IP 192.168.x.x.59416 > 216.58.x.x.80: Flags [S], seq [...], length 0
10:18:36.001373 enpX In  IP 216.58.x.x.80 > 192.168.x.x.59416: Flags [S.], seq [...], ack [...], length 0
10:18:36.001385 enpX Out IP 192.168.x.x.59416 > 216.58.x.x.80: Flags [.], ack 1, length 0

10:18:36.001409 enpX Out IP 192.168.x.x.59416 > 216.58.x.x.80: Flags [P.], length 75: HTTP
    HEAD / HTTP/1.1
    Host: google.com
    User-Agent: curl/8.14.1
    Accept: */*

10:18:36.134911 enpX In  IP 216.58.x.x.80 > 192.168.x.x.59416: Flags [P.], length 554: HTTP
    HTTP/1.1 301 Moved Permanently
    Location: http://www.google.com/
    Content-Type: text/html; charset=UTF-8
    Server: gws
```

#### Analisi Dettagliata

**Timing Analysis**:
- **Latenza**: ~47ms verso Google
- **RTT**: Round-trip time accettabile
- **Possibile vulnerability**: SYN flood (porte client predicibili)

**Flag TCP**:
- **[S]**: SYN (sincronizzazione)
- **[S.]**: SYN-ACK (sincronizzazione + acknowledgment)
- **[.]**: ACK (acknowledgment)
- **[P.]**: PSH (push data immediately)
- **[F.]**: FIN (fine connessione)

**User-Agent Disclosure**:
- **curl/8.14.1**: Versione software esposta
- **Rischio**: Fingerprinting e vulnerability targeting

**Security Headers Missing**:
- **X-XSS-Protection**: 0 (disabled)
- **Potenziale vulnerability**: XSS attacks

## Three-Way Handshake

### Concetti Base

Il three-way handshake è il processo di stabilimento connessione TCP.

**Fasi**:
1. **Client → Server**: SYN (synchronize)
2. **Server → Client**: SYN-ACK (synchronize-acknowledge)
3. **Client → Server**: ACK (acknowledge)

### Cattura Handshake

#### Setup tcpdump per Handshake

```bash
# Filtro per catturare solo SYN/ACK flags
sudo tcpdump -i interface 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'

# Parametri spiegati:
# tcp[tcpflags]           = byte dei flag TCP
# tcp-syn|tcp-ack         = flag SYN o ACK
# != 0                    = almeno uno dei flag settato
```

#### Test con telnet

```bash
# Trigger handshake
telnet example.com 80
```

#### Risultato Catturato

```
11:01:40.925898 IP [CLIENT] > [SERVER]: Flags [S], seq ..., win ..., length 0
11:01:41.141589 IP [SERVER] > [CLIENT]: Flags [S.], seq ..., ack ..., length 0
11:01:41.141604 IP [CLIENT] > [SERVER]: Flags [.], ack ..., length 0
```

### Analisi Sequenza Numbers

**Dettagli tecnici**:
```
1. Client → Server: SYN (seq=X, flags=S)
2. Server → Client: SYN-ACK (seq=Y, ack=X+1, flags=SA)
3. Client → Server: ACK (seq=X+1, ack=Y+1, flags=A)
```

**Security Implications**:
- **Sequence prediction**: Difficoltà 259 (alta sicurezza)
- **SYN flood attack**: Possibile saturare half-open connections
- **RST injection**: Possibile se sequence numbers predicibili

## Subnetting

### Concetti Base

La subnet mask definisce quanti host sono disponibili in una rete.

**Formula**: Host disponibili = 2^(32-CIDR) - 2
- **-2**: Network address e Broadcast address non utilizzabili

### ipcalc - Network Calculator

#### Rete Standard /24

```bash
ipcalc 192.168.1.0/24
```

**Output**:
```
Address:   192.168.1.0          11000000.10101000.00000001. 00000000
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
=>
Network:   192.168.1.0/24       11000000.10101000.00000001. 00000000
HostMin:   192.168.1.1          11000000.10101000.00000001. 00000001
HostMax:   192.168.1.254        11000000.10101000.00000001. 11111110
Broadcast: 192.168.1.255        11000000.10101000.00000001. 11111111
Hosts/Net: 254                   Class C, Private Internet
```

#### Rete Piccola /28

```bash
ipcalc 192.168.1.0/28
```

**Output**:
```
Address:   192.168.1.0          11000000.10101000.00000001.0000 0000
Netmask:   255.255.255.240 = 28 11111111.11111111.11111111.1111 0000
Wildcard:  0.0.0.15             00000000.00000000.00000000.0000 1111
=>
Network:   192.168.1.0/28       11000000.10101000.00000001.0000 0000
HostMin:   192.168.1.1          11000000.10101000.00000001.0000 0001
HostMax:   192.168.1.14         11000000.10101000.00000001.0000 1110
Broadcast: 192.168.1.15         11000000.10101000.00000001.0000 1111
Hosts/Net: 14                    Class C, Private Internet
```

**Calcolo manuale /28**:
- 32 - 28 = 4 bit per host
- 2^4 = 16 indirizzi totali
- 16 - 2 = 14 host utilizzabili

### Classi di Indirizzi IP

#### Classe A - Large Networks

```bash
ipcalc 1.0.0.0/8
```

| Parametro | Valore |
|-----------|--------|
| **Range** | 1.0.0.0 - 126.255.255.255 |
| **CIDR** | /8 |
| **Subnet Mask** | 255.0.0.0 |
| **Host Max** | 16,777,214 |
| **Uso tipico** | ISP, grandi corporation |

#### Classe B - Medium Networks

```bash
ipcalc 128.0.0.0/16
```

| Parametro | Valore |
|-----------|--------|
| **Range** | 128.0.0.0 - 191.255.255.255 |
| **CIDR** | /16 |
| **Subnet Mask** | 255.255.0.0 |
| **Host Max** | 65,534 |
| **Uso tipico** | Università, aziende medie |

#### Classe C - Small Networks

```bash
ipcalc 192.0.0.0/24
```

| Parametro | Valore |
|-----------|--------|
| **Range** | 192.0.0.0 - 223.255.255.255 |
| **CIDR** | /24 |
| **Subnet Mask** | 255.255.255.0 |
| **Host Max** | 254 |
| **Uso tipico** | Piccole aziende, home network |

### VLSM (Variable Length Subnet Masking)

#### Esempio Pratico

**Scenario**: Azienda con diversi dipartimenti

| Dipartimento | Host Richiesti | CIDR Ottimale | Range |
|--------------|----------------|---------------|--------|
| **IT** | 50 | /26 (62 host) | 192.168.1.0/26 |
| **HR** | 20 | /27 (30 host) | 192.168.1.64/27 |
| **Finance** | 10 | /28 (14 host) | 192.168.1.96/28 |
| **Guest** | 5 | /29 (6 host) | 192.168.1.112/29 |

**Vantaggi VLSM**:
- Ottimizzazione spazio indirizzi
- Riduzione broadcast domain
- Migliore sicurezza (segregazione)

## Port Scanning

### nmap - Network Mapper

#### Installazione e Verifica

```bash
# Verifica versione
nmap -v
# Starting Nmap 7.97 ( https://nmap.org )

# Help completo
nmap --help | less
```

#### Sintassi Base

```bash
# Host singolo
nmap 192.168.1.100

# Subnet completa
nmap 192.168.1.0/24

# Lista da file
nmap -iL targets.txt

# DNS resolution
nmap www.google.com
```

#### Tipi di Scan

| Parametro | Tipo Scan | Descrizione |
|-----------|-----------|-------------|
| **-sS** | SYN Stealth | Half-open, stealth |
| **-sT** | TCP Connect | Full connection |
| **-sU** | UDP Scan | UDP ports |
| **-sN** | NULL Scan | No flags set |
| **-sF** | FIN Scan | FIN flag only |
| **-sX** | Xmas Scan | FIN+PSH+URG flags |

#### Windows 11 Target Scan

**Problema iniziale**:
```bash
nmap 192.168.130.234
# Host seems down. If it is really up, but blocking our ping probes, try -Pn
```

**Soluzione Windows Firewall**:
1. Abilitare regola: "File And Printer Sharing (Echo Request - ICMPv4-In)"
2. Oppure usare `-Pn` per saltare ping discovery

**Scan riuscito**:
```bash
nmap 192.168.130.234

PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

#### Scan Completo Stealth

```bash
sudo nmap -sS -p- -O -sV -vv -T5 192.168.130.234
```

**Parametri spiegati**:
- **-sS**: SYN stealth scan
- **-p-**: Tutte le 65535 porte
- **-O**: OS detection
- **-sV**: Service version detection
- **-vv**: Very verbose
- **-T5**: Timing template (insane speed)

**Risultati Windows 11**:
```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?    Windows Delivery Optimization
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
[... più porte RPC ...]

MAC Address: 08:00:27:10:C6:E5 (Oracle VirtualBox virtual NIC)
OS fingerprint: Microsoft Windows 10 1703 or Windows 11 21H2 (99%)
TCP Sequence Prediction: Difficulty=259 (Good luck!)
```

#### Porte ad Alto Rischio Identificate

| Porta | Servizio | Rischio | Vulnerabilità Note |
|-------|----------|---------|-------------------|
| **135** | MS-RPC | 🔴 Alto | RPC endpoint mapper |
| **139** | NetBIOS-SSN | 🟡 Medio | Legacy sharing |
| **445** | Microsoft-DS | 🔴 Critico | EternalBlue, SMBGhost |
| **7680** | Delivery Opt | 🟢 Basso | Windows Update P2P |

#### Vulnerability Scanning

```bash
# Script vulnerabilità
nmap --script=vuln 192.168.130.234
```

**Risultato Windows 11**:
```
Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
```

**Analisi**:
- **ms10-061**: Non vulnerabile (sistema aggiornato)
- **ms10-054**: Non vulnerabile
- **Errori connessione**: SMB hardening efficace

## Network Discovery

### netdiscover - ARP Scanner

#### Funzionalità Base

```bash
# Scan subnet locale
netdiscover -r 192.168.1.0/24

# Passive mode (solo listening)
netdiscover -p

# Output in file
netdiscover -r 192.168.1.0/24 > network_map.txt
```

#### Esempio Output Reale

```
Currently scanning: 192.168.0.0/16   |   Screen View: Unique Hosts

13 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 714
_____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.X.1      aa:bb:cc:11:22:33      5     280  [Firewall] Fortinet, Inc.
192.168.X.2      dd:ee:ff:44:55:66      2     112  [Smart TV] Vestel Elektronik
192.168.X.3      77:88:99:00:aa:bb      1      42  [Smart TV] Vestel Elektronik
192.168.X.4      cc:dd:ee:ff:00:11      5     280  [Dispositivo sconosciuto]
```

#### Analisi MAC Address Vendors

**Informazioni ottenute**:
- **Fortinet**: Firewall enterprise
- **Vestel**: Smart TV manufacturer
- **Dispositivo sconosciuto**: Possibile target interessante

**Security Implications**:
- Fingerprinting dispositivi di rete
- Identificazione infrastruttura critica
- Target selection per penetration testing

## ARP Spoofing & Man-in-the-Middle Attack

### Teoria del Protocollo ARP

#### Cos'è ARP (Address Resolution Protocol)
- **Funzione**: Mappa indirizzi IP → MAC address nella rete locale (LAN)
- **Meccanismo**: Quando un host vuole comunicare con un IP, invia broadcast ARP "Chi ha questo IP?"
- **Risposta**: L'host con quell'IP risponde con il suo MAC address
- **Cache**: Il MAC viene salvato nella ARP table per uso futuro

#### Vulnerabilità Intrinseche di ARP
1. **Stateless Protocol**: Nessuna verifica dell'identità
2. **Broadcast Domain**: Tutti nella LAN ricevono pacchetti ARP
3. **Cache Poisoning**: Accetta aggiornamenti ARP senza autenticazione
4. **Trust-based**: Si fida di qualsiasi risposta ARP ricevuta

### ARP Spoofing Implementation

#### Installazione Dipendenze
```bash
# Installa Scapy per Python
pip install scapy --break-system-packages

# Verifica installazione
python3 -c "import scapy.all as scapy; print('Scapy OK')"
```

#### Script ARP Spoofer

**📄 Script completo**: [`scripts/networking/mitm_spoofer.py`](../../scripts/networking/mitm_spoofer.py)

**Funzionalità principali**:
- ARP spoofing bidirezionale (target ↔ gateway)
- Intercettazione traffico HTTP in tempo reale
- Estrazione automatica credenziali da form POST
- IP forwarding e configurazione iptables automatica
- Cleanup completo all'interruzione

**Uso**:
```bash
# Sintassi base
sudo python3 scripts/networking/mitm_spoofer.py <target_ip> <gateway_ip> [interface]

# Esempio pratico
sudo python3 scripts/networking/mitm_spoofer.py 192.168.1.100 192.168.1.1 wlan0
```

### Network Discovery Pre-Attack

#### Scoprire Target e Gateway
```bash
# Identifica la tua interfaccia di rete
ip addr show

# Trova il gateway predefinito  
ip route show | grep default
# Output: default via 192.168.1.1 dev wlan0

# Scansiona la rete locale
netdiscover -r 192.168.1.0/24
# O alternativamente:
nmap -sn 192.168.1.0/24
```

### Esecuzione Attacco MITM

#### Output Attacco Reale
```
🎯 Advanced MITM ARP Spoofer v2.0
=================================
⚠️  Solo per scopi educativi e test di sicurezza

[+] Risolvendo MAC address per 192.168.x.58...
[+] MAC di 192.168.x.58 è 08:00:27:2f:36:a6
[+] Risolvendo MAC address per 192.168.x.141...
[+] MAC di 192.168.x.141 è 2a:42:c4:38:b7:66
[+] Abilitando IP forwarding...
[+] Configurando iptables...
[+] Avviando cattura pacchetti HTTP...

🎯 Iniziando MITM attack:
    Target: 192.168.x.58 (08:00:27:2f:36:a6)
    Gateway: 192.168.x.141 (2a:42:c4:38:b7:66)
    Interface: wlo1

📡 ARP spoofing attivo (modalità silenziosa)
🕵️  Monitorando traffico HTTP...

🌐 [14:30:30] HTTP GET Request
    From: 192.168.x.58 → To: 146.190.62.39
    URL: http://httpforever.com/

📡 [14:30:30] HTTP Response
    From: 146.190.62.39 → To: 192.168.x.58
    Status: 200

🌐 [14:30:31] HTTP POST Request
    From: 192.168.x.58 → To: 216.58.205.35
    URL: http://o.pki.goog/wr2
    POST Data: 0R0P0N0L0J0...

📊 Pacchetti ARP inviati: 150+ | Dati intercettati: 25
```

### Risultati e Implicazioni

#### Traffico Intercettato con Successo
- **HTTP GET Requests**: Tutti i siti web visitati
- **HTTP POST Requests**: Dati di form, login, ricerche
- **Response Status**: 200 (OK), 304 (Not Modified)
- **Invisibilità Completa**: Vittima ignara dell'attacco

#### Dati Sensibili Intercettabili
1. **Credenziali HTTP**: Username/password in chiaro
2. **Session Cookies**: Per session hijacking
3. **Dati Personali**: Form submissions, ricerche  
4. **File Downloads**: Modificabili in tempo reale
5. **DNS Queries**: Domini visitati

#### Limitazioni dell'Attacco
- **HTTPS Traffic**: Protetto da crittografia (solo metadata visibili)
- **HSTS Sites**: HTTP Strict Transport Security impedisce downgrade
- **Certificate Pinning**: App mobili con pinning resistono a MITM

### Protezioni Anti-ARP Spoofing

#### Configurazioni Difensive
```bash
# Static ARP entries (impedisce spoofing del gateway)
sudo arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff

# Monitoring ARP anomalies
arp-scan -l | grep "DUP"  # Cerca duplicati sospetti

# ARP table monitoring
watch -n 5 'arp -a'  # Monitora cambiamenti ARP

# Network monitoring con tcpdump
sudo tcpdump -i wlan0 arp and ether src aa:bb:cc:dd:ee:ff
```

#### Network Hardening
```bash
# Enable ARP filtering (Linux)
echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter

# DHCP snooping (managed switches)
# Port security con MAC address binding
# VLAN segmentation per isolare traffico critico
```

### Lezioni di Sicurezza Apprese

#### Riflessione sull'Attacco
> **"Oggi ho capito davvero cosa significa 'man in the middle'"**
> 
> Non è solo teoria - è una cosa che funziona davvero e fa paura quanto sia semplice. Con poche righe di Python sono riuscito a mettermi nel mezzo delle comunicazioni di una macchina senza che se ne accorgesse minimamente.
> 
> La vittima navigava tranquilla su httpforever.com mentre io vedevo tutto il suo traffico HTTP passarmi davanti agli occhi. **L'invisibilità dell'attacco è la cosa più spaventosa** - nessun rallentamento, errore o avviso.

#### Vulnerabilità Fondamentale di ARP
- **Design Flaw**: ARP si basa sulla "fiducia cieca"
- **Analogia**: Come gridare "sono il postino" e tutti ti danno le lettere senza verifica
- **Impatto**: Rende insicura ogni rete locale non hardened

#### Importanza di HTTPS
- **Unica Protezione Reale**: Solo HTTPS protegge i dati in MITM
- **Educazione**: La maggior parte degli utenti non capisce la differenza HTTP/HTTPS
- **Responsibility**: Sviluppatori devono forzare HTTPS sempre

### ARP Spoofing Detection

#### Monitoring ARP Table

```bash
# ARP table corrente
arp -a
# gateway (192.168.1.1) at aa:bb:cc:11:22:33 [ether] on eth0

# Monitoring continuo
watch -n 1 'arp -a'

# Log ARP changes
tcpdump -i eth0 arp > arp_monitoring.log
```

#### Rilevazione Anomalie

**Indicatori di ARP spoofing**:
- MAC address duplicati per IP diversi
- Cambi frequenti MAC per stesso IP
- MAC vendor inconsistenti con dispositivo atteso

## Protocol Vulnerabilities

### DNS Analysis

#### DNS Query Types Identificati

```bash
# Monitor DNS queries
sudo tcpdump -i any port 53
```

**Query types osservati**:
- **A**: IPv4 address lookup
- **AAAA**: IPv6 address lookup
- **PTR**: Reverse DNS lookup
- **MX**: Mail exchange records

#### DNS Security Issues

**Vulnerabilities identificate**:
- **DNS poisoning**: Possible con DNS non autenticato
- **DNS tunneling**: Possibile data exfiltration
- **Information disclosure**: Query pattern analysis

### ARP Protocol Weaknesses

#### ARP Spoofing Potential

**Vulnerabilità ARP**:
- Nessuna autenticazione
- Broadcast-based
- Last response wins

**Test spoofing (ambiente controllato)**:
```bash
# Invio ARP gratuito falso
arping -c 1 -A -I eth0 192.168.1.1
echo "Sent gratuitous ARP for gateway"
```

### Legacy Protocol Risks

#### NetBIOS/SMB Analysis

**Porte legacy identificate**:
- **137/udp**: NetBIOS Name Service
- **138/udp**: NetBIOS Datagram Service  
- **139/tcp**: NetBIOS Session Service
- **445/tcp**: SMB over TCP

**Rischi associati**:
- Information disclosure (null sessions)
- Brute force attacks
- Pass-the-hash attacks
- Relay attacks

## Best Practices

### Network Monitoring

#### Continuous Packet Capture

**📄 Script completo**: [`scripts/networking/network_monitor.sh`](../../scripts/networking/network_monitor.sh)

```bash
#!/bin/bash
# Script monitoring rete continuo
INTERFACE="eth0"
CAPTURE_DIR="/var/log/network"
ROTATION_SIZE="100M"

# Rotazione automatica
tcpdump -i $INTERFACE -C $ROTATION_SIZE -W 10 -w $CAPTURE_DIR/capture.pcap
```

#### Anomaly Detection

**📄 Script completo**: [`scripts/networking/scan_detection.sh`](../../scripts/networking/scan_detection.sh)

**Funzionalità**:
- Monitoring SYN packets anomali
- Alert automatici per possibili port scan
- Logging centralizzato
- Email notifications

### Defensive Measures

#### Port Hardening

```bash
# Chiusura porte non necessarie
sudo ufw deny 135
sudo ufw deny 139
sudo ufw deny 445

# Rate limiting per SSH
sudo ufw limit ssh

# Log delle connessioni negate
sudo ufw logging on
```

#### Network Segmentation

```bash
# VLAN configuration esempio
# VLAN 10: Management
# VLAN 20: Users  
# VLAN 30: Servers
# VLAN 99: DMZ

# iptables rules tra VLAN
iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.20.0/24 -j DROP
iptables -A FORWARD -s 192.168.20.0/24 -d 192.168.30.0/24 -p tcp --dport 80,443 -j ACCEPT
```

### Offensive Reconnaissance

#### Target Enumeration

**📄 Script completo**: [`scripts/networking/reconnaissance.sh`](../../scripts/networking/reconnaissance.sh)

**Funzionalità**:
- Host discovery automatizzato
- Port scanning parallelo
- Service enumeration
- Vulnerability assessment
- Report generation

**Uso**:
```bash
# Reconnaissance completo di una rete
./scripts/networking/reconnaissance.sh 192.168.1.0/24

# Output generato:
# - live_hosts.txt
# - scan_[IP].txt per ogni host
# - detailed_scan.txt
# - vuln_scan.txt
```

#### Stealth Techniques

```bash
# Scan stealth con timing random
nmap -sS -T1 --randomize-hosts target_network

# Decoy scanning
nmap -D RND:10 target_host

# Fragment packets
nmap -f target_host

# Source port spoofing
nmap --source-port 53 target_host
```

### Performance Optimization

#### Large Network Scanning

```bash
# Scan parallelo per grandi reti
echo "192.168.0.0/16" | masscan -p80,443,22,21,25,53,110,995,993,143 --rate=1000
```

#### Traffic Analysis Optimization

```bash
# Buffer size optimization per tcpdump
tcpdump -B 4096 -i any -w capture.pcap

# Ring buffer per continuous capture
tcpdump -i any -C 100 -W 50 -w rotating_capture.pcap
```

### Advanced Monitoring Techniques

#### Real-time Traffic Analysis

**📄 Script completo**: [`scripts/networking/traffic_analyzer.py`](../../scripts/networking/traffic_analyzer.py)

**Funzionalità**:
- Real-time packet analysis
- Protocol distribution statistics
- Anomaly detection algorithms
- Automated threat identification
- Dashboard generation

#### Network Baseline Creation

**📄 Script completo**: [`scripts/networking/network_baseline.sh`](../../scripts/networking/network_baseline.sh)

```bash
# Crea baseline del traffico normale
./scripts/networking/network_baseline.sh

# Genera:
# - normal_traffic_patterns.json
# - baseline_metrics.txt
# - protocol_distribution.csv
```

### Incident Response

#### Network Forensics

**📄 Script completo**: [`scripts/networking/network_forensics.sh`](../../scripts/networking/network_forensics.sh)

**Capabilities**:
- Automatic evidence collection
- Timeline reconstruction
- IOC (Indicators of Compromise) extraction
- Report generation for legal purposes

#### Emergency Response Procedures

```bash
# Isolamento immediato host compromesso
iptables -A INPUT -s [COMPROMISED_IP] -j DROP
iptables -A OUTPUT -d [COMPROMISED_IP] -j DROP

# Cattura traffico per analisi
tcpdump -i any -w incident_$(date +%Y%m%d_%H%M%S).pcap host [COMPROMISED_IP]

# Backup configurazioni critiche
cp /etc/iptables/rules.v4 /backup/iptables_backup_$(date +%Y%m%d)
```

### Commands Reference Quick

```bash
# Network discovery
ip route show | grep default
netdiscover -r 192.168.1.0/24
nmap -sn 192.168.1.0/24

# ARP table inspection  
arp -a
arp -s <ip> <mac>  # Static entry
watch -n 5 'arp -a'  # Monitoring

# Traffic monitoring
sudo tcpdump -i wlan0 arp
sudo tcpdump -i wlan0 'tcp port 80'
sudo tshark -i interface

# MITM Attack
sudo python3 scripts/networking/mitm_spoofer.py <target> <gateway>

# Port scanning
nmap -sS -p- -O -sV target
nmap --script=vuln target
nmap -sS -T1 --randomize-hosts target  # Stealth

# Packet analysis
tshark -r capture.pcap
tcpdump -r capture.pcap 'filter'

# Network monitoring
./scripts/networking/network_monitor.sh
./scripts/networking/scan_detection.sh

# Reconnaissance
./scripts/networking/reconnaissance.sh 192.168.1.0/24

# Forensics
./scripts/networking/network_forensics.sh
```

### Security Assessment Checklist

#### Pre-Assessment Phase
- [ ] Obtain proper authorization
- [ ] Define scope and limitations
- [ ] Prepare isolated test environment
- [ ] Backup critical configurations
- [ ] Establish communication protocols

#### Discovery Phase
- [ ] Network topology mapping
- [ ] Host enumeration (netdiscover/nmap)
- [ ] Service identification
- [ ] OS fingerprinting
- [ ] Vulnerability assessment

#### Testing Phase
- [ ] ARP spoofing feasibility
- [ ] MITM attack simulation
- [ ] Traffic interception verification
- [ ] Protocol vulnerability testing
- [ ] Evasion technique validation

#### Documentation Phase
- [ ] Detailed methodology documentation
- [ ] Evidence collection and preservation
- [ ] Risk assessment and impact analysis
- [ ] Remediation recommendations
- [ ] Executive summary preparation

### Remediation Strategies

#### Network Hardening

**Immediate Actions**:
```bash
# Disable unused network services
systemctl disable telnet
systemctl disable ftp
systemctl disable rsh

# Enable secure protocols only
systemctl enable ssh
systemctl enable https

# Configure firewall rules
ufw enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw limit ssh
```

**Long-term Solutions**:
- Network segmentation with VLANs
- Implement network access control (NAC)
- Deploy intrusion detection systems (IDS)
- Regular security assessments
- Staff security awareness training

#### Monitoring Implementation

**📄 Configuration files**: [`configs/networking/`](../../configs/networking/)

**Includes**:
- `iptables_secure.rules` - Hardened firewall configuration
- `snort.conf` - IDS configuration
- `rsyslog_network.conf` - Centralized logging
- `nagios_network.cfg` - Network monitoring

### Legal and Ethical Considerations

#### Important Disclaimers

**⚠️ LEGAL WARNING**: 
- Use these techniques ONLY on networks you own or have explicit written permission to test
- Unauthorized network attacks are illegal in most jurisdictions
- Always follow responsible disclosure practices
- Document all testing activities for legal protection

#### Ethical Guidelines

**Best Practices**:
- Obtain proper authorization before testing
- Minimize impact on production systems
- Protect confidentiality of discovered information
- Provide constructive remediation guidance
- Follow industry ethical standards (EC-Council, SANS, etc.)

#### Compliance Considerations

**Regulatory Frameworks**:
- GDPR: Data protection during network testing
- HIPAA: Healthcare network security requirements
- PCI DSS: Payment card industry standards
- SOX: Financial data protection requirements

---

**Conclusioni Networking e Sicurezza**:

### Key Takeaways

1. **ARP Vulnerability is Fundamental**: Il protocollo ARP rimane intrinsecamente insicuro per design, rendendo ogni rete locale potenzialmente vulnerabile a MITM attacks.

2. **HTTPS è l'Unica Protezione Reale**: Contro attacchi MITM, solo HTTPS fornisce protezione effettiva dei dati in transito.

3. **Invisibilità degli Attacchi**: Gli attacchi ARP spoofing sono completamente invisibili alle vittime, rendendo la detection proattiva essenziale.

4. **Windows 11 Security Improvements**: Le versioni moderne di Windows mostrano significativi miglioramenti nella security posture rispetto alle versioni precedenti.

5. **Network Monitoring è Critico**: Il monitoraggio continuo del traffico di rete è essenziale per early warning e incident response.

6. **Defense in Depth**: Nessuna singola tecnologia di sicurezza è sufficiente; serve un approccio stratificato.

### Lessons Learned

**Technical Insights**:
- Port scanning rimane una tecnica fondamentale di reconnaissance
- La comprensione dei protocolli è essenziale per identificare vulnerabilità
- Network segmentation e monitoring continuo sono pilastri della difesa
- L'automazione degli assessment accelera significativamente il processo

**Security Implications**:
- Le reti locali non sono intrinsecamente sicure
- L'educazione degli utenti su HTTPS è cruciale
- La visibility del traffico di rete è fondamentale per la sicurezza
- Gli attacchi moderni richiedono tecniche di detection sofisticate

**Operational Impact**:
- Gli strumenti open source sono potenti quanto le soluzioni commerciali
- La documentazione dettagliata è essenziale per incident response
- L'approccio systematico supera sempre gli attacchi "spray and pray"
- La collaboration tra team offensivi e difensivi migliora la security posture complessiva

### Future Research Directions

**Areas of Interest**:
- IoT device security in modern networks
- AI/ML-based network anomaly detection
- Zero-trust network architecture implementation
- Advanced persistent threat (APT) detection techniques
- Container and cloud network security

**Tool Development**:
- Enhanced MITM detection algorithms
- Automated vulnerability assessment frameworks
- Real-time network visualization tools
- Integrated threat intelligence platforms

---

**Repository Structure for Scripts**:
```
scripts/networking/
├── mitm_spoofer.py           # Advanced MITM ARP Spoofer
├── network_monitor.sh        # Continuous packet capture
├── scan_detection.sh         # Anomaly detection
├── reconnaissance.sh         # Automated target enumeration
├── traffic_analyzer.py       # Real-time traffic analysis
├── network_baseline.sh       # Baseline creation
└── network_forensics.sh      # Incident response forensics

configs/networking/
├── iptables_secure.rules     # Hardened firewall configuration
├── snort.conf               # IDS configuration
├── rsyslog_network.conf     # Centralized logging
└── nagios_network.cfg       # Network monitoring
```

Questa documentazione rappresenta un percorso completo attraverso le tecniche moderne di network security assessment, bilanciando aspetti offensivi e difensivi con un forte focus sull'etica e sulla legalità.
[← Linux Security](../linux-security/README.md) | [Defensive Security →](../defensive-security/README.md)# Networking e Sicurezza - Documentazione Completa

Documentazione tecnica completa su networking, analisi protocolli, packet capture e attack vectors. Include analisi pratica di traffico di rete, ARP spoofing, MITM attacks e tecniche di reconnaissance con tools professionali.

## Indice

- [Packet Analysis](#packet-analysis)
- [Three-Way Handshake](#three-way-handshake)
- [Subnetting](#subnetting)
- [Port Scanning](#port-scanning)
- [Network Discovery](#network-discovery)
- [ARP Spoofing & Man-in-the-Middle Attack](#arp-spoofing--man-in-the-middle-attack)
- [Protocol Vulnerabilities](#protocol-vulnerabilities)
- [Best Practices](#best-practices)

## Packet Analysis

### tshark - Network Protocol Analyzer

#### Setup e Configurazione

```bash
# Verifica installazione
tshark -v
# TShark (Wireshark) 3.6.2

# Lista interfacce disponibili
tshark -D
# 1. eth0
# 2. wlan0
# 3. lo (Loopback)
```

#### Cattura Base

```bash
# Cattura tutto il traffico
sudo tshark

# Cattura su interfaccia specifica
sudo tshark -i wlan0

# Salvataggio in file
sudo tshark -w capture.pcap

# Lettura da file
tshark -r capture.pcap
```

#### Esempio Traffico Catturato (176 pacchetti)

```
146 10.527487448 192.168.x.x → 192.168.130.187 DNS 76 Standard query 0x0a89 A ping.manjaro.org
147 10.527501668 192.168.x.x → 192.168.130.187 DNS 76 Standard query 0xcab7 AAAA ping.manjaro.org
148 10.530278726 192.168.130.187 → 192.168.x.x DNS 92 Standard query response 0x0a89 A ping.manjaro.org A 116.203.91.91
149 10.530517532 192.168.130.187 → 192.168.x.x DNS 104 Standard query response 0xcab7 AAAA ping.manjaro.org AAAA 2a01:4f8:c0c:51f3::1
150 12.360664754 [MAC_1] → [MAC_2] ARP 42 Who has 192.168.x.x? Tell 192.168.130.187
151 12.360679494 [MAC_2] → [MAC_1] ARP 42 192.168.x.x is at [MAC_2]
152 16.555285247 192.168.x.x → 18.97.36.75 TLSv1.2 307 Application Data
153 16.579458804 192.168.x.x → 239.255.255.250 SSDP 210 M-SEARCH * HTTP/1.1
```

#### Analisi Traffico Identificato

**DNS Queries**:
- **A record** (IPv4): ping.manjaro.org → 116.203.91.91
- **AAAA record** (IPv6): ping.manjaro.org → 2a01:4f8:c0c:51f3::1
- **Funzione**: Risoluzione nomi di dominio

**ARP (Address Resolution Protocol)**:
- **Scopo**: Mappatura IP → MAC address
- **Rete locale**: 192.168.x.x discovery
- **Frequenza**: Ogni pochi secondi per host attivi

**SSDP (Simple Service Discovery Protocol)**:
- **IP multicast**: 239.255.255.250
- **Protocollo**: HTTP-like su UDP
- **Funzione**: Scoperta dispositivi UPnP

**TLS Traffic**:
- **Versione**: TLSv1.2
- **Porte**: 443 (HTTPS)
- **Data**: Application Data encrypted

### tcpdump - Command Line Packet Analyzer

#### Sintassi Base

```bash
# Cattura base
sudo tcpdump

# Interfaccia specifica
sudo tcpdump -i eth0

# Host specifico
sudo tcpdump host 8.8.8.8

# Porta specifica
sudo tcpdump port 80

# Protocollo specifico
sudo tcpdump tcp
```

#### Filtri Avanzati

```bash
# TCP traffico verso Google
sudo tcpdump -i any -n -v 'tcp and host google.com'

# Parametri spiegati:
# -i any     = tutte le interfacce
# -n         = no DNS resolution
# -v         = verbose mode
# 'tcp and host google.com' = filtro BPF
```

#### Test Pratico con Google

**Trigger**: `curl -I http://google.com`

**Output catturato**:
```
10:18:35.954106 enpX Out IP 192.168.x.x.59416 > 216.58.x.x.80: Flags [S], seq [...], length 0
10:18:36.001373 enpX In  IP 216.58.x.x.80 > 192.168.x.x.59416: Flags [S.], seq [...], ack [...], length 0
10:18:36.001385 enpX Out IP 192.168.x.x.59416 > 216.58.x.x.80: Flags [.], ack 1, length 0

10:18:36.001409 enpX Out IP 192.168.x.x.59416 > 216.58.x.x.80: Flags [P.], length 75: HTTP
    HEAD / HTTP/1.1
    Host: google.com
    User-Agent: curl/8.14.1
    Accept: */*

10:18:36.134911 enpX In  IP 216.58.x.x.80 > 192.168.x.x.59416: Flags [P.], length 554: HTTP
    HTTP/1.1 301 Moved Permanently
    Location: http://www.google.com/
    Content-Type: text/html; charset=UTF-8
    Server: gws
```

#### Analisi Dettagliata

**Timing Analysis**:
- **Latenza**: ~47ms verso Google
- **RTT**: Round-trip time accettabile
- **Possibile vulnerability**: SYN flood (porte client predicibili)

**Flag TCP**:
- **[S]**: SYN (sincronizzazione)
- **[S.]**: SYN-ACK (sincronizzazione + acknowledgment)
- **[.]**: ACK (acknowledgment)
- **[P.]**: PSH (push data immediately)
- **[F.]**: FIN (fine connessione)

**User-Agent Disclosure**:
- **curl/8.14.1**: Versione software esposta
- **Rischio**: Fingerprinting e vulnerability targeting

**Security Headers Missing**:
- **X-XSS-Protection**: 0 (disabled)
- **Potenziale vulnerability**: XSS attacks

## Three-Way Handshake

### Concetti Base

Il three-way handshake è il processo di stabilimento connessione TCP.

**Fasi**:
1. **Client → Server**: SYN (synchronize)
2. **Server → Client**: SYN-ACK (synchronize-acknowledge)
3. **Client → Server**: ACK (acknowledge)

### Cattura Handshake

#### Setup tcpdump per Handshake

```bash
# Filtro per catturare solo SYN/ACK flags
sudo tcpdump -i interface 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'

# Parametri spiegati:
# tcp[tcpflags]           = byte dei flag TCP
# tcp-syn|tcp-ack         = flag SYN o ACK
# != 0                    = almeno uno dei flag settato
```

#### Test con telnet

```bash
# Trigger handshake
telnet example.com 80
```

#### Risultato Catturato

```
11:01:40.925898 IP [CLIENT] > [SERVER]: Flags [S], seq ..., win ..., length 0
11:01:41.141589 IP [SERVER] > [CLIENT]: Flags [S.], seq ..., ack ..., length 0
11:01:41.141604 IP [CLIENT] > [SERVER]: Flags [.], ack ..., length 0
```

### Analisi Sequenza Numbers

**Dettagli tecnici**:
```
1. Client → Server: SYN (seq=X, flags=S)
2. Server → Client: SYN-ACK (seq=Y, ack=X+1, flags=SA)
3. Client → Server: ACK (seq=X+1, ack=Y+1, flags=A)
```

**Security Implications**:
- **Sequence prediction**: Difficoltà 259 (alta sicurezza)
- **SYN flood attack**: Possibile saturare half-open connections
- **RST injection**: Possibile se sequence numbers predicibili

## Subnetting

### Concetti Base

La subnet mask definisce quanti host sono disponibili in una rete.

**Formula**: Host disponibili = 2^(32-CIDR) - 2
- **-2**: Network address e Broadcast address non utilizzabili

### ipcalc - Network Calculator

#### Rete Standard /24

```bash
ipcalc 192.168.1.0/24
```

**Output**:
```
Address:   192.168.1.0          11000000.10101000.00000001. 00000000
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
=>
Network:   192.168.1.0/24       11000000.10101000.00000001. 00000000
HostMin:   192.168.1.1          11000000.10101000.00000001. 00000001
HostMax:   192.168.1.254        11000000.10101000.00000001. 11111110
Broadcast: 192.168.1.255        11000000.10101000.00000001. 11111111
Hosts/Net: 254                   Class C, Private Internet
```

#### Rete Piccola /28

```bash
ipcalc 192.168.1.0/28
```

**Output**:
```
Address:   192.168.1.0          11000000.10101000.00000001.0000 0000
Netmask:   255.255.255.240 = 28 11111111.11111111.11111111.1111 0000
Wildcard:  0.0.0.15             00000000.00000000.00000000.0000 1111
=>
Network:   192.168.1.0/28       11000000.10101000.00000001.0000 0000
HostMin:   192.168.1.1          11000000.10101000.00000001.0000 0001
HostMax:   192.168.1.14         11000000.10101000.00000001.0000 1110
Broadcast: 192.168.1.15         11000000.10101000.00000001.0000 1111
Hosts/Net: 14                    Class C, Private Internet
```

**Calcolo manuale /28**:
- 32 - 28 = 4 bit per host
- 2^4 = 16 indirizzi totali
- 16 - 2 = 14 host utilizzabili

### Classi di Indirizzi IP

#### Classe A - Large Networks

```bash
ipcalc 1.0.0.0/8
```

| Parametro | Valore |
|-----------|--------|
| **Range** | 1.0.0.0 - 126.255.255.255 |
| **CIDR** | /8 |
| **Subnet Mask** | 255.0.0.0 |
| **Host Max** | 16,777,214 |
| **Uso tipico** | ISP, grandi corporation |

#### Classe B - Medium Networks

```bash
ipcalc 128.0.0.0/16
```

| Parametro | Valore |
|-----------|--------|
| **Range** | 128.0.0.0 - 191.255.255.255 |
| **CIDR** | /16 |
| **Subnet Mask** | 255.255.0.0 |
| **Host Max** | 65,534 |
| **Uso tipico** | Università, aziende medie |

#### Classe C - Small Networks

```bash
ipcalc 192.0.0.0/24
```

| Parametro | Valore |
|-----------|--------|
| **Range** | 192.0.0.0 - 223.255.255.255 |
| **CIDR** | /24 |
| **Subnet Mask** | 255.255.255.0 |
| **Host Max** | 254 |
| **Uso tipico** | Piccole aziende, home network |

### VLSM (Variable Length Subnet Masking)

#### Esempio Pratico

**Scenario**: Azienda con diversi dipartimenti

| Dipartimento | Host Richiesti | CIDR Ottimale | Range |
|--------------|----------------|---------------|--------|
| **IT** | 50 | /26 (62 host) | 192.168.1.0/26 |
| **HR** | 20 | /27 (30 host) | 192.168.1.64/27 |
| **Finance** | 10 | /28 (14 host) | 192.168.1.96/28 |
| **Guest** | 5 | /29 (6 host) | 192.168.1.112/29 |

**Vantaggi VLSM**:
- Ottimizzazione spazio indirizzi
- Riduzione broadcast domain
- Migliore sicurezza (segregazione)

## Port Scanning

### nmap - Network Mapper

#### Installazione e Verifica

```bash
# Verifica versione
nmap -v
# Starting Nmap 7.97 ( https://nmap.org )

# Help completo
nmap --help | less
```

#### Sintassi Base

```bash
# Host singolo
nmap 192.168.1.100

# Subnet completa
nmap 192.168.1.0/24

# Lista da file
nmap -iL targets.txt

# DNS resolution
nmap www.google.com
```

#### Tipi di Scan

| Parametro | Tipo Scan | Descrizione |
|-----------|-----------|-------------|
| **-sS** | SYN Stealth | Half-open, stealth |
| **-sT** | TCP Connect | Full connection |
| **-sU** | UDP Scan | UDP ports |
| **-sN** | NULL Scan | No flags set |
| **-sF** | FIN Scan | FIN flag only |
| **-sX** | Xmas Scan | FIN+PSH+URG flags |

#### Windows 11 Target Scan

**Problema iniziale**:
```bash
nmap 192.168.130.234
# Host seems down. If it is really up, but blocking our ping probes, try -Pn
```

**Soluzione Windows Firewall**:
1. Abilitare regola: "File And Printer Sharing (Echo Request - ICMPv4-In)"
2. Oppure usare `-Pn` per saltare ping discovery

**Scan riuscito**:
```bash
nmap 192.168.130.234

PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

#### Scan Completo Stealth

```bash
sudo nmap -sS -p- -O -sV -vv -T5 192.168.130.234
```

**Parametri spiegati**:
- **-sS**: SYN stealth scan
- **-p-**: Tutte le 65535 porte
- **-O**: OS detection
- **-sV**: Service version detection
- **-vv**: Very verbose
- **-T5**: Timing template (insane speed)

**Risultati Windows 11**:
```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?    Windows Delivery Optimization
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
[... più porte RPC ...]

MAC Address: 08:00:27:10:C6:E5 (Oracle VirtualBox virtual NIC)
OS fingerprint: Microsoft Windows 10 1703 or Windows 11 21H2 (99%)
TCP Sequence Prediction: Difficulty=259 (Good luck!)
```

#### Porte ad Alto Rischio Identificate

| Porta | Servizio | Rischio | Vulnerabilità Note |
|-------|----------|---------|-------------------|
| **135** | MS-RPC | 🔴 Alto | RPC endpoint mapper |
| **139** | NetBIOS-SSN | 🟡 Medio | Legacy sharing |
| **445** | Microsoft-DS | 🔴 Critico | EternalBlue, SMBGhost |
| **7680** | Delivery Opt | 🟢 Basso | Windows Update P2P |

#### Vulnerability Scanning

```bash
# Script vulnerabilità
nmap --script=vuln 192.168.130.234
```

**Risultato Windows 11**:
```
Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
```

**Analisi**:
- **ms10-061**: Non vulnerabile (sistema aggiornato)
- **ms10-054**: Non vulnerabile
- **Errori connessione**: SMB hardening efficace

## Network Discovery

### netdiscover - ARP Scanner

#### Funzionalità Base

```bash
# Scan subnet locale
netdiscover -r 192.168.1.0/24

# Passive mode (solo listening)
netdiscover -p

# Output in file
netdiscover -r 192.168.1.0/24 > network_map.txt
```

#### Esempio Output Reale

```
Currently scanning: 192.168.0.0/16   |   Screen View: Unique Hosts

13 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 714
_____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.X.1      aa:bb:cc:11:22:33      5     280  [Firewall] Fortinet, Inc.
192.168.X.2      dd:ee:ff:44:55:66      2     112  [Smart TV] Vestel Elektronik
192.168.X.3      77:88:99:00:aa:bb      1      42  [Smart TV] Vestel Elektronik
192.168.X.4      cc:dd:ee:ff:00:11      5     280  [Dispositivo sconosciuto]
```

#### Analisi MAC Address Vendors

**Informazioni ottenute**:
- **Fortinet**: Firewall enterprise
- **Vestel**: Smart TV manufacturer
- **Dispositivo sconosciuto**: Possibile target interessante

**Security Implications**:
- Fingerprinting dispositivi di rete
- Identificazione infrastruttura critica
- Target selection per penetration testing

## ARP Spoofing & Man-in-the-Middle Attack

### Teoria del Protocollo ARP

#### Cos'è ARP (Address Resolution Protocol)
- **Funzione**: Mappa indirizzi IP → MAC address nella rete locale (LAN)
- **Meccanismo**: Quando un host vuole comunicare con un IP, invia broadcast ARP "Chi ha questo IP?"
- **Risposta**: L'host con quell'IP risponde con il suo MAC address
- **Cache**: Il MAC viene salvato nella ARP table per uso futuro

#### Vulnerabilità Intrinseche di ARP
1. **Stateless Protocol**: Nessuna verifica dell'identità
2. **Broadcast Domain**: Tutti nella LAN ricevono pacchetti ARP
3. **Cache Poisoning**: Accetta aggiornamenti ARP senza autenticazione
4. **Trust-based**: Si fida di qualsiasi risposta ARP ricevuta

### ARP Spoofing Implementation

#### Installazione Dipendenze
```bash
# Installa Scapy per Python
pip install scapy --break-system-packages

# Verifica installazione
python3 -c "import scapy.all as scapy; print('Scapy OK')"
```

#### Script ARP Spoofer

**📄 Script completo**: [`scripts/networking/mitm_spoofer.py`](../../scripts/networking/mitm_spoofer.py)

**Funzionalità principali**:
- ARP spoofing bidirezionale (target ↔ gateway)
- Intercettazione traffico HTTP in tempo reale
- Estrazione automatica credenziali da form POST
- IP forwarding e configurazione iptables automatica
- Cleanup completo all'interruzione

**Uso**:
```bash
# Sintassi base
sudo python3 scripts/networking/mitm_spoofer.py <target_ip> <gateway_ip> [interface]

# Esempio pratico
sudo python3 scripts/networking/mitm_spoofer.py 192.168.1.100 192.168.1.1 wlan0
```

### Network Discovery Pre-Attack

#### Scoprire Target e Gateway
```bash
# Identifica la tua interfaccia di rete
ip addr show

# Trova il gateway predefinito  
ip route show | grep default
# Output: default via 192.168.1.1 dev wlan0

# Scansiona la rete locale
netdiscover -r 192.168.1.0/24
# O alternativamente:
nmap -sn 192.168.1.0/24
```

### Esecuzione Attacco MITM

#### Output Attacco Reale
```
🎯 Advanced MITM ARP Spoofer v2.0
=================================
⚠️  Solo per scopi educativi e test di sicurezza

[+] Risolvendo MAC address per 192.168.x.58...
[+] MAC di 192.168.x.58 è 08:00:27:2f:36:a6
[+] Risolvendo MAC address per 192.168.x.141...
[+] MAC di 192.168.x.141 è 2a:42:c4:38:b7:66
[+] Abilitando IP forwarding...
[+] Configurando iptables...
[+] Avviando cattura pacchetti HTTP...

🎯 Iniziando MITM attack:
    Target: 192.168.x.58 (08:00:27:2f:36:a6)
    Gateway: 192.168.x.141 (2a:42:c4:38:b7:66)
    Interface: wlo1

📡 ARP spoofing attivo (modalità silenziosa)
🕵️  Monitorando traffico HTTP...

🌐 [14:30:30] HTTP GET Request
    From: 192.168.x.58 → To: 146.190.62.39
    URL: http://httpforever.com/

📡 [14:30:30] HTTP Response
    From: 146.190.62.39 → To: 192.168.x.58
    Status: 200

🌐 [14:30:31] HTTP POST Request
    From: 192.168.x.58 → To: 216.58.205.35
    URL: http://o.pki.goog/wr2
    POST Data: 0R0P0N0L0J0...

📊 Pacchetti ARP inviati: 150+ | Dati intercettati: 25
```

### Risultati e Implicazioni

#### Traffico Intercettato con Successo
- **HTTP GET Requests**: Tutti i siti web visitati
- **HTTP POST Requests**: Dati di form, login, ricerche
- **Response Status**: 200 (OK), 304 (Not Modified)
- **Invisibilità Completa**: Vittima ignara dell'attacco

#### Dati Sensibili Intercettabili
1. **Credenziali HTTP**: Username/password in chiaro
2. **Session Cookies**: Per session hijacking
3. **Dati Personali**: Form submissions, ricerche  
4. **File Downloads**: Modificabili in tempo reale
5. **DNS Queries**: Domini visitati

#### Limitazioni dell'Attacco
- **HTTPS Traffic**: Protetto da crittografia (solo metadata visibili)
- **HSTS Sites**: HTTP Strict Transport Security impedisce downgrade
- **Certificate Pinning**: App mobili con pinning resistono a MITM

### Protezioni Anti-ARP Spoofing

#### Configurazioni Difensive
```bash
# Static ARP entries (impedisce spoofing del gateway)
sudo arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff

# Monitoring ARP anomalies
arp-scan -l | grep "DUP"  # Cerca duplicati sospetti

# ARP table monitoring
watch -n 5 'arp -a'  # Monitora cambiamenti ARP

# Network monitoring con tcpdump
sudo tcpdump -i wlan0 arp and ether src aa:bb:cc:dd:ee:ff
```

#### Network Hardening
```bash
# Enable ARP filtering (Linux)
echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter

# DHCP snooping (managed switches)
# Port security con MAC address binding
# VLAN segmentation per isolare traffico critico
```

### Lezioni di Sicurezza Apprese

#### Riflessione sull'Attacco
> **"Oggi ho capito davvero cosa significa 'man in the middle'"**
> 
> Non è solo teoria - è una cosa che funziona davvero e fa paura quanto sia semplice. Con poche righe di Python sono riuscito a mettermi nel mezzo delle comunicazioni di una macchina senza che se ne accorgesse minimamente.
> 
> La vittima navigava tranquilla su httpforever.com mentre io vedevo tutto il suo traffico HTTP passarmi davanti agli occhi. **L'invisibilità dell'attacco è la cosa più spaventosa** - nessun rallentamento, errore o avviso.

#### Vulnerabilità Fondamentale di ARP
- **Design Flaw**: ARP si basa sulla "fiducia cieca"
- **Analogia**: Come gridare "sono il postino" e tutti ti danno le lettere senza verifica
- **Impatto**: Rende insicura ogni rete locale non hardened

#### Importanza di HTTPS
- **Unica Protezione Reale**: Solo HTTPS protegge i dati in MITM
- **Educazione**: La maggior parte degli utenti non capisce la differenza HTTP/HTTPS
- **Responsibility**: Sviluppatori devono forzare HTTPS sempre

### ARP Spoofing Detection

#### Monitoring ARP Table

```bash
# ARP table corrente
arp -a
# gateway (192.168.1.1) at aa:bb:cc:11:22:33 [ether] on eth0

# Monitoring continuo
watch -n 1 'arp -a'

# Log ARP changes
tcpdump -i eth0 arp > arp_monitoring.log
```

#### Rilevazione Anomalie

**Indicatori di ARP spoofing**:
- MAC address duplicati per IP diversi
- Cambi frequenti MAC per stesso IP
- MAC vendor inconsistenti con dispositivo atteso

## Protocol Vulnerabilities

### DNS Analysis

#### DNS Query Types Identificati

```bash
# Monitor DNS queries
sudo tcpdump -i any port 53
```

**Query types osservati**:
- **A**: IPv4 address lookup
- **AAAA**: IPv6 address lookup
- **PTR**: Reverse DNS lookup
- **MX**: Mail exchange records

#### DNS Security Issues

**Vulnerabilities identificate**:
- **DNS poisoning**: Possible con DNS non autenticato
- **DNS tunneling**: Possibile data exfiltration
- **Information disclosure**: Query pattern analysis

### ARP Protocol Weaknesses

#### ARP Spoofing Potential

**Vulnerabilità ARP**:
- Nessuna autenticazione
- Broadcast-based
- Last response wins

**Test spoofing (ambiente controllato)**:
```bash
# Invio ARP gratuito falso
arping -c 1 -A -I eth0 192.168.1.1
echo "Sent gratuitous ARP for gateway"
```

### Legacy Protocol Risks

#### NetBIOS/SMB Analysis

**Porte legacy identificate**:
- **137/udp**: NetBIOS Name Service
- **138/udp**: NetBIOS Datagram Service  
- **139/tcp**: NetBIOS Session Service
- **445/tcp**: SMB over TCP

**Rischi associati**:
- Information disclosure (null sessions)
- Brute force attacks
- Pass-the-hash attacks
- Relay attacks

## Best Practices

### Network Monitoring

#### Continuous Packet Capture

**📄 Script completo**: [`scripts/networking/network_monitor.sh`](../../scripts/networking/network_monitor.sh)

```bash
#!/bin/bash
# Script monitoring rete continuo
INTERFACE="eth0"
CAPTURE_DIR="/var/log/network"
ROTATION_SIZE="100M"

# Rotazione automatica
tcpdump -i $INTERFACE -C $ROTATION_SIZE -W 10 -w $CAPTURE_DIR/capture.pcap
```

#### Anomaly Detection

**📄 Script completo**: [`scripts/networking/scan_detection.sh`](../../scripts/networking/scan_detection.sh)

**Funzionalità**:
- Monitoring SYN packets anomali
- Alert automatici per possibili port scan
- Logging centralizzato
- Email notifications

### Defensive Measures

#### Port Hardening

```bash
# Chiusura porte non necessarie
sudo ufw deny 135
sudo ufw deny 139
sudo ufw deny 445

# Rate limiting per SSH
sudo ufw limit ssh

# Log delle connessioni negate
sudo ufw logging on
```

#### Network Segmentation

```bash
# VLAN configuration esempio
# VLAN 10: Management
# VLAN 20: Users  
# VLAN 30: Servers
# VLAN 99: DMZ

# iptables rules tra VLAN
iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.20.0/24 -j DROP
iptables -A FORWARD -s 192.168.20.0/24 -d 192.168.30.0/24 -p tcp --dport 80,443 -j ACCEPT
```

### Offensive Reconnaissance

#### Target Enumeration

**📄 Script completo**: [`scripts/networking/reconnaissance.sh`](../../scripts/networking/reconnaissance.sh)

**Funzionalità**:
- Host discovery automatizzato
- Port scanning parallelo
- Service enumeration
- Vulnerability assessment
- Report generation

**Uso**:
```bash
# Reconnaissance completo di una rete
./scripts/networking/reconnaissance.sh 192.168.1.0/24

# Output generato:
# - live_hosts.txt
# - scan_[IP].txt per ogni host
# - detailed_scan.txt
# - vuln_scan.txt
```

#### Stealth Techniques

```bash
# Scan stealth con timing random
nmap -sS -T1 --randomize-hosts target_network

# Decoy scanning
nmap -D RND:10 target_host

# Fragment packets
nmap -f target_host

# Source port spoofing
nmap --source-port 53 target_host
```

### Performance Optimization

#### Large Network Scanning

```bash
# Scan parallelo per grandi reti
echo "192.168.0.0/16" | masscan -p80,443,22,21,25,53,110,995,993,143 --rate=1000
```

#### Traffic Analysis Optimization

```bash
# Buffer size optimization per tcpdump
tcpdump -B 4096 -i any -w capture.pcap

# Ring buffer per continuous capture
tcpdump -i any -C 100 -W 50 -w rotating_capture.pcap
```

### Advanced Monitoring Techniques

#### Real-time Traffic Analysis

**📄 Script completo**: [`scripts/networking/traffic_analyzer.py`](../../scripts/networking/traffic_analyzer.py)

**Funzionalità**:
- Real-time packet analysis
- Protocol distribution statistics
- Anomaly detection algorithms
- Automated threat identification
- Dashboard generation

#### Network Baseline Creation

**📄 Script completo**: [`scripts/networking/network_baseline.sh`](../../scripts/networking/network_baseline.sh)

```bash
# Crea baseline del traffico normale
./scripts/networking/network_baseline.sh

# Genera:
# - normal_traffic_patterns.json
# - baseline_metrics.txt
# - protocol_distribution.csv
```

### Incident Response

#### Network Forensics

**📄 Script completo**: [`scripts/networking/network_forensics.sh`](../../scripts/networking/network_forensics.sh)

**Capabilities**:
- Automatic evidence collection
- Timeline reconstruction
- IOC (Indicators of Compromise) extraction
- Report generation for legal purposes

#### Emergency Response Procedures

```bash
# Isolamento immediato host compromesso
iptables -A INPUT -s [COMPROMISED_IP] -j DROP
iptables -A OUTPUT -d [COMPROMISED_IP] -j DROP

# Cattura traffico per analisi
tcpdump -i any -w incident_$(date +%Y%m%d_%H%M%S).pcap host [COMPROMISED_IP]

# Backup configurazioni critiche
cp /etc/iptables/rules.v4 /backup/iptables_backup_$(date +%Y%m%d)
```

### Commands Reference Quick

```bash
# Network discovery
ip route show | grep default
netdiscover -r 192.168.1.0/24
nmap -sn 192.168.1.0/24

# ARP table inspection  
arp -a
arp -s <ip> <mac>  # Static entry
watch -n 5 'arp -a'  # Monitoring

# Traffic monitoring
sudo tcpdump -i wlan0 arp
sudo tcpdump -i wlan0 'tcp port 80'
sudo tshark -i interface

# MITM Attack
sudo python3 scripts/networking/mitm_spoofer.py <target> <gateway>

# Port scanning
nmap -sS -p- -O -sV target
nmap --script=vuln target
nmap -sS -T1 --randomize-hosts target  # Stealth

# Packet analysis
tshark -r capture.pcap
tcpdump -r capture.pcap 'filter'

# Network monitoring
./scripts/networking/network_monitor.sh
./scripts/networking/scan_detection.sh

# Reconnaissance
./scripts/networking/reconnaissance.sh 192.168.1.0/24

# Forensics
./scripts/networking/network_forensics.sh
```

### Security Assessment Checklist

#### Pre-Assessment Phase
- [ ] Obtain proper authorization
- [ ] Define scope and limitations
- [ ] Prepare isolated test environment
- [ ] Backup critical configurations
- [ ] Establish communication protocols

#### Discovery Phase
- [ ] Network topology mapping
- [ ] Host enumeration (netdiscover/nmap)
- [ ] Service identification
- [ ] OS fingerprinting
- [ ] Vulnerability assessment

#### Testing Phase
- [ ] ARP spoofing feasibility
- [ ] MITM attack simulation
- [ ] Traffic interception verification
- [ ] Protocol vulnerability testing
- [ ] Evasion technique validation

#### Documentation Phase
- [ ] Detailed methodology documentation
- [ ] Evidence collection and preservation
- [ ] Risk assessment and impact analysis
- [ ] Remediation recommendations
- [ ] Executive summary preparation

### Remediation Strategies

#### Network Hardening

**Immediate Actions**:
```bash
# Disable unused network services
systemctl disable telnet
systemctl disable ftp
systemctl disable rsh

# Enable secure protocols only
systemctl enable ssh
systemctl enable https

# Configure firewall rules
ufw enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw limit ssh
```

**Long-term Solutions**:
- Network segmentation with VLANs
- Implement network access control (NAC)
- Deploy intrusion detection systems (IDS)
- Regular security assessments
- Staff security awareness training

#### Monitoring Implementation

**📄 Configuration files**: [`configs/networking/`](../../configs/networking/)

**Includes**:
- `iptables_secure.rules` - Hardened firewall configuration
- `snort.conf` - IDS configuration
- `rsyslog_network.conf` - Centralized logging
- `nagios_network.cfg` - Network monitoring

### Legal and Ethical Considerations

#### Important Disclaimers

**⚠️ LEGAL WARNING**: 
- Use these techniques ONLY on networks you own or have explicit written permission to test
- Unauthorized network attacks are illegal in most jurisdictions
- Always follow responsible disclosure practices
- Document all testing activities for legal protection

#### Ethical Guidelines

**Best Practices**:
- Obtain proper authorization before testing
- Minimize impact on production systems
- Protect confidentiality of discovered information
- Provide constructive remediation guidance
- Follow industry ethical standards (EC-Council, SANS, etc.)

#### Compliance Considerations

**Regulatory Frameworks**:
- GDPR: Data protection during network testing
- HIPAA: Healthcare network security requirements
- PCI DSS: Payment card industry standards
- SOX: Financial data protection requirements

---

**Conclusioni Networking e Sicurezza**:

### Key Takeaways

1. **ARP Vulnerability is Fundamental**: Il protocollo ARP rimane intrinsecamente insicuro per design, rendendo ogni rete locale potenzialmente vulnerabile a MITM attacks.

2. **HTTPS è l'Unica Protezione Reale**: Contro attacchi MITM, solo HTTPS fornisce protezione effettiva dei dati in transito.

3. **Invisibilità degli Attacchi**: Gli attacchi ARP spoofing sono completamente invisibili alle vittime, rendendo la detection proattiva essenziale.

4. **Windows 11 Security Improvements**: Le versioni moderne di Windows mostrano significativi miglioramenti nella security posture rispetto alle versioni precedenti.

5. **Network Monitoring è Critico**: Il monitoraggio continuo del traffico di rete è essenziale per early warning e incident response.

6. **Defense in Depth**: Nessuna singola tecnologia di sicurezza è sufficiente; serve un approccio stratificato.

### Lessons Learned

**Technical Insights**:
- Port scanning rimane una tecnica fondamentale di reconnaissance
- La comprensione dei protocolli è essenziale per identificare vulnerabilità
- Network segmentation e monitoring continuo sono pilastri della difesa
- L'automazione degli assessment accelera significativamente il processo

**Security Implications**:
- Le reti locali non sono intrinsecamente sicure
- L'educazione degli utenti su HTTPS è cruciale
- La visibility del traffico di rete è fondamentale per la sicurezza
- Gli attacchi moderni richiedono tecniche di detection sofisticate

**Operational Impact**:
- Gli strumenti open source sono potenti quanto le soluzioni commerciali
- La documentazione dettagliata è essenziale per incident response
- L'approccio systematico supera sempre gli attacchi "spray and pray"
- La collaboration tra team offensivi e difensivi migliora la security posture complessiva

### Future Research Directions

**Areas of Interest**:
- IoT device security in modern networks
- AI/ML-based network anomaly detection
- Zero-trust network architecture implementation
- Advanced persistent threat (APT) detection techniques
- Container and cloud network security

**Tool Development**:
- Enhanced MITM detection algorithms
- Automated vulnerability assessment frameworks
- Real-time network visualization tools
- Integrated threat intelligence platforms

---

**Repository Structure for Scripts**:
```
scripts/networking/
├── mitm_spoofer.py           # Advanced MITM ARP Spoofer
├── network_monitor.sh        # Continuous packet capture
├── scan_detection.sh         # Anomaly detection
├── reconnaissance.sh         # Automated target enumeration
├── traffic_analyzer.py       # Real-time traffic analysis
├── network_baseline.sh       # Baseline creation
└── network_forensics.sh      # Incident response forensics

configs/networking/
├── iptables_secure.rules     # Hardened firewall configuration
├── snort.conf               # IDS configuration
├── rsyslog_network.conf     # Centralized logging
└── nagios_network.cfg       # Network monitoring
```

Questa documentazione rappresenta un percorso completo attraverso le tecniche moderne di network security assessment, bilanciando aspetti offensivi e difensivi con un forte focus sull'etica e sulla legalità.
[← Linux Security](../linux-security/README.md) | [Defensive Security →](../defensive-security/README.md)
