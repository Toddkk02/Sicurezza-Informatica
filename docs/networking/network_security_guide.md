# Sicurezza di Rete - VLAN, VPN, Firewall, IDS/IPS e Microsegmentazione

## Introduzione

Questa guida copre gli aspetti fondamentali della sicurezza di rete, dalla segmentazione logica con VLAN alla microsegmentazione avanzata, passando per configurazioni VPN, firewall e sistemi di rilevamento intrusioni. Include configurazioni pratiche e test su ambiente virtualizzato.

## VLAN (Virtual Local Area Network)

### Concetti Fondamentali

Le **VLAN** sono reti locali virtuali che operano al **Livello 2 (Data Link)** del modello OSI. Permettono di dividere logicamente una rete fisica in più reti isolate condividendo lo stesso hardware.

#### Caratteristiche Principali

- **Broadcast Domain Separati**: Ogni VLAN crea un ambiente isolato
- **Isolamento Logico**: I dispositivi di VLAN diverse non possono comunicare direttamente
- **Condivisione Hardware**: Stesso switch fisico per multiple VLAN

**Esempio**: Un PC nella VLAN 10 che invia un broadcast non sarà ricevuto da un PC nella VLAN 20, anche usando lo stesso switch.

### Tipi di Porte

#### Access Port
- **Scopo**: Collegare host singoli (PC, stampanti)
- **Caratteristica**: Appartiene a una sola VLAN
- **Esempio**: `Porta 1 → VLAN 10`

#### Trunk Port
- **Scopo**: Collegare switch a switch o switch a router
- **Caratteristica**: Trasporta traffico di multiple VLAN
- **Standard**: Utilizza tag VLAN (802.1Q) per distinguere i pacchetti

### Inter-VLAN Routing

Per far comunicare dispositivi in VLAN diverse è necessario l'**Inter-VLAN Routing**.

#### Requisiti
- Dispositivo Layer 3 (Router o Switch L3)

#### Metodi Implementazione

**SVI (Switch Virtual Interface)**:
- Interfaccia virtuale per ogni VLAN su switch L3

**Router-on-a-stick**:
- Router con porta divisa in subinterface (una per VLAN)

**Esempio Pratico**:
```
PC1 (VLAN 10) → Router/Switch L3 → PC2 (VLAN 20)
```

## Configurazione Pratica VLAN

### Setup Ubuntu Server

#### Installazione Supporto VLAN

```bash
sudo apt install vlan
sudo modprobe 8021q
```

#### Creazione Interfacce VLAN

```bash
# Crea interfacce VLAN
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip link add link eth0 name eth0.20 type vlan id 20

# Attiva interfacce
sudo ip link set dev eth0.10 up
sudo ip link set dev eth0.20 up

# Assegna indirizzi IP
sudo ip addr add 192.168.10.1/24 dev eth0.10
sudo ip addr add 192.168.20.1/24 dev eth0.20
```

#### Test di Connettività

```bash
# Test interfaccia VLAN 10
ping 192.168.10.1

# Test interfaccia VLAN 20
ping 192.168.20.1
```

### Configurazione Cisco Packet Tracer

#### Topologia di Test
- **2 Switch**
- **1 Router** 
- **4 PC** (2 per VLAN)

#### Configurazione Switch

```cisco
Switch>enable
Switch#conf t

# Creazione VLAN
Switch(config)#vlan 10
Switch(config-vlan)#name SALES
Switch(config-vlan)#exit

Switch(config)#vlan 20
Switch(config-vlan)#name IT
Switch(config-vlan)#exit

# Configurazione Access Port - VLAN 10
Switch(config)#interface range fa0/1-2
Switch(config-if-range)#switchport mode access
Switch(config-if-range)#switchport access vlan 10
Switch(config-if-range)#exit

# Configurazione Access Port - VLAN 20
Switch(config)#interface range fa0/3-4
Switch(config-if-range)#switchport mode access
Switch(config-if-range)#switchport access vlan 20
Switch(config-if-range)#exit

# Configurazione Trunk Port
Switch(config)#interface fa0/5
Switch(config-if)#switchport mode trunk
Switch(config-if)#switchport trunk allowed vlan 10,20
Switch(config-if)#exit

# Salvataggio configurazione
Switch#write memory
```

#### Configurazione Router

```cisco
Router>enable
Router#configure terminal

# Attivazione interfaccia fisica
Router(config)#interface gigabitEthernet0/0/0
Router(config-if)#no shutdown
Router(config-if)#exit

# Subinterface VLAN 10
Router(config)#interface gigabitEthernet0/0/0.10
Router(config-subif)#encapsulation dot1Q 10
Router(config-subif)#ip address 192.168.10.1 255.255.255.0
Router(config-subif)#exit

# Subinterface VLAN 20
Router(config)#interface gigabitEthernet0/0/0.20
Router(config-subif)#encapsulation dot1Q 20
Router(config-subif)#ip address 192.168.20.1 255.255.255.0
Router(config-subif)#exit

# Salvataggio configurazione
Router#write memory
```

## Firewall con iptables

### Configurazione Base - Default Policy DROP

#### Policy Principali

```bash
# Blocca tutto il traffico in ingresso
sudo iptables -P INPUT DROP

# Blocca tutto il traffico in transit (routing)
sudo iptables -P FORWARD DROP

# Permette tutto il traffico in uscita
sudo iptables -P OUTPUT ACCEPT
```

### Eccezioni Fondamentali

#### Traffico Loopback

```bash
# Permette traffico localhost (necessario per funzionamento locale)
sudo iptables -A INPUT -i lo -j ACCEPT
```

#### Connessioni Stabilite

```bash
# Permette traffico di risposta a connessioni già iniziate
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

#### ICMP con Limitazione

```bash
# Permette ping con rate limiting (anti-flood)
sudo iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT
```

### Port Forwarding (NAT)

#### Redirect Porta SSH

```bash
# Reindirizza porta 2222 verso SSH interno (porta 22)
sudo iptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT --to-destination 192.168.10.10:22

# Abilita forwarding verso macchina interna
sudo iptables -A FORWARD -p tcp -d 192.168.10.10 --dport 22 -j ACCEPT
```

### Logging e Monitoraggio

#### Log Tentativi SSH

```bash
# Registra ogni tentativo di connessione SSH
sudo iptables -A INPUT -p tcp --dport 22 -j LOG --log-prefix "SSH ATTEMPT: "
```

#### Troubleshooting

```bash
# Visualizza regole attive
sudo iptables -L -v -n

# Controlla log di sistema
dmesg | grep IPTABLES
```

## Configurazione VPN

### Tipologie di VPN

#### 1. Site-to-Site VPN
- **Scopo**: Connette due intere reti (Sede A ↔ Sede B)
- **Caratteristiche**: 
  - Routing automatico attraverso tunnel cifrato
  - Trasparente ai dispositivi finali
  - Gestita a livello router/firewall

#### 2. Client VPN
- **Scopo**: Utente singolo da remoto verso rete aziendale
- **Caratteristiche**:
  - Richiede client VPN installato
  - Traffico cifrato e instradato come se fosse locale

#### 3. IPSec
- **Livello**: Layer 3 (Network) del modello OSI
- **Caratteristiche**:
  - Cifra e autentica pacchetti IP direttamente
  - Standard per VPN professionali (Cisco)
  - Ideale per Site-to-Site

#### 4. OpenVPN
- **Architettura**: User-space (non kernel)
- **Protocolli**: TCP o UDP
- **Porta**: 1194 (configurabile)
- **Vantaggi**: Cross-platform, flessibile

### Setup OpenVPN

#### Installazione Server Ubuntu

```bash
# Installazione pacchetti
sudo apt install openvpn easy-rsa

# Setup Certificate Authority
make-cadir ~/openvpn-ca
cd ~/openvpn-ca

# Inizializzazione PKI
./easyrsa init-pki
./easyrsa build-ca
./easyrsa gen-req server nopass
./easyrsa sign-req server server
```

#### Log Connessione Client

```
2025-07-24 12:22:38 OpenVPN 2.6.14 x86_64-pc-linux-gnu
2025-07-24 12:22:38 library versions: OpenSSL 3.5.1, LZO 2.10
2025-07-24 12:22:38 TCP/UDP: [AF_INET]10.26.106.151:1194
2025-07-24 12:22:39 VERIFY OK: depth=1, CN=MyVPN CA
2025-07-24 12:22:39 VERIFY OK: depth=0, CN=server
2025-07-24 12:22:39 Control Channel: TLSv1.3, cipher TLS_AES_256_GCM_SHA384
2025-07-24 12:22:40 [server] Peer Connection Initiated
2025-07-24 12:22:40 PUSH_REPLY,route 10.8.0.0 255.255.255.0
2025-07-24 12:22:40 TUN/TAP device tun0 opened
2025-07-24 12:22:40 Initialization Sequence Completed
```

**Elementi Chiave del Log**:
- **Cifratura**: TLSv1.3 con AES-256-GCM
- **Tunnel**: Interfaccia tun0 attivata
- **Network VPN**: 10.8.0.0/24
- **Client IP**: 10.8.0.2

## IDS/IPS con Suricata

### Introduzione a Suricata

**Suricata** è un sistema moderno di rilevamento (IDS) e prevenzione (IPS) intrusioni, evoluzione di Snort con performance superiori.

### Metodi di Detection

#### 1. Signature-based Detection
- **Funzionamento**: Usa regole/firme predefinite
- **Vantaggi**: Precisione su attacchi noti
- **Limiti**: Non rileva zero-day o attacchi sconosciuti

**Esempio**: Rilevamento sequenza byte di exploit conosciuto

#### 2. Anomaly-based Detection
- **Funzionamento**: Monitora traffico "normale" e rileva deviazioni
- **Vantaggi**: Può scoprire attacchi nuovi
- **Limiti**: Maggiore predisposizione a falsi positivi

**Esempio**: Numero anomalo di richieste verso un server

### Modalità Operative

#### IDS Mode (Intrusion Detection System)
- **Funzionamento**: Monitoraggio passivo del traffico
- **Azioni**: Analisi, logging, alerting
- **Utilizzo**: Investigazioni e monitoraggio

#### IPS Mode (Intrusion Prevention System)
- **Funzionamento**: Installazione inline nel flusso traffico
- **Azioni**: Blocco e scarto pacchetti sospetti in tempo reale
- **Utilizzo**: Protezione attiva della rete

### Vantaggi di Suricata

- **Compatibilità**: Supporta regole Snort
- **Performance**: Più moderno e performante di Snort
- **Protocolli**: Analizza HTTP, DNS, TLS, etc.
- **Flessibilità**: Modalità IDS/IPS
- **Integrazione**: Dashboard con ELK stack

## Network Microsegmentation

### Concetto Zero Trust Network (ZTN)

#### Principio Fondamentale
**"Mai fidarsi, sempre verificare"** - Nessun dispositivo o utente è considerato affidabile per default.

#### Implicazioni

1. **Autenticazione Universale**: Ogni connessione deve essere autenticata
2. **Policy Ovunque**: Non solo al perimetro di rete
3. **Least Privilege**: Accesso minimo necessario

**Esempio**: Un'app web non può accedere al database solo perché nella stessa LAN - serve autorizzazione esplicita.

### Microsegmentazione

#### Definizione
Pratica di dividere la rete in piccoli segmenti isolati, anche all'interno della stessa subnet o VLAN.

#### Obiettivi
- **Bloccare movimenti laterali** degli attaccanti
- **Limitare superficie di attacco**
- **Controllo granulare** delle comunicazioni

#### Funzionamento
- Policy per singolo host, processo, container, servizio
- Filtraggio tramite firewall, iptables, altri strumenti
- Isolamento anche sullo stesso host fisico

### Linux Namespaces

#### Introduzione
Tecnologia fondamentale per microsegmentazione in ambienti containerizzati.

#### Tipi di Namespace

- **net**: Isola stack di rete (interfacce separate)
- **pid**: Separa processi
- **mnt**: Separa filesystem  
- **ipc**: Isola comunicazioni inter-processo
- **uts**: Isola hostname
- **user**: Isola UID/GID

### Implementazione Pratica

#### Creazione Network Namespaces

```bash
# Creazione namespace isolati
sudo ip netns add ns1
sudo ip netns add ns2

# Creazione coppia interfacce virtuali
sudo ip link add veth1 type veth peer name veth2

# Assegnazione interfacce ai namespace
sudo ip link set veth1 netns ns1
sudo ip link set veth2 netns ns2

# Configurazione indirizzi IP
sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth1
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2

# Attivazione interfacce
sudo ip netns exec ns1 ip link set veth1 up
sudo ip netns exec ns2 ip link set veth2 up
```

#### Test Connettività

```bash
# Test comunicazione tra namespace
sudo ip netns exec ns1 ping 10.0.0.2
```

**Risultato**: Comunicazione successful

#### Implementazione Microsegmentazione

```bash
# Blocco traffico da ns1 verso ns2
sudo ip netns exec ns1 iptables -A OUTPUT -d 10.0.0.2 -j DROP
```

**Risultato**: Ping fallisce - comunicazione bloccata senza autorizzazione esplicita

### Rischi Senza Microsegmentazione

#### Movimenti Laterali
- Compromissione di una macchina → accesso facile al resto della rete
- Propagazione malware senza ostacoli
- Pivoting e persistenza in reti "flat"

#### Superficie di Attacco Estesa
- Visibilità eccessiva tra sistemi
- Comunicazioni non controllate
- Privilegi eccessivi per i servizi

## Conclusioni

### Implementazione Stratificata

1. **Segmentazione Base**: VLAN per separazione logica
2. **Controllo Perimetrale**: Firewall con policy restrittive
3. **Connettività Sicura**: VPN per accessi remoti
4. **Monitoraggio Attivo**: IDS/IPS per rilevamento intrusioni
5. **Microsegmentazione**: Controllo granulare interno

### Best Practices

- **Default Deny**: Bloccare tutto, permettere solo necessario
- **Least Privilege**: Accesso minimo indispensabile
- **Monitoring Continuo**: Log e alerting su attività sospette
- **Segmentazione Multipla**: Livelli di isolamento sovrapposti
- **Zero Trust**: Verificare sempre, non fidarsi mai

### Strumenti Chiave

- **VLAN**: Segmentazione Layer 2
- **iptables**: Firewall Linux avanzato
- **OpenVPN**: VPN flessibile e sicura
- **Suricata**: IDS/IPS moderno e performante
- **Linux Namespaces**: Microsegmentazione containerizzata

---
