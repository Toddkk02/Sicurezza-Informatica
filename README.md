# Diario di Sicurezza Informatica

Documentazione tecnica di un percorso di apprendimento intensivo su sicurezza informatica, networking e amministrazione sistemi Linux/Windows. Questo repository contiene analisi pratiche, exploit sviluppati e tecniche di hardening testate in ambiente laboratorio.

## Quick Overview

# 📊 Statistiche del Progetto

- **🕐 Durata**: 7+ giorni intensivi
- **🖥️ Sistemi testati**: Linux (Manjaro, Kali), Windows 11
- **⚡ Tools utilizzati**: 30+ strumenti di security
- **📝 Script sviluppati**: 15+ custom tools
- **🔍 Vulnerabilità identificate**: Multiple configuration issues
- **📋 Log analizzati**: 2000+ entries
- **🎯 Exploit sviluppati**: Buffer overflow, CAP_SYS_ADMIN privilege escalation, ARP spoofing MITM
- **🛡️ Tecniche difensive**: Filesystem security analysis, iptables logging, process monitoring, IDS development

### 🎯 Competenze Sviluppate

- **Linux Security**: SUID/SGID exploitation, capabilities, ACL, filesystem security
- **Network Analysis**: Packet capture, protocol analysis, MITM attacks, reconnaissance  
- **Penetration Testing**: nmap, vulnerability assessment, buffer overflow exploitation
- **Digital Forensics**: /proc analysis, log correlation, incident response, registry analysis
- **Windows Security**: PowerShell security, process monitoring, persistence techniques
- **Binary Exploitation**: Buffer overflow development, shellcode injection, ASLR bypass

## Aree di Studio

### [🐧 Linux Security](docs/linux-security/)
- Permessi speciali (chattr, lsattr)
- Linux Capabilities e privilege escalation
- Access Control Lists (ACL)
- **NEW**: SUID/SGID Exploitation con script automatizzati
- Exploit CAP_SYS_ADMIN sviluppato

### [🌐 Networking](docs/networking/)
- Stack TCP/IP vs modello OSI
- Packet analysis con tshark/tcpdump
- Subnetting e calcoli di rete
- Port scanning con nmap

### [🛡️ Defensive Security](docs/defensive/)
- Log analysis con journalctl
- Firewall configuration (iptables)
- SSH forensics e incident response
- Port scan detection
- **NEW**: Filesystem Security Analysis (/proc, /sys monitoring)
- **NEW**: IDS development e honeypot deployment

### [💥 Offensive Security](docs/offensive/)
- **NEW**: Buffer Overflow exploitation su Linux x86
- **NEW**: ASLR bypass techniques con brute force
- CAP_SYS_ADMIN privilege escalation
- Windows registry persistence
- **NEW**: SUID/SGID privilege escalation automation

### [🖥️ Windows Security](docs/windows-security/)
- PowerShell security analysis
- Registry forensics e persistence
- Process monitoring e detection
- Privilege analysis

## Ambiente di Laboratorio

### VM Configuration
- **Host**: Manjaro Linux (sistema principale)
- **VM 1**: Kali Linux (offensive tools)
- **VM 2**: Windows 11 (target testing)
- **VM 3**: Ubuntu Server (defensive testing)

## 🛠️ Tools Principali

| Categoria | Strumenti |
|-----------|-----------|
| **Reconnaissance** | nmap, netdiscover, ping |
| **Network Analysis** | tshark, tcpdump, wireshark |
| **Linux Security** | chattr, setfacl, getcap, setcap, find, lsof |
| **Binary Exploitation** | gdb, gcc, python3, pwntools, nasm |
| **Windows Analysis** | PowerShell, reg, bcdedit, netstat |
| **Monitoring** | journalctl, iptables, grep, tail |
| **Exploitation** | Python (scapy), C exploits, Ruby scripts, Bash automation |
| **Forensics** | lsof, ps, pgrep, /proc analysis, sqlite3 |

## 🔍 Scoperte Principali

### 🐧 Linux Security
- **Defense in depth** efficace contro exploit classici
- **SUID/SGID** automation possibile con find e script personalizzati
- **Filesystem virtuale** (/proc, /sys) fonte cruciale per security monitoring
- **Capabilities** come CAP_SYS_ADMIN quasi equivale a root

### 💥 Binary Exploitation
- **Buffer overflow** su x86 ancora funzionante con protezioni disabilitate
- **ASLR bypass** possibile con brute force su sistemi 32-bit
- **Shellcode injection** richiede conoscenza approfondita assembly
- **Modern protections** (Stack Canaries, NX bit) aumentano difficoltà significativamente

### 🖥️ Windows Security
- **Registry persistence** ancora molto efficace
- **PowerShell** analysis rivela pattern di attacco chiari
- **Process monitoring** essenziale per malware detection

### 🌐 Network Security
- **iptables logging** ottimo per detection
- **ARP spoofing** funziona ancora e rimane invisibile
- **MITM attacks** devastanti su reti locali
- **Port scan detection** facilmente implementabile

### 🛡️ Defensive Capabilities
- **ACL** migliore di chattr +i per protezione log
- **Process analysis** con lsof e /proc filesystem potenti per forensics
- **Automated IDS** development possibile con script personalizzati
- **Real-time monitoring** efficace con journalctl e tail

## 📈 Skills Progression

```
Livello iniziale: Beginner
Livello finale:   Advanced
Tempo:           7+ giorni intensivi
Focus:           Hands-on practical testing + exploit development
```

## Best Practices Identificate

### 🔵 Blue Team Best Practices
- Implementare iptables logging per network monitoring
- Monitorare registry Windows con script automatici
- Utilizzare ACL invece di chattr +i per protezione log
- Analizzare CommandLine processi per malware detection
- **NEW**: Monitoring continuo di /proc e /sys per anomalie
- **NEW**: Automated compliance reporting con HTML dashboard
- **NEW**: Database-driven log analysis per pattern recognition

### 🔴 Red Team Insights
- Capabilities exploitation richiede deep system knowledge
- Registry persistence ancora efficace su Windows
- Modern defenses richiedono multiple attack vectors
- Build-based OS detection più accurato
- ARP spoofing + MITM ancora devastante su reti locali
- **NEW**: Buffer overflow development richiede disabilitazione protezioni moderne
- **NEW**: SUID/SGID automation accelera privilege escalation discovery
- **NEW**: Filesystem analysis rivela weakness di sistema

### 👨‍💻 System Administrator Tips
- journalctl + grep = threat hunting efficace  
- Controllare capabilities pericolose sui binari
- Monitorare modifiche registry per early warning
- Rate limiting SSH per prevenire brute force
- Implementare monitoring proattivo dei processi sospetti
- **NEW**: Audit regolare di SUID/SGID binaries
- **NEW**: Filesystem hardening tramite /sys parameter tuning
- **NEW**: Automated security reporting per compliance

## Come Navigare

1. **Inizia dal [Linux Security](docs/linux-security/)** per fondamentali e SUID/SGID
2. **Prosegui con [Networking](docs/networking/)** per analisi protocolli
3. **Studia [Defensive Security](docs/defensive/)** per protezione e filesystem analysis
4. **Esplora [Offensive Security](docs/offensive/)** per buffer overflow e exploitation
5. **Analizza [Windows Security](docs/windows-security/)** per ambiente Windows


### 📚 Documentazione Tecnica
- **Filesystem Security Analysis**: Guida completa a /proc e /sys
- **Buffer Overflow Tutorial**: Step-by-step exploitation su Linux x86
- **SUID/SGID Exploitation**: Metodologie complete di privilege escalation
- **Defensive Security Framework**: Multi-layer defense implementation

## Avvertenze

> ⚠️ **Nota Etica**: Tutti i test sono stati condotti su sistemi di proprietà personale in ambiente isolato per scopi educativi. Non utilizzare queste tecniche su sistemi non autorizzati.

> 📚 **Scopo Educativo**: Questa documentazione è destinata esclusivamente all'apprendimento e alla ricerca nella cybersecurity.

> 🔒 **Responsabilità**: L'utilizzo improprio di queste informazioni può costituire reato. L'autore non è responsabile per usi impropri.

---

**Autore**: Alessandro  
**Periodo**: Luglio 2025  
**Ultima Revisione**: 22 luglio 2025  
**Licenza**: Documentazione per uso educativo  

Per dettagli specifici, naviga nelle sezioni dedicate linkate sopra.
