# Diario di Sicurezza Informatica

Documentazione tecnica di un percorso di apprendimento intensivo su sicurezza informatica, networking e amministrazione sistemi Linux/Windows. Questo repository contiene analisi pratiche, exploit sviluppati e tecniche di hardening testate in ambiente laboratorio.

## Quick Overview

# 📊 Statistiche del Progetto

- **🕐 Durata**: 10+ giorni intensivi
- **🖥️ Sistemi testati**: Linux (Manjaro, Kali, Ubuntu Server), Windows 11
- **⚡ Tools utilizzati**: 40+ strumenti di security
- **📝 Script sviluppati**: 20+ custom tools
- **🔍 Vulnerabilità identificate**: Multiple configuration issues
- **📋 Log analizzati**: 3000+ entries
- **🎯 Exploit sviluppati**: Buffer overflow, CAP_SYS_ADMIN privilege escalation, ARP spoofing MITM, SQL injection automation
- **🛡️ Tecniche difensive**: Filesystem security analysis, iptables logging, process monitoring, IDS development, VLAN segmentation, microsegmentazione

### 🎯 Competenze Sviluppate

- **Linux Security**: SUID/SGID exploitation, capabilities, ACL, filesystem security
- **Network Analysis**: Packet capture, protocol analysis, MITM attacks, reconnaissance  
- **Penetration Testing**: nmap, vulnerability assessment, buffer overflow exploitation
- **Digital Forensics**: /proc analysis, log correlation, incident response, registry analysis, malware analysis
- **Windows Security**: PowerShell security, process monitoring, persistence techniques
- **Binary Exploitation**: Buffer overflow development, shellcode injection, ASLR bypass
- **Web Application Security**: SQL injection, DVWA exploitation, database enumeration
- **Network Segmentation**: VLAN configuration, VPN setup, microsegmentazione, Zero Trust
- **Malware Analysis**: Static/dynamic analysis, reverse engineering, sandboxing

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
- **NEW**: VLAN configuration e Inter-VLAN routing
- **NEW**: VPN setup (OpenVPN, IPSec)
- **NEW**: Network microsegmentation e Zero Trust
- **NEW**: Firewall avanzato con iptables
- **NEW**: IDS/IPS con Suricata

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

### [🕷️ Exploits](docs/exploits/)
- **NEW**: DVWA SQL Injection exploitation
- **NEW**: Union-based SQL injection
- **NEW**: Database enumeration techniques
- **NEW**: Hash cracking e password analysis
- **NEW**: Web application vulnerability assessment

### [🔬 Forensic](docs/forensic/)
- **NEW**: Malware analysis metodologie
- **NEW**: Static analysis con PEStudio e Ghidra
- **NEW**: Dynamic analysis e sandboxing
- **NEW**: Reverse engineering techniques
- **NEW**: IoC identification e threat intelligence

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
- **VM 3**: Ubuntu Server (defensive testing, VLAN, VPN)
- **VM 4**: REMnux (malware analysis)

### Network Lab Setup
- **VLAN Segmentation**: Multiple isolated networks
- **VPN Infrastructure**: OpenVPN server/client setup
- **IDS/IPS**: Suricata monitoring
- **Microsegmentation**: Linux namespaces isolation

## 🛠️ Tools Principali

| Categoria | Strumenti |
|-----------|-----------|
| **Reconnaissance** | nmap, netdiscover, ping |
| **Network Analysis** | tshark, tcpdump, wireshark, Suricata |
| **Linux Security** | chattr, setfacl, getcap, setcap, find, lsof |
| **Binary Exploitation** | gdb, gcc, python3, pwntools, nasm |
| **Windows Analysis** | PowerShell, reg, bcdedit, netstat |
| **Monitoring** | journalctl, iptables, grep, tail |
| **Exploitation** | Python (scapy), C exploits, Ruby scripts, Bash automation |
| **Forensics** | lsof, ps, pgrep, /proc analysis, sqlite3 |
| **Web Security** | DVWA, SQLMap, Burp Suite, curl |
| **Malware Analysis** | PEStudio, Ghidra, Regshot, ProcMon, x64dbg |
| **Network Security** | Cisco Packet Tracer, OpenVPN, iptables |

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

### 🕷️ Web Application Security
- **SQL Injection** ancora molto diffusa in applicazioni legacy
- **Union-based techniques** efficaci per database enumeration
- **Information schema** exploitation rivela strutture complete
- **MD5 hashes** facilmente crackabili con dizionari

### 🔬 Malware Analysis
- **NSIS packers** comuni per RAT e trojan
- **Static analysis** rivela API calls e comportamenti
- **Dynamic analysis** necessaria per evasion techniques
- **Sandbox isolation** critica per analisi sicura

### 🌐 Network Security
- **VLAN segmentation** efficace per isolamento logico
- **Microsegmentazione** essenziale per Zero Trust
- **VPN encryption** garantisce confidenzialità traffico
- **IDS/IPS** detection basata su signature e anomalie

### 🖥️ Windows Security
- **Registry persistence** ancora molto efficace
- **PowerShell** analysis rivela pattern di attacco chiari
- **Process monitoring** essenziale per malware detection

### 🛡️ Defensive Capabilities
- **ACL** migliore di chattr +i per protezione log
- **Process analysis** con lsof e /proc filesystem potenti per forensics
- **Automated IDS** development possibile con script personalizzati
- **Real-time monitoring** efficace con journalctl e tail

## 📈 Skills Progression

```
Livello iniziale: Beginner
Livello finale:   Advanced
Tempo:           10+ giorni intensivi
Focus:           Hands-on practical testing + exploit development + malware analysis
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
- **NEW**: VLAN segmentation per isolamento critico
- **NEW**: IDS/IPS deployment per threat detection
- **NEW**: Sandbox isolation per malware analysis

### 🔴 Red Team Insights
- Capabilities exploitation richiede deep system knowledge
- Registry persistence ancora efficace su Windows
- Modern defenses richiedono multiple attack vectors
- Build-based OS detection più accurato
- ARP spoofing + MITM ancora devastante su reti locali
- **NEW**: Buffer overflow development richiede disabilitazione protezioni moderne
- **NEW**: SUID/SGID automation accelera privilege escalation discovery
- **NEW**: Filesystem analysis rivela weakness di sistema
- **NEW**: SQL injection automation con custom scripts
- **NEW**: NSIS malware packing elude detection classica
- **NEW**: Inter-VLAN routing required per lateral movement

### 👨‍💻 System Administrator Tips
- journalctl + grep = threat hunting efficace  
- Controllare capabilities pericolose sui binari
- Monitorare modifiche registry per early warning
- Rate limiting SSH per prevenire brute force
- Implementare monitoring proattivo dei processi sospetti
- **NEW**: Audit regolare di SUID/SGID binaries
- **NEW**: Filesystem hardening tramite /sys parameter tuning
- **NEW**: Automated security reporting per compliance
- **NEW**: Network microsegmentation per Zero Trust
- **NEW**: Malware sandboxing per incident response
- **NEW**: VPN monitoring per remote access security

## Come Navigare

1. **Inizia dal [Linux Security](docs/linux-security/)** per fondamentali e SUID/SGID
2. **Prosegui con [Networking](docs/networking/)** per analisi protocolli e VLAN
3. **Studia [Defensive Security](docs/defensive/)** per protezione e filesystem analysis
4. **Esplora [Offensive Security](docs/offensive/)** per buffer overflow e exploitation
5. **Analizza [Exploits](docs/exploits/)** per web application security
6. **Approfondisci [Forensic](docs/forensic/)** per malware analysis
7. **Completa con [Windows Security](docs/windows-security/)** per ambiente Windows

### 📚 Documentazione Tecnica
- **Filesystem Security Analysis**: Guida completa a /proc e /sys
- **Buffer Overflow Tutorial**: Step-by-step exploitation su Linux x86
- **SUID/SGID Exploitation**: Metodologie complete di privilege escalation
- **Defensive Security Framework**: Multi-layer defense implementation
- **SQL Injection Mastery**: Complete DVWA exploitation guide
- **Malware Analysis Methodology**: Static/dynamic analysis workflow
- **Network Segmentation Guide**: VLAN, VPN e microsegmentazione

## Laboratori Pratici Completati

### 🔬 Malware Analysis Lab
- **Setup**: REMnux + Windows VM isolate
- **Samples**: NSIS-packed RAT analysis
- **Tools**: PEStudio, Ghidra, Regshot, ProcMon
- **Risultati**: IoC extraction, behavior analysis

### 🕷️ Web Application Lab  
- **Target**: DVWA (Damn Vulnerable Web App)
- **Tecniche**: SQL injection, database enumeration
- **Tools**: Custom Python scripts, manual exploitation
- **Risultati**: Complete database dump, hash extraction

### 🌐 Network Security Lab
- **Infrastruttura**: Multi-VLAN environment
- **Servizi**: OpenVPN, Suricata IDS/IPS
- **Test**: Inter-VLAN routing, microsegmentazione
- **Risultati**: Zero Trust network implementation

### 💥 Binary Exploitation Lab
- **Target**: Custom vulnerable C programs
- **Tecniche**: Buffer overflow, shellcode injection
- **Environment**: Linux x86 con protezioni disabilitate
- **Risultati**: Remote code execution achievement

## Avvertenze

> ⚠️ **Nota Etica**: Tutti i test sono stati condotti su sistemi di proprietà personale in ambiente isolato per scopi educativi. Non utilizzare queste tecniche su sistemi non autorizzati.

> 📚 **Scopo Educativo**: Questa documentazione è destinata esclusivamente all'apprendimento e alla ricerca nella cybersecurity.

> 🔒 **Responsabilità**: L'utilizzo improprio di queste informazioni può costituire reato. L'autore non è responsabile per usi impropri.

> 🦠 **Malware Warning**: I sample di malware sono utilizzati solo per analisi educativa in ambiente completamente isolato.

---

**Autore**: Alessandro  
**Periodo**: Luglio 2025  
**Ultima Revisione**: 24 luglio 2025  
**Licenza**: Documentazione per uso educativo  

Per dettagli specifici, naviga nelle sezioni dedicate linkate sopra.
