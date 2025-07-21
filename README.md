# Diario di Sicurezza Informatica

Documentazione tecnica di un percorso di apprendimento intensivo su sicurezza informatica, networking e amministrazione sistemi Linux/Windows. Questo repository contiene analisi pratiche, exploit sviluppati e tecniche di hardening testate in ambiente laboratorio.


## Quick Overview
# 📊 Statistiche del Progetto
- **🕐 Durata**: 5+ giorni intensivi
- **🖥️ Sistemi testati**: Linux (Manjaro, Kali), Windows 11
- **⚡ Tools utilizzati**: 25+ strumenti di security
- **📝 Script sviluppati**: 8+ custom tools
- **🔍 Vulnerabilità identificate**: Multiple configuration issues
- **📋 Log analizzati**: 1000+ entries
- **🎯 Exploit sviluppati**: CAP_SYS_ADMIN privilege escalation, ARP spoofing MITM
- **🛡️ Tecniche difensive**: ACL hardening, iptables logging, process monitoring

### 🎯 Competenze Sviluppate
- **Linux Security**: Permessi avanzati, capabilities, ACL
- **Network Analysis**: Packet capture, protocol analysis, reconnaissance  
- **Penetration Testing**: nmap, vulnerability assessment, exploitation
- **Digital Forensics**: Log analysis, incident response, registry analysis
- **Windows Security**: PowerShell security, process monitoring, persistence

## Aree di Studio

### [🐧 Linux Security](docs/linux-security/)
- Permessi speciali (chattr, lsattr)
- Linux Capabilities e privilege escalation
- Access Control Lists (ACL)
- Exploit CAP_SYS_ADMIN sviluppato

### [🌐 Networking](docs/networking/)
- Stack TCP/IP vs modello OSI
- Packet analysis con tshark/tcpdump
- Subnetting e calcoli di rete
- Port scanning con nmap

### [🛡️ Defensive Security](docs/defensive-security/)
- Log analysis con journalctl
- Firewall configuration (iptables)
- SSH forensics e incident response
- Port scan detection

### [🖥️ Windows Security](docs/windows-security/)
- PowerShell security analysis
- Registry forensics e persistence
- Process monitoring e detection
- Privilege analysis

### [💥 Exploit Development](docs/exploits/)
- CAP_SYS_ADMIN privilege escalation
- Windows registry persistence
- Malware simulation per testing

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
| **Linux Security** | chattr, setfacl, getcap, setcap |
| **Windows Analysis** | PowerShell, reg, bcdedit, netstat |
| **Monitoring** | journalctl, iptables, grep |
| **Exploitation** | Python (scapy), C exploits, Bash scripts |
| **Forensics** | lsof, ps, pgrep, Process analysis |

## Key Findings Highlights

## 🔍 Scoperte Principali
- **🐧 Linux**: Defense in depth efficace contro exploit classici
- **🖥️ Windows**: Registry persistence ancora molto efficace
- **🌐 Network**: iptables logging ottimo per detection, ARP spoofing funziona ancora
- **🔒 ACL**: Migliore di chattr +i per protezione log
- **⚡ Capabilities**: CAP_SYS_ADMIN quasi equivale a root
- **🕵️ MITM**: ARP spoofing invisibile alle vittime, intercettazione HTTP riuscita
- **📊 Process Analysis**: lsof e /proc filesystem potenti per forensics

### 📈 Skills Progression
```
Livello iniziale: Beginner
Livello finale:   Intermediate-Advanced
Tempo:           3+ giorni intensivi
Focus:           Hands-on practical testing
```

## Best Practices Identificate

## 🔵 Blue Team Best Practices
- Implementare iptables logging per network monitoring
- Monitorare registry Windows con script automatici
- Utilizzare ACL invece di chattr +i per protezione log
- Analizzare CommandLine processi per malware detection

## 🔴 Red Team Insights
- Capabilities exploitation richiede deep system knowledge
- Registry persistence ancora efficace su Windows
- Modern defenses richiedono multiple attack vectors
- Build-based OS detection più accurato
- ARP spoofing + MITM ancora devastante su reti locali

## 👨‍💻 System Administrator Tips
- journalctl + grep = threat hunting efficace
- Controllare capabilities pericolose sui binari
- Monitorare modifiche registry per early warning
- Rate limiting SSH per prevenire brute force
- Implementare monitoring proattivo dei processi sospetti

## Come Navigare

1. **Inizia dal [Linux Security](docs/linux-security/)** per fondamentali
2. **Prosegui con [Networking](docs/networking/)** per analisi protocolli
3. **Studia [Defensive Security](docs/defensive-security/)** per protezione
4. **Esplora [Windows Security](docs/windows-security/)** per ambiente Windows
5. **Analizza [Exploits](docs/exploits/)** per tecniche offensive

## Avvertenze

> ⚠️ **Nota Etica**: Tutti i test sono stati condotti su sistemi di proprietà personale in ambiente isolato per scopi educativi. Non utilizzare queste tecniche su sistemi non autorizzati.

> 📚 **Scopo Educativo**: Questa documentazione è destinata esclusivamente all'apprendimento e alla ricerca nella cybersecurity.

---

**Autore**: Alessandro  
**Periodo**: Luglio 2025  
**Licenza**: Documentazione per uso educativo  

Per dettagli specifici, naviga nelle sezioni dedicate linkate sopra.
