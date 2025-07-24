# Linux Forensics

Documentazione completa su analisi dei processi, memory forensics, log analysis e tecniche di threat hunting su sistemi Linux. Include detection di malware, incident response e metodologie investigative.

## Indice

- [Process Analysis](#process-analysis)
- [Memory Forensics](#memory-forensics)
- [Log Analysis con journalctl](#log-analysis-con-journalctl)
- [Network Monitoring](#network-monitoring)
- [Malware Detection](#malware-detection)
- [Incident Response](#incident-response)
- [Threat Hunting Techniques](#threat-hunting-techniques)
- [Best Practices](#best-practices)
  [Malware Analysis](malware_analysis_guide.md)
## Process Analysis

### Comandi Base per Analisi Processi

#### ps aux - Vista Completa Sistema

```bash
# Vista completa tutti i processi
ps aux

# Output formato:
# USER    PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND
# root      1  0.0  0.0  22348 13220 ?     Ss   13:07   0:12 /sbin/init splash
# root      2  0.0  0.0      0     0 ?     S    13:07   0:00 [kthreadd]
```

**Significato colonne**:
- **USER**: Proprietario del processo
- **PID**: Process ID (identificativo univoco)
- **%CPU**: Percentuale utilizzo CPU
- **%MEM**: Percentuale utilizzo RAM
- **VSZ**: Memoria virtuale usata (KB)
- **RSS**: Memoria fisica usata (KB)
- **TTY**: Terminale associato (se presente)
- **STAT**: Stato processo (S=Sleep, R=Running, Z=Zombie, ecc.)
- **START**: Orario di avvio
- **TIME**: Tempo CPU consumato
- **COMMAND**: Comando completo

#### Conteggio e Filtering

```bash
# Contare processi totali
ps aux | wc -l
# Output: 405

# Vista ad albero (mostra relazioni parent-child)
ps aux --forest > process_tree.txt

# Ordinamento per CPU usage
ps aux --sort=-%cpu | head -10

# Ordinamento per memoria
ps aux --sort=-%mem | head -10

# Filtraggio per utente specifico
ps aux | grep alessandro

# Processi in directory specifica
ps aux | grep /tmp
```

### pgrep - Process Grep

Strumento specializzato per trovare processi per nome.

```bash
# Trova PID di processo per nome
pgrep zsh
# Output: 1669

# Primo processo trovato
pgrep zsh | head -1
# Output: 1669

# Tutti i processi di un utente
pgrep -u alessandro

# Con informazioni dettagliate
pgrep -l firefox
# Output: 1828 firefox

# Pattern matching complesso
pgrep -f "python.*script"
```

### lsof - List Open Files

Mostra tutti i file aperti da processi specifici.

#### Analisi File Aperti

```bash
# File aperti da processo specifico
PID=$(pgrep zsh | head -1)
lsof -p $PID
```

**Output tipico**:
```
COMMAND  PID       USER  FD   TYPE DEVICE SIZE/OFF    NODE NAME
zsh     1669 alessandro cwd    DIR   0,45       98 1058428 /home/alessandro/Desktop/...
zsh     1669 alessandro rtd    DIR   0,29      216     256 /
zsh     1669 alessandro txt    REG   0,29   947360    3132 /usr/bin/zsh
zsh     1669 alessandro mem    REG   0,27           373476 /usr/lib/locale/locale-archive
zsh     1669 alessandro   0u   CHR  136,2      0t0       5 /dev/pts/2
zsh     1669 alessandro   1u   CHR  136,2      0t0       5 /dev/pts/2
zsh     1669 alessandro   2u   CHR  136,2      0t0       5 /dev/pts/2
```

**Significato colonne**:
- **FD**: File Descriptor (cwd=current dir, txt=executable, mem=memory map)
- **TYPE**: Tipo file (REG=regular, DIR=directory, CHR=character device)
- **DEVICE**: Device che contiene il file
- **SIZE/OFF**: Dimensione o offset
- **NODE**: Inode number
- **NAME**: Path completo del file

#### File di Configurazione

```bash
# File configurazione aperti da processo
lsof -p $PID | grep -E "(etc|config)"

# Per systemd (esempio)
sudo lsof -p $(pgrep systemd | head -1) | grep etc
```

**Output esempio**:
```
systemd   1 root  82u unix /etc/pacman.d/gnupg/S.dirmngr
systemd   1 root  83u unix /etc/pacman.d/gnupg/S.gpg-agent.browser
systemd   1 root  84u unix /etc/pacman.d/gnupg/S.gpg-agent.extra
```

#### Connessioni di Rete

```bash
# Connessioni di rete per processo
lsof -p $PID -i

# Esempio output Firefox e Spotify:
# firefox   1828 alessandro  46u  IPv4 220692 TCP TheArrival:49088->github.com:https (ESTABLISHED)
# spotify   2319 alessandro 104u  IPv4  20339 TCP TheArrival:34902->44.224.186.35:https (ESTABLISHED)
```

### Informazioni Dettagliate Processo

#### Comando ps Esteso

```bash
# Informazioni specifiche processo
PID=$(pgrep zsh | head -1)
ps -p $PID -o pid,ppid,user,cmd,etime,pcpu,pmem
```

**Output**:
```
PID    PPID USER     CMD                             ELAPSED %CPU %MEM
1669   1646 alessan+ /bin/zsh                       04:40:44  0.0  0.0
```

**Informazioni mostrate**:
- **PID**: Process ID
- **PPID**: Parent Process ID
- **USER**: Utente proprietario
- **CMD**: Comando completo
- **ELAPSED**: Tempo di esecuzione
- **%CPU**: Utilizzo CPU
- **%MEM**: Utilizzo memoria

## Memory Forensics

### /proc Filesystem Analysis

Il filesystem `/proc` fornisce accesso diretto alle informazioni dei processi kernel.

#### Memory Mapping

```bash
# Mappatura memoria processo
cat /proc/$PID/maps
```

**Output esempio**:
```
55f297771000-55f29778c000 r--p 00000000 00:1b 1924    /usr/bin/bash
55f29778c000-55f29784b000 r-xp 0001b000 00:1b 1924    /usr/bin/bash
55f297877000-55f29787a000 r--p 00106000 00:1b 1924    /usr/bin/bash
55f29787e000-55f29788d000 rw-p 00000000 00:00 0       [heap]
7f3b0d600000-7f3b0d8ed000 r--p 00000000 00:1b 373476 /usr/lib/locale/locale-archive
7ffc6411f000-7ffc64141000 rw-p 00000000 00:00 0       [stack]
```

**Analisi formato**:
- **Range memoria**: `55f297771000-55f29778c000`
- **Permessi**: `r--p` (read, no-write, no-execute, private)
- **Offset**: `00000000`
- **Device**: `00:1b`
- **Inode**: `1924`
- **File**: `/usr/bin/bash`

**Aree speciali**:
- `[heap]`: Area heap del processo
- `[stack]`: Stack del processo
- `[vdso]`: Virtual Dynamic Shared Object
- `[vsyscall]`: Virtual system call

#### Command Line Analysis

```bash
# Command line completa processo
cat /proc/$PID/cmdline
# Output: /bin/bash/tmp/system_update

# Versione leggibile
cat /proc/$PID/cmdline | tr '\0' ' '
# Output: /bin/bash /tmp/system_update
```

**Nota**: Gli argomenti sono separati da caratteri NULL (`\0`).

#### Environment Variables

```bash
# Variabili ambiente processo
cat /proc/$PID/environ | tr '\0' '\n'
```

#### Status Information

```bash
# Informazioni dettagliate stato
cat /proc/$PID/status
```

**Output contiene**:
- Name, Pid, PPid
- TracerPid (se under debug)
- Uid, Gid (reale ed effective)
- FDSize (file descriptors)
- VmPeak, VmSize (memoria virtuale)
- VmRSS (memoria fisica)

#### File Descriptors

```bash
# Lista file descriptors aperti
ls -la /proc/$PID/fd/

# Output esempio:
# lrwx------ 1 alessandro alessandro 64 21 lug 13:35 0 -> /dev/pts/3
# lrwx------ 1 alessandro alessandro 64 21 lug 13:35 1 -> /dev/pts/3
# lrwx------ 1 alessandro alessandro 64 21 lug 13:35 2 -> /dev/pts/3
# lr-x------ 1 alessandro alessandro 64 21 lug 13:35 255 -> /tmp/system_update
```

## Log Analysis con journalctl

### Comandi Base journalctl

```bash
# Visualizza tutti i log
sudo journalctl

# Ultime 10 righe + follow
sudo journalctl -n 10 -f

# Log di oggi
sudo journalctl --since today

# Log ultima ora
sudo journalctl --since '1 hour ago'

# Log periodo specifico
sudo journalctl --since '2025-07-17 15:00:00'

# Output in formato JSON
sudo journalctl -o json
```

### Analisi per Servizio

```bash
# Log servizio specifico
sudo journalctl -u sshd

# Follow log SSH in tempo reale
sudo journalctl -u sshd -f

# Log con priorità specifica
sudo journalctl -p err     # Solo errori
sudo journalctl -p warning # Warning e superiori
sudo journalctl -p info    # Info e superiori
```

### SSH Forensics

#### Tentivi di Accesso Falliti

```bash
# Tentativi SSH falliti
sudo journalctl -u sshd | grep "Failed"
```

**Output esempio**:
```
lug 17 17:50:49 TheArrival sshd-session[56903]: Failed password for alessandro from ::1 port 49600 ssh2
lug 17 17:56:15 TheArrival sshd-session[57457]: Failed password for alessandro from 192.168.130.234 port 44504 ssh2
```

#### Accessi Riusciti

```bash
# Accessi SSH riusciti
sudo journalctl -u sshd | grep "Accepted"
```

**Output esempio**:
```
lug 17 17:56:19 TheArrival sshd-session[57457]: Accepted password for alessandro from 192.168.130.234 port 44504 ssh2
lug 17 17:56:19 TheArrival sshd-session[57457]: pam_unix(sshd:session): session opened for user alessandro(uid=1000) by alessandro(uid=0)
```

#### Escalation Privilege

```bash
# Comandi sudo eseguiti
sudo journalctl | grep "sudo"
```

**Output esempio**:
```
lug 17 17:58:00 TheArrival sudo[57563]: alessandro : TTY=pts/11 ; PWD=/home/alessandro ; USER=root ; COMMAND=/usr/bin/su
lug 17 17:58:00 TheArrival su[57572]: (to root) root on pts/12
lug 17 17:58:00 TheArrival su[57572]: pam_unix(su:session): session opened for user root(uid=0) by alessandro(uid=0)
```

**Analisi**:
- Utente `alessandro` ha eseguito `su` per diventare root
- Escalation successful da UID 1000 a UID 0
- Sessione aperta su terminal `pts/12`

### Pattern di Attacco

#### Brute Force Detection

```bash
# Script per detection brute force SSH
#!/bin/bash
echo "=== SSH BRUTE FORCE DETECTION ==="

# Conta tentativi falliti per IP
sudo journalctl -u sshd --since today | \
grep "Failed password" | \
awk '{print $NF}' | sort | uniq -c | sort -rn

# IPs con più di 5 tentativi falliti
sudo journalctl -u sshd --since today | \
grep "Failed password" | \
awk '{print $NF}' | sort | uniq -c | \
awk '$1 > 5 {print "🚨 ALERT: " $2 " - " $1 " attempts"}'
```

#### Timeline Analysis

```bash
# Timeline completa attacco
sudo journalctl --since '2025-07-17 17:50:00' --until '2025-07-17 18:00:00' | \
grep -E "(Failed|Accepted|sudo|su)" | \
sort
```

## Network Monitoring

### iptables Logging per Detection

#### Setup Logging

```bash
# Aggiungere regola logging per scan detection
sudo iptables -I INPUT -j LOG --log-prefix 'SCAN DETECT: '

# Monitoring in tempo reale
sudo journalctl -f | grep 'SCAN DETECT'
```

#### Analisi Traffico

**Output esempio durante scan nmap**:
```
lug 18 09:49:40 kernel: SCAN DETECT: IN=lo OUT= MAC=00:00:... SRC=192.168.130.xxx DST=192.168.130.xxx PROTO=TCP SPT=56292 DPT=1106 FLAGS=SYN
lug 18 09:49:40 kernel: SCAN DETECT: IN=lo OUT= MAC=00:00:... SRC=192.168.130.xxx DST=192.168.130.xxx PROTO=TCP SPT=1106 DPT=56292 FLAGS=ACK RST
```

**Analisi**:
- **SRC/DST**: IP sorgente e destinazione
- **PROTO**: Protocollo (TCP/UDP/ICMP)
- **SPT/DPT**: Source/Destination Port
- **FLAGS**: Flag TCP (SYN, ACK, RST, PSH)

#### Pattern Recognition

```bash
# Script detection port scan
#!/bin/bash
echo "=== PORT SCAN DETECTION ==="

# Conteggia connessioni per IP
sudo journalctl --since '1 hour ago' | \
grep 'SCAN DETECT' | \
awk '{for(i=1;i<=NF;i++) if($i~/SRC=/) print $i}' | \
sort | uniq -c | sort -rn

# IPs con più di 100 tentativi
sudo journalctl --since '1 hour ago' | \
grep 'SCAN DETECT' | \
awk '{for(i=1;i<=NF;i++) if($i~/SRC=/) print $i}' | \
sort | uniq -c | \
awk '$1 > 100 {gsub(/SRC=/, "", $2); print "🚨 PORT SCAN: " $2 " - " $1 " attempts"}'
```

## Malware Detection

### Creazione Scenario Test

#### Malware Simulato

```bash
# Script malware di test
cat > /tmp/system_update << 'EOF'
#!/bin/bash
while true; do
  cat /etc/passwd > /dev/null
  cat /etc/shadow > /dev/null
  ping -c 1 8.8.8.8 > /dev/null
  sleep 5
done
EOF

chmod +x /tmp/system_update
```

**Comportamenti sospetti**:
- Lettura continua `/etc/passwd` e `/etc/shadow`
- Comunicazioni esterne (DNS Google)
- Loop infinito
- Posizione in `/tmp`

#### Esecuzione in Background

```bash
# Avvio malware simulato
/tmp/system_update &
MALWARE_PID=$!
echo "Malware PID: $MALWARE_PID"
```

### Tecniche di Detection

#### 1. High CPU Usage Detection

```bash
# Processi ad alto uso CPU
ps aux --sort=-%cpu | head -10
```

#### 2. Location-Based Detection

```bash
# Processi in directory sospette
ps aux | grep -E "(/tmp|/var/tmp|/dev/shm)"

# Output:
# alessan+ 28160  0.0  0.0   7576  5508 pts/3  SN   13:35   0:00 /bin/bash /tmp/system_update
```

#### 3. Behavior Analysis

```bash
# File aperti dal processo sospetto
SUSP_PID=28160
lsof -p $SUSP_PID
```

**Output**:
```
COMMAND     PID       USER  FD   TYPE DEVICE SIZE/OFF   NODE NAME
system_up 28160 alessandro cwd    DIR   0,47      974    257 /home/alessandro
system_up 28160 alessandro txt    REG   0,29  1100536   1924 /usr/bin/bash
system_up 28160 alessandro 255r   REG   0,39      146    228 /tmp/system_update
```

**Indicatori sospetti**:
- Script bash in `/tmp`
- File descriptor `255r` (script in sola lettura)
- Working directory diversa da location script

#### 4. Network Behavior

```bash
# Connessioni di rete del processo
lsof -p $SUSP_PID -i
# (Nessun output = nessuna connessione attiva permanente)

# Ma monitoriamo traffico di rete
sudo netstat -tulnp | grep $SUSP_PID
```

#### 5. System Call Tracing

```bash
# Trace system calls (se strace disponibile)
sudo strace -p $SUSP_PID -f -e trace=file,network

# Output mostrerebbe:
# openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
# openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)
# socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 3
```

### Memory Analysis Approfondita

#### Memory Maps

```bash
# Memory mapping del processo sospetto
cat /proc/$SUSP_PID/maps
```

**Output indica**:
- Aree di memoria utilizzate
- Librerie caricate
- Permessi memoria (rwx)
- File mappati

#### Command Line Forensics

```bash
# Command line con cui è stato lanciato
cat /proc/$SUSP_PID/cmdline | tr '\0' ' '
# Output: /bin/bash /tmp/system_update
```

#### Process Status

```bash
# Informazioni dettagliate stato
cat /proc/$SUSP_PID/status | grep -E "(Name|Pid|PPid|TracerPid|Uid|Gid)"
```

**Output**:
```
Name:   system_update
Pid:    28160
PPid:   3156
TracerPid:      0
Uid:    1000    1000    1000    1000
Gid:    1000    1000    1000    1000
```

### Process Tree Analysis

```bash
# Visualizza albero processi
ps aux --forest | grep -A 5 -B 5 $SUSP_PID

# Output mostra relazioni parent-child:
#  \_ /usr/bin/konsole
#      \_ /bin/zsh
#          \_ /bin/bash /tmp/system_update
```

## Incident Response

### Processo di Investigazione

#### 1. Identificazione Iniziale

```bash
# Step 1: Identificare processi sospetti
ps aux | grep -E "(/tmp|/var/tmp)" > suspect_processes.txt

# Step 2: Informazioni dettagliate
for pid in $(awk '{print $2}' suspect_processes.txt | tail -n +2); do
    echo "=== PID $pid ==="
    ps -p $pid -o pid,ppid,user,cmd,etime,pcpu,pmem
    echo "Command line: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
    echo "Files opened:"
    lsof -p $pid 2>/dev/null | head -10
    echo ""
done
```

#### 2. Network Analysis

```bash
# Connessioni di rete processo
lsof -p $SUSP_PID -i

# Traffico di rete corrente
sudo netstat -tulnp | grep $SUSP_PID

# DNS queries (se tcpdump disponibile)
sudo tcpdump -i any -n 'port 53' | grep -i $(cat /proc/$SUSP_PID/comm)
```

#### 3. File System Impact

```bash
# File creati/modificati di recente
find /tmp /var/tmp -newer /var/log/boot.log 2>/dev/null

# File con attributi sospetti
find /tmp -type f -executable 2>/dev/null

# Controllo integrità
ls -la /etc/passwd /etc/shadow /etc/hosts
```

#### 4. Log Correlation

```bash
# Cerca tracce nei log di sistema
sudo journalctl --since '1 hour ago' | grep -i -E "($(cat /proc/$SUSP_PID/comm)|$SUSP_PID)"

# Log di sicurezza
sudo journalctl -u sshd --since today | grep -v "session closed"

# Modifiche sudo/su
sudo journalctl --since today | grep -E "(sudo|su\[)"
```

### Containment e Eradication

#### 1. Process Termination

```bash
# Terminazione graceful
kill $SUSP_PID

# Terminazione forzata se necessario
kill -9 $SUSP_PID

# Verifica terminazione
ps -p $SUSP_PID
# Output: (nessun output = processo terminato)
```

#### 2. File Cleanup

```bash
# Rimozione file malware
rm -f /tmp/system_update

# Pulizia directory temporanee
find /tmp -type f -name "*system*" -delete

# Verifica rimozione
ls -la /tmp/system*
# Output: ls: cannot access '/tmp/system*': No such file or directory
```

#### 3. System State Verification

```bash
# Verifica nessun processo residuo
ps aux | grep system_update

# Controllo connessioni di rete anomale
sudo netstat -tulnp | grep -E "(:8080|:4444|:31337)"

# Verifica integrità file sistema
sudo find / -name ".*" -path "/tmp/*" -o -path "/var/tmp/*" 2>/dev/null
```

## Threat Hunting Techniques

### Proactive Hunting

#### 1. Process Anomaly Detection

```bash
#!/bin/bash
# Script hunting anomalie processi

echo "=== THREAT HUNTING: PROCESS ANOMALIES ==="

# Processi con nomi numerici (sospetti)
echo "🔍 Processi con nomi numerici:"
ps aux | awk '$11 ~ /^[0-9]+$/ {print $2, $11}'

# Processi in directory inusuali
echo "🔍 Processi in location sospette:"
ps aux | grep -E "/tmp/|/var/tmp/|/dev/shm/|/home/.*/\."

# Processi con uso CPU > 50%
echo "🔍 Processi ad alto CPU:"
ps aux --sort=-%cpu | awk '$3 > 50 {print $2, $3, $11}'

# Processi senza TTY associato (potenziali backdoor)
echo "🔍 Processi senza TTY:"
ps aux | awk '$7 == "?" && $2 > 1000 {print $2, $11}'
```

#### 2. Network Connection Hunting

```bash
#!/bin/bash
# Script hunting connessioni sospette

echo "=== THREAT HUNTING: NETWORK CONNECTIONS ==="

# Connessioni su porte non standard
echo "🔍 Connessioni porte sospette:"
sudo netstat -tulnp | grep -E ":(4444|31337|8080|9999|1234)"

# Processi con molte connessioni
echo "🔍 Processi con multiple connessioni:"
sudo netstat -tulnp | awk '{print $NF}' | grep "/" | sort | uniq -c | sort -rn | head -5

# Connessioni verso IP sospetti (esempio)
echo "🔍 Connessioni verso IP esterni non comuni:"
sudo netstat -tulnp | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | \
grep -v -E "(192\.168\.|10\.|172\.|127\.)" | sort | uniq
```

#### 3. File System Hunting

```bash
#!/bin/bash
# Script hunting file system

echo "=== THREAT HUNTING: FILE SYSTEM ==="

# File eseguibili in directory tmp
echo "🔍 Eseguibili in /tmp:"
find /tmp -type f -executable 2>/dev/null

# File con SUID bit in location sospette
echo "🔍 SUID files sospetti:"
find /tmp /var/tmp -perm -4000 -type f 2>/dev/null

# File con nomi nascosti
echo "🔍 File nascosti in /tmp:"
find /tmp -name ".*" -type f 2>/dev/null

# File modificati nelle ultime 24h
echo "🔍 File recenti in system directories:"
find /usr/bin /usr/sbin -type f -mtime -1 2>/dev/null
```

### Behavioral Analysis

#### 1. User Activity Patterns

```bash
# Analisi attività utente
echo "=== USER ACTIVITY ANALYSIS ==="

# Login patterns
sudo journalctl --since today | grep -E "session (opened|closed)" | \
awk '{print $1, $2, $3, $NF}' | sort

# Comando eseguiti con sudo
sudo journalctl --since today | grep sudo | \
awk '{print $3, $5, $NF}' | sort | uniq -c
```

#### 2. System Changes

```bash
# Cambiamenti sistema
echo "=== SYSTEM CHANGES ==="

# Nuovi processi (confronto con baseline)
ps aux > /tmp/current_processes.txt
if [ -f /tmp/baseline_processes.txt ]; then
    echo "🔍 Nuovi processi:"
    diff /tmp/baseline_processes.txt /tmp/current_processes.txt | grep "^>" | awk '{print $3, $12}'
fi

# Connessioni di rete nuove
sudo netstat -tulnp > /tmp/current_connections.txt
if [ -f /tmp/baseline_connections.txt ]; then
    echo "🔍 Nuove connessioni:"
    diff /tmp/baseline_connections.txt /tmp/current_connections.txt | grep "^>"
fi
```

## Best Practices

### Per Blue Team Defenders

#### 1. Monitoring Automatizzato

```bash
# Script monitoring continuo
#!/bin/bash
# /usr/local/bin/security_monitor.sh

LOG_FILE="/var/log/security_monitor.log"
ALERT_THRESHOLD=10

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Check processi sospetti
    SUSP_COUNT=$(ps aux | grep -E "/tmp/|/var/tmp/" | wc -l)
    if [ $SUSP_COUNT -gt 0 ]; then
        echo "$TIMESTAMP [ALERT] $SUSP_COUNT processi in directory temporanee" >> $LOG_FILE
        ps aux | grep -E "/tmp/|/var/tmp/" >> $LOG_FILE
    fi
    
    # Check connessioni sospette
    CONN_COUNT=$(sudo netstat -tulnp | grep -E ":(4444|31337|8080)" | wc -l)
    if [ $CONN_COUNT -gt 0 ]; then
        echo "$TIMESTAMP [ALERT] Connessioni su porte sospette" >> $LOG_FILE
        sudo netstat -tulnp | grep -E ":(4444|31337|8080)" >> $LOG_FILE
    fi
    
    # Check high CPU
    HIGH_CPU=$(ps aux --sort=-%cpu | head -2 | tail -1 | awk '{print $3}' | cut -d. -f1)
    if [ $HIGH_CPU -gt 80 ]; then
        echo "$TIMESTAMP [ALERT] Processo ad alto CPU: $HIGH_CPU%" >> $LOG_FILE
        ps aux --sort=-%cpu | head -5 >> $LOG_FILE
    fi
    
    sleep 30
done
```

#### 2. Baseline Creation

```bash
#!/bin/bash
# Creazione baseline sistema

BASELINE_DIR="/var/baseline"
mkdir -p $BASELINE_DIR

echo "Creando baseline sistema..."

# Processi normali
ps aux > $BASELINE_DIR/processes_baseline.txt

# Connessioni normali
sudo netstat -tulnp > $BASELINE_DIR/connections_baseline.txt

# Servizi attivi
systemctl list-units --type=service --state=active > $BASELINE_DIR/services_baseline.txt

# File SUID
find /usr/bin /usr/sbin -perm -4000 2>/dev/null > $BASELINE_DIR/suid_baseline.txt

# Capabilities
getcap -r / 2>/dev/null > $BASELINE_DIR/capabilities_baseline.txt

echo "Baseline creato in $BASELINE_DIR"
```

#### 3. Incident Response Automation

```bash
#!/bin/bash
# Script risposta automatica incidenti

incident_response() {
    local PID=$1
    local INCIDENT_DIR="/var/incidents/$(date +%Y%m%d_%H%M%S)_$PID"
    
    mkdir -p $INCIDENT_DIR
    
    echo "=== INCIDENT RESPONSE: PID $PID ===" | tee $INCIDENT_DIR/summary.txt
    
    # Informazioni processo
    ps -p $PID -o pid,ppid,user,cmd,etime,pcpu,pmem >> $INCIDENT_DIR/process_info.txt
    cat /proc/$PID/cmdline | tr '\0' ' ' > $INCIDENT_DIR/cmdline.txt
    cp /proc/$PID/maps $INCIDENT_DIR/memory_maps.txt 2>/dev/null
    cp /proc/$PID/status $INCIDENT_DIR/status.txt 2>/dev/null
    
    # File aperti
    lsof -p $PID > $INCIDENT_DIR/open_files.txt 2>/dev/null
    
    # Connessioni di rete
    lsof -p $PID -i > $INCIDENT_DIR/network_connections.txt 2>/dev/null
    
    # Environment
    cat /proc/$PID/environ | tr '\0' '\n' > $INCIDENT_DIR/environment.txt 2>/dev/null
    
    # Process tree
    ps aux --forest | grep -A 10 -B 10 $PID > $INCIDENT_DIR/process_tree.txt
    
    # System state snapshot
    ps aux > $INCIDENT_DIR/all_processes.txt
    sudo netstat -tulnp > $INCIDENT_DIR/network_state.txt
    
    echo "Incident data collected in $INCIDENT_DIR"
    
    # Optional: Kill process if malicious
    read -p "Kill process $PID? (y/N): " -n 1 -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kill -9 $PID
        echo "Process $PID terminated"
    fi
}

# Uso: incident_response <PID>
```

### Per Red Team Attackers

#### 1. Process Hiding Techniques

```bash
# Tecniche per nascondere processi (educational)

# 1. Nomi processi ingannevoli
cp /tmp/malware /usr/local/bin/systemd-update
# Appare come processo legittimo

# 2. Process hollowing simulation
cp /bin/bash /tmp/.hidden_process
chmod +x /tmp/.hidden_process
# Nome inizia con punto (nascosto in ls)

# 3. Parent process spoofing
nohup /tmp/malware > /dev/null 2>&1 &
# Diventa figlio di init (PID 1)
```

#### 2. Anti-Forensics

```bash
# Pulizia tracce (educational)

# Clear bash history
history -c
export HISTSIZE=0

# Clear system logs (richiede root)
# truncate -s 0 /var/log/auth.log

# Clear process accounting
# truncate -s 0 /var/log/pacct

# Memory wipe prima di terminare
# sync && echo 3 > /proc/sys/vm/drop_caches
```

### Per System Administrators

#### 1. Hardening Checklist

```bash
#!/bin/bash
# Security hardening checklist

echo "=== SYSTEM HARDENING CHECKLIST ==="

# 1. Process monitoring
echo "✅ Setup process monitoring:"
echo "   - Installa psacct: apt-get install acct"
echo "   - Enable: systemctl enable psacct"

# 2. File integrity
echo "✅ File integrity monitoring:"
echo "   - Installa aide: apt-get install aide"
echo "   - Setup baseline: aide --init"

# 3. Kernel hardening
echo "✅ Kernel parameters:"
cat << EOF > /etc/sysctl.d/99-security.conf
# Hide kernel pointers
kernel.kptr_restrict = 2

# Disable ptrace for non-root
kernel.yama.ptrace_scope = 2

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Enable ASLR
kernel.randomize_va_space = 2
EOF

# 4. Process limits
echo "✅ Process resource limits:"
cat << EOF > /etc/security/limits.d/99-security.conf
* soft nproc 1024
* hard nproc 2048
* soft nofile 1024
* hard nofile 2048
EOF

echo "Hardening configuration created. Reboot required."
```

#### 2. Monitoring Dashboard

```bash
#!/bin/bash
# Dashboard monitoring sicurezza

show_security_dashboard() {
    clear
    echo "================== SECURITY DASHBOARD =================="
    echo "Timestamp: $(date)"
    echo ""
    
    # System load
    echo "🖥️  SYSTEM STATUS:"
    echo "   Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "   Users: $(who | wc -l) logged in"
    echo "   Processes: $(ps aux | wc -l)"
    
    echo ""
    
    # Top CPU processes
    echo "⚡ TOP CPU PROCESSES:"
    ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "   %s: %.1f%% - %s\n", $2, $3, $11}'
    
    echo ""
    
    # Network connections
    echo "🌐 NETWORK CONNECTIONS:"
    ESTABLISHED=$(sudo netstat -tulnp | grep ESTABLISHED | wc -l)
    LISTENING=$(sudo netstat -tulnp | grep LISTEN | wc -l)
    echo "   Established: $ESTABLISHED"
    echo "   Listening: $LISTENING"
    
    echo ""
    
    # Suspicious activities
    echo "🚨 SECURITY ALERTS:"
    
    # Check for processes in tmp
    TMP_PROC=$(ps aux | grep -E "/tmp/|/var/tmp/" | grep -v grep | wc -l)
    if [ $TMP_PROC -gt 0 ]; then
        echo "   ⚠️  $TMP_PROC processes in temp directories"
    fi
    
    # Check for high CPU
    HIGH_CPU=$(ps aux --sort=-%cpu | head -2 | tail -1 | awk '{print $3}' | cut -d. -f1)
    if [ $HIGH_CPU -gt 80 ]; then
        echo "   ⚠️  High CPU usage: $HIGH_CPU%"
    fi
    
    # Check for failed SSH
    FAILED_SSH=$(sudo journalctl -u sshd --since '1 hour ago' | grep "Failed password" | wc -l)
    if [ $FAILED_SSH -gt 5 ]; then
        echo "   ⚠️  $FAILED_SSH failed SSH attempts in last hour"
    fi
    
    if [ $TMP_PROC -eq 0 ] && [ $HIGH_CPU -lt 80 ] && [ $FAILED_SSH -le 5 ]; then
        echo "   ✅ No alerts detected"
    fi
    
    echo ""
    echo "=========================================================="
    echo "Press 'r' to refresh, 'q' to quit, Enter to continue..."
}

# Main loop
while true; do
    show_security_dashboard
    read -n 1 -t 10 key
    case $key in
        q|Q) break ;;
        r|R) continue ;;
        *) sleep 1 ;;
    esac
done
```

## Advanced Forensics Techniques

### 1. Memory Dump Analysis

```bash
#!/bin/bash
# Memory forensics per processo specifico

memory_forensics() {
    local PID=$1
    local OUTPUT_DIR="/tmp/memory_forensics_$PID"
    
    mkdir -p $OUTPUT_DIR
    
    echo "=== MEMORY FORENSICS: PID $PID ==="
    
    # Process memory info
    cat /proc/$PID/status | grep -E "Vm|Rss" > $OUTPUT_DIR/memory_stats.txt
    
    # Memory maps with permissions
    cat /proc/$PID/maps > $OUTPUT_DIR/memory_maps.txt
    
    # SMAPS (detailed memory info)
    cat /proc/$PID/smaps > $OUTPUT_DIR/memory_detailed.txt 2>/dev/null
    
    # Memory segments analysis
    echo "=== MEMORY SEGMENTS ANALYSIS ===" > $OUTPUT_DIR/segments_analysis.txt
    awk '{
        gsub(/-/, " ", $1); 
        print $2, $1, $6
    }' /proc/$PID/maps | \
    awk '{
        if ($1 == "r-xp") print "EXECUTABLE: " $2 "-" $3 " " $4;
        if ($1 == "rw-p") print "WRITABLE: " $2 "-" $3 " " $4;
        if ($1 == "r--p") print "READ-ONLY: " $2 "-" $3 " " $4;
    }' >> $OUTPUT_DIR/segments_analysis.txt
    
    # Stack and heap info
    grep -E "\[stack\]|\[heap\]" /proc/$PID/maps > $OUTPUT_DIR/stack_heap.txt
    
    # Shared libraries
    grep "\.so" /proc/$PID/maps | awk '{print $6}' | sort | uniq > $OUTPUT_DIR/shared_libs.txt
    
    echo "Memory forensics completed in $OUTPUT_DIR"
}
```

### 2. String Analysis

```bash
#!/bin/bash
# String analysis da memory maps

string_analysis() {
    local PID=$1
    local OUTPUT_FILE="/tmp/strings_analysis_$PID.txt"
    
    echo "=== STRING ANALYSIS: PID $PID ===" > $OUTPUT_FILE
    
    # Extract strings from process memory (se gdb disponibile)
    if command -v gdb >/dev/null 2>&1; then
        echo "Extracting strings from process memory..." >> $OUTPUT_FILE
        
        # Create gdb script
        cat > /tmp/extract_strings.gdb << EOF
attach $PID
set logging file /tmp/memory_dump_$PID.txt
set logging on
maintenance info sections
quit
EOF
        
        gdb -batch -x /tmp/extract_strings.gdb >/dev/null 2>&1
        
        # Extract strings from memory dump
        if [ -f /tmp/memory_dump_$PID.txt ]; then
            strings /tmp/memory_dump_$PID.txt | grep -E "(password|key|secret|token|http|ftp)" >> $OUTPUT_FILE
            rm /tmp/memory_dump_$PID.txt
        fi
        
        rm /tmp/extract_strings.gdb
    fi
    
    # Alternative: extract from /proc/PID/mem (requires specific permissions)
    echo "Checking for suspicious patterns..." >> $OUTPUT_FILE
    
    # Check environment variables for secrets
    cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' | \
    grep -i -E "(password|key|secret|token)" >> $OUTPUT_FILE
    
    echo "String analysis completed: $OUTPUT_FILE"
}
```

### 3. Network Forensics Integration

```bash
#!/bin/bash
# Correlazione network e processi

network_process_correlation() {
    local OUTPUT_FILE="/tmp/network_correlation.txt"
    
    echo "=== NETWORK-PROCESS CORRELATION ===" > $OUTPUT_FILE
    echo "Timestamp: $(date)" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    
    # Processi con connessioni di rete
    echo "PROCESSES WITH NETWORK CONNECTIONS:" >> $OUTPUT_FILE
    sudo netstat -tulnp | grep "/" | while read line; do
        PID=$(echo $line | awk '{print $NF}' | cut -d'/' -f1)
        PROCESS=$(echo $line | awk '{print $NF}' | cut -d'/' -f2)
        CONN=$(echo $line | awk '{print $1, $4, $5}')
        
        if [ ! -z "$PID" ] && [ "$PID" != "-" ]; then
            echo "  PID $PID ($PROCESS): $CONN" >> $OUTPUT_FILE
            
            # Additional info per processo
            CMD=$(cat /proc/$PID/cmdline 2>/dev/null | tr '\0' ' ')
            if [ ! -z "$CMD" ]; then
                echo "    Command: $CMD" >> $OUTPUT_FILE
            fi
            echo "" >> $OUTPUT_FILE
        fi
    done
    
    # Connessioni esterne (non localhost/private)
    echo "EXTERNAL CONNECTIONS:" >> $OUTPUT_FILE
    sudo netstat -tulnp | grep ESTABLISHED | \
    awk '{print $5}' | cut -d: -f1 | \
    grep -v -E "(127\.|192\.168\.|10\.|172\.)" | sort | uniq | \
    while read ip; do
        echo "  External IP: $ip" >> $OUTPUT_FILE
        # Reverse DNS lookup
        HOST=$(host $ip 2>/dev/null | awk '{print $NF}' | head -1)
        if [ ! -z "$HOST" ]; then
            echo "    Hostname: $HOST" >> $OUTPUT_FILE
        fi
    done
    
    echo "Network correlation completed: $OUTPUT_FILE"
}
```

### 4. Timeline Reconstruction

```bash
#!/bin/bash
# Ricostruzione timeline eventi

create_timeline() {
    local OUTPUT_FILE="/tmp/security_timeline.txt"
    local SINCE_TIME=${1:-"1 hour ago"}
    
    echo "=== SECURITY TIMELINE ===" > $OUTPUT_FILE
    echo "Period: Since $SINCE_TIME" >> $OUTPUT_FILE
    echo "Generated: $(date)" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    
    # Combina diversi log sources
    {
        # SSH events
        sudo journalctl -u sshd --since "$SINCE_TIME" --no-pager | \
        grep -E "(Failed|Accepted|session)" | \
        awk '{print $1 " " $2 " " $3 " SSH: " substr($0, index($0,$4))}'
        
        # Sudo events  
        sudo journalctl --since "$SINCE_TIME" --no-pager | \
        grep "sudo" | \
        awk '{print $1 " " $2 " " $3 " SUDO: " substr($0, index($0,$4))}'
        
        # Process events (se psacct attivo)
        if command -v lastcomm >/dev/null 2>&1; then
            lastcomm --since "$SINCE_TIME" 2>/dev/null | head -20 | \
            awk '{print strftime("%b %d %H:%M:%S", systime()) " PROCESS: " $0}'
        fi
        
        # Network scan detection
        sudo journalctl --since "$SINCE_TIME" --no-pager | \
        grep "SCAN DETECT" | \
        awk '{print $1 " " $2 " " $3 " SCAN: " substr($0, index($0,$4))}'
        
    } | sort >> $OUTPUT_FILE
    
    echo "" >> $OUTPUT_FILE
    echo "=== SUMMARY ===" >> $OUTPUT_FILE
    
    # Summary statistics
    SSH_FAILED=$(grep "SSH.*Failed" $OUTPUT_FILE | wc -l)
    SSH_SUCCESS=$(grep "SSH.*Accepted" $OUTPUT_FILE | wc -l)
    SUDO_COUNT=$(grep "SUDO" $OUTPUT_FILE | wc -l)
    SCAN_COUNT=$(grep "SCAN" $OUTPUT_FILE | wc -l)
    
    echo "SSH Failed attempts: $SSH_FAILED" >> $OUTPUT_FILE
    echo "SSH Successful logins: $SSH_SUCCESS" >> $OUTPUT_FILE
    echo "Sudo commands: $SUDO_COUNT" >> $OUTPUT_FILE
    echo "Network scans detected: $SCAN_COUNT" >> $OUTPUT_FILE
    
    echo "Timeline created: $OUTPUT_FILE"
}
```

## Quick Reference Commands

### Process Investigation Cheatsheet

```bash
# Quick process investigation
PID=<suspect_pid>

# Basic info
ps -p $PID -o pid,ppid,user,cmd,etime,pcpu,pmem
cat /proc/$PID/cmdline | tr '\0' ' '

# Memory and files
lsof -p $PID
cat /proc/$PID/maps | head -10

# Network
lsof -p $PID -i
sudo netstat -tulnp | grep $PID

# Kill process
kill $PID          # Graceful
kill -9 $PID       # Force
```

### Log Analysis Cheatsheet

```bash
# SSH investigation
sudo journalctl -u sshd | grep "Failed\|Accepted"
sudo journalctl -u sshd --since "1 hour ago" -f

# System events
sudo journalctl --since today | grep -E "sudo|su"
sudo journalctl -p err --since today

# Network scanning
sudo journalctl -f | grep "SCAN DETECT"
```

### Network Forensics Cheatsheet

```bash
# Network connections
sudo netstat -tulnp | grep ESTABLISHED
sudo lsof -i | grep ESTABLISHED

# Port scan detection
sudo iptables -I INPUT -j LOG --log-prefix 'SCAN: '
sudo journalctl -f | grep 'SCAN:'

# External connections
sudo netstat -tulnp | grep ESTABLISHED | \
awk '{print $5}' | cut -d: -f1 | \
grep -v -E "(127\.|192\.168\.|10\.)"
```

---

**Conclusioni Linux Forensics**:
- L'analisi dei processi è fondamentale per incident response
- Il filesystem /proc fornisce informazioni cruciali sui processi
- journalctl è potentissimo per correlation degli eventi
- La combinazione di più tecniche di analysis aumenta l'efficacia
- Il monitoring proattivo previene molti incidenti

[← Linux Security](../linux-security/README.md) | [← Torna al Main](../../README.md) | [Networking →](../networking/README.md)
