# File System Security Analysis

## Introduzione

Approfondiamo il File System Security nel profondo. Analizzeremo `/proc/` e `/sys/`, filesystem virtuali che forniscono una finestra sulla mente del kernel e informazioni cruciali per l'analisi di sicurezza.

## Analisi del Filesystem /proc/

### Panoramica

`/proc/` non è una vera directory, ma una finestra sulla mente del kernel. Ogni processo ha la sua directory `/proc/PID/` che contiene tutto: file aperti, variabili d'ambiente, mappatura della memoria, comandi eseguiti. È come leggere i pensieri di un computer.

Non serve root per tutto, ma certi file come `/proc/pid/environ` richiedono privilegi elevati. Ci vai dentro e il processo si rivela con tutte le informazioni sensibili, senza nessuna protezione o difesa.

### Comandi Base

#### Listare Contenuto /proc/

```bash
ls -al /proc/ | head -20
```

**Output:**
```
totale 0
dr-xr-xr-x 454 root             root                           0 20 lug 16.38 .
drwxr-xr-x   1 root             root                         216 26 mag 08.46 ..
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 1
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 100
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 101
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 103
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 104
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 105
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 106
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 107
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 108
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 109
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 11
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 110
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 111
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 112
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 113
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 115
dr-xr-xr-x   9 root             root                           0 20 lug 16.38 116
```

**Analisi:**
- Ogni numero è il PID (es: 1, 100, 101)
- Ogni directory numerica dentro `/proc/` contiene informazioni dettagliate su ogni singolo processo
- Sono tutti utente root
- Il valore 0 prima della data è la dimensione (fittizia perché `/proc/` è virtuale)

#### Contare Processi Attivi

```bash
ls -al /proc/[0-9]* -d | wc -l
```

**Risultato:**
```
390
```

**Breakdown comando:**
- La regex `[0-9]*` conta solo i processi numerici
- `wc -l` conta le righe che ha prodotto `ls`
- `-d` fa sì che `ls` mostri solo le directory, non il contenuto

### Informazioni Sistema

#### Informazioni Memoria

```bash
cat /proc/meminfo | head -10
```

**Output:**
```
MemTotal:       32787872 kB
MemFree:        15067000 kB
MemAvailable:   25773504 kB
Buffers:            1744 kB
Cached:         11033408 kB
SwapCached:            0 kB
Active:          7769096 kB
Inactive:        8835032 kB
Active(anon):    5505560 kB
Inactive(anon):   173196 kB
```

**Significato delle voci chiave:**

| Campo | Significato | Valore |
|-------|-------------|--------|
| **MemTotal** | RAM fisica totale disponibile | ~32 GB |
| **MemFree** | RAM libera non allocata | ~15 GB |
| **MemAvailable** | RAM stimata disponibile per i programmi, inclusa quella recuperabile da cache | ~25 GB |
| **Buffers** | Dati temporanei del filesystem (block devices) | ~1.7 MB |
| **Cached** | File già letti, mantenuti in RAM per velocità | ~11 GB |
| **SwapCached** | Dati swap riportati in RAM e ancora nel file di swap | 0 kB → nessuna swap usata |
| **Active** | RAM usata attivamente da programmi | ~7.7 GB |
| **Inactive** | RAM che può essere liberata, ma ancora utile (cache) | ~8.8 GB |
| **Active(anon)** | RAM usata da processi anonimi (heap, stack) | ~5.5 GB |
| **Inactive(anon)** | RAM anonima non più attiva ma non ancora liberata | ~173 MB |

#### Informazioni CPU

```bash
grep -E "(model name|cpu cores)" /proc/cpuinfo
```

**Output:**
```
model name      : AMD Ryzen 7 5800X 8-Core Processor
cpu cores       : 8
```

#### Sottocartelle di /proc/

- **`/proc/sys`** → parametri configurabili del kernel
- **`/proc/net`** → informazioni di rete
- **`/proc/fs`** → informazioni sui filesystem

### Analisi Variabili d'Ambiente Processi

Per vedere le variabili d'ambiente di un processo:

```bash
cat /proc/$PID/environ | tr '\0' '\n'
```

**Output esempio:**
```
LANG=it_IT.UTF-8
LC_ADDRESS=it_IT.UTF-8
LC_IDENTIFICATION=it_IT.UTF-8
LC_MEASUREMENT=it_IT.UTF-8
LC_MONETARY=it_IT.UTF-8
LC_NAME=it_IT.UTF-8
LC_NUMERIC=it_IT.UTF-8
LC_PAPER=it_IT.UTF-8
LC_TELEPHONE=it_IT.UTF-8
LC_TIME=it_IT.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/var/lib/snapd/snap/bin
XDG_DATA_DIRS=/var/lib/flatpak/exports/share:/usr/local/share/:/usr/share/
WATCHDOG_PID=458
WATCHDOG_USEC=180000000
USER=root
INVOCATION_ID=9b1ece02ff634024863546b8532aa85b
JOURNAL_STREAM=9:9301
SYSTEMD_EXEC_PID=458
MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/systemd-userdbd.service/memory.pressure
MEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=
SYSTEMD_BYPASS_USERDB=io.systemd.NameServiceSwitch:io.systemd.Multiplexer:io.systemd.DropIn
LISTEN_PID=39594
LISTEN_FDS=1
USERDB_FIXED_WORKER=1
SYSTEMD_LOG_LEVEL=info
```

### Comandi di Sistema Generici

#### Uptime Sistema
```bash
cat /proc/uptime
```
**Output:** `82881.49 1266437.30`

#### Load Average
```bash
cat /proc/loadavg
```
**Output:** `2.07 2.04 1.94 1/1719 40153`

#### Versione Kernel
```bash
cat /proc/version
```
**Output:** `Linux version 6.12.37-1-MANJARO (linux612@manjaro) (gcc (GCC) 15.1.1 20250425, GNU ld (GNU Binutils) 2.44.0) #1 SMP PREEMPT_DYNAMIC Thu, 10 Jul 2025 15:37:43 +0000`

#### Connessioni TCP
```bash
cat /proc/net/tcp
```
**Output:**
```
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11445 1 00000000edfd784d 99 0 0 10 0                      
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6032 1 000000004c0f68e6 99 0 0 10 0                       
   2: 00000000:E115 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 183772 1 00000000139ae869 99 0 0 10 0                     
   3: 00000000:EACD 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 183773 1 00000000df2917d0 99 0 0 10 0                     
   4: CF6A1A0A:A852 D1649522:01BB 06 00000000:00000000 03:0000063F 00000000     0        0 0 3 000000001f01ea24                                      
   5: CF6A1A0A:E874 63A79A95:01BB 01 00000000:00000000 02:00001D23 00000000  1000        0 181239 2 0000000036f9d681 26 3 30 10 28                   
   6: CF6A1A0A:9738 2F201268:01BB 06 00000000:00000000 03:000013A4 00000000     0        0 0 3 0000000016ba0a76                                      
   7: CF6A1A0A:9FF6 5DF36B22:01BB 06 00000000:00000000 03:000005DD 00000000     0        0 0 3 0000000013679118                                      
   8: CF6A1A0A:B418 2CE0BA23:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 189699 1 000000004b5f1069 24 3 30 10 -1                   
   9: CF6A1A0A:A002 5DF36B22:01BB 01 00000000:00000000 02:00009661 00000000  1000        0 232188 2 000000003b063a37 22 3 26 10 -1                   
  10: CF6A1A0A:8F50 0A684FA0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 234836 1 00000000ec8a57a8 23 3 22 10 -1                   
  11: CF6A1A0A:B41C 2CE0BA23:01BB 01 00000000:00000000 02:0000097C 00000000  1000        0 192681 2 00000000be8cac2b 24 3 30 10 -1                   
  12: CF6A1A0A:D32A 7C8D9FA2:01BB 01 00000000:00000000 02:000007E3 00000000  1000        0 256664 2 000000003be58b3a 22 3 0 10 -1                    
  13: CF6A1A0A:C92E CB892422:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 260423 1 000000005f82d008 23 3 30 10 -1                   
  14: CF6A1A0A:8802 1CE0BA23:01BB 01 00000000:00000000 02:00000A8D 00000000  1000        0 236682 2 000000001107ef32 23 4 29 10 -1                   
  15: CF6A1A0A:DC18 24D1FB8E:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 256716 1 00000000f016e9df 23 3 30 10 -1                   
  16: CF6A1A0A:D296 33560D1F:01BB 01 00000000:00000000 02:0000B096 00000000  1000        0 199055 2 00000000a8b4572b 26 3 30 10 36                   
  17: CF6A1A0A:CF6A 1CE0BA23:01BB 01 00000000:00000000 02:00000923 00000000  1000        0 238076 2 0000000011e3d249 23 3 29 10 -1                   
  18: CF6A1A0A:E02A 18E0BA23:01BB 01 00000000:00000000 02:000005E3 00000000  1000        0 230222 2 00000000e19f58ec 23 3 28 10 -1                   
  19: CF6A1A0A:9606 1970528C:01BB 01 00000000:00000000 02:0000A975 00000000  1000        0 234590 2 0000000053be0482 33 3 31 10 -1                   
  20: CF6A1A0A:EB7C 13246112:01BB 01 00000000:00000000 02:0000C071 00000000  1000        0 181023 2 00000000b5708a6a 35 3 30 4 4                     
  21: CF6A1A0A:E600 D98A6E22:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 260424 1 000000003635879c 23 3 30 10 -1                   
  22: CF6A1A0A:A176 85019E22:0FE6 01 00000000:00000000 00:00000000 00000000  1000        0 189062 1 00000000e43f0fc8 25 3 30 10 -1                   
  23: CF6A1A0A:972A 2F201268:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 238122 1 00000000617b4a58 24 3 30 10 -1                   
```

#### Moduli Kernel Caricati
```bash
cat /proc/modules
```
**Output (parziale):**
```
rndis_host 24576 0 - Live 0x0000000000000000
cdc_ether 24576 1 rndis_host, Live 0x0000000000000000
usbnet 61440 2 rndis_host,cdc_ether, Live 0x0000000000000000
mii 16384 1 usbnet, Live 0x0000000000000000
ses 20480 0 - Live 0x0000000000000000
enclosure 20480 1 ses, Live 0x0000000000000000
scsi_transport_sas 57344 1 ses, Live 0x0000000000000000
uas 36864 0 - Live 0x0000000000000000
usb_storage 94208 1 uas, Live 0x0000000000000000
uinput 20480 1 - Live 0x0000000000000000
ccm 20480 0 - Live 0x0000000000000000
rfcomm 102400 9 - Live 0x0000000000000000
snd_seq_dummy 12288 0 - Live 0x0000000000000000
snd_hrtimer 12288 1 - Live 0x0000000000000000
snd_seq 131072 7 snd_seq_dummy, Live 0x0000000000000000
```

#### Filesystem Supportati
```bash
cat /proc/filesystems
```
**Output:**
```
nodev   sysfs
nodev   tmpfs
nodev   bdev
nodev   proc
nodev   cgroup
nodev   cgroup2
nodev   devtmpfs
nodev   binfmt_misc
nodev   configfs
nodev   debugfs
nodev   tracefs
nodev   securityfs
nodev   sockfs
nodev   bpf
nodev   pipefs
nodev   ramfs
nodev   hugetlbfs
nodev   devpts
nodev   autofs
        fuseblk
nodev   fuse
nodev   fusectl
nodev   virtiofs
nodev   efivarfs
nodev   mqueue
nodev   binder
nodev   resctrl
nodev   pstore
        btrfs
        vfat
```

## Analisi di Sicurezza con /proc/

### Ricerca Processi Sospetti in /tmp

```bash
find /proc/*/exe -type l 2>/dev/null | xargs ls -la | grep tmp
```

**Risultato:** Nessun output (il file non c'è)

**Spiegazione dettagliata:**
1. **`find /proc/*/exe -type l`** - Cerca tutti i link simbolici chiamati `exe` sotto `/proc/[PID]/exe`. Ogni `exe` è un link al binario eseguito da quel processo
2. **`2>/dev/null`** - Sopprime gli errori tipo "permesso negato" o "processo inesistente"
3. **`xargs ls -la`** - Per ogni percorso trovato, mostra informazioni dettagliate del file eseguibile del processo
4. **`grep tmp`** - Filtra i processi che eseguono binari da `/tmp`, `/dev/shm`, o altri path sospetti

### File Eliminati ma Ancora Aperti

```bash
lsof +L1 | tail -n 10
```

**Output:**
```
Web\x20Co 39884 alessandro  29r   REG    0,1     2876     0    3375 /memfd:mozilla-ipc (deleted)
Web\x20Co 39884 alessandro  30r   REG    0,1    79292     0    3376 /memfd:mozilla-ipc (deleted)
Web\x20Co 39884 alessandro  31r   REG    0,1    30190     0    3377 /memfd:mozilla-ipc (deleted)
Web\x20Co 39884 alessandro  32r   REG    0,1      222     0    5167 /memfd:mozilla-ipc (deleted)
Web\x20Co 39884 alessandro  33r   REG    0,1     3026     0    5168 /memfd:mozilla-ipc (deleted)
Web\x20Co 39884 alessandro  34r   REG    0,1     1700     0    5169 /memfd:mozilla-ipc (deleted)
Web\x20Co 39884 alessandro  35r   REG    0,1    24514     0    3378 /memfd:mozilla-ipc (deleted)
Web\x20Co 39884 alessandro  36r   REG    0,1    12586     0    3379 /memfd:mozilla-ipc (deleted)
Web\x20Co 39884 alessandro  37r   REG    0,1   800040     0   19772 /memfd:mozilla-ipc (deleted)
Web\x20Co 39884 alessandro  38r   REG    0,1    15558     0    4200 /memfd:mozilla-ipc (deleted)
```

**Totale file cancellati:**
```bash
lsof +L1 | wc -l
```
**Risultato:** `472`

### Ricerca Possibili Backdoor

Per trovare possibili backdoor (processi senza terminale):

```bash
ps aux | awk '$7 == "?"'
```

**Output (processo daemon tipici):**
```
root           1  0.0  0.0  22344 12880 ?        Ss   lug20   0:04 /sbin/init splash
root           2  0.0  0.0      0     0 ?        S    lug20   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        S    lug20   0:00 [pool_workqueue_release]
root           4  0.0  0.0      0     0 ?        I<   lug20   0:00 [kworker/R-kvfree_rcu_reclaim]
root           5  0.0  0.0      0     0 ?        I<   lug20   0:00 [kworker/R-rcu_gp]
```
*(Output troncato per brevità - 390 processi totali)*

**Nota:** Ovviamente non basta solo questo per determinare se c'è una backdoor. Più che altro mostra tutti i processi in esecuzione senza essere associati a un terminale, questo è normale per molti servizi e processi di sistema.

## Analisi del Filesystem /sys/

### Introduzione a /sys/

Il filesystem `/sys/` (anche chiamato "sysfs") è un filesystem virtuale montato tipicamente su `/sys/`, creato dal kernel Linux. Lo scopo è di fornire una rappresentazione strutturata e gerarchica dell'hardware e dei device driver.

È un tipo di filesystem in memoria creato dinamicamente dal kernel.

### Funzioni Principali

- Esporre informazioni sui dispositivi hardware
- Permettere lettura e modifica dei parametri di kernel e driver
- È read/write per root (**ATTENZIONE: modifiche errate = instabilità**)

### Struttura Generale

| Directory | Descrizione |
|-----------|-------------|
| **`/sys/block/`** | Dispositivi a blocchi (HDD, SSD, USB, loopback) |
| **`/sys/class/`** | Classi logiche di dispositivi (net, input, tty...) |
| **`/sys/bus/`** | Dispositivi organizzati per bus (PCI, USB, etc) |
| **`/sys/devices/`** | Albero gerarchico fisico dei dispositivi |
| **`/sys/kernel/`** | Parametri del kernel |
| **`/sys/fs/`** | Filesystem virtuali (es: cgroup, ecryptfs, etc.) |

## Analisi /sys/block/

### Dispositivi a Blocchi

```bash
ls -la /sys/block/
```

**Output:**
```
totale 0
drwxr-xr-x  2 root root 0 21 lug 17.45 .
dr-xr-xr-x 13 root root 0 21 lug 17.45 ..
lrwxrwxrwx  1 root root 0 21 lug 17.45 nvme0n1 -> ../devices/pci0000:00/0000:00:01.2/0000:02:00.2/0000:03:00.0/0000:04:00.0/nvme/nvme0/nvme0n1
```

### Informazioni Disco NVMe

```bash
cat /sys/block/nvme0n1/size
```
**Output:** `1953525168`

```bash
cat /sys/block/nvme0n1/removable
```
**Output:** `0`

```bash
cat /sys/block/nvme0n1/ro
```
**Output:** `0`

## Analisi /sys/class/

### Classi di Dispositivi

Qui i dispositivi sono organizzati per tipo, indipendentemente da dove siano collegati fisicamente.

#### Interfacce di Rete

```bash
ls -la /sys/class/net/
```

**Output:**
```
drwxr-xr-x  2 root root 0 21 lug 17.51 .
drwxr-xr-x 76 root root 0 20 lug 16.38 ..
lrwxrwxrwx  1 root root 0 21 lug 13.07 enp2s0f0u3 -> ../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-3/1-3:1.0/net/enp2s0f0u3
lrwxrwxrwx  1 root root 0 20 lug 16.38 enp42s0 -> ../../devices/pci0000:00/0000:00:01.2/0000:02:00.2/0000:03:09.0/0000:2a:00.0/net/enp42s0
lrwxrwxrwx  1 root root 0 20 lug 16.38 lo -> ../../devices/virtual/net/lo
lrwxrwxrwx  1 root root 0 20 lug 16.38 wlo1 -> ../../devices/pci0000:00/0000:00:01.2/0000:02:00.2/0000:03:08.0/0000:29:00.0/net/wlo1
```

Queste sono le interfacce di rete come ad esempio la rete wireless `wlo1`.

#### Informazioni Dettagliate Interfaccia WiFi (wlo1)

```bash
cat /sys/class/net/wlo1/address
```
**Output:** `7e:7a:ff:ef:80:4f`

```bash
cat /sys/class/net/wlo1/operstate
```
**Output:** `down`

```bash
cat /sys/class/net/wlo1/speed
```
**Output:** `cat: /sys/class/net/wlo1/speed: Argomento non valido`

```bash
cat /sys/class/net/wlo1/mtu
```
**Output:** `1500`

**Analisi:** Attualmente il WiFi è scollegato quindi non c'è rete, quindi ci dice `down` e `speed` è un valore non valido.

#### Informazioni Interfaccia Ethernet (enp42s0)

```bash
cat /sys/class/net/enp42s0/address
```
**Output:** `d8:43:ae:23:1e:3c`

```bash
cat /sys/class/net/enp42s0/operstate
```
**Output:** `down`

```bash
cat /sys/class/net/enp42s0/speed
```
**Output:** `-1`

```bash
cat /sys/class/net/enp42s0/mtu
```
**Output:** `1500`

## Analisi /sys/bus/

### Dispositivi Hardware Connessi (USB)

```bash
ls -la /sys/bus/usb/devices/
```

**Output:**
```
drwxr-xr-x 2 root root 0 22 lug 08.31 .
drwxr-xr-x 4 root root 0 22 lug 08.16 ..
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-0:1.0 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-0:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.24 1-3 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-3
lrwxrwxrwx 1 root root 0 22 lug 08.18 1-3:1.0 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-3/1-3:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.24 1-3:1.1 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-3/1-3:1.1
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-5 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-5
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-5:1.0 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-5/1-5:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-5:1.1 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-5/1-5:1.1
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-5:1.2 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-5/1-5:1.2
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-5:1.3 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-5/1-5:1.3
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-7 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-7
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-7:1.0 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-7/1-7:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-8 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-8
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-8:1.0 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-8/1-8:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-9 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-9
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-9:1.0 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-9/1-9:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-9:1.1 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-9/1-9:1.1
lrwxrwxrwx 1 root root 0 22 lug 08.16 1-9:1.2 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1/1-9/1-9:1.2
lrwxrwxrwx 1 root root 0 22 lug 08.16 2-0:1.0 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb2/2-0:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.16 3-0:1.0 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3/3-0:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.16 3-2 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3/3-2
lrwxrwxrwx 1 root root 0 22 lug 08.16 3-2:1.0 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3/3-2/3-2:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.16 3-2:1.1 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3/3-2/3-2:1.1
lrwxrwxrwx 1 root root 0 22 lug 08.16 3-2:1.2 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3/3-2/3-2:1.2
lrwxrwxrwx 1 root root 0 22 lug 08.16 3-2:1.3 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3/3-2/3-2:1.3
lrwxrwxrwx 1 root root 0 22 lug 08.16 3-4 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3/3-4
lrwxrwxrwx 1 root root 0 22 lug 08.16 3-4:1.0 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3/3-4/3-4:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.16 3-4:1.1 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3/3-4/3-4:1.1
lrwxrwxrwx 1 root root 0 22 lug 08.16 4-0:1.0 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb4/4-0:1.0
lrwxrwxrwx 1 root root 0 22 lug 08.16 usb1 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb1
lrwxrwxrwx 1 root root 0 22 lug 08.16 usb2 -> ../../../devices/pci0000:00/0000:00:01.2/0000:02:00.0/usb2
lrwxrwxrwx 1 root root 0 22 lug 08.16 usb3 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb3
lrwxrwxrwx 1 root root 0 22 lug 08.16 usb4 -> ../../../devices/pci0000:00/0000:00:08.1/0000:2f:00.3/usb4
```

**Analisi USB:**
- Ogni riga è un link simbolico a un dispositivo USB specifico situato fisicamente più in profondità nella gerarchia di `/sys/devices/`
- I numeri come `1-3` sono il nome logico del dispositivo: `1` = controller USB1 root hub, `3` = terza porta su quel controller
- `1-3:1.0` è un'interfaccia di quel dispositivo USB

### Identificazione Dispositivi USB

#### Vendor ID
```bash
cat /sys/bus/usb/devices/*/idVendor
```
**Output:**
```
22b8
046d
05e3
1462
0e8d
1b1c
18f8
1d6b
1d6b
1d6b
1d6b
```

#### Product ID
```bash
cat /sys/bus/usb/devices/*/idProduct
```
**Output:**
```
2e24
085c
0608
7c95
0608
2b01
0f97
0002
0003
0002
0003
```

#### Nomi Prodotti
```bash
cat /sys/bus/usb/devices/*/product
```
**Output:**
```
moto g85 5G
C922 Pro Stream Webcam
USB2.0 Hub
MYSTIC LIGHT 
Wireless_Device
CORSAIR K70 CORE RGB TKL Mechanical Gaming Keyboard
USB OPTICAL MOUSE 
xHCI Host Controller
xHCI Host Controller
xHCI Host Controller
xHCI Host Controller
```

**Dispositivi Identificati:**
- **moto g85 5G** - Telefono Android collegato
- **C922 Pro Stream Webcam** - Webcam Logitech
- **USB2.0 Hub** - Hub USB
- **MYSTIC LIGHT** - Sistema illuminazione MSI
- **Wireless_Device** - Dispositivo wireless generico
- **CORSAIR K70 CORE RGB TKL** - Tastiera meccanica gaming
- **USB OPTICAL MOUSE** - Mouse ottico USB
- **xHCI Host Controller** - Controller USB 3.0/2.0

## Analisi /sys/kernel/

### Directory Kernel

Contiene file che permettono di osservare e modificare opzioni di debug, mostrare configurazioni attive e leggere parametri come:
- `/sys/kernel/hostname`
- `/sys/kernel/mm` → memory management
- `/sys/kernel/debug` → richiede mount specifico

**⚠️ ATTENZIONE:** Non modificare parametri del kernel senza conoscenza approfondita - rischio di instabilità del sistema.

## Analisi /sys/fs/

### Filesystem Virtuali

Contiene configurazioni per filesystem speciali:
- **`/sys/fs/cgroup/`** → controllo delle risorse (CPU, RAM, I/O)
- **`/sys/fs/ecryptfs/`** → encryption
- **`/sys/fs/bpf/`** → eBPF program info  
- **`/sys/fs/selinux/`** → informazioni e stato SELinux (se attivo)

## Utilizzo di /sys/ per Sicurezza

Il filesystem `/sys/` è una fonte cruciale per strumenti di sicurezza:

| Verifica | Percorso |
|----------|----------|
| **Dispositivi USB connessi** | `/sys/bus/usb/devices/` + `dmesg` |
| **Interfacce di rete attive** | `/sys/class/net/*/operstate` |
| **Modifica live parametri kernel** | `/sys/kernel/debug/` |
| **Storage sospetti montati** | `/sys/block/` + `/proc/mounts` |
| **MTU anomalo (esfiltrazione?)** | `/sys/class/net/*/mtu` |

## Script di Sicurezza Automatizzato

### Monitor Dispositivi USB

```bash
#!/bin/bash
# Monitor continuo dispositivi USB per rilevare connessioni sospette

echo "=== USB Security Monitor ==="
while true; do
    echo "$(date): Scanning USB devices..."
    
    # Lista tutti i dispositivi USB con dettagli
    for device in /sys/bus/usb/devices/*/product; do
        if [ -f "$device" ]; then
            product=$(cat "$device" 2>/dev/null)
            vendor_file=$(dirname "$device")/idVendor
            product_file=$(dirname "$device")/idProduct
            
            if [ -f "$vendor_file" ] && [ -f "$product_file" ]; then
                vendor=$(cat "$vendor_file" 2>/dev/null)
                product_id=$(cat "$product_file" 2>/dev/null)
                echo "DEVICE: $product (Vendor: $vendor, Product: $product_id)"
                
                # Verifica dispositivi sospetti
                case "$product" in
                    *"Rubber Ducky"*|*"BadUSB"*|*"Unknown"*)
                        echo "🚨 SUSPICIOUS DEVICE DETECTED: $product"
                        logger "SECURITY ALERT: Suspicious USB device detected: $product"
                        ;;
                esac
            fi
        fi
    done
    
    sleep 5  # Controlla ogni 5 secondi
done
```

### Monitor Interfacce di Rete

```bash
#!/bin/bash
# Monitora cambiamenti stato interfacce di rete

echo "=== Network Interface Monitor ==="
for interface in /sys/class/net/*; do
    if [ -d "$interface" ]; then
        iface_name=$(basename "$interface")
        
        # Skip loopback
        [ "$iface_name" = "lo" ] && continue
        
        # Leggi stato e configurazione
        operstate=$(cat "$interface/operstate" 2>/dev/null || echo "unknown")
        address=$(cat "$interface/address" 2>/dev/null || echo "unknown")
        mtu=$(cat "$interface/mtu" 2>/dev/null || echo "unknown")
        
        echo "Interface: $iface_name"
        echo "  State: $operstate"
        echo "  MAC: $address" 
        echo "  MTU: $mtu"
        
        # Verifica MTU sospetti (comuni per tunnel/VPN)
        if [ "$mtu" -lt 1400 ] && [ "$operstate" = "up" ]; then
            echo "  ⚠️  SUSPICIOUS: Low MTU detected (possible tunnel/VPN)"
        fi
        
        # Verifica MTU molto alti (jumbo frames - possibile esfiltrazione)
        if [ "$mtu" -gt 8000 ]; then
            echo "  🚨 ALERT: Jumbo frames detected (MTU > 8000)"
        fi
        echo "---"
    fi
done
```

## Lezioni Apprese

1. **`/proc/` e `/sys/`** sono filesystem virtuali cruciali per l'analisi di sicurezza
2. **Monitoraggio continuo** di questi filesystem può rivelare attività sospette
3. **Dispositivi USB** possono essere facilmente monitored tramite `/sys/bus/usb/devices/`
4. **Interfacce di rete** forniscono indicatori di compromissione tramite `/sys/class/net/`
5. **File cancellati ma aperti** (`lsof +L1`) possono indicare attività malevole
6. **Processi senza terminale** richiedono analisi approfondita per escludere backdoor
7. **Parametri kernel modificabili** in `/sys/kernel/` richiedono protezione adeguata

## Note di Sicurezza

> ⚠️ **IMPORTANTE**: L'analisi approfondita di `/proc/` e `/sys/` richiede privilegi root. Modifiche inappropriate ai parametri del kernel possono causare instabilità del sistema o compromissioni di sicurezza. Utilizzare sempre con cautela in ambiente di produzione.