# 3. Log monitoring setup
echo "Setting up log monitoring..."
mkdir -p /var/log/security
chmod 750 /var/log/security

# Logrotate configuration
cat > /etc/logrotate.d/security << EOF
/var/log/security/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 root adm
}
EOF

# 4. Fail2ban installation and configuration
if ! command -v fail2ban-client &> /dev/null; then
    echo "Installing fail2ban..."
    apt update && apt install -y fail2ban
fi

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[apache-auth]
enabled = false

[apache-badbots]
enabled = false

[apache-noscript]
enabled = false

[apache-overflows]
enabled = false
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# 5. System updates automation
cat > /etc/cron.daily/security-updates << 'EOF'
#!/bin/bash
apt update
apt list --upgradable | grep -i security > /var/log/security/pending_updates.log
if [ -s /var/log/security/pending_updates.log ]; then
    echo "Security updates available:" | mail -s "Security Updates Available" admin@company.com
fi
EOF
chmod +x /etc/cron.daily/security-updates

echo "✅ System hardening completed!"
```

#### Network Monitoring

```bash
#!/bin/bash
# Comprehensive network monitoring setup

# 1. Continuous packet capture con rotazione
setup_packet_capture() {
    local interface=$1
    local capture_dir="/var/log/network"
    
    mkdir -p $capture_dir
    
    # Script per capture continuo
    cat > /usr/local/bin/network_monitor.sh << EOF
#!/bin/bash
INTERFACE="$interface"
CAPTURE_DIR="$capture_dir"
MAX_SIZE="100M"
MAX_FILES="50"

# Capture con rotazione automatica
tcpdump -i \$INTERFACE -C \$MAX_SIZE -W \$MAX_FILES -w \$CAPTURE_DIR/capture.pcap &
TCPDUMP_PID=\$!
echo \$TCPDUMP_PID > /var/run/tcpdump.pid

# Monitor disk space
while true; do
    disk_usage=\$(df \$CAPTURE_DIR | tail -1 | awk '{print \$5}' | tr -d '%')
    if [ \$disk_usage -gt 80 ]; then
        echo "Disk space critical: \${disk_usage}%" | \\
        mail -s "Network Monitoring Disk Alert" admin@company.com
        
        # Pulisci file più vecchi
        find \$CAPTURE_DIR -name "*.pcap" -mtime +7 -delete
    fi
    sleep 300
done
EOF
    
    chmod +x /usr/local/bin/network_monitor.sh
    
    # Systemd service
    cat > /etc/systemd/system/network-monitor.service << EOF
[Unit]
Description=Network Traffic Monitoring
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/network_monitor.sh
PIDFile=/var/run/tcpdump.pid
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl enable network-monitor.service
    systemctl start network-monitor.service
}

# 2. Intrusion Detection System
setup_ids() {
    echo "Setting up custom IDS..."
    
    cat > /usr/local/bin/simple_ids.sh << 'EOF'
#!/bin/bash
# Simple signature-based IDS

RULES_FILE="/etc/ids/rules.conf"
LOG_FILE="/var/log/security/ids.log"
ALERT_THRESHOLD=5

mkdir -p /etc/ids /var/log/security

# IDS Rules
cat > $RULES_FILE << RULES
# Signature rules (regex patterns)
RULE1="Multiple SSH failures:|Failed password.*ssh"
RULE2="Port scan detected:|SCAN DETECT"
RULE3="Suspicious executable:|/tmp/.*\.(sh|py|pl|exe)"
RULE4="Privilege escalation:|sudo.*su.*root"
RULE5="Network anomaly:|TCP.*flags.*NULL|XMAS"
RULES

# Monitor system logs
tail -f /var/log/syslog /var/log/auth.log | while read line; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Check against rules
    while IFS='=' read -r rule_name pattern; do
        if [[ $rule_name =~ ^RULE[0-9]+$ ]] && echo "$line" | grep -qE "$pattern"; then
            alert_msg="$timestamp - $rule_name triggered: $line"
            echo "$alert_msg" >> $LOG_FILE
            
            # Count recent alerts
            recent_alerts=$(grep "$rule_name" $LOG_FILE | tail -n 100 | wc -l)
            
            if [ $recent_alerts -gt $ALERT_THRESHOLD ]; then
                echo "🚨 IDS ALERT: $rule_name threshold exceeded ($recent_alerts alerts)" | \
                mail -s "IDS Alert - $rule_name" admin@company.com
            fi
        fi
    done < $RULES_FILE
done
EOF
    
    chmod +x /usr/local/bin/simple_ids.sh
    
    # Systemd service per IDS
    cat > /etc/systemd/system/simple-ids.service << EOF
[Unit]
Description=Simple Intrusion Detection System
After=rsyslog.service

[Service]
Type=simple
ExecStart=/usr/local/bin/simple_ids.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl enable simple-ids.service
    systemctl start simple-ids.service
}

# 3. Honeypot setup
setup_honeypot() {
    echo "Setting up honeypot services..."
    
    # SSH honeypot su porta alternativa
    cat > /usr/local/bin/ssh_honeypot.py << 'EOF'
#!/usr/bin/env python3
import socket
import threading
import datetime
import logging

# Setup logging
logging.basicConfig(
    filename='/var/log/security/honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def handle_connection(conn, addr):
    try:
        logging.info(f"SSH Honeypot connection from {addr[0]}:{addr[1]}")
        
        # Fake SSH banner
        conn.send(b"SSH-2.0-OpenSSH_8.0\r\n")
        
        # Read client data
        data = conn.recv(1024)
        if data:
            logging.info(f"Data received from {addr[0]}: {data[:100]}")
        
        # Simulate authentication delay
        import time
        time.sleep(2)
        
        # Send fake failure
        conn.send(b"Authentication failed\r\n")
        
    except Exception as e:
        logging.error(f"Honeypot error: {e}")
    finally:
        conn.close()

def run_honeypot(port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    
    logging.info(f"SSH Honeypot started on port {port}")
    
    while True:
        try:
            conn, addr = sock.accept()
            thread = threading.Thread(target=handle_connection, args=(conn, addr))
            thread.daemon = True
            thread.start()
        except KeyboardInterrupt:
            break
    
    sock.close()

if __name__ == "__main__":
    run_honeypot()
EOF
    
    chmod +x /usr/local/bin/ssh_honeypot.py
    
    # Systemd service per honeypot
    cat > /etc/systemd/system/ssh-honeypot.service << EOF
[Unit]
Description=SSH Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssh_honeypot.py
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl enable ssh-honeypot.service
    systemctl start ssh-honeypot.service
}

# Execute setup functions
echo "🛡️ Setting up comprehensive monitoring..."
setup_packet_capture "eth0"  # Adatta all'interfaccia corretta
setup_ids
setup_honeypot

echo "✅ Network monitoring setup completed!"
```

### Performance Optimization

#### Resource Management

```bash
#!/bin/bash
# Ottimizzazione performance per security monitoring

# 1. Log rotation ottimizzata
optimize_logging() {
    echo "Optimizing logging performance..."
    
    # Configurazione rsyslog ottimizzata
    cat >> /etc/rsyslog.conf << EOF

# Performance optimizations
\$WorkDirectory /var/spool/rsyslog
\$ActionQueueFileName fwdRule1
\$ActionQueueMaxDiskSpace 1g
\$ActionQueueSaveOnShutdown on
\$ActionQueueType LinkedList
\$ActionResumeRetryCount -1

# Security logs separation
if \$programname == 'iptables' then /var/log/security/firewall.log
& stop
if \$programname == 'sshd' then /var/log/security/ssh.log
& stop
if \$programname startswith 'fail2ban' then /var/log/security/fail2ban.log
& stop
EOF

    systemctl restart rsyslog
    
    # Logrotate ottimizzato per security logs
    cat > /etc/logrotate.d/security-optimized << EOF
/var/log/security/*.log {
    hourly
    missingok
    rotate 168
    compress
    delaycompress
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}

/var/log/security/firewall.log {
    size 100M
    rotate 10
    compress
    missingok
    notifempty
    create 0640 root adm
}
EOF
}

# 2. Database per log analysis
setup_log_database() {
    echo "Setting up log analysis database..."
    
    # Install SQLite per log analysis
    apt install -y sqlite3
    
    # Create database schema
    cat > /usr/local/bin/create_security_db.sql << EOF
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME,
    event_type TEXT,
    source_ip TEXT,
    destination_port INTEGER,
    message TEXT,
    severity TEXT,
    INDEX(timestamp),
    INDEX(source_ip),
    INDEX(event_type)
);

CREATE TABLE IF NOT EXISTS ssh_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME,
    source_ip TEXT,
    username TEXT,
    success BOOLEAN,
    INDEX(timestamp),
    INDEX(source_ip)
);

CREATE TABLE IF NOT EXISTS port_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME,
    source_ip TEXT,
    target_port INTEGER,
    scan_type TEXT,
    INDEX(timestamp),
    INDEX(source_ip)
);
EOF
    
    sqlite3 /var/db/security.db < /usr/local/bin/create_security_db.sql
    
    # Script per import log in database
    cat > /usr/local/bin/log_to_db.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import re
import sys
from datetime import datetime

def parse_log_line(line):
    # Parse different log formats
    patterns = {
        'ssh_fail': r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (\w+) from ([\d.]+)',
        'ssh_success': r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\w+) from ([\d.]+)',
        'port_scan': r'(\w+\s+\d+\s+\d+:\d+:\d+).*SCAN DETECT.*SRC=([\d.]+).*DPT=(\d+)'
    }
    
    for event_type, pattern in patterns.items():
        match = re.search(pattern, line)
        if match:
            return event_type, match.groups()
    
    return None, None

def insert_event(db_path, event_type, data):
    conn = sqlite3.connect(db_path)
    
    if event_type in ['ssh_fail', 'ssh_success']:
        timestamp, username, source_ip = data
        success = event_type == 'ssh_success'
        
        conn.execute('''
            INSERT INTO ssh_attempts (timestamp, source_ip, username, success)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, source_ip, username, success))
        
    elif event_type == 'port_scan':
        timestamp, source_ip, port = data
        
        conn.execute('''
            INSERT INTO port_scans (timestamp, source_ip, target_port, scan_type)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, source_ip, int(port), 'SYN'))
    
    conn.commit()
    conn.close()

# Process stdin
db_path = '/var/db/security.db'
for line in sys.stdin:
    event_type, data = parse_log_line(line.strip())
    if event_type:
        insert_event(db_path, event_type, data)
EOF
    
    chmod +x /usr/local/bin/log_to_db.py
    
    # Pipe log in database
    echo "tail -f /var/log/auth.log /var/log/security/firewall.log | /usr/local/bin/log_to_db.py &" >> /etc/rc.local
}

# 3. Memory optimization
optimize_memory() {
    echo "Optimizing memory usage..."
    
    # Kernel parameters per networking
    cat >> /etc/sysctl.conf << EOF

# Network security optimizations
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 3
net.core.netdev_max_backlog = 5000

# Memory optimization
vm.swappiness = 10
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
EOF
    
    sysctl -p
    
    # Process monitoring
    cat > /usr/local/bin/memory_monitor.sh << 'EOF'
#!/bin/bash
THRESHOLD=80
LOG_FILE="/var/log/security/memory_usage.log"

while true; do
    memory_usage=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}')
    
    if [ $memory_usage -gt $THRESHOLD ]; then
        echo "$(date): Memory usage critical: ${memory_usage}%" >> $LOG_FILE
        
        # Find memory hogs
        ps aux --sort=-%mem | head -10 >> $LOG_FILE
        
        # Alert
        echo "Memory usage critical: ${memory_usage}%" | \
        mail -s "Memory Alert" admin@company.com
    fi
    
    sleep 60
done
EOF
    
    chmod +x /usr/local/bin/memory_monitor.sh
    nohup /usr/local/bin/memory_monitor.sh &
}

# Execute optimizations
optimize_logging
setup_log_database  
optimize_memory

echo "✅ Performance optimization completed!"
```

### Compliance and Reporting

#### Automated Compliance Checks

```bash
#!/bin/bash
# Security compliance automation

generate_security_report() {
    local report_date=$(date '+%Y-%m-%d')
    local report_file="/var/reports/security_report_$report_date.html"
    
    mkdir -p /var/reports
    
    cat > $report_file << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Compliance Report - $report_date</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>🛡️ Security Compliance Report</h1>
    <p><strong>Generated:</strong> $report_date</p>
    <p><strong>System:</strong> $(hostname)</p>
    
    <h2>📋 Compliance Checks</h2>
    <table>
        <tr><th>Check</th><th>Status</th><th>Details</th></tr>
EOF

    # SSH Configuration Checks
    check_ssh_config() {
        local status="PASS"
        local details=""
        
        if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config; then
            status="FAIL"
            details="Root login enabled"
        fi
        
        if ! grep -q "MaxAuthTries" /etc/ssh/sshd_config; then
            status="WARNING"
            details="MaxAuthTries not configured"
        fi
        
        echo "<tr><td>SSH Configuration</td><td class='$(echo $status | tr '[:upper:]' '[:lower:]')'>$status</td><td>$details</td></tr>"
    }
    
    # Firewall Status Check
    check_firewall() {
        local status="PASS"
        local details="Firewall active"
        
        if ! iptables -L | grep -q "DROP"; then
            status="FAIL"
            details="No DROP rules found"
        fi
        
        echo "<tr><td>Firewall Status</td><td class='$(echo $status | tr '[:upper:]' '[:lower:]')'>$status</td><td>$details</td></tr>"
    }
    
    # User Account Security
    check_user_security() {
        local status="PASS"
        local details=""
        
        # Check for accounts without passwords
        empty_passwords=$(awk -F: '($2 == "") {print $1}' /etc/shadow | wc -l)
        if [ $empty_passwords -gt 0 ]; then
            status="FAIL"
            details="$empty_passwords accounts without passwords"
        fi
        
        # Check for UID 0 accounts other than root
        root_accounts=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v root | wc -l)
        if [ $root_accounts -gt 0 ]; then
            status="FAIL"
            details="$root_accounts non-root accounts with UID 0"
        fi
        
        echo "<tr><td>User Account Security</td><td class='$(echo $status | tr '[:upper:]' '[:lower:]')'>$status</td><td>$details</td></tr>"
    }
    
    # File Permissions Check
    check_file_permissions() {
        local status="PASS"
        local details=""
        
        # Check for world-writable files
        world_writable=$(find /etc /bin /sbin /usr/bin /usr/sbin -type f -perm -002 2>/dev/null | wc -l)
        if [ $world_writable -gt 0 ]; then
            status="WARNING"
            details="$world_writable world-writable files found"
        fi
        
        echo "<tr><td>File Permissions</td><td class='$(echo $status | tr '[:upper:]' '[:lower:]')'>$status</td><td>$details</td></tr>"
    }
    
    # Execute checks
    check_ssh_config >> $report_file
    check_firewall >> $report_file
    check_user_security >> $report_file
    check_file_permissions >> $report_file
    
    cat >> $report_file << EOF
    </table>
    
    <h2>📊 Security Statistics</h2>
    <table>
        <tr><th>Metric</th><th>Last 24h</th><th>Last 7 days</th></tr>
        <tr><td>SSH Login Attempts</td><td>$(grep "$(date '+%b %d')" /var/log/auth.log | grep "sshd" | wc -l)</td><td>$(grep "sshd" /var/log/auth.log | wc -l)</td></tr>
        <tr><td>Failed Logins</td><td>$(grep "$(date '+%b %d')" /var/log/auth.log | grep "Failed password" | wc -l)</td><td>$(grep "Failed password" /var/log/auth.log | wc -l)</td></tr>
        <tr><td>Firewall Blocks</td><td>$(grep "$(date '+%b %d')" /var/log/syslog | grep "SCAN DETECT" | wc -l)</td><td>$(grep "SCAN DETECT" /var/log/syslog | wc -l)</td></tr>
        <tr><td>Sudo Usage</td><td>$(grep "$(date '+%b %d')" /var/log/auth.log | grep "sudo.*COMMAND" | wc -l)</td><td>$(grep "sudo.*COMMAND" /var/log/auth.log | wc -l)</td></tr>
    </table>
    
    <h2>🔍 Recent Security Events</h2>
    <h3>Failed SSH Attempts</h3>
    <pre>$(tail -20 /var/log/auth.log | grep "Failed password" | tail -10)</pre>
    
    <h3>Port Scan Attempts</h3>
    <pre>$(tail -20 /var/log/syslog | grep "SCAN DETECT" | tail -10)</pre>
    
    <h2>🖥️ System Information</h2>
    <table>
        <tr><th>Component</th><th>Status</th></tr>
        <tr><td>Uptime</td><td>$(uptime)</td></tr>
        <tr><td>Disk Usage</td><td>$(df -h / | tail -1 | awk '{print $5}')</td></tr>
        <tr><td>Memory Usage</td><td>$(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}')</td></tr>
        <tr><td>Load Average</td><td>$(uptime | awk -F'load average:' '{print $2}')</td></tr>
    </table>
    
    <hr>
    <p><small>Report generated by Security Monitoring System - $(date)</small></p>
</body>
</html>
EOF

    echo "Security report generated: $report_file"
    
    # Email report
    echo "Security compliance report attached." | \
    mail -s "Daily Security Report - $(hostname)" -A $report_file admin@company.com
}

# Schedule daily reports
echo "0 6 * * * root /usr/local/bin/generate_security_report.sh" >> /etc/crontab

# Create the script
cat > /usr/local/bin/generate_security_report.sh << 'EOF'
#!/bin/bash
source /path/to/compliance_functions.sh
generate_security_report
EOF

chmod +x /usr/local/bin/generate_security_report.sh
```

---

**Conclusioni Defensive Security**:

La sicurezza difensiva richiede un approccio multi-layer che combina:
- **Monitoring proattivo** con journalctl e log analysis
- **Firewall configuration** con detection avanzato
- **Incident response** automatizzato e scalabile
- **Compliance** continuo con reporting automatico

I log di sistema sono una miniera d'oro per la security intelligence, ma richiedono analisi strutturata e automation per essere efficaci. L'integrazione di multiple tecnologie (iptables, fail2ban, custom scripts) crea una defense in depth robusta.

**Key takeaways**:
- SSH forensics rivela pattern di attacco chiari
- Port scan detection è facilmente implementabile
- Automation è essenziale per response tempestivo
- Performance optimization previene degradazione servizi

[← Networking](../networking/README.md) | [Windows Security →](../windows-security/README.md)
```

#### Formattazione Output

```bash
# Output JSON per parsing
sudo journalctl -o json | jq '.'

# Output compatto
sudo journalctl -o short

# Output dettagliato
sudo journalctl -o verbose

# Solo messaggi (no timestamp)
sudo journalctl -o cat
```

#### Esempio Log Analysis Reale

**Sistema sotto osservazione**:
```bash
sudo journalctl -n 10 -f
```

**Output catturato**:
```
lug 17 17:36:17 TheArrival spotify[6957]: App Name is not available when using Portal Notifications
lug 17 17:36:21 TheArrival NetworkManager[774]: <info> device (wlo1): set-hw-addr: set MAC address to AE:59:03:B4:79:E9 (scanning)
lug 17 17:36:22 TheArrival NetworkManager[774]: <info> device (wlo1): supplicant interface state: disconnected -> interface_disabled
lug 17 17:36:42 TheArrival unix_chkpwd[56348]: password check failed for user (alessandro)
lug 17 17:36:42 TheArrival sudo[56346]: pam_unix(sudo:auth): authentication failure; logname=alessandro uid=1000 euid=0 tty=/dev/pts/4 ruser=alessandro rhost= user=alessandro
lug 17 17:36:46 TheArrival sudo[56346]: alessandro : TTY=pts/4 ; PWD=/home/alessandro ; USER=root ; COMMAND=/usr/bin/journalctl -n 10 -f
lug 17 17:36:46 TheArrival sudo[56346]: pam_unix(sudo:session): session opened for user root(uid=0) by alessandro(uid=1000)
```

**Analisi dettagliata**:
- **Spotify notification**: Applicazione desktop normale
- **NetworkManager**: Cambio MAC address per scanning WiFi
- **WiFi disconnect**: Problemi di connettività (segnale debole)
- **Password failure**: Tentativo sudo fallito (errore digitazione)
- **Auth failure**: Stesso evento dal punto di vista PAM
- **Successful sudo**: Accesso root riuscito dopo retry
- **Session opened**: Escalation privilegi completata

### Ricerca Avanzata nei Log

#### Grep con journalctl

```bash
# Combinazione potente
sudo journalctl | grep -E "(failed|error|denied)" | tail -20

# Multiline grep
sudo journalctl | grep -A 3 -B 3 "authentication failure"

# Case insensitive
sudo journalctl | grep -i "critical"
```

#### Analisi Pattern Comuni

```bash
# Login failures
sudo journalctl | grep "authentication failure" | wc -l

# Sudo usage
sudo journalctl | grep "sudo.*COMMAND" | awk '{print $6,$11}' | sort | uniq -c

# Service restarts
sudo journalctl | grep "started\|stopped" | grep -v "session"
```

## Firewall Configuration

### iptables - Packet Filtering

#### Verifica Configurazione Attuale

```bash
# Lista regole con numeri di linea
sudo iptables -L --line-numbers -v

# Policy di default
sudo iptables -L | grep "policy"
```

**Output tipico sistema default**:
```
Chain INPUT (policy ACCEPT)
Chain FORWARD (policy ACCEPT)  
Chain OUTPUT (policy ACCEPT)
```

**⚠️ Sicurezza**: Policy ACCEPT di default = nessuna protezione!

#### Sintassi Base iptables

```bash
# Struttura comando
iptables [-t table] [operation] [chain] [match criteria] [-j target]

# Operazioni principali:
# -A    Append (aggiunge in fondo)
# -I    Insert (inserisce in posizione specifica)
# -R    Replace (sostituisce regola)
# -D    Delete (cancella regola)
# -F    Flush (cancella tutte le regole)
```

#### Regole Base di Sicurezza

```bash
# Permettere loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Permettere connessioni stabilite
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH con rate limiting
sudo iptables -A INPUT -p tcp --dport 22 -m recent --set --name SSH
sudo iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Bloccare tutto il resto
sudo iptables -A INPUT -j DROP
```

#### Logging Avanzato

```bash
# Log tentativi di connessione negati
sudo iptables -A INPUT -j LOG --log-prefix "DROPPED: " --log-level 4

# Log port scan detection
sudo iptables -A INPUT -j LOG --log-prefix "SCAN DETECT: " --log-level 4

# Log con rate limiting (evita spam)
sudo iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "RATE LIMITED: "
```

#### Protezione DDoS Base

```bash
# Limite connessioni simultanee
sudo iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP

# Protezione SYN flood
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP

# Blocco port scan comuni
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "NULL-SCAN: "
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "XMAS-SCAN: "  
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
```

## SSH Forensics

### Analisi Accessi SSH

#### Monitoring SSH Activity

```bash
# Tutti gli eventi SSH
sudo journalctl -u sshd

# Solo login falliti
sudo journalctl -u sshd | grep "Failed"

# Solo login riusciti
sudo journalctl -u sshd | grep "Accepted"

# Sessioni aperte/chiuse
sudo journalctl -u sshd | grep -E "(session opened|session closed)"
```

#### Esempio Analisi Reale

**Log sequence catturata**:
```
lug 17 17:56:15 TheArrival sshd-session[57457]: Failed password for alessandro from 192.168.130.234 port 44504 ssh2
lug 17 17:56:19 TheArrival sshd-session[57457]: Accepted password for alessandro from 192.168.130.234 port 44504 ssh2
lug 17 17:56:19 TheArrival sshd-session[57457]: pam_unix(sshd:session): session opened for user alessandro(uid=1000) by alessandro(uid=0)
```

**Timeline analysis**:
1. **17:56:15**: Tentativo login fallito
2. **17:56:19**: Login riuscito (4 secondi dopo)
3. **17:56:19**: Sessione PAM aperta

**Indicatori**:
- IP source: 192.168.130.234 (rete locale)
- Username: alessandro (account valido)
- Metodo: password authentication
- Intervallo: 4 secondi tra fallimento e successo

#### Post-Login Activity Analysis

```bash
# Comandi sudo eseguiti dopo login SSH
sudo journalctl | grep "alessandro.*COMMAND" | grep "pts/11"
```

**Output correlato**:
```
lug 17 17:58:00 TheArrival sudo[57563]: alessandro : TTY=pts/11 ; PWD=/home/alessandro ; USER=root ; COMMAND=/usr/bin/su
lug 17 17:58:00 TheArrival sudo[57563]: pam_unix(sudo:session): session opened for user root(uid=0) by alessandro(uid=1000)
lug 17 17:58:00 TheArrival su[57572]: (to root) root on pts/12
lug 17 17:58:00 TheArrival su[57572]: pam_unix(su:session): session opened for user root(uid=0) by alessandro(uid=0)
```

**Escalation pattern**:
1. Login SSH come alessandro
2. `sudo su` per diventare root
3. Apertura sessione root su pts/12

#### Brute Force Detection

```bash
#!/bin/bash
# Script detection brute force SSH
LOG_FILE="/var/log/ssh_analysis.log"
THRESHOLD=5
TIMEFRAME=300  # 5 minuti

analyze_ssh_failures() {
    echo "=== SSH BRUTE FORCE ANALYSIS ===" > $LOG_FILE
    
    # Estrai IP con tentativi falliti
    sudo journalctl -u sshd | grep "Failed password" | \
    awk '{print $9}' | sort | uniq -c | \
    while read count ip; do
        if [ $count -gt $THRESHOLD ]; then
            echo "🚨 ALERT: $ip - $count failed attempts" >> $LOG_FILE
            
            # Verifica se negli ultimi 5 minuti
            recent_failures=$(sudo journalctl --since "5 minutes ago" -u sshd | \
                             grep "Failed password" | grep $ip | wc -l)
            
            if [ $recent_failures -gt 3 ]; then
                echo "⚠️  ACTIVE ATTACK: $ip - $recent_failures recent failures" >> $LOG_FILE
                # Auto-block con iptables
                sudo iptables -A INPUT -s $ip -j DROP
                echo "🛡️  BLOCKED: $ip" >> $LOG_FILE
            fi
        fi
    done
    
    cat $LOG_FILE
}

analyze_ssh_failures
```

#### Geographic Analysis

```bash
# Estrai IP esterni per geo-lookup
sudo journalctl -u sshd | grep "Failed password" | \
awk '{print $9}' | grep -v "192.168\|10\.\|172\." | \
sort | uniq > external_ips.txt

# Manual GeoIP lookup (richiede geoiplookup)
while read ip; do
    location=$(geoiplookup $ip | cut -d: -f2)
    echo "$ip: $location"
done < external_ips.txt
```

## Port Scan Detection

### Real-time Detection con iptables

#### Setup Detection Rules

```bash
# Regola base per port scan detection
sudo iptables -I INPUT -j LOG --log-prefix 'SCAN DETECT: '

# Detection più granulare
sudo iptables -I INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "NULL SCAN: "
sudo iptables -I INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "XMAS SCAN: "
sudo iptables -I INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "SYN-RST SCAN: "
```

#### Monitoring in Real-time

```bash
# Monitor scan detection
sudo journalctl -f | grep 'SCAN DETECT'

# Script per alerting automatico
#!/bin/bash
tail -f /var/log/syslog | grep "SCAN DETECT" | while read line; do
    timestamp=$(echo $line | awk '{print $1,$2,$3}')
    src_ip=$(echo $line | awk '{print $6}' | cut -d= -f2)
    dst_port=$(echo $line | awk '{print $8}' | cut -d= -f2)
    
    echo "⚠️ Port scan detected: $src_ip → port $dst_port at $timestamp"
    
    # Conteggio tentativi da stesso IP
    scan_count=$(grep "SCAN DETECT.*$src_ip" /var/log/syslog | wc -l)
    
    if [ $scan_count -gt 10 ]; then
        echo "🚨 MASSIVE SCAN: $src_ip ($scan_count attempts)"
        # Auto-block
        iptables -A INPUT -s $src_ip -j DROP
        echo "🛡️ Blocked $src_ip"
    fi
done
```

#### Test Port Scan Detection

**Trigger nmap scan**:
```bash
# Da altro terminale
nmap -sS localhost
```

**Output detection catturato**:
```
lug 18 09:49:40 kernel: SCAN DETECT: IN=lo OUT= MAC=00:00:... SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT=56292 DPT=1106 FLAGS=SYN
lug 18 09:49:40 kernel: SCAN DETECT: IN=lo OUT= MAC=00:00:... SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT=1106 DPT=56292 FLAGS=ACK RST
lug 18 09:49:40 kernel: SCAN DETECT: IN=lo OUT= MAC=00:00:... SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT=50894 DPT=3300 FLAGS=SYN
```

**Pattern analysis**:
- **SYN packets**: Indicano port scan attivo
- **ACK RST**: Porte chiuse che rispondono
- **Porte sequenziali**: Pattern di scanning sistematico

### Advanced Scan Detection

#### Honeypot Ports

```bash
# Setup porte honeypot (non utilizzate)
for port in 1234 5678 9999; do
    iptables -A INPUT -p tcp --dport $port -j LOG --log-prefix "HONEYPOT-$port: "
    iptables -A INPUT -p tcp --dport $port -j DROP
done

# Qualsiasi connessione a queste porte = attività sospetta
```

#### Scan Speed Detection

```bash
#!/bin/bash
# Detection scan veloci (possibile automated tools)
TEMP_FILE="/tmp/port_scan_analysis"
TIME_WINDOW=10  # secondi
PORT_THRESHOLD=20  # porte diverse in time window

monitor_scan_speed() {
    tail -f /var/log/syslog | grep "SCAN DETECT" | while read line; do
        timestamp=$(date +%s)
        src_ip=$(echo $line | awk '{print $6}' | cut -d= -f2)
        dst_port=$(echo $line | awk '{print $8}' | cut -d= -f2)
        
        # Log entry con timestamp
        echo "$timestamp $src_ip $dst_port" >> $TEMP_FILE
        
        # Pulisci entries più vecchie di TIME_WINDOW
        cutoff=$((timestamp - TIME_WINDOW))
        awk -v cutoff=$cutoff '$1 > cutoff' $TEMP_FILE > $TEMP_FILE.new
        mv $TEMP_FILE.new $TEMP_FILE
        
        # Conta porte uniche per IP nel time window
        unique_ports=$(awk -v ip=$src_ip '$2 == ip {print $3}' $TEMP_FILE | sort -u | wc -l)
        
        if [ $unique_ports -gt $PORT_THRESHOLD ]; then
            echo "🚨 FAST SCAN DETECTED: $src_ip hit $unique_ports ports in ${TIME_WINDOW}s"
            # Immediate block
            iptables -A INPUT -s $src_ip -j DROP
            echo "⚡ FAST-BLOCKED: $src_ip"
        fi
    done
}

monitor_scan_speed
```

## Incident Response

### Automated Response System

#### Tiered Response Framework

```bash
#!/bin/bash
# Incident Response Automation
ALERT_EMAIL="admin@company.com"
LOG_DIR="/var/log/security"
QUARANTINE_DIR="/quarantine"

# Livelli di risposta
LEVEL_1_THRESHOLD=5    # Suspicious
LEVEL_2_THRESHOLD=15   # Malicious  
LEVEL_3_THRESHOLD=50   # Critical

incident_response() {
    local event_type=$1
    local source_ip=$2
    local event_count=$3
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Logging centralizzato
    echo "$timestamp - $event_type - $source_ip - Count: $event_count" >> $LOG_DIR/incidents.log
    
    if [ $event_count -ge $LEVEL_3_THRESHOLD ]; then
        # LEVEL 3: Critical Response
        echo "🔴 CRITICAL INCIDENT: $event_type from $source_ip"
        
        # Immediate isolation
        iptables -A INPUT -s $source_ip -j DROP
        iptables -A OUTPUT -d $source_ip -j DROP
        
        # Network segment isolation se necessario
        if [[ $source_ip =~ ^192\.168\.1\. ]]; then
            echo "Internal threat detected - isolating segment"
            iptables -A FORWARD -s 192.168.1.0/24 -j DROP
        fi
        
        # Alert immediato
        echo "CRITICAL SECURITY INCIDENT: $event_type from $source_ip at $timestamp" | \
        mail -s "🔴 CRITICAL ALERT - Immediate Response Required" $ALERT_EMAIL
        
        # System snapshot per forensics
        df -h > $LOG_DIR/system_snapshot_$timestamp.txt
        ps aux >> $LOG_DIR/system_snapshot_$timestamp.txt
        netstat -tulpn >> $LOG_DIR/system_snapshot_$timestamp.txt
        
    elif [ $event_count -ge $LEVEL_2_THRESHOLD ]; then
        # LEVEL 2: Malicious Activity
        echo "🟡 MALICIOUS ACTIVITY: $event_type from $source_ip"
        
        # Rate limiting invece di block completo
        iptables -A INPUT -s $source_ip -m limit --limit 1/min -j ACCEPT
        iptables -A INPUT -s $source_ip -j DROP
        
        # Alert con delay
        echo "Malicious activity detected: $event_type from $source_ip" | \
        mail -s "🟡 Security Alert - Malicious Activity" $ALERT_EMAIL
        
    elif [ $event_count -ge $LEVEL_1_THRESHOLD ]; then
        # LEVEL 1: Suspicious Activity
        echo "🟢 SUSPICIOUS ACTIVITY: $event_type from $source_ip"
        
        # Solo logging, no blocking
        echo "$timestamp - SUSPICIOUS: $source_ip - $event_type" >> $LOG_DIR/suspicious.log
        
        # Monitoring aumentato
        tcpdump -i any host $source_ip -w $LOG_DIR/capture_$source_ip_$timestamp.pcap &
        TCPDUMP_PID=$!
        sleep 300  # 5 minuti di capture
        kill $TCPDUMP_PID 2>/dev/null
    fi
}

# Integrazione con detection scripts
monitor_and_respond() {
    tail -f /var/log/syslog | while read line; do
        if echo $line | grep -q "SCAN DETECT"; then
            source_ip=$(echo $line | awk '{print $6}' | cut -d= -f2)
            scan_count=$(grep "SCAN DETECT.*$source_ip" /var/log/syslog | wc -l)
            incident_response "PORT_SCAN" $source_ip $scan_count
            
        elif echo $line | grep -q "Failed password"; then
            source_ip=$(echo $line | awk '{print $9}')
            fail_count=$(grep "Failed password.*$source_ip" /var/log/auth.log | wc -l)
            incident_response "BRUTE_FORCE" $source_ip $fail_count
        fi
    done
}
```

#### Forensics Data Collection

```bash
#!/bin/bash
# Automated forensics collection
collect_forensics() {
    local incident_id=$1
    local target_ip=$2
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local forensics_dir="/var/forensics/$incident_id_$timestamp"
    
    mkdir -p $forensics_dir
    
    echo "🔍 Collecting forensics for incident $incident_id"
    
    # System state
    date > $forensics_dir/collection_time.txt
    uname -a > $forensics_dir/system_info.txt
    uptime > $forensics_dir/uptime.txt
    
    # Process information
    ps auxf > $forensics_dir/processes.txt
    lsof > $forensics_dir/open_files.txt
    
    # Network state
    netstat -tulpn > $forensics_dir/network_connections.txt
    ss -tulpn > $forensics_dir/socket_stats.txt
    arp -a > $forensics_dir/arp_table.txt
    
    # Memory info
    free -h > $forensics_dir/memory.txt
    cat /proc/meminfo > $forensics_dir/meminfo.txt
    
    # Recent logs
    journalctl --since "1 hour ago" > $forensics_dir/recent_logs.txt
    
    # Network capture se IP specificato
    if [ ! -z "$target_ip" ]; then
        echo "Starting network capture for $target_ip"
        timeout 300 tcpdump -i any host $target_ip -w $forensics_dir/network_capture.pcap &
    fi
    
    # File integrity check
    find /bin /sbin /usr/bin /usr/sbin -type f -exec md5sum {} \; > $forensics_dir/binary_hashes.txt
    
    # Package per archivio
    tar -czf $forensics_dir.tar.gz $forensics_dir/
    
    echo "✅ Forensics collected: $forensics_dir.tar.gz"
}
```

## Monitoring Automation

### Centralized Security Dashboard

#### Log Aggregation

```bash
#!/bin/bash
# Security events aggregation
DASHBOARD_DIR="/var/security_dashboard"
REFRESH_INTERVAL=30

generate_security_dashboard() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    cat > $DASHBOARD_DIR/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Dashboard</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { font-family: monospace; background: #1a1a1a; color: #00ff00; }
        .alert { color: #ff0000; font-weight: bold; }
        .warning { color: #ffff00; }
        .info { color: #00ffff; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #333; padding: 5px; text-align: left; }
    </style>
</head>
<body>
    <h1>🛡️ Security Dashboard - $timestamp</h1>
    
    <h2>🚨 Active Alerts</h2>
    <table>
        <tr><th>Time</th><th>Type</th><th>Source</th><th>Count</th><th>Status</th></tr>
EOF

    # Port scan alerts
    tail -50 /var/log/syslog | grep "SCAN DETECT" | tail -10 | while read line; do
        time=$(echo $line | awk '{print $1,$2,$3}')
        src=$(echo $line | awk '{print $6}' | cut -d= -f2)
        echo "        <tr class='alert'><td>$time</td><td>Port Scan</td><td>$src</td><td>Active</td><td>🔴 Monitoring</td></tr>" >> $DASHBOARD_DIR/index.html
    done
    
    # SSH brute force
    tail -50 /var/log/auth.log | grep "Failed password" | tail -5 | while read line; do
        time=$(echo $line | awk '{print $1,$2,$3}')
        src=$(echo $line | awk '{print $9}')
        echo "        <tr class='warning'><td>$time</td><td>SSH Brute Force</td><td>$src</td><td>Failed Login</td><td>🟡 Tracking</td></tr>" >> $DASHBOARD_DIR/index.html
    done
    
    cat >> $DASHBOARD_DIR/index.html << EOF
    </table>
    
    <h2>📊 System Stats</h2>
    <pre>
$(uptime)
$(free -h | head -2)
$(df -h | grep -E "/$|/var|/home")
    </pre>
    
    <h2>🌐 Network Activity</h2>
    <pre>
$(netstat -i | head -5)
$(ss -s)
    </pre>
    
    <h2>🔍 Recent Security Events</h2>
    <pre>
$(tail -20 /var/log/security/incidents.log 2>/dev/null || echo "No incidents logged")
    </pre>
    
</body>
</html>
EOF

    echo "Dashboard updated: $timestamp"
}

# Aggiornamento continuo
while true; do
    generate_security_dashboard
    sleep $REFRESH_INTERVAL
done
```

#### Alerting System

```bash
#!/bin/bash
# Multi-channel alerting system
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
EMAIL_LIST="admin@company.com security@company.com"
TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN"
TELEGRAM_CHAT_ID="YOUR_CHAT_ID"

send_alert() {
    local severity=$1
    local title=$2
    local message=$3
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Color coding
    case $severity in
        "CRITICAL") color="#ff0000"; emoji="🔴" ;;
        "HIGH")     color="#ff8800"; emoji="🟠" ;;
        "MEDIUM")   color="#ffff00"; emoji="🟡" ;;
        "LOW")      color="#00ff00"; emoji="🟢" ;;
        *)          color="#ffffff"; emoji="ℹ️" ;;
    esac
    
    # Email alert
    echo "[$severity] $title - $timestamp
    
$message

System: $(hostname)
Time: $timestamp
Severity: $severity" | mail -s "[$severity] Security Alert: $title" $EMAIL_LIST
    
    # Slack alert
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"$emoji [$severity] $title\",\"attachments\":[{\"color\":\"$color\",\"fields\":[{\"title\":\"Message\",\"value\":\"$message\",\"short\":false},{\"title\":\"System\",\"value\":\"$(hostname)\",\"short\":true},{\"title\":\"Time\",\"value\":\"$timestamp\",\"short\":true}]}]}" \
        $SLACK_WEBHOOK
    
    # Telegram alert (per critical)
    if [ "$severity" = "CRITICAL" ]; then
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d chat_id=$TELEGRAM_CHAT_ID \
            -d text="$emoji CRITICAL ALERT: $title
            
$message

System: $(hostname)
Time: $timestamp"
    fi
    
    # Log alert
    echo "$timestamp [$severity] $title - $message" >> /var/log/security/alerts.log
}

# Test alerts
# send_alert "CRITICAL" "Port Scan Detected" "Multiple port scan attempts from 192.168.1.100"
# send_alert "HIGH" "SSH Brute Force" "15 failed login attempts from external IP"
```

## Best Practices

### Hardening Checklist

#### System Configuration

```bash
#!/bin/bash
# Automated hardening script
echo "🛡️ Starting system hardening..."

# 1. SSH Hardening
backup_and_edit() {
    local file=$1
    cp $file $file.backup.$(date +%Y%m%d)
}

backup_and_edit /etc/ssh/sshd_config

# SSH security settings
cat >> /etc/ssh/sshd_config << EOF
# Security hardening
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
UsePAM yes
X11Forwarding no
PrintMotd no
Banner /etc/ssh/banner
EOF

# Create SSH banner
cat > /etc/ssh/banner << EOF
********************************************************************************
*                                WARNING                                       *
********************************************************************************
* This system is for authorized users only. All activities are monitored and  *
* logged. Unauthorized access is strictly prohibited and will be prosecuted   *
* to the full extent of the law.                                             *
********************************************************************************
EOF

# 2. Firewall setup
echo "Setting up firewall..."
iptables-save > /etc/iptables.backup

# Basic firewall rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH with protection
iptables -A INPUT -p tcp --dport 22 -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Web services (se necessario)
# iptables -A INPUT -p tcp --dport 80 -j ACCEPT
# iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP (limitato)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4

# 3. Log monitoring setup
echo "Setting up log monitoring..."
mkdir -p /# Defensive Security

Documentazione completa su tecniche difensive, log analysis, firewall configuration e incident response. Include detection di port scan, SSH forensics e monitoring proattivo del sistema.

## Indice

- [Log Analysis](#log-analysis)
- [Firewall Configuration](#firewall-configuration)
- [SSH Forensics](#ssh-forensics)
- [Port Scan Detection](#port-scan-detection)
- [Incident Response](#incident-response)
- [Monitoring Automation](#monitoring-automation)
- [Best Practices](#best-practices)

## Log Analysis

### journalctl - Systemd Journal

#### Comandi Base

```bash
# Visualizzazione log in tempo reale
sudo journalctl -f

# Ultime N righe
sudo journalctl -n 50

# Seguire specifico servizio
sudo journalctl -u sshd -f

# Log dall'ultimo boot
sudo journalctl -b
```

#### Filtri Temporali

```bash
# Ultima ora
sudo journalctl --since "1 hour ago"

# Ultimo giorno
sudo journalctl --since "yesterday"

# Range specifico
sudo journalctl --since "2025-07-17 15:00:00" --until "2025-07-17 18:00:00"

# Solo oggi
sudo journalctl --since today
```

#### Filtri per Priorità

```bash
# Solo errori critici
journalctl -p err

# Warning e superiori
journalctl -p warning

# Debug completo
journalctl -p debug

# Tabella priorit