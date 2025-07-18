Next Steps:
1. Review processes.csv for suspicious executables
2. Check registry_* files for unauthorized persistence
3. Analyze network_connections.csv for unusual outbound traffic
4. Correlate security_events.csv with timeline of incident
5. Verify installed_software.csv for unknown applications

CRITICAL CHECKS:
- Look for processes running from temp directories
- Verify all autostart registry entries
- Check for unsigned executables in system directories
- Review failed logon events for brute force attempts
- Examine PowerShell execution logs if available
"@
    
    $Summary | Out-File "$OutputPath\SUMMARY_README.txt"
    
    return $OutputPath
}

# Quick incident response
# $IRPath = Collect-IncidentData
```

#### Automated Threat Hunting

```powershell
# Threat hunting automation
function Start-ThreatHunt {
    param(
        [string]$OutputFile = "C:\temp\threat_hunt_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    )
    
    $Findings = @()
    
    # Hunt 1: Suspicious processes
    $SuspiciousProcesses = Get-Process | Where-Object {
        $_.Path -like "*temp*" -or 
        $_.Path -like "*appdata*" -or
        $_.ProcessName -like "*cmd*" -or
        $_.ProcessName -like "*powershell*"
    }
    
    if ($SuspiciousProcesses) {
        $Findings += "SUSPICIOUS PROCESSES DETECTED:"
        $SuspiciousProcesses | ForEach-Object {
            $Findings += "  - $($_.ProcessName) (PID: $($_.Id)) - Path: $($_.Path)"
        }
    }
    
    # Hunt 2: Unsigned executables in system directories
    $UnsignedSystemFiles = Get-ChildItem "C:\Windows\System32\*.exe" | ForEach-Object {
        $Sig = Get-AuthenticodeSignature $_.FullName
        if ($Sig.Status -ne "Valid") {
            [PSCustomObject]@{
                File = $_.FullName
                SignatureStatus = $Sig.Status
                Signer = $Sig.SignerCertificate.Subject
            }
        }
    }
    
    if ($UnsignedSystemFiles) {
        $Findings += "`nUNSIGNED SYSTEM EXECUTABLES:"
        $UnsignedSystemFiles | ForEach-Object {
            $Findings += "  - $($_.File) - Status: $($_.SignatureStatus)"
        }
    }
    
    # Hunt 3: Unusual network connections
    $SuspiciousConnections = Get-NetTCPConnection | Where-Object {
        $_.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 9999) -or
        $_.RemoteAddress -notlike "192.168.*" -and 
        $_.RemoteAddress -notlike "10.*" -and 
        $_.RemoteAddress -notlike "172.*" -and
        $_.RemoteAddress -ne "127.0.0.1" -and
        $_.RemoteAddress -ne "::"
    }
    
    if ($SuspiciousConnections) {
        $Findings += "`nSUSPICIOUS NETWORK CONNECTIONS:"
        $SuspiciousConnections | ForEach-Object {
            $Process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $Findings += "  - $($_.RemoteAddress):$($_.RemotePort) - Process: $($Process.ProcessName) (PID: $($_.OwningProcess))"
        }
    }
    
    # Hunt 4: Recent registry modifications
    $RecentlyModified = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | 
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
    
    if ($RecentlyModified) {
        $Findings += "`nRECENT REGISTRY MODIFICATIONS (Run keys):"
        $RecentlyModified | ForEach-Object {
            $Findings += "  - Modified: $($_.LastWriteTime) - Key: $($_.Name)"
        }
    }
    
    # Hunt 5: PowerShell execution artifacts
    $PSHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $PSHistory) {
        $SuspiciousPSCommands = Get-Content $PSHistory | Where-Object {
            $_ -like "*downloadstring*" -or
            $_ -like "*invoke-expression*" -or
            $_ -like "*invoke-webrequest*" -or
            $_ -like "*iex*" -or
            $_ -like "*-enc*" -or
            $_ -like "*bypass*"
        }
        
        if ($SuspiciousPSCommands) {
            $Findings += "`nSUSPICIOUS POWERSHELL COMMANDS IN HISTORY:"
            $SuspiciousPSCommands | ForEach-Object {
                $Findings += "  - $_"
            }
        }
    }
    
    # Hunt 6: Unusual services
    $SuspiciousServices = Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -like "*temp*" -or
        $_.PathName -like "*appdata*" -or
        ($_.PathName -notlike "*system32*" -and $_.PathName -notlike "*Program Files*")
    }
    
    if ($SuspiciousServices) {
        $Findings += "`nSUSPICIOUS SERVICES:"
        $SuspiciousServices | ForEach-Object {
            $Findings += "  - $($_.Name) - Path: $($_.PathName) - State: $($_.State)"
        }
    }
    
    # Output results
    if ($Findings.Count -gt 0) {
        $Report = @"
THREAT HUNTING REPORT
=====================
Scan Time: $(Get-Date)
System: $(hostname)

$($Findings -join "`n")

RECOMMENDED ACTIONS:
1. Investigate all suspicious processes and their parent processes
2. Verify legitimacy of unsigned executables
3. Block suspicious network connections at firewall level
4. Review and revert unauthorized registry changes
5. Analyze PowerShell execution logs for attack vectors
6. Validate all running services and their configurations

NEXT STEPS:
- Collect memory dumps of suspicious processes
- Perform network traffic analysis
- Check for persistence mechanisms in startup folders
- Review Windows Event Logs for correlation
- Consider endpoint isolation if compromise confirmed
"@
        
        $Report | Out-File $OutputFile
        Write-Host "Threat hunt completed. Report saved to: $OutputFile" -ForegroundColor Yellow
        
        if ($Findings.Count -gt 0) {
            Write-Host "POTENTIAL THREATS DETECTED!" -ForegroundColor Red
        }
    } else {
        Write-Host "No immediate threats detected in automated hunt." -ForegroundColor Green
    }
    
    return $OutputFile
}

# Execute threat hunt
# Start-ThreatHunt
```

### Performance and Optimization

#### Resource Monitoring

```powershell
# System performance monitoring for security tools
function Monitor-SecurityPerformance {
    param(
        [int]$DurationMinutes = 60,
        [string]$OutputPath = "C:\temp\performance_monitor.csv"
    )
    
    $Data = @()
    $EndTime = (Get-Date).AddMinutes($DurationMinutes)
    
    while ((Get-Date) -lt $EndTime) {
        $CPU = (Get-Counter "\Processor(_Total)\% Processor Time").CounterSamples.CookedValue
        $Memory = (Get-Counter "\Memory\% Committed Bytes In Use").CounterSamples.CookedValue
        $Disk = (Get-Counter "\PhysicalDisk(_Total)\% Disk Time").CounterSamples.CookedValue
        $Network = (Get-Counter "\Network Interface(*)\Bytes Total/sec").CounterSamples | 
                  Measure-Object CookedValue -Sum | Select-Object -ExpandProperty Sum
        
        $Entry = [PSCustomObject]@{
            Timestamp = Get-Date
            CPU_Percent = [math]::Round($CPU, 2)
            Memory_Percent = [math]::Round($Memory, 2)  
            Disk_Percent = [math]::Round($Disk, 2)
            Network_BytesPerSec = $Network
            SecurityProcesses = (Get-Process | Where-Object {$_.ProcessName -like "*defender*" -or $_.ProcessName -like "*antimalware*"}).Count
        }
        
        $Data += $Entry
        ```powershell
# Processi critici di sistema
Get-Process | Where-Object {$_.ProcessName -match "^(winlogon|csrss|lsass|services|svchost)$"} | 
Select-Object Id, ProcessName, Path, Company | Sort-Object ProcessName
```

**Output tipico**:
```
Id    ProcessName  Path                               Company
668   csrss        
748   csrss        
908   lsass        
888   services     
568   svchost      C:\WINDOWS\system32\svchost.exe    Microsoft Corporation
812   winlogon     C:\WINDOWS\system32\winlogon.exe   Microsoft Corporation
```

**Analisi di sicurezza**:
- ✅ **svchost.exe**: Tutti in percorso legittimo `C:\WINDOWS\system32\`
- ✅ **winlogon.exe**: Percorso corretto e company Microsoft
- ⚠️ **csrss/lsass**: Path vuoto normale (protezione kernel)

#### Suspicious Process Detection

```powershell
# Processi con percorsi sospetti
Get-CimInstance Win32_Process | Where-Object { 
    $_.ExecutablePath -like "*temp*" -or 
    $_.ExecutablePath -like "*AppData*" -or
    $_.ExecutablePath -like "*Downloads*"
} | Select-Object ProcessId, Name, ExecutablePath, ParentProcessId

# Processi senza percorso (possibile injection)
Get-Process | Where-Object {$_.Path -eq $null -and $_.ProcessName -notmatch "^(System|csrss|lsass)$"}

# Processi con alta CPU (possibile mining/botnet)
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 ProcessName, CPU, WorkingSet
```

#### Process CommandLine Analysis

```powershell
# Analisi command line per detection malware
Get-CimInstance Win32_Process | Where-Object { 
    $_.CommandLine -like "*powershell*" -or
    $_.CommandLine -like "*cmd*" -or
    $_.CommandLine -like "*wscript*"
} | Select-Object ProcessId, Name, CommandLine, ParentProcessId

# Script per monitoraggio continuo
$EventFilter = @"
SELECT * FROM Win32_ProcessStartTrace
"@

Register-WmiEvent -Query $EventFilter -Action {
    $Event = $Event.SourceEventArgs.NewEvent
    $LogEntry = "$(Get-Date) - New Process: $($Event.ProcessName) - PID: $($Event.ProcessID) - Parent: $($Event.ParentProcessID)"
    Add-Content -Path "C:\temp\process_monitor.log" -Value $LogEntry
}
```

### Service Security Assessment

#### Service Analysis

```powershell
# Servizi in esecuzione con percorsi
Get-CimInstance Win32_Service | Where-Object {$_.State -eq "Running"} | 
Select-Object Name, DisplayName, PathName, StartMode, StartName | 
Sort-Object Name

# Servizi con percorsi sospetti
Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -like "*temp*" -or 
    $_.PathName -like "*AppData*" -or
    $_.PathName -notlike "*system32*"
} | Select-Object Name, PathName, State

# Servizi senza firma digitale
Get-CimInstance Win32_Service | ForEach-Object {
    $ServicePath = ($_.PathName -replace '"', '' -split ' ')[0]
    if (Test-Path $ServicePath) {
        $Signature = Get-AuthenticodeSignature $ServicePath
        if ($Signature.Status -ne "Valid") {
            [PSCustomObject]@{
                ServiceName = $_.Name
                Path = $ServicePath
                SignatureStatus = $Signature.Status
                Signer = $Signature.SignerCertificate.Subject
            }
        }
    }
}
```

### Malware Detection Simulation

#### Test Process Creation

**Creazione processo sospetto per testing**:
```powershell
# Creazione script batch sospetto
Set-Content -Path "C:\temp\sospetto.bat" -Value "ping -t 127.0.0.1 > nul"

# Avvio processo nascosto
Start-Process -FilePath "C:\temp\sospetto.bat" -WindowStyle Hidden
```

#### Detection del processo sospetto

```powershell
# Rilevazione tramite CommandLine
Get-CimInstance Win32_Process | Where-Object { 
    $_.CommandLine -like "*sospetto.bat*" 
} | Select-Object ProcessId, CommandLine

# Output esempio:
# ProcessId CommandLine
# --------- -----------
#      1512 C:\WINDOWS\system32\cmd.exe /c ""C:\Temp\sospetto.bat" "
#      3864 "C:\WINDOWS\system32\cmd.exe" /c C:\Temp\sospetto.bat
```

**Analisi**: Processo lanciato via `cmd.exe` con parametro batch file.

## Registry Forensics

### Persistence Mechanisms

#### User-Level Autostart

```powershell
# Current user autostart
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Output tipico**:
```
OneDrive                                : "C:\Users\aless\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
MicrosoftEdgeAutoLaunch_[GUID]         : "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --win-session-start
```

**Analisi**:
- **OneDrive**: Legittimo, parte per utente corrente
- **Edge AutoLaunch**: Legittimo, launch automatico browser

#### System-Level Autostart (Requires Admin)

```powershell
# System-wide autostart
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Output normale**:
```
SecurityHealth : C:\WINDOWS\system32\SecurityHealthSystray.exe
VBoxTray       : C:\WINDOWS\system32\VBoxTray.exe
```

#### Malware Persistence Test

**Simulazione malware persistence**:
```powershell
# Copia malware simulato in System32
Copy-Item -Path "C:\Temp\sospetto.bat" -Destination "C:\WINDOWS\system32\virus.bat"

# Aggiunta registry key per persistence
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "UpdaterService" -Value "C:\Windows\System32\virus.bat" -PropertyType String
```

**Verifica persistence**:
```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Output con malware**:
```
SecurityHealth : C:\WINDOWS\system32\SecurityHealthSystray.exe
VBoxTray       : C:\WINDOWS\system32\VBoxTray.exe
UpdaterService : C:\Windows\System32\virus.bat
```

**⚠️ Indicatori di compromissione**:
- Nome generico ("UpdaterService")
- Estensione batch in System32
- Percorso inusuale per service

#### Advanced Persistence Locations

```powershell
# Altri punti di persistence comuni
$PersistenceKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($Key in $PersistenceKeys) {
    if (Test-Path $Key) {
        Write-Host "=== $Key ===" -ForegroundColor Yellow
        Get-ItemProperty -Path $Key | Format-List
    }
}
```

### Registry Security Analysis

#### Recently Modified Keys

```powershell
# Chiavi modificate recentemente (ultime 24 ore)
$Yesterday = (Get-Date).AddDays(-1)
Get-ChildItem -Path "HKLM:\SOFTWARE" -Recurse | Where-Object {
    $_.LastWriteTime -gt $Yesterday
} | Select-Object Name, LastWriteTime | Sort-Object LastWriteTime -Descending
```

#### Suspicious Registry Entries

```powershell
# Valori registry con percorsi sospetti
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | 
ForEach-Object {
    Get-ItemProperty -Path $_.PSPath | ForEach-Object {
        $_.PSObject.Properties | Where-Object {
            $_.Value -like "*temp*" -or 
            $_.Value -like "*appdata*" -or
            $_.Value -like "*.bat*" -or
            $_.Value -like "*.vbs*"
        }
    }
}
```

## Privilege Analysis

### Current User Privileges

#### Privilege Enumeration

```powershell
# Privilegi utente corrente (output localizzato)
whoami /priv | Select-String "Abilitato|Disabilitato"
```

**Output critico identificato**:
```
SeDebugPrivilege                       Debug di programmi                     Abilitato
SeImpersonatePrivilege                 Rappresenta un client dopo l'autenticazione  Abilitato  
SeCreateGlobalPrivilege                Creazione oggetti globali               Abilitato
```

#### Dangerous Privileges Analysis

| Privilegio | Stato | Rischio | Implicazioni |
|------------|--------|---------|--------------|
| **SeDebugPrivilege** | 🔴 Abilitato | Critico | Debug altri processi, usato da Mimikatz |
| **SeImpersonatePrivilege** | 🔴 Abilitato | Critico | Token impersonation attacks |
| **SeCreateGlobalPrivilege** | 🟡 Abilitato | Medio | Oggetti globali condivisi |
| **SeShutdownPrivilege** | 🟢 Disabilitato | Basso | Spegnimento sistema |
| **SeTakeOwnershipPrivilege** | 🟢 Disabilitato | Alto | Acquisizione proprietà file |

#### Group Membership Analysis

```powershell
# Gruppi utente corrente
whoami /groups | findstr /i "admin\|power\|backup"

# Utenti locali con dettagli
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordExpires

# Membri gruppo Administrators
Get-LocalGroupMember -Group "Administrators"

# Account con privilegi elevati
Get-CimInstance Win32_UserAccount | Where-Object {$_.SID -like "*-500" -or $_.SID -like "*-501"}
```

### Service Account Analysis

```powershell
# Servizi in esecuzione come SYSTEM
Get-CimInstance Win32_Service | Where-Object {$_.StartName -eq "LocalSystem"} | 
Select-Object Name, DisplayName, State | Sort-Object Name

# Servizi con account custom
Get-CimInstance Win32_Service | Where-Object {
    $_.StartName -ne "LocalSystem" -and 
    $_.StartName -ne "LocalService" -and 
    $_.StartName -ne "NetworkService" -and
    $_.StartName -ne $null
} | Select-Object Name, StartName, State
```

## Network Security Assessment

### Port and Service Analysis

#### Open Ports Enumeration

```powershell
# Porte in ascolto con dettagli processo
netstat -an | findstr "LISTENING"

# Versione più dettagliata
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | 
Select-Object LocalAddress, LocalPort, OwningProcess | 
Sort-Object LocalPort

# Correlazione porta-processo
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | 
ForEach-Object {
    $Process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalPort = $_.LocalPort
        ProcessName = $Process.ProcessName
        ProcessPath = $Process.Path
        PID = $_.OwningProcess
    }
} | Sort-Object LocalPort
```

**Output analysis**:
```
LocalPort ProcessName ProcessPath                           PID
--------- ----------- -----------                           ---
135       svchost     C:\WINDOWS\system32\svchost.exe      1234
139       System                                            4
445       System                                            4
```

#### High-Risk Ports Identified

| Porta | Servizio | Rischio | Mitigazione Raccomandata |
|-------|----------|---------|--------------------------|
| **135** | RPC Endpoint Mapper | 🔴 Alto | Firewall block se non necessario |
| **139** | NetBIOS Session | 🟡 Medio | Disabilitare NetBIOS se possibile |
| **445** | SMB/CIFS | 🔴 Critico | Patch aggiornate, firewall |
| **3389** | RDP | 🔴 Alto | NLA, rate limiting, VPN |
| **5985** | WinRM HTTP | 🟡 Medio | HTTPS only, authentication |

### Network Configuration Security

```powershell
# Configurazione network interfaces
Get-NetAdapter | Select-Object Name, InterfaceDescription, LinkSpeed, Status

# DNS configuration
Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses

# Routing table
Get-NetRoute | Where-Object {$_.NextHop -ne "0.0.0.0"} | 
Select-Object DestinationPrefix, NextHop, InterfaceAlias

# Firewall rules analysis
Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True" -and $_.Direction -eq "Inbound"} | 
Select-Object DisplayName, Action, Protocol, LocalPort | Sort-Object LocalPort
```

### SMB Security Assessment

```powershell
# SMB configuration
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature

# SMB shares
Get-SmbShare | Select-Object Name, Path, ShareType, CurrentUsers

# SMB client connections
Get-SmbConnection | Select-Object ServerName, ShareName, UserName, Dialect
```

## Event Log Analysis

### Security Event Monitoring

#### Logon Events Analysis

```powershell
# Successful logons (Event ID 4624)
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | 
Select-Object TimeCreated, Id, LogonType, @{Name="User";Expression={$_.Properties[5].Value}}, @{Name="SourceIP";Expression={$_.Properties[18].Value}} |
Sort-Object TimeCreated -Descending | Select-Object -First 10

# Failed logons (Event ID 4625)
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625} | 
Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[5].Value}}, @{Name="SourceIP";Expression={$_.Properties[19].Value}} |
Sort-Object TimeCreated -Descending | Select-Object -First 10

# Privilege escalation events (Event ID 4672)
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4672} | 
Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[1].Value}} |
Sort-Object TimeCreated -Descending | Select-Object -First 5
```

#### Process Creation Events

```powershell
# Process creation (Event ID 4688) - requires audit policy
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4688} | 
Select-Object TimeCreated, @{Name="ProcessName";Expression={$_.Properties[5].Value}}, @{Name="CommandLine";Expression={$_.Properties[8].Value}} |
Sort-Object TimeCreated -Descending | Select-Object -First 10

# PowerShell execution events (Event ID 4103)
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4103} |
Select-Object TimeCreated, @{Name="ScriptBlock";Expression={$_.Properties[2].Value}} |
Sort-Object TimeCreated -Descending | Select-Object -First 5
```

### Application Event Analysis

```powershell
# Application crashes
Get-WinEvent -LogName Application | Where-Object {$_.LevelDisplayName -eq "Error"} |
Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
Sort-Object TimeCreated -Descending | Select-Object -First 10

# Windows Defender events
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | 
Where-Object {$_.Id -in @(1006,1007,1008,1009,1010,1011,1012)} |
Select-Object TimeCreated, Id, LevelDisplayName, Message |
Sort-Object TimeCreated -Descending
```

### Custom Event Monitoring

```powershell
# Script per monitoring continuo eventi critici
$CriticalEvents = @(
    @{LogName="Security"; ID=4625; Description="Failed Logon"},
    @{LogName="Security"; ID=4648; Description="Explicit Logon"},
    @{LogName="Security"; ID=4672; Description="Special Privileges"},
    @{LogName="System"; ID=7034; Description="Service Crashed"},
    @{LogName="System"; ID=7040; Description="Service Start Type Changed"}
)

Register-WmiEvent -Query "SELECT * FROM Win32_NTLogEvent WHERE Logfile='Security' AND EventCode=4625" -Action {
    $Event = $Event.SourceEventArgs.NewEvent
    $AlertMessage = "SECURITY ALERT: Failed logon attempt at $(Get-Date)"
    Write-Host $AlertMessage -ForegroundColor Red
    # Send email or notification here
}
```

## Malware Simulation

### Persistence Testing

#### Registry Persistence Demo

**Scenario completo di test malware**:

1. **Payload Creation**:
```powershell
Set-Content -Path "C:\temp\sospetto.bat" -Value @"
@echo off
start notepad.exe
timeout /t 2 >nul
exit
"@
```

2. **System Installation**:
```powershell
# Copia in System32 (richiede admin)
Copy-Item -Path "C:\Temp\sospetto.bat" -Destination "C:\WINDOWS\system32\virus.bat"
```

3. **Registry Persistence**:
```powershell
# Aggiunta registry key con nome ingannevole
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "UpdaterService" -Value "C:\Windows\System32\virus.bat" -PropertyType String -Force
```

4. **Test Execution**:
   - Riavvio sistema
   - **Risultato**: Notepad si apre automaticamente + flash CMD visibile

5. **Detection**:
```powershell
# Identificazione malware
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Output detection**:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    VBoxTray         REG_EXPAND_SZ    %SystemRoot%\system32\VBoxTray.exe
    UpdaterService   REG_SZ           C:\Windows\System32\virus.bat
```

6. **Cleanup**:
```powershell
# Rimozione malware
Remove-Item -Path "C:\Windows\System32\virus.bat" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "UpdaterService"
```

#### Advanced Persistence Techniques

```powershell
# WMI Event Subscription (fileless persistence)
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "SystemTimeFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 30"
}

$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = "SystemTimeConsumer"
    CommandLineTemplate = "powershell.exe -WindowStyle Hidden -Command ""Start-Process notepad.exe"""
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

### Behavioral Analysis

#### Anomalous Activity Detection

```powershell
# Monitor per attività sospette
$SuspiciousActivities = @(
    "Process hollowing indicators",
    "Unusual network connections", 
    "Registry modifications",
    "File system changes",
    "Service installations"
)

# File system monitoring
$Watcher = New-Object System.IO.FileSystemWatcher
$Watcher.Path = "C:\Windows\System32"
$Watcher.Filter = "*.exe"
$Watcher.NotifyFilter = [System.IO.NotifyFilters]::CreationTime

Register-ObjectEvent -InputObject $Watcher -EventName Created -Action {
    $Event = $Event.SourceEventArgs
    Write-Host "NEW EXECUTABLE: $($Event.FullPath) created at $(Get-Date)" -ForegroundColor Red
    
    # Log to file
    Add-Content -Path "C:\temp\file_monitor.log" -Value "$(Get-Date) - New executable: $($Event.FullPath)"
}

$Watcher.EnableRaisingEvents = $true
```

## Best Practices

### Security Hardening

#### PowerShell Security Configuration

```powershell
# Enable PowerShell logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Set execution policy (restrictive)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Enable Windows PowerShell ISE logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"
```

#### User Account Security

```powershell
# Disable unnecessary accounts
Disable-LocalUser -Name "Guest"

# Password policy enforcement
net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5

# Account lockout policy
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

# Audit policy configuration
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
```

### Monitoring and Alerting

#### Automated Security Monitoring

```powershell
# Security monitoring script
$SecurityMonitor = {
    param($LogPath)
    
    while ($true) {
        # Check for failed logons
        $FailedLogons = Get-WinEvent -LogName Security | Where-Object {
            $_.Id -eq 4625 -and $_.TimeCreated -gt (Get-Date).AddMinutes(-5)
        }
        
        if ($FailedLogons.Count -gt 5) {
            $Alert = "SECURITY ALERT: $($FailedLogons.Count) failed logons in last 5 minutes"
            Write-Host $Alert -ForegroundColor Red
            Add-Content -Path $LogPath -Value "$(Get-Date) - $Alert"
        }
        
        # Check for new services
        $NewServices = Get-WinEvent -LogName System | Where-Object {
            $_.Id -eq 7034 -and $_.TimeCreated -gt (Get-Date).AddMinutes(-5)
        }
        
        if ($NewServices) {
            $Alert = "SERVICE ALERT: Service installation/modification detected"
            Write-Host $Alert -ForegroundColor Yellow
            Add-Content -Path $LogPath -Value "$(Get-Date) - $Alert"
        }
        
        Start-Sleep -Seconds 60
    }
}

# Start monitoring in background
Start-Job -ScriptBlock $SecurityMonitor -ArgumentList "C:\temp\security_monitor.log"
```

#### Registry Integrity Monitoring

```powershell
# Baseline critical registry keys
$CriticalKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

$Baseline = @{}
foreach ($Key in $CriticalKeys) {
    if (Test-Path $Key) {
        $Baseline[$Key] = Get-ItemProperty -Path $Key
    }
}

# Export baseline
$Baseline | ConvertTo-Json -Depth 3 | Out-File "C:\temp\registry_baseline.json"

# Monitoring function
function Compare-RegistryBaseline {
    param($BaselinePath)
    
    $Baseline = Get-Content $BaselinePath | ConvertFrom-Json
    $Changes = @()
    
    foreach ($Key in $Baseline.PSObject.Properties.Name) {
        if (Test-Path $Key) {
            $Current = Get-ItemProperty -Path $Key
            $BaselineValues = $Baseline.$Key
            
            # Compare values
            foreach ($Property in $Current.PSObject.Properties) {
                if ($Property.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    $BaselineValue = $BaselineValues.$($Property.Name)
                    if ($BaselineValue -ne $Property.Value) {
                        $Changes += [PSCustomObject]@{
                            Key = $Key
                            Property = $Property.Name
                            OldValue = $BaselineValue
                            NewValue = $Property.Value
                            Timestamp = Get-Date
                        }
                    }
                }
            }
        }
    }
    
    return $Changes
}

# Schedule periodic checks
$Action = {
    $Changes = Compare-RegistryBaseline -BaselinePath "C:\temp\registry_baseline.json"
    if ($Changes) {
        $Changes | ConvertTo-Json | Out-File "C:\temp\registry_changes_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Write-Host "Registry changes detected! Check log files." -ForegroundColor Red
    }
}

# Run every 5 minutes
while ($true) {
    & $Action
    Start-Sleep -Seconds 300
}
```

### Incident Response

#### Automated Evidence Collection

```powershell
# Incident response data collection
function Collect-IncidentData {
    param(
        [string]$OutputPath = "C:\IR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    New-Item -Path $OutputPath -ItemType Directory -Force
    
    # System information
    Get-ComputerInfo | Out-File "$OutputPath\system_info.txt"
    Get-Date | Out-File "$OutputPath\collection_time.txt"
    
    # Running processes
    Get-Process | Select-Object * | Export-Csv "$OutputPath\processes.csv" -NoTypeInformation
    Get-CimInstance Win32_Process | Select-Object * | Export-Csv "$OutputPath\processes_detailed.csv" -NoTypeInformation
    
    # Services
    Get-Service | Export-Csv "$OutputPath\services.csv" -NoTypeInformation
    
    # Network connections
    Get-NetTCPConnection | Export-Csv "$OutputPath\network_connections.csv" -NoTypeInformation
    netstat -ano | Out-File "$OutputPath\netstat.txt"
    
    # Registry persistence locations
    foreach ($Key in $CriticalKeys) {
        if (Test-Path $Key) {
            $KeyName = $Key.Replace(":", "").Replace("\", "_")
            Get-ItemProperty -Path $Key | Out-File "$OutputPath\registry_$KeyName.txt"
        }
    }
    
    # Event logs (last 24 hours)
    $Yesterday = (Get-Date).AddDays(-1)
    Get-WinEvent -LogName Security | Where-Object {$_.TimeCreated -gt $Yesterday} | 
    Export-Csv "$OutputPath\security_events.csv" -NoTypeInformation
    
    Get-WinEvent -LogName System | Where-Object {$_.TimeCreated -gt $Yesterday} | 
    Export-Csv "$OutputPath\system_events.csv" -NoTypeInformation
    
    # Installed software
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Export-Csv "$OutputPath\installed_software.csv" -NoTypeInformation
    
    # User accounts
    Get-LocalUser | Export-Csv "$OutputPath\local_users.csv" -NoTypeInformation
    Get-LocalGroup | Export-Csv "$OutputPath\local_groups.csv" -NoTypeInformation
    
    # Startup items
    Get-CimInstance Win32_StartupCommand | Export-Csv "$OutputPath\startup_commands.csv" -NoTypeInformation
    
    Write-Host "Incident data collected in: $OutputPath" -ForegroundColor Green
    
    # Create summary report
    $Summary = @"
INCIDENT RESPONSE DATA COLLECTION SUMMARY
==========================================
Collection Time: $(Get-Date)
System: $(hostname)
OS: $((Get-CimInstance Win32_OperatingSystem).Caption)
Domain: $((Get-CimInstance Win32_ComputerSystem).Domain)

Files Collected:
$(Get-ChildItem $OutputPath | ForEach-Object {"- $($_.Name) ($($_.Length) bytes)"})

Next Steps:
1. Review processes.csv for suspicious executables
2. Check registry_* files for unauthorized persistence
3. Analyze# Windows Security

Documentazione completa su analisi di sicurezza Windows, PowerShell security assessment, registry forensics e detection di malware. Include tecniche di persistence, privilege analysis e monitoring avanzato.

## Indice

- [PowerShell Security Analysis](#powershell-security-analysis)
- [System Information Gathering](#system-information-gathering)
- [Process and Service Monitoring](#process-and-service-monitoring)
- [Registry Forensics](#registry-forensics)
- [Privilege Analysis](#privilege-analysis)
- [Malware Simulation](#malware-simulation)
- [Network Security Assessment](#network-security-assessment)
- [Event Log Analysis](#event-log-analysis)
- [Best Practices](#best-practices)

## PowerShell Security Analysis

### Identificazione Sistema

#### Comandi Base di Reconnaissance

```powershell
# Informazioni sistema base
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, WindowsBuildLabEx

# Informazioni dettagliate OS
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture

# Informazioni hardware
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Manufacturer, Model, TotalPhysicalMemory
```

**Output tipico**:
```
WindowsProductName WindowsVersion WindowsBuildLabEx
------------------ -------------- -----------------
Windows 10 Home    2009           26100.1.amd64fre.ge_release.240331-1435
```

**⚠️ Discovery importante**: Windows 11 internamente usa kernel NT 10.0 per mantenere compatibilità con applicazioni legacy.

#### Informazioni Accurate del Sistema

```powershell
# Verifica reale della versione
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture
```

**Output corretto**:
```
Caption                   Version    OSArchitecture
-------                   -------    --------------
Microsoft Windows 11 Home 10.0.26100 64 bit
```

**Build number interpretation**:
- **26100** = Windows 11 24H2
- **22000** = Windows 11 21H2
- **19045** = Windows 10 22H2

### Security Features Assessment

#### DEP/NX Status

```powershell
# Data Execution Prevention status
bcdedit | findstr -i "nx"
```

**Output**: `nx OptIn`

**Significato**:
- **OptIn**: DEP attivo solo per applicazioni essenziali di Windows
- **OptOut**: DEP attivo per tutte le applicazioni (più sicuro)
- **AlwaysOff**: DEP disabilitato (vulnerabile)

#### Windows Defender Status

```powershell
# Status Windows Defender
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, DefinitionVersion

# Ultima scansione
Get-MpComputerStatus | Select-Object QuickScanStartTime, QuickScanEndTime

# Esclusioni configurate
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension
```

#### BitLocker Status

```powershell
# Status crittografia dischi
Get-BitLockerVolume | Select-Object MountPoint, EncryptionPercentage, VolumeStatus, ProtectionStatus
```

## System Information Gathering

### Hardware e Driver Information

```powershell
# Informazioni CPU
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors

# Informazioni memoria
Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity, Speed, Manufacturer

# Driver installati (potenziali entry point)
Get-WindowsDriver -Online | Where-Object {$_.DriverSignature -eq "Not Signed"} | Select-Object Driver, ProviderName, Version

# Dispositivi USB recenti
Get-CimInstance Win32_VolumeChangeEvent | Select-Object DriveLetter, EventType, Time
```

### Software Inventory

```powershell
# Programmi installati (metodo 1 - più veloce)
Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor | Sort-Object Name

# Programmi installati (metodo 2 - più completo)
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
Select-Object DisplayName, DisplayVersion, Publisher | 
Where-Object {$_.DisplayName -ne $null}

# Software di sicurezza installato
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | 
Select-Object displayName, productState, timestamp
```

### Update Status

```powershell
# Windows Update status
Get-Hotfix | Sort-Object InstalledOn -Descending | Select-Object -First 10

# Pending updates
Get-WUList

# Update history con dettagli
Get-CimInstance Win32_QuickFixEngineering | 
Select-Object HotFixID, Description, InstalledOn, InstalledBy | 
Sort-Object InstalledOn -Descending
```

## Process and Service Monitoring

### Critical Process Analysis

#### System Process Verification

```powershell
# Processi critici di sistema
Get-Process | Where-Object {$_.ProcessName -match "^(winlogon|csrss|lsass|services|