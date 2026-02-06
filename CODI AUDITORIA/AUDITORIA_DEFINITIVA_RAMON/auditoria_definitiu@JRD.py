#!/usr/bin/env python3
"""
🔒 SEC-AUDIT PRO - Advanced Security Auditing Tool v3.0
Eina professional d'auditoria de seguretat amb interfície moderna
Inclou: Network Discovery, Port Scanning, Version Detection, Vulnerability Assessment
"""

import threading
import subprocess
import sys
import os
import time
import re
from datetime import datetime
from tkinter import (
    Tk, Frame, Label, Button, Entry, Text, Scrollbar, END, messagebox, 
    ttk, StringVar, FLAT, LEFT, RIGHT, BOTTOM, TOP, BOTH, X, Y, Canvas, Listbox, Toplevel
)
from tkinter import filedialog
import json
import html

# ========== PALETA DE COLORS MODERNA - CYBERSECURITY THEME ==========
# Gradients cibernètics: Blau fosc → Cian → Porpra
COLOR_BG_MAIN = "#0a0e27"           # Fons principal ultra fosc
COLOR_BG_SIDEBAR = "#0f1419"        # Sidebar encara més fosc
COLOR_ACCENT_PRIMARY = "#00d4ff"    # Cian brillant (neon)
COLOR_ACCENT_SECONDARY = "#7b2cbf"  # Porpra profund
COLOR_ACCENT_HOVER = "#00ffff"      # Cian més brillant
COLOR_DANGER = "#ff006e"            # Rosa neon per perill
COLOR_SUCCESS = "#06ffa5"           # Verd neon
COLOR_WARNING = "#ffbe0b"           # Groc neon
COLOR_TEXT_MAIN = "#e0e0e0"         # Text principal
COLOR_TEXT_DIM = "#8892b0"          # Text secundari
COLOR_TERM_BG = "#0a0a0a"           # Terminal negre profund
COLOR_TERM_FG = "#00ff41"           # Verd matrix per terminal
COLOR_GRADIENT_START = "#1a1a2e"    # Inici gradient
COLOR_GRADIENT_END = "#16213e"      # Fi gradient

# ---------- UTILS ----------
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)

def prettify_ssh_audit(raw: str) -> str:
    lines = raw.splitlines()
    out_lines = []
    for raw_line in lines:
        line = strip_ansi(raw_line).rstrip()
        if not line:
            if out_lines and out_lines[-1] != "": out_lines.append("")
            continue
        if line.startswith("#"):
            sec = line.lstrip("# ").upper()
            out_lines.append(f"SECTION_HEADER::{sec}")
            continue
        low = line.lower()
        if "[fail]" in low or " -- [fail]" in line.lower():
            out_lines.append(f"TAG_FAIL::‼ FAIL: {line}")
        elif "[warn]" in low or " -- [warn]" in line.lower():
            out_lines.append(f"TAG_WARN::⚠ WARN: {line}")
        elif "(rec)" in low or "recommend" in low:
            cleaned = line.lstrip(" -")
            out_lines.append(f"TAG_REC::→ RECOMANACIÓ: {cleaned}")
        else:
            out_lines.append(f"  {line}")
    return "\n".join(out_lines).strip() + "\n"

# ========== NOTIFICACIONS PERSONALITZADES MODERNES ==========
def show_modern_notification(parent, title, message, notification_type="info"):
    """
    Mostra una notificació moderna amb el tema cybersecurity
    notification_type: 'info', 'success', 'warning', 'error'
    """
    # Colors segons el tipus
    colors = {
        'info': {'bg': '#1a1f2e', 'accent': '#00d4ff', 'icon': 'ℹ️'},
        'success': {'bg': '#0d2818', 'accent': '#06ffa5', 'icon': '✅'},
        'warning': {'bg': '#2e1f0d', 'accent': '#ffbe0b', 'icon': '⚠️'},
        'error': {'bg': '#2e0d1a', 'accent': '#ff006e', 'icon': '❌'}
    }
    
    config = colors.get(notification_type, colors['info'])
    
    # Crear finestra toplevel
    dialog = Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg=config['bg'])
    dialog.resizable(False, False)
    
    # Centrar a la pantalla
    dialog.update_idletasks()
    width = 450
    height = 200
    x = (dialog.winfo_screenwidth() // 2) - (width // 2)
    y = (dialog.winfo_screenheight() // 2) - (height // 2)
    dialog.geometry(f'{width}x{height}+{x}+{y}')
    
    # Fer modal
    dialog.transient(parent)
    dialog.grab_set()
    
    # Frame principal amb gradient simulat
    main_frame = Frame(dialog, bg=config['bg'], padx=30, pady=25)
    main_frame.pack(fill=BOTH, expand=True)
    
    # Header amb icona i títol
    header_frame = Frame(main_frame, bg=config['bg'])
    header_frame.pack(fill=X, pady=(0, 20))
    
    icon_label = Label(header_frame, text=config['icon'], 
                      bg=config['bg'], fg=config['accent'],
                      font=("Segoe UI", 32))
    icon_label.pack(side=LEFT, padx=(0, 15))
    
    title_label = Label(header_frame, text=title,
                       bg=config['bg'], fg=config['accent'],
                       font=("Segoe UI", 16, "bold"))
    title_label.pack(side=LEFT, anchor="w")
    
    # Línia separadora
    separator = Frame(main_frame, bg=config['accent'], height=2)
    separator.pack(fill=X, pady=(0, 15))
    
    # Missatge
    message_label = Label(main_frame, text=message,
                         bg=config['bg'], fg=COLOR_TEXT_MAIN,
                         font=("Segoe UI", 11),
                         wraplength=380, justify=LEFT)
    message_label.pack(pady=(0, 20))
    
    # Botó OK
    def close_dialog():
        dialog.destroy()
    
    btn_ok = Button(main_frame, text="D'ACORD", command=close_dialog,
                   bg=config['accent'], fg="#0a0e27",
                   font=("Segoe UI", 11, "bold"),
                   relief=FLAT, cursor="hand2",
                   padx=30, pady=10)
    btn_ok.pack()
    
    # Efecte hover
    def on_enter(e):
        btn_ok['bg'] = COLOR_TEXT_MAIN
    def on_leave(e):
        btn_ok['bg'] = config['accent']
    
    btn_ok.bind("<Enter>", on_enter)
    btn_ok.bind("<Leave>", on_leave)
    
    # Tancar amb ESC
    dialog.bind('<Escape>', lambda e: close_dialog())
    
    # Esperar que es tanqui
    dialog.wait_window()

def prettify_enum4linux(raw: str) -> str:
    lines = raw.splitlines()
    out_lines = []
    for raw_line in lines:
        line = strip_ansi(raw_line).rstrip()
        if not line:
            if out_lines and out_lines[-1] != "": out_lines.append("")
            continue
        if line.startswith("===") and line.endswith("==="):
            sec = line.strip("= ").upper()
            out_lines.append(f"SECTION_HEADER::{sec}")
            continue
        if line.startswith("[+]"):
            out_lines.append(f"TAG_SUCCESS::✔ INFO: {line.lstrip('[+] ')}")
        elif line.startswith("[-]"):
            out_lines.append(f"TAG_FAIL::✘ {line.lstrip('[-] ')}")
        else:
            out_lines.append(f"    {line}")
    return "\n".join(out_lines).strip() + "\n"

def prettify_vuln(raw: str) -> str:
    """Neteja bàsica per a l'escaneig de vulns"""
    lines = raw.splitlines()
    out_lines = []
    for raw_line in lines:
        line = strip_ansi(raw_line).rstrip()
        # Destaquem línies clau manualment si cal, però el parser GUI ho farà millor
        if "|_ssl-ccs-injection: VULNERABLE" in line:
             out_lines.append(f"TAG_FAIL::{line}")
        else:
             out_lines.append(line)
    return "\n".join(out_lines)

# ========== DATA PARSING UTILITIES ==========
class ScanDataParser:
    """Parser intel·ligent per extreure dades estructurades dels scans"""
    
    @staticmethod
    def parse_nmap_ports(raw_output: str) -> dict:
        """Extreu informació de ports d'un scan nmap"""
        data = {
            'ports': [],
            'total_open': 0,
            'total_closed': 0,
            'total_filtered': 0,
            'host_up': False
        }
        
        lines = raw_output.splitlines()
        for line in lines:
            # Detectar si el host està actiu
            if "Host is up" in line or "host up" in line.lower():
                data['host_up'] = True
            
            # Parsejar ports: format "22/tcp   open  ssh     OpenSSH 8.2"
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.+))?', line)
            if port_match:
                port_num, protocol, state, service, version = port_match.groups()
                data['ports'].append({
                    'port': int(port_num),
                    'protocol': protocol,
                    'state': state,
                    'service': service,
                    'version': version.strip() if version else 'N/A'
                })
                
                if state == 'open':
                    data['total_open'] += 1
                elif state == 'closed':
                    data['total_closed'] += 1
                elif state == 'filtered':
                    data['total_filtered'] += 1
        
        return data
    
    @staticmethod
    def parse_vulnerabilities(raw_output: str) -> dict:
        """Extreu vulnerabilitats d'un scan"""
        data = {
            'vulnerabilities': [],
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
        
        lines = raw_output.splitlines()
        current_vuln = None
        
        for line in lines:
            # Detectar CVEs
            cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
            if cve_match:
                cve_id = cve_match.group(1)
                
                # Intentar detectar severitat
                severity = 'UNKNOWN'
                if 'CRITICAL' in line.upper():
                    severity = 'CRITICAL'
                    data['critical_count'] += 1
                elif 'HIGH' in line.upper():
                    severity = 'HIGH'
                    data['high_count'] += 1
                elif 'MEDIUM' in line.upper():
                    severity = 'MEDIUM'
                    data['medium_count'] += 1
                elif 'LOW' in line.upper():
                    severity = 'LOW'
                    data['low_count'] += 1
                
                data['vulnerabilities'].append({
                    'cve': cve_id,
                    'severity': severity,
                    'description': line.strip()
                })
            
            # Detectar VULNERABLE
            elif 'VULNERABLE' in line.upper():
                # Extraure nom de la vulnerabilitat
                vuln_name = line.split('VULNERABLE')[0].strip()
                if vuln_name:
                    data['vulnerabilities'].append({
                        'cve': 'N/A',
                        'severity': 'HIGH',
                        'description': line.strip()
                    })
                    data['high_count'] += 1
        
        return data
    
    @staticmethod
    def parse_ssh_audit(raw_output: str) -> dict:
        """Extreu informació de SSH audit"""
        data = {
            'algorithms': [],
            'recommendations': [],
            'warnings': [],
            'failures': []
        }
        
        lines = raw_output.splitlines()
        for line in lines:
            clean_line = strip_ansi(line).strip()
            if '[FAIL]' in clean_line or 'FAIL:' in clean_line:
                data['failures'].append(clean_line)
            elif '[WARN]' in clean_line or 'WARN:' in clean_line:
                data['warnings'].append(clean_line)
            elif 'recommend' in clean_line.lower() or '(rec)' in clean_line.lower():
                data['recommendations'].append(clean_line)
        
        return data
    
    @staticmethod
    def parse_network_scan(raw_output: str) -> dict:
        """Extreu IPs detectades d'un scan de xarxa (nmap -sn)"""
        data = {
            'discovered_ips': [],
            'total_hosts': 0
        }
        
        lines = raw_output.splitlines()
        for line in lines:
            # Buscar línies amb "Nmap scan report for <IP>"
            # Formats possibles:
            # - "Nmap scan report for 192.168.1.1"
            # - "Nmap scan report for hostname (192.168.1.1)"
            match = re.search(r'Nmap scan report for (?:.*\()?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                ip = match.group(1)
                if ip not in data['discovered_ips']:
                    data['discovered_ips'].append(ip)
            
            # També comptar hosts actius del resum
            if 'host up' in line.lower() or 'hosts up' in line.lower():
                # Format: "Nmap done: 256 IP addresses (5 hosts up) scanned in 2.50 seconds"
                hosts_match = re.search(r'(\d+) hosts? up', line, re.IGNORECASE)
                if hosts_match:
                    data['total_hosts'] = int(hosts_match.group(1))
        
        # Si no hem trobat el total al resum, usar el nombre d'IPs detectades
        if data['total_hosts'] == 0:
            data['total_hosts'] = len(data['discovered_ips'])
        
        return data

def generate_html_report(scan_data: dict, target: str, scan_type: str) -> str:
    """Genera un report HTML professional amb taules"""
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SEC-AUDIT PRO - Report {scan_type}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #16213e 100%);
            color: #e0e0e0;
            padding: 40px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 8px 32px rgba(0, 212, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(0, 212, 255, 0.2);
        }}
        
        .header {{
            text-align: center;
            border-bottom: 3px solid #00d4ff;
            padding-bottom: 30px;
            margin-bottom: 40px;
        }}
        
        .header h1 {{
            font-size: 42px;
            color: #00d4ff;
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 18px;
            color: #8892b0;
            font-style: italic;
        }}
        
        .info-section {{
            background: rgba(0, 212, 255, 0.05);
            border-left: 4px solid #00d4ff;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 8px;
        }}
        
        .info-section h2 {{
            color: #00d4ff;
            font-size: 24px;
            margin-bottom: 15px;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        
        .info-item {{
            display: flex;
            align-items: center;
        }}
        
        .info-label {{
            font-weight: bold;
            color: #00d4ff;
            margin-right: 10px;
        }}
        
        .info-value {{
            color: #e0e0e0;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #00d4ff;
            font-size: 28px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid rgba(0, 212, 255, 0.3);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        thead {{
            background: linear-gradient(135deg, #00d4ff 0%, #7b2cbf 100%);
        }}
        
        th {{
            padding: 15px;
            text-align: left;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
            font-size: 14px;
            letter-spacing: 1px;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        tr:hover {{
            background: rgba(0, 212, 255, 0.1);
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .badge-open {{
            background: #06ffa5;
            color: #0a0e27;
        }}
        
        .badge-closed {{
            background: #8892b0;
            color: #0a0e27;
        }}
        
        .badge-critical {{
            background: #ff006e;
            color: white;
        }}
        
        .badge-high {{
            background: #ff6b35;
            color: white;
        }}
        
        .badge-medium {{
            background: #ffbe0b;
            color: #0a0e27;
        }}
        
        .badge-low {{
            background: #8be9fd;
            color: #0a0e27;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.1) 0%, rgba(123, 44, 191, 0.1) 100%);
            border: 1px solid rgba(0, 212, 255, 0.3);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
            color: #00d4ff;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 14px;
            color: #8892b0;
            text-transform: uppercase;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 30px;
            border-top: 2px solid rgba(0, 212, 255, 0.2);
            color: #8892b0;
            font-size: 14px;
        }}
        
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #8892b0;
            font-style: italic;
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .container {{
                box-shadow: none;
                border: 1px solid #ccc;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 SEC-AUDIT PRO</h1>
            <div class="subtitle">Advanced Security Auditing Report</div>
        </div>
        
        <div class="info-section">
            <h2>📋 Informació General</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">🎯 Objectiu:</span>
                    <span class="info-value">{html.escape(target)}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">🔍 Tipus de Scan:</span>
                    <span class="info-value">{html.escape(scan_type)}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">📅 Data:</span>
                    <span class="info-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">⚙️ Eina:</span>
                    <span class="info-value">SEC-AUDIT PRO v3.0</span>
                </div>
            </div>
        </div>
"""
    
    # Afegir seccions segons el tipus de dades
    if 'ports' in scan_data and scan_data['ports']:
        ports_data = scan_data
        html_content += f"""
        <div class="section">
            <h2>📊 Estadístiques de Ports</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{ports_data['total_open']}</div>
                    <div class="stat-label">Ports Oberts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{ports_data['total_closed']}</div>
                    <div class="stat-label">Ports Tancats</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{ports_data['total_filtered']}</div>
                    <div class="stat-label">Ports Filtrats</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(ports_data['ports'])}</div>
                    <div class="stat-label">Total Analitzats</div>
                </div>
            </div>
            
            <h2>🔌 Detall de Ports</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Estat</th>
                        <th>Servei</th>
                        <th>Versió</th>
                    </tr>
                </thead>
                <tbody>
"""
        for port in ports_data['ports']:
            badge_class = f"badge-{port['state']}"
            html_content += f"""
                    <tr>
                        <td><strong>{port['port']}</strong></td>
                        <td>{port['protocol'].upper()}</td>
                        <td><span class="badge {badge_class}">{port['state']}</span></td>
                        <td>{html.escape(port['service'])}</td>
                        <td>{html.escape(port['version'])}</td>
                    </tr>
"""
        html_content += """
                </tbody>
            </table>
        </div>
"""
    
    if 'vulnerabilities' in scan_data and scan_data['vulnerabilities']:
        vuln_data = scan_data
        html_content += f"""
        <div class="section">
            <h2>⚠️ Estadístiques de Vulnerabilitats</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{vuln_data['critical_count']}</div>
                    <div class="stat-label">Crítiques</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{vuln_data['high_count']}</div>
                    <div class="stat-label">Altes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{vuln_data['medium_count']}</div>
                    <div class="stat-label">Mitjanes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{vuln_data['low_count']}</div>
                    <div class="stat-label">Baixes</div>
                </div>
            </div>
            
            <h2>🛡️ Vulnerabilitats Detectades</h2>
            <table>
                <thead>
                    <tr>
                        <th>CVE</th>
                        <th>Severitat</th>
                        <th>Descripció</th>
                    </tr>
                </thead>
                <tbody>
"""
        for vuln in vuln_data['vulnerabilities']:
            severity_lower = vuln['severity'].lower()
            badge_class = f"badge-{severity_lower}"
            html_content += f"""
                    <tr>
                        <td><strong>{html.escape(vuln['cve'])}</strong></td>
                        <td><span class="badge {badge_class}">{html.escape(vuln['severity'])}</span></td>
                        <td>{html.escape(vuln['description'][:200])}</td>
                    </tr>
"""
        html_content += """
                </tbody>
            </table>
        </div>
"""
    
    # Footer
    html_content += """
        <div class="footer">
            <p>🔒 Generat per SEC-AUDIT PRO v3.0 - Advanced Security Auditing Suite</p>
            <p style="margin-top: 10px; font-size: 12px;">
                Fes click al botó "📄 EXPORTAR A PDF" per convertir aquest report a PDF
            </p>
        </div>
    </div>
    
    <!-- Botó flotant per exportar a PDF -->
    <button onclick="window.print()" style="
        position: fixed;
        bottom: 30px;
        right: 30px;
        background: linear-gradient(135deg, #00d4ff 0%, #7b2cbf 100%);
        color: white;
        border: none;
        border-radius: 50px;
        padding: 15px 30px;
        font-size: 16px;
        font-weight: bold;
        cursor: pointer;
        box-shadow: 0 4px 15px rgba(0, 212, 255, 0.4);
        z-index: 1000;
        transition: all 0.3s ease;
    " onmouseover="this.style.transform='scale(1.05)'; this.style.boxShadow='0 6px 20px rgba(0, 212, 255, 0.6)';" 
       onmouseout="this.style.transform='scale(1)'; this.style.boxShadow='0 4px 15px rgba(0, 212, 255, 0.4)';">
        📄 EXPORTAR A PDF
    </button>
    
    <style>
        @media print {
            button {
                display: none !important;
            }
        }
    </style>
</body>
</html>
"""
    
    return html_content

def generate_complete_audit_report(scan_history_list: list, target: str) -> str:
    """Genera un report HTML complet amb tots els scans d'un target"""
    
    # Calcular estadístiques agregades
    unique_ports = set()  # Usar set para evitar duplicados
    total_vulnerabilities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    all_services = set()
    
    for scan in scan_history_list:
        data = scan['data']
        if 'ports' in data:
            for port in data['ports']:
                if port['state'] == 'open':
                    # Añadir tupla (port, protocol) para evitar duplicados
                    unique_ports.add((port['port'], port['protocol']))
                    all_services.add(port['service'])
        if 'vulnerabilities' in data:
            total_vulnerabilities['critical'] += data.get('critical_count', 0)
            total_vulnerabilities['high'] += data.get('high_count', 0)
            total_vulnerabilities['medium'] += data.get('medium_count', 0)
            total_vulnerabilities['low'] += data.get('low_count', 0)
    
    total_ports_open = len(unique_ports)  # Contar puertos únicos
    total_vulns = sum(total_vulnerabilities.values())
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SEC-AUDIT PRO - Auditoria Completa {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #16213e 100%);
            color: #e0e0e0;
            padding: 40px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 8px 32px rgba(0, 212, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(0, 212, 255, 0.2);
        }}
        
        .cover-page {{
            text-align: center;
            padding: 80px 40px;
            border-bottom: 3px solid #00d4ff;
            margin-bottom: 60px;
        }}
        
        .cover-page h1 {{
            font-size: 48px;
            color: #00d4ff;
            text-shadow: 0 0 30px rgba(0, 212, 255, 0.7);
            margin-bottom: 20px;
        }}
        
        .cover-page .subtitle {{
            font-size: 28px;
            color: #b794f6;
            margin-bottom: 40px;
            font-weight: 300;
        }}
        
        .cover-info {{
            display: inline-block;
            background: rgba(0, 212, 255, 0.1);
            border: 2px solid #00d4ff;
            border-radius: 10px;
            padding: 30px 50px;
            margin-top: 30px;
        }}
        
        .cover-info-item {{
            font-size: 18px;
            margin: 15px 0;
        }}
        
        .cover-info-label {{
            color: #00d4ff;
            font-weight: bold;
        }}
        
        .section {{
            margin-bottom: 50px;
            page-break-inside: avoid;
        }}
        
        .section h2 {{
            color: #00d4ff;
            font-size: 32px;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 3px solid rgba(0, 212, 255, 0.3);
        }}
        
        .section h3 {{
            color: #b794f6;
            font-size: 24px;
            margin: 30px 0 15px 0;
            padding-left: 15px;
            border-left: 4px solid #b794f6;
        }}
        
        .executive-summary {{
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.1) 0%, rgba(183, 148, 246, 0.1) 100%);
            border-left: 5px solid #00d4ff;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 40px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.15) 0%, rgba(123, 44, 191, 0.15) 100%);
            border: 2px solid rgba(0, 212, 255, 0.3);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
        }}
        
        .stat-number {{
            font-size: 42px;
            font-weight: bold;
            color: #00d4ff;
            margin-bottom: 10px;
        }}
        
        .stat-label {{
            font-size: 14px;
            color: #8892b0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        thead {{
            background: linear-gradient(135deg, #00d4ff 0%, #7b2cbf 100%);
        }}
        
        th {{
            padding: 15px;
            text-align: left;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
            font-size: 13px;
            letter-spacing: 1px;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        tr:hover {{
            background: rgba(0, 212, 255, 0.1);
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .badge-success {{
            background: #06ffa5;
            color: #0a0e27;
        }}
        
        .badge-critical {{
            background: #ff006e;
            color: white;
        }}
        
        .badge-high {{
            background: #ff6b35;
            color: white;
        }}
        
        .badge-medium {{
            background: #ffbe0b;
            color: #0a0e27;
        }}
        
        .badge-low {{
            background: #8be9fd;
            color: #0a0e27;
        }}
        
        .scan-section {{
            background: rgba(255, 255, 255, 0.03);
            border-left: 4px solid #b794f6;
            padding: 25px;
            margin: 25px 0;
            border-radius: 8px;
        }}
        
        .scan-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid rgba(183, 148, 246, 0.3);
        }}
        
        .scan-title {{
            font-size: 22px;
            color: #b794f6;
            font-weight: bold;
        }}
        
        .scan-meta {{
            font-size: 14px;
            color: #8892b0;
        }}
        
        .conclusions {{
            background: linear-gradient(135deg, rgba(255, 0, 110, 0.1) 0%, rgba(255, 190, 11, 0.1) 100%);
            border: 2px solid #ff006e;
            border-radius: 10px;
            padding: 30px;
            margin-top: 40px;
        }}
        
        .conclusions h3 {{
            color: #ff006e;
            border-left-color: #ff006e;
        }}
        
        .recommendation {{
            background: rgba(0, 212, 255, 0.05);
            border-left: 3px solid #00d4ff;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 60px;
            padding-top: 30px;
            border-top: 2px solid rgba(0, 212, 255, 0.2);
            color: #8892b0;
            font-size: 14px;
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .container {{
                box-shadow: none;
                border: 1px solid #ccc;
            }}
            .page-break {{
                page-break-before: always;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- PORTADA -->
        <div class="cover-page">
            <h1>🔒 SEC-AUDIT PRO</h1>
            <div class="subtitle">AUDITORIA COMPLETA DE SEGURETAT</div>
            <div class="cover-info">
                <div class="cover-info-item">
                    <span class="cover-info-label">🎯 Objectiu:</span> {html.escape(target)}
                </div>
                <div class="cover-info-item">
                    <span class="cover-info-label">📅 Data Auditoria:</span> {datetime.now().strftime('%Y-%m-%d')}
                </div>
                <div class="cover-info-item">
                    <span class="cover-info-label">📊 Scans Realitzats:</span> {len(scan_history_list)}
                </div>
                <div class="cover-info-item">
                    <span class="cover-info-label">⚙️ Eina:</span> SEC-AUDIT PRO v3.0
                </div>
            </div>
        </div>
        
        <!-- RESUM EXECUTIU -->
        <div class="section page-break">
            <h2>📋 Resum Executiu</h2>
            <div class="executive-summary">
                <p style="font-size: 16px; line-height: 1.8; margin-bottom: 20px;">
                    Aquest document presenta els resultats d'una auditoria de seguretat completa realitzada sobre 
                    <strong>{html.escape(target)}</strong>. S'han executat <strong>{len(scan_history_list)} scans</strong> 
                    diferents per avaluar la postura de seguretat del sistema.
                </p>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{total_ports_open}</div>
                        <div class="stat-label">Ports Oberts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(all_services)}</div>
                        <div class="stat-label">Serveis Detectats</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_vulns}</div>
                        <div class="stat-label">Vulnerabilitats</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(scan_history_list)}</div>
                        <div class="stat-label">Scans Executats</div>
                    </div>
                </div>
            </div>
            
            <h3>🛡️ Distribució de Vulnerabilitats</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" style="color: #ff006e;">{total_vulnerabilities['critical']}</div>
                    <div class="stat-label">Crítiques</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #ff6b35;">{total_vulnerabilities['high']}</div>
                    <div class="stat-label">Altes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #ffbe0b;">{total_vulnerabilities['medium']}</div>
                    <div class="stat-label">Mitjanes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #8be9fd;">{total_vulnerabilities['low']}</div>
                    <div class="stat-label">Baixes</div>
                </div>
            </div>
        </div>
        
        <!-- ÍNDEX DE SCANS -->
        <div class="section">
            <h2>📑 Índex de Scans Realitzats</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Tipus de Scan</th>
                        <th>Data i Hora</th>
                        <th>Duració</th>
                        <th>Estat</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    for idx, scan in enumerate(scan_history_list, 1):
        html_content += f"""
                    <tr>
                        <td><strong>{idx}</strong></td>
                        <td>{html.escape(scan['type'])}</td>
                        <td>{scan['timestamp']}</td>
                        <td>{scan['duration']}</td>
                        <td><span class="badge badge-success">✓ Completat</span></td>
                    </tr>
"""
    
    html_content += """
                </tbody>
            </table>
        </div>
        
        <!-- DETALL DE CADA SCAN -->
        <div class="section page-break">
            <h2>🔍 Detall dels Scans</h2>
"""
    
    for idx, scan in enumerate(scan_history_list, 1):
        html_content += f"""
            <div class="scan-section">
                <div class="scan-header">
                    <div class="scan-title">SCAN #{idx}: {html.escape(scan['type'])}</div>
                    <div class="scan-meta">
                        ⏰ {scan['timestamp']} | ⏱ Duració: {scan['duration']}
                    </div>
                </div>
"""
        
        data = scan['data']
        
        # Si té ports
        if 'ports' in data and data['ports']:
            html_content += f"""
                <h4 style="color: #00d4ff; margin: 20px 0 10px 0;">🔌 Ports Detectats ({len(data['ports'])})</h4>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Estat</th>
                            <th>Servei</th>
                            <th>Versió</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for port in data['ports'][:20]:  # Limitar a 20 ports per scan
                badge_class = "badge-success" if port['state'] == 'open' else "badge-low"
                html_content += f"""
                        <tr>
                            <td><strong>{port['port']}</strong></td>
                            <td>{port['protocol'].upper()}</td>
                            <td><span class="badge {badge_class}">{port['state']}</span></td>
                            <td>{html.escape(port['service'])}</td>
                            <td>{html.escape(port['version'])}</td>
                        </tr>
"""
            html_content += """
                    </tbody>
                </table>
"""
        
        # Si té vulnerabilitats
        if 'vulnerabilities' in data and data['vulnerabilities']:
            html_content += f"""
                <h4 style="color: #ff006e; margin: 20px 0 10px 0;">⚠️ Vulnerabilitats Detectades ({len(data['vulnerabilities'])})</h4>
                <table>
                    <thead>
                        <tr>
                            <th>CVE</th>
                            <th>Severitat</th>
                            <th>Descripció</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for vuln in data['vulnerabilities']:
                severity_lower = vuln['severity'].lower()
                badge_class = f"badge-{severity_lower}"
                html_content += f"""
                        <tr>
                            <td><strong>{html.escape(vuln['cve'])}</strong></td>
                            <td><span class="badge {badge_class}">{html.escape(vuln['severity'])}</span></td>
                            <td>{html.escape(vuln['description'][:150])}</td>
                        </tr>
"""
            html_content += """
                    </tbody>
                </table>
"""
        
        html_content += """
            </div>
"""
    
    # CONCLUSIONS
    risk_level = "BAIX"
    risk_color = "#06ffa5"
    if total_vulnerabilities['critical'] > 0:
        risk_level = "CRÍTIC"
        risk_color = "#ff006e"
    elif total_vulnerabilities['high'] > 3:
        risk_level = "ALT"
        risk_color = "#ff6b35"
    elif total_vulnerabilities['high'] > 0 or total_vulnerabilities['medium'] > 5:
        risk_level = "MITJÀ"
        risk_color = "#ffbe0b"
    
    html_content += f"""
        <!-- CONCLUSIONS -->
        <div class="conclusions page-break">
            <h3>🎯 Conclusions i Recomanacions</h3>
            
            <div style="margin: 25px 0;">
                <p style="font-size: 18px; margin-bottom: 15px;">
                    <strong>Nivell de Risc Global:</strong> 
                    <span style="color: {risk_color}; font-size: 24px; font-weight: bold;">{risk_level}</span>
                </p>
            </div>
            
            <h4 style="color: #00d4ff; margin: 25px 0 15px 0;">📌 Troballes Principals:</h4>
            <ul style="list-style: none; padding: 0;">
                <li style="margin: 10px 0; padding-left: 20px;">
                    ✓ S'han detectat <strong>{total_ports_open} ports oberts</strong> en el sistema
                </li>
                <li style="margin: 10px 0; padding-left: 20px;">
                    ✓ S'han identificat <strong>{len(all_services)} serveis diferents</strong> en execució
                </li>
                <li style="margin: 10px 0; padding-left: 20px;">
                    ⚠ S'han trobat <strong>{total_vulns} vulnerabilitats</strong> en total
                </li>
            </ul>
            
            <h4 style="color: #00d4ff; margin: 25px 0 15px 0;">💡 Recomanacions:</h4>
"""
    
    if total_vulnerabilities['critical'] > 0:
        html_content += """
            <div class="recommendation">
                <strong style="color: #ff006e;">🔴 URGENT:</strong> Corregir immediatament les vulnerabilitats crítiques detectades
            </div>
"""
    
    if total_vulnerabilities['high'] > 0:
        html_content += """
            <div class="recommendation">
                <strong style="color: #ff6b35;">🟠 PRIORITARI:</strong> Aplicar pegats de seguretat per les vulnerabilitats d'alta severitat
            </div>
"""
    
    if total_ports_open > 10:
        html_content += """
            <div class="recommendation">
                <strong style="color: #ffbe0b;">🟡 RECOMANAT:</strong> Revisar i tancar ports innecessaris per reduir la superfície d'atac
            </div>
"""
    
    html_content += """
            <div class="recommendation">
                <strong style="color: #00d4ff;">🔵 GENERAL:</strong> Mantenir tots els serveis actualitzats amb les últimes versions de seguretat
            </div>
            <div class="recommendation">
                <strong style="color: #00d4ff;">🔵 GENERAL:</strong> Implementar monitorització contínua de seguretat
            </div>
        </div>
        
        <!-- FOOTER -->
        <div class="footer">
            <p>🔒 Generat per SEC-AUDIT PRO v3.0 - Advanced Security Auditing Suite</p>
            <p style="margin-top: 10px;">
                Data de generació: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """
            </p>
            <p style="margin-top: 10px; font-size: 12px;">
                Fes click al botó "📄 EXPORTAR A PDF" per convertir aquest report a PDF
            </p>
        </div>
    </div>
    
    <!-- Botó flotant per exportar a PDF -->
    <button onclick="window.print()" style="
        position: fixed;
        bottom: 30px;
        right: 30px;
        background: linear-gradient(135deg, #00d4ff 0%, #7b2cbf 100%);
        color: white;
        border: none;
        border-radius: 50px;
        padding: 15px 30px;
        font-size: 16px;
        font-weight: bold;
        cursor: pointer;
        box-shadow: 0 4px 15px rgba(0, 212, 255, 0.4);
        z-index: 1000;
        transition: all 0.3s ease;
    " onmouseover="this.style.transform='scale(1.05)'; this.style.boxShadow='0 6px 20px rgba(0, 212, 255, 0.6)';" 
       onmouseout="this.style.transform='scale(1)'; this.style.boxShadow='0 4px 15px rgba(0, 212, 255, 0.4)';">
        📄 EXPORTAR A PDF
    </button>
    
    <style>
        @media print {
            button {
                display: none !important;
            }
        }
    </style>
</body>
</html>
"""
    
    return html_content


# ---------- FUNCIONS D'EXECUCIÓ ----------
current_process = None
def run_stoppable_command(cmd_list, stop_event):
    global current_process
    cmd = cmd_list
    try:
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        current_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, startupinfo=startupinfo
        )
        
        while True:
            if stop_event.is_set():
                current_process.terminate()
                current_process.wait()
                return "", "Escaneig aturat per l'usuari", -1

            returncode = current_process.poll()
            if returncode is not None:
                stdout, stderr = current_process.communicate()
                return stdout, stderr, returncode
            time.sleep(0.1)
    except FileNotFoundError:
        return "", f"Error: Comanda no trobada '{cmd[0]}'.", 1
    except Exception as e:
        return "", f"Error genèric: {e}", 1
    finally:
        current_process = None

def ping_scan(target, stop_event=None):
    if stop_event:
        # Auto-correcció xarxa
        if target.strip().endswith(".0") and "/" not in target: target += "/24"
        cmd = ["nmap", target, "-sn"]
        stdout, stderr, rc = run_stoppable_command(cmd, stop_event)
    else: return "Error intern"
    return stdout or stderr

def port_scan(target, stop_event=None):
    if stop_event:
        cmd = ["nmap", target, "-sT", "--top-ports", "100"]
        stdout, stderr, rc = run_stoppable_command(cmd, stop_event)
    else: return "Error intern"
    return stdout or stderr

def version_scan(target, stop_event=None):
    if stop_event:
        cmd = ["nmap", target, "-sV", "--top-ports", "100"]
        stdout, stderr, rc = run_stoppable_command(cmd, stop_event)
    else: return "Error intern"
    return stdout or stderr

# --- NOVA FUNCIÓ DE VULNERABILITATS ---
def vuln_scan(target, stop_event=None):
    if stop_event:
        # --script vuln: Executa scripts de detecció de vulnerabilitats
        # -sV: Necessari per saber la versió del servei
        cmd = ["nmap", target, "-sV", "--script", "vuln"]
        stdout, stderr, rc = run_stoppable_command(cmd, stop_event)
        
        # Si triga molt i l'usuari cancel·la
        if rc == -1: return "Escaneig de vulnerabilitats aturat."
        
        return prettify_vuln(stdout + "\n" + stderr)
    else: return "Error intern"
# ---------------------------------------

def enum4linux_scan(target, stop_event=None):
    if not stop_event: return "Error intern"
    try:
        cmd = ["enum4linux", "-a", target]
        stdout, stderr, rc = run_stoppable_command(cmd, stop_event)
        if rc == -1: return "Aturat per l'usuari"
        return prettify_enum4linux((stdout or "") + (stderr or ""))
    except Exception as e: return f"Error: {e}"

def ssh_audit_scan(target, stop_event=None):
    if not stop_event: return "Error intern"
    try:
        cmd = ["ssh-audit", target]
        global current_process
        current_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout_acc = []
        stderr_acc = []
        while True:
            if stop_event.is_set():
                current_process.terminate()
                return "Aturat per l'usuari"
            line = current_process.stdout.readline()
            if line: stdout_acc.append(line)
            else:
                if current_process.poll() is not None:
                    rem_out, rem_err = current_process.communicate()
                    if rem_out: stdout_acc.append(rem_out)
                    if rem_err: stderr_acc.append(rem_err)
                    break
                time.sleep(0.05)
        return prettify_ssh_audit("".join(stdout_acc) + "".join(stderr_acc))
    except Exception as e: return f"Error: {e}"
    finally: current_process = None


# ========== GUI PROFESSIONAL AMB EFECTES MODERNS ==========
class AuditorGUI:
    def __init__(self, root):
        self.root = root
        self.stop_event = threading.Event()
        self.scan_in_progress = False
        self.scan_start_time = None
        self.timer_job = None
        
        # Data storage for reports
        self.current_scan_data = {}
        self.current_scan_type = ""
        self.current_target = ""
        self.raw_output = ""
        
        # IP list storage for network scans
        self.discovered_ips = []
        
        # Scan history for complete audit reports
        self.scan_history = {}  # {target: [scan1, scan2, ...]}
        self.scan_duration = ""
        
        root.title("SEC-AUDIT PRO v3.0 - Advanced Security Suite")
        root.geometry("1200x800")
        root.configure(bg=COLOR_BG_MAIN)
        
        # Intentar fer la finestra més gran si és possible
        try:
            root.state('zoomed')  # Maximitzar en alguns sistemes
        except:
            pass

        self._setup_styles()

        # ===== SIDEBAR AMB SCROLL PER FINESTRES PETITES =====
        sidebar_container = Frame(root, bg=COLOR_BG_SIDEBAR, width=280)
        sidebar_container.pack(side=LEFT, fill="y")
        sidebar_container.pack_propagate(False)
        
        # Canvas i scrollbar per sidebar amb colors visibles
        sidebar_canvas = Canvas(sidebar_container, bg=COLOR_BG_SIDEBAR, highlightthickness=0, width=260)
        sidebar_scrollbar = Scrollbar(sidebar_container, orient="vertical", command=sidebar_canvas.yview,
                                     bg=COLOR_BG_SIDEBAR, troughcolor="#1a1f2e", 
                                     activebackground=COLOR_ACCENT_PRIMARY, width=12)
        
        self.sidebar = Frame(sidebar_canvas, bg=COLOR_BG_SIDEBAR, padx=15, pady=20)
        
        # Configurar scroll
        sidebar_canvas.configure(yscrollcommand=sidebar_scrollbar.set)
        sidebar_scrollbar.pack(side=RIGHT, fill=Y)
        sidebar_canvas.pack(side=LEFT, fill=BOTH, expand=True)
        
        # Crear finestra al canvas amb amplada fixa
        canvas_frame = sidebar_canvas.create_window((0, 0), window=self.sidebar, anchor="nw", width=245)
        
        # Actualitzar scroll region quan canvia la mida
        def configure_scroll(event):
            sidebar_canvas.configure(scrollregion=sidebar_canvas.bbox("all"))
        
        self.sidebar.bind("<Configure>", configure_scroll)
        
        # Scroll amb roda del ratolí
        def on_mousewheel(event):
            sidebar_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        sidebar_canvas.bind_all("<MouseWheel>", on_mousewheel)  # Windows
        sidebar_canvas.bind_all("<Button-4>", lambda e: sidebar_canvas.yview_scroll(-1, "units"))  # Linux scroll up
        sidebar_canvas.bind_all("<Button-5>", lambda e: sidebar_canvas.yview_scroll(1, "units"))   # Linux scroll down

        self.main_area = Frame(root, bg=COLOR_BG_MAIN)
        self.main_area.pack(side=RIGHT, fill=BOTH, expand=True)

        # ===== LOGO AMB EFECTE NEON =====
        logo_frame = Frame(self.sidebar, bg=COLOR_BG_SIDEBAR)
        logo_frame.pack(anchor="w", pady=(0, 5))
        
        lbl_logo = Label(logo_frame, text="🔒 SEC-AUDIT", bg=COLOR_BG_SIDEBAR, 
                        fg=COLOR_ACCENT_PRIMARY, font=("Arial Black", 18, "bold"))
        lbl_logo.pack(anchor="w")
        
        lbl_subtitle = Label(self.sidebar, text="Professional Security Suite", 
                           bg=COLOR_BG_SIDEBAR, fg=COLOR_TEXT_DIM, 
                           font=("Segoe UI", 9, "italic"))
        lbl_subtitle.pack(anchor="w", pady=(0, 5))
        
        lbl_version = Label(self.sidebar, text="v3.0 ULTIMATE", 
                          bg=COLOR_BG_SIDEBAR, fg=COLOR_ACCENT_SECONDARY, 
                          font=("Consolas", 8, "bold"))
        lbl_version.pack(anchor="w", pady=(0, 25))

        # ===== INPUT AMB ESTIL MODERN =====
        Label(self.sidebar, text="🎯 OBJECTIU", bg=COLOR_BG_SIDEBAR, 
              fg=COLOR_TEXT_MAIN, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        
        # Frame contenidor per input i llista d'IPs
        input_frame = Frame(self.sidebar, bg="#1a1f2e", highlightbackground=COLOR_ACCENT_PRIMARY, 
                          highlightthickness=1)
        input_frame.pack(fill="x", pady=(0, 10))
        
        # Entry per l'objectiu
        self.entry_target = Entry(input_frame, bg="#1a1f2e", fg=COLOR_ACCENT_PRIMARY, 
                                 insertbackground=COLOR_ACCENT_PRIMARY, relief=FLAT, 
                                 font=("Consolas", 11, "bold"), bd=0)
        self.entry_target.pack(fill="x", ipady=8, padx=2, pady=(2, 0))
        self.entry_target.insert(0, "127.0.0.1")
        
        # Separador dins del frame
        sep_line = Frame(input_frame, bg=COLOR_ACCENT_PRIMARY, height=1)
        sep_line.pack(fill="x", padx=2, pady=5)
        
        # Label per IPs detectades (dins del mateix frame)
        lbl_ips = Label(input_frame, text="📋 IPs detectades:", bg="#1a1f2e", 
                       fg=COLOR_TEXT_DIM, font=("Segoe UI", 8), anchor="w")
        lbl_ips.pack(fill="x", padx=4, pady=(0, 2))
        
        # Frame per listbox i scrollbar
        list_container = Frame(input_frame, bg="#1a1f2e")
        list_container.pack(fill="x", padx=2, pady=(0, 2))
        
        # Listbox amb scrollbar
        ip_scroll = Scrollbar(list_container, orient="vertical", bg="#1a1f2e", 
                             troughcolor="#0f1419", activebackground=COLOR_ACCENT_PRIMARY, width=10)
        ip_scroll.pack(side=RIGHT, fill=Y)
        
        self.ip_listbox = Listbox(list_container, bg="#1a1f2e", fg=COLOR_ACCENT_PRIMARY, 
                                 selectbackground=COLOR_ACCENT_SECONDARY, 
                                 selectforeground=COLOR_TEXT_MAIN,
                                 font=("Consolas", 9), relief=FLAT, bd=0,
                                 height=5, yscrollcommand=ip_scroll.set,
                                 highlightthickness=0)
        self.ip_listbox.pack(side=LEFT, fill=BOTH, expand=True)
        ip_scroll.config(command=self.ip_listbox.yview)
        
        # Event de doble clic per seleccionar IP
        self.ip_listbox.bind("<Double-Button-1>", self.on_ip_double_click)
        
        # Botó per netejar la llista (dins del frame)
        btn_clear_ips = Button(input_frame, text="🗑️ Netejar", 
                              command=self.clear_ip_list,
                              bg="#1a1f2e", fg=COLOR_WARNING, 
                              font=("Segoe UI", 8),
                              relief=FLAT, cursor="hand2", padx=5, pady=3)
        btn_clear_ips.pack(anchor="e", padx=4, pady=(0, 4))
        
        # Efecte hover per botó netejar
        def clear_enter(e):
            btn_clear_ips['fg'] = COLOR_ACCENT_PRIMARY
        def clear_leave(e):
            btn_clear_ips['fg'] = COLOR_WARNING
        
        btn_clear_ips.bind("<Enter>", clear_enter)
        btn_clear_ips.bind("<Leave>", clear_leave)

        # Separador amb efecte lluminós
        sep_canvas = Canvas(self.sidebar, height=3, bg=COLOR_BG_SIDEBAR, highlightthickness=0)
        sep_canvas.pack(fill="x", pady=(0, 20))
        sep_canvas.create_line(0, 1, 300, 1, fill=COLOR_ACCENT_PRIMARY, width=2)

        # ===== BOTONS AMB CATEGORIES =====
        self._create_button_section("⚡ XARXA I PORTS", [
            ("PING SCAN (Discovery)", self.start_ping_scan, "normal"),
            ("PORT SCAN (Fast)", self.start_port_scan, "normal"),
            ("VERSION SCAN (Services)", self.start_version_scan, "normal"),
        ])
        
        self._create_button_section("ANÀLISI AVANÇADA", [
            ("VULN SCAN (NSE)", self.start_vuln_scan, "danger"),
        ])
        
        self._create_button_section("SERVEIS ESPECÍFICS", [
            ("SMB ENUM (enum4linux)", self.start_enum4linux_scan, "normal"),
            ("SSH AUDIT", self.start_ssh_audit, "normal"),
        ])

        # Botó STOP amb efecte especial
        Frame(self.sidebar, height=20, bg=COLOR_BG_SIDEBAR).pack()
        self.btn_stop = Button(self.sidebar, text="⏹ ATURAR PROCÉS", 
                              command=self.peticio_stop_auditoria,
                              bg=COLOR_DANGER, fg="white", 
                              activebackground="#ff1744", activeforeground="white",
                              relief=FLAT, font=("Segoe UI", 11, "bold"), 
                              cursor="hand2", bd=0)
        self.btn_stop.pack(side=BOTTOM, fill="x", pady=10, ipady=10)
        
        # Efecte hover per botó stop
        def stop_enter(e):
            e.widget['bg'] = "#ff1744"
        def stop_leave(e):
            e.widget['bg'] = COLOR_DANGER
        self.btn_stop.bind("<Enter>", stop_enter)
        self.btn_stop.bind("<Leave>", stop_leave)

        # Botó EXPORT HTML/PDF
        Frame(self.sidebar, height=10, bg=COLOR_BG_SIDEBAR).pack(side=BOTTOM)
        self.btn_export = Button(self.sidebar, text="📄 EXPORTAR REPORT (HTML)", 
                                command=self.export_report,
                                bg="#1a4d2e", fg=COLOR_SUCCESS, 
                                activebackground="#2d6a4f", activeforeground="white",
                                relief=FLAT, font=("Segoe UI", 10, "bold"), 
                                cursor="hand2", bd=0)
        self.btn_export.pack(side=BOTTOM, fill="x", pady=(0, 10), ipady=8)
        
        # Efecte hover per botó export
        def export_enter(e):
            e.widget['bg'] = "#2d6a4f"
        def export_leave(e):
            e.widget['bg'] = "#1a4d2e"
        self.btn_export.bind("<Enter>", export_enter)
        self.btn_export.bind("<Leave>", export_leave)

        # Botó EXPORT AUDITORIA COMPLETA
        self.btn_export_complete = Button(self.sidebar, text="📚 AUDITORIA COMPLETA", 
                                         command=self.export_complete_audit,
                                         bg="#2d1b4e", fg="#b794f6", 
                                         activebackground="#3d2b5e", activeforeground="white",
                                         relief=FLAT, font=("Segoe UI", 10, "bold"), 
                                         cursor="hand2", bd=0)
        self.btn_export_complete.pack(side=BOTTOM, fill="x", pady=(0, 10), ipady=8)
        
        # Efecte hover per botó export complete
        def export_complete_enter(e):
            e.widget['bg'] = "#3d2b5e"
        def export_complete_leave(e):
            e.widget['bg'] = "#2d1b4e"
        self.btn_export_complete.bind("<Enter>", export_complete_enter)
        self.btn_export_complete.bind("<Leave>", export_complete_leave)
        
        # Label comptador de scans
        self.scan_count_var = StringVar()
        self.scan_count_var.set("📊 Scans guardats: 0")
        self.lbl_scan_count = Label(self.sidebar, textvariable=self.scan_count_var,
                                   bg=COLOR_BG_SIDEBAR, fg=COLOR_TEXT_DIM,
                                   font=("Segoe UI", 9))
        self.lbl_scan_count.pack(side=BOTTOM, pady=(0, 15))


        # ===== ÀREA PRINCIPAL AMB HEADER PROFESSIONAL =====
        header_frame = Frame(self.main_area, bg=COLOR_GRADIENT_START, pady=15, padx=25)
        header_frame.pack(fill="x")
        
        # Status amb icona animada
        status_container = Frame(header_frame, bg=COLOR_GRADIENT_START)
        status_container.pack(side=LEFT, fill="x", expand=True)
        
        self.status_var = StringVar()
        self.status_var.set("⚡ Sistema preparat. Esperant comandes...")
        self.lbl_status = Label(status_container, textvariable=self.status_var, 
                               bg=COLOR_GRADIENT_START, fg=COLOR_TEXT_MAIN, 
                               font=("Segoe UI", 11))
        self.lbl_status.pack(side=LEFT)
        
        # Timer
        self.timer_var = StringVar()
        self.timer_var.set("")
        self.lbl_timer = Label(header_frame, textvariable=self.timer_var,
                              bg=COLOR_GRADIENT_START, fg=COLOR_ACCENT_PRIMARY,
                              font=("Consolas", 10, "bold"))
        self.lbl_timer.pack(side=RIGHT, padx=10)

        # Barra de progrés
        self.progress_frame = Frame(self.main_area, bg=COLOR_BG_MAIN, height=8)
        self.progress_frame.pack(fill="x", padx=25, pady=(0, 5))
        
        self.progress_canvas = Canvas(self.progress_frame, height=6, bg="#1a1f2e", 
                                     highlightthickness=0)
        self.progress_canvas.pack(fill="x")
        self.progress_bar = None
        self.progress_animation_running = False

        # ===== TERMINAL OUTPUT AMB ESTIL MATRIX =====
        out_container = Frame(self.main_area, bg=COLOR_TERM_BG, padx=3, pady=3,
                            highlightbackground=COLOR_ACCENT_PRIMARY, highlightthickness=1)
        out_container.pack(fill=BOTH, expand=True, padx=25, pady=(5, 25))
        
        scroll = Scrollbar(out_container, bg=COLOR_TERM_BG, troughcolor=COLOR_TERM_BG)
        scroll.pack(side=RIGHT, fill=Y)
        
        self.txt = Text(out_container, bg=COLOR_TERM_BG, fg=COLOR_TERM_FG, 
                       font=("Consolas", 10), bd=0, highlightthickness=0, 
                       yscrollcommand=scroll.set, wrap="word", padx=10, pady=10)
        self.txt.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.config(command=self.txt.yview)

        # ===== TAGS AMB COLORS NEON =====
        self.txt.tag_config("HEADER", foreground=COLOR_ACCENT_PRIMARY, 
                          font=("Consolas", 12, "bold"))
        self.txt.tag_config("FAIL", foreground="#ff006e", 
                          font=("Consolas", 10, "bold"))
        self.txt.tag_config("WARN", foreground=COLOR_WARNING, 
                          font=("Consolas", 10))
        self.txt.tag_config("SUCCESS", foreground=COLOR_SUCCESS, 
                          font=("Consolas", 10, "bold"))
        self.txt.tag_config("INFO", foreground="#00d4ff", 
                          font=("Consolas", 10))
        self.txt.tag_config("CMD", foreground=COLOR_TEXT_DIM, 
                          font=("Consolas", 9, "italic"))
        self.txt.tag_config("VULN_HIGHLIGHT", foreground="#ff006e", 
                          background="#330011", font=("Consolas", 11, "bold"))
        self.txt.tag_config("GLOW", foreground=COLOR_ACCENT_PRIMARY,
                          font=("Consolas", 10, "bold"))

        self._welcome_msg()
    
    def _create_button_section(self, title, buttons):
        """Crea una secció de botons amb títol"""
        Frame(self.sidebar, height=15, bg=COLOR_BG_SIDEBAR).pack()
        Label(self.sidebar, text=title, bg=COLOR_BG_SIDEBAR, 
              fg=COLOR_ACCENT_PRIMARY, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 8))
        
        for btn_text, btn_command, btn_type in buttons:
            self.create_btn(btn_text, btn_command, btn_type)

    def _setup_styles(self):
        """Configura estils TTK"""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", background=COLOR_BG_SIDEBAR, foreground="white", borderwidth=0)
        style.map("TButton", background=[('active', '#3e3e42')])

    def create_btn(self, text, command, btn_type="normal"):
        """Crea botons amb estil modern i efectes hover"""
        # Colors segons tipus
        if btn_type == "danger":
            bg_color = "#3d0a1f"  # Fons fosc vermellós
            fg_color = "#ff006e"  # Text rosa neon
            hover_bg = "#5a0f2f"
            hover_fg = "#ff3399"
        else:
            bg_color = "#1a1f2e"
            fg_color = COLOR_TEXT_MAIN
            hover_bg = "#252d3d"
            hover_fg = COLOR_ACCENT_PRIMARY

        btn = Button(self.sidebar, text=text, command=command,
                     bg=bg_color, fg=fg_color, 
                     activebackground=hover_bg, activeforeground=hover_fg,
                     relief=FLAT, bd=0, font=("Segoe UI", 9, "bold"),
                     cursor="hand2", anchor="w", padx=12)
        btn.pack(fill="x", pady=3, ipady=6)
        
        # Efectes hover suaus
        def on_enter(e):
            if e.widget['state'] != 'disabled': 
                e.widget['background'] = hover_bg
                e.widget['foreground'] = hover_fg
        def on_leave(e):
            if e.widget['state'] != 'disabled': 
                e.widget['background'] = bg_color
                e.widget['foreground'] = fg_color
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)

    def _welcome_msg(self):
        """Missatge de benvinguda amb ASCII art"""
        ascii_art = """
╔═══════════════════════════════════════════════════════════════╗
║  🔒 SEC-AUDIT PRO v3.0 - Advanced Security Auditing Suite   ║
╚═══════════════════════════════════════════════════════════════╝
        """
        self.append_text_tagged(ascii_art, "GLOW")
        self.append_text_tagged("[✓] Sistema inicialitzat correctament", "SUCCESS")
        self.append_text_tagged("[i] Eines disponibles: NMAP, enum4linux, ssh-audit", "INFO")
        self.append_text_tagged("[⚡] Esperant instruccions...", "CMD")
        self.append_text_tagged("═" * 65, "CMD")

    def append_text_tagged(self, text, tag=None):
        """Afegeix text amb tag de color al terminal"""
        self.txt.insert(END, text + "\n", tag)
        self.txt.see(END)
        self.root.update()
    
    def start_progress_animation(self):
        """Inicia animació de barra de progrés"""
        self.progress_animation_running = True
        self.progress_canvas.delete("all")
        self._animate_progress(0)
    
    def _animate_progress(self, pos):
        """Animació de barra de progrés infinita"""
        if not self.progress_animation_running:
            return
        
        width = self.progress_canvas.winfo_width()
        if width <= 1:
            width = 800  # Valor per defecte
        
        # Neteja i dibuixa barra
        self.progress_canvas.delete("all")
        bar_width = 100
        x = (pos % (width + bar_width)) - bar_width
        
        # Gradient effect amb múltiples rectangles
        for i in range(bar_width):
            alpha = i / bar_width
            x_pos = x + i
            if 0 <= x_pos < width:
                color_intensity = int(alpha * 255)
                color = f"#{color_intensity:02x}{color_intensity:02x}{255:02x}"
                self.progress_canvas.create_line(x_pos, 0, x_pos, 6, fill=color, width=1)
        
        # Continua animació
        if self.progress_animation_running:
            self.root.after(20, lambda: self._animate_progress(pos + 5))
    
    def stop_progress_animation(self):
        """Atura animació de progrés"""
        self.progress_animation_running = False
        self.progress_canvas.delete("all")
    
    def start_timer(self):
        """Inicia comptador de temps"""
        self.scan_start_time = time.time()
        self._update_timer()
    
    def _update_timer(self):
        """Actualitza el timer cada segon"""
        if self.scan_in_progress and self.scan_start_time:
            elapsed = int(time.time() - self.scan_start_time)
            mins, secs = divmod(elapsed, 60)
            self.timer_var.set(f"⏱ {mins:02d}:{secs:02d}")
            self.timer_job = self.root.after(1000, self._update_timer)
    
    def stop_timer(self):
        """Atura el timer"""
        if self.timer_job:
            self.root.after_cancel(self.timer_job)
            self.timer_job = None
        self.scan_start_time = None

    # ===== IP LIST MANAGEMENT =====
    def add_ip_to_list(self, ip):
        """Afegeix una IP a la llista si no existeix ja"""
        if ip and ip not in self.discovered_ips:
            self.discovered_ips.append(ip)
            self.ip_listbox.insert(END, ip)
    
    def clear_ip_list(self):
        """Neteja la llista d'IPs detectades"""
        self.discovered_ips.clear()
        self.ip_listbox.delete(0, END)
    
    def on_ip_double_click(self, event):
        """Handler per doble clic sobre una IP de la llista"""
        selection = self.ip_listbox.curselection()
        if selection:
            ip = self.ip_listbox.get(selection[0])
            # Omplir el camp objectiu amb la IP seleccionada
            self.entry_target.delete(0, END)
            self.entry_target.insert(0, ip)
            # Feedback visual
            self.append_text_tagged(f"\n✅ IP seleccionada: {ip}\n", "SUCCESS")

    def show_summary(self):
        """Mostra un resum estructurat de les dades parsejades"""
        if not self.current_scan_data:
            return
        
        self.append_text_tagged("\n", "")
        self.append_text_tagged("═" * 65, "GLOW")
        self.append_text_tagged("📊 RESUM DE RESULTATS", "HEADER")
        self.append_text_tagged("═" * 65, "GLOW")
        
        # Resum de ports
        if 'ports' in self.current_scan_data:
            data = self.current_scan_data
            self.append_text_tagged(f"\n✅ Ports Oberts: {data['total_open']}", "SUCCESS")
            self.append_text_tagged(f"❌ Ports Tancats: {data['total_closed']}", "FAIL")
            self.append_text_tagged(f"🔒 Ports Filtrats: {data['total_filtered']}", "WARN")

    def parse_and_print_output(self, text):
        """Analitza sortida i aplica colors amb millor formatació"""
        for line in text.splitlines():
            # Detecció de vulnerabilitats amb highlight especial
            if "VULNERABLE" in line or "CVE-" in line:
                self.txt.insert(END, "  ⚠️  " + line + "\n", "VULN_HIGHLIGHT")
                continue
            
            # Detecció de ports oberts
            if "/tcp" in line or "/udp" in line:
                if "open" in line.lower():
                    self.txt.insert(END, "  ✅ " + line + "\n", "SUCCESS")
                    continue
            
            # Parsing de seccions
            if line.startswith("SECTION_HEADER::"):
                content = line.split("::", 1)[1]
                self.txt.insert(END, "\n" + "═"*50 + "\n", "CMD")
                self.txt.insert(END, f"  🔹 {content}\n", "HEADER")
                self.txt.insert(END, "═"*50 + "\n", "CMD")
            elif line.startswith("TAG_FAIL::"):
                self.txt.insert(END, "  ❌ " + line.split("::", 1)[1] + "\n", "FAIL")
            elif line.startswith("TAG_WARN::"):
                self.txt.insert(END, "  ⚠️  " + line.split("::", 1)[1] + "\n", "WARN")
            elif line.startswith("TAG_REC::"):
                self.txt.insert(END, "  💡 " + line.split("::", 1)[1] + "\n", "INFO")
            elif line.startswith("TAG_SUCCESS::"):
                self.txt.insert(END, "  ✅ " + line.split("::", 1)[1] + "\n", "SUCCESS")
            else:
                self.txt.insert(END, line + "\n")
        self.txt.see(END)

    def _prepare_scan(self, scan_type):
        """Prepara l'inici d'un escaneig amb efectes visuals"""
        self.stop_event.clear()
        self.scan_in_progress = True
        self.txt.delete(1.0, END)
        
        # Guardar metadata per reports
        self.current_scan_type = scan_type
        target = self.entry_target.get().strip()
        self.current_target = target
        self.current_scan_data = {}  # Reset data
        
        # Actualitza status amb animació
        self.status_var.set(f"🔍 EXECUTANT: {scan_type}...")
        self.lbl_status.config(fg=COLOR_ACCENT_PRIMARY)
        
        # Inicia timer i progress bar
        self.start_timer()
        self.start_progress_animation()
        
        # Header visual millorat
        self.append_text_tagged("═" * 65, "GLOW")
        self.append_text_tagged(f"🔹 INICIANT {scan_type}", "HEADER")
        self.append_text_tagged(f"🎯 OBJECTIU: {target}", "INFO")
        self.append_text_tagged(f"⏰ HORA INICI: {datetime.now().strftime('%H:%M:%S')}", "CMD")
        
        # Avís especial per vuln scan
        if "VULN" in scan_type:
            self.append_text_tagged("", "")
            self.append_text_tagged("⚠️  ATENCIÓ: Aquest escaneig pot trigar diversos minuts.", "WARN")
            self.append_text_tagged("🔍 S'executen scripts NSE contra tots els serveis detectats.", "INFO")

        self.append_text_tagged("═" * 65, "GLOW")
        self.append_text_tagged("", "")
        return target

    def _finish_scan(self):
        """Finalitza escaneig amb feedback visual"""
        self.scan_in_progress = False
        
        # Atura animacions
        self.stop_timer()
        self.stop_progress_animation()
        
        # Calcula temps total
        if self.scan_start_time:
            elapsed = int(time.time() - self.scan_start_time)
            mins, secs = divmod(elapsed, 60)
            time_str = f"{mins:02d}:{secs:02d}"
        else:
            time_str = "00:00"
        
        self.scan_duration = time_str
        
        # Guardar scan a l'historial si hi ha dades
        if self.current_scan_data and self.current_target:
            if self.current_target not in self.scan_history:
                self.scan_history[self.current_target] = []
            
            scan_record = {
                'type': self.current_scan_type,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'duration': time_str,
                'data': self.current_scan_data.copy(),
                'raw_output': self.raw_output
            }
            self.scan_history[self.current_target].append(scan_record)
            
            # Actualitzar comptador
            count = len(self.scan_history.get(self.current_target, []))
            self.scan_count_var.set(f"📊 Scans guardats: {count}")
        
        # Missatge de finalització
        self.append_text_tagged("", "")
        self.append_text_tagged("═" * 65, "GLOW")
        self.append_text_tagged(f"✅ PROCÉS FINALITZAT - Temps total: {time_str}", "SUCCESS")
        self.append_text_tagged(f"⏰ HORA FI: {datetime.now().strftime('%H:%M:%S')}", "CMD")
        self.append_text_tagged("═" * 65, "GLOW")
        
        # Actualitza status
        self.status_var.set("✅ Escaneig completat. Esperant comandes...")
        self.lbl_status.config(fg=COLOR_SUCCESS)
        self.timer_var.set(f"✓ {time_str}")

    # --- HANDLERS ---
    def start_ping_scan(self):
        if self.scan_in_progress: return
        target = self._prepare_scan("PING SCAN")
        if not target: return
        self.execucions(ping_scan, target)

    def start_port_scan(self):
        if self.scan_in_progress: return
        target = self._prepare_scan("PORT SCAN")
        if not target: return
        self.execucions(port_scan, target)

    def start_version_scan(self):
        if self.scan_in_progress: return
        target = self._prepare_scan("VERSION SCAN")
        if not target: return
        self.execucions(version_scan, target)

    def start_vuln_scan(self):
        if self.scan_in_progress: return
        target = self._prepare_scan("VULN SCAN (NSE)")
        if not target: return
        self.execucions(vuln_scan, target)

    def start_enum4linux_scan(self):
        if self.scan_in_progress: return
        target = self._prepare_scan("ENUM4LINUX")
        if not target: return
        self.execucions(enum4linux_scan, target)

    def start_ssh_audit(self):
        if self.scan_in_progress: return
        target = self._prepare_scan("SSH AUDIT")
        if not target: return
        self.execucions(ssh_audit_scan, target)

    def execucions(self, func, *args):
        def task():
            try:
                output = func(*args, self.stop_event)
                
                # Guardar output raw
                self.raw_output = output
                
                # Parsejar dades segons el tipus de scan
                if "PING" in self.current_scan_type:
                    # Parsejar network scan per extreure IPs
                    self.current_scan_data = ScanDataParser.parse_network_scan(output)
                    # Afegir IPs a la llista
                    if 'discovered_ips' in self.current_scan_data:
                        for ip in self.current_scan_data['discovered_ips']:
                            self.root.after(0, lambda ip=ip: self.add_ip_to_list(ip))
                elif "PORT" in self.current_scan_type or "VERSION" in self.current_scan_type:
                    self.current_scan_data = ScanDataParser.parse_nmap_ports(output)
                elif "VULN" in self.current_scan_type:
                    self.current_scan_data = ScanDataParser.parse_vulnerabilities(output)
                elif "SSH" in self.current_scan_type:
                    self.current_scan_data = ScanDataParser.parse_ssh_audit(output)
                
                self.root.after(0, lambda: self.parse_and_print_output(output))
                
                # Mostrar resum si hi ha dades
                if self.current_scan_data:
                    self.root.after(0, lambda: self.show_summary())
                    
            except Exception as e:
                self.root.after(0, lambda: self.append_text_tagged(f"[ERROR] {e}", "FAIL"))
            finally:
                self.root.after(0, self._finish_scan)
        t = threading.Thread(target=task)
        t.daemon = True
        t.start()
    
    def show_summary(self):
        """Mostra un resum estructurat de les dades parsejades"""
        if not self.current_scan_data:
            return
        
        self.append_text_tagged("\n", "")
        self.append_text_tagged("═" * 65, "GLOW")
        self.append_text_tagged("📊 RESUM DE RESULTATS", "HEADER")
        self.append_text_tagged("═" * 65, "GLOW")
        
        # Resum de ports
        if 'ports' in self.current_scan_data:
            data = self.current_scan_data
            self.append_text_tagged(f"\n✅ Ports Oberts: {data['total_open']}", "SUCCESS")
            self.append_text_tagged(f"❌ Ports Tancats: {data['total_closed']}", "FAIL")
            self.append_text_tagged(f"🔒 Ports Filtrats: {data['total_filtered']}", "WARN")
            
            if data['ports']:
                self.append_text_tagged("\n🔌 PORTS DETECTATS:", "INFO")
                self.append_text_tagged("─" * 65, "CMD")
                for port in data['ports'][:10]:  # Mostrar només els primers 10
                    port_info = f"  Port {port['port']}/{port['protocol']} - {port['state'].upper()} - {port['service']}"
                    if port['version'] != 'N/A':
                        port_info += f" ({port['version']})"
                    
                    if port['state'] == 'open':
                        self.append_text_tagged(port_info, "SUCCESS")
                    else:
                        self.append_text_tagged(port_info, "CMD")
                
                if len(data['ports']) > 10:
                    self.append_text_tagged(f"  ... i {len(data['ports']) - 10} ports més", "CMD")
        
        # Resum de vulnerabilitats
        if 'vulnerabilities' in self.current_scan_data:
            data = self.current_scan_data
            self.append_text_tagged(f"\n⚠️ Vulnerabilitats Crítiques: {data['critical_count']}", "FAIL")
            self.append_text_tagged(f"⚠️ Vulnerabilitats Altes: {data['high_count']}", "WARN")
            self.append_text_tagged(f"⚠️ Vulnerabilitats Mitjanes: {data['medium_count']}", "INFO")
            self.append_text_tagged(f"⚠️ Vulnerabilitats Baixes: {data['low_count']}", "CMD")
            
            if data['vulnerabilities']:
                self.append_text_tagged("\n🛡️ VULNERABILITATS DETECTADES:", "FAIL")
                self.append_text_tagged("─" * 65, "CMD")
                for vuln in data['vulnerabilities'][:5]:  # Mostrar només les primeres 5
                    vuln_info = f"  [{vuln['severity']}] {vuln['cve']}: {vuln['description'][:80]}"
                    self.append_text_tagged(vuln_info, "WARN")
                
                if len(data['vulnerabilities']) > 5:
                    self.append_text_tagged(f"  ... i {len(data['vulnerabilities']) - 5} vulnerabilitats més", "CMD")
        
        self.append_text_tagged("\n💡 Utilitza el botó 'EXPORTAR REPORT' per generar un informe HTML complet", "INFO")
        self.append_text_tagged("═" * 65, "GLOW")
    
    def export_report(self):
        """Exporta les dades a un fitxer HTML professional"""
        if not self.current_scan_data:
            show_modern_notification(self.root, "Sense Dades", 
                                   "No hi ha dades per exportar. Executa primer un escaneig.",
                                   "warning")
            return
        
        # Diàleg per guardar fitxer
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"sec_audit_report_{self.current_target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        
        if not filename:
            return
        
        try:
            # Generar HTML
            html_content = generate_html_report(
                self.current_scan_data,
                self.current_target,
                self.current_scan_type
            )
            
            # Guardar fitxer
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.append_text_tagged(f"\n✅ Report exportat correctament: {filename}", "SUCCESS")
            self.append_text_tagged("💡 Obre el fitxer HTML al navegador i usa 'Imprimir → Guardar com PDF' per convertir-lo", "INFO")
            
            show_modern_notification(self.root, "Èxit", 
                                   f"Report exportat correctament!\n\n{filename}\n\nObre el fitxer HTML al navegador i fes click al botó 'EXPORTAR A PDF'.",
                                   "success")
        except Exception as e:
            self.append_text_tagged(f"\n❌ Error exportant report: {e}", "FAIL")
            show_modern_notification(self.root, "Error", f"Error exportant report:\n{e}", "error")

    def export_complete_audit(self):
        """Exporta tots els scans d'un target en un únic report complet"""
        target = self.current_target or self.entry_target.get().strip()
        
        if not target or target not in self.scan_history or not self.scan_history[target]:
            show_modern_notification(self.root, "Sense Historial", 
                                   "No hi ha scans guardats per aquest target.\n\nExecuta diversos scans primer per generar una auditoria completa.",
                                   "warning")
            return
        
        scan_count = len(self.scan_history[target])
        
        # Diàleg per guardar fitxer
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"auditoria_completa_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        
        if not filename:
            return
        
        try:
            # Generar HTML complet
            html_content = generate_complete_audit_report(
                self.scan_history[target],
                target
            )
            
            # Guardar fitxer
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.append_text_tagged(f"\n✅ Auditoria completa exportada: {filename}", "SUCCESS")
            self.append_text_tagged(f"📊 Inclou {scan_count} scans del target {target}", "INFO")
            self.append_text_tagged("💡 Obre el fitxer HTML al navegador i usa 'Imprimir → Guardar com PDF' per convertir-lo", "INFO")
            
            show_modern_notification(self.root, "Èxit", 
                                   f"Auditoria completa exportada correctament!\n\nFitxer: {filename}\nScans inclosos: {scan_count}\n\nObre el fitxer HTML i fes click al botó 'EXPORTAR A PDF'.",
                                   "success")
        except Exception as e:
            self.append_text_tagged(f"\n❌ Error exportant auditoria completa: {e}", "FAIL")
            show_modern_notification(self.root, "Error", f"Error exportant auditoria completa:\n{e}", "error")

    def peticio_stop_auditoria(self):
        """Atura el procés d'auditoria en curs"""
        if self.scan_in_progress:
            self.append_text_tagged("\n[⚠️] SOL·LICITANT ATURADA DEL PROCÉS...", "WARN")
            self.stop_event.set()
            
            # Atura animacions
            self.stop_timer()
            self.stop_progress_animation()
            
            # Actualitza status
            self.status_var.set("❌ Procés aturat per l'usuari")
            self.lbl_status.config(fg=COLOR_DANGER)
            
            global current_process
            if current_process:
                try: 
                    current_process.terminate()
                except: 
                    pass
        else:
            show_modern_notification(self.root, "Info", "No hi ha cap procés actiu per aturar.", "info")

def main():
    root = Tk()
    app = AuditorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()