#!/usr/bin/env python3
"""
Eina d'auditoria simple amb GUI (Tkinter), escaneig amb nmap, ssh-audit i enum4linux.
Sortida de ssh-audit i enum4linux processada i neta per fer-la més llegible.
"""

import threading
import subprocess
import sys
import os
import time
import re
from tkinter import (
    Tk, Frame, Label, Button, Entry, Text, Scrollbar, END, messagebox
)

# ---------- UTILS ----------
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)

def prettify_ssh_audit(raw: str) -> str:
    """
    Converteix la sortida bruta de ssh-audit (amb colors i format) en un text net,
    amb headers clars i marcatge per fails/warns/recommendacions.
    """
    lines = raw.splitlines()
    out_lines = []
    current_section = None

    for raw_line in lines:
        line = strip_ansi(raw_line).rstrip()

        if not line:
            # mantenim una línia en blanc curta per separar seccions
            if out_lines and out_lines[-1] != "":
                out_lines.append("")
            continue

        # Secció: línies que comencen amb '#'
        if line.startswith("#"):
            sec = line.lstrip("# ").upper()
            sep = "=" * max(10, len(sec) + 6)
            out_lines.append(sep)
            out_lines.append(f"  {sec}")
            out_lines.append(sep)
            current_section = sec
            continue

        # Línies d'informació amb prefix entre parèntesis: (gen), (kex), (key), (enc), (mac), (fin), (rec), (nfo)
        m = re.match(r'^\(?([a-zA-Z0-9\-\s@_/]+)\)?\s*(.*)', line)
        # No confiar massa en l'estructura: busquem keywords dins la línia
        low = line.lower()

        # Prioritat: FAIL -> WARN -> REC -> INFO/GEN
        if "[fail]" in low or " -- [fail]" in low or " -- [fail]" in line.lower():
            # fail
            out_lines.append(f"‼ FAIL: {line}")
        elif "[warn]" in low or " -- [warn]" in low:
            out_lines.append(f"⚠ WARN: {line}")
        elif line.strip().startswith("(rec)") or line.strip().startswith("rec") or "(rec)" in low or "recommend" in low:
            # recomanacions: netegem possibles prefixos '-'
            cleaned = line.lstrip(" -")
            out_lines.append(f"→ RECOMANACIÓ: {cleaned}")
        elif line.strip().startswith("(nfo)") or line.strip().startswith("nfo") or "(nfo)" in low or "info" in low:
            out_lines.append(f"[info] {line}")
        else:
            # Línies generals: fem una indentació si tenen forma `(tag) text`
            # Si tenen prefix `(tag) something`, preservem en format: tag: text
            tag_match = re.match(r'^\(([^)]+)\)\s*(.*)', line)
            if tag_match:
                tag = tag_match.group(1).strip()
                text = tag_match.group(2).strip()
                out_lines.append(f"  - {tag}: {text}")
            else:
                # línia normal, la deixem amb guió per llegibilitat
                out_lines.append(f"  - {line}")

    # netejar múltiples línies buides seguides
    cleaned = []
    prev_blank = False
    for l in out_lines:
        if l == "":
            if not prev_blank:
                cleaned.append(l)
            prev_blank = True
        else:
            cleaned.append(l)
            prev_blank = False

    return "\n".join(cleaned).strip() + "\n"

def prettify_enum4linux(raw: str) -> str:
    """
    Converteix la sortida bruta d'enum4linux en un text net i llegible,
    estructurant la informació clau.
    """
    lines = raw.splitlines()
    out_lines = []

    for raw_line in lines:
        line = strip_ansi(raw_line).rstrip()

        if not line:
            if out_lines and out_lines[-1] != "":
                out_lines.append("")
            continue

        # Secció: línies que comencen amb '===='
        if line.startswith("===") and line.endswith("==="):
            sec = line.strip("= ").upper()
            sep = "=" * max(10, len(sec) + 6)
            out_lines.append(sep)
            out_lines.append(f"  {sec}")
            out_lines.append(sep)
            continue

        # Línies d'informació clau
        if line.startswith("[+]"):
            out_lines.append(f"✔ INFO: {line.lstrip('[+] ')}")
        elif line.startswith("[*]"):
            out_lines.append(f"→ DETALL: {line.lstrip('[*] ')}")
        elif line.startswith("[-]"):
            out_lines.append(f"✘ (No trobat/Error): {line.lstrip('[-] ')}")
        elif line.startswith("Sharename"): # Header de taula de shares
             out_lines.append(f"\n  {line}")
        elif line.startswith("Server "): # Header de taula
             out_lines.append(f"  {line}")
        else:
            # Línia normal, indentar
            out_lines.append(f"    {line}")

    # netejar múltiples línies buides seguides
    cleaned = []
    prev_blank = False
    for l in out_lines:
        if l == "":
            if not prev_blank:
                cleaned.append(l)
            prev_blank = True
        else:
            cleaned.append(l)
            prev_blank = False

    return "\n".join(cleaned).strip() + "\n"


# ---------- FUNCIONS D'EXECUCIÓ AUDITORIA ----------

# FUNCIO PER ATURAR PROCESSOS
current_process = None
def run_stoppable_command(cmd_list, stop_event):
    """
    Executa una comanda (com a llista) i permet aturar-la
    amb un threading.Event.
    Substitueix run_nmap_stoppable per ser genèrica.
    """
    global current_process
    cmd = cmd_list
    try:
        current_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Esperar que acabi o que es demani aturada
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
        return "", f"Error: Comanda no trobada '{cmd[0]}'. Està instal·lat i al PATH?", 1
    except Exception as e:
        return "", f"Error: {e}", 1
    finally:
        current_process = None

# ---------- FUNCIONS D'ESCANEIG ----------

def ping_scan(target, stop_event=None):
    """Escaneig de ping bàsic"""
    if stop_event:
        cmd = ["nmap", target, "-sn"]
        stdout, stderr, rc = run_stoppable_command(cmd, stop_event)
    else:
        return f"Error executant ping scan:"
    return stdout or stderr

def port_scan(target, stop_event=None):
    """Escaneig de ports bàsic"""
    if stop_event:
        cmd = ["nmap", target, "-sT", "--top-ports", "100"]
        stdout, stderr, rc = run_stoppable_command(cmd, stop_event)
    else:
        return f"Error executant port scan:"
    return stdout or stderr

def version_scan(target, stop_event=None):
    """Escaneig de versió"""
    if stop_event:
        cmd = ["nmap", target, "-sV", "--top-ports", "100"]
        stdout, stderr, rc = run_stoppable_command(cmd, stop_event)
    else:
        return f"Error executant version scan:"
    return stdout or stderr

def enum4linux_scan(target, stop_event=None):
    """Enumeració SMB/NetBIOS amb enum4linux.
       Retorna una sortida neta i 'prettified'."""
    if not stop_event:
        return "Error intern: falta stop_event"

    try:
        # -a per a "all" (usuaris, shares, grups, info domini, etc.)
        cmd = ["enum4linux", "-a", target]
        stdout, stderr, rc = run_stoppable_command(cmd, stop_event)

        if rc == -1: # Aturat per l'usuari
            return "Enumeració SMB aturada per l'usuari"

        if stderr:
            # Afegim stderr per si 'enum4linux' no es troba o dóna error
            raw = stdout + "\n\n[enum4linux stderr]\n" + stderr
        else:
            raw = stdout

        # Neteja i format
        pretty = prettify_enum4linux(raw)
        return pretty

    except Exception as e:
        return f"Error executant enum4linux: {e}"


def ssh_audit_scan(target, stop_event=None):
    """Auditoria de seguretat SSH amb ssh-audit.
       Retorna una sortida neta i 'prettified' per a una lectura fàcil."""
    # NOTA: ssh-audit fa servir una lògica lleugerament diferent (llegint
    # línia a línia) que les comandes nmap/enum4linux. Ho mantenim.
    if not stop_event:
        return "Error intern: falta stop_event"

    try:
        cmd = ["ssh-audit", target]
        global current_process
        current_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Llegim tota la sortida mentre podem aturar
        stdout_acc = []
        stderr_acc = []
        # llegim línia a línia per poder detectar aturada ràpida
        while True:
            if stop_event.is_set():
                try:
                    current_process.terminate()
                except Exception:
                    pass
                current_process.wait(timeout=2)
                return "Auditoria SSH aturada per l'usuari"

            # llegim una línia si disponible
            line = current_process.stdout.readline()
            if line:
                stdout_acc.append(line)
            else:
                # si no hi ha línies immediates, comprovem si el procés ha acabat
                if current_process.poll() is not None:
                    # capturar restes
                    rem_out, rem_err = current_process.communicate()
                    if rem_out:
                        stdout_acc.append(rem_out)
                    if rem_err:
                        stderr_acc.append(rem_err)
                    break
                time.sleep(0.05)

        raw_stdout = "".join(stdout_acc)
        raw_stderr = "".join(stderr_acc).strip()

        if raw_stderr:
            # afegim l'error al final per transparència
            raw = raw_stdout + "\n\n[ssh-audit stderr]\n" + raw_stderr
        else:
            raw = raw_stdout

        # Neteja i format
        pretty = prettify_ssh_audit(raw)
        return pretty

    except FileNotFoundError:
        return f"Error: 'ssh-audit' no està instal·lat o no es troba al PATH del sistema."
    except Exception as e:
        return f"Error executant ssh-audit: {e}"
    finally:
        current_process = None

# ---------- GUI ----------
class AuditorGUI:
    def __init__(self, root):
        self.root = root
        self.stop_event = threading.Event()
        self.scan_in_progress = False
        
        root.title("Eina d'auditoria - GUI")
        root.geometry("900x600")

        frm_top = Frame(root, pady=6)
        frm_top.pack(fill="x")

        Label(frm_top, text=" XARXA :").grid(row=0, column=0, sticky="w")
        self.entry_target = Entry(frm_top, width=40)
        self.entry_target.grid(row=0, column=1, padx=6)
        self.entry_target.insert(0,  "127.0.0.1")

        # BOTONS D'ESCANEIG
        btn_frame = Frame(frm_top)
        btn_frame.grid(row=0, column=2, rowspan=2, padx=10)
        Button(btn_frame, text="HOSTS DE XARXA", command=self.start_ping_scan).pack(fill="x")
        Button(btn_frame, text="PORTS OBERTS", command=self.start_port_scan).pack(fill="x", pady=4)
        Button(btn_frame, text="SERVEIS AMB VERSIÓ", command=self.start_version_scan).pack(fill="x")
        # --- NOU BOTÓ ---
        Button(btn_frame, text="ENUMERACIÓ SMB", command=self.start_enum4linux_scan).pack(fill="x", pady=4)
        # ---
        Button(btn_frame, text="AUDITORIA SSH", command=self.start_ssh_audit).pack(fill="x")
        Button(btn_frame, text="⏹ ATURA", command=self.peticio_stop_auditoria, 
               bg="#ff4444", fg="white").pack(fill="x", pady=4)

        # RESULTATS
        Label(root, text="RESULTATS:").pack(anchor="w", padx=8)
        text_frame = Frame(root)
        text_frame.pack(fill="both", expand=True, padx=8, pady=6)
        self.txt = Text(text_frame, wrap="none")
        self.txt.pack(side="left", fill="both", expand=True)
        scroll = Scrollbar(text_frame, command=self.txt.yview)
        scroll.pack(side="right", fill="y")
        self.txt.config(yscrollcommand=scroll.set)

    # --- FUNCIONS GUI ---
    def append_text(self, text):
        """Afegeix text a l'àrea de resultats"""
        self.txt.insert(END, text + "\n")
        self.txt.see(END)
        self.root.update()

    def _prepare_scan(self):
        """Prepara una nova execució d'escaneig"""
        self.stop_event.clear()
        self.scan_in_progress = True
        self.txt.delete(1.0, END)
        self.append_text("-" * 50)

    # --- CRIDES D'ESCANEIG ---
    def start_ping_scan(self):
        """Inicia l'escaneig de ping"""
        if self.scan_in_progress:
            messagebox.showwarning("Escaneig en curs", "Ja hi ha un escaneig en curs. Atura'l primer.")
            return
        self._prepare_scan()
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Indica una xarxa/host al camp.")
            return
        self.execucions(self._do_ping_scan, target)

    def _do_ping_scan(self, target):
        self.append_text(f"[*] Iniciant Ping scan: {target}")
        self.append_text("[!] Prem 'Atura Escaneig' per cancel·lar")
        out = ping_scan(target, self.stop_event)
        return out

    def start_port_scan(self):
        """Inicia l'escaneig de ports"""
        if self.scan_in_progress:
            messagebox.showwarning("Escaneig en curs", "Ja hi ha un escaneig en curs. Atura'l primer.")
            return
        self._prepare_scan()
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Indica una IP/host.")
            return
        self.execucions(self._do_port_scan, target)

    def _do_port_scan(self, target):
        self.append_text(f"[*] Iniciant Port scan a: {target}")
        self.append_text("[!] Prem 'Atura Escaneig' per cancel·lar")
        out = port_scan(target, self.stop_event)
        return out

    def start_version_scan(self):
        """Inicia l'escaneig de versió"""
        if self.scan_in_progress:
            messagebox.showwarning("Escaneig en curs", "Ja hi ha un escaneig en curs. Atura'l primer.")
            return
        self._prepare_scan()
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Indica una IP/host.")
            return
        self.execucions(self._do_version_scan, target)

    def _do_version_scan(self, target):
        self.append_text(f"[*] Iniciant Version scan a: {target} ports: 1-1024")
        self.append_text("[!] Prem 'Atura Escaneig' per cancel·lar")
        out = version_scan(target, self.stop_event)
        return out

    # --- NOVES FUNCIONS ENUM4LINUX ---
    def start_enum4linux_scan(self):
        """Inicia l'enumeració SMB amb enum4linux"""
        if self.scan_in_progress:
            messagebox.showwarning("Escaneig en curs", "Ja hi ha un escaneig en curs. Atura'l primer.")
            return
        self._prepare_scan()
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Indica una IP o hostname del servidor.")
            return
        self.execucions(self._do_enum4linux_scan, target)

    def _do_enum4linux_scan(self, target):
        self.append_text(f"[*] Iniciant enumeració SMB (enum4linux) a: {target}")
        self.append_text("[!] Prem 'Atura Escaneig' per cancel·lar")
        out = enum4linux_scan(target, self.stop_event)
        return out
    # --- FI NOVES FUNCIONS ---

    def start_ssh_audit(self):
        """Inicia una auditoria SSH al servidor objectiu"""
        if self.scan_in_progress:
            messagebox.showwarning("Escaneig en curs", "Ja hi ha un escaneig en curs. Atura'l primer.")
            return
        self._prepare_scan()
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Indica una IP o hostname del servidor SSH.")
            return
        self.execucions(self._do_ssh_audit, target)

    def _do_ssh_audit(self, target):
        self.append_text(f"[*] Iniciant auditoria SSH a: {target}")
        self.append_text("[!] Prem 'Atura Escaneig' per cancel·lar")
        out = ssh_audit_scan(target, self.stop_event)
        return out

    # --- EXECUCIÓ I RESULTATS ---
    def execucions(self, func, *args):
        def task():
            try:
                output = func(*args)
                self.scan_in_progress = False
                
                if self.stop_event.is_set():
                    self.append_text("[!] ⏹ Escaneig ATURAT per l'usuari")
                elif output:
                    self.append_text(output)
                    self.append_text("[✓] Escaneig COMPLETAT")
                else:
                    self.append_text("[!] Sense sortida o error desconegut.")
            except Exception as e:
                self.scan_in_progress = False
                self.append_text(f"[ERROR] {e}")

        t = threading.Thread(target=task)
        t.daemon = True
        t.start()

    def peticio_stop_auditoria(self):
        if self.scan_in_progress:
            self.append_text("[!] Sol·licitant aturada...")
            self.stop_event.set()
            global current_process
            if current_process:
                try:
                    current_process.terminate()
                except:
                    pass
        else:
            self.append_text("[!] No hi ha cap escaneig en curs")

# ---------- Main ----------
def main():
    root = Tk()
    app = AuditorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()