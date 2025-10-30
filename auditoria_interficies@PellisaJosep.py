#!/usr/bin/env python3
"""
Eina d'auditoria simple amb GUI (Tkinter), escaneig amb nmap
"""

import threading
import subprocess
import sys
import os
import time
from tkinter import (
    Tk, Frame, Label, Button, Entry, Text, Scrollbar, StringVar, OptionMenu, END, messagebox
)

# ---------- FUNCIONS D'EXECUCIÓ AUDITORIA ----------

# FUNCIO PER ATURAR PROCESSOS
current_process = None
def run_nmap_stoppable(args_list, stop_event):
        global current_process
        cmd = ["nmap"] + args_list
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
        except Exception as e:
            return "", f"Error: {e}", 1
        finally:
            current_process = None

# FUNCIONS D'ESCANEIG 
def ping_scan(target, stop_event=None):
    """Escaneig de ping bàsic"""
    if stop_event:
        stdout, stderr, rc = run_nmap_stoppable([target, "-sn"], stop_event)
    else:
        return f"Error executant ping scan:"
    return stdout or stderr

def port_scan(target, stop_event=None):
    """Escaneig de ports bàsic - VERSIÓ CORREGIDA"""
    if stop_event:
        stdout, stderr, rc = run_nmap_stoppable([target, "-sT", "--top-ports", "100"], stop_event)
    else:
        return f"Error executant port scan:"
    return stdout or stderr

def version_scan(target, stop_event=None):
    """Escaneig de versió"""
    if stop_event:
        stdout, stderr, rc = run_nmap_stoppable([target, "-sV", "--top-ports", "100"], stop_event)
    else:
        return f"Error executant version scan:"
    return stdout or stderr

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

# PREPARACIÓ DE L'ENTORN D'ESCANEIG
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

# CRIDES D'ESCANEIG A LA GUI #

# CRIDA HOSTS DE XARXA
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

# CRIDA PORTS OBERTS
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

# CRIDA SERVEIS AMB VERSIÓ
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

# ESTAT I RESULTATS
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

# CRIDA PETICIÓ D'ATURADA
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









