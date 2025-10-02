import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tools.password_check import check_password_strength
from tools.port_scan import scan_ports
from tools.log_analyzer import analyze_logs
from tools.hash_crack import crack_hash
from tools.phishing_check import analyze_url
import asyncio
import threading

class CyberToolsGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('CyberTools GUI')
        self.root.geometry('800x600')
        self.create_widgets()

    def create_widgets(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True, padx=8, pady=8)

        # Password tab
        pw_frame = ttk.Frame(nb)
        nb.add(pw_frame, text='Password')
        ttk.Label(pw_frame, text='Password to check:').pack(anchor='w')
        self.pw_entry = ttk.Entry(pw_frame, show='*', width=60)
        self.pw_entry.pack(anchor='w', pady=4)
        ttk.Button(pw_frame, text='Check', command=self.on_check_password).pack()
        self.pw_out = scrolledtext.ScrolledText(pw_frame, height=8)
        self.pw_out.pack(fill='x', pady=6)

        # Port scan tab
        ps_frame = ttk.Frame(nb)
        nb.add(ps_frame, text='Port Scan')
        ttk.Label(ps_frame, text='Host (IP or domain):').pack(anchor='w')
        self.ps_host = ttk.Entry(ps_frame, width=40)
        self.ps_host.pack(anchor='w')
        ports_frame = ttk.Frame(ps_frame)
        ports_frame.pack(anchor='w', pady=4)
        ttk.Label(ports_frame, text='Start:').pack(side='left')
        self.ps_start = ttk.Entry(ports_frame, width=6)
        self.ps_start.insert(0, '1')
        self.ps_start.pack(side='left', padx=4)
        ttk.Label(ports_frame, text='End:').pack(side='left')
        self.ps_end = ttk.Entry(ports_frame, width=6)
        self.ps_end.insert(0, '1024')
        self.ps_end.pack(side='left', padx=4)
        ttk.Button(ps_frame, text='Scan', command=self.on_scan_ports).pack(pady=4)
        self.ps_out = scrolledtext.ScrolledText(ps_frame, height=12)
        self.ps_out.pack(fill='both', expand=True)

        # Log analyze tab
        la_frame = ttk.Frame(nb)
        nb.add(la_frame, text='Log Analyzer')
        ttk.Button(la_frame, text='Open Log File', command=self.on_open_log).pack(anchor='w')
        self.la_out = scrolledtext.ScrolledText(la_frame, height=18)
        self.la_out.pack(fill='both', expand=True, pady=6)

        # Hash crack tab
        hc_frame = ttk.Frame(nb)
        nb.add(hc_frame, text='Hash Crack')
        ttk.Label(hc_frame, text='Hash (hex):').pack(anchor='w')
        self.hc_hash = ttk.Entry(hc_frame, width=60)
        self.hc_hash.pack(anchor='w')
        ttk.Button(hc_frame, text='Open Dictionary & Crack', command=self.on_hash_crack).pack(pady=6)
        self.hc_out = scrolledtext.ScrolledText(hc_frame, height=10)
        self.hc_out.pack(fill='both', expand=True)

        # Phishing tab
        ph_frame = ttk.Frame(nb)
        nb.add(ph_frame, text='Phishing Check')
        ttk.Label(ph_frame, text='URL:').pack(anchor='w')
        self.ph_url = ttk.Entry(ph_frame, width=80)
        self.ph_url.pack(anchor='w')
        ttk.Button(ph_frame, text='Analyze', command=self.on_phishing_check).pack(pady=4)
        self.ph_out = scrolledtext.ScrolledText(ph_frame, height=12)
        self.ph_out.pack(fill='both', expand=True)

    def run(self):
        self.root.mainloop()

    def on_check_password(self):
        pw = self.pw_entry.get().strip()
        if not pw:
            messagebox.showinfo('Info', 'Enter a password first')
            return
        res = check_password_strength(pw)
        self.pw_out.delete('1.0', tk.END)
        self.pw_out.insert(tk.END, f"Verdict: {res['verdict']}\n")
        self.pw_out.insert(tk.END, f"Score: {res['score']}\n")
        if res['issues']:
            self.pw_out.insert(tk.END, 'Issues:\n')
            for it in res['issues']:
                self.pw_out.insert(tk.END, f' - {it}\n')

    def on_scan_ports(self):
        host = self.ps_host.get().strip()
        try:
            start = int(self.ps_start.get())
            end = int(self.ps_end.get())
        except ValueError:
            messagebox.showerror('Error', 'Start and End must be integers')
            return
        if not host:
            messagebox.showerror('Error', 'Enter host')
            return
        self.ps_out.delete('1.0', tk.END)
        self.ps_out.insert(tk.END, f'Starting scan {host} {start}-{end}\n')

        def worker():
            try:
                ports = list(range(start, end+1))
                open_ports = asyncio.run(scan_ports(host, ports, concurrency=200, timeout=0.8))
                self.ps_out.insert(tk.END, f'Open ports: {open_ports}\n')
            except Exception as e:
                self.ps_out.insert(tk.END, f'Error: {e}\n')

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def on_open_log(self):
        path = filedialog.askopenfilename(title='Select log file')
        if not path:
            return
        self.la_out.delete('1.0', tk.END)
        self.la_out.insert(tk.END, f'Analyzing {path}...\n')
        try:
            out = analyze_logs(path)
            summary = out['summary']
            self.la_out.insert(tk.END, f"Total lines: {summary['total_lines']}\n")
            self.la_out.insert(tk.END, 'Status counts sample:\n')
            for st, cnt in list(summary['status_counts'].items())[:10]:
                self.la_out.insert(tk.END, f' {st}: {cnt}\n')
            if summary['suspicious_ips']:
                self.la_out.insert(tk.END, 'Suspicious textual matches:\n')
                for ip, cnt in summary['suspicious_ips'].items():
                    self.la_out.insert(tk.END, f' {ip}: {cnt}\n')
            if out['brute_candidates']:
                self.la_out.insert(tk.END, 'Brute-force candidates:\n')
                for ip, hits in out['brute_candidates'].items():
                    self.la_out.insert(tk.END, f' {ip}: {hits}\n')
            else:
                self.la_out.insert(tk.END, 'No brute-force candidates found.\n')
        except FileNotFoundError:
            messagebox.showerror('Error', 'File not found')
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def on_hash_crack(self):
        target = self.hc_hash.get().strip().lower()
        if not target:
            messagebox.showerror('Error', 'Enter target hash')
            return
        path = filedialog.askopenfilename(title='Select dictionary file')
        if not path:
            return
        self.hc_out.delete('1.0', tk.END)
        self.hc_out.insert(tk.END, f'Cracking {target} using {path}...\n')

        def worker():
            try:
                matches = crack_hash(target, path, algo='md5', stop_on_first=True)
                if matches:
                    self.hc_out.insert(tk.END, f'Found: {matches}\n')
                else:
                    self.hc_out.insert(tk.END, 'No matches found.\n')
            except FileNotFoundError:
                self.hc_out.insert(tk.END, 'Dictionary file not found.\n')
            except Exception as e:
                self.hc_out.insert(tk.END, f'Error: {e}\n')

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def on_phishing_check(self):
        url = self.ph_url.get().strip()
        if not url:
            messagebox.showerror('Error', 'Enter URL')
            return
        res = analyze_url(url)
        self.ph_out.delete('1.0', tk.END)
        if not res.get('valid'):
            self.ph_out.insert(tk.END, 'Invalid URL or parse error.\n')
            for it in res.get('issues', []):
                self.ph_out.insert(tk.END, f' - {it}\n')
            return
        self.ph_out.insert(tk.END, f"Host: {res.get('host')}\n")
        self.ph_out.insert(tk.END, f"Verdict: {res.get('verdict')}\n")
        if res.get('issues'):
            self.ph_out.insert(tk.END, 'Issues:\n')
            for it in res.get('issues'):
                self.ph_out.insert(tk.END, f' - {it}\n')
