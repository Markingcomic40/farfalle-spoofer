import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import sys
import logging
import io
from datetime import datetime
import subprocess

from main import FarfallePoisoner

class LogCapture(logging.Handler):
    """Logging handler to capture logs in GUI"""
    def __init__(self, gui_logger):
        super().__init__()
        self.gui_logger = gui_logger
        
    def emit(self, record):
        try:
            msg = self.format(record)
            self.gui_logger(msg, record.levelname)
        except:
            pass

class FarfalleGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🍝 Farfalle Poisoner - Network Attack Tool")
        self.root.geometry("1000x800")
        
        # Application state
        self.poisoner = None
        self.attack_thread = None
        self.is_running = False
        
        # Setup logging capture
        self.setup_logging()
        
        # Create GUI components
        self.create_widgets()
        
        # Load network interfaces
        self.load_interfaces()
    
    def setup_logging(self):
        """Setup logging to capture all output in GUI"""
        # Create logging handler that sends logs to GUI
        self.log_handler = LogCapture(self.log_message_from_handler)
        self.log_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        self.log_handler.setFormatter(formatter)
        
        # Add to root logger
        logging.getLogger().addHandler(self.log_handler)
        
        # Also capture print statements by redirecting stdout
        self.original_stdout = sys.stdout
        sys.stdout = self.StdoutCapture(self.log_message_from_print)
    
    class StdoutCapture:
        """Capture print statements"""
        def __init__(self, gui_logger):
            self.gui_logger = gui_logger
            
        def write(self, text):
            if text.strip():  # Don't log empty lines
                self.gui_logger(text.strip())
                
        def flush(self):
            pass
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Banner and Title Section
        banner_frame = ttk.Frame(main_frame)
        banner_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))

        # Add the butterfly art
        banner_display = self.create_banner_display(banner_frame)
        banner_display.pack(fill=tk.X)

        # Network Configuration Section
        config_frame = ttk.LabelFrame(main_frame, text="Network Configuration", padding="10")
        config_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        
        # Interface field
        ttk.Label(config_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_entry = ttk.Entry(config_frame, textvariable=self.interface_var, width=40)
        self.interface_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        # Target(s) IP field
        ttk.Label(config_frame, text="Target(s) IP:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(config_frame, textvariable=self.target_var, width=40)
        self.target_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)

        
        # Gateway IP field
        ttk.Label(config_frame, text="Gateway IP:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.gateway_var = tk.StringVar()
        self.gateway_entry = ttk.Entry(config_frame, textvariable=self.gateway_var, width=40)
        self.gateway_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        # Network scan button for multiple targets
        scan_frame = ttk.Frame(config_frame)
        scan_frame.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=(10,0), pady=(10, 0))
        
        # Scan button
        self.scan_btn = ttk.Button(scan_frame, text="🔍 Scan Network", 
                                   command=self.scan_network)
        self.scan_btn.pack(side=tk.LEFT)
        
        # Scan results button
        self.scan_results_btn = ttk.Button(scan_frame, text = "📋 Show Hosts",
                                           command=self.show_scan_results, state="disabled")
        self.scan_results_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        # List to store discovered hosts
        self.discovered_hosts = []

        # Attack Configuration Section
        attack_frame = ttk.LabelFrame(main_frame, text="Attack Configuration", padding="10")
        attack_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        attack_frame.columnconfigure(1, weight=1)
        
        # Attack Mode Radio
        ttk.Label(attack_frame, text="Attack Mode:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.mode_var = tk.StringVar(value="dns")  # Default to DNS for testing
        mode_frame = ttk.Frame(attack_frame)
        mode_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        modes = [("ARP", "arp"), ("DNS", "dns"), ("SSL", "ssl"), ("All", "all")]
        for i, (text, value) in enumerate(modes):
            ttk.Radiobutton(mode_frame, text=text, variable=self.mode_var, 
                           value=value).grid(row=0, column=i, padx=(0, 15))
        
        # DNS Mapping with better input handling
        ttk.Label(attack_frame, text="DNS Mapping:").grid(row=1, column=0, sticky=tk.W, pady=5)
        dns_frame = ttk.Frame(attack_frame)
        dns_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        dns_frame.columnconfigure(0, weight=1)

        self.dns_var = tk.StringVar(value="github.com,example.com,httpbin.org")
        self.dns_entry = ttk.Entry(dns_frame, textvariable=self.dns_var, width=40)
        self.dns_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))

        # Button to use current host IP
        self.use_host_ip_btn = ttk.Button(dns_frame, text="Use Host IP", 
                                        command=self.set_host_ip_for_dns, width=12)
        self.use_host_ip_btn.grid(row=0, column=1, padx=(5, 0))

        # Help text
        dns_help = ttk.Label(attack_frame,
                            text="Domains to spoof (comma-separated). Leave empty for defaults.",
                            font=('Arial', 8), foreground='gray')
        dns_help.grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        # Options (verbose/silent/normal)
        options_frame = ttk.Frame(attack_frame)
        options_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=(10, 0))
        
        ttk.Label(options_frame, text="Output Level:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))

        self.output_var = tk.StringVar(value="normal")  # Default to normal
        output_frame = ttk.Frame(options_frame)
        output_frame.grid(row=0, column=1, sticky=tk.W)

        ttk.Radiobutton(output_frame, text="Verbose", variable=self.output_var, 
               value="verbose").grid(row=0, column=0, padx=(0, 10))
        ttk.Radiobutton(output_frame, text="Normal", variable=self.output_var, 
               value="normal").grid(row=0, column=1, padx=(0, 10))
        ttk.Radiobutton(output_frame, text="Silent", variable=self.output_var, 
               value="silent").grid(row=0, column=2)

        # Attack control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=3, column=0, columnspan=2, pady=(0, 10))
        
        self.start_btn = ttk.Button(control_frame, text="🚀 Start Attack", command=self.start_attack)
        self.start_btn.grid(row=0, column=0, padx=(0, 10))
        
        self.stop_btn = ttk.Button(control_frame, text="⏹️ Stop Attack", command=self.stop_attack, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=(0, 10))
        
        self.clear_btn = ttk.Button(control_frame, text="🗑️ Clear Log", command=self.clear_log)
        self.clear_btn.grid(row=0, column=2)
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Log Output
        log_frame = ttk.LabelFrame(main_frame, text="Output Log", padding="5")
        log_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, width=100, 
                                                 bg='white', fg='black')
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def create_banner_display(self, parent_frame):
        """Create a compact banner layout"""
        # Main banner container
        banner_container = ttk.Frame(parent_frame)
        
        # Luis' majestic butterfly
        left_frame = ttk.Frame(banner_container)
        left_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        compact_banner = r'''
          `     '
    ;,,    `   '    ,,;
    `Y8bo.  : :  .o8Y'
    8I8D8b. : : .d8D8I8
    LOVE `Yb.'.dY' EVOL
    8! .db. b d .db. !8
    `8 Y8Y `d' Y8Y 8'
      8b "  ','  " d8
    j8gf"' ':' "'fg8j
      'Y .8'd'b8. Y'
      ! .8'd;`b8. !
        88 8;8 88
        8Ib8'8dI8
      :8LY' 'YL8:
      '!88' '88!'
        8Y   Y8
    '''
    
        banner_widget = tk.Text(left_frame, height=17, width=25,
                           bg='black', fg='green',
                           font=('Courier', 6),
                           wrap=tk.NONE, state=tk.DISABLED,
                           cursor='arrow', relief=tk.FLAT)
    
        banner_widget.config(state=tk.NORMAL)
        banner_widget.insert(tk.END, compact_banner)
        banner_widget.config(state=tk.DISABLED)
        banner_widget.pack()
    
        # Title and info
        right_frame = ttk.Frame(banner_container)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
        # Main title
        title_label = ttk.Label(right_frame, text="🍝🦋 Farfalle Poisoner 🦋🍝", 
                           font=('Arial', 18, 'bold'))
        title_label.pack(anchor=tk.W, pady=(10, 5))
    
        # Subtitle
        subtitle_label = ttk.Label(right_frame, text="Network Attack & MITM Tool", 
                              font=('Arial', 12))
        subtitle_label.pack(anchor=tk.W, pady=(0, 5))
    
        # Features list
        features_label = ttk.Label(right_frame, 
                              text="• ARP Poisoning  • DNS Spoofing  • SSL Stripping",
                              font=('Arial', 9), foreground='gray')
        features_label.pack(anchor=tk.W, pady=(0, 5))
        
        ipv6_frame = ttk.Frame(right_frame)
        ipv6_frame.pack(anchor=tk.W, pady=(5, 0))

        self.ipv6_status_var = tk.StringVar(value="IPv6: Checking...")
        ipv6_label = ttk.Label(ipv6_frame, textvariable=self.ipv6_status_var,
                              font=('Arial', 8), foreground='blue')
        ipv6_label.pack(anchor=tk.W)

        return banner_container

    def load_interfaces(self):
        """Load available network interfaces with IPv6 detection"""
        try:
            import psutil
            
            interfaces = []
            for interface_name, addresses in psutil.net_if_addrs().items():
                if interface_name.lower() not in ['lo', 'loopback']:
                    has_ipv4 = any(addr.family == 2 for addr in addresses)
                    has_ipv6 = any(addr.family == 10 for addr in addresses)
                    
                    if has_ipv4:
                        suffix = " (IPv4+IPv6)" if has_ipv6 else " (IPv4)"
                        interfaces.append(interface_name + suffix)
            
            # Set default, kinda hardcoded sorry
            defaults = ["Ethernet 2", "eth0", "wlan0", "en0"]
            for default in defaults:
                matching = [iface for iface in interfaces if default in iface]
                if matching:
                    self.interface_var.set(matching[0].split(' (')[0])  # Remove suffix
                    break
            
            if not self.interface_var.get() and interfaces:
                self.interface_var.set(interfaces[0].split(' (')[0])
                
            # Check IPv6 support (idk if this'll work out)
            self.root.after(1000, self.check_ipv6_support)
            
        except Exception as e:
            self.log_message(f"Error loading interfaces: {e}", "ERROR")
            # Fallback to simple default
            self.interface_var.set("Ethernet 2")

    def set_host_ip_for_dns(self):
        """Set DNS mapping to use host IP"""
        try:
            import psutil
            interface_name = self.interface_var.get()
            
            for name, addrs in psutil.net_if_addrs().items():
                if name == interface_name:
                    for addr in addrs:
                        if addr.family == 2:  # IPv4
                            # Update DNS mapping to point to host IP
                            domains = self.dns_var.get().split(',')
                            mapped_domains = [f"{d.strip()}:{addr.address}" for d in domains if d.strip()]
                            self.dns_var.set(','.join(mapped_domains) if mapped_domains else f"github.com:{addr.address}")
                            self.log_message(f"DNS mapping set to host IP: {addr.address}")
                            return
            
            messagebox.showwarning("Warning", "Could not determine host IP for interface")
        except Exception as e:
            self.log_message(f"Error setting host IP: {e}", "ERROR")

    def scan_network(self):
        """Scan network for available hosts"""
        if not self.gateway_var.get():
            messagebox.showerror("Error", "Please enter gateway IP first")
            return
        
        self.scan_btn.config(state="disabled", text="⏳ Scanning...")
        self.log_message("Starting network scan...")

        def scan_thread():
            try:
                from utils.network_scanner import NetworkScanner
                
                interface = self.interface_var.get()
                gateway_ip = self.gateway_var.get()
                
                scanner = NetworkScanner(interface)
                # Determine network range from gateway IP
                gateway_parts = gateway_ip.split('.')
                network_range = f"{'.'.join(gateway_parts[:3])}.0/24"
                
                self.log_message(f"Scanning network {network_range}...")
                hosts = scanner.scan(network_range)
                
                self.discovered_hosts = hosts
                
                if hosts:
                    self.log_message(f"Found {len(hosts)} hosts:")
                    for host in hosts:
                        self.log_message(f"  {host['ip']:<15} - {host['mac']}")
                        
                    # Enable show results button
                    self.root.after(0, lambda: self.scan_results_btn.config(state="normal"))
                else:
                    self.log_message("No hosts found on network")
                    
            except Exception as e:
                self.log_message(f"Scan error: {e}", "ERROR")
            finally:
                self.root.after(0, lambda: self.scan_btn.config(state="normal", text="🔍 Scan Network"))
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def show_scan_results(self):
        """Show discovered hosts in a popup"""
        if not self.discovered_hosts:
            messagebox.showinfo("Scan Results", "No hosts discovered yet. Run a network scan first.")
            return
    
        # Create popup window
        popup = tk.Toplevel(self.root)
        popup.title("Discovered Hosts")
        popup.geometry("500x400")
        
        # Host list
        frame = ttk.Frame(popup, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Select targets (click to add to target field):", 
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0, 10))
        
        # Listbox with scrollbar
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox.yview)
    
        # Populate listbox
        for host in self.discovered_hosts:
            listbox.insert(tk.END, f"{host['ip']:<15} - {host['mac']}")
        
        def add_selected():
            selection = listbox.curselection()
            if selection:
                selected_ips = []
                for i in selection:
                    ip = self.discovered_hosts[i]['ip']
                    selected_ips.append(ip)
                
                # Add to target field
                current_targets = self.target_var.get()
                if current_targets:
                    new_targets = current_targets + "," + ",".join(selected_ips)
                else:
                    new_targets = ",".join(selected_ips)
                
                self.target_var.set(new_targets)
                popup.destroy()
        
        ttk.Button(frame, text="Add Selected to Targets", 
              command=add_selected).pack(pady=(10, 0))

    def check_ipv6_support(self):
        """Check if interface supports IPv6"""
        try:
            import psutil
            interface_name = self.interface_var.get()
            
            for name, addrs in psutil.net_if_addrs().items():
                if name == interface_name:
                    for addr in addrs:
                        if addr.family == 10:  # IPv6
                            self.ipv6_status_var.set("IPv6: ✓ Supported")
                            return
            
            self.ipv6_status_var.set("IPv6: ✗ Not available")
        except:
            self.ipv6_status_var.set("IPv6: ? Unknown")
        
    def log_message_from_handler(self, message, level="INFO"):
        """Handle log messages from logging handler"""
        self.log_message(message, level)
        
    def log_message_from_print(self, message):
        """Handle messages from print statements"""
        # Remove ANSI color codes for GUI display
        import re
        clean_message = re.sub(r'\x1b\[[0-9;]*m', '', message)
        self.log_message(clean_message, "PRINT")
        
    def start_attack(self):
        """Start the attack"""
        # Validate inputs
        if not self.interface_var.get():
            messagebox.showerror("Error", "Please enter network interface")
            return
        if not self.target_var.get():
            messagebox.showerror("Error", "Please enter target IP")
            return
        if not self.gateway_var.get():
            messagebox.showerror("Error", "Please enter gateway IP")
            return
            
        # Confirm attack
        if not messagebox.askyesno("Confirm Attack", 
                                  f"Start {self.mode_var.get().upper()} attack?\n\n"):
            return
        
        self.is_running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Attack running...")
        
        def attack_thread():
            try:
                # Build arguments
                args = [
                    "gui_mode",
                    "--interface", self.interface_var.get(),
                    "--target", self.target_var.get(),
                    "--gateway", self.gateway_var.get(),
                    "--mode", self.mode_var.get()
                ]
                
                if self.dns_var.get().strip():
                    domains = [d.strip() for d in self.dns_var.get().split(',') if d.strip()]
                    if domains:
                        args.extend(["--dns-domains"] + domains)
                        
                # Add network scan option if hosts were discovered
                if self.discovered_hosts:
                    args.append("--scan")
                    
                output_level = self.output_var.get()
                if output_level == "verbose":
                    args.append("--verbose")
                elif output_level == "silent":
                    args.append("--silent")
                # (Normal mode adds neither flag)
                
                # Override sys.argv
                original_argv = sys.argv[:]
                sys.argv = args
                
                try:
                    self.log_message("🍝 Starting Farfalle Poisoner...")
                    self.poisoner = FarfallePoisoner()
                    self.poisoner.start()
                except Exception as e:
                    self.log_message(f"Error: {e}", "ERROR")
                finally:
                    sys.argv = original_argv
                    
            except Exception as e:
                self.log_message(f"Failed to start: {e}", "ERROR")
            finally:
                self.root.after(0, self.attack_finished)
        
        self.attack_thread = threading.Thread(target=attack_thread, daemon=True)
        self.attack_thread.start()
    
    def stop_attack(self):
        """Stop the attack"""
        if self.poisoner:
            self.log_message("Stopping attack...")
            try:
                self.poisoner.stop()
            except Exception as e:
                self.log_message(f"Stop error: {e}", "ERROR")
        
        self.attack_finished()
    
    def attack_finished(self):
        """Reset UI after attack ends"""
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Ready")
        self.is_running = False
        self.poisoner = None
        self.log_message("Attack stopped")
    
    def clear_log(self):
        """Clear the log"""
        self.log_text.delete(1.0, tk.END)
    
    def log_message(self, message, level="INFO"):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {level}: {message}\n"
        
        self.root.after(0, lambda: [
            self.log_text.insert(tk.END, formatted),
            self.log_text.see(tk.END)
        ])
    
    def on_closing(self):
        """Handle window closing"""
        # Restore stdout
        sys.stdout = self.original_stdout
        
        if self.is_running:
            if messagebox.askyesno("Exit", "Attack running. Stop and exit?"):
                self.stop_attack()
                self.root.after(1000, self.root.destroy)
            return
        self.root.destroy()

def main():
    """Launch GUI"""
    root = tk.Tk()
    root.attributes('-topmost', True)
    root.after_idle(root.attributes, '-topmost', False)
    root.focus_force()
    app = FarfalleGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    print("🍝 Farfalle Poisoner GUI")

    
    root.mainloop()

if __name__ == "__main__":
    main()