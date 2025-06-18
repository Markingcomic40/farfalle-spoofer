import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import sys
import logging
import io
from datetime import datetime
import subprocess

# Import your main application
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
        
        # Target IP field
        ttk.Label(config_frame, text="Target IP:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(config_frame, textvariable=self.target_var, width=40)
        self.target_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        # Gateway IP field
        ttk.Label(config_frame, text="Gateway IP:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.gateway_var = tk.StringVar()
        self.gateway_entry = ttk.Entry(config_frame, textvariable=self.gateway_var, width=40)
        self.gateway_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
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
        
        # DNS Mapping
        ttk.Label(attack_frame, text="DNS Mapping:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.dns_var = tk.StringVar(value="github.com:192.168.56.1")  # Set for your test
        self.dns_entry = ttk.Entry(attack_frame, textvariable=self.dns_var, width=40)
        self.dns_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        # Options (verbose/silent)
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

        # Control Buttons
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
        
        # Left side - Compact butterfly (smaller)
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
    
        # Right side - Title and info
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
    
        # Feature list
        features_label = ttk.Label(right_frame, 
                              text="• ARP Poisoning  • DNS Spoofing  • SSL Stripping",
                              font=('Arial', 9), foreground='gray')
        features_label.pack(anchor=tk.W, pady=(0, 5))
    
        return banner_container

    def load_interfaces(self):
        """Load common interface names"""
        # Set defaults for your test setup
        self.interface_var.set("Ethernet 2")
        
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
                
                if self.dns_var.get():
                    args.extend(["--dns-mapping", self.dns_var.get()])
                    
                output_level = self.output_var.get()
                if output_level == "verbose":
                    args.append("--verbose")
                elif output_level == "silent":
                    args.append("--silent")
                # Normal mode adds neither flag
                
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