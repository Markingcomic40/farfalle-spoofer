#!/usr/bin/env python3
"""
Farfalle Poisoner Launcher
"""

import sys

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        from gui import main as gui_main
        gui_main()
    elif len(sys.argv) > 1:
        from main import FarfallePoisoner, print_banner
        print_banner()
        poisoner = FarfallePoisoner()
        poisoner.start()
    else:
        print("🍝 Farfalle Poisoner")
        print("Usage:")
        print("  python launcher.py --gui          # Launch GUI")
        print("  python launcher.py [options]      # Launch CLI")
        print("  python main.py [options]          # Direct CLI")

if __name__ == "__main__":
    main()