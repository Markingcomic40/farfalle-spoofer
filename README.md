# 🦋 Farfalle Poisoner 🍝

**Farfalle Poisoner** is a modular network spoofing toolkit that supports ARP, DNS, SSL stripping, and NDP (work in progress) poisoning attacks.

---

## Installation

**Requirements:**

- Python 3.8+
- `scapy`, `colorama`, and other dependencies (listed in `requirements.txt`)

### 1. Clone the repo

```bash
git clone https://github.com/Markgincomic40/farfalle-spoofer.git
cd farfalle-spoofer
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> NOTE It's recommended to use a virtual environment.

---

## Launching Farfalle

### CLI Mode (Recommended for advanced users)

```bash
python main.py -i <interface> -t <target(s)> -g <gateway> -m <mode>
```

#### Example:

```bash
python main.py -i en0 -t 192.168.1.5,192.168.1.6 -g 192.168.1.1 -m all --verbose
```

- `-i`: Interface (e.g., eth0, en0)
- `-t`: Target IP(s) or subnet (comma-separated or CIDR)
- `-g`: Gateway IP
- `-m`: Mode (`arp`, `dns`, `ssl`, `all`)
- `--dns-domains`: (Optional) Spoof specific domains
- `--scan`: (Optional) Run network scan before attack
- `--scan-ports`: (Optional) Include port scanning
- `--detect-os`: (Optional) Attempt OS detection
- `--verbose`: Enable debug logs
- `--silent`: Silence all output except errors

### GUI Mode

To launch the GUI (if implemented):

```bash
python launcher.py --gui
```

### Launcher (CLI + GUI wrapper)

```bash
python launcher.py [options]
```

If no arguments are passed, usage instructions will be printed.

---

## Examples

### Scan the network:

```bash
python main.py -i en0 --scan --scan-range 192.168.1.0/24 --scan-ports --detect-os
```

### Poison a subnet:

```bash
python main.py -i en0 -t 192.168.1.0/24 -g 192.168.1.1 -m arp
```

### DNS spoof with SSL stripping:

```bash
python main.py -i en0 -t 192.168.1.5 -g 192.168.1.1 -m all --dns-domains example.com github.com
```

---

## Disclaimer

This tool is intended **for educational and authorized testing purposes only**. Unauthorized use against networks you don't own or control may be **illegal**.

---

## Project Structure

```bash
farfalle-spoofer/
├── main.py             # Core CLI logic
├── launcher.py         # CLI/GUI launcher
├── gui.py              # Optional GUI launcher
├── modules/            # Spoofers (ARP, DNS, NDP, SSL)
├── utils/              # Packet handler, network scanner, helpers
├── requirements.txt    # Required Python packages
├── demo/               # Example HTTPS MITM demo
```

---

## 🍝🦋

Buon appetito, and happy spoofing B)
