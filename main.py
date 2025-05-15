import argparse
import logging
import time
import sys
import os
from scapy.layers.inet import IP

# from modules.arp_spoofer import ARPSpoofer
from modules.dns_spoofer import DNSSpoofer
# from modules.ssl_stripper import SSLStripper
from utils.network_scanner import NetworkScanner
from utils.packet_handler import PacketHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('FarfallePoisoner')


try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Dummy:
        def __getattr__(self, name): return ""
    Fore = Style = Dummy()


class FarfallePoisoner:
    """Main class/Entry point"""

    def __init__(self):
        self.args = self._parse_arguments()
        self.interface = self.args.interface
        self.target_ip = self.args.target
        self.gateway_ip = self.args.gateway
        self.mode = self.args.mode
        self.verbose = self.args.verbose

        # Set verbosity level
        if self.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        # Initialize components
        self.scanner = NetworkScanner(self.interface)
        self.packet_handler = PacketHandler(self.interface, self.gateway_ip)

        if self.verbose:
            targets = {
                '18.158.249.75',
                '3.125.209.94',
            }

            def log_all_packets(packet):
                if IP in packet and (packet[IP].dst in targets or packet[IP].src in targets):
                    src = packet[IP].src
                    dst = packet[IP].dst
                    proto = packet[IP].proto
                    logger.info(f"Packet: {src} -> {dst} (proto={proto})")

                return False

            self.packet_handler.add_filter(log_all_packets)

        # Initialize attack module
        self.arp_spoofer = None
        self.dns_spoofer = None
        self.ssl_stripper = None

        if self.mode in ['arp', 'all']:
            self.arp_spoofer = ARPSpoofer(
                interface=self.interface,
                target_ip=self.target_ip,
                gateway_ip=self.gateway_ip,
                packet_handler=self.packet_handler
            )

        if self.mode in ['dns', 'all']:
            self.dns_spoofer = DNSSpoofer(
                interface=self.interface,
                target_ip=self.target_ip,
                dns_mapping=self.args.dns_mapping,
                packet_handler=self.packet_handler
            )

        if self.mode in ['ssl', 'all']:
            self.ssl_stripper = SSLStripper(
                interface=self.interface,
                packet_handler=self.packet_handler
            )

    def _parse_arguments(self):
        """Parse command line args. terminal app for now but maybe we can do a quick flask app if we have timeee"""
        parser = argparse.ArgumentParser(
            description='Farfalle poisoning tool for ARP, DNS, and SSL',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )

        parser.add_argument('-i', '--interface', required=True,
                            help='Network interface to use')
        parser.add_argument('-t', '--target', required=True,
                            help='Target IP address')
        parser.add_argument('-g', '--gateway', required=True,
                            help='Gateway IP address')
        parser.add_argument('-m', '--mode', default='all',
                            choices=['arp', 'dns', 'ssl', 'all'],
                            help='Attack mode')
        parser.add_argument('-d', '--dns-mapping', default={},
                            help='DNS mapping (e.g., "example.com:10.0.0.1,google.com:10.0.0.1")')
        parser.add_argument('-v', '--verbose', action='store_true',
                            help='Enable verbose output')
        parser.add_argument('--silent', action='store_true',
                            help='Minimize output (only errors)')

        return parser.parse_args()

    def start(self):
        """Start the attack based on selected mode"""
        logger.info(f"Starting network poisoning in {self.mode} mode")

        try:
            self._enable_ip_forwarding()
            self.packet_handler.start()

            if self.arp_spoofer:
                self.arp_spoofer.start()
                logger.info("ARP spoofing active")

            if self.dns_spoofer:
                self.dns_spoofer.start()
                logger.info("DNS spoofing active")

            if self.ssl_stripper:
                self.ssl_stripper.start()
                logger.info("SSL stripping active")

            logger.info("Bon Apetit. Press Ctrl+C to stop..........")

            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("Thatll be 20 euros.")
        finally:
            self.stop()

    def stop(self):
        """smetilaaaa"""
        logger.info("Cleaning up...")

        if self.ssl_stripper:
            self.ssl_stripper.stop()

        if self.dns_spoofer:
            self.dns_spoofer.stop()

        if self.arp_spoofer:
            self.arp_spoofer.stop()

        self._disable_ip_forwarding()
        self.packet_handler.stop()

        logger.info("欢迎下次光临")

    def _enable_ip_forwarding(self):
        """Enable IP forwarding based on platform"""
        if sys.platform == "linux" or sys.platform == "linux2":
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        elif sys.platform == "darwin":
            os.system("sudo sysctl -w net.inet.ip.forwarding=1")
        else:
            logger.warning(
                f"IP forwarding not automatically configured for {sys.platform}. May have to configure manually :(")

    def _disable_ip_forwarding(self):
        """Disable IP forwarding based on platform"""
        if sys.platform == "linux" or sys.platform == "linux2":
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        elif sys.platform == "darwin":
            os.system("sudo sysctl -w net.inet.ip.forwarding=0")


def heading():
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

    print(Fore.GREEN + logo)
    print(Fore.YELLOW + "WELCOMe TO THE                🍝🦋 Farfalle Poisoner 🦋🍝            OMNYONYONYONM\n" + Style.RESET_ALL)


if __name__ == "__main__":
    heading()
    farfalle = FarfallePoisoner()
    farfalle.start()
