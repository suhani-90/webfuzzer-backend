"""
app/utils/url_validator.py
───────────────────────────
URL validation and SSRF (Server-Side Request Forgery) prevention.
Blocks private IP ranges and dangerous schemes from being used as scan targets.
"""

import ipaddress
import socket
from typing import Tuple
from urllib.parse import urlparse

from app.core.logging import get_logger

logger = get_logger(__name__)

# Private and reserved IP ranges to block (SSRF prevention)
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("::1/128"),  # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 ULA
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("0.0.0.0/8"),  # Unspecified
    ipaddress.ip_network("100.64.0.0/10"),  # Shared address space
    ipaddress.ip_network("192.0.2.0/24"),  # Documentation
    ipaddress.ip_network("198.51.100.0/24"),  # Documentation
    ipaddress.ip_network("203.0.113.0/24"),  # Documentation
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
]

# Blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",  # AWS metadata
    "instance-data",  # AWS
    "metadata",  # GCP
}

# Only these URL schemes are allowed
ALLOWED_SCHEMES = {"http", "https"}


class URLValidator:
    """
    Validates scan target URLs against security rules.
    Prevents SSRF attacks that could target internal infrastructure.
    """

    def validate(self, url: str) -> Tuple[bool, str]:
        """
        Validate a URL for use as a fuzzing target.

        Returns:
            (is_valid: bool, reason: str)
        """
        if not url:
            return False, "URL cannot be empty."

        try:
            parsed = urlparse(url)
        except Exception:
            return False, "Malformed URL."

        # ── Scheme check ───────────────────────────────────────────────────────
        if parsed.scheme not in ALLOWED_SCHEMES:
            return (
                False,
                f"URL scheme '{parsed.scheme}' is not allowed. Use http or https.",
            )

        # ── Hostname presence ──────────────────────────────────────────────────
        hostname = parsed.hostname
        if not hostname:
            return False, "URL must have a valid hostname."

        # ── Blocked hostnames ──────────────────────────────────────────────────
        if hostname.lower() in BLOCKED_HOSTNAMES:
            logger.warning("url_validator.blocked_hostname", hostname=hostname)
            return False, f"Hostname '{hostname}' is not permitted as a scan target."

        # ── Resolve hostname and check IP ──────────────────────────────────────
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_addr = ipaddress.ip_address(ip_str)
        except socket.gaierror:
            return False, f"Cannot resolve hostname '{hostname}'."
        except ValueError:
            return False, "Invalid IP address resolved."

        for network in BLOCKED_IP_NETWORKS:
            if ip_addr in network:
                logger.warning(
                    "url_validator.private_ip_blocked",
                    hostname=hostname,
                    ip=ip_str,
                    network=str(network),
                )
                return False, (
                    f"Scanning private/internal IP addresses is not permitted "
                    f"(resolved to {ip_str})."
                )

        # ── Port check ─────────────────────────────────────────────────────────
        port = parsed.port
        if port is not None:
            if port < 1 or port > 65535:
                return False, f"Invalid port number: {port}."
            # Block common internal service ports
            dangerous_ports = {22, 23, 25, 110, 143, 3306, 5432, 6379, 27017}
            if port in dangerous_ports:
                return False, f"Port {port} is not permitted as a scan target."

        return True, "URL is valid."

    def sanitise(self, url: str) -> str:
        """
        Strip fragments and normalise the URL for consistent use.
        """
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl().rstrip("/")


# Module-level singleton
url_validator = URLValidator()
