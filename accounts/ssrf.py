"""SSRF protection helper.

The application currently makes NO server-side outbound HTTP requests, so the
SSRF attack surface is zero. This helper exists so that if one is ever added,
the target host must be validated against ``settings.OUTBOUND_HTTP_ALLOWLIST``
rather than taking a user-supplied URL directly.
"""
import ipaddress
import socket
from urllib.parse import urlparse

from django.conf import settings


class DisallowedOutboundURL(Exception):
    pass


def validate_outbound_url(url: str) -> str:
    """Return the URL if it is safe to fetch server-side, else raise.

    Enforces: https only, host on the configured allowlist, and resolved IPs
    that are not private/loopback/link-local (blocks DNS-rebinding to internal
    services)."""
    allowlist = set(settings.OUTBOUND_HTTP_ALLOWLIST)
    if not allowlist:
        raise DisallowedOutboundURL("No outbound hosts are allowlisted.")

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise DisallowedOutboundURL("Only https outbound requests are allowed.")
    if parsed.hostname not in allowlist:
        raise DisallowedOutboundURL(f"Host {parsed.hostname!r} is not allowlisted.")

    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    except socket.gaierror as exc:
        raise DisallowedOutboundURL("Host could not be resolved.") from exc

    for *_, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise DisallowedOutboundURL("Resolved IP is in a disallowed range.")

    return url
