"""Input validation. Every value a tool receives passes through here first.

The rules are strict on purpose: exactly one host, exactly one port, and
nothing that a command-line program could read as an option.
"""

from __future__ import annotations

import ipaddress
import re

MAX_HOST_LENGTH = 253
_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_TLD = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


class ValidationError(ValueError):
    """Raised when an input is rejected. The message is safe to show the user."""


def validate_host(value: object) -> str:
    """Return a single hostname or IP address, or raise ValidationError.

    Rejected on purpose: lists, ranges, CIDR blocks, wildcards, spaces,
    anything starting with '-', and broadcast / multicast / unspecified
    addresses (which would reach many machines at once).
    """
    if not isinstance(value, str):
        raise ValidationError("host must be a string")
    host = value.strip()
    if not host:
        raise ValidationError("host is empty")
    if len(host) > MAX_HOST_LENGTH:
        raise ValidationError("host is too long")
    if host.startswith("-"):
        raise ValidationError("host must not start with '-'")
    if not host.isascii() or not host.isprintable():
        raise ValidationError("host must be plain ASCII (use the punycode form for international names)")
    if any(ch in host for ch in " \t\r\n,;/*?|&<>()[]{}'\"`$\\!%#@=+~^"):
        raise ValidationError(
            "host must be exactly one hostname or IP address "
            "(no lists, ranges, CIDR blocks, wildcards or IPv6 zone IDs)"
        )

    ip = _parse_ip(host)
    if ip is not None:
        ip = normalize_ip(ip)
        reject_mass_address(ip)
        return str(ip)

    if ":" in host:
        raise ValidationError("not a valid IP address or hostname")
    name = host[:-1] if host.endswith(".") else host
    labels = name.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise ValidationError("not a valid hostname")
    if not _TLD.match(labels[-1]) or (len(labels) > 1 and len(labels[-1]) < 2):
        # Blocks numeric shorthand that system resolvers read as IP addresses
        # (0xffffffff, 0x7f.0x1, 127.1, 1e3, 10.0.0.1-50 ...). Real top-level
        # domains start with a letter and are at least two characters long.
        raise ValidationError(
            "not a valid hostname or IP address (numeric shorthand and ranges are not allowed)"
        )
    return name.lower()


def normalize_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Unwrap IPv4-mapped IPv6 (::ffff:1.2.3.4) so one machine has one spelling."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def reject_mass_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Refuse addresses that reach many machines at once."""
    ip = normalize_ip(ip)
    if ip.is_multicast:
        raise ValidationError("multicast addresses are not allowed")
    if ip.is_unspecified:
        raise ValidationError("unspecified address (0.0.0.0 / ::) is not allowed")
    if isinstance(ip, ipaddress.IPv4Address):
        if ip == ipaddress.IPv4Address("255.255.255.255") or ip.packed[-1] == 255:
            raise ValidationError(
                "addresses ending in .255 are usually broadcast addresses and are not allowed"
            )


def validate_port(value: object) -> int:
    """Return exactly one TCP port (1-65535), or raise ValidationError."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("port must be a single whole number (no ranges or lists)")
    if not 1 <= value <= 65535:
        raise ValidationError("port must be between 1 and 65535")
    return value


def validate_int(value: object, name: str, low: int, high: int) -> int:
    """Return an int within [low, high], or raise ValidationError."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be a whole number")
    if not low <= value <= high:
        raise ValidationError(f"{name} must be between {low} and {high}")
    return value


def validate_record_type(value: object) -> str:
    """Return one of the supported DNS record types, upper-cased."""
    if not isinstance(value, str) or value.strip().upper() not in DNS_RECORD_TYPES:
        raise ValidationError(f"record_type must be one of: {', '.join(DNS_RECORD_TYPES)}")
    return value.strip().upper()
