import pytest

from netdoctor.validate import (
    ValidationError,
    validate_host,
    validate_int,
    validate_port,
    validate_record_type,
)


@pytest.mark.parametrize(
    "host, expected",
    [
        ("example.com", "example.com"),
        ("Example.COM.", "example.com"),
        ("  one.one.one.one ", "one.one.one.one"),
        ("192.168.1.1", "192.168.1.1"),
        ("8.8.8.8", "8.8.8.8"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111"),
        ("localhost", "localhost"),
        ("my-router", "my-router"),
        ("2.pool.ntp.org", "2.pool.ntp.org"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("::ffff:192.168.1.1", "192.168.1.1"),  # one spelling per machine
    ],
)
def test_accepts_single_hosts(host, expected):
    assert validate_host(host) == expected


@pytest.mark.parametrize(
    "host",
    [
        "",
        "   ",
        "-n",
        "--help",
        "-t example.com",
        "example.com -t",
        "example.com,example.org",
        "example.com example.org",
        "example.com;whoami",
        "example.com|calc",
        "example.com&&calc",
        "$(whoami)",
        "`whoami`",
        "192.168.1.0/24",
        "10.0.0.1-50",
        "10.0.0.*",
        "*.example.com",
        "999.1.1.1",
        "a" * 254,
        "bad_label.com",
        "-bad.com",
        "bad-.com",
        "a..b",
        "224.0.0.1",
        "ff02::1",
        "0.0.0.0",
        "::",
        "255.255.255.255",
        "192.168.1.255",
        "[::1]",
        "example.com\nexample.org",
        # numeric shorthand that resolvers read as IP addresses (security review)
        "0xffffffff",
        "0xe0000001",
        "0x7f.0x1",
        "0177.1.x",
        "127.1.a",
        "127.1",
        "1e3",
        "2130706433",
        # IPv4-mapped broadcast / multicast
        "::ffff:255.255.255.255",
        "::ffff:224.0.0.1",
        # IPv6 zone IDs
        "fe80::1%eth0",
        "fe80::1%-h",
        "fe80::1%a\x0bb",
        "fe80::1%a\x00b",
        # non-ASCII look-alikes
        "exаmple.com",  # Cyrillic 'а'
        "example.com​",
    ],
)
def test_rejects_lists_ranges_flags_and_mass_addresses(host):
    with pytest.raises(ValidationError):
        validate_host(host)


@pytest.mark.parametrize("bad", [None, 123, ["example.com"], ("a", "b"), {"host": "x"}])
def test_rejects_non_strings(bad):
    with pytest.raises(ValidationError):
        validate_host(bad)


@pytest.mark.parametrize("port", [1, 22, 443, 65535])
def test_accepts_one_port(port):
    assert validate_port(port) == port


@pytest.mark.parametrize(
    "port", [0, -1, 65536, "443", "1-1024", "80,443", [80, 443], range(1, 10), 80.0, True, None]
)
def test_rejects_port_ranges_lists_and_non_ints(port):
    with pytest.raises(ValidationError):
        validate_port(port)


def test_validate_int_bounds():
    assert validate_int(5, "count", 1, 10) == 5
    for bad in (0, 11, "5", True, 2.5):
        with pytest.raises(ValidationError):
            validate_int(bad, "count", 1, 10)


def test_record_types():
    assert validate_record_type("mx") == "MX"
    for bad in ("ANY", "AXFR", "PTR", "", None, "A AAAA"):
        with pytest.raises(ValidationError):
            validate_record_type(bad)
