import pytest

from netdoctor.ratelimit import RateLimited, RateLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def limiter(clock):
    return RateLimiter(clock=clock)


def port_check(limiter, ip, port):
    limiter.acquire("check_port")
    limiter.acquire_port(ip, port)


def test_min_interval_between_calls(limiter, clock):
    limiter.acquire("ping")
    with pytest.raises(RateLimited) as err:
        limiter.acquire("ping")
    assert 0 < err.value.retry_after <= 1.0
    clock.advance(1.0)
    limiter.acquire("dns_lookup")


def test_rejected_call_is_not_counted(limiter, clock):
    limiter.acquire("ping")
    for _ in range(5):
        with pytest.raises(RateLimited):
            limiter.acquire("ping")
    clock.advance(1.0)
    limiter.acquire("ping")  # rejected attempts did not push the window


def test_per_minute_cap(limiter, clock):
    for _ in range(20):
        limiter.acquire("ping")
        clock.advance(1.0)
    with pytest.raises(RateLimited, match="20 checks per minute"):
        limiter.acquire("ping")
    clock.advance(41.0)  # first call is now 60s old
    limiter.acquire("ping")


def test_port_checks_per_minute(limiter, clock):
    for i in range(10):
        port_check(limiter, f"203.0.113.{i + 1}", 443)
        clock.advance(1.0)
    with pytest.raises(RateLimited, match="port checks per minute"):
        limiter.acquire_port("198.51.100.1", 443)


def test_blocks_port_scanning_one_host(limiter, clock):
    for port in (22, 80, 443, 3389, 8080):
        port_check(limiter, "203.0.113.5", port)
        clock.advance(7.0)
    with pytest.raises(RateLimited, match="not a port scanner"):
        limiter.acquire_port("203.0.113.5", 21)
    # re-checking a port already checked is fine
    limiter.acquire_port("203.0.113.5", 443)
    clock.advance(7.0)
    # a different host is unaffected
    limiter.acquire_port("203.0.113.6", 21)


def test_blocks_sweeping_many_hosts(limiter, clock):
    for i in range(10):
        port_check(limiter, f"192.168.1.{i + 1}", 22)
        clock.advance(7.0)
    with pytest.raises(RateLimited, match="not a network scanner"):
        limiter.acquire_port("192.168.1.11", 22)
    limiter.acquire_port("192.168.1.1", 22)  # a host already checked is fine


def test_scan_window_expires(limiter, clock):
    for port in (1, 2, 3, 4, 5):
        port_check(limiter, "203.0.113.5", port)
        clock.advance(7.0)
    clock.advance(600.0)
    limiter.acquire_port("203.0.113.5", 6)
