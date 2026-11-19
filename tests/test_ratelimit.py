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
    hosts = [f"host{i}.example" for i in range(11)]
    for host in hosts[:10]:
        limiter.acquire("check_port", host, 443)
        clock.advance(1.0)
    with pytest.raises(RateLimited, match="port checks per minute"):
        limiter.acquire("check_port", hosts[10], 443)


def test_blocks_port_scanning_one_host(limiter, clock):
    for port in (22, 80, 443, 3389, 8080):
        limiter.acquire("check_port", "example.com", port)
        clock.advance(7.0)
    with pytest.raises(RateLimited, match="not a port scanner"):
        limiter.acquire("check_port", "example.com", 21)
    # re-checking a port already checked is fine
    limiter.acquire("check_port", "example.com", 443)
    clock.advance(7.0)
    # a different host is unaffected
    limiter.acquire("check_port", "example.org", 21)


def test_scan_window_expires(limiter, clock):
    for port in (1, 2, 3, 4, 5):
        limiter.acquire("check_port", "example.com", port)
        clock.advance(7.0)
    clock.advance(600.0)
    limiter.acquire("check_port", "example.com", 6)


def test_check_port_requires_host_and_port(limiter):
    with pytest.raises(ValueError):
        limiter.acquire("check_port")
