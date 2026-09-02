import pytest

from invariant_discovery.ranges import MIN_PREFIX_LENGTH, RangeTooLargeError, expand


def test_single_ip_expands_to_itself():
    assert expand("10.0.0.5") == ["10.0.0.5"]


def test_slash_32_expands_to_itself():
    assert expand("10.0.0.5/32") == ["10.0.0.5"]


def test_slash_24_expands_to_254_usable_hosts():
    hosts = expand("10.0.0.0/24")

    assert len(hosts) == 254
    assert "10.0.0.1" in hosts
    assert "10.0.0.254" in hosts
    assert "10.0.0.0" not in hosts  # network address
    assert "10.0.0.255" not in hosts  # broadcast


def test_slash_20_is_the_largest_allowed_range():
    hosts = expand("10.0.0.0/20")

    assert len(hosts) == 2**(32 - MIN_PREFIX_LENGTH) - 2


def test_prefix_smaller_than_slash_20_raises():
    with pytest.raises(RangeTooLargeError):
        expand("10.0.0.0/19")


def test_non_strict_host_bits_set_still_expands():
    # ip_network(strict=False) tolera "10.0.0.5/24" (bits de host setados)
    # em vez de exigir exatamente "10.0.0.0/24" -- mais tolerante com o
    # que um admin pode digitar.
    hosts = expand("10.0.0.5/24")

    assert len(hosts) == 254
