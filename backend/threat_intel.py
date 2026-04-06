import ipaddress

_KNOWN_C2_IPS: dict[str, str] = {
    "10.0.0.50": "Simulated C2 server — attacker node alpha",
    "10.0.0.51": "Simulated C2 server — attacker node beta",
}
_KNOWN_MALICIOUS_CIDRS: list[tuple[str, str]] = [
    ("192.0.2.0/24",    "TEST-NET — should never appear in real traffic"),
    ("198.51.100.0/24", "TEST-NET-2 — documentation range"),
    ("203.0.113.0/24",  "TEST-NET-3 — documentation range"),
]

_TRUSTED_CIDRS: list[tuple[str, str]] = [
    # Google
    ("8.8.8.0/24",          "Google DNS"),
    ("8.8.4.0/24",          "Google DNS"),
    ("142.250.0.0/15",      "Google CDN / Services"),
    ("142.251.0.0/16",      "Google CDN / Services"),
    ("172.217.0.0/16",      "Google CDN"),
    ("216.58.192.0/19",     "Google CDN"),
    ("74.125.0.0/16",       "Google Infrastructure"),
    ("64.233.160.0/19",     "Google Infrastructure"),
    ("192.178.0.0/16",      "Google LLC Infrastructure"),
    ("108.177.0.0/17",      "Google Infrastructure"),
    ("209.85.128.0/17",     "Google Infrastructure"),
    ("34.64.0.0/10",        "Google Cloud"),
    ("35.184.0.0/13",       "Google Cloud"),
    ("34.0.0.0/9",          "Google Cloud"),
    # Cloudflare
    ("1.1.1.0/24",          "Cloudflare DNS"),
    ("1.0.0.0/24",          "Cloudflare DNS"),
    ("104.16.0.0/13",       "Cloudflare CDN"),
    ("104.24.0.0/14",       "Cloudflare CDN"),
    ("172.64.0.0/13",       "Cloudflare CDN"),
    ("131.0.72.0/22",       "Cloudflare CDN"),
    # Fastly
    ("199.232.0.0/16",      "Fastly CDN"),
    ("151.101.0.0/16",      "Fastly CDN"),
    # Amazon / AWS
    ("52.0.0.0/8",          "Amazon AWS"),
    ("54.0.0.0/8",          "Amazon AWS"),
    ("3.0.0.0/8",           "Amazon AWS"),
    ("13.0.0.0/8",          "Amazon AWS"),
    # Microsoft
    ("20.0.0.0/8",          "Microsoft Azure"),
    ("40.0.0.0/8",          "Microsoft Azure"),
    ("52.224.0.0/11",       "Microsoft Azure"),
    ("13.64.0.0/11",        "Microsoft Azure"),
    # Akamai
    ("23.32.0.0/11",        "Akamai CDN"),
    ("104.64.0.0/10",       "Akamai CDN"),
]


def _build_networks(entries: list[tuple[str, str]]) -> list[tuple[ipaddress.IPv4Network, str]]:
    result = []
    for cidr, reason in entries:
        try:
            result.append((ipaddress.IPv4Network(cidr, strict=False), reason))
        except ValueError:
            pass
    return result


_MALICIOUS_NETWORKS = _build_networks(_KNOWN_MALICIOUS_CIDRS)
_TRUSTED_NETWORKS   = _build_networks(_TRUSTED_CIDRS)


class ThreatIntelFeed:

    def is_trusted(self, ip: str) -> tuple[bool, str]:
        """Return (True, reason) if IP belongs to a known good provider."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return False, ""
        for network, reason in _TRUSTED_NETWORKS:
            if addr in network:
                return True, reason
        return False, ""

    def is_malicious(self, ip: str) -> tuple[bool, str]:
        """Return (True, reason) if IP is a known threat. Always False for trusted IPs."""
        trusted, _ = self.is_trusted(ip)
        if trusted:
            return False, ""

        if ip in _KNOWN_C2_IPS:
            return True, _KNOWN_C2_IPS[ip]

        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return False, ""

        for network, reason in _MALICIOUS_NETWORKS:
            if addr in network:
                return True, f"IP in malicious range {network} — {reason}"

        return False, ""
