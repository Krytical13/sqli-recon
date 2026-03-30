"""Live domain probing — checks HTTP status, detects CDN/parking, fingerprints tech."""

import re
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

log = logging.getLogger(__name__)

# Known CDN IP ranges (CIDR prefixes) — domains behind these are proxied
CDN_PREFIXES = [
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "172.64.", "172.65.", "172.66.", "172.67.",
    "162.158.", "141.101.", "190.93.", "188.114.",
    "103.21.", "103.22.", "103.31.",
    # Akamai
    "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.",
    "23.38.", "23.39.", "23.40.", "23.41.", "23.42.", "23.43.",
    "23.44.", "23.45.", "23.46.", "23.47.", "23.48.", "23.49.",
    "23.50.", "23.51.", "23.52.", "23.53.", "23.54.", "23.55.",
    "23.56.", "23.57.", "23.58.", "23.59.", "23.60.", "23.61.",
    "23.62.", "23.63.", "23.64.", "23.65.", "23.66.", "23.67.",
    "104.64.", "104.65.", "104.66.", "104.67.", "104.68.", "104.69.",
    "104.70.", "104.71.", "104.72.", "104.73.", "104.74.", "104.75.",
    "104.76.", "104.77.", "104.78.", "104.79.",
    # Fastly
    "151.101.",
    # Amazon CloudFront
    "13.32.", "13.33.", "13.35.", "13.224.", "13.225.", "13.226.", "13.227.",
    "52.84.", "52.85.", "54.182.", "54.192.", "54.230.", "54.239.", "54.240.",
    "99.84.", "99.86.",
    # Sucuri
    "192.124.",
    # Incapsula/Imperva
    "45.223.",
]

# CDN indicators in HTTP headers
CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-cdn": None,  # Generic CDN header, value is the CDN name
    "x-cache": None,  # Often from CloudFront/Varnish
    "x-akamai-request-id": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-iinfo": "Incapsula",
    "server": None,  # Check value for CDN names
}

CDN_SERVER_PATTERNS = [
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"AkamaiGHost|AkamaiNetStorage", re.I), "Akamai"),
    (re.compile(r"CloudFront", re.I), "CloudFront"),
    (re.compile(r"sucuri", re.I), "Sucuri"),
    (re.compile(r"Incapsula", re.I), "Incapsula"),
]

# Parking page indicators
PARKING_PATTERNS = [
    re.compile(r"domain.*(?:is )?for sale|buy this domain", re.I),
    re.compile(r"parked.*domain|domain.*parked", re.I),
    re.compile(r"godaddy|namecheap|sedo|afternic|dan\.com", re.I),
    re.compile(r"this domain has expired|domain expired", re.I),
    re.compile(r"coming soon|under construction", re.I),
    re.compile(r"hugedomains|register\.com", re.I),
]


class DomainProbe:
    """Probe discovered domains for liveness, CDN, parking, and tech stack."""

    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout

    def probe_domains(self, domains, max_workers=5, progress_callback=None):
        """
        Probe a list of domain strings. Returns dict of {domain: ProbeResult}.
        """
        results = {}
        done = [0]

        def _probe_one(domain):
            result = self._probe(domain)
            done[0] += 1
            if progress_callback and done[0] % 10 == 0:
                progress_callback(done[0], len(domains))
            return domain, result

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_probe_one, d): d for d in domains}
            for future in as_completed(futures):
                domain, result = future.result()
                results[domain] = result

        if progress_callback:
            progress_callback(len(domains), len(domains))

        # Wildcard DNS detection: if many subdomains resolve to the same IP,
        # it's likely a DNS wildcard catch-all (not real individual sites)
        ip_counts = {}
        for d, r in results.items():
            if r["ip"]:
                ip_counts.setdefault(r["ip"], []).append(d)

        for ip, ip_domains in ip_counts.items():
            # If 10+ subdomains of the same parent resolve to one IP → wildcard
            if len(ip_domains) >= 10:
                parents = set()
                for d in ip_domains:
                    parts = d.split(".")
                    if len(parts) >= 3:
                        parents.add(".".join(parts[-2:]))
                for parent in parents:
                    children = [d for d in ip_domains if d.endswith(f".{parent}")]
                    if len(children) >= 10:
                        for d in children:
                            results[d]["wildcard"] = True
                            results[d]["scannable"] = False

        return results

    def _probe(self, domain):
        """Probe a single domain. Returns a ProbeResult dict."""
        result = {
            "status": "unknown",
            "http_code": 0,
            "cdn": None,
            "parked": False,
            "wildcard": False,
            "tech": [],
            "title": "",
            "redirect": "",
            "ip": "",
            "scannable": False,
        }

        # DNS resolution
        try:
            ip = socket.gethostbyname(domain)
            result["ip"] = ip
        except (socket.gaierror, OSError):
            result["status"] = "dns_failed"
            return result

        # CDN check by IP
        cdn = self._check_cdn_ip(ip)
        if cdn:
            result["cdn"] = cdn

        # HTTP probe
        for scheme in ("https", "http"):
            try:
                resp = self.session.get(
                    f"{scheme}://{domain}/",
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                result["http_code"] = resp.status_code
                result["status"] = "live"

                # Track redirect
                if resp.url and domain not in resp.url:
                    result["redirect"] = resp.url

                # CDN check by headers
                if not cdn:
                    cdn = self._check_cdn_headers(resp.headers)
                    if cdn:
                        result["cdn"] = cdn

                # Parking check
                if resp.text:
                    body = resp.text[:5000]
                    for pattern in PARKING_PATTERNS:
                        if pattern.search(body):
                            result["parked"] = True
                            result["status"] = "parked"
                            break

                    # Title extraction
                    title_match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
                    if title_match:
                        result["title"] = title_match.group(1).strip()[:80]

                # Tech fingerprint from headers
                result["tech"] = self._fingerprint_tech(resp)

                # Determine if scannable
                result["scannable"] = (
                    result["status"] == "live"
                    and not result["parked"]
                    and result["cdn"] is None
                    and result["http_code"] < 500
                )

                return result

            except requests.RequestException:
                continue

        if result["status"] == "unknown":
            result["status"] = "http_failed"

        return result

    def _check_cdn_ip(self, ip):
        for prefix in CDN_PREFIXES:
            if ip.startswith(prefix):
                # Determine which CDN
                if ip.startswith(("104.16.", "104.17.", "104.18.", "104.19.",
                                  "104.20.", "104.21.", "104.22.", "104.23.",
                                  "104.24.", "104.25.", "104.26.", "104.27.",
                                  "172.64.", "172.65.", "172.66.", "172.67.",
                                  "162.158.", "141.101.", "190.93.", "188.114.",
                                  "103.21.", "103.22.", "103.31.")):
                    return "Cloudflare"
                elif ip.startswith(("23.32.", "23.33.", "23.34.", "23.35.",
                                    "104.64.", "104.65.", "104.66.", "104.67.")):
                    return "Akamai"
                elif ip.startswith("151.101."):
                    return "Fastly"
                elif ip.startswith(("13.32.", "13.33.", "52.84.", "99.84.")):
                    return "CloudFront"
                return "CDN"
        return None

    def _check_cdn_headers(self, headers):
        for header, cdn_name in CDN_HEADERS.items():
            val = headers.get(header, "")
            if val:
                if cdn_name:
                    return cdn_name
                # Check server header patterns
                if header == "server":
                    for pattern, name in CDN_SERVER_PATTERNS:
                        if pattern.search(val):
                            return name
                elif header == "x-cdn":
                    return val[:30]
        return None

    def _fingerprint_tech(self, resp):
        """Quick tech fingerprint from response headers."""
        techs = []
        headers = {k.lower(): v for k, v in resp.headers.items()}

        powered = headers.get("x-powered-by", "")
        if "PHP" in powered:
            techs.append("PHP")
        elif "ASP.NET" in powered:
            techs.append("ASP.NET")
        elif "Express" in powered:
            techs.append("Node.js")

        server = headers.get("server", "")
        if "nginx" in server.lower():
            techs.append("nginx")
        elif "Apache" in server:
            techs.append("Apache")
        elif "IIS" in server:
            techs.append("IIS")

        return techs
