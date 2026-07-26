import socket
import ipaddress
from urllib.parse import urlparse
import requests

from .utils import canonicalize_path, is_subpath

# -------------------------
# CONSTANTS
# -------------------------
SANDBOX_ROOT = "/srv/agent-redteam/sandbox-bd7c2042f2"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}


# -------------------------
# PATH VALIDATION (CLEAN)
# -------------------------
def is_path_allowed(path: str) -> bool:
    return is_subpath(path, SANDBOX_ROOT)


# -------------------------
# IP CHECK
# -------------------------
def is_ip_private(ip):
    ip_obj = ipaddress.ip_address(ip)
    return (
        ip_obj.is_private or
        ip_obj.is_loopback or
        ip_obj.is_link_local or
        ip_obj.is_reserved or
        ip_obj.is_multicast
    )


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None


# -------------------------
# URL VALIDATION (STRONG)
# -------------------------
def is_url_allowed(url: str) -> bool:
    try:
        parsed = urlparse(url)

        # ✅ scheme check
        if parsed.scheme not in ("http", "https"):
            return False

        # ✅ block userinfo tricks
        if "@" in parsed.netloc:
            return False

        host = parsed.hostname
        if not host:
            return False

        # ✅ strict allowlist
        if host not in ALLOWED_HOSTS:
            return False

        # ✅ DNS resolution
        ip = resolve_host(host)
        if not ip:
            return False

        # ✅ block private/internal IPs
        if is_ip_private(ip):
            return False

        return True

    except:
        return False


# -------------------------
# SAFE FETCH (REDIRECT SAFE)
# -------------------------
def safe_fetch(url: str):
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)

        # ❌ block unsafe redirects
        if 300 <= resp.status_code < 400:
            location = resp.headers.get("Location")
            if not location or not is_url_allowed(location):
                return None

        return resp.text[:5000]

    except:
        return None