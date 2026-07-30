import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

from .utils import resolve_safe_path


SANDBOX_ROOT = "/srv/agent-redteam/sandbox-bd7c2042f2"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
MAX_REDIRECTS = 5


def get_safe_path(path: str) -> str | None:
    if not isinstance(path, str) or not path:
        return None

    return resolve_safe_path(path, SANDBOX_ROOT)


def is_path_allowed(path: str) -> bool:
    return get_safe_path(path) is not None


def read_safe_file(path: str) -> str | None:
    safe_path = get_safe_path(path)
    if safe_path is None:
        return None

    try:
        with open(safe_path, "r", encoding="utf-8") as file:
            return file.read()
    except OSError:
        return None


def is_ip_unsafe(ip: str) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []

    ips = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            ips.append(sockaddr[0])

    return sorted(set(ips))


def is_url_allowed(url: str) -> bool:
    try:
        if not isinstance(url, str) or any(ch.isspace() for ch in url):
            return False

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            return False

        host = parsed.hostname.lower() if parsed.hostname else None
        if host not in ALLOWED_HOSTS:
            return False

        if parsed.scheme == "http" and parsed.port not in (None, 80):
            return False
        if parsed.scheme == "https" and parsed.port not in (None, 443):
            return False

        ips = resolve_host(host)
        if not ips:
            return False

        if any(is_ip_unsafe(ip) for ip in ips):
            return False

        return True
    except (TypeError, ValueError):
        return False


def safe_fetch(url: str) -> str | None:
    try:
        current_url = url

        for _ in range(MAX_REDIRECTS + 1):
            if not is_url_allowed(current_url):
                return None

            response = requests.get(current_url, timeout=5, allow_redirects=False)

            if 300 <= response.status_code < 400:
                location = response.headers.get("Location")
                if not location:
                    return None

                current_url = urljoin(current_url, location)
                continue

            return response.text[:5000]

        return None
    except requests.RequestException:
        return None
