import requests
from urllib.parse import urlparse

_ORIGINAL_REQUEST = requests.sessions.Session.request

def install_hackerone_headers():
    def patched_request(session, method, url, **kwargs):
        hostname = (urlparse(str(url)).hostname or "").lower()

        if hostname == "stripchat.com" or hostname.endswith(".stripchat.com"):
            headers = dict(kwargs.get("headers") or {})
            headers.setdefault("User-Agent", "Mozilla/5.0")
            headers.setdefault("HackerOne", "VaalSec")
            kwargs["headers"] = headers

        return _ORIGINAL_REQUEST(session, method, url, **kwargs)

    requests.sessions.Session.request = patched_request
