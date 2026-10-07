"""
IoC type auto-detection utilities.
"""
import re
from typing import Optional

from app.models import IoCType

# Regex patterns
_IPv4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPv6_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def detect_ioc_type(value: str) -> Optional[IoCType]:
    """Return the most likely IoCType for the given value, or None if unrecognised."""
    v = value.strip()

    if _IPv4_RE.match(v) or _IPv6_RE.match(v):
        return IoCType.ip
    if _SHA256_RE.match(v):
        return IoCType.hash_sha256
    if _SHA1_RE.match(v):
        return IoCType.hash_sha1
    if _MD5_RE.match(v):
        return IoCType.hash_md5
    if _EMAIL_RE.match(v):
        return IoCType.email
    if _URL_RE.match(v):
        return IoCType.url
    if _DOMAIN_RE.match(v):
        return IoCType.domain
    return None
