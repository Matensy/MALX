"""IOC extraction engine (offline).

Extracts URLs, domains, IPv4/IPv6, e-mails, file paths, registry keys, mutex-like
names, embedded hashes, User-Agents, onion services and crypto wallets from the
string set, then enriches them with offline context (common references, abused
services, dynamic DNS, unusual ports) for the heuristics.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlsplit

from backend.core.enums import IOCType
from backend.rules.loader import RulePack

from .base import ExtractedString
from .tlds import ALL_TLDS, BARE_TLDS, EXTENSION_LIKE_TLDS

URL_RE = re.compile(r"(?i)\b(?:https?|ftp|ftps|wss?|stratum\+(?:tcp|ssl|tls))://[^\s\"'<>\x00\\^`{|}]{3,2000}")
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::(\d{1,5}))?(?![\d.])")
IPV6_RE = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}(?::|[0-9a-fA-F]{1,4})(?![0-9a-fA-F:])|(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])")
DOMAIN_RE = re.compile(r"(?i)(?<![\w.\-@\\/$%])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){1,8}[a-z]{2,24})(?![\w\-]|\.[a-z0-9])")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+\-]{1,64}@(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
WINPATH_RE = re.compile(r"(?i)(?:\b[a-z]:\\|%[a-z_]{2,32}%\\|\\\\[a-z0-9._$\-]{2,64}\\)(?:[^\\/:*?\"<>|\r\n\x00\t]{1,255}\\)*[^\\/:*?\"<>|\r\n\x00\t]{0,255}")
UNIXPATH_RE = re.compile(r"(?<![\w.~])/(?:etc|tmp|var|usr|bin|sbin|dev|proc|home|root|opt|lib|lib64|run|boot|sys|mnt|private|Library|Users|Applications|System)(?:/[A-Za-z0-9._@%+=:,\-]+)+")
REGISTRY_RE = re.compile(r"(?i)\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|HKEY_CURRENT_CONFIG|HKCC)(?:\\[^\\\r\n\x00\"*?<>|]{1,255}){1,20}|\b(?:SOFTWARE|SYSTEM)\\(?:[A-Za-z0-9 _.{}\-]{1,128}\\){1,15}[A-Za-z0-9 _.{}\-]{1,128}")
MUTEX_RE = re.compile(r"^(?:Global|Local|Session\\\d+)\\[A-Za-z0-9_{}\-.:#@]{4,120}$")
HASH_RE = re.compile(r"(?i)(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])")
UA_RE = re.compile(r"(?:Mozilla/[45]\.0 \([^)\r\n]{5,200}\)[^\"\r\n\x00]{0,200}|(?:curl|Wget|python-requests|Go-http-client|okhttp|Java)/[0-9.]{1,12})")
ONION_RE = re.compile(r"(?i)\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b")
BTC_RE = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b")
XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
GUID_CONTEXT_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-")

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_REVERSE_DNS_FIRST = {"com", "org", "net", "java", "javax", "android", "androidx", "kotlin", "dalvik", "io", "me",
                      "de", "uk", "edu", "gov", "sun", "jdk", "scala", "groovy", "junit", "lombok"}


@dataclass
class RawIOC:
    type: str
    value: str
    normalized: str
    offset: int
    context: str
    meta: dict = field(default_factory=dict)


def _b58check(addr: str) -> bool:
    try:
        n = 0
        for ch in addr:
            n = n * 58 + _B58.index(ch)
        raw = n.to_bytes(25, "big")
    except (ValueError, OverflowError):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _bech32_ok(addr: str) -> bool:
    addr = addr.lower()
    hrp, _, data = addr.rpartition("1")
    if hrp != "bc" or len(data) < 6:
        return False
    try:
        values = [_BECH32.index(c) for c in data]
    except ValueError:
        return False
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk in (1, 0x2BC830A3)


def _clean_url(url: str) -> str:
    url = url.rstrip(".,;:)]}'\"!?>")
    if url.count("(") < url.count(")"):
        url = url.rstrip(")")
    return url


def _valid_domain(domain: str, from_url: bool, original: str) -> bool:
    d = domain.lower().strip(".")
    labels = d.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if from_url:
        return tld in ALL_TLDS or d == "localhost"
    if tld not in BARE_TLDS:
        return False
    if any(len(l) == 0 or len(l) > 63 for l in labels):
        return False
    if all(l.isdigit() for l in labels[:-1]):
        return False
    # Namespaces / identifiers (System.Net, Microsoft.Win32) are mixed case; real hosts in
    # binaries are almost always lower case.
    if any(c.isupper() for c in original) and not original.isupper():
        return False
    if len(labels) >= 3 and labels[0] in _REVERSE_DNS_FIRST:
        return False
    sld = labels[-2]
    if tld in EXTENSION_LIKE_TLDS and not (len(labels) >= 3 or labels[0] == "www"):
        return False
    if len(sld) < 2:
        return False
    return True


def extract_iocs(strings: Iterable[ExtractedString]) -> list[RawIOC]:
    out: list[RawIOC] = []
    for s in strings:
        v = s.value
        if len(v) < 5:
            continue
        ctx = v[:240]
        url_spans: list[tuple[int, int]] = []
        if "://" in v:
            for m in URL_RE.finditer(v):
                url = _clean_url(m.group())
                try:
                    parts = urlsplit(url)
                    host = (parts.hostname or "").lower()
                    port = parts.port
                except ValueError:
                    continue
                if not host:
                    continue
                url_spans.append((m.start(), m.start() + len(url)))
                out.append(RawIOC(IOCType.URL.value, url, url.lower() if len(url) < 300 else url, s.offset, ctx,
                                  {"host": host, "port": port, "scheme": parts.scheme.lower()}))
                if _is_ip(host):
                    out.append(RawIOC(IOCType.IPV4.value if ":" not in host else IOCType.IPV6.value, host, host, s.offset, ctx,
                                      {"from_url": True, "port": port}))
                elif _valid_domain(host, True, host):
                    out.append(RawIOC(IOCType.ONION.value if host.endswith(".onion") else IOCType.DOMAIN.value,
                                      host, host, s.offset, ctx, {"from_url": True, "port": port}))
        if "@" in v:
            for m in EMAIL_RE.finditer(v):
                email = m.group()
                if email.rsplit(".", 1)[-1].lower() in ALL_TLDS:
                    out.append(RawIOC(IOCType.EMAIL.value, email, email.lower(), s.offset, ctx))
        if "." in v:
            for m in IPV4_RE.finditer(v):
                if _inside(m.start(), url_spans):
                    continue
                ip = m.group().split(":")[0]
                octets = [int(o) for o in ip.split(".")]
                if octets[0] == 0 or ip in ("255.255.255.255",):
                    continue
                low_v = v.lower()
                if all(o < 10 for o in octets) and ("version" in low_v or v.strip() == ip):
                    continue  # version-number-like (e.g. 1.0.0.0)
                port = int(m.group(1)) if m.group(1) else None
                out.append(RawIOC(IOCType.IPV4.value, ip, ip, s.offset, ctx, {"port": port}))
            if ".onion" in v.lower():
                for m in ONION_RE.finditer(v):
                    out.append(RawIOC(IOCType.ONION.value, m.group().lower(), m.group().lower(), s.offset, ctx))
            for m in DOMAIN_RE.finditer(v):
                if _inside(m.start(), url_spans):
                    continue
                dom = m.group(1)
                prev = v[m.start() - 1] if m.start() > 0 else ""
                if prev == "@":
                    continue
                if dom.lower().endswith(".onion"):
                    continue
                if _valid_domain(dom, False, dom):
                    out.append(RawIOC(IOCType.DOMAIN.value, dom.lower(), dom.lower(), s.offset, ctx))
        if v.count(":") >= 2:
            for m in IPV6_RE.finditer(v):
                cand = m.group()
                try:
                    addr = ipaddress.IPv6Address(cand)
                except ValueError:
                    continue
                if cand.count(":") < 3 or len(cand) < 6 or addr.is_unspecified:
                    continue
                if not any(c.isdigit() for c in cand):
                    continue
                out.append(RawIOC(IOCType.IPV6.value, cand, addr.compressed, s.offset, ctx))
        if "\\" in v:
            for m in WINPATH_RE.finditer(v):
                p = m.group().rstrip(" .")
                if len(p) >= 6:
                    out.append(RawIOC(IOCType.FILE_PATH.value, p, p.lower(), s.offset, ctx, {"os": "windows"}))
            for m in REGISTRY_RE.finditer(v):
                key = re.split(r"\s+/[A-Za-z]{1,2}\b|\s+-[A-Za-z]{2,}\b|[\"']", m.group(), maxsplit=1)[0].rstrip(" \\")
                if len(key) >= 12 and key.count("\\") >= 2:
                    out.append(RawIOC(IOCType.REGISTRY.value, key, _normalize_reg(key), s.offset, ctx))
            if MUTEX_RE.match(v):
                out.append(RawIOC(IOCType.MUTEX.value, v, v, s.offset, ctx))
        if "/" in v:
            for m in UNIXPATH_RE.finditer(v):
                if _inside(m.start(), url_spans):
                    continue
                p = m.group()
                if len(p) >= 6:
                    out.append(RawIOC(IOCType.FILE_PATH.value, p, p, s.offset, ctx, {"os": "unix"}))
            for m in UA_RE.finditer(v):
                out.append(RawIOC(IOCType.USER_AGENT.value, m.group().strip(), m.group().strip(), s.offset, ctx))
        if len(v) >= 32 and not GUID_CONTEXT_RE.search(v):
            for m in HASH_RE.finditer(v):
                h = m.group(1).lower()
                if len(set(h)) > 6 and (len(v) <= len(h) + 16):
                    kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(h)]
                    out.append(RawIOC(IOCType.HASH.value, h, h, s.offset, ctx, {"hash_type": kind, "embedded": True}))
        if 26 <= len(v) <= 200:
            for m in BTC_RE.finditer(v):
                a = m.group()
                if (a.startswith("bc1") and _bech32_ok(a)) or (not a.startswith("bc1") and _b58check(a)):
                    out.append(RawIOC(IOCType.CRYPTO_WALLET.value, a, a, s.offset, ctx, {"currency": "bitcoin"}))
            for m in XMR_RE.finditer(v):
                out.append(RawIOC(IOCType.CRYPTO_WALLET.value, m.group(), m.group(), s.offset, ctx, {"currency": "monero"}))
            for m in ETH_RE.finditer(v):
                if len(set(m.group()[2:].lower())) > 8:
                    out.append(RawIOC(IOCType.CRYPTO_WALLET.value, m.group(), m.group().lower(), s.offset, ctx,
                                      {"currency": "ethereum", "low_confidence": True}))
    return out


def _inside(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(a <= pos < b for a, b in spans)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _normalize_reg(key: str) -> str:
    k = key.lower()
    for long, short in (("hkey_local_machine", "hklm"), ("hkey_current_user", "hkcu"), ("hkey_classes_root", "hkcr"),
                        ("hkey_users", "hku"), ("hkey_current_config", "hkcc")):
        if k.startswith(long):
            k = short + k[len(long):]
    return k


class IOCEnricher:
    """Adds offline context to IOCs (common reference, abused service, private IP...)."""

    def __init__(self, pack: RulePack):
        self.common = pack.common_domains
        self.services = pack.suspicious_services
        self.bad_tlds = pack.suspicious_tlds
        self.ports = pack.unusual_ports

    @staticmethod
    def _matches(host: str, domains: set[str]) -> str | None:
        host = host.lower().strip(".")
        for d in domains:
            if host == d or host.endswith("." + d):
                return d
        return None

    def enrich(self, ioc: RawIOC) -> dict:
        info: dict = {}
        host = None
        if ioc.type in (IOCType.DOMAIN.value, IOCType.ONION.value):
            host = ioc.normalized
        elif ioc.type == IOCType.URL.value:
            host = ioc.meta.get("host")
            port = ioc.meta.get("port")
            if port and port in self.ports:
                info["unusual_port"] = port
            if host and _is_ip(host):
                info["ip_host"] = True
        elif ioc.type == IOCType.EMAIL.value:
            host = ioc.normalized.split("@", 1)[1]
        if ioc.type in (IOCType.IPV4.value, IOCType.IPV6.value):
            try:
                ip = ipaddress.ip_address(ioc.normalized)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    info["private"] = True
                    info["common"] = True
            except ValueError:
                pass
            port = ioc.meta.get("port")
            if port and port in self.ports:
                info["unusual_port"] = port
        if host:
            if host.endswith(".onion"):
                info["service"] = "tor"
            if self._matches(host, self.common):
                info["common"] = True
            for group, domains in self.services.items():
                match = self._matches(host, domains)
                if match:
                    info["service"] = group
                    info["service_domain"] = match
                    info.pop("common", None)
                    break
            tld = host.rsplit(".", 1)[-1]
            if tld in self.bad_tlds:
                info["suspicious_tld"] = tld
        return info
