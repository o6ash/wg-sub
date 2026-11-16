"""Turn WireGuard and AmneziaWG configs into CoreForge wireguard:// links.

Accepted input, mixed in one blob:
- wg-quick / AmneziaWG ini ([Interface] / [Peer])
- an existing wireguard:// or awg:// link
- a base64 blob that decodes to either of those

A link is emitted only when a private key, a peer public key, and an
endpoint are all present. Obfuscation fields are copied, not invented.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, unquote, urlsplit

# Query keys CoreForge reads, in a stable order. Unknown keys on an
# incoming link (cfwarp, inner, ...) are kept after these.
_KNOWN = (
    "publickey",
    "address",
    "dns",
    "mtu",
    "presharedkey",
    "reserved",
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "keepalive",
    "wnoise",
    "wnoisecount",
    "wnoisedelay",
    "wpayloadsize",
)

_INI_TO_QUERY = {
    "privatekey": "private",
    "publickey": "publickey",
    "address": "address",
    "endpoint": "endpoint",
    "dns": "dns",
    "mtu": "mtu",
    "presharedkey": "presharedkey",
    "persistentkeepalive": "keepalive",
    "jc": "jc",
    "jmin": "jmin",
    "jmax": "jmax",
    "s1": "s1",
    "s2": "s2",
    "s3": "s3",
    "s4": "s4",
    "h1": "h1",
    "h2": "h2",
    "h3": "h3",
    "h4": "h4",
    "i1": "i1",
    "i2": "i2",
    "i3": "i3",
    "i4": "i4",
    "i5": "i5",
}

_URI_RE = re.compile(r"(?i)\b(?:wireguard|awg)://[^\s<>\"']+")
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])")


@dataclass
class Profile:
    private: str
    host: str
    port: int
    params: dict[str, str] = field(default_factory=dict)
    name: str = ""

    def identity(self) -> str:
        """Same tunnel and same disguise, ignoring the display name."""
        items = "&".join(f"{k}={self.params[k]}" for k in sorted(self.params))
        return f"{self.private}|{self.host}|{self.port}|{items}"

    def uri(self) -> str:
        user = quote(self.private, safe="")
        host = self.host if ":" not in self.host else f"[{self.host}]"
        pairs = []
        used = set()
        for key in _KNOWN:
            if key in self.params and self.params[key] != "":
                pairs.append(f"{key}={quote(self.params[key], safe='')}")
                used.add(key)
        for key in sorted(self.params):
            if key in used or self.params[key] == "":
                continue
            pairs.append(f"{quote(key, safe='')}={quote(self.params[key], safe='')}")
        uri = f"wireguard://{user}@{host}:{self.port}?{'&'.join(pairs)}"
        if self.name:
            uri += "#" + quote(self.name, safe="")
        return uri


def parse_blob(text: str, name: str = "") -> list[Profile]:
    """Extract every usable profile from a message, file, or pasted mix."""
    found: list[Profile] = []
    if not text:
        return found
    found.extend(_from_ini(text, name))
    for match in _URI_RE.finditer(text):
        profile = _from_uri(match.group(0), name)
        if profile:
            found.append(profile)
    # A whole-file base64 conf, not a key that happens to look like base64.
    stripped = text.strip()
    if _B64_RE.fullmatch(stripped):
        decoded = _try_b64(stripped)
        if decoded and decoded != text:
            found.extend(parse_blob(decoded, name))
    return _dedupe(found)


def _dedupe(profiles: list[Profile]) -> list[Profile]:
    seen = set()
    out = []
    for profile in profiles:
        key = profile.identity()
        if key in seen:
            continue
        seen.add(key)
        out.append(profile)
    return out


def _from_uri(raw: str, fallback_name: str) -> Profile | None:
    raw = raw.strip()
    parts = urlsplit(raw)
    if parts.scheme.lower() not in ("wireguard", "awg"):
        return None
    private = unquote(parts.username or "")
    host = parts.hostname or ""
    port = parts.port
    if not _key_ok(private) or not host or not port:
        return None
    params = {}
    for key, value in parse_qsl(parts.query, keep_blank_values=False):
        params[key.lower()] = value
    if not _key_ok(params.get("publickey", "")):
        return None
    name = unquote(parts.fragment) if parts.fragment else fallback_name
    return Profile(private=private, host=host, port=port, params=params, name=_clean_name(name))


def _from_ini(text: str, fallback_name: str) -> list[Profile]:
    out = []
    chunks = re.split(r"(?mi)^(?=\s*\[interface\]\s*$)", text)
    for index, chunk in enumerate(chunks):
        if not re.search(r"(?mi)^\s*\[interface\]\s*$", chunk):
            continue
        preamble = chunks[index - 1] if index else ""
        names = re.findall(r"(?mi)^\s*#\s*Name\s*=\s*(.+)$", preamble)
        name = names[-1].strip() if names else fallback_name
        interface, peers = _split_peers(chunk)
        iface = _fields(interface)
        private = iface.get("private", "")
        if not _key_ok(private):
            continue
        for peer_text in peers:
            peer = _fields(peer_text)
            public = peer.get("publickey", "")
            endpoint = peer.get("endpoint", "")
            if not _key_ok(public) or not endpoint:
                continue
            host, port = _endpoint(endpoint)
            if not host or not port:
                continue
            params = {"publickey": public}
            for key in (
                "address",
                "dns",
                "mtu",
                "presharedkey",
                "jc",
                "jmin",
                "jmax",
                "s1",
                "s2",
                "s3",
                "s4",
                "h1",
                "h2",
                "h3",
                "h4",
                "i1",
                "i2",
                "i3",
                "i4",
                "i5",
            ):
                if iface.get(key, "") != "":
                    params[key] = iface[key]
            if peer.get("presharedkey", "") != "":
                params["presharedkey"] = peer["presharedkey"]
            if peer.get("keepalive", "") != "":
                params["keepalive"] = peer["keepalive"]
            out.append(
                Profile(
                    private=private,
                    host=host,
                    port=port,
                    params=params,
                    name=_clean_name(name),
                )
            )
    return out


def _split_peers(chunk: str) -> tuple[str, list[str]]:
    parts = re.split(r"(?mi)^(?=\s*\[peer\]\s*$)", chunk)
    interface = parts[0]
    peers = [part for part in parts[1:] if re.search(r"(?mi)^\s*\[peer\]\s*$", part)]
    return interface, peers


def _fields(section: str) -> dict[str, str]:
    found = {}
    for line in section.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        mapped = _INI_TO_QUERY.get(re.sub(r"[\s_\-]", "", key).lower())
        if not mapped:
            continue
        found[mapped] = value.strip()
    if "address" in found:
        found["address"] = ",".join(part.strip() for part in found["address"].split(",") if part.strip())
    if "dns" in found:
        found["dns"] = ",".join(part.strip() for part in found["dns"].split(",") if part.strip())
    return found


def _endpoint(value: str) -> tuple[str, int | None]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or not value[end:].startswith("]:"):
            return "", None
        host = value[1:end]
        port_text = value[end + 2 :]
    else:
        if value.count(":") != 1:
            return "", None
        host, port_text = value.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError:
        return "", None
    if not host or not 1 <= port <= 65535:
        return "", None
    return host, port


def _key_ok(value: str) -> bool:
    if not value:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) == 32


def _clean_name(name: str) -> str:
    name = re.sub(r"\s+", " ", name).strip()
    return name[:60]


def _try_b64(text: str) -> str:
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception:
        return ""
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    if "[Interface]" in decoded or "wireguard://" in decoded or "awg://" in decoded:
        return decoded
    return ""
