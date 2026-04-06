from __future__ import annotations

import threading

try:
    from mac_vendor_lookup import MacLookup
except Exception:  # pragma: no cover - optional dependency at runtime
    MacLookup = None


_LOOKUP_LOCK = threading.Lock()
_LOOKUP_CLIENT = None
_LOOKUP_READY = True
_CACHE: dict[str, str] = {}

_FALLBACK_VENDORS = {
    "00:17:88": "Philips",
    "00:1a:79": "Cisco",
    "00:1b:63": "Apple",
    "00:40:8c": "Axis",
    "00:e0:4c": "Realtek",
    "08:66:98": "TP-Link",
    "10:27:f5": "Apple",
    "18:b4:30": "Google Nest",
    "1c:5f:2b": "Hikvision",
    "1c:69:7a": "Intel",
    "24:5a:4c": "Ubiquiti",
    "28:6d:cd": "TP-Link",
    "2c:54:cf": "Samsung",
    "3c:52:82": "Google",
    "3c:84:6a": "Hon Hai / Foxconn",
    "44:65:0d": "Amazon",
    "48:3f:da": "HUAWEI",
    "50:c7:bf": "TP-Link",
    "50:d4:f7": "Xiaomi",
    "64:09:80": "Ubiquiti",
    "64:16:66": "Xiaomi",
    "70:4f:57": "Samsung",
    "7c:dd:90": "Apple",
    "84:16:f9": "Sonos",
    "9c:20:7b": "Apple",
    "a0:b5:3c": "Intel",
    "ac:bc:32": "Apple",
    "b0:95:75": "Samsung",
    "b8:27:eb": "Raspberry Pi",
    "b8:e9:37": "Sonos",
    "bc:ad:28": "Hikvision",
    "c8:5b:76": "Apple",
    "cc:2d:e0": "Huawei",
    "d0:03:4b": "Apple",
    "d4:f5:47": "Amazon",
    "d8:96:95": "Apple",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Xiaomi",
    "e4:60:17": "Espressif",
    "ec:fa:bc": "Samsung",
    "f0:18:98": "Apple",
    "f4:cf:a2": "Espressif",
    "f4:f2:6d": "Ubiquiti",
    "f4:f5:d8": "Google",
    "f8:3b:09": "Intel",
    "fc:a6:67": "Amazon",
}


def _normalize_mac(mac: str) -> str:
    value = (mac or "").strip().lower().replace("-", ":")
    parts = [part.zfill(2) for part in value.split(":") if part]
    return ":".join(parts[:6]) if parts else ""


def _is_local_admin_mac(mac: str) -> bool:
    normalized = _normalize_mac(mac)
    if not normalized:
        return False
    try:
        first_octet = int(normalized.split(":")[0], 16)
    except Exception:
        return False
    return bool(first_octet & 0x02)


def _get_lookup_client():
    global _LOOKUP_CLIENT, _LOOKUP_READY
    if not _LOOKUP_READY or MacLookup is None:
        return None
    if _LOOKUP_CLIENT is not None:
        return _LOOKUP_CLIENT
    with _LOOKUP_LOCK:
        if _LOOKUP_CLIENT is not None:
            return _LOOKUP_CLIENT
        if not _LOOKUP_READY or MacLookup is None:
            return None
        try:
            _LOOKUP_CLIENT = MacLookup()
        except Exception:
            _LOOKUP_READY = False
            _LOOKUP_CLIENT = None
        return _LOOKUP_CLIENT


def lookup_vendor(mac: str) -> str:
    normalized = _normalize_mac(mac)
    if not normalized:
        return ""
    prefix = ":".join(normalized.split(":")[:3])
    if prefix in _CACHE:
        return _CACHE[prefix]
    if _is_local_admin_mac(normalized):
        _CACHE[prefix] = "Private / Randomized"
        return _CACHE[prefix]

    vendor = _FALLBACK_VENDORS.get(prefix, "")
    if not vendor:
        lookup_client = _get_lookup_client()
        if lookup_client is not None:
            try:
                vendor = str(lookup_client.lookup(normalized)).strip()
            except Exception:
                vendor = ""

    _CACHE[prefix] = vendor
    return vendor
