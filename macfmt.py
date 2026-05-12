"""MAC address normalization. Canonical form everywhere internal: lowercase, no separators."""
import re

_HEX = re.compile(r"[^0-9a-f]")


def canonical(mac: str) -> str:
    """Normalize any of aa:bb:..., AA-BB-..., aabbccddeeff, etc. to 'aabbccddeeff'."""
    s = _HEX.sub("", mac.lower())
    if len(s) != 12:
        raise ValueError(f"not a MAC: {mac!r}")
    return s


def display_colon(mac: str) -> str:
    s = canonical(mac)
    return ":".join(s[i:i + 2] for i in range(0, 12, 2))


def display_upper_colon(mac: str) -> str:
    return display_colon(mac).upper()


def to_radius_format(mac: str, fmt: str) -> str:
    """Render a canonical MAC in the format SmartZone is configured to send."""
    s = canonical(mac)
    upper = "upper" in fmt
    if "colon" in fmt:
        out = ":".join(s[i:i + 2] for i in range(0, 12, 2))
    elif "hyphen" in fmt:
        out = "-".join(s[i:i + 2] for i in range(0, 12, 2))
    else:
        out = s
    return out.upper() if upper else out
