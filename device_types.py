"""Device type catalog and per-OS instructions for disabling MAC randomization.

Shown on the registration page so users can pick what they're connecting and
optionally follow the steps to disable randomization (only matters if they need
the same MAC across SSIDs or after a 'Reset Network Settings').
"""

DEVICE_TYPES = [
    {
        "key": "ios",
        "label": "iPhone or iPad",
        "instructions": [
            "Open Settings → Wi-Fi.",
            "Tap the (i) next to this network's name.",
            "Turn OFF 'Private Wi-Fi Address'.",
            "Tap 'Forget This Network', then reconnect once approved.",
        ],
    },
    {
        "key": "android",
        "label": "Android phone or tablet",
        "instructions": [
            "Open Settings → Network & Internet → Wi-Fi.",
            "Tap this network → Privacy.",
            "Choose 'Use device MAC' (instead of randomized).",
            "Forget the network and reconnect once approved.",
        ],
    },
    {
        "key": "macos",
        "label": "Mac (macOS)",
        "instructions": [
            "Open System Settings → Wi-Fi.",
            "Click 'Details' next to this network.",
            "Set 'Private Wi-Fi address' to 'Off'.",
            "Forget the network and reconnect once approved.",
        ],
    },
    {
        "key": "windows",
        "label": "Windows laptop",
        "instructions": [
            "Open Settings → Network & Internet → Wi-Fi.",
            "Click this network → Random hardware addresses.",
            "Set to 'Off' for this network.",
            "Forget the network and reconnect once approved.",
        ],
    },
    {
        "key": "chromeos",
        "label": "Chromebook",
        "instructions": [
            "Open Settings → Network → Wi-Fi → this network.",
            "Toggle 'Randomize MAC address' OFF.",
            "Forget the network and reconnect once approved.",
        ],
    },
    {
        "key": "iot",
        "label": "Smart TV / console / IoT (no randomization)",
        "instructions": [
            "Most IoT devices don't randomize MACs — no changes needed.",
            "Just wait for approval and reconnect.",
        ],
    },
    {
        "key": "other",
        "label": "Something else",
        "instructions": [
            "If your device offers a 'use random MAC' option, turn it off for this network.",
            "Otherwise just wait for approval.",
        ],
    },
]

DEVICE_TYPES_BY_KEY = {d["key"]: d for d in DEVICE_TYPES}


def infer_device_type(user_agent: str | None) -> str:
    """Best-effort guess of device_type key from the User-Agent string.

    Limitations:
      - iPadOS 13+ default Safari identifies as Macintosh, so iPad-as-Mac is mistaken
        for macOS. (User can correct it on the form.)
      - Headless / IoT devices typically don't hit the portal in a browser, so we
        don't try to detect them here.
    """
    ua = (user_agent or "").lower()
    # iOS / iPadOS (must match before macOS because iPhones say "Mac OS" too)
    if "iphone" in ua or "ipod" in ua or "ipad" in ua:
        return "ios"
    # Android (must match before Linux because Android UAs contain "Linux")
    if "android" in ua:
        return "android"
    # ChromeOS
    if "cros" in ua:
        return "chromeos"
    # Windows
    if "windows nt" in ua or "windows phone" in ua:
        return "windows"
    # macOS (after iOS checks)
    if "macintosh" in ua or "mac os x" in ua or "mac_powerpc" in ua:
        return "macos"
    return "other"
