"""Read/write the .env file with comment + key-order preservation.

The setup wizard needs to update .env in place — adding values the operator
filled in, leaving comments and any operator-added keys untouched. Python-
dotenv's mutate APIs are good but their quoting decisions are inconsistent
across versions; rolling our own keeps the behavior obvious.

Writes are atomic: write to a .tmp file, fsync, rename. A power loss between
"about to write" and "done" leaves either the old file or the new file —
never a half-corrupted one.
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

_KEY_RE = re.compile(r"^([A-Z][A-Z0-9_]*)\s*=\s*(.*)$")


def env_path() -> Path:
    """Where .env lives. Override with CAPTIVE_PORTAL_ENV_FILE if needed."""
    return Path(os.environ.get("CAPTIVE_PORTAL_ENV_FILE") or ".env").resolve()


def read_env() -> dict[str, str]:
    """Parse .env into a {key: value} dict. Comments + blank lines ignored.
    Returns empty dict if the file doesn't exist."""
    path = env_path()
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _KEY_RE.match(stripped)
        if not m:
            continue
        key, raw = m.group(1), m.group(2)
        out[key] = _unquote(raw)
    return out


def write_env(updates: dict[str, str | None]) -> Path:
    """Merge `updates` into .env. Pass None to *remove* a key.

    Preserves comments, blank lines, and the order of existing keys. New keys
    are appended at the end. Returns the path written.
    """
    path = env_path()
    existing_lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    # Track which update keys we've placed by rewriting an existing line, so
    # the rest get appended at the end.
    remaining = dict(updates)
    new_lines: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        m = _KEY_RE.match(stripped)
        if not m:
            new_lines.append(line)
            continue
        key = m.group(1)
        if key in remaining:
            value = remaining.pop(key)
            if value is None:
                # Remove the line entirely.
                continue
            new_lines.append(_format_line(key, value))
        else:
            new_lines.append(line)

    # Any updates that weren't existing keys: append at the bottom.
    appended_any = False
    for key, value in remaining.items():
        if value is None:
            continue
        if not appended_any and new_lines and new_lines[-1].strip():
            new_lines.append("")  # blank line before the new section
        if not appended_any:
            new_lines.append("# --- Added by setup wizard ---")
            appended_any = True
        new_lines.append(_format_line(key, value))

    content = "\n".join(new_lines)
    if not content.endswith("\n"):
        content += "\n"
    _atomic_write(path, content)
    return path


def _format_line(key: str, value: str) -> str:
    """KEY=value, quoting if the value needs it."""
    return f"{key}={_quote(value)}"


_NEEDS_QUOTING = re.compile(r'[\s"#\'=]')


def _quote(value: str) -> str:
    """Quote only when necessary. Empty string and values with whitespace,
    quotes, # or = get wrapped in double quotes and escaped."""
    if value == "":
        return ""
    if _NEEDS_QUOTING.search(value):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


def _unquote(raw: str) -> str:
    """Inverse of _quote. Strips matched single/double quotes if present."""
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ('"', "'"):
        inner = raw[1:-1]
        if raw[0] == '"':
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return raw


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
