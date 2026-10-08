"""A polite client for syzbot's public dashboard (syzkaller.appspot.com).

syzbot is a free service run by the syzkaller team; this client tries hard
not to be a burden:

- every request carries a User-Agent naming this project and its repo;
- requests are serialized and spaced at least MIN_INTERVAL seconds apart
  (default 1.5s, never below 1s, process-wide);
- responses are cached on disk. Crash reports, reproducers and configs
  (`/text?tag=...&x=...`) are immutable and cached for 30 days; bug pages
  for 15 minutes; bug lists for 1 hour (fixed/invalid lists, several MB
  each, for 6 hours);
- HTTP 429/503 back off once (honouring Retry-After), then fail with an
  error that says so, instead of retrying in a loop.

Endpoints used: `/<ns>?json=1` style JSON where syzbot offers it (bug pages,
fixed/invalid lists), HTML for the open-bug table (it carries subsystems,
repro and counts that the JSON list lacks), and `/text?tag=...` for report,
reproducer and config text. robots.txt allows all of these.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from . import __version__

BASE = "https://syzkaller.appspot.com"
USER_AGENT = f"syzbot-mcp/{__version__} (+https://github.com/0xmortuex/syzbot-mcp)"

TTL_TEXT = 30 * 24 * 3600
TTL_BUG = 15 * 60
TTL_LIST = 3600
TTL_BIG_LIST = 6 * 3600


class SyzbotError(RuntimeError):
    pass


def _cache_dir() -> str:
    d = os.environ.get("SYZBOT_MCP_CACHE")
    if not d:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") \
            or os.path.join(os.path.expanduser("~"), ".cache")
        d = os.path.join(base, "syzbot-mcp")
    os.makedirs(d, exist_ok=True)
    return d


def min_interval() -> float:
    raw = os.environ.get("SYZBOT_MCP_MIN_INTERVAL", "1.5")
    try:
        value = float(raw)
    except ValueError:
        raise SyzbotError(f"SYZBOT_MCP_MIN_INTERVAL={raw!r} is not a number") from None
    return max(1.0, value)  # never hammer syzbot, whatever the setting


_lock = threading.Lock()
_last_request = 0.0


def _throttled(network: Callable[[str, float], bytes], url: str, timeout: float) -> bytes:
    """Run one network fetch, serialized and spaced min_interval() apart."""
    global _last_request
    with _lock:
        wait = _last_request + min_interval() - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        try:
            return network(url, timeout)
        finally:
            _last_request = time.monotonic()


def _network(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in (1, 2):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data: bytes = resp.read()
            return data
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and attempt == 1:
                retry = e.headers.get("Retry-After", "")
                time.sleep(min(float(retry), 60.0) if retry.isdigit() else 10.0)
                continue
            if e.code == 404:
                raise SyzbotError(f"syzbot has no page at {url} (HTTP 404)") from None
            raise SyzbotError(f"syzbot returned HTTP {e.code} for {url}"
                              + (" - it is rate-limiting us; try again later" if e.code in (429, 503) else "")) from None
        except urllib.error.URLError as e:
            raise SyzbotError(f"could not reach syzbot ({e.reason}) for {url}") from None
    raise SyzbotError(f"syzbot kept rate-limiting {url}; try again later")


def _fetch(url: str, timeout: float) -> bytes:
    return _throttled(_network, url, timeout)


def get(path: str, ttl: float, timeout: float = 60.0, refresh: bool = False) -> str:
    """GET BASE+path as text, through the on-disk cache."""
    if not path.startswith("/"):
        raise ValueError(f"path must start with '/': {path!r}")
    url = BASE + path
    key = hashlib.sha256(url.encode()).hexdigest()[:32]
    body_path = os.path.join(_cache_dir(), key + ".body")
    meta_path = os.path.join(_cache_dir(), key + ".json")
    if not refresh and os.path.isfile(body_path) and os.path.isfile(meta_path):
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        if time.time() - float(meta["fetched"]) < ttl:
            with open(body_path, encoding="utf-8") as fh:
                return fh.read()
    text = _fetch(url, timeout).decode("utf-8", "replace")
    tmp = body_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    os.replace(tmp, body_path)
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump({"url": url, "fetched": time.time()}, fh)
    return text


def get_json(path: str, ttl: float, refresh: bool = False) -> Any:
    sep = "&" if "?" in path else "?"
    text = get(path + sep + "json=1", ttl, refresh=refresh)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise SyzbotError(f"syzbot returned non-JSON for {path} (the page format may have changed)") from None
