"""Page parsing on real (trimmed) syzbot HTML, bug references, and the polite
client's cache and rate limiting - all without network."""

import json
import os
import time

import pytest

from syzbot_mcp import client, pages

HERE = os.path.join(os.path.dirname(__file__), "fixtures", "pages")


def read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return fh.read()


def test_open_and_moderation_tables():
    page = read("upstream.html")
    rows = pages.parse_bug_table(page, "upstream", "open")
    assert len(rows) == 15
    first = rows[0]
    assert first.title == "inconsistent lock state in ccp_raw_event"
    assert first.link == "/bug?extid=0f98b0c0bdeaab2dc2fd"
    assert first.subsystems == ["hwmon"] and first.labels == ["prio:low"]
    assert first.repro == "C" and first.count == "47"
    assert len(pages.parse_bug_table(page, "upstream", "moderation")) == 5
    with pytest.raises(ValueError, match="no 'fixed' bug table.*open"):
        pages.parse_bug_table(page, "upstream", "fixed")


def test_bug_labels_ignore_other_namespaces():
    subs, labels = pages.bug_labels(read("bug_e91dc13b1b37759b3d9f.html"), "upstream")
    assert subs == ["wireless"] and labels == ["prio:high"]  # not linux-4.19's ext4


@pytest.mark.parametrize("raw,path", [
    ("e91dc13b1b37759b3d9f", "/bug?extid=e91dc13b1b37759b3d9f"),
    ("syzbot+e91dc13b1b37759b3d9f@syzkaller.appspotmail.com", "/bug?extid=e91dc13b1b37759b3d9f"),
    ("https://syzkaller.appspot.com/bug?extid=e91dc13b1b37759b3d9f", "/bug?extid=e91dc13b1b37759b3d9f"),
    ("b996cc5aef7ac7c49e6ce8ef24e64cdbc35cbd03", "/bug?id=b996cc5aef7ac7c49e6ce8ef24e64cdbc35cbd03"),
    ("https://syzkaller.appspot.com/bug?id=b996cc5aef7ac7c49e6ce8ef24e64cdbc35cbd03",
     "/bug?id=b996cc5aef7ac7c49e6ce8ef24e64cdbc35cbd03"),
])
def test_bug_refs(raw, path):
    assert pages.BugRef(raw).path == path


def test_bad_bug_ref_is_instructive():
    with pytest.raises(ValueError, match="extid .20 hex chars"):
        pages.BugRef("not-a-bug")


@pytest.fixture
def fake_fetch(monkeypatch, tmp_path):
    monkeypatch.setenv("SYZBOT_MCP_CACHE", str(tmp_path))
    calls = []

    def fetch(url, timeout):
        calls.append((url, time.monotonic()))
        return json.dumps({"url": url, "n": len(calls)}).encode()

    # Real throttling, fake network.
    monkeypatch.setattr(client, "_network", fetch)
    return calls


def test_cache_hits_skip_the_network(fake_fetch):
    a = client.get_json("/bug?extid=x", ttl=60)
    b = client.get_json("/bug?extid=x", ttl=60)
    assert a == b and len(fake_fetch) == 1
    c = client.get_json("/bug?extid=x", ttl=60, refresh=True)
    assert c["n"] == 2 and len(fake_fetch) == 2


def test_expired_cache_refetches(fake_fetch):
    client.get("/a", ttl=60)
    client.get("/a", ttl=0)
    assert len(fake_fetch) == 2


def test_requests_are_spaced_at_least_a_second(fake_fetch, monkeypatch):
    monkeypatch.setenv("SYZBOT_MCP_MIN_INTERVAL", "0.1")  # clamped up to 1.0
    assert client.min_interval() == 1.0
    client.get("/p1", ttl=60)
    client.get("/p2", ttl=60)
    gap = fake_fetch[1][1] - fake_fetch[0][1]
    assert gap >= 0.95, gap


def test_user_agent_identifies_the_project():
    assert "syzbot-mcp/" in client.USER_AGENT and "github.com/0xmortuex/syzbot-mcp" in client.USER_AGENT
