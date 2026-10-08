"""Against the real syzbot dashboard. Skipped unless SYZBOT_LIVE=1, so normal
test runs (and CI on every push) never send it requests. The whole module
makes about six requests, spaced by the client's rate limit, and uses a
throwaway cache so results are really fetched."""

import os

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("SYZBOT_LIVE") != "1",
                                reason="set SYZBOT_LIVE=1 to test against syzkaller.appspot.com")

from syzbot_mcp import server as S  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def cache(tmp_path_factory):
    old = os.environ.get("SYZBOT_MCP_CACHE")
    os.environ["SYZBOT_MCP_CACHE"] = str(tmp_path_factory.mktemp("syzbot-cache"))
    yield
    if old is None:
        os.environ.pop("SYZBOT_MCP_CACHE")
    else:
        os.environ["SYZBOT_MCP_CACHE"] = old


def test_open_list_has_subsystems_and_repro_info():
    out = S.syzbot_bugs(limit=5)
    assert "open upstream bugs" in out and "https://syzkaller.appspot.com/bug?" in out
    assert "repro" in out


def test_bug_report_and_repro_round_trip():
    # Take a bug that has a C reproducer from the open list, then follow it.
    listing = S.syzbot_bugs(query="KASAN", limit=50)
    lines = [ln for ln in listing.splitlines() if "repro: C" in ln or "repro: syz, C" in ln]
    if not lines:
        pytest.skip("no open KASAN bug with a C reproducer right now")
    idx = listing.splitlines().index(lines[0])
    url = listing.splitlines()[idx].split()[0]
    bug = S.syzbot_bug(url)
    assert "status:" in bug and "crashes recorded" in bug
    rep = S.syzbot_report(url, max_frames=3)
    assert "KASAN" in rep and "stack (" in rep
    repro = S.syzbot_repro(url, kind="c")
    # Usually syzkaller-generated, but some C reproducers are hand-written by
    # reporters - both are C programs with a main().
    assert repro.startswith("// c reproducer for:") and "main(" in repro
