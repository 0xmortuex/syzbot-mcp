"""syzbot-mcp: an MCP server that fetches and explains syzbot kernel bug reports."""

from __future__ import annotations

import functools
import re
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import client
from . import pages
from . import report as reportmod
from .client import BASE, SyzbotError

mcp = MCPServer(
    "syzbot",
    instructions=(
        "Look up and understand Linux kernel bugs found by syzbot (syzkaller.appspot.com). "
        "syzbot_bugs lists bugs (filter by subsystem or title words); syzbot_bug shows one bug's "
        "status, fix or bisected cause commit and its crashes; syzbot_report parses a crash report "
        "into the bug class, the bad access, symbolized stacks (with allocation/free stacks for "
        "use-after-free) and a plain-English explanation; syzbot_repro returns the C or syz "
        "reproducer. syzbot_explain does the same parsing on report text you already have, "
        "offline. Requests are rate-limited and cached - prefer reusing results over re-fetching."
    ),
)

F = TypeVar("F", bound=Callable[..., Any])

# Failures an agent can act on. MCPServer only forwards a ToolError's message
# to the client - anything else arrives as a bare "Error executing tool X" -
# so these are re-raised as ToolError with their text intact.
_EXPECTED = (SyzbotError, KeyError, ValueError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except _EXPECTED as e:
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            raise ToolError(str(msg)) from e

    mcp.tool()(wrapper)
    return fn


def _ns(namespace: str) -> str:
    return pages.check_name(namespace, "namespace")


def _matches(title: str, query: str | None) -> bool:
    if not query:
        return True
    words = query.lower().split()
    t = title.lower()
    return all(w in t for w in words)


@tool
def syzbot_bugs(namespace: str = "upstream", status: str = "open", subsystem: str | None = None,
                query: str | None = None, limit: int = 20, refresh: bool = False) -> str:
    """List syzbot bugs.

    status: "open" (reported, not fixed), "moderation" (found, not yet
    reported upstream), "fixed" (with fix commits) or "invalid".
    subsystem: a syzbot subsystem name (e.g. "net", "xfs", "bluetooth") - open
    and moderation lists only, since syzbot's fixed/invalid lists don't carry
    subsystems. query: words that must all appear in the title (e.g.
    "use-after-free ext4"). namespace: "upstream" (mainline Linux), or another
    syzbot namespace such as "linux-6.1" or "android-6.1".
    Lists are cached (1h; fixed/invalid 6h) - pass refresh=True for fresh data.
    """
    ns = _ns(namespace)
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if subsystem is not None:
        pages.check_name(subsystem, "subsystem")
    out: list[str] = []
    if status in ("open", "moderation"):
        page = client.get(f"/{ns}", client.TTL_LIST, refresh=refresh)
        rows = pages.parse_bug_table(page, ns, status)
        if subsystem:
            known = sorted({s for r in rows for s in r.subsystems})
            if subsystem not in known:
                raise ValueError(f"no {status} bugs in subsystem {subsystem!r}. Subsystems with "
                                 f"{status} bugs: {', '.join(known)}")
            rows = [r for r in rows if subsystem in r.subsystems]
        rows = [r for r in rows if _matches(r.title, query)]
        out.append(f"{len(rows)} {status} {ns} bugs" + (f" in {subsystem}" if subsystem else "")
                   + (f" matching {query!r}" if query else "") + (f" (showing {limit})" if len(rows) > limit else "") + ":")
        for r in rows[:limit]:
            bits = []
            if r.subsystems:
                bits.append("/".join(r.subsystems))
            bits.append(f"repro: {r.repro}" if r.repro else "no repro")
            if r.cause_bisect:
                bits.append(f"cause bisect: {r.cause_bisect}")
            if r.count:
                bits.append(f"{r.count} crashes")
            if r.last:
                bits.append(f"last {r.last} ago")
            if r.reported:
                bits.append(f"reported {r.reported} ago")
            out.append(f"- {r.title}\n    {BASE}{r.link}  [{'; '.join(bits)}]")
        return "\n".join(out)
    if status in ("fixed", "invalid"):
        if subsystem:
            raise ValueError(f"syzbot's {status} list has no subsystem information - drop "
                             f"subsystem= and use query= with title words instead")
        data = client.get_json(f"/{ns}/{status}", client.TTL_BIG_LIST, refresh=refresh)
        bugs = [b for b in data.get("Bugs", []) if _matches(b.get("title", ""), query)]
        out.append(f"{len(bugs)} {status} {ns} bugs" + (f" matching {query!r}" if query else "")
                   + (f" (showing {limit})" if len(bugs) > limit else "") + ":")
        for b in bugs[:limit]:
            line = f"- {b['title']}\n    {BASE}{b['link']}"
            fixes = b.get("fix-commits") or []
            if fixes:
                line += "\n    fixed by: " + "; ".join(
                    f"{c.get('title', '?')}" + (f" ({c['hash'][:12]})" if c.get("hash") else " (not yet merged)")
                    for c in fixes)
            out.append(line)
        return "\n".join(out)
    raise ValueError('status must be "open", "moderation", "fixed" or "invalid"')


def _commit(c: dict[str, Any]) -> str:
    h = c.get("hash")
    s = f"{c.get('title', '?')}"
    if h:
        s += f" ({h[:12]}"
        if c.get("date"):
            s += f", {c['date'][:10]}"
        s += ")"
    else:
        s += " (not yet in a tree syzbot tracks)"
    if c.get("link"):
        s += f"\n      {c['link']}"
    return s


def _bug_json(bug: str, refresh: bool) -> tuple[pages.BugRef, dict[str, Any]]:
    ref = pages.BugRef(bug)
    data: dict[str, Any] = client.get_json(ref.path, client.TTL_BUG, refresh=refresh)
    return ref, data


@tool
def syzbot_bug(bug: str, namespace: str = "upstream", refresh: bool = False) -> str:
    """Show one syzbot bug: title, subsystems, status, fix commits or the
    bisected cause commit, the crashes (kernel tree/commit, config, whether a
    C/syz reproducer exists) and mailing-list discussions.

    bug: a syzbot URL, an extid (the hex in syzbot+<extid>@syzkaller.appspotmail.com),
    or a 40-hex bug id.
    """
    ns = _ns(namespace)
    ref, d = _bug_json(bug, refresh)
    page = client.get(ref.path, client.TTL_BUG, refresh=refresh)
    subs, labels = pages.bug_labels(page, ns)
    out = [d.get("title", "?"), f"{BASE}{ref.path}"]
    if subs:
        out.append(f"subsystems: {', '.join(subs)}")
    if labels:
        out.append(f"labels: {', '.join(labels)}")
    out.append(f"status: {d.get('status', '?')}")
    out.append(f"crashes: first {d.get('first-crash', '?')[:16]}, last {d.get('last-crash', '?')[:16]}")
    if d.get("fix-commits"):
        out.append("fixed by:")
        out.extend(f"  - {_commit(c)}" for c in d["fix-commits"])
    for key, label in (("cause-commit", "bisected cause (introduced by)"),
                       ("fix-commit", "bisected fix")):
        if d.get(key):
            out.append(f"{label}:\n  - {_commit(d[key])}")
    crashes = d.get("crashes") or []
    if crashes:
        out.append(f"crashes recorded ({len(crashes)}, newest first):")
        for i, c in enumerate(crashes[:10]):
            repro = [k for k, name in (("c-reproducer", "C"), ("syz-reproducer", "syz")) if c.get(k)]
            kinds = ", ".join("C" if k == "c-reproducer" else "syz" for k in repro) or "none"
            tree = c.get("kernel-source-git", "?").rsplit("/", 1)[-1].removesuffix(".git")
            out.append(f"  [{i}] {tree} @ {c.get('kernel-source-commit', '?')[:12]}  repro: {kinds}  "
                       f"config: {BASE}{c['kernel-config']}" if c.get("kernel-config") else
                       f"  [{i}] {tree} @ {c.get('kernel-source-commit', '?')[:12]}  repro: {kinds}")
        if len(crashes) > 10:
            out.append(f"  ... {len(crashes) - 10} more")
        out.append("Next: syzbot_report(bug) to parse the newest crash, syzbot_repro(bug) for the reproducer.")
    for disc in d.get("discussions") or []:
        out.append(f"discussion: {disc}")
    return "\n".join(out)


def _crash(d: dict[str, Any], crash: int, need: str) -> dict[str, Any]:
    crashes = d.get("crashes") or []
    if not crashes:
        raise SyzbotError(f"syzbot lists no crashes for this bug, so there is no {need}")
    if not 0 <= crash < len(crashes):
        raise ValueError(f"crash index {crash} out of range: this bug has {len(crashes)} crash(es), 0..{len(crashes) - 1}")
    c: dict[str, Any] = crashes[crash]
    return c


@tool
def syzbot_report(bug: str, crash: int = 0, max_frames: int = 12, raw: bool = False,
                  refresh: bool = False) -> str:
    """Fetch a bug's crash report and explain it.

    Parses the bug class (KASAN use-after-free/out-of-bounds/null-ptr-deref,
    KCSAN data-race, lockdep, WARNING, UBSAN, oops, hung task...), the bad
    access (read/write, size, address), the faulting function with file:line,
    the allocation/free stacks for use-after-free, lock details for lockdep and
    hung tasks, and summarizes what it means. crash: which crash (0 = newest;
    see syzbot_bug). raw=True returns the unparsed report text.
    """
    _, d = _bug_json(bug, refresh)
    c = _crash(d, crash, "crash report")
    link = c.get("crash-report-link")
    if not link:
        raise SyzbotError("this crash has no report text on syzbot")
    text = client.get(link, client.TTL_TEXT)
    if raw:
        return text
    parsed = reportmod.parse(text)
    head = f"{d.get('title', '?')}\nreport: {BASE}{link}\n"
    return head + "\n" + reportmod.render(parsed, max_frames=max_frames)


@tool
def syzbot_repro(bug: str, kind: str = "c", crash: int | None = None, refresh: bool = False) -> str:
    """Return a bug's reproducer: kind="c" (a C program) or "syz" (a syzkaller
    program, run with syz-execprog). crash: which crash's reproducer; default
    is the newest crash that has one."""
    if kind not in ("c", "syz"):
        raise ValueError('kind must be "c" or "syz"')
    key = "c-reproducer" if kind == "c" else "syz-reproducer"
    _, d = _bug_json(bug, refresh)
    crashes = d.get("crashes") or []
    if crash is not None:
        candidates = [(crash, _crash(d, crash, "reproducer"))]
    else:
        candidates = list(enumerate(crashes))
    for i, c in candidates:
        if c.get(key):
            text = client.get(c[key], client.TTL_TEXT)
            opts = f"\n// repro options: {c['repro-opts']}" if c.get("repro-opts") and kind == "syz" else ""
            return f"// {kind} reproducer for: {d.get('title', '?')} (crash {i})\n// {BASE}{c[key]}{opts}\n\n{text}"
    other = "syz" if kind == "c" else "c"
    has_other = any(c.get("c-reproducer" if other == "c" else "syz-reproducer") for c in crashes)
    raise SyzbotError(f"no {kind} reproducer for this bug" + (f" - a {other} one exists: syzbot_repro(bug, kind={other!r})"
                                                               if has_other else " (syzbot hasn't found one)"))


@tool
def syzbot_explain(text: str, max_frames: int = 12) -> str:
    """Parse and explain kernel crash report text you already have (from a
    syzbot email, a console log, dmesg...). Works offline - no syzbot request."""
    if not text.strip():
        raise ValueError("text is empty - paste the crash report (from the BUG:/WARNING:/Oops: line onward)")
    parsed = reportmod.parse(text)
    if parsed.category == "unknown" and not any(parsed.stacks.values()):
        raise ValueError("no kernel crash report found in this text (looked for BUG:, WARNING:, KASAN:, "
                         "KCSAN:, UBSAN:, Oops:, general protection fault, INFO: task ... blocked)")
    return reportmod.render(parsed, max_frames=max_frames)


def _strip(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
