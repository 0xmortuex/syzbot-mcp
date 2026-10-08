"""Turning syzbot pages into data: bug ids, the open-bug HTML table, labels."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse


class BugRef:
    """A bug identifier: extid (20 hex, in syzbot's emails) or id (40 hex)."""

    def __init__(self, raw: str):
        s = raw.strip()
        if s.startswith(("http://", "https://")) or s.startswith("/bug?"):
            q = parse_qs(urlparse(s).query)
            if "extid" in q:
                s = q["extid"][0]
            elif "id" in q:
                s = q["id"][0]
            else:
                raise ValueError(f"{raw!r} is not a syzbot bug URL (expected ?extid= or ?id=)")
        m = re.fullmatch(r"(?:syzbot\+)?([0-9a-f]{20})(?:@syzkaller\.appspotmail\.com)?", s)
        if m:
            self.key, self.value = "extid", m.group(1)
            return
        if re.fullmatch(r"[0-9a-f]{40}", s):
            self.key, self.value = "id", s
            return
        raise ValueError(
            f"{raw!r} isn't a syzbot bug reference. Pass a bug URL, an extid (20 hex chars, e.g. "
            f"from syzbot+<extid>@syzkaller.appspotmail.com), or a 40-hex bug id - "
            f"syzbot_bugs lists bugs with their links.")

    @property
    def path(self) -> str:
        return f"/bug?{self.key}={self.value}"


def check_name(value: str, what: str) -> str:
    if not re.fullmatch(r"[\w.-]+", value):
        raise ValueError(f"invalid {what} {value!r}: letters, digits, '.', '-' and '_' only")
    return value


@dataclass
class BugRow:
    title: str
    link: str
    subsystems: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    repro: str = ""
    cause_bisect: str = ""
    fix_bisect: str = ""
    count: str = ""
    last: str = ""
    reported: str = ""
    fix_commits: list[str] = field(default_factory=list)


def _text(fragment: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", fragment)).strip()


def parse_bug_table(page: str, ns: str, section: str = "open") -> list[BugRow]:
    """Rows of the bug table whose caption starts with `section` ("open",
    "moderation"). Column order (Title, Rank, Repro, Cause bisect, Fix bisect,
    Count, Last, Reported, ...) is taken from the table header, not assumed."""
    tables = list(re.finditer(r'<table class="list_table">(.*?)</table>', page, re.S))
    captions: list[str] = []
    prev_end = 0
    for t in tables:
        body = t.group(1)
        # The heading is a <caption> inside the table, or (on the main bug
        # list) a <summary class="bug_list_caption"> just before it.
        cap = re.search(r"<caption[^>]*>(.*?)</caption>", body, re.S)
        summaries = re.findall(r'<summary class="bug_list_caption">(.*?)</summary>',
                               page[prev_end:t.start()], re.S)
        prev_end = t.end()
        caption = _text(cap.group(1)) if cap else (_text(summaries[-1]) if summaries else "")
        captions.append(" ".join(caption.split()))
        if not re.match(rf"\s*{re.escape(section)}\b", caption, re.I):
            continue
        headers = [_text(h).split("\n")[0].strip().lower()
                   for h in re.findall(r"<th[^>]*>(.*?)</th>", body, re.S)]
        rows = []
        for tr in re.findall(r"<tr>(.*?)</tr>", body, re.S):
            cells = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
            if len(cells) < 2:
                continue
            link = re.search(r'<a href="(/bug\?[^"]+)">(.*?)</a>', cells[0], re.S)
            if not link:
                continue
            row = BugRow(title=_text(link.group(2)), link=html.unescape(link.group(1)))
            for href, label in re.findall(r'class="bug-label"><a href="([^"]+)">([^<]+)</a>', cells[0]):
                label = _text(label)
                if re.match(rf"^/{re.escape(ns)}/s/", href):
                    row.subsystems.append(label)
                else:
                    row.labels.append(label)
            values = dict(zip(headers, (_text(c) for c in cells)))
            row.repro = values.get("repro", "")
            row.cause_bisect = values.get("cause bisect", "")
            row.fix_bisect = values.get("fix bisect", "")
            row.count = values.get("count", "")
            row.last = values.get("last", "")
            row.reported = values.get("reported", "")
            rows.append(row)
        return rows
    raise ValueError(f"no '{section}' bug table on this page (tables: {', '.join(c for c in captions if c) or 'none'})")


def bug_labels(page: str, ns: str) -> tuple[list[str], list[str]]:
    """(subsystems, other labels) of the bug itself. Labels further down the
    page belong to similar bugs in other namespaces, so only those before the
    first table count."""
    head = page[: page.find("<table")] if "<table" in page else page
    subs: list[str] = []
    other: list[str] = []
    for href, label in re.findall(r'class="bug-label"><a href="([^"]+)">([^<]+)</a>', head):
        (subs if re.match(rf"^/{re.escape(ns)}/s/", href) else other).append(_text(label))
    return subs, other
