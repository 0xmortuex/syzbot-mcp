# syzbot-mcp

**Let your AI agent read syzbot kernel bug reports the way a kernel developer does.**

<!-- mcp-name: io.github.0xmortuex/syzbot-mcp -->

[syzbot](https://syzkaller.appspot.com) fuzzes the Linux kernel around the clock and
reports thousands of bugs: KASAN use-after-frees, data races, lockdep splats, WARNINGs,
hung tasks. Each report is a wall of stack traces. syzbot-mcp is an
[MCP](https://modelcontextprotocol.io) server that fetches those bugs and **parses** them
into what matters:

- the bug class
- the bad access
- the faulting line
- for a use-after-free, who allocated and who freed the object
- for a hang, which lock the task is stuck on and who else holds it

A plain-English summary comes on top.

## What it looks like

Real output, from a live bug. `syzbot_report` on
[KASAN: slab-use-after-free Read in tasklet_action_common](https://syzkaller.appspot.com/bug?extid=e91dc13b1b37759b3d9f):

```
KASAN slab-use-after-free: memory from a slab cache was used after it had been freed.
Access: 8-byte read at ffff888035947158 by task syz-executor/5756.
Faulting code: tasklet_action_common (kernel/softirq.c:954).
Object: the access is 344 bytes inside a freed 2048-byte object from cache 'kmalloc-2k' at ffff888035947000.
Allocated by task 9: ath9k_init_wmi (drivers/net/wireless/ath/ath9k/wmi.c:95).
Freed by task 9: ath9k_htc_probe_device (drivers/net/wireless/ath/ath9k/htc_drv_init.c:978).
...
allocated by task 9 stack (19 frames, 8 reporting/allocator frames hidden):
  ath9k_init_wmi (drivers/net/wireless/ath/ath9k/wmi.c:95)
  ath9k_htc_probe_device (drivers/net/wireless/ath/ath9k/htc_drv_init.c:956)
  ...
```

`syzbot_bug` on the same bug adds the bisection result: *introduced by
"wifi: ath9k: Clean up device initialisation guards" (1af8dc9ca726)*, which agrees with
the allocation and free stacks. Both point into ath9k.

A hung task (`syzbot_explain`, offline, on a real report):

```
Hung task: dhcpcd:5279 was stuck in uninterruptible sleep (state D) for more than 146s.
It is blocked in: rtnl_net_lock (include/linux/rtnetlink.h:134, inlined).
It is waiting for: rtnl_mutex (ffffffff90254c40) at inet6_rtm_deladdr+0x249/0x390 net/ipv6/addrconf.c:4835.
6 other task(s) list the same lock - one of them owns it, the rest are waiting too (lockdep's
list doesn't say which). Look for the one NOT blocked in a lock function:
  - kworker/u8:0/12: took it at linkwatch_event+0xe/0x60 net/core/link_watch.c:313
  - kworker/u8:4/59: took it at addrconf_dad_work+0x116/0x15c0 net/ipv6/addrconf.c:4230
  ...
```

Finding the hung task's lock is normally done by hand: you search a 50 KB "Showing all
locks held in the system" dump for the same lock address.

## Install

```bash
pip install syzbot-mcp
claude mcp add syzbot -- syzbot-mcp
```

Python 3.10+, and no dependencies besides `mcp`.

## Tools

| Tool | What it does |
|------|--------------|
| `syzbot_bugs` | List bugs. `status` is open, moderation, fixed or invalid. Filter with `subsystem` (open and moderation lists only) or `query` (words in the title). Shows subsystems, repro availability, crash counts and ages, and fix commits for fixed bugs. |
| `syzbot_bug` | One bug: subsystems, status, fix commits, the bisected cause, crashes (kernel tree and commit, config, C/syz repro) and discussions. Accepts a URL, an extid (also `syzbot+<extid>@syzkaller.appspotmail.com`) or a bug id. |
| `syzbot_report` | Fetch a crash report and parse it: bug class, access, faulting `function (file:line)`, every stack with the reporting, allocator and locking frames hidden, and an explanation. |
| `syzbot_repro` | The C or syz reproducer. If only the other kind exists, the error says so. |
| `syzbot_explain` | The same parsing on report text you already have, such as an email or a console log. Offline. |

The parser understands these report types:
- KASAN: use-after-free, out-of-bounds, null-ptr-deref, double/invalid free and more
- KCSAN data races, with both accesses and their values
- lockdep: recursive, circular and inconsistent-state reports, plus the held-lock list
- WARNING, in the new and old formats
- UBSAN
- general protection faults, page faults and NULL dereferences, including KASAN's
  null-ptr-deref range
- hung tasks
- `kernel BUG at`, RCU stalls and soft lockups

## Being a good citizen

syzbot is a free service. syzbot-mcp:

- **identifies itself.** Every request carries
  `User-Agent: syzbot-mcp/<version> (+https://github.com/0xmortuex/syzbot-mcp)`.
- **rate-limits.** Requests are serialized and spaced 1.5 s apart. You can configure
  this with `SYZBOT_MCP_MIN_INTERVAL`, but never below 1 s.
- **caches on disk** (`SYZBOT_MCP_CACHE`):
  - crash reports, reproducers and configs: 30 days, because they never change
  - bug pages: 15 minutes
  - bug lists: 1 hour, or 6 hours for the multi-MB fixed and invalid lists
- **backs off once** on HTTP 429/503, honouring `Retry-After`, and then reports the
  failure. It never retries in a loop.
- **uses the JSON syzbot offers** (`?json=1`) wherever it exists. It parses HTML only for
  the open-bug table, which has the subsystems and repro columns the JSON lacks, and for a
  bug's subsystem labels. robots.txt allows all of these.

Normal test runs and CI on every push send syzbot nothing. A weekly CI job makes about
six requests to catch changes in syzbot's page format.

## Tests

```bash
pip install ".[test]" "ruff==0.16.0" "mypy==2.3.0"
ruff check src tests && mypy --strict src
pytest tests                       # offline
SYZBOT_LIVE=1 pytest tests/test_live.py   # ~6 real requests
```

The parser is tested on 9 real crash reports in
[`tests/fixtures/reports`](tests/fixtures/reports), each one's source URL recorded in
`SOURCES.json`. They cover KASAN use-after-free, out-of-bounds and null-ptr-deref, a KCSAN
data race, lockdep recursion, a new-format WARNING, UBSAN shift, a GPF with a KASAN range,
and a hung task. Page parsing is tested on trimmed real HTML from the dashboard. The
cache and rate limiter are tested with real timing and a fake network. A stdio test
checks that error messages reach the client.

## Limitations

- **Format drift:** syzbot's HTML has no stability promise. If the open-bug table changes,
  `syzbot_bugs` fails with an error naming the tables it did find. The weekly live job
  exists to notice this.
- **Subsystem filter:** works on open and moderation bugs only, because syzbot's
  fixed/invalid JSON has no subsystems.
- **Hung tasks:** lockdep's held-lock list doesn't say which task owns a contended lock.
  The tool lists every task holding or waiting on it and says so.
- **Not decoded:** register dumps and `Code:` bytes.

## License

MIT
