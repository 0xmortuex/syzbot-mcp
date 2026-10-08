"""Parse and explain Linux kernel crash reports as syzbot prints them.

Everything here works offline on the report text, so it is unit-tested on
real reports committed under tests/fixtures. The shapes handled:

  KASAN    BUG: KASAN: slab-use-after-free in f+0x5c8/0x760 file.c:202
           Read of size 1 at addr ffff... by task kworker/u33:8/1163
           ... "Allocated by task N:" / "Freed by task N:" stacks,
           "The buggy address belongs to the object at ..."
  KCSAN    BUG: KCSAN: data-race in a / b, two "write to 0x.. of 4 bytes by
           task N on cpu C:" access stacks and "value changed: x -> y"
  lockdep  WARNING: possible recursive locking detected / possible circular
           locking dependency detected / inconsistent lock state ...
  WARNING  WARNING: file.c:2353 at f+0x.. file.c:2352, CPU#0: comm/pid  (new)
           WARNING: CPU: 0 PID: 1 at file.c:12 f+0x../0x..               (old)
  UBSAN    UBSAN: shift-out-of-bounds in file.c:3950:27  + one detail line
  Oops     Oops: general protection fault, probably for non-canonical address
           (with "KASAN: null-ptr-deref in range [a-b]"), BUG: unable to handle
           page fault / kernel paging request / kernel NULL pointer dereference
  hung     INFO: task comm:pid blocked for more than N seconds.
  other    kernel BUG at file.c:N!, INFO: rcu detected stall, BUG: soft lockup...
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

FRAME_RE = re.compile(
    r"^\s*(?:\?\s+)?(?P<func>[A-Za-z_.$][\w.$]*)"
    r"(?:\+(?P<off>0x[0-9a-f]+)/(?P<size>0x[0-9a-f]+))?"
    r"(?:\s+\[(?P<module>[\w-]+)\])?"
    r"(?:\s+(?P<file>[\w./+-]+\.(?:c|h|S|rs|s)):(?P<line>\d+)(?::\d+)?)?"
    r"(?P<inline>\s+\[inline\])?\s*$"
)

# Frames that belong to the reporting machinery, not to the bug.
_NOISE_FUNCS = re.compile(
    r"^(__dump_stack|dump_stack(_lvl)?|show_stack|print_report|print_address_description|"
    r"kasan_report|__kasan_\w+|kasan_\w+|check_region_inline|__asan_\w+|"
    r"instrument_\w+|atomic\w*|arch_atomic\w*|raw_atomic\w*|"
    r"ubsan_\w+|__ubsan_handle_\w+|"
    r"lock_acquire|__lock_acquire|lock_release|validate_chain|check_deadlock|check_prev_add|"
    r"check_prevs_add|check_noncircular|print_\w*bug\w*|print_circular_bug\w*|"
    r"print_deadlock_bug\w*|lockdep_\w+|mark_lock\w*|"
    r"report_bug|handle_bug|exc_invalid_op|asm_exc_invalid_op|__warn|warn_slowpath_fmt|"
    r"context_switch|__schedule|__schedule_loop|schedule|schedule_preempt_disabled|"
    r"schedule_timeout|io_schedule|__mutex_lock\w*|mutex_lock\w*|__down\w*|down\w*|"
    r"rwsem_down_\w+|__rwsem_\w+|wait_for_completion\w*|__wait_for_common|"
    r"stack_trace_save|save_stack|kmsan_\w+|kcsan_\w+)$"
)
_NOISE_FILES = re.compile(
    r"^(mm/kasan/|lib/ubsan\.c|kernel/locking/lockdep|include/linux/instrumented\.h|"
    r"include/linux/atomic/|lib/dump_stack\.c|kernel/kcsan/|kernel/sched/core\.c)"
)
# In "Allocated by"/"Freed by" stacks the allocator itself is noise: the
# interesting frame is whoever called kmalloc()/kfree().
_ALLOC_FUNCS = re.compile(
    r"^(kmalloc\w*|__kmalloc\w*|_kmalloc\w*|kzalloc\w*|kcalloc\w*|krealloc\w*|kvmalloc\w*|"
    r"__kvmalloc\w*|kvfree\w*|kfree\w*|kmem_cache_\w+|slab_\w+|___slab_alloc|__slab_\w+|"
    r"kmemdup\w*|kstrdup\w*|__kvzalloc\w*|kvzalloc\w*|alloc_pages\w*|__alloc_pages\w*|"
    r"rcu_do_batch|rcu_core|rcu_core_si|kfree_rcu\w*)$"
)
_ALLOC_FILES = re.compile(r"^(mm/slub\.c|mm/slab\w*\.c|include/linux/slab\.h|mm/util\.c|mm/page_alloc\.c)")
_ENTRY_FUNCS = re.compile(
    r"^(entry_SYSCALL\w*|do_syscall_\w+|x64_sys_call|ret_from_fork\w*|kthread|"
    r"worker_thread|process_one_work|process_scheduled_works|asm_\w+|"
    r"__do_softirq|handle_softirqs|irq_exit\w*|common_interrupt|"
    r"do_initcall\w*|kernel_init\w*|start_kernel|secondary_startup_\w+)$"
)


@dataclass
class Frame:
    func: str
    offset: str | None
    file: str | None
    line: int | None
    inline: bool
    module: str | None = None

    @property
    def is_noise(self) -> bool:
        return bool(_NOISE_FUNCS.match(self.func) or (self.file and _NOISE_FILES.match(self.file)))

    def where(self) -> str:
        loc = f"{self.file}:{self.line}" if self.file else "?"
        mod = f" [{self.module}]" if self.module else ""
        return f"{self.func}{mod} ({loc}{', inlined' if self.inline else ''})"


@dataclass
class Access:
    op: str  # "read" | "write"
    size: int | None
    addr: str | None
    task: str | None = None
    cpu: str | None = None
    marked: bool = False


@dataclass
class Report:
    category: str  # kasan | kcsan | lockdep | warning | ubsan | oops | hung | bug | unknown
    headline: str
    kind: str = ""  # e.g. slab-use-after-free, data-race, shift-out-of-bounds
    location: str | None = None  # where the report itself says it happened
    access: Access | None = None
    accesses: list[Access] = field(default_factory=list)  # KCSAN
    stacks: dict[str, list[Frame]] = field(default_factory=dict)
    details: dict[str, str] = field(default_factory=dict)
    locks: list[str] = field(default_factory=list)

    def culprit(self, stack: str | None = None) -> Frame | None:
        """First frame that isn't reporting/locking machinery (and, for
        allocation/free stacks, isn't the allocator itself)."""
        frames = self.stacks.get(stack) if stack else next(iter(self.stacks.values()), None)
        if not frames:
            return None
        alloc = bool(stack and stack.startswith(("allocated", "freed")))
        for f in frames:
            if f.is_noise:
                continue
            if alloc and (_ALLOC_FUNCS.match(f.func) or (f.file and _ALLOC_FILES.match(f.file))):
                continue
            return f
        return frames[0]


def parse_frames(lines: list[str]) -> list[Frame]:
    out = []
    for ln in lines:
        s = ln.strip()
        if not s or s in ("<TASK>", "</TASK>", "<IRQ>", "</IRQ>", "<NMI>", "</NMI>",
                          "<SOFTIRQ>", "</SOFTIRQ>"):
            continue
        m = FRAME_RE.match(ln)
        if not m or (m.group("file") is None and m.group("off") is None):
            continue
        out.append(Frame(
            func=m.group("func"),
            offset=m.group("off"),
            file=m.group("file"),
            line=int(m.group("line")) if m.group("line") else None,
            inline=bool(m.group("inline")),
            module=m.group("module"),
        ))
    return out


def _block_after(lines: list[str], start: int) -> list[str]:
    """Lines of an indented stack following a header line, until a blank line
    or a line that isn't a frame / task marker."""
    out = []
    for ln in lines[start + 1:]:
        s = ln.strip()
        if not s:
            break
        if s.startswith(("<", "RIP:", "Code:", "RSP:", "RAX:", "RBX:", "RDX:", "RBP:", "R08:",
                         "R10:", "R13:")) and s not in ("<TASK>", "</TASK>", "<IRQ>", "</IRQ>"):
            if s.startswith("RIP:") or s.startswith("Code:"):
                continue
            if s.startswith("R"):
                continue
        if not (ln.startswith(" ") or s in ("<TASK>", "</TASK>")):
            break
        out.append(ln)
    return out


def _call_trace(lines: list[str], after: int = 0) -> list[Frame]:
    for i in range(after, len(lines)):
        if lines[i].strip().startswith("Call Trace:"):
            return parse_frames(_block_after(lines, i))
    return []


_KASAN_RE = re.compile(r"^BUG: KASAN: (?P<kind>[\w-]+) in (?P<loc>.+)$")
_KASAN_ACCESS_RE = re.compile(
    r"^(?P<op>Read|Write) of size (?P<size>\d+) at addr (?P<addr>[0-9a-fx]+) by task (?P<task>.+)$")
_KCSAN_RE = re.compile(r"^BUG: KCSAN: (?P<kind>[\w-]+) in (?P<loc>.+)$")
_KCSAN_ACCESS_RE = re.compile(
    r"^(?P<op>read|write)(?P<marked> \(marked\))?(?: \(reordered\))? to (?P<addr>[0-9a-fx]+) "
    r"of (?P<size>\d+) bytes by (?P<who>task \d+|interrupt) on cpu (?P<cpu>\d+):$")
_UBSAN_RE = re.compile(r"^UBSAN: (?P<kind>[\w-]+) in (?P<loc>\S+)")
_WARN_NEW_RE = re.compile(r"^WARNING: (?P<file>\S+:\d+) at (?P<func>\S+)(?: (?P<src>\S+))?, CPU#(?P<cpu>\d+): (?P<task>\S+)")
_WARN_OLD_RE = re.compile(r"^WARNING: CPU: (?P<cpu>\d+) PID: (?P<pid>\d+) at (?P<file>\S+) (?P<func>\S+)")
_LOCKDEP_RE = re.compile(
    r"^WARNING: (?P<kind>possible recursive locking detected|possible circular locking dependency detected|"
    r"inconsistent lock state|possible irq lock inversion dependency detected|"
    r"suspicious RCU usage|bad unlock balance detected!|held lock freed!|"
    r"lock held when returning to user space!|.*locking bug.*|"
    r"(?:SOFTIRQ|HARDIRQ)-(?:safe|unsafe) -> \S+ lock order detected)")
_OOPS_RE = re.compile(
    r"^(?:Oops: )?(?P<what>general protection fault[^:]*|BUG: unable to handle page fault for address: \S+|"
    r"BUG: unable to handle kernel paging request at \S+|BUG: kernel NULL pointer dereference, address: \S+|"
    r"BUG: unable to handle kernel NULL pointer dereference at \S+|stack segment[^:]*|"
    r"Oops: \S.*)")
_HUNG_RE = re.compile(r"^INFO: task (?P<task>\S+) blocked for more than (?P<secs>\d+) seconds\.")
_RIP_RE = re.compile(r"^RIP: 0010:(?P<func>\S+?)(?:\s+(?P<file>\S+:\d+))?$")


def _first(lines: list[str], rx: re.Pattern[str]) -> tuple[int, re.Match[str]] | None:
    for i, ln in enumerate(lines):
        m = rx.match(ln.strip())
        if m:
            return i, m
    return None


def parse(text: str) -> Report:
    lines = text.replace("\r\n", "\n").split("\n")

    hit = _first(lines, _KASAN_RE)
    if hit:
        return _parse_kasan(lines, hit)
    hit = _first(lines, _KCSAN_RE)
    if hit:
        return _parse_kcsan(lines, hit)
    hit = _first(lines, _LOCKDEP_RE)
    if hit:
        return _parse_lockdep(lines, hit)
    hit = _first(lines, _UBSAN_RE)
    if hit:
        i, m = hit
        r = Report("ubsan", lines[i].strip(), kind=m.group("kind"), location=m.group("loc"))
        if i + 1 < len(lines) and lines[i + 1].strip():
            r.details["detail"] = lines[i + 1].strip()
        r.stacks["crash"] = _call_trace(lines, i)
        return r
    hit = _first(lines, _OOPS_RE)
    if hit:
        return _parse_oops(lines, hit)
    hit = _first(lines, _WARN_NEW_RE) or _first(lines, _WARN_OLD_RE)
    if hit:
        return _parse_warning(lines, hit)
    hit = _first(lines, _HUNG_RE)
    if hit:
        i, m = hit
        r = Report("hung", lines[i].strip(), kind="task hung", details={"task": m.group("task"),
                                                                        "seconds": m.group("secs")})
        r.stacks[f"blocked task {m.group('task')}"] = _call_trace(lines, i)
        _analyze_hung_locks(r, lines, m.group("task"))
        return r
    for rx, cat in ((re.compile(r"^kernel BUG at (?P<loc>\S+)!"), "bug"),
                    (re.compile(r"^(?P<loc>INFO: rcu (?:detected stall|_sched self-detected stall).*)"), "bug"),
                    (re.compile(r"^(?P<loc>BUG: (?:soft lockup|workqueue lockup|scheduling while atomic|"
                                r"sleeping function called from invalid context|.+))"), "bug")):
        hit = _first(lines, rx)
        if hit:
            i, m = hit
            r = Report(cat, lines[i].strip(), kind=lines[i].strip().split(" at ")[0], location=m.group("loc"))
            r.stacks["crash"] = _call_trace(lines, i)
            return r
    r = Report("unknown", next((ln.strip() for ln in lines if ln.strip()), ""))
    r.stacks["crash"] = _call_trace(lines)
    return r


# "locks held by kworker/u8:0/12: 4, last CPU#0:" (task names contain colons)
# and the older "2 locks held by syz-executor/123:".
_HELD_TASK_RE = re.compile(r"^(?:\d+ )?locks? held by (?P<task>.+?):(?:\s+\d+,.*)?$")
_HELD_LOCK_RE = re.compile(r"^\s*#(?P<n>\d+): (?P<addr>\S+) \((?P<name>.*)\)\{[^{}]*\}-\{\d+:\d+\}, at: (?P<at>.+)$")


def held_locks(lines: list[str]) -> dict[str, list[tuple[str, str, str]]]:
    """The "Showing all locks held in the system" section: task -> [(addr,
    name, where)], one entry per lock (the last, most specific `at:` line)."""
    out: dict[str, dict[str, tuple[str, str, str]]] = {}
    task: str | None = None
    for ln in lines:
        s = ln.strip()
        tm = _HELD_TASK_RE.match(s)
        if tm:
            task = tm.group("task").rstrip(":")
            out.setdefault(task, {})
            continue
        lm = _HELD_LOCK_RE.match(ln)
        if lm and task is not None:
            out[task][lm.group("n")] = (lm.group("addr"), lm.group("name"), lm.group("at").strip())
    return {t: list(v.values()) for t, v in out.items() if v}


def _analyze_hung_locks(r: Report, lines: list[str], task: str) -> None:
    held = held_locks(lines)
    me = task.replace(":", "/", 1)  # "dhcpcd:5279" in the headline, "dhcpcd/5279" in lock lists
    mine = held.get(me)
    if not mine:
        return
    # lockdep records a lock before the task sleeps on it, so the blocked
    # task's last listed lock is the one it is waiting for.
    addr, name, at = mine[-1]
    r.details["waiting for"] = f"{name} ({addr}) at {at}"
    others = [(t, w) for t, locks in held.items() if t != me for a, n, w in locks if a == addr]
    r.details["same lock listed by"] = str(len(others))
    r.locks = [f"{t}: took it at {w}" for t, w in others]


def _parse_kasan(lines: list[str], hit: tuple[int, re.Match[str]]) -> Report:
    i, m = hit
    # Several "BUG: KASAN: kind in X [inline]" lines may precede the real one.
    j = i
    while j + 1 < len(lines) and _KASAN_RE.match(lines[j + 1].strip()):
        j += 1
    last = _KASAN_RE.match(lines[j].strip())
    assert last is not None
    r = Report("kasan", lines[j].strip(), kind=m.group("kind"), location=last.group("loc"))
    acc = _first(lines[j:], _KASAN_ACCESS_RE)
    if acc:
        _, a = acc
        r.access = Access(a.group("op").lower(), int(a.group("size")), a.group("addr"), a.group("task"))
    r.stacks["crash"] = _call_trace(lines, j)
    for k, ln in enumerate(lines):
        s = ln.strip()
        mm = re.match(r"^(Allocated|Freed) by task (\d+)(?: on cpu \d+)?(?: at [\d.]+s)?:$", s)
        if mm:
            r.stacks[f"{mm.group(1).lower()} by task {mm.group(2)}"] = parse_frames(_block_after(lines, k))
        mm = re.match(r"^Last potentially related work creation:$", s)
        if mm:
            r.stacks["last work creation"] = parse_frames(_block_after(lines, k))
    text = "\n".join(lines)
    obj = re.search(r"The buggy address belongs to the object at (\S+)\n\s*which belongs to the cache (\S+) of size (\d+)", text)
    if obj:
        r.details["object"] = obj.group(1)
        r.details["cache"] = obj.group(2)
        r.details["object size"] = obj.group(3)
    loc = re.search(r"The buggy address is located (\d+) bytes (inside|to the right|to the left) of\n\s*(\w+) (\d+)-byte region \[([^)]+)\)", text)
    if loc:
        r.details["offset"] = loc.group(1)
        r.details["relation"] = loc.group(2)
        r.details["region state"] = loc.group(3)
        r.details["region size"] = loc.group(4)
    rng = re.search(r"KASAN: null-ptr-deref in range \[(\S+)\]", text)
    if rng:
        r.details["range"] = rng.group(1)
    return r


def _parse_kcsan(lines: list[str], hit: tuple[int, re.Match[str]]) -> Report:
    i, m = hit
    r = Report("kcsan", lines[i].strip(), kind=m.group("kind"), location=m.group("loc"))
    for k in range(i, len(lines)):
        a = _KCSAN_ACCESS_RE.match(lines[k].strip())
        if a:
            acc = Access(a.group("op"), int(a.group("size")), a.group("addr"), a.group("who"),
                         a.group("cpu"), bool(a.group("marked")))
            r.accesses.append(acc)
            r.stacks[f"{acc.op}{' (marked)' if acc.marked else ''} by {acc.task} on cpu {acc.cpu}"] = \
                parse_frames(_block_after(lines, k))
    vc = re.search(r"value changed: (\S+) -> (\S+)", "\n".join(lines))
    if vc:
        r.details["value changed"] = f"{vc.group(1)} -> {vc.group(2)}"
    return r


def _parse_lockdep(lines: list[str], hit: tuple[int, re.Match[str]]) -> Report:
    i, m = hit
    r = Report("lockdep", lines[i].strip(), kind=m.group("kind"))
    text = "\n".join(lines)
    want = re.search(r"is trying to acquire lock:\n(\S+) \(([^)]*(?:\)[^{]*)?)\)\{[^}]*\}-\{[^}]*\}, at: (.+)", text)
    held = re.search(r"but task is already holding lock:\n(\S+) \(([^)]*(?:\)[^{]*)?)\)\{[^}]*\}-\{[^}]*\}, at: (.+)", text)
    if want:
        r.details["acquiring"] = f"{want.group(2)} at {want.group(3).strip()}"
    if held:
        r.details["already holding"] = f"{held.group(2)} at {held.group(3).strip()}"
        if want and want.group(1) == held.group(1):
            r.details["same instance"] = "yes - the very same lock object is taken twice"
    holders = re.findall(r"^\s*#\d+: \S+ \(([^)]+(?:\)[^{]*)?)\)\{[^}]*\}-\{[^}]*\}, at: (.+)$", text, re.M)
    seen: list[str] = []
    for name, at in holders:
        entry = f"{name} at {at.strip()}"
        if not any(e.startswith(name + " ") for e in seen):
            seen.append(entry)
    r.locks = seen
    scen = re.search(r"Possible unsafe locking scenario:\n(.*?)\n\s*\*\*\* DEADLOCK \*\*\*", text, re.S)
    if scen:
        r.details["scenario"] = "\n".join(ln.rstrip() for ln in scen.group(1).splitlines() if ln.strip())
    # The interesting stack is after "stack backtrace:".
    idx = next((k for k, ln in enumerate(lines) if ln.strip() == "stack backtrace:"), i)
    r.stacks["crash"] = _call_trace(lines, idx)
    return r


def _parse_oops(lines: list[str], hit: tuple[int, re.Match[str]]) -> Report:
    i, m = hit
    r = Report("oops", lines[i].strip(), kind=m.group("what").split(",")[0])
    text = "\n".join(lines)
    rng = re.search(r"KASAN: (null-ptr-deref|maybe wild-memory-access|probably user-memory-access) in range \[(\S+)\]", text)
    if rng:
        r.details["KASAN"] = f"{rng.group(1)} in range [{rng.group(2)}]"
        if rng.group(1) == "null-ptr-deref":
            r.kind = "null pointer dereference"
    addr = re.search(r"(?:address: |at |address )(0x[0-9a-f]+|[0-9a-f]{16})", lines[i])
    if addr:
        r.details["address"] = addr.group(1)
    for ln in lines[i:]:
        rm = _RIP_RE.match(ln.strip())
        if rm:
            r.location = f"{rm.group('func')} {rm.group('file') or ''}".strip()
            break
    r.stacks["crash"] = _call_trace(lines, i)
    if r.location:
        fm = FRAME_RE.match(r.location)
        if fm and fm.group("file"):
            r.stacks["crash"].insert(0, Frame(fm.group("func"), fm.group("off"), fm.group("file"),
                                              int(fm.group("line")), False))
    return r


def _parse_warning(lines: list[str], hit: tuple[int, re.Match[str]]) -> Report:
    i, m = hit
    func = m.group("func").split("+")[0]
    r = Report("warning", lines[i].strip(), kind="WARNING", location=f"{m.group('file')} (in {func})")
    # The message printed just before the WARNING line, after "cut here".
    for k in range(i - 1, max(-1, i - 4), -1):
        s = lines[k].strip()
        if not s or "cut here" in s:
            break
        r.details["message"] = s
        break
    r.stacks["crash"] = _call_trace(lines, i)
    fm = FRAME_RE.match(m.group("func") + (" " + m.group("src") if "src" in m.groupdict() and m.group("src") else ""))
    if fm and fm.group("file"):
        r.stacks["crash"].insert(0, Frame(fm.group("func"), fm.group("off"), fm.group("file"),
                                          int(fm.group("line")), False))
    return r


# -- explanation ----------------------------------------------------------------

_KASAN_MEANING = {
    "slab-use-after-free": "memory from a slab cache was used after it had been freed",
    "use-after-free": "memory was used after it had been freed",
    "vmalloc-use-after-free": "vmalloc'd memory was used after it had been freed",
    "slab-out-of-bounds": "an access ran past the end (or before the start) of a slab object",
    "global-out-of-bounds": "an access ran outside a global variable",
    "stack-out-of-bounds": "an access ran outside a stack variable",
    "vmalloc-out-of-bounds": "an access ran outside a vmalloc'd buffer",
    "null-ptr-deref": "a NULL (or near-NULL) pointer was dereferenced",
    "wild-memory-access": "an access hit an address that was never valid kernel memory",
    "double-free": "the same object was freed twice",
    "invalid-free": "kfree() was given a pointer that isn't the start of an allocated object",
    "stack-use-after-return": "a pointer to a stack variable was used after its function returned",
    "user-memory-access": "kernel code dereferenced a user-space address directly",
}

_LOCKDEP_MEANING = {
    "possible recursive locking detected":
        "a task tried to take a lock (class) it already holds - a self-deadlock unless the two "
        "acquisitions are of different instances and annotated with a nesting level",
    "possible circular locking dependency detected":
        "two (or more) code paths take the same locks in opposite orders (an ABBA pattern) - "
        "run concurrently, they can deadlock",
    "inconsistent lock state":
        "a lock is taken both with interrupts enabled and from interrupt context, so the "
        "interrupt can arrive while the lock is held and deadlock on it",
    "possible irq lock inversion dependency detected":
        "lock ordering conflicts with how locks are used from interrupt context",
    "suspicious RCU usage": "an RCU-protected pointer was used without the required protection",
}

_UBSAN_MEANING = {
    "shift-out-of-bounds": "a shift by a negative amount or by >= the type's width (undefined in C)",
    "array-index-out-of-bounds": "an array was indexed outside its declared bounds",
    "signed-integer-overflow": "signed arithmetic overflowed (undefined in C)",
    "invalid-load": "a load of a value that isn't valid for its type (e.g. a bool that isn't 0/1)",
    "null-ptr-deref": "a NULL pointer was dereferenced",
}


def explain(r: Report) -> str:
    out: list[str] = []
    culprit = r.culprit("crash") if "crash" in r.stacks else r.culprit()
    if r.category == "kasan":
        meaning = _KASAN_MEANING.get(r.kind, r.kind)
        out.append(f"KASAN {r.kind}: {meaning}.")
        if r.access:
            out.append(f"Access: {r.access.size}-byte {r.access.op} at {r.access.addr} by task {r.access.task}.")
        if culprit:
            out.append(f"Faulting code: {culprit.where()}.")
        if "cache" in r.details:
            rel = r.details.get("relation", "inside")
            rel_txt = {"inside": "inside", "to the right": "past the end of",
                       "to the left": "before the start of"}.get(rel, rel)
            state = r.details.get("region state", "")
            article = "an" if state[:1] in ("a", "e", "i", "o", "u") else "a"
            out.append(f"Object: the access is {r.details.get('offset', '?')} bytes {rel_txt} {article} "
                       f"{state} {r.details.get('region size', r.details['object size'])}-byte "
                       f"object from cache '{r.details['cache']}' at {r.details['object']}.")
        for name in r.stacks:
            if name.startswith(("allocated", "freed")):
                f = r.culprit(name)
                if f:
                    out.append(f"{name.capitalize()}: {f.where()}.")
        if r.kind.endswith("use-after-free"):
            out.append("Typical causes: a reference dropped (kfree/put) while another path still holds "
                       "the pointer; a missing refcount, RCU grace period or lock between the free path "
                       "and the use path. Compare the 'freed by' and crash stacks to find the two paths.")
        elif "out-of-bounds" in r.kind:
            out.append("Typical causes: a length/index taken from untrusted input without a bounds check, "
                       "or an off-by-one between an allocation size and its use.")
        elif r.kind == "null-ptr-deref":
            if r.access and r.access.addr:
                out.append(f"Address {r.access.addr} is a small offset from NULL: the code dereferenced a "
                           f"field of a NULL struct pointer (the offset is the field's position).")
    elif r.category == "kcsan":
        out.append(f"KCSAN {r.kind}: two CPUs accessed the same memory concurrently, at least one "
                   f"writing, without synchronization (or with only one side annotated).")
        for acc, (name, frames) in zip(r.accesses, r.stacks.items()):
            f = next((fr for fr in frames if not fr.is_noise), frames[0] if frames else None)
            mark = " (marked: READ_ONCE/WRITE_ONCE/atomic)" if acc.marked else ""
            out.append(f"- {acc.size}-byte {acc.op}{mark} at {acc.addr} by {acc.task} on cpu {acc.cpu}"
                       + (f" in {f.where()}" if f else ""))
        if "value changed" in r.details:
            out.append(f"Value changed {r.details['value changed']} - the race was observed, not just possible.")
        out.append("Fix options: protect both sides with the same lock, use READ_ONCE()/WRITE_ONCE() "
                   "if the race is intentional and benign, or data_race() to document a known-benign race.")
    elif r.category == "lockdep":
        out.append(f"lockdep: {r.kind}.")
        lock_meaning = _LOCKDEP_MEANING.get(r.kind)
        if lock_meaning:
            out.append(f"Meaning: {lock_meaning}.")
        for k in ("acquiring", "already holding", "same instance"):
            if k in r.details:
                out.append(f"{k.capitalize()}: {r.details[k]}")
        if "scenario" in r.details:
            out.append("Unsafe scenario lockdep found:\n" + r.details["scenario"])
        if r.locks:
            out.append("Locks held at the time (outermost first):")
            out.extend(f"  {i}. {lk}" for i, lk in enumerate(r.locks[:8]))
        if r.kind == "possible recursive locking detected" and "same instance" not in r.details:
            out.append("If these are different objects of the same lock class, this may be a false "
                       "positive fixable with mutex_lock_nested()/spin_lock_nested().")
    elif r.category == "warning":
        out.append(f"WARN_ON triggered at {r.location}: the code hit a condition its author asserted "
                   f"should never happen.")
        if "message" in r.details:
            out.append(f"Message printed before it: {r.details['message']}")
        caller = next((f for f in r.stacks.get("crash", [])[1:] if not f.is_noise), None)
        if caller:
            out.append(f"Reached from: {caller.where()}.")
        out.append("Find the WARN_ON at that file:line - its condition is what went wrong.")
    elif r.category == "ubsan":
        out.append(f"UBSAN {r.kind} at {r.location}: {_UBSAN_MEANING.get(r.kind, 'undefined behaviour')}.")
        if "detail" in r.details:
            out.append(f"Detail: {r.details['detail']}")
        if culprit:
            out.append(f"In: {culprit.where()}.")
        if r.kind == "shift-out-of-bounds":
            m = re.search(r"shift exponent (\d+)", r.details.get("detail", ""))
            if m and int(m.group(1)) > 2**31:
                out.append(f"Exponent {m.group(1)} is a negative 32-bit value ({int(m.group(1)) - 2**32}) "
                           f"seen as unsigned - typically computed from untrusted on-disk/input data.")
    elif r.category == "oops":
        out.append(f"Kernel oops: {r.kind}.")
        if "KASAN" in r.details:
            out.append(f"KASAN narrows it to: {r.details['KASAN']} - the faulting pointer was NULL plus "
                       f"a small offset (a field of a NULL struct pointer).")
        elif "address" in r.details:
            out.append(f"Faulting address: {r.details['address']}.")
        if r.location:
            out.append(f"Faulting instruction (RIP): {r.location}.")
        caller = next((f for f in r.stacks.get("crash", [])[1:] if not f.is_noise), None)
        if caller:
            out.append(f"Called from: {caller.where()}.")
    elif r.category == "hung":
        out.append(f"Hung task: {r.details.get('task')} was stuck in uninterruptible sleep (state D) for "
                   f"more than {r.details.get('seconds')}s.")
        if culprit:
            out.append(f"It is blocked in: {culprit.where()}.")
        out.append("Usually a lock or wait that's never released: find which task holds the lock it waits "
                   "for (the report lists all held locks) and why that task doesn't progress.")
        if "waiting for" in r.details:
            out.append(f"It is waiting for: {r.details['waiting for']}.")
            n = int(r.details.get("same lock listed by", "0"))
            if n:
                out.append(f"{n} other task(s) list the same lock - one of them owns it, the rest are "
                           f"waiting too (lockdep's list doesn't say which). Look for the one NOT blocked "
                           f"in a lock function:")
                out.extend(f"  - {lk}" for lk in r.locks[:10])
                if n > 10:
                    out.append(f"  ... and {n - 10} more")
            else:
                out.append("No other task lists that lock: its owner may have exited without "
                           "releasing it, or it is a completion/wait that nobody signals.")
    else:
        out.append(f"{r.headline}")
        if culprit:
            out.append(f"In: {culprit.where()}.")
    return "\n".join(out)


def render(r: Report, max_frames: int = 12) -> str:
    """Full parsed view: headline, explanation, then each stack (noise frames dropped)."""
    out = [r.headline, "", explain(r)]
    for name, frames in r.stacks.items():
        if not frames:
            continue
        alloc = name.startswith(("allocated", "freed"))
        shown = [f for f in frames if not f.is_noise and not (
            alloc and (_ALLOC_FUNCS.match(f.func) or (f.file and _ALLOC_FILES.match(f.file))))]
        hidden = len(frames) - len(shown)
        what = "reporting/allocator frames" if alloc else "reporting/locking frames"
        out.append("")
        out.append(f"{name} stack ({len(frames)} frames" + (f", {hidden} {what} hidden" if hidden else "") + "):")
        for f in shown[:max_frames]:
            out.append(f"  {f.where()}")
        if len(shown) > max_frames:
            rest = shown[max_frames:]
            entry = next((f for f in rest if _ENTRY_FUNCS.match(f.func)), rest[-1])
            out.append(f"  ... {len(rest)} more, down to {entry.func}")
    return "\n".join(out)
