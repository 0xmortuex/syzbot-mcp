"""The parser on real syzbot crash reports (see fixtures/reports/SOURCES.json
for where each came from)."""

import json
import os

import pytest

from syzbot_mcp import report as R

HERE = os.path.join(os.path.dirname(__file__), "fixtures", "reports")


def load(name):
    with open(os.path.join(HERE, f"report_{name}.txt"), encoding="utf-8") as fh:
        return R.parse(fh.read())


def test_every_fixture_has_a_recorded_source():
    with open(os.path.join(HERE, "SOURCES.json"), encoding="utf-8") as fh:
        sources = json.load(fh)
    names = {f[len("report_"):-4] for f in os.listdir(HERE) if f.startswith("report_")}
    assert names == set(sources)
    for s in sources.values():
        assert s["report"].startswith("https://syzkaller.appspot.com/text?tag=CrashReport")


def test_kasan_use_after_free():
    r = load("kasan_uaf")
    assert (r.category, r.kind) == ("kasan", "slab-use-after-free")
    assert (r.access.op, r.access.size, r.access.addr) == ("read", 1, "ffff888020923688")
    assert r.culprit("crash").func == "acpi_ns_check_object_type"
    assert r.culprit("crash").file == "drivers/acpi/acpica/nspredef.c" and r.culprit("crash").line == 202
    # Allocation/free stacks skip the allocator to the real caller.
    assert r.culprit("allocated by task 1").func == "acpi_ut_allocate_object_desc_dbg"
    assert r.culprit("freed by task 1163").func == "acpi_os_release_object"
    assert r.details["cache"] == "Acpi-Operand" and r.details["offset"] == "8"
    assert r.details["region state"] == "freed"
    text = R.explain(r)
    assert "8 bytes inside a freed 72-byte object from cache 'Acpi-Operand'" in text


def test_kasan_out_of_bounds_wording():
    r = load("kasan_oob")
    assert r.kind == "slab-out-of-bounds" and r.access.op == "write"
    assert "0 bytes past the end of an allocated 4096-byte object" in R.explain(r)
    assert r.culprit("allocated by task 5946").func == "jfs_readdir"


def test_kasan_null_deref_skips_instrumentation():
    r = load("null_deref")
    assert r.kind == "null-ptr-deref"
    # Four "BUG: KASAN ... [inline]" headlines: the last, real one is kept.
    assert r.headline.endswith("fput+0x2e/0x100 fs/file_table.c:588")
    assert r.access.addr == "0000000000000158"
    assert r.culprit("crash").func == "file_ref_put"
    assert "small offset from NULL" in R.explain(r)


def test_kcsan_both_accesses():
    r = load("kcsan")
    assert (r.category, r.kind) == ("kcsan", "data-race")
    assert [(a.op, a.size, a.cpu) for a in r.accesses] == [("write", 4, "0"), ("read", 4, "1")]
    assert r.details["value changed"] == "0x00000013 -> 0x00000000"
    stacks = list(r.stacks)
    assert r.stacks[stacks[0]][0].func == "wait_task_stopped"
    assert r.stacks[stacks[1]][0].func == "do_notify_parent_cldstop"


def test_lockdep_recursive_same_instance():
    r = load("lockdep")
    assert (r.category, r.kind) == ("lockdep", "possible recursive locking detected")
    assert r.details["acquiring"].startswith("&subsys->lock at nvmet_ctrl_free")
    assert r.details["already holding"].startswith("&subsys->lock at nvmet_port_del_ctrls")
    assert "same instance" in r.details
    assert len(r.locks) == 5 and r.locks[3].startswith("nvmet_config_sem")
    assert "lock(&subsys->lock);" in r.details["scenario"]
    assert r.culprit("crash").func == "nvmet_ctrl_free"


def test_warning_new_format():
    r = load("warning")
    assert r.category == "warning"
    assert r.location == "kernel/workqueue.c:2353 (in __queue_work)"
    assert r.details["message"] == "workqueue: cannot queue hci_rx_work on wq hci0"
    assert [f.func for f in r.stacks["crash"][:3]] == ["__queue_work", "queue_work_on", "queue_work"]


def test_ubsan_shift():
    r = load("ubsan")
    assert (r.category, r.kind, r.location) == ("ubsan", "shift-out-of-bounds", "fs/f2fs/super.c:3950:27")
    assert "negative 32-bit value (-9)" in R.explain(r)
    assert r.culprit("crash").func == "__f2fs_commit_super"


def test_gpf_with_kasan_range():
    r = load("paging")
    assert r.category == "oops" and r.kind == "null pointer dereference"
    assert r.location == "klist_put+0x4d/0x1d0 lib/klist.c:212"
    assert r.stacks["crash"][0].func == "klist_put"
    assert "0x0000000000000058-0x000000000000005f" in r.details["KASAN"]


def test_hung_task_finds_the_contended_lock():
    r = load("hung_task")
    assert r.category == "hung" and r.details["task"] == "dhcpcd:5279"
    assert r.culprit().func == "rtnl_net_lock"
    assert r.details["waiting for"].startswith("rtnl_mutex (ffffffff90254c40)")
    # Task names with colons (kworker/u8:0/12) must parse.
    assert any(lk.startswith("kworker/u8:0/12: took it at linkwatch_event") for lk in r.locks)
    assert r.details["same lock listed by"] == "6"


def test_frame_regex_shapes():
    f = R.parse_frames([" foo+0x10/0x20 [mymod] drivers/x/y.c:12",
                        " bar include/linux/z.h:3 [inline]",
                        " ? baz+0x1/0x2",
                        " <TASK>",
                        "RIP: 0010:x+0x1/0x2 a.c:1"])
    assert [(x.func, x.module, x.file, x.line, x.inline) for x in f] == [
        ("foo", "mymod", "drivers/x/y.c", 12, False),
        ("bar", None, "include/linux/z.h", 3, True),
        ("baz", None, None, None, False),
    ]


@pytest.mark.parametrize("text,category", [
    ("kernel BUG at mm/slub.c:123!\nCall Trace:\n f+0x1/0x2 a.c:1\n", "bug"),
    ("WARNING: CPU: 0 PID: 1 at fs/x.c:9 foo+0x1/0x2\nCall Trace:\n foo+0x1/0x2 fs/x.c:9\n", "warning"),
    ("BUG: kernel NULL pointer dereference, address: 0000000000000010\nRIP: 0010:f+0x1/0x2 a.c:3\n", "oops"),
    ("hello world", "unknown"),
])
def test_other_shapes(text, category):
    assert R.parse(text).category == category
