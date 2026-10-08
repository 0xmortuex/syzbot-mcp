# Backlog

- [ ] Decode the `Code:` bytes around the faulting instruction (capstone) and point at the faulting byte.
- [ ] `syzbot_config(bug, option)`: grep the crash's kernel .config for CONFIG_ options (cached 30d).
- [ ] Similar bugs: syzbot's bug page lists similar bugs in other namespaces; surface them in `syzbot_bug`.
- [ ] Bisection logs (`/text?tag=Log`) for cause/fix bisects that ended in error or inconclusive.
- [ ] More report shapes: KMSAN uninit-value (with origin stack), KFENCE, "BUG: Bad page state", refcount_t warnings.
- [ ] Per-namespace subsystem list tool (`/<ns>/subsystems`) so agents can discover valid `subsystem=` names.
