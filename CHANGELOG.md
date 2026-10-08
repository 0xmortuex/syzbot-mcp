# Changelog

## 0.1.0 - 2026-10-09

First release.

- `syzbot_bugs`, `syzbot_bug`, `syzbot_report`, `syzbot_repro`, and the offline
  `syzbot_explain`.
- Crash report parser for KASAN, KCSAN, lockdep, WARNING (new and old formats), UBSAN,
  oopses/GPFs, hung tasks and generic BUGs. It hides reporting, allocator and locking
  frames, names the alloc/free callers for use-after-free, and finds the contended lock
  and its holders for hung tasks.
- Polite client: identifying User-Agent, rate limit of 1 s or more, on-disk cache with
  per-endpoint TTLs, and a single back-off on 429/503.
