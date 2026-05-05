# pwned-deps benchmark (v0.1.0)

_Best-of-3 offline match time on `darwin`, Python 3.12.13. Excludes parse + render._

| Fixture | Packages | Time (ms) | Packages/sec |
|---|---:|---:|---:|
| npm clean (1 pkg) | 1 | 0.09 | 11,555 |
| npm Mini Shai-Hulud (1 pkg, 2 hits) | 1 | 0.06 | 16,961 |
| npm event-stream historic (2 pkgs) | 2 | 0.09 | 21,286 |
| npm synthetic-malicious (3 pkgs) | 1 | 0.05 | 19,262 |
| npm v3 lockfile | 2 | 0.06 | 32,389 |
| pypi requirements.txt | 8 | 0.08 | 101,587 |
| maven pom.xml | 3 | 0.07 | 42,278 |
