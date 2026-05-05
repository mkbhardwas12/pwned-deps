# pwned-deps — Launch Posts

GitHub: https://github.com/mkbhardwas12/pwned-deps
Install: `pipx install pwned-deps`

Images in `launch_assets/`:
- `thumbnail.png` — **cover / feature image** (1500 × 750, works for Medium hero, X card, LinkedIn preview)
- `hero-flow.png` — what the tool does at a glance
- `timeline.png` — the named compromises 2018 → 2026
- `four-commands.png` — quick-reference card

---

## 1. Medium — long-form post

**Title:**
*pwned-deps: The 5-second lockfile check that answers "did we pull a compromised package?"*

**Subtitle:**
*A small free tool for any team that ships software. Born out of years working on the SAP platform side, finally pushed out the door after the npm wave reached SAP CAP last week.*

---

### The post

> *[Insert image: launch_assets/hero-flow.png — alt text: "pwned-deps takes your lockfile and returns a green 'all clean' or a red list of compromised packages with the advisory ID and exit code 1."]*

Look, every app you ship today pulls in hundreds of open-source packages. You didn't write most of them. You can't read all of them. And every now and then — more often than most teams realise — one of them quietly turns dangerous. An npm maintainer's account gets stolen. A typosquat sneaks into someone's `requirements.txt`. A package nobody has touched in two years suddenly publishes a v1.4.3 with a credential stealer wedged into the preinstall script.

When that happens, your team ends up asking the same three questions, usually around 2 a.m. on a weekday:

> *Did we install one of those bad versions? Where? Is it still in our caches and container images?*

The data you need to triage is, at that exact moment, already public. Somewhere. There's an OSV record. A GHSA entry. A vendor blog from SecurityBridge or Wiz with the IoCs. A GitHub issue where the maintainer is apologising in their local language at 4 a.m. their time. The problem is never that the information doesn't exist — it's that it's spread across half a dozen browser tabs and you're stitching it together with one eye open while the on-call pager keeps going off.

I built a small tool that does the stitching upfront, so the answer comes back in one command.

It is called `pwned-deps`. You feed it your project's lockfile — `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `Cargo.lock`, `go.sum`, `pom.xml`, `Gemfile.lock`, whichever your stack uses — and in about five seconds it cross-checks every package against the public [OSV.dev](https://osv.dev) advisory database plus a small hand-curated feed of named real-world incidents that I've been keeping. You get a green tick, or you get a red list with the version, the advisory ID, and a link to where you can read more. That's the whole tool. That's the whole pitch.

### A bit of context on the timing

I work on the platform side of SAP. The drumbeat of package-registry compromises across the wider industry has been hard to ignore for years now — `xz-utils` in 2024 (CVSS 10.0, the one where the researcher caught a multi-year backdoor by accident in his Postgres benchmarks), the `tj-actions/changed-files` retroactive commit in 2025, the original Shai-Hulud npm worm that quietly self-replicated through 180+ packages last year, and a long list before that going back at least to `event-stream` in 2018. None of this is new. It has been steady for the better part of a decade, across pretty much every major language ecosystem.

> *[Insert image: launch_assets/timeline.png — alt text: "Horizontal timeline of fifteen named package-registry compromises from event-stream in 2018 through Mini Shai-Hulud on the SAP CAP packages in April 2026, with the SAP incident annotated."]*

What pushed me to actually clean up and publish what I'd been working on was last week. On April 29, four SAP-flavoured npm packages — `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`, and `mbt@1.2.48` — were briefly poisoned with a credential-stealing preinstall script. The window was about two-to-four hours. Anyone whose CI happened to run `npm install` during that window pulled a payload that exfiltrated GitHub, npm, AWS, Azure, GCP and Kubernetes credentials, and then dropped persistence files (`.claude/execution.js`, `.vscode/setup.mjs`, a shared `setup.mjs` dropper) into other repositories on the same machine. SecurityBridge, Wiz, and The Hacker News all wrote it up under the name *Mini Shai-Hulud*. There's a follow-on campaign — `intercom-client` on npm and `lightning` on PyPI, same operator, shared C2 — that surfaced a couple of days later.

Until then I'd been quietly using my tooling on my own teams. The SAP incident was the moment it stopped feeling theoretical. I figured if it could help my own colleagues, it could help anyone, and it would help most if it were free, open and out the door this week instead of next year.

So here it is.

### Who it's actually for

Important point, and the reason I'm not posting this only in security circles: **this tool is not specific to SAP, and it is not specific to security teams**. If your code depends on open-source packages from npm, PyPI, Maven, crates.io, Go modules, or RubyGems — and unless you write everything from scratch on a typewriter, it does — you can use this in five minutes. A few honest examples of who I had in mind:

- A solo developer who wants to know their hobby project hasn't pulled a known-bad package.
- An open-source maintainer auditing their own dependencies before cutting a release.
- A small startup with one CI pipeline and zero dedicated security headcount.
- A platform team at a large enterprise that wants a same-day signal across many repositories.
- An engineering or IT manager who needs a defensible answer to "are we exposed to the incident in the news this morning?"
- A consultant doing due-diligence on a codebase they've inherited.
- An SAP CAP / Fiori / UI5 / BTP developer whose build pipeline pulls npm and Python packages alongside the SAP-side work.

### What you actually run

> *[Insert image: launch_assets/four-commands.png — alt text: "The four pwned-deps commands: check for one-shot scan, watch for nightly delta alerts, audit-repo for forensic file scan, and report for a multi-repo HTML dashboard."]*

```bash
pipx install pwned-deps

pwned-deps check .
# 5-second one-shot scan. exit 0 = clean, exit 1 = compromised.

pwned-deps watch . --baseline .pwned-deps-baseline.json
# nightly delta alerts. fires only when something already in your tree
# becomes newly flagged.

pwned-deps audit-repo .
# forensic SHA-256 walk for the IDE-persistence droppers campaigns leave
# behind. clean / confirmed / suspect, three exit codes.

pwned-deps report scans/*.json -o dashboard.html
# self-contained HTML dashboard for platform/security teams that need
# a multi-repo aggregate view. drop into S3 or GitHub Pages.
```

Wiring it into CI is, deliberately, one line:

```yaml
- run: pip install pwned-deps && pwned-deps check . --ci
```

Exit code 1 stops the build.

### Things I deliberately did, because in this category they matter as much as the features

- **No service mode.** Your lockfile bytes never leave the machine running the command. There is no hosted backend behind this — nothing that could later get compromised, exfiltrated from, or accidentally bill anyone.
- **One outbound network host: `api.osv.dev`.** No telemetry, no analytics, no crash reporting. `--offline` is a real flag and the cache is a plain SQLite file in your home directory.
- **Apache 2.0**, with SLSA Level 3 build provenance on every published wheel. You can cryptographically verify the artifact before you install it, if you're paranoid (or in a regulated environment).
- **OIDC-only PyPI publishing.** No long-lived tokens sitting in repository secrets.
- **The campaign feed itself is keyless-OIDC signed with sigstore** on every push to `main`, and the bundle is logged to the public Rekor transparency log — so a force-push or a silent removal can't quietly hide.
- **Free for individuals and enterprises alike.** No "contact sales" tier. No upsell. The whole tool is the open-source CLI you `pipx install`.

### What this is not

This is not a replacement for `osv-scanner` (the bar in this space — if you only run one tool, run that one), or `socket` (deepest behavioural analysis), or `npm audit --audit-signatures`, or `pip-audit`. It's the friendly five-second sanity check that fits in any team's existing CI in one line, and it's specifically tuned for the first hour of a fresh incident — when you need a yes/no answer about your pipeline before the CVE is even published.

### Closing

If your code depends on open-source packages, please give it a try this week. If it stays quiet, you've burned about ten seconds. If it doesn't, the report tells you exactly what was found and where to read more.

This is my contribution back to the community. Pull requests adding new incidents to the campaign feed are extremely welcome — the schema is documented and the review target is five minutes.

Source, GitHub Action, pre-commit hook, schema docs:
**https://github.com/mkbhardwas12/pwned-deps**

— Manish

---

## 2. X / Twitter — thread

**Tweet 1 (hook + hero image):**
*[Attach hero-flow.png]*

if you've ever run `npm install`, `pip install`, `cargo build`, `go get`, `mvn install`, or `bundle install` — this is for you.

a small free tool i've been working on. drop a lockfile in, get a green/red answer in ~5s. apache 2.0, no telemetry, no upsell.

🔗 https://github.com/mkbhardwas12/pwned-deps

**Tweet 2 (with timeline image):**
*[Attach timeline.png]*

the problem isn't new. it's been steady for nearly a decade — event-stream in 2018, ua-parser-js, ctx, xz-utils, tj-actions, the original shai-hulud worm last year.

what got me to publish was last week, when the wave finally rolled into the SAP ecosystem.

**Tweet 3 (what it does):**

every modern app pulls hundreds of open-source packages. occasionally one quietly goes bad (account hijack, typosquat, retroactive trojan).

`pwned-deps` cross-checks every package in your lockfile against OSV.dev + a curated, sigstore-signed feed of named real-world incidents.

**Tweet 4 (with four-commands image):**
*[Attach four-commands.png]*

works on:
npm · pypi · maven · cargo · go · rubygems

four commands cover the whole workflow:
• check — one-shot scan
• watch — nightly delta alerts
• audit-repo — SHA-256 forensic walk
• report — multi-repo HTML dashboard

**Tweet 5 (close):**

apache 2.0. SLSA L3 provenance on every wheel. OIDC-only PyPI. no telemetry. one outbound host (api.osv.dev). offline mode is a real flag. lockfile bytes never leave the machine.

solo devs, OSS maintainers, startups, platform teams — all welcome.

```
pipx install pwned-deps
pwned-deps check .
```

⭐ https://github.com/mkbhardwas12/pwned-deps

---

## 3. X / Twitter — single post (if not threading)

*[Attach hero-flow.png]*

if your code pulls open-source packages — npm, pip, maven, cargo, go, rubygems — this is for you.

a small free tool i've been working on. drop a lockfile in, get a green/red answer in ~5s. apache 2.0. no telemetry. solo devs and enterprises welcome equally.

https://github.com/mkbhardwas12/pwned-deps

---

## 4. LinkedIn — professional post

*[Attach hero-flow.png as the primary image. Optionally attach four-commands.png as a second image.]*

**A small free tool for any team that ships software.**

If your codebase depends on open-source packages — npm, Python, Java, Rust, Go, Ruby — then somewhere in your project there's a lockfile with hundreds of dependencies in it. You almost certainly didn't write most of that code. You couldn't read it all if you wanted to. And every now and then, more often than most teams realise, one of those packages quietly turns dangerous: a maintainer's account is taken over, a typosquat slips through, a previously trusted release is retroactively replaced with something hostile.

When that happens, the question is always the same:

> *"Did we install one of those bad versions? Where? When? Is it still in our caches and build images?"*

I'm sharing a small open-source tool, `pwned-deps`, that answers that question in about five seconds. You hand it any standard lockfile (`package-lock.json`, `requirements.txt`, `pom.xml`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, and many more), and it cross-checks every dependency against the public OSV.dev advisory database plus a hand-curated, signed feed of named real-world incidents. You get either a green tick or a clear list of which package, which version, which advisory, and where to read more.

A bit of context on why I'm publishing this now. I work on the platform side of SAP. Compromises in the wider package-registry world have been a steady drumbeat for years — `xz-utils` in 2024, `tj-actions/changed-files` in 2025, the Shai-Hulud npm worm last year, plenty before that. What pushed me to actually put what I'd been working on out the door was last week: on April 29, 2026, four SAP-flavoured npm packages were briefly poisoned with a credential-stealing preinstall script. SecurityBridge, Wiz, and The Hacker News covered it under the name "Mini Shai-Hulud." It mattered to teams I work with directly. Cleaning the tool up and publishing it felt like the right contribution to make.

But the part that matters most for reach — and the reason I'm posting here rather than only in security circles — is that **this tool is not specific to SAP, and it is not specific to security teams**.

It's genuinely useful for:

- Solo developers and open-source maintainers auditing their own projects.
- Small teams and startups with one CI pipeline and no dedicated security headcount.
- Platform and DevOps teams at large organisations that want a same-day signal across many repositories.
- Engineering managers and IT leaders who need a defensible, evidence-based answer to "are we exposed?" the moment a fresh incident hits the news.
- Consultants doing due-diligence on inherited codebases.
- SAP CAP, Fiori, UI5, and BTP developers whose build pipelines pull npm and Python dependencies — yes — but everyone else too.

The whole CLI is one `pipx install` away:

```
pipx install pwned-deps
pwned-deps check .
```

Four commands cover the workflow: `check` (one-shot scan), `watch` (nightly baseline + delta alerts), `audit-repo` (forensic SHA-256 walk over a checkout for the persistence files real campaigns leave behind), and `report` (a self-contained HTML dashboard across many repositories).

A few things I deliberately did, because in this category they matter at least as much as features:

- No service mode, no telemetry. Lockfile contents never leave the machine running the command. One outbound host: `api.osv.dev`. `--offline` is a real flag.
- Apache 2.0, SLSA Level 3 build provenance on every wheel, OIDC-only PyPI publishing.
- Free for individuals and enterprises alike. No upsell, no "contact sales" tier, no proprietary cloud component.

This is not a replacement for the heavier-weight tools in the space — `osv-scanner` (the bar), `socket` (deepest behavioural analysis), `npm audit --audit-signatures`, `pip-audit`. It's the friendly five-second sanity check that fits any team's existing CI in a single line, specifically tuned for the first hour of a fresh incident.

If your team ships software, please try it on your project this week. If it stays quiet, you've burned ten seconds. If it doesn't, the report tells you exactly what was found and where to look next.

This is my contribution back to the community. Pull requests are very welcome.

Source, GitHub Action, pre-commit hook, schema documentation:
https://github.com/mkbhardwas12/pwned-deps

#opensource #softwaredevelopment #devops #platformengineering #SAP #engineering #appsec #infosec
