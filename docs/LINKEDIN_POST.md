# LinkedIn post — pwned-deps v0.1.0 launch

LinkedIn caps a feed post at ~3000 characters and renders **only**
plain line breaks + hashtags (no markdown headings, no inline links —
clickable URLs are auto-detected). The text below fits that constraint.
Upload `docs/images/mini-shai-hulud.png` as the post image when you
share it.

---

🚨 If your CI ran `npm install` between 09:55 and 12:14 UTC on
April 29, 2026, you may have shipped credential-stealing malware.

That morning four SAP-ecosystem npm packages were briefly poisoned:

  • @cap-js/sqlite@2.2.2
  • @cap-js/postgres@2.2.2
  • @cap-js/db-service@2.10.1
  • mbt@1.2.48

Combined ~570,000 weekly downloads. Over a thousand victim
repositories visible to a public GitHub search within hours. The
preinstall script exfiltrated GitHub PATs, npm tokens, AWS / Azure /
GCP / Kubernetes credentials.

A day later, the same operator trojanised three more package
versions: intercom-client@7.0.5, lightning@2.6.2, lightning@2.6.3.

Today, confirming whether YOUR pipeline ran during that window means
manual log-diving across CI runs, lockfile diffs, and vendor blogs.

I built pwned-deps to make the answer 5 seconds:

    pipx install pwned-deps
    pwned-deps check ./package-lock.json

Drop your lockfile in. Get a red/green answer. Exit 1 if any
compromised package is on disk, with the campaign name, the exposure
window, the SHA-256 of the bad tarball, and the credentials to rotate.

Supports npm (package-lock, pnpm, yarn v1+Berry), PyPI
(requirements, Pipfile, poetry, uv), Cargo, Go, Maven, RubyGems.
Output: text, JSON, or SARIF v2.1.0 for GitHub Code Scanning.

Backed by OSV.dev plus an open community-PR campaigns feed for
incidents OSV hasn't yet ingested — Mini Shai-Hulud and the April-30
follow-on are in the bundled feed today, sourced strictly from named
research blogs (The Hacker News, SecurityBridge, Wiz).

Apache-2.0. No telemetry. No hosted backend. Network calls are
allow-listed to api.osv.dev only. Container-only dev posture, pinned
+ hash-verified deps, OIDC-only PyPI publishing.

The next supply-chain incident is already being prepared somewhere.
This tool exists so the answer to "did I install one of those bad
versions?" can stop being a research project.

GitHub: https://github.com/mkbhardwas12/pwned-deps
PyPI:   https://pypi.org/project/pwned-deps/

Sources for the launch campaign data:
The Hacker News — https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html
SecurityBridge — https://securitybridge.com/blog/a-mini-shai-hulud-has-appeared-when-the-npm-supply-chain-reaches-into-sap/
Wiz — https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm

#supplychain #devsecops #npm #python #security #opensource
