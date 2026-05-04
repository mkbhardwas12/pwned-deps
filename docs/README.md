# pwned-deps — launch documentation

Source-cited launch material for the v0.1.0 release. Every factual
claim about the Mini Shai-Hulud campaign is hyperlinked to the named
research blog that published it. No fabricated version numbers, no
fabricated timestamps — uncertain bits carry `TODO(...)` markers.

## Posts

| File                                          | Where to use it                                                                          |
|-----------------------------------------------|------------------------------------------------------------------------------------------|
| [`LAUNCH_POST.md`](LAUNCH_POST.md)            | Long-form post for Medium, Dev.to, Hashnode, LinkedIn Article. Embeds all three diagrams. |
| [`LINKEDIN_POST.md`](LINKEDIN_POST.md)        | Short feed post (≤3000 chars, plain text). Upload `images/mini-shai-hulud.png` as the post image. |
| [`RELEASE_NOTES_v0.1.0.md`](RELEASE_NOTES_v0.1.0.md) | Body of the GitHub Release when tagging `v0.1.0`.                                         |

## Diagrams

All three are PNG, generated reproducibly via `tools/generate_diagrams.py`
running inside a one-off Pillow + DejaVu container. Re-run the script
if any text needs updating; the source script is committed and easy to
diff.

| File                                              | What it shows                                              |
|---------------------------------------------------|------------------------------------------------------------|
| [`images/architecture.png`](images/architecture.png) | System data flow: lockfile → 6 ecosystem parsers → matcher → ExtrasFeed + OSV → reporter → terminal / SARIF. |
| [`images/mini-shai-hulud.png`](images/mini-shai-hulud.png) | April 29-30 incident timeline. UTC events, affected packages, impact stats, every fact source-cited. |
| [`images/detection-flow.png`](images/detection-flow.png) | Step-by-step: what `pwned-deps check ./package-lock.json` actually does. |

## Sources for the launch campaign data

- [The Hacker News — "SAP npm Packages Compromised by Mini Shai-Hulud"](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)
- [SecurityBridge — "A Mini Shai-Hulud has Appeared"](https://securitybridge.com/blog/a-mini-shai-hulud-has-appeared-when-the-npm-supply-chain-reaches-into-sap/)
- [Wiz — "Mini Shai-Hulud supply-chain attack on SAP npm"](https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm)

If a future revision changes any timestamp, package, or impact figure,
the change must come with a hyperlink to the source that published it.
The `extras.json` file in the project root carries the same discipline.
