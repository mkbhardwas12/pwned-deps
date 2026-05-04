# vhs script — record the hero demo GIF for the README.
#
# Prereq:  brew install vhs
# Record:  vhs demo.tape    (writes docs/demo.gif)
#
# vhs spawns a real shell, types each line at human speed, and
# captures the terminal as a GIF. Deterministic and replay-able —
# update this file, re-run vhs, ship the new GIF.

Output docs/demo.gif

Set Shell      "zsh"
Set FontSize   16
Set Width      1100
Set Height     680
Set Theme      "Catppuccin Mocha"
Set Padding    20
Set TypingSpeed 40ms

# --- Setup (hidden) ---
Hide
Type "clear"  Enter
Type "alias pwned-deps='pwned-deps --no-color' 2>/dev/null; clear"  Enter
Show

# --- Beat 1: green case ---
Type "# Drop your lockfile in. Find out if you're pwned."  Enter
Sleep 800ms
Type "pwned-deps check ./tests/fixtures/npm/clean.lock.json"  Enter
Sleep 2s

# --- Beat 2: the actual Mini Shai-Hulud lockfile ---
Type "# What if you ran `npm install` during Mini Shai-Hulud (Apr 29)?"  Enter
Sleep 800ms
Type "pwned-deps check ./tests/fixtures/npm/mini-shaihulud.lock.json"  Enter
Sleep 4s

# --- Beat 3: exit code is the receipt ---
Type "echo \"exit: $?\"   # 1 = compromised, fail your CI build"  Enter
Sleep 2500ms

# --- Beat 4: SARIF for GitHub Code Scanning ---
Type "pwned-deps check . --format sarif > pwned-deps.sarif && echo 'wrote pwned-deps.sarif'"  Enter
Sleep 2s

Type "# 12 ecosystems. Offline cache. Open campaign feed. Apache-2.0."  Enter
Sleep 2500ms
