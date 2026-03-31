# 🛡️ Discord Link Protector — Mobile

All‑in‑one Discord link protector for mobile 🔒🛡️ — real-time detection & flagging of scams, phishing, token grabbers, IP loggers, shorteners, and unsafe downloads; block/unblock links, on‑device heuristics + updatable blocklists. Firefox for Android compatible 🚀🔍

Requires Firefox for Android — mobile only.

---

## Features
- 🔴 Real-time link protection  
  Scans messages instantly as they appear and flags suspicious links inline (turns links red / adds warning UI). Works across chats, servers, DMs and the Discover page when using Discord web in a supported mobile browser.

- 🧠 Smart scam detection  
  Detects fake giveaways (Nitro, prizes), phishing attempts, referral scams, token-grabbers, and obfuscated text (e.g., fr33 m0ney). Uses text normalization and heuristics to catch bypass tricks.

- ⚠️ Malware & virus detection  
  Flags links that appear to point to unsafe downloads (exe, apk, zip, dmg, etc.) or known malware-hosting sites.

- 🔗 Suspicious link detection  
  Blocks or flags URL shorteners, IP-grabbers (Grabify, iplogger), scam/crypto/gambling domains and other suspicious hosts — plus heuristic detection for unknown threats.

- 🧩 Server protection  
  Scans content loaded on the Discord Discover page and highlights risky server names (web client only).

- 🚫 Block / Unblock system  
  One-click Block button for flagged links. Blocked links become gray and unclickable; you can unblock them later.

- ⚡ Real-time monitoring  
  Automatically scans new messages, edited messages, and newly loaded content via MutationObserver.

- 🎨 Clean UI  
  Non-intrusive inline warnings (no full-screen overlays). Mobile-friendly controls.

---

## Installation (Firefox for Android — developer / testing)
1. Clone or download this repository to your device.
2. Install Firefox for Android.
3. In Firefox address bar open: `about:debugging` and enable "Add-on debugging".
4. Tap "Load Temporary Add-on" and select `manifest.json` from the extension folder.  
   - Alternatively you can build an XPI (see Packaging below) and open it in Firefox to install.
5. Open https://discord.com in Firefox and sign in; the extension will run on the web client.

Notes:
- This extension runs in the browser only. It does NOT run inside the native Discord mobile app.
- For more stable distribution package as an XPI and publish on addons.mozilla.org (AMO).

---

## Packaging (create XPI)
Recommended: use Mozilla web-ext
- Install: `npm install --global web-ext`
- Build: `web-ext build` (output saved in `web-ext-artifacts/`)

Or create a zip of the extension files and rename to `.xpi`.

---

## Usage
- When the extension detects a suspicious link it will:
  - Add a warning icon and reason text inline.
  - Offer a "Block" button — blocked links turn gray and are unclickable.
- To unblock: use the Blocked Links manager (future UI) or clear via extension storage.

---

## Configuration & Lists
- Built-in detection lives in `detector.js`. It includes curated lists and heuristics.
- You can add/maintain blocklists in `lists/` (JSON arrays). Example:
  - `lists/shorteners.json`
  - `lists/ip_loggers.json`
  - `lists/scams.json`
- Load bundled lists at runtime by adding fetch calls to `contentScript.js`:
```js
fetch(chrome.runtime.getURL('lists/shorteners.json')).then(r=>r.json()).then(d=>LinkDetector.mergeExternalLists({shorteners:d})).catch(()=>{});

❤️ Support
If you like this project, consider supporting:

Join my Discord: https://discord.gg/4pnWZhhw4
Cash App: $GodkillerYT
GitHub Sponsors
Ko-fi / Buy Me a Coffee
Or share the project
