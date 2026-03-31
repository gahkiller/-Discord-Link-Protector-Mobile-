# Discord Link Protector - Mobile (Firefox for Android)

Files:
- manifest.json
- background.js
- detector.js
- contentScript.js
- styles.css

Install (developer/testing):
1. On Android install Firefox for Android.
2. In Firefox address bar go to about:debugging and enable "Enable add-on debugging".
3. Use "Load Temporary Add-on" and select the manifest.json (or the XPI when packaged).
4. Open discord.com in Firefox mobile — the extension will run and flag suspicious links.

Notes:
- This is an MV2 manifest for compatibility with Firefox for Android.
- The detector uses a small built-in list and heuristics; expand detector.js blocklists for more coverage.
- This extension cannot run inside the native Discord app.
- For production, sign and package as an XPI and publish to addons.mozilla.org if desired.

Generated on: 2026-03-31
