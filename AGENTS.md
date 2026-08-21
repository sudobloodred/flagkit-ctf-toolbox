# FlagKit contributor guide

FlagKit is a dependency-free static web application. Keep all challenge data processing local in the browser and avoid introducing API keys, telemetry, remote uploads, or runtime CDN dependencies.

## Verification

Run these checks after changing JavaScript or the PWA configuration:

```bash
node --check app.js
node --check advanced.js
node --check sw.js
python3 -m json.tool manifest.webmanifest >/dev/null
```

For visual checks, serve the repository with:

```bash
python3 -m http.server 8080
```

Then inspect the relevant hash route, such as `http://localhost:8080/#recipes` or `http://localhost:8080/#media-lab`.

Only include security commands intended for legal CTF infrastructure, labs, or systems the user is authorized to test.
