# FlagKit CTF Toolbox

A dependency-free, browser-based toolbox for legal CTF challenges and security labs. All transforms run locally in the browser.

## Run

### Local setup (Windows)

1. Install [Python 3 for Windows](https://www.python.org/downloads/windows/) if it
   is not already installed. Enable **Add Python to PATH** in its installer.
2. Double-click `install.cmd` in this folder.
3. Use the **FlagKit CTF Toolbox** shortcut added to the desktop or Start menu.

The shortcut starts a local-only web server, opens `http://localhost:8080` in the
default browser, and keeps a terminal window open while FlagKit is running. Close
that terminal or press <kbd>Ctrl</kbd>+<kbd>C</kbd> to stop the server.

For a custom port or to avoid opening the browser automatically, run this from
PowerShell in the FlagKit folder:

```powershell
$env:PORT = 9000
powershell.exe -ExecutionPolicy Bypass -File .\scripts\flagkit.ps1 -NoBrowser
```

### Run without installing

Open `index.html` directly, run the PowerShell launcher, or serve the repository
manually from PowerShell:

```powershell
py -3 -m http.server 8080
```

On macOS or Linux, use:

```sh
python3 -m http.server 8080
```

Then visit `http://localhost:8080`.

## Included tools

- Base64, hexadecimal, binary, decimal ASCII, URL, ROT13, reverse, and HTML entity transforms
- Caesar cipher shift and all-shifts view
- SHA-1, SHA-256, SHA-384, and SHA-512 generation plus hash-length identification
- Repeating-key XOR and ranked single-byte XOR brute force
- Character frequency, Shannon entropy, and flag-shaped token extraction
- Arbitrary-size decimal, hexadecimal, binary, and octal conversion
- Unix timestamp and ISO/local date conversion
- JWT header and payload inspection (decoding only; no signature claims)
- Local file triage with magic-byte identification, SHA-256, byte preview, and printable strings
- IPv4/CIDR calculation and offline URL parsing
- Searchable field notes for Linux, forensics, Nmap, DNS, HTTP, PCAPs, WiFi captures, steganography, Git, PDFs, password challenges, RSA, PGP, SSL, metadata, and logs
- Multi-step transform recipes with ordering, parameters, and locally saved pipelines
- Classic PCAP parsing for Ethernet, IPv4, TCP, UDP, DNS, ICMP, and ARP captures, accelerated by an embedded WebAssembly network-byte reader
- Image RGB/alpha channel isolation, grayscale viewing, and per-channel bit planes
- BigInt RSA key calculations, raw modular operations, primality hints, and shared-prime checks
- A persistent challenge notebook with status, flags, evidence, JSON backup, and Markdown reports
- User-created Field Guide snippets with JSON import/export
- Installable PWA support with an offline application cache

The command guide is intended only for CTF infrastructure and systems you are authorized to test. Tools such as Nmap, Wireshark, Binwalk, John, and Hashcat run on the host system and are documented in the guide; FlagKit does not execute those commands from the browser.

## Offline installation

Serve FlagKit over `http://localhost` and use the **Install** button when the browser offers it. The service worker caches the complete application shell, so subsequent launches work without a network connection. Browser storage holds saved recipes, notebook entries, and custom snippets; export them to JSON before clearing site data or switching browsers.

The packet inspector currently supports classic Ethernet PCAP files. Convert PCAPNG captures locally when needed:

```bash
editcap -F pcap input.pcapng output.pcap
```
