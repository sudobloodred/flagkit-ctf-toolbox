# FlagKit CTF Toolbox

A dependency-free, browser-based toolbox for legal CTF challenges and security labs. All transforms run locally in the browser.

## Run

Open `index.html` directly, or serve the directory locally:

```bash
python3 -m http.server 8080 --directory /home/sudosmash/ctf-toolbox
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
