(() => {
  'use strict';

  const input = document.getElementById('scout-input');
  const results = document.getElementById('scout-results');
  const fileInput = document.getElementById('scout-file');
  const fileMeta = document.getElementById('scout-file-meta');

  const TOOLS = {
    cyberchef: ['CyberChef', 'https://gchq.github.io/CyberChef/'],
    dcode: ['dCode', 'https://www.dcode.fr/'],
    boxentriq: ['Boxentriq', 'https://www.boxentriq.com/'],
    crtsh: ['crt.sh', 'https://crt.sh/'],
    mxtoolbox: ['MXToolbox', 'https://mxtoolbox.com/SuperTool.aspx'],
    urlscan: ['urlscan.io', 'https://urlscan.io/'],
    virustotal: ['VirusTotal', 'https://www.virustotal.com/gui/home/search'],
    wayback: ['Wayback Machine', 'https://web.archive.org/'],
    crackstation: ['CrackStation', 'https://crackstation.net/'],
    hashes: ['Hashes.com', 'https://hashes.com/en/decrypt/hash'],
    aperisolve: ["Aperi'Solve", 'https://www.aperisolve.com/'],
    stegonline: ['StegOnline', 'https://georgeom.net/StegOnline/upload'],
    metadata2go: ['Metadata2Go', 'https://www.metadata2go.com/'],
    jwt: ['JWT.io', 'https://jwt.io/'],
    regex101: ['regex101', 'https://regex101.com/']
  };

  const ROUTES = {
    encoders: ['Encoder / Decoder', 'index.html#encoders'],
    crypto: ['Classical Crypto', 'index.html#crypto'],
    hashing: ['Hash Bench', 'index.html#hashing'],
    xor: ['XOR Lab', 'index.html#xor'],
    analysis: ['Text Inspector', 'index.html#analysis'],
    data: ['Data Lab', 'index.html#data-lab'],
    file: ['File Lab', 'index.html#file-lab'],
    network: ['Network Lab', 'index.html#network'],
    guide: ['CTF Field Guide', 'index.html#guide'],
    recipes: ['Transform Recipes', 'index.html#recipes'],
    media: ['Media & PCAP', 'index.html#media-lab'],
    rsa: ['RSA Lab', 'index.html#rsa-lab'],
    notebook: ['Flag Notebook', 'index.html#notebook']
  };

  const safeExternalForDomain = (domain) => {
    const encoded = encodeURIComponent(`%.${domain}`);
    return ['crt.sh', `https://crt.sh/?q=${encoded}`];
  };

  function addFinding(map, key, title, score, reason, route, external = [], next = []) {
    const existing = map.get(key);
    if (existing) {
      existing.score = Math.min(100, existing.score + score);
      if (!existing.reasons.includes(reason)) existing.reasons.push(reason);
      external.forEach((tool) => { if (!existing.external.includes(tool)) existing.external.push(tool); });
      next.forEach((step) => { if (!existing.next.includes(step)) existing.next.push(step); });
      return;
    }
    map.set(key, { key, title, score: Math.min(100, score), reasons: [reason], route, external: [...external], next: [...next] });
  }

  function looksBase64(value) {
    const clean = value.replace(/\s+/g, '');
    return clean.length >= 12 && clean.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(clean);
  }

  function looksHex(value) {
    const clean = value.replace(/(?:0x)|[\s,:-]/gi, '');
    return clean.length >= 8 && clean.length % 2 === 0 && /^[0-9a-f]+$/i.test(clean);
  }

  function looksBinary(value) {
    const clean = value.replace(/[\s,]/g, '');
    return clean.length >= 16 && clean.length % 8 === 0 && /^[01]+$/.test(clean);
  }

  function extractDomain(value) {
    const direct = value.trim().toLowerCase().replace(/^https?:\/\//, '').split(/[\/:?#\s]/)[0];
    return /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(direct) ? direct : null;
  }

  function classify(raw, fileInfo = null) {
    const text = raw.trim();
    const lower = text.toLowerCase();
    const findings = new Map();

    if (!text && !fileInfo) return [];

    if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(text)) {
      addFinding(findings, 'jwt', 'JWT / web token', 96, 'Three Base64URL-style dot-separated sections match a JSON Web Token shape.', 'data', ['jwt', 'cyberchef'], ['Decode header and payload.', 'Check alg, exp, iat, iss, aud, and role-like claims.', 'Do not assume the signature is valid just because the token decodes.']);
    }

    if (/^https?:\/\//i.test(text)) {
      addFinding(findings, 'url', 'URL / web investigation', 92, 'The input is a full HTTP(S) URL.', 'network', ['urlscan', 'virustotal', 'wayback'], ['Parse the URL locally first.', 'Inspect path, parameters, encoding, redirects, and historical versions.', 'Open reputation or archive tools only when the CTF rules allow it.']);
    }

    const domain = extractDomain(text);
    if (domain && !/^https?:\/\//i.test(text)) {
      addFinding(findings, 'domain', 'Domain / DNS / subdomain recon', 92, 'The input matches a fully qualified domain name.', 'network', ['crtsh-domain', 'mxtoolbox', 'urlscan'], ['Check DNS records and certificate-transparency names.', 'Look for dev, staging, API, VPN, mail, or legacy hostnames.', 'Treat certificate-transparency results as leads, not proof that a host is live.']);
    }

    if (/^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/.test(text)) {
      addFinding(findings, 'ip', 'IPv4 / CIDR clue', 94, 'The input matches an IPv4 address or CIDR range.', 'network', ['mxtoolbox'], ['Calculate the network range if a prefix is present.', 'Check whether the address is private or public before using external lookups.', 'Use only challenge infrastructure you are authorized to inspect.']);
    }

    if (/^[a-f0-9]+$/i.test(text)) {
      const hashTypes = { 32: 'MD5 / NTLM-sized', 40: 'SHA-1-sized', 56: 'SHA-224-sized', 64: 'SHA-256-sized', 96: 'SHA-384-sized', 128: 'SHA-512-sized' };
      if (hashTypes[text.length]) {
        addFinding(findings, 'hash', 'Hash / digest', 95, `${text.length} hexadecimal characters match a common ${hashTypes[text.length]} digest length.`, 'hashing', ['crackstation', 'hashes', 'cyberchef'], ['Identify the likely hash family before attempting recovery.', 'Try challenge-provided context and wordlists before brute force.', 'Remember that multiple hash families can share the same length.']);
      }
    }

    if (looksBase64(text) && !findings.has('jwt')) {
      addFinding(findings, 'encoding', 'Encoded text', 78, 'The character set, padding, and length are consistent with Base64.', 'encoders', ['cyberchef', 'dcode'], ['Decode once and inspect the output.', 'If the output is still structured or encoded, continue with a recipe rather than guessing.', 'Check for compression, hex, URLs, JSON, or another Base64 layer.']);
    }

    if (looksHex(text) && !findings.has('hash')) {
      addFinding(findings, 'hex', 'Hexadecimal data', 78, 'The input can be interpreted as an even-length hexadecimal byte sequence.', 'encoders', ['cyberchef'], ['Decode hex to bytes or UTF-8.', 'If the result is binary, move to File Lab.', 'If the output is unreadable, consider XOR or compressed data.']);
    }

    if (looksBinary(text)) {
      addFinding(findings, 'binary', 'Binary-encoded bytes', 88, 'The input contains only binary digits in complete byte-sized groups.', 'encoders', ['cyberchef'], ['Decode 8-bit groups to bytes.', 'Inspect the resulting text or magic bytes.', 'If readable text appears, continue from that new clue.']);
    }

    if (/^\d{10}$/.test(text) || /^\d{13}$/.test(text)) {
      addFinding(findings, 'time', 'Unix timestamp', 84, `${text.length === 10 ? '10' : '13'} digits are consistent with Unix ${text.length === 10 ? 'seconds' : 'milliseconds'}.`, 'data', ['cyberchef'], ['Convert to UTC and local time.', 'Compare the time with challenge events, logs, certificate dates, or file metadata.']);
    }

    if (/\b(?:dns|txt|cname|mx|aaaa?|ptr|ns|spf|dkim|dmarc|certificate transparency|subdomain|crt\.sh)\b/i.test(text)) {
      addFinding(findings, 'dns', 'DNS / certificate-transparency clue', 74, 'The clue contains DNS, certificate, or subdomain terminology.', 'network', ['crtsh-domain', 'mxtoolbox', 'urlscan'], ['Start with the exact DNS record type mentioned.', 'For subdomains, inspect certificate-transparency records.', 'Record findings in the notebook before branching into more enumeration.']);
    }

    if (/\b(?:caesar|rot\d*|vigen[eè]re|atbash|rail fence|morse|bacon|polybius|affine|cipher|shift)\b/i.test(text)) {
      addFinding(findings, 'classical', 'Classical cipher', 80, 'The clue names or strongly hints at a classical cipher family.', 'crypto', ['dcode', 'boxentriq', 'cyberchef'], ['Identify the cipher before changing parameters.', 'Preserve spaces and punctuation; they can be clues.', 'Try all Caesar shifts only when the cipher family supports it.']);
    }

    if (/\b(?:rsa|modulus|public exponent|private exponent|prime|p\s*=|q\s*=|phi\b|e\s*=\s*65537|gcd)\b/i.test(text)) {
      addFinding(findings, 'rsa', 'RSA challenge', 86, 'RSA parameter terminology appears in the clue.', 'rsa', ['cyberchef', 'dcode'], ['Collect n, e, c and any supplied p/q values.', 'Check small-prime, shared-prime, or parameter mistakes before considering factorization.', 'Use raw modular operations only when the challenge is intentionally using textbook RSA.']);
    }

    if (/\b(?:xor|exclusive[- ]or|single[- ]byte|repeating key)\b/i.test(text)) {
      addFinding(findings, 'xor', 'XOR challenge', 86, 'The clue explicitly points to XOR or a repeating/single-byte key.', 'xor', ['cyberchef'], ['Determine whether the input is text or hex bytes.', 'Try single-byte ranking before broad brute force.', 'Use known plaintext or flag-format structure when available.']);
    }

    if (/\b(?:steg|steganography|lsb|least significant bit|bit plane|hidden in (?:the )?image|alpha channel|exif|metadata)\b/i.test(text) || /\.(?:png|jpe?g|gif|bmp|webp)\b/i.test(text)) {
      addFinding(findings, 'stego', 'Image / steganography', 82, 'The clue references image data, metadata, LSBs, channels, or a common image extension.', 'media', ['aperisolve', 'stegonline', 'metadata2go'], ['Inspect metadata and dimensions first.', 'Check RGB/alpha channels and bit planes.', 'Look for appended or embedded data if visual inspection finds nothing.']);
    }

    if (/\b(?:pcap|pcapng|packet capture|wireshark|tcpdump|dns traffic|http traffic)\b/i.test(text) || /\.(?:pcap|pcapng)\b/i.test(text)) {
      addFinding(findings, 'pcap', 'Packet capture / network forensics', 88, 'The clue references packet captures or traffic-analysis tooling.', 'media', ['cyberchef'], ['Identify protocols and top talkers.', 'Filter DNS, HTTP, TCP streams, and suspicious payloads.', 'Extract printable content and record evidence before following a new lead.']);
    }

    if (/\.(?:pdf|zip|7z|rar|gz|tar|elf|exe|dll|bin|dat|docx?|xlsx?|pptx?)\b/i.test(text) || /\b(?:magic bytes|file signature|strings|binwalk|embedded file|carve|archive)\b/i.test(text)) {
      addFinding(findings, 'file', 'File forensics / triage', 78, 'The clue references a file type, signature, archive, carving, or embedded content.', 'file', ['cyberchef'], ['Verify the file type by magic bytes instead of trusting the extension.', 'Hash it and extract printable strings.', 'Inspect archives or embedded content only after basic triage.']);
    }

    if (/\b(?:wayback|archive|old website|previous version|historical|deleted page|osint|whois)\b/i.test(text)) {
      addFinding(findings, 'osint', 'OSINT / historical web', 76, 'The wording suggests historical or public-source investigation.', 'guide', ['wayback', 'urlscan', 'virustotal'], ['Preserve the exact domain, path, username, or date clue.', 'Check historical snapshots before broad searching.', 'Corroborate results instead of trusting a single archived artifact.']);
    }

    if (/\b(?:flag\{|ctf\{|thm\{|htb\{|picoctf\{)[^}\n]*\}/i.test(text)) {
      addFinding(findings, 'flag', 'Flag-shaped token detected', 99, 'The input already contains a common CTF flag structure.', 'notebook', [], ['Verify the flag belongs to the current challenge.', 'Save the supporting evidence, not just the token.', 'Submit only through the CTF platform.']);
    }

    if (/\b(?:regex|regular expression|pattern match|grep|extract)\b/i.test(text)) {
      addFinding(findings, 'pattern', 'Pattern / extraction task', 60, 'The clue suggests extracting or matching structured text.', 'analysis', ['regex101', 'cyberchef'], ['Inspect the text before writing a complex pattern.', 'Start with a narrow expression and test against known positives.', 'Extract flag-shaped tokens as a quick sanity check.']);
    }

    if (fileInfo) {
      const fileReason = `${fileInfo.name} identified locally as ${fileInfo.kind}.`;
      if (fileInfo.family === 'image') addFinding(findings, 'stego', 'Image / steganography', 95, fileReason, 'media', ['aperisolve', 'stegonline', 'metadata2go'], ['Inspect metadata.', 'View individual channels and bit planes.', 'Check for appended or embedded data.']);
      else if (fileInfo.family === 'pcap') addFinding(findings, 'pcap', 'Packet capture / network forensics', 98, fileReason, 'media', [], ['Inspect protocol counts.', 'Filter suspicious conversations.', 'Extract readable payloads and DNS/HTTP artifacts.']);
      else addFinding(findings, 'file', 'File forensics / triage', 92, fileReason, 'file', ['cyberchef'], ['Confirm the detected type.', 'Hash the file and inspect strings.', 'Use extension-specific analysis only after basic triage.']);
    }

    if (!findings.size) {
      addFinding(findings, 'unknown', 'Unknown / mixed clue', 35, 'No strong fingerprint matched. Start with broad local inspection instead of forcing a guess.', 'analysis', ['cyberchef', 'dcode'], ['Look for encodings, separators, repeated structure, filenames, domains, and flag shapes.', 'Search the Field Guide using important nouns from the challenge.', 'Add more of the challenge question or artifact context and run Scout again.']);
    }

    return [...findings.values()].sort((a, b) => b.score - a.score).slice(0, 4);
  }

  function toolTuple(key, domain) {
    if (key === 'crtsh-domain' && domain) return safeExternalForDomain(domain);
    return TOOLS[key];
  }

  function buttonLink(label, href, external = false) {
    const a = document.createElement('a');
    a.className = 'ghost-button';
    a.textContent = label;
    a.href = href;
    if (external) {
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
    }
    return a;
  }

  function render(findings, raw) {
    results.replaceChildren();
    const domain = extractDomain(raw || '');

    findings.forEach((finding, index) => {
      const card = document.createElement('article');
      card.className = 'scout-card';

      const head = document.createElement('div');
      head.className = 'scout-card-head';
      const h3 = document.createElement('h3');
      h3.textContent = `${index + 1}. ${finding.title}`;
      const score = document.createElement('span');
      score.className = 'scout-score';
      score.textContent = `${finding.score}% MATCH`;
      head.append(h3, score);
      card.append(head);

      const reason = document.createElement('p');
      reason.className = 'scout-reason';
      reason.textContent = finding.reasons.join(' ');
      card.append(reason);

      if (finding.next.length) {
        const list = document.createElement('ol');
        list.className = 'scout-next';
        finding.next.slice(0, 3).forEach((step) => {
          const li = document.createElement('li');
          li.textContent = step;
          list.append(li);
        });
        card.append(list);
      }

      const links = document.createElement('div');
      links.className = 'scout-links';
      const route = ROUTES[finding.route];
      if (route) links.append(buttonLink(`FLAGKIT: ${route[0].toUpperCase()}`, route[1]));
      finding.external.slice(0, 3).forEach((key) => {
        const tool = toolTuple(key, domain);
        if (tool) links.append(buttonLink(tool[0], tool[1], true));
      });
      card.append(links);
      results.append(card);
    });
  }

  let currentFileInfo = null;

  function run() {
    render(classify(input.value, currentFileInfo), input.value);
  }

  function bytesStart(bytes, signature) {
    return signature.every((byte, index) => bytes[index] === byte);
  }

  function detectFileKind(name, bytes) {
    const lower = name.toLowerCase();
    if (bytesStart(bytes, [0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])) return { kind: 'PNG image', family: 'image' };
    if (bytesStart(bytes, [0xff,0xd8,0xff])) return { kind: 'JPEG image', family: 'image' };
    if (bytesStart(bytes, [0x47,0x49,0x46,0x38])) return { kind: 'GIF image', family: 'image' };
    if (bytesStart(bytes, [0x25,0x50,0x44,0x46])) return { kind: 'PDF document', family: 'file' };
    if (bytesStart(bytes, [0x50,0x4b,0x03,0x04])) return { kind: 'ZIP-compatible archive/container', family: 'file' };
    if (bytesStart(bytes, [0x7f,0x45,0x4c,0x46])) return { kind: 'ELF executable', family: 'file' };
    if (bytesStart(bytes, [0x4d,0x5a])) return { kind: 'PE/DOS executable', family: 'file' };
    if (bytesStart(bytes, [0x1f,0x8b])) return { kind: 'GZIP archive', family: 'file' };
    if (bytesStart(bytes, [0x0a,0x0d,0x0d,0x0a])) return { kind: 'PCAPNG capture', family: 'pcap' };
    if (bytesStart(bytes, [0xa1,0xb2,0xc3,0xd4]) || bytesStart(bytes, [0xd4,0xc3,0xb2,0xa1]) || bytesStart(bytes, [0xa1,0xb2,0x3c,0x4d]) || bytesStart(bytes, [0x4d,0x3c,0xb2,0xa1])) return { kind: 'classic PCAP capture', family: 'pcap' };
    if (/\.(png|jpe?g|gif|bmp|webp)$/i.test(lower)) return { kind: 'image by filename', family: 'image' };
    if (/\.(pcap|pcapng)$/i.test(lower)) return { kind: 'packet capture by filename', family: 'pcap' };
    return { kind: 'unknown binary/file type', family: 'file' };
  }

  fileInput.addEventListener('change', async () => {
    const file = fileInput.files[0];
    if (!file) {
      currentFileInfo = null;
      fileMeta.textContent = 'Optional: reads only the filename and first bytes locally.';
      run();
      return;
    }
    const bytes = new Uint8Array(await file.slice(0, 16).arrayBuffer());
    const detected = detectFileKind(file.name, bytes);
    currentFileInfo = { name: file.name, size: file.size, ...detected };
    fileMeta.textContent = `${file.name} • ${file.size.toLocaleString()} bytes • ${detected.kind} • local inspection only`;
    run();
  });

  document.getElementById('scout-run').addEventListener('click', run);
  document.getElementById('scout-clear').addEventListener('click', () => {
    input.value = '';
    fileInput.value = '';
    currentFileInfo = null;
    fileMeta.textContent = 'Optional: reads only the filename and first bytes locally.';
    render(classify('', null), '');
    results.innerHTML = '<div class="workbench scout-empty"><div><strong>Waiting for a clue.</strong><p>Scout will rank the most likely paths and explain each recommendation.</p></div></div>';
    input.focus();
  });
  document.getElementById('scout-example').addEventListener('click', () => {
    input.value = 'What DNS TXT record and certificate transparency entries can reveal hidden subdomains for example.com?';
    run();
  });
  document.querySelectorAll('[data-scout-sample]').forEach((button) => {
    button.addEventListener('click', () => {
      input.value = button.dataset.scoutSample;
      run();
    });
  });
  input.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') run();
  });
})();
