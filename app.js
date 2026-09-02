const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function showPage(id) {
  if (!document.getElementById(id)) id = 'dashboard';
  $$('.page').forEach((page) => page.classList.toggle('active', page.id === id));
  $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.page === id));
  $('#sidebar').classList.remove('open');
  if (location.hash !== `#${id}`) history.replaceState(null, '', `#${id}`);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

$$('[data-page]').forEach((button) => button.addEventListener('click', () => showPage(button.dataset.page)));
$$('[data-go]').forEach((button) => button.addEventListener('click', () => showPage(button.dataset.go)));
$('.brand').addEventListener('click', (event) => { event.preventDefault(); showPage('dashboard'); });
$('#mobile-menu').addEventListener('click', () => $('#sidebar').classList.toggle('open'));

const search = $('#tool-search');
function runSearch() {
  const query = search.value.trim().toLowerCase();
  showPage('dashboard');
  $$('.tool-card').forEach((card) => card.classList.toggle('search-hidden', query && !card.dataset.search.includes(query)));
}
search.addEventListener('input', runSearch);
document.addEventListener('keydown', (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault(); search.focus(); search.select();
  }
});

let toastTimer;
function toast(message = 'Copied to clipboard') {
  const el = $('#toast'); el.textContent = message; el.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove('show'), 1600);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast(); }
  catch { toast('Clipboard unavailable'); }
}
$$('[data-copy]').forEach((button) => button.addEventListener('click', () => copyText($(`#${button.dataset.copy}`).value)));
$$('[data-clear]').forEach((button) => button.addEventListener('click', () => {
  const input = $(`#${button.dataset.clear}`); input.value = ''; input.dispatchEvent(new Event('input'));
}));

const bytesToBase64 = (bytes) => {
  let binary = ''; bytes.forEach((byte) => binary += String.fromCharCode(byte)); return btoa(binary);
};
const base64ToBytes = (value) => {
  const clean = value.replace(/\s/g, ''); const binary = atob(clean);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
};
const bytesToHex = (bytes) => [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
const hexToBytes = (value) => {
  const clean = value.replace(/0x|[^0-9a-f]/gi, '');
  if (clean.length % 2) throw new Error('Hex input needs an even number of digits');
  return Uint8Array.from(clean.match(/.{2}/g) || [], (pair) => parseInt(pair, 16));
};
const rot13 = (value) => value.replace(/[a-z]/gi, (char) => String.fromCharCode((char.charCodeAt(0) <= 90 ? 65 : 97) + (char.toLowerCase().charCodeAt(0) - 97 + 13) % 26));

let codecMode = 'encode';
function transformCodec() {
  const input = $('#codec-input').value; const format = $('#codec-format').value;
  $('#codec-input-count').textContent = `${input.length} character${input.length === 1 ? '' : 's'}`;
  try {
    let output = '';
    if (format === 'base64') output = codecMode === 'encode' ? bytesToBase64(encoder.encode(input)) : decoder.decode(base64ToBytes(input));
    if (format === 'hex') output = codecMode === 'encode' ? bytesToHex(encoder.encode(input)) : decoder.decode(hexToBytes(input));
    if (format === 'binary') output = codecMode === 'encode' ? [...encoder.encode(input)].map((b) => b.toString(2).padStart(8, '0')).join(' ') : decoder.decode(Uint8Array.from(input.trim().split(/\s+/).filter(Boolean), (b) => parseInt(b, 2)));
    if (format === 'decimal') output = codecMode === 'encode' ? [...encoder.encode(input)].join(' ') : decoder.decode(Uint8Array.from(input.trim().split(/[\s,]+/).filter(Boolean), Number));
    if (format === 'url') output = codecMode === 'encode' ? encodeURIComponent(input) : decodeURIComponent(input);
    if (format === 'rot13') output = rot13(input);
    if (format === 'reverse') output = [...input].reverse().join('');
    if (format === 'html') {
      if (codecMode === 'encode') output = input.replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      else { const area = document.createElement('textarea'); area.innerHTML = input; output = area.value; }
    }
    $('#codec-output').value = output; $('#codec-status').textContent = `✓ ${format.toUpperCase()} ${codecMode} complete`;
  } catch (error) { $('#codec-output').value = ''; $('#codec-status').textContent = `Error: ${error.message}`; }
}
$('#codec-input').addEventListener('input', transformCodec); $('#codec-format').addEventListener('change', transformCodec);
$$('#codec-mode button').forEach((button) => button.addEventListener('click', () => { codecMode = button.dataset.mode; $$('#codec-mode button').forEach((b) => b.classList.toggle('active', b === button)); transformCodec(); }));
$('#codec-swap').addEventListener('click', () => { const old = $('#codec-input').value; $('#codec-input').value = $('#codec-output').value; $('#codec-output').value = old; codecMode = codecMode === 'encode' ? 'decode' : 'encode'; $$('#codec-mode button').forEach((b) => b.classList.toggle('active', b.dataset.mode === codecMode)); transformCodec(); });
$$('[data-recipe]').forEach((button) => button.addEventListener('click', () => { $('#codec-format').value = button.dataset.recipe; transformCodec(); }));

function caesar(value, shift) { return value.replace(/[a-z]/gi, (char) => { const base = char <= 'Z' ? 65 : 97; return String.fromCharCode(base + (char.charCodeAt(0) - base + shift + 26) % 26); }); }
function updateCaesar() { const shift = Number($('#caesar-shift').value); $('#shift-value').value = shift; $('#caesar-output').value = caesar($('#caesar-input').value, shift); }
$('#caesar-input').addEventListener('input', updateCaesar); $('#caesar-shift').addEventListener('input', updateCaesar);
$('#caesar-brute').addEventListener('click', () => { const list = $('#caesar-results'); list.innerHTML = Array.from({length:26}, (_, shift) => `<div class="result-row"><span>ROT ${shift.toString().padStart(2,'0')}</span><code>${escapeHtml(caesar($('#caesar-input').value, shift))}</code></div>`).join(''); list.classList.remove('hidden'); });

const hashAlgorithms = ['SHA-1','SHA-256','SHA-384','SHA-512'];
async function updateHashes() {
  const input = encoder.encode($('#hash-input').value);
  const values = await Promise.all(hashAlgorithms.map(async (name) => bytesToHex(new Uint8Array(await crypto.subtle.digest(name, input)))));
  $('#hash-results').innerHTML = hashAlgorithms.map((name, i) => `<div class="hash-item"><div><span>${name}</span><button data-hash-copy="${values[i]}">COPY</button></div><code>${values[i]}</code></div>`).join('');
  $$('[data-hash-copy]').forEach((b) => b.addEventListener('click', () => copyText(b.dataset.hashCopy)));
}
$('#hash-input').addEventListener('input', updateHashes);
$('#hash-identify').addEventListener('input', () => { const value = $('#hash-identify').value.trim(); const lengths = {32:'MD5 / NTLM',40:'SHA-1',56:'SHA-224',64:'SHA-256',96:'SHA-384',128:'SHA-512'}; $('#hash-identity').textContent = !value ? 'Waiting for input' : !/^[a-f0-9]+$/i.test(value) ? 'Not a plain hexadecimal digest' : lengths[value.length] || `Unknown (${value.length} hex characters)`; });

function xorInputBytes() { return $('#xor-format').value === 'hex' ? hexToBytes($('#xor-input').value) : encoder.encode($('#xor-input').value); }
function xorWith(bytes, key) { return Uint8Array.from(bytes, (byte, i) => byte ^ key[i % key.length]); }
function updateXor() {
  try { const keyValue = $('#xor-key').value; const key = /^0x[0-9a-f]{1,2}$/i.test(keyValue) ? Uint8Array.of(parseInt(keyValue,16)) : encoder.encode(keyValue); if (!key.length) throw new Error('Enter a key'); const result = xorWith(xorInputBytes(), key); $('#xor-output').value = decoder.decode(result); $('#xor-hex').textContent = `HEX: ${bytesToHex(result)}`; }
  catch (error) { $('#xor-output').value = ''; $('#xor-hex').textContent = `Error: ${error.message}`; }
}
['xor-input','xor-key'].forEach((id) => $(`#${id}`).addEventListener('input', updateXor)); $('#xor-format').addEventListener('change', updateXor);
function englishScore(bytes) { return [...bytes].reduce((score, b) => score + (b === 32 ? 4 : /[etaoinshrdluETAOINSHRDLU]/.test(String.fromCharCode(b)) ? 2 : b >= 32 && b < 127 ? .4 : -4), 0); }
$('#xor-brute').addEventListener('click', () => { try { const bytes = xorInputBytes(); const candidates = Array.from({length:256}, (_, key) => { const out = xorWith(bytes, Uint8Array.of(key)); return {key,out,score:englishScore(out)}; }).sort((a,b) => b.score-a.score).slice(0,20); const list = $('#xor-results'); list.innerHTML = candidates.map(({key,out}) => `<div class="result-row"><span>0x${key.toString(16).padStart(2,'0')}</span><code>${escapeHtml(decoder.decode(out).replace(/[^\x20-\x7E\n\r\t]/g,'·'))}</code></div>`).join(''); list.classList.remove('hidden'); } catch(error) { toast(error.message); } });

function escapeHtml(value) { return value.replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); }
function analyze() {
  const value = $('#analysis-input').value; const chars = [...value]; const counts = chars.reduce((map, char) => (map[char] = (map[char] || 0) + 1, map), {}); const entropy = value.length ? -Object.values(counts).reduce((sum,count) => { const p=count/value.length; return sum+p*Math.log2(p); },0) : 0;
  $('#metric-chars').textContent = value.length; $('#metric-words').textContent = value.trim() ? value.trim().split(/\s+/).length : 0; $('#metric-unique').textContent = Object.keys(counts).length; $('#metric-entropy').textContent = entropy.toFixed(2);
  const top = Object.entries(counts).filter(([char]) => !/\s/.test(char)).sort((a,b) => b[1]-a[1]).slice(0,24); const chart = $('#frequency-chart'); chart.classList.toggle('empty', !top.length); chart.innerHTML = top.length ? top.map(([char,count]) => `<div class="freq-bar" style="height:${Math.max(8,count/top[0][1]*175)}px" title="${escapeHtml(char)}: ${count}"><span>${escapeHtml(char)}</span></div>`).join('') : 'No data yet';
  const flags = value.match(/[A-Za-z0-9_-]{2,20}\{[^}\n]{1,120}\}/g) || []; const strings = value.match(/[\x20-\x7E]{6,}/g) || []; const tokens = [...new Set([...flags,...strings])].sort((a,b) => Number(flags.includes(b))-Number(flags.includes(a))).slice(0,30); const list = $('#token-list'); list.classList.toggle('empty', !tokens.length); list.innerHTML = tokens.length ? tokens.map((token) => `<div class="token">${escapeHtml(token)}</div>`).join('') : 'No tokens found';
}
$('#analysis-input').addEventListener('input', analyze);
updateCaesar(); updateHashes(); updateXor();

// Data lab
function updateNumberBases() {
  const raw = $('#number-input').value.trim().replace(/_/g, ''); const base = Number($('#number-base').value);
  try {
    if (!raw) throw new Error('empty');
    const clean = raw.replace(/^([-+])?0[xbo]/i, '$1');
    const sign = clean.startsWith('-') ? -1n : 1n; const digits = clean.replace(/^[-+]/, '').toLowerCase();
    const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
    if ([...digits].some((char) => alphabet.indexOf(char) < 0 || alphabet.indexOf(char) >= base)) throw new Error('Invalid digit for selected base');
    let value = 0n; for (const char of digits) value = value * BigInt(base) + BigInt(alphabet.indexOf(char)); value *= sign;
    $('#number-dec').textContent = value.toString(10); $('#number-hex').textContent = `${value < 0 ? '-' : ''}0x${(value < 0 ? -value : value).toString(16)}`;
    $('#number-bin').textContent = `${value < 0 ? '-' : ''}0b${(value < 0 ? -value : value).toString(2)}`; $('#number-oct').textContent = `${value < 0 ? '-' : ''}0o${(value < 0 ? -value : value).toString(8)}`;
  } catch (error) { ['number-dec','number-hex','number-bin','number-oct'].forEach((id) => $(`#${id}`).textContent = raw ? error.message : '—'); }
}
$('#number-input').addEventListener('input', updateNumberBases); $('#number-base').addEventListener('change', updateNumberBases);

function updateTime() {
  const value = $('#time-input').value.trim(); const mode = $('#time-mode').value;
  try {
    if (!value) throw new Error('empty'); const date = mode === 'seconds' ? new Date(Number(value) * 1000) : mode === 'milliseconds' ? new Date(Number(value)) : new Date(value);
    if (Number.isNaN(date.getTime())) throw new Error('Invalid date or timestamp');
    $('#time-local').textContent = date.toLocaleString(); $('#time-iso').textContent = date.toISOString(); $('#time-unix').textContent = Math.floor(date.getTime() / 1000).toString();
  } catch (error) { ['time-local','time-iso','time-unix'].forEach((id) => $(`#${id}`).textContent = value ? error.message : '—'); }
}
$('#time-input').addEventListener('input', updateTime); $('#time-mode').addEventListener('change', updateTime);
$('#time-now').addEventListener('click', () => { $('#time-mode').value = 'seconds'; $('#time-input').value = Math.floor(Date.now() / 1000); updateTime(); });

function decodeBase64Url(part) { const normalized = part.replace(/-/g, '+').replace(/_/g, '/'); return decoder.decode(base64ToBytes(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='))); }
function updateJwt() {
  const value = $('#jwt-input').value.trim();
  try {
    if (!value) throw new Error('Waiting for a token.'); const parts = value.split('.'); if (parts.length !== 3) throw new Error('A JWT must have three dot-separated parts.');
    const header = JSON.parse(decodeBase64Url(parts[0])); const payload = JSON.parse(decodeBase64Url(parts[1]));
    $('#jwt-header').textContent = JSON.stringify(header, null, 2); $('#jwt-payload').textContent = JSON.stringify(payload, null, 2);
    const notes = [`Algorithm: ${header.alg || 'unspecified'}`]; if (payload.exp) notes.push(`Expires: ${new Date(payload.exp * 1000).toLocaleString()}`); if (payload.iat) notes.push(`Issued: ${new Date(payload.iat * 1000).toLocaleString()}`); $('#jwt-note').textContent = `${notes.join(' • ')} • Signature not verified`;
  } catch (error) { $('#jwt-header').textContent = '—'; $('#jwt-payload').textContent = '—'; $('#jwt-note').textContent = error.message; }
}
$('#jwt-input').addEventListener('input', updateJwt);

// File lab
const magicTypes = [
  {hex:'89504e470d0a1a0a',name:'PNG image'}, {hex:'ffd8ff',name:'JPEG image'}, {hex:'474946383761',name:'GIF87a image'}, {hex:'474946383961',name:'GIF89a image'},
  {hex:'25504446',name:'PDF document'}, {hex:'504b0304',name:'ZIP / OOXML / JAR archive'}, {hex:'7f454c46',name:'ELF executable'}, {hex:'4d5a',name:'Windows PE executable'},
  {hex:'1f8b08',name:'GZIP archive'}, {hex:'425a68',name:'BZIP2 archive'}, {hex:'377abcaf271c',name:'7-Zip archive'}, {hex:'526172211a0700',name:'RAR archive'},
  {hex:'494433',name:'MP3 audio (ID3)'}, {hex:'664c6143',name:'FLAC audio'}, {hex:'4f676753',name:'Ogg container'}, {hex:'d0cf11e0a1b11ae1',name:'Microsoft Compound File'},
  {hex:'53514c69746520666f726d6174203300',name:'SQLite database'}, {hex:'0a0d0d0a',name:'PCAPNG capture'}, {hex:'d4c3b2a1',name:'PCAP capture (little endian)'}, {hex:'a1b2c3d4',name:'PCAP capture (big endian)'}
];
function formatBytes(size) { if (!size) return '0 B'; const units=['B','KB','MB','GB']; const i=Math.min(Math.floor(Math.log(size)/Math.log(1024)),3); return `${(size/1024**i).toFixed(i ? 2 : 0)} ${units[i]}`; }
async function inspectFile(file) {
  const buffer = await file.arrayBuffer(); const bytes = new Uint8Array(buffer); const hex = bytesToHex(bytes.slice(0, 64)); const detected = magicTypes.find((type) => hex.startsWith(type.hex));
  $('#file-name').textContent = file.name; $('#file-size').textContent = formatBytes(file.size); $('#file-type').textContent = detected?.name || file.type || 'Unknown signature';
  $('#file-hash').textContent = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', buffer))); $('#file-bytes').textContent = [...bytes.slice(0,64)].map((b) => b.toString(16).padStart(2,'0')).join(' ');
  const strings = []; let current = ''; for (const byte of bytes) { if (byte >= 32 && byte <= 126) current += String.fromCharCode(byte); else { if (current.length >= 6) strings.push(current); current=''; } if (strings.length >= 500) break; } if (current.length >= 6 && strings.length < 500) strings.push(current);
  $('#file-string-count').textContent = `${strings.length}${strings.length === 500 ? '+' : ''} found`; $('#file-strings').textContent = strings.join('\n') || 'No printable strings found.'; $('#file-results').classList.remove('hidden');
}
$('#file-input').addEventListener('change', (event) => event.target.files[0] && inspectFile(event.target.files[0]));
const dropZone = $('#file-drop'); ['dragenter','dragover'].forEach((name) => dropZone.addEventListener(name, (event) => { event.preventDefault(); dropZone.classList.add('dragging'); })); ['dragleave','drop'].forEach((name) => dropZone.addEventListener(name, (event) => { event.preventDefault(); dropZone.classList.remove('dragging'); }));
dropZone.addEventListener('drop', (event) => event.dataTransfer.files[0] && inspectFile(event.dataTransfer.files[0]));
$$('[data-copy-text]').forEach((button) => button.addEventListener('click', () => copyText($(`#${button.dataset.copyText}`).textContent)));

// Network lab
const intToIp = (value) => [24,16,8,0].map((shift) => (value >>> shift) & 255).join('.');
function updateCidr() {
  const value = $('#cidr-input').value.trim();
  try {
    const [ip,prefixRaw] = value.split('/'); const octets = ip.split('.').map(Number); const prefix = Number(prefixRaw);
    if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new Error('Use IPv4/prefix, for example 10.0.0.5/24');
    const ipInt = (((octets[0]<<24)>>>0) + (octets[1]<<16) + (octets[2]<<8) + octets[3]) >>> 0; const mask = prefix === 0 ? 0 : (0xffffffff << (32-prefix)) >>> 0; const network = (ipInt & mask) >>> 0; const broadcast = (network | (~mask >>> 0)) >>> 0; const hostCount = 2 ** (32-prefix);
    $('#cidr-network').textContent = `${intToIp(network)}/${prefix}`; $('#cidr-broadcast').textContent = intToIp(broadcast); $('#cidr-mask').textContent = intToIp(mask); $('#cidr-first').textContent = intToIp(prefix >= 31 ? network : network+1); $('#cidr-last').textContent = intToIp(prefix >= 31 ? broadcast : broadcast-1); $('#cidr-count').textContent = hostCount.toLocaleString();
  } catch (error) { ['cidr-network','cidr-broadcast','cidr-mask','cidr-first','cidr-last','cidr-count'].forEach((id) => $(`#${id}`).textContent = error.message); }
}
$('#cidr-input').addEventListener('input', updateCidr); updateCidr();
function updateUrl() {
  const value = $('#url-input').value.trim(); const root = $('#url-results');
  try {
    if (!value) { root.innerHTML='<span>Waiting for a URL.</span>'; return; } const url = new URL(value);
    const rows = [['Protocol',url.protocol],['Hostname',url.hostname],['Port',url.port || '(default)'],['Username',url.username || '—'],['Password',url.password || '—'],['Path',decodeURIComponent(url.pathname)],['Query',decodeURIComponent(url.search.slice(1)) || '—'],['Fragment',decodeURIComponent(url.hash.slice(1)) || '—']];
    root.innerHTML = rows.map(([label,item]) => `<div class="url-row"><b>${label}</b><code>${escapeHtml(item)}</code></div>`).join('');
  } catch { root.innerHTML='<span>Enter a complete URL including http:// or https://</span>'; }
}
$('#url-input').addEventListener('input', updateUrl);

// Searchable CTF field guide
const guideItems = [
  {title:'Linux Triage',category:'Linux',summary:'Orient yourself, locate unusual files, and inspect permissions or history.',commands:['pwd; id; uname -a','ls -lah; find . -maxdepth 3 -type f -ls','find / -type f -perm -4000 2>/dev/null','history; env | sort']},
  {title:'Files & Magic Bytes',category:'Forensics',summary:'Never trust an extension. Identify structure, embedded data, and readable clues.',commands:['file challenge.bin','xxd -l 128 challenge.bin','strings -a -n 6 challenge.bin | less','binwalk challenge.bin']},
  {title:'File Carving',category:'Forensics',summary:'Recover embedded or deleted objects from blobs and disk images.',commands:['binwalk -e challenge.bin','foremost -i image.dd -o carved','scalpel image.dd -o carved','testdisk image.dd']},
  {title:'Image Steganography',category:'Forensics',summary:'Inspect metadata, channels, appended data, and common stego containers.',commands:['exiftool image.png','zsteg -a image.png','steghide info image.jpg','stegseek image.jpg wordlist.txt']},
  {title:'PDF Examination',category:'Forensics',summary:'Inspect document metadata, text, JavaScript, attachments, and protection.',commands:['pdfinfo document.pdf','pdftotext document.pdf -','pdfimages -all document.pdf extracted','qpdf --show-encryption document.pdf']},
  {title:'Git History',category:'Forensics',summary:'Search revisions, branches, reflogs, and deleted content for hidden clues.',commands:['git log --all --oneline --decorate --graph','git log -p --all','git branch -a; git tag','git reflog; git fsck --lost-found']},
  {title:'Nmap Recon',category:'Recon',summary:'Start with service discovery, then target identified services within challenge scope.',commands:['nmap -sC -sV -oA scan TARGET','nmap -p- --min-rate 1000 TARGET','nmap -sU --top-ports 100 TARGET','nmap --script vuln -p PORT TARGET']},
  {title:'DNS & WHOIS',category:'OSINT',summary:'Inspect records, delegation, reverse DNS, registration, and certificate names.',commands:['dig example.com ANY','dig +short TXT example.com','dig -x 192.0.2.1','whois example.com']},
  {title:'HTTP Inspection',category:'Web',summary:'Study headers, redirects, cookies, methods, robots, and raw responses.',commands:['curl -i https://example.com/','curl -sS -D headers.txt -o body.html URL','curl -X OPTIONS -i URL','curl -s URL/robots.txt']},
  {title:'Web Content Discovery',category:'Web',summary:'Enumerate challenge content and virtual hosts with permission.',commands:['ffuf -u http://TARGET/FUZZ -w wordlist.txt','gobuster dir -u http://TARGET -w wordlist.txt','nikto -h http://TARGET','whatweb http://TARGET']},
  {title:'PCAP First Pass',category:'Network',summary:'Summarize protocols and endpoints before following suspicious streams.',commands:['capinfos capture.pcap','tshark -r capture.pcap -q -z io,phs','tshark -r capture.pcap -q -z conv,tcp','tshark -r capture.pcap -Y "http"']},
  {title:'Extract Network Objects',category:'Network',summary:'Follow streams and export transferred content from packet captures.',commands:['tshark -r capture.pcap -z follow,tcp,ascii,0','tshark -r capture.pcap --export-objects http,objects','tcpflow -r capture.pcap -o flows','wireshark capture.pcap']},
  {title:'WiFi PCAP',category:'Network',summary:'Inspect wireless handshakes and prepare capture material for an authorized lab.',commands:['aircrack-ng capture.cap','tshark -r capture.cap -Y "eapol"','hcxdumptool --help','hcxpcapngtool -o handshake.22000 capture.pcapng']},
  {title:'Hash Identification',category:'Passwords',summary:'Identify likely algorithms before choosing a cracking mode or strategy.',commands:['hashid HASH','hash-identifier','name-that-hash HASH','hashcat --example-hashes | less']},
  {title:'John & Hashcat',category:'Passwords',summary:'Use targeted wordlists, rules, and masks against challenge-provided hashes.',commands:['john --wordlist=wordlist.txt hashes.txt','john --show hashes.txt','hashcat -m MODE hashes.txt wordlist.txt','hashcat -m MODE hashes.txt -a 3 "?u?l?l?l?d?d"']},
  {title:'Archive & PDF Passwords',category:'Passwords',summary:'Extract crackable hashes from protected challenge files.',commands:['zip2john archive.zip > zip.hash','rar2john archive.rar > rar.hash','pdf2john.pl document.pdf > pdf.hash','john --wordlist=wordlist.txt pdf.hash']},
  {title:'RSA Checklist',category:'Crypto',summary:'Inspect parameters for weak keys, shared factors, small exponents, or reused primes.',commands:['openssl rsa -pubin -in public.pem -text -noout','openssl pkeyutl -decrypt -inkey private.pem -in cipher.bin','RsaCtfTool.py --publickey public.pem --private','python3 -m pip show pycryptodome']},
  {title:'PGP & SSL',category:'Crypto',summary:'Inspect public keys, certificates, fingerprints, and supported TLS details.',commands:['gpg --show-keys key.asc','gpg --list-packets message.pgp','openssl x509 -in cert.pem -text -noout','openssl s_client -connect HOST:443 -servername HOST']},
  {title:'Barcode & Metadata',category:'OSINT',summary:'Decode visual codes and inspect embedded author, GPS, or software fields.',commands:['zbarimg image.png','exiftool -a -u -g1 file','identify -verbose image.png','strings image.png | less']},
  {title:'Log Analysis',category:'Logs',summary:'Count events, isolate failures, and pivot on IPs, users, paths, or timestamps.',commands:["awk '{print $1}' access.log | sort | uniq -c | sort -nr | head",'grep -iE "fail|error|denied" *.log','jq -r ".source_ip" events.json | sort | uniq -c','journalctl --since today -p warning']}
];
let guideCategory = 'All';
function renderGuide() {
  const query = $('#guide-search').value.trim().toLowerCase();
  const filtered = guideItems.filter((item) => (guideCategory === 'All' || item.category === guideCategory) && (!query || `${item.title} ${item.category} ${item.summary} ${item.commands.join(' ')}`.toLowerCase().includes(query)));
  $('#guide-grid').innerHTML = filtered.length
    ? filtered.map((item) => {
        const deleteButton = item.custom
          ? `<button class="snippet-delete" data-delete-snippet="${encodeURIComponent(item.id)}">DELETE</button>`
          : '';
        return `<article class="guide-card"><div class="guide-card-head"><h3>${escapeHtml(String(item.title))}</h3><div><span class="guide-tag">${escapeHtml(String(item.category).toUpperCase())}</span>${deleteButton}</div></div><p>${escapeHtml(String(item.summary))}</p><div class="command-list">${item.commands.map((cmd) => `<div class="command"><code>${escapeHtml(String(cmd))}</code><button data-command="${encodeURIComponent(String(cmd))}">COPY</button></div>`).join('')}</div></article>`;
      }).join('')
    : '<div class="guide-empty">No matching field notes.</div>';
  $$('[data-command]').forEach((button) => button.addEventListener('click', () => copyText(decodeURIComponent(button.dataset.command))));
  $$('[data-delete-snippet]').forEach((button) => button.addEventListener('click', () => window.deleteCustomSnippet?.(decodeURIComponent(button.dataset.deleteSnippet))));
}
const guideCategories = ['All', ...new Set(guideItems.map((item) => item.category))];
$('#guide-filters').innerHTML = guideCategories.map((category) => `<button class="${category === 'All' ? 'active' : ''}" data-guide-category="${category}">${category}</button>`).join('');
$$('[data-guide-category]').forEach((button) => button.addEventListener('click', () => { guideCategory = button.dataset.guideCategory; $$('[data-guide-category]').forEach((b) => b.classList.toggle('active', b === button)); renderGuide(); }));
$('#guide-search').addEventListener('input', renderGuide); renderGuide();

const initialPage = location.hash.slice(1);
if (initialPage && document.getElementById(initialPage)) showPage(initialPage);
