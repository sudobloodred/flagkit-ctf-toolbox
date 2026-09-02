(() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const safe = (value) => escapeHtml(String(value));
  const download = (name, content, type = 'application/json') => {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const link = document.createElement('a'); link.href = url; link.download = name; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const readJsonFile = async (file) => JSON.parse(await file.text());

  // Multi-step transform recipes
  const recipeOperations = {
    base64Encode: { label: 'To Base64', run: (v) => bytesToBase64(enc.encode(v)) },
    base64Decode: { label: 'From Base64', run: (v) => dec.decode(base64ToBytes(v)) },
    hexEncode: { label: 'To Hex', run: (v) => bytesToHex(enc.encode(v)) },
    hexDecode: { label: 'From Hex', run: (v) => dec.decode(hexToBytes(v)) },
    urlEncode: { label: 'URL Encode', run: encodeURIComponent },
    urlDecode: { label: 'URL Decode', run: decodeURIComponent },
    rot13: { label: 'ROT13', run: rot13 },
    reverse: { label: 'Reverse', run: (v) => [...v].reverse().join('') },
    upper: { label: 'Uppercase', run: (v) => v.toUpperCase() },
    lower: { label: 'Lowercase', run: (v) => v.toLowerCase() },
    xor: { label: 'XOR key', parameter: 'key', run: (v, key) => {
      const keyBytes = enc.encode(key); if (!keyBytes.length) throw new Error('XOR needs a key');
      return dec.decode(Uint8Array.from(enc.encode(v), (byte, i) => byte ^ keyBytes[i % keyBytes.length]));
    }},
    stripWhitespace: { label: 'Strip whitespace', run: (v) => v.replace(/\s+/g, '') },
    decimalDecode: { label: 'Decimal → Text', run: (v) => dec.decode(Uint8Array.from(v.trim().split(/[\s,]+/), Number)) },
    binaryDecode: { label: 'Binary → Text', run: (v) => dec.decode(Uint8Array.from(v.trim().split(/\s+/), (item) => parseInt(item, 2))) }
  };
  let recipe = [];
  $('#operation-list').innerHTML = Object.entries(recipeOperations).map(([id, op]) => `<button data-add-operation="${id}">＋ ${op.label}</button>`).join('');
  $$('[data-add-operation]').forEach((button) => button.addEventListener('click', () => { recipe.push({ id: button.dataset.addOperation, parameter: '' }); renderRecipe(); }));
  function renderRecipe() {
    $('#recipe-count').textContent = `${recipe.length} OPERATION${recipe.length === 1 ? '' : 'S'}`;
    $('#recipe-chain').innerHTML = recipe.length ? recipe.map((step, index) => `${index ? '<span class="recipe-arrow">→</span>' : ''}<div class="recipe-step"><b>${recipeOperations[step.id].label}</b>${recipeOperations[step.id].parameter ? `<input data-recipe-param="${index}" value="${safe(step.parameter)}" placeholder="${recipeOperations[step.id].parameter}" />` : ''}<button title="Move left" data-recipe-up="${index}">←</button><button title="Move right" data-recipe-down="${index}">→</button><button title="Remove" data-recipe-remove="${index}">×</button></div>`).join('') : '<div class="empty-chain">Choose operations from the left to build a recipe.</div>';
    $$('[data-recipe-param]').forEach((input) => input.addEventListener('input', () => { recipe[Number(input.dataset.recipeParam)].parameter = input.value; runRecipe(); }));
    $$('[data-recipe-remove]').forEach((button) => button.addEventListener('click', () => { recipe.splice(Number(button.dataset.recipeRemove), 1); renderRecipe(); }));
    $$('[data-recipe-up]').forEach((button) => button.addEventListener('click', () => { const i=Number(button.dataset.recipeUp); if(i>0) [recipe[i-1],recipe[i]]=[recipe[i],recipe[i-1]]; renderRecipe(); }));
    $$('[data-recipe-down]').forEach((button) => button.addEventListener('click', () => { const i=Number(button.dataset.recipeDown); if(i<recipe.length-1) [recipe[i+1],recipe[i]]=[recipe[i],recipe[i+1]]; renderRecipe(); }));
    runRecipe();
  }
  function runRecipe() {
    let value = $('#recipe-input').value;
    try { recipe.forEach((step) => { value = recipeOperations[step.id].run(value, step.parameter); }); $('#recipe-output').value = value; $('#recipe-status').textContent = `✓ ${recipe.length} operation${recipe.length === 1 ? '' : 's'} complete`; }
    catch (error) { $('#recipe-output').value = ''; $('#recipe-status').textContent = `Error: ${error.message}`; }
  }
  $('#recipe-input').addEventListener('input', runRecipe);
  $('#recipe-clear').addEventListener('click', () => { recipe=[]; renderRecipe(); });
  $('#recipe-save').addEventListener('click', () => { localStorage.setItem('flagkit.recipe', JSON.stringify(recipe)); toast('Recipe saved locally'); });
  $('#recipe-load').addEventListener('click', () => { try { recipe=JSON.parse(localStorage.getItem('flagkit.recipe') || '[]').filter((s) => recipeOperations[s.id]); renderRecipe(); toast('Saved recipe loaded'); } catch { toast('Saved recipe is invalid'); } });
  renderRecipe();

  // Classic PCAP parser (browser-native, dependency-free)
  const ipAt = (view, offset) => [0,1,2,3].map((i) => view.getUint8(offset+i)).join('.');
  // Tiny embedded WebAssembly core for the hot 16-bit network-order reads.
  const pcapWasmBytes = Uint8Array.from([0,97,115,109,1,0,0,0,1,7,1,96,2,127,127,1,127,3,2,1,0,7,9,1,5,117,49,54,98,101,0,0,10,12,1,10,0,32,0,65,8,116,32,1,114,11]);
  let pcapWasm = null;
  try { pcapWasm = new WebAssembly.Instance(new WebAssembly.Module(pcapWasmBytes)).exports; } catch { /* DataView fallback below */ }
  const u16 = (view, offset) => pcapWasm ? pcapWasm.u16be(view.getUint8(offset), view.getUint8(offset + 1)) : view.getUint16(offset, false);
  $('#pcap-note').textContent = `${pcapWasm ? 'WebAssembly byte core ready.' : 'JavaScript byte-reader fallback active.'} Classic PCAP is supported; convert PCAPNG with editcap when needed.`;
  function dnsQuestion(view, offset, limit) {
    try {
      if (offset + 12 > limit || view.getUint16(offset + 4, false) < 1) return '';
      let cursor = offset + 12; const labels=[]; let guard=0;
      while (cursor < limit && guard++ < 64) { const length=view.getUint8(cursor++); if (!length) break; if ((length & 0xc0) === 0xc0) { labels.push('[ptr]'); cursor++; break; } if (cursor+length>limit) break; let label=''; for(let i=0;i<length;i++) label+=String.fromCharCode(view.getUint8(cursor++)); labels.push(label); }
      return labels.join('.');
    } catch { return ''; }
  }
  function parsePcap(buffer) {
    const view = new DataView(buffer); if (view.byteLength < 24) throw new Error('Capture is shorter than a PCAP header');
    const magic = view.getUint32(0, false); let little=false; let nanos=false;
    if (magic === 0xd4c3b2a1) little=true; else if (magic === 0xa1b2c3d4) little=false; else if (magic === 0x4d3cb2a1) {little=true;nanos=true;} else if (magic === 0xa1b23c4d) nanos=true; else if (magic === 0x0a0d0d0a) throw new Error('PCAPNG is not yet supported by the packet table; convert it with editcap -F pcap input.pcapng output.pcap'); else throw new Error('Unrecognized PCAP magic bytes');
    const linkType=view.getUint32(20,little); if(linkType!==1) throw new Error(`Link type ${linkType} is not Ethernet (DLT_EN10MB)`);
    const packets=[]; const protocols={}; let cursor=24; let firstTime=null; let lastTime=null;
    while(cursor+16<=view.byteLength && packets.length<5000) {
      const sec=view.getUint32(cursor,little); const frac=view.getUint32(cursor+4,little); const captured=view.getUint32(cursor+8,little); const original=view.getUint32(cursor+12,little); cursor+=16;
      if(captured>view.byteLength-cursor) break; const start=cursor; const end=cursor+captured; const time=sec+frac/(nanos?1e9:1e6); if(firstTime===null) firstTime=time; lastTime=time;
      let source='—',destination='—',protocol='Ethernet',info=`${original} bytes`; if(captured>=14) {
        let etherType=u16(view,start+12); let net=start+14; if(etherType===0x8100 && captured>=18){etherType=u16(view,start+16);net=start+18;}
        if(etherType===0x0800 && net+20<=end) {
          const ihl=(view.getUint8(net)&15)*4; const proto=view.getUint8(net+9); source=ipAt(view,net+12);destination=ipAt(view,net+16); const transport=net+ihl;
          if(proto===6 && transport+20<=end){protocol='TCP';const sp=u16(view,transport),dp=u16(view,transport+2),flags=view.getUint8(transport+13);const names=[[1,'FIN'],[2,'SYN'],[4,'RST'],[8,'PSH'],[16,'ACK'],[32,'URG']].filter(([mask])=>flags&mask).map(([,name])=>name);info=`${sp} → ${dp} [${names.join(',')||'NONE'}]`;source+=`:${sp}`;destination+=`:${dp}`;}
          else if(proto===17 && transport+8<=end){const sp=u16(view,transport),dp=u16(view,transport+2);protocol=(sp===53||dp===53)?'DNS':'UDP';info=`${sp} → ${dp}`;if(protocol==='DNS'){const q=dnsQuestion(view,transport+8,end);if(q) info+=` query ${q}`;}source+=`:${sp}`;destination+=`:${dp}`;}
          else if(proto===1){protocol='ICMP';info=`Type ${view.getUint8(transport)} code ${view.getUint8(transport+1)}`;} else {protocol=`IPv4/${proto}`;}
        } else if(etherType===0x0806 && net+28<=end){protocol='ARP';source=ipAt(view,net+14);destination=ipAt(view,net+24);info=view.getUint16(net+6,false)===1?'Who has?':'Reply';}
        else if(etherType===0x86dd){protocol='IPv6';info=`${original} bytes`;}
      }
      protocols[protocol]=(protocols[protocol]||0)+1; packets.push({number:packets.length+1,time:time-firstTime,source,destination,protocol,info}); cursor=end;
    }
    return {packets,protocols,little,nanos,duration:(lastTime??0)-(firstTime??0),truncated:packets.length===5000};
  }
  $('#pcap-input').addEventListener('change', async (event) => {
    const file=event.target.files[0]; if(!file)return;
    try { const result=parsePcap(await file.arrayBuffer()); $('#pcap-packets').textContent=result.packets.length+(result.truncated?'+':''); $('#pcap-size').textContent=formatBytes(file.size); $('#pcap-duration').textContent=`${result.duration.toFixed(3)}s`; $('#pcap-endian').textContent=result.little?'LITTLE':'BIG'; $('#pcap-protocols').innerHTML=Object.entries(result.protocols).sort((a,b)=>b[1]-a[1]).map(([name,count])=>`<span class="protocol-pill">${safe(name)} <b>${count}</b></span>`).join(''); $('#packet-rows').innerHTML=result.packets.slice(0,1000).map((p)=>`<tr><td>${p.number}</td><td>${p.time.toFixed(6)}</td><td>${safe(p.source)}</td><td>${safe(p.destination)}</td><td>${safe(p.protocol)}</td><td>${safe(p.info)}</td></tr>`).join(''); $('#pcap-results').classList.remove('hidden'); $('#pcap-note').textContent=result.truncated?'Showing the first 5,000 packets; the table displays the first 1,000.':'The table displays up to 1,000 packets.'; }
    catch(error){$('#pcap-results').classList.add('hidden');$('#pcap-note').textContent=`Error: ${error.message}`;}
  });

  // Image channel and bit-plane viewer
  let originalPixels=null; let imageWidth=0; let imageHeight=0;
  const canvas=$('#image-canvas'); const ctx=canvas.getContext('2d',{willReadFrequently:true});
  $('#image-input').addEventListener('change',(event)=>{const file=event.target.files[0];if(!file)return;const image=new Image();const url=URL.createObjectURL(file);image.onload=()=>{imageWidth=image.naturalWidth;imageHeight=image.naturalHeight;canvas.width=imageWidth;canvas.height=imageHeight;ctx.drawImage(image,0,0);originalPixels=ctx.getImageData(0,0,imageWidth,imageHeight);$('#image-placeholder').classList.add('hidden');$('#image-meta').textContent=`${file.name} • ${imageWidth} × ${imageHeight} • ${formatBytes(file.size)}`;renderImage();URL.revokeObjectURL(url);};image.src=url;});
  function renderImage(){if(!originalPixels)return;const mode=$('#image-view').value;const data=new Uint8ClampedArray(originalPixels.data);const channelMap={red:0,green:1,blue:2,alpha:3};for(let i=0;i<data.length;i+=4){const r=data[i],g=data[i+1],b=data[i+2],a=data[i+3];if(channelMap[mode]!==undefined){const v=data[i+channelMap[mode]];data[i]=data[i+1]=data[i+2]=v;data[i+3]=255;}else if(mode==='gray'){const v=Math.round(.299*r+.587*g+.114*b);data[i]=data[i+1]=data[i+2]=v;data[i+3]=255;}else if(mode==='bit'){const c=channelMap[$('#bit-channel').value],bit=Number($('#bit-index').value),v=((data[i+c]>>bit)&1)*255;data[i]=data[i+1]=data[i+2]=v;data[i+3]=255;}}ctx.putImageData(new ImageData(data,imageWidth,imageHeight),0,0);}
  ['image-view','bit-channel','bit-index'].forEach((id)=>$(`#${id}`).addEventListener('change',()=>{const bit=$('#image-view').value==='bit';$('#bit-control').classList.toggle('hidden',!bit);$('#bit-index-control').classList.toggle('hidden',!bit);renderImage();}));
  $('#image-download').addEventListener('click',()=>{if(!originalPixels){toast('Select an image first');return;}const link=document.createElement('a');link.download=`flagkit-${$('#image-view').value}.png`;link.href=canvas.toDataURL('image/png');link.click();});

  // RSA BigInt utilities
  const abs=(n)=>n<0n?-n:n; const gcd=(a,b)=>{a=abs(a);b=abs(b);while(b)[a,b]=[b,a%b];return a;};
  const modPow=(base,exp,mod)=>{if(mod<=0n||exp<0n)throw new Error('Modulus must be positive and exponent non-negative');let result=1n;base=((base%mod)+mod)%mod;while(exp){if(exp&1n)result=result*base%mod;base=base*base%mod;exp>>=1n;}return result;};
  const inverse=(a,m)=>{let [oldR,r]=[a,m],[oldS,s]=[1n,0n];while(r){const q=oldR/r;[oldR,r]=[r,oldR-q*r];[oldS,s]=[s,oldS-q*s];}if(abs(oldR)!==1n)throw new Error('No modular inverse');return ((oldS%m)+m)%m;};
  const isProbablyPrime=(n)=>{if(n<2n)return false;for(const p of [2n,3n,5n,7n,11n,13n,17n,19n,23n,29n,31n,37n]){if(n===p)return true;if(n%p===0n)return false;}let d=n-1n,s=0;while(!(d&1n)){d>>=1n;s++;}for(const a of [2n,3n,5n,7n,11n]){if(a>=n-1n)continue;let x=modPow(a,d,n);if(x===1n||x===n-1n)continue;let composite=true;for(let r=1;r<s;r++){x=x*x%n;if(x===n-1n){composite=false;break;}}if(composite)return false;}return true;};
  const parseBig=(value)=>{const clean=value.trim().replace(/_/g,'');if(!clean)throw new Error('Missing parameter');return BigInt(clean);};
  function updateRsa(){try{const p=parseBig($('#rsa-p').value),q=parseBig($('#rsa-q').value),e=parseBig($('#rsa-e').value);const n=p*q,phi=(p-1n)*(q-1n),d=inverse(e,phi);$('#rsa-n').textContent=n;$('#rsa-phi').textContent=phi;$('#rsa-d').textContent=d;$('#rsa-dp').textContent=d%(p-1n);$('#rsa-dq').textContent=d%(q-1n);$('#rsa-qinv').textContent=inverse(q,p);const findings=[];findings.push({text:isProbablyPrime(p)?'p is probably prime':'p is composite',warn:!isProbablyPrime(p)});findings.push({text:isProbablyPrime(q)?'q is probably prime':'q is composite',warn:!isProbablyPrime(q)});if(p===q)findings.push({text:'p and q are identical',warn:true});if(e===3n)findings.push({text:'Small public exponent e=3: check message padding',warn:true});findings.push({text:`gcd(e, φ) = ${gcd(e,phi)}`,warn:gcd(e,phi)!==1n});if(n.toString(2).length<1024)findings.push({text:`${n.toString(2).length}-bit modulus: intentionally small / weak`,warn:true});$('#rsa-findings').innerHTML=findings.map(f=>`<span class="finding-pill ${f.warn?'warn':''}">${safe(f.text)}</span>`).join('');}catch(error){['rsa-n','rsa-phi','rsa-d','rsa-dp','rsa-dq','rsa-qinv'].forEach(id=>$(`#${id}`).textContent='—');$('#rsa-findings').innerHTML=$('#rsa-p').value||$('#rsa-q').value?`<span class="finding-pill warn">${safe(error.message)}</span>`:'';}}
  ['rsa-p','rsa-q','rsa-e'].forEach(id=>$(`#${id}`).addEventListener('input',updateRsa));
  $('#rsa-compute').addEventListener('click',()=>{try{$('#rsa-result').textContent=modPow(parseBig($('#rsa-value').value),parseBig($('#rsa-exp').value),parseBig($('#rsa-mod').value));}catch(error){$('#rsa-result').textContent=error.message;}});
  function updateShared(){try{const result=gcd(parseBig($('#rsa-na').value),parseBig($('#rsa-nb').value));$('#rsa-gcd').textContent=result===1n?'1 — no shared factor':result.toString();}catch{$('#rsa-gcd').textContent='—';}}
  ['rsa-na','rsa-nb'].forEach(id=>$(`#${id}`).addEventListener('input',updateShared));
  updateRsa(); updateShared();

  // Flag notebook
  const MAX_IMPORTED_NOTES = 500;
  const MAX_IMPORTED_SNIPPETS = 200;
  const isSafeLocalId = (value) => typeof value === 'string' && /^[A-Za-z0-9-]{1,64}$/.test(value);
  const boundedText = (value, limit) => typeof value === 'string' ? value.trim().slice(0, limit) : '';
  const normalizeTimestamp = (value) => Number.isFinite(value) && value > 0 ? value : Date.now();
  const noteStatuses = new Set(['Not started', 'In progress', 'Solved']);
  function normalizeNote(value) {
    if (!value || typeof value !== 'object') return null;
    const title = boundedText(value.title, 160);
    if (!title) return null;
    return {
      id: isSafeLocalId(value.id) ? value.id : crypto.randomUUID(),
      title,
      category: boundedText(value.category, 80) || 'Other',
      status: noteStatuses.has(value.status) ? value.status : 'Not started',
      flag: boundedText(value.flag, 500),
      body: boundedText(value.body, 12000),
      created: normalizeTimestamp(value.created),
      updated: normalizeTimestamp(value.updated)
    };
  }
  function normalizeSnippet(value) {
    if (!value || typeof value !== 'object') return null;
    const title = boundedText(value.title, 160);
    const command = boundedText(value.command, 4000);
    if (!title || !command) return null;
    return {
      id: isSafeLocalId(value.id) ? value.id : crypto.randomUUID(),
      title,
      category: boundedText(value.category, 80) || 'Custom',
      command
    };
  }
  const notesKey='flagkit.notes.v1'; let notes=[];
  try{const saved=JSON.parse(localStorage.getItem(notesKey)||'[]');notes=Array.isArray(saved)?saved.map(normalizeNote).filter(Boolean).slice(0,MAX_IMPORTED_NOTES):[];}catch{notes=[];}
  const persistNotes=()=>localStorage.setItem(notesKey,JSON.stringify(notes));
  function renderNotes(){const counts={total:notes.length,solved:notes.filter(n=>n.status==='Solved').length,progress:notes.filter(n=>n.status==='In progress').length,flags:notes.filter(n=>n.flag).length};$('#notebook-stats').innerHTML=[['CHALLENGES',counts.total],['SOLVED',counts.solved],['IN PROGRESS',counts.progress],['FLAGS SAVED',counts.flags]].map(([label,value])=>`<div><span>${label}</span><strong>${value}</strong></div>`).join('');$('#notebook-grid').innerHTML=notes.length?notes.sort((a,b)=>b.updated-a.updated).map(note=>`<article class="note-card"><div class="note-head"><h3>${safe(note.title)}</h3><span class="note-status ${note.status.toLowerCase().replace(/\s/g,'-')}">${safe(note.status)}</span></div><div class="note-meta">${safe(note.category)} • UPDATED ${new Date(note.updated).toLocaleDateString()}</div>${note.flag?`<div class="note-flag">${safe(note.flag)}</div>`:''}<p class="note-body">${safe(note.body||'No notes yet.')}</p><div class="note-actions"><button data-note-edit="${note.id}">EDIT</button><button data-note-copy="${note.id}">COPY FLAG</button><button data-note-delete="${note.id}">DELETE</button></div></article>`).join(''):'<div class="notebook-empty">No challenges yet. Create one to start your field log.</div>';$$('[data-note-edit]').forEach(b=>b.addEventListener('click',()=>openNote(b.dataset.noteEdit)));$$('[data-note-copy]').forEach(b=>b.addEventListener('click',()=>{const note=notes.find(n=>n.id===b.dataset.noteCopy);note?.flag?copyText(note.flag):toast('No flag saved');}));$$('[data-note-delete]').forEach(b=>b.addEventListener('click',()=>{notes=notes.filter(n=>n.id!==b.dataset.noteDelete);persistNotes();renderNotes();}));}
  function openNote(id){const note=notes.find(n=>n.id===id);$('#note-id').value=note?.id||'';$('#note-title').value=note?.title||'';$('#note-category').value=note?.category||'Cryptography';$('#note-status').value=note?.status||'Not started';$('#note-flag').value=note?.flag||'';$('#note-body').value=note?.body||'';$('#note-form').classList.remove('hidden');$('#note-title').focus();}
  $('#note-new').addEventListener('click',()=>openNote());$('#note-cancel').addEventListener('click',()=>$('#note-form').classList.add('hidden'));
  $('#note-form').addEventListener('submit',(event)=>{event.preventDefault();const id=$('#note-id').value||crypto.randomUUID();const old=notes.find(n=>n.id===id);const note={id,title:$('#note-title').value.trim(),category:$('#note-category').value,status:$('#note-status').value,flag:$('#note-flag').value.trim(),body:$('#note-body').value.trim(),created:old?.created||Date.now(),updated:Date.now()};notes=notes.filter(n=>n.id!==id);notes.push(note);persistNotes();renderNotes();event.target.classList.add('hidden');toast('Challenge saved locally');});
  $('#notes-export-json').addEventListener('click',()=>download('flagkit-notebook.json',JSON.stringify({version:1,exported:new Date().toISOString(),notes},null,2)));
  $('#notes-export-md').addEventListener('click',()=>{const report=`# FlagKit CTF Report\n\nExported ${new Date().toLocaleString()}\n\n${notes.map(n=>`## ${n.title}\n\n- Category: ${n.category}\n- Status: ${n.status}\n- Flag: ${n.flag||'—'}\n\n${n.body||'No notes.'}`).join('\n\n---\n\n')}`;download('flagkit-report.md',report,'text/markdown');});
  $('#notes-import').addEventListener('change',async(event)=>{try{const data=await readJsonFile(event.target.files[0]);const incoming=Array.isArray(data)?data:data.notes;if(!Array.isArray(incoming))throw new Error('No notes array found');notes=incoming.map(normalizeNote).filter(Boolean).slice(0,MAX_IMPORTED_NOTES);persistNotes();renderNotes();toast(`${notes.length} notes imported`);}catch(error){toast(`Import failed: ${error.message}`);}event.target.value='';});renderNotes();

  // Custom command snippets and guide portability
  const snippetsKey='flagkit.snippets.v1';let snippets=[];try{const saved=JSON.parse(localStorage.getItem(snippetsKey)||'[]');snippets=Array.isArray(saved)?saved.map(normalizeSnippet).filter(Boolean).slice(0,MAX_IMPORTED_SNIPPETS):[];}catch{snippets=[];}
  function syncSnippets(){for(let i=guideItems.length-1;i>=0;i--)if(guideItems[i].custom)guideItems.splice(i,1);snippets.forEach(s=>guideItems.push({title:s.title,category:s.category||'Custom',summary:'User-created local command snippet.',commands:[s.command],custom:true,id:s.id}));localStorage.setItem(snippetsKey,JSON.stringify(snippets));rebuildGuideFilters();renderGuide();}
  function rebuildGuideFilters(){const categories=['All',...new Set(guideItems.map(i=>i.category))];if(!categories.includes(guideCategory))guideCategory='All';$('#guide-filters').innerHTML=categories.map(c=>`<button class="${c===guideCategory?'active':''}" data-guide-category="${safe(c)}">${safe(c)}</button>`).join('');$$('[data-guide-category]').forEach(button=>button.addEventListener('click',()=>{guideCategory=button.dataset.guideCategory;rebuildGuideFilters();renderGuide();}));}
  window.deleteCustomSnippet=(id)=>{snippets=snippets.filter(s=>s.id!==id);syncSnippets();toast('Snippet deleted');};
  $('#snippet-new').addEventListener('click',()=>{$('#snippet-form').classList.remove('hidden');$('#snippet-title').focus();});$('#snippet-cancel').addEventListener('click',()=>$('#snippet-form').classList.add('hidden'));
  $('#snippet-form').addEventListener('submit',(event)=>{event.preventDefault();snippets.push({id:crypto.randomUUID(),title:$('#snippet-title').value.trim(),category:$('#snippet-category').value.trim()||'Custom',command:$('#snippet-command').value.trim()});event.target.reset();event.target.classList.add('hidden');syncSnippets();toast('Snippet added');});
  $('#guide-export').addEventListener('click',()=>download('flagkit-guide.json',JSON.stringify({version:1,exported:new Date().toISOString(),customSnippets:snippets},null,2)));
  $('#guide-import').addEventListener('change',async(event)=>{try{const data=await readJsonFile(event.target.files[0]);const incoming=Array.isArray(data)?data:data.customSnippets;if(!Array.isArray(incoming))throw new Error('No customSnippets array found');const byId=new Map(snippets.map(s=>[s.id,s]));incoming.map(normalizeSnippet).filter(Boolean).slice(0,MAX_IMPORTED_SNIPPETS).forEach(s=>byId.set(s.id,s));snippets=[...byId.values()].slice(0,MAX_IMPORTED_SNIPPETS);syncSnippets();toast(`${snippets.length} snippets imported`);}catch(error){toast(`Import failed: ${error.message}`);}event.target.value='';});syncSnippets();

  // PWA install and service worker
  let deferredInstall=null;
  window.addEventListener('beforeinstallprompt',(event)=>{event.preventDefault();deferredInstall=event;$('#install-app').classList.remove('hidden');});
  $('#install-app').addEventListener('click',async()=>{if(!deferredInstall)return;deferredInstall.prompt();await deferredInstall.userChoice;deferredInstall=null;$('#install-app').classList.add('hidden');});
  window.addEventListener('appinstalled',()=>toast('FlagKit installed for offline use'));
  if('serviceWorker' in navigator && location.protocol.startsWith('http')) navigator.serviceWorker.register('./sw.js').catch(()=>{});
})();
