use serde_json::json;

pub const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Share2Me</title>
<meta name="description" content="Quick and simple self-hosted file sharing.">
<style>
:root{color-scheme:dark;--bg:#0f172a;--panel:#1e293b;--edge:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--danger:#f87171;--ok:#4ade80}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif;padding:20px}
.card{width:min(480px,100%);padding:32px;background:var(--panel);border:1px solid var(--edge);border-radius:14px;box-shadow:0 12px 35px #0006}
h1{margin:0;font-size:1.7rem}.sub{margin:4px 0 24px;color:var(--muted)}.pick{display:flex;justify-content:center;padding:22px;border:2px dashed var(--edge);border-radius:12px;color:var(--muted);cursor:pointer;text-align:center}.pick:hover,.pick.ready{border-color:var(--accent);color:var(--accent)}
input[type=file]{display:none}.option{display:flex;align-items:center;gap:9px;margin:16px 0;color:var(--muted);cursor:pointer}.option input{width:18px;height:18px;accent-color:var(--accent)}select{width:100%;padding:8px;background:var(--bg);color:var(--text);border:1px solid var(--edge);border-radius:8px}
button{width:100%;padding:13px;border:0;border-radius:10px;background:var(--accent);color:#082f49;font-weight:700;font-size:1rem;cursor:pointer}button:disabled{opacity:.55}.result{display:none;margin-top:20px;padding:15px;background:var(--bg);border-radius:10px;overflow-wrap:anywhere}.result a{color:var(--accent)}.error{color:var(--danger)}.secure{color:var(--ok);font-size:.78rem;font-weight:700}.foot{text-align:center;color:var(--muted);font-size:.82rem;margin-top:18px}.foot a{color:var(--accent)}
</style>
</head>
<body>
<main class="card">
<h1>📤 Share2Me</h1><p class="sub">Quick &amp; simple file sharing</p>
<form id="form">
  <label class="pick" id="pick"><span id="pickText">📁 Choose a file or drop it here</span><input id="file" type="file" required></label>
  <label class="option"><input id="single" type="checkbox">Single-time download</label>
  <label class="option"><input id="expiryOn" type="checkbox">Set expiry time</label>
  <div id="expiryRow" hidden><select id="expiry">
    <option value="5m">5 minutes</option><option value="30m">30 minutes</option>
    <option value="1h">1 hour</option><option value="6h">6 hours</option>
    <option value="12h">12 hours</option><option value="1d">1 day</option>
    <option value="3d">3 days</option><option value="7d">7 days</option>
    <option value="30d">30 days</option><option value="90d">90 days</option>
    <option value="1y">1 year</option>
  </select></div>
  <label class="option"><input id="e2ee" type="checkbox">End-to-end encrypted <span class="secure">🔒 E2EE</span></label>
  <button id="submit" type="submit">Upload</button>
</form>
<section class="result" id="result" aria-live="polite"></section>
<div class="foot">Copyright © 2026 Cassiano Martin<br><a href="https://github.com/polaco1782/share2me" rel="noopener noreferrer">Project on GitHub</a></div>
</main>
<script>
const fileInput=document.querySelector('#file'),pick=document.querySelector('#pick'),pickText=document.querySelector('#pickText');
const form=document.querySelector('#form'),submit=document.querySelector('#submit'),result=document.querySelector('#result');
const expiryOn=document.querySelector('#expiryOn'),expiryRow=document.querySelector('#expiryRow');
expiryOn.addEventListener('change',()=>expiryRow.hidden=!expiryOn.checked);
function showFile(){if(fileInput.files.length){pickText.textContent=fileInput.files[0].name;pick.classList.add('ready')}}
fileInput.addEventListener('change',showFile);
for(const event of ['dragenter','dragover'])pick.addEventListener(event,e=>{e.preventDefault();pick.classList.add('ready')});
pick.addEventListener('drop',e=>{e.preventDefault();if(e.dataTransfer.files.length){fileInput.files=e.dataTransfer.files;showFile()}});

async function encryptFile(file){
  const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
  const chunkSize=1024*1024,chunkCount=Math.ceil(file.size/chunkSize),header=new Uint8Array(16),headerView=new DataView(header.buffer),parts=[header];
  header.set([83,50,77,49]);headerView.setBigUint64(4,BigInt(file.size),false);headerView.setUint32(12,chunkCount,false);let chunkIndex=0;
  for(let offset=0;offset<file.size;offset+=chunkSize){
    const plain=await file.slice(offset,offset+chunkSize).arrayBuffer();
    const iv=crypto.getRandomValues(new Uint8Array(12)),aad=new Uint8Array(20);aad.set(header);new DataView(aad.buffer).setUint32(16,chunkIndex,false);
    const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad},key,plain);
    const frame=new Uint8Array(16+encrypted.byteLength);
    new DataView(frame.buffer).setUint32(0,encrypted.byteLength,false);frame.set(iv,4);frame.set(new Uint8Array(encrypted),16);parts.push(frame);chunkIndex++;
  }
  const raw=new Uint8Array(await crypto.subtle.exportKey('raw',key));
  return {blob:new Blob(parts,{type:'application/octet-stream'}),key:btoa(String.fromCharCode(...raw))};
}

function addLink(label,url){const line=document.createElement('div');line.append(label+' ');const link=document.createElement('a');link.href=url;link.textContent=url;link.addEventListener('click',async e=>{e.preventDefault();await navigator.clipboard.writeText(url);link.textContent='Copied!';setTimeout(()=>link.textContent=url,1200)});line.append(link);result.append(line)}
function showError(message){result.replaceChildren();const text=document.createElement('span');text.className='error';text.textContent='❌ '+message;result.append(text);result.style.display='block'}

form.addEventListener('submit',async event=>{
  event.preventDefault();if(!fileInput.files.length)return;
  const original=fileInput.files[0],encrypted=document.querySelector('#e2ee').checked;
  submit.disabled=true;submit.textContent=encrypted?'Encrypting & uploading…':'Uploading…';result.style.display='none';
  try{
    let upload=original,key=null;
    if(encrypted){const value=await encryptFile(original);upload=new File([value.blob],original.name,{type:'application/octet-stream'});key=value.key}
    const data=new FormData();data.append('file',upload);data.append('single_download',document.querySelector('#single').checked?'1':'0');data.append('expire_after',expiryOn.checked?document.querySelector('#expiry').value:'');if(encrypted)data.append('encrypted','1');
    const response=await fetch('/upload',{method:'POST',body:data});
    const payload=await response.json().catch(()=>({error:'Upload failed'}));if(!response.ok||!payload.ok)throw new Error(payload.error||'Upload failed');
    result.replaceChildren();const title=document.createElement('strong');title.textContent=encrypted?'🔒 Encrypted & uploaded!':'✅ Uploaded!';result.append(title,document.createElement('br'),document.createElement('br'));
    if(encrypted){const fragment=new URLSearchParams({k:key,n:original.name}).toString();addLink('🔗 Download:',location.origin+'/d/'+payload.hash+'#'+fragment);if(original.type.startsWith('image/')||original.type.startsWith('text/')||original.type==='application/json')addLink('🖼️ View:',location.origin+'/v/'+payload.hash+'#'+fragment)}
    else{addLink('🔗 Download:',location.origin+'/'+payload.hash);if(payload.viewable)addLink('🖼️ View:',location.origin+'/v/'+payload.hash)}
    result.style.display='block';
  }catch(error){showError(error instanceof Error?error.message:'Upload failed')}
  finally{submit.disabled=false;submit.textContent='Upload'}
});
</script>
</body>
</html>"#;

pub fn decrypt_page_html() -> String {
    DECRYPT_PAGE_HTML.replace("__DECRYPT_FUNCTION__", DECRYPT_FUNCTION_JS)
}

const DECRYPT_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Share2Me – Decrypt</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f172a;color:#e2e8f0;font:15px/1.5 system-ui,sans-serif;padding:20px}.card{width:min(520px,100%);background:#1e293b;border:1px solid #334155;border-radius:14px;padding:32px;text-align:center}.muted{color:#94a3b8}.error{color:#f87171}button{padding:12px 22px;border:0;border-radius:10px;background:#38bdf8;color:#082f49;font-weight:700;cursor:pointer}a{color:#38bdf8}</style></head>
<body><main class="card"><h1>🔒 Share2Me</h1><p class="muted">End-to-end encrypted download</p><p id="name"></p><button id="download">Decrypt &amp; Download</button><p id="status" class="muted" aria-live="polite"></p><p><a href="/">← Upload another file</a></p></main>
<script>
const params=new URLSearchParams(location.hash.slice(1)),keyText=params.get('k');
const requested=params.get('n')||'download',filename=(requested.split(/[\\/]/).pop()||'download').replace(/[\u0000-\u001f\u007f]/g,'');
document.querySelector('#name').textContent=filename;
__DECRYPT_FUNCTION__
const button=document.querySelector('#download'),status=document.querySelector('#status');if(!keyText){button.disabled=true;status.className='error';status.textContent='The decryption key is missing from the URL.'}
button.addEventListener('click',async()=>{button.disabled=true;status.textContent='Fetching and decrypting…';try{const response=await fetch('/'+location.pathname.split('/').pop());if(!response.ok)throw new Error('File not found or link expired');const blob=await decrypt(await response.arrayBuffer(),keyText);const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=filename;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);status.textContent='Decrypted. Your download has started.'}catch(error){status.className='error';status.textContent=error instanceof Error?error.message:'Decryption failed'}finally{button.disabled=false}});
</script></body></html>"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewerKind {
    Text,
    Image,
}

pub fn viewer_html(
    token: &str,
    filename: &str,
    single_download: bool,
    encrypted: bool,
    kind: ViewerKind,
    base_url: &str,
) -> String {
    let title = match (encrypted, kind) {
        (true, ViewerKind::Text) => "Encrypted text",
        (true, ViewerKind::Image) => "Encrypted image",
        (false, ViewerKind::Text) => "Text file",
        (false, ViewerKind::Image) => "Image",
    };
    VIEWER_HTML
        .replace("__PAGE_TITLE__", &html_escape(title))
        .replace(
            "__CANONICAL__",
            &html_escape(&format!("{base_url}/v/{token}")),
        )
        .replace("__TOKEN__", &json_for_script(token))
        .replace("__FILENAME__", &json_for_script(filename))
        .replace("__SINGLE__", if single_download { "true" } else { "false" })
        .replace("__ENCRYPTED__", if encrypted { "true" } else { "false" })
        .replace(
            "__KIND__",
            &json_for_script(match kind {
                ViewerKind::Text => "text",
                ViewerKind::Image => "image",
            }),
        )
        .replace("__DECRYPT_FUNCTION__", DECRYPT_FUNCTION_JS)
}

const VIEWER_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Share2Me – __PAGE_TITLE__</title><link rel="canonical" href="__CANONICAL__">
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f172a;color:#e2e8f0;font:15px/1.5 system-ui,sans-serif;padding:20px}.card{width:min(920px,100%);background:#1e293b;border:1px solid #334155;border-radius:14px;padding:28px;text-align:center}.muted{color:#94a3b8}.warning{color:#fbbf24;border:1px solid #854d0e;background:#42200655;border-radius:9px;padding:14px;margin:16px}.error{color:#f87171}button{padding:10px 18px;border:0;border-radius:9px;background:#38bdf8;color:#082f49;font-weight:700;cursor:pointer}pre{max-height:70vh;overflow:auto;text-align:left;white-space:pre-wrap;overflow-wrap:anywhere;background:#0f172a;border:1px solid #334155;border-radius:9px;padding:18px}img{max-width:100%;max-height:72vh;border-radius:9px}a{color:#38bdf8}.hidden{display:none}</style></head>
<body><main class="card"><h1>__PAGE_TITLE__</h1><p id="filename" class="muted"></p><section id="warning" class="warning hidden">⚠️ This is a single-use link. Viewing it will permanently consume the download.<br><button id="open">Continue</button></section><p id="status" class="muted">Loading…</p><section id="content" class="hidden"><pre id="text" class="hidden"></pre><img id="image" class="hidden" alt="Shared image"><p><button id="save">Save file</button></p></section><p><a href="/">← Upload another file</a></p></main>
<script>
const TOKEN=__TOKEN__,SERVER_FILENAME=__FILENAME__,SINGLE=__SINGLE__,ENCRYPTED=__ENCRYPTED__,KIND=__KIND__;
const fragment=new URLSearchParams(location.hash.slice(1)),requested=ENCRYPTED?(fragment.get('n')||'download'):SERVER_FILENAME;
const filename=(requested.split(/[\\/]/).pop()||'download').replace(/[\u0000-\u001f\u007f]/g,'');document.querySelector('#filename').textContent=filename;
function mimeFor(name){const ext=(name.split('.').pop()||'').toLowerCase(),map={png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',webp:'image/webp',svg:'image/svg+xml',bmp:'image/bmp',avif:'image/avif',ico:'image/x-icon',tif:'image/tiff',tiff:'image/tiff'};return map[ext]||(KIND==='text'?'text/plain;charset=utf-8':'application/octet-stream')}
__DECRYPT_FUNCTION__
let blobUrl=null;async function load(){const status=document.querySelector('#status');status.textContent=ENCRYPTED?'Fetching and decrypting…':'Loading…';try{const response=await fetch('/'+TOKEN);if(!response.ok)throw new Error('File not found or link expired');let blob;if(ENCRYPTED){const key=fragment.get('k');if(!key)throw new Error('The decryption key is missing from the URL');blob=await decrypt(await response.arrayBuffer(),key,mimeFor(filename))}else blob=await response.blob();blobUrl=URL.createObjectURL(blob);if(KIND==='text'){document.querySelector('#text').textContent=await blob.text();document.querySelector('#text').classList.remove('hidden')}else{document.querySelector('#image').src=blobUrl;document.querySelector('#image').classList.remove('hidden')}status.classList.add('hidden');document.querySelector('#content').classList.remove('hidden')}catch(error){status.className='error';status.textContent=error instanceof Error?error.message:'Unable to load file'}}
document.querySelector('#save').addEventListener('click',()=>{if(!blobUrl)return;const link=document.createElement('a');link.href=blobUrl;link.download=filename;document.body.append(link);link.click();link.remove()});if(SINGLE){document.querySelector('#status').classList.add('hidden');document.querySelector('#warning').classList.remove('hidden');document.querySelector('#open').addEventListener('click',()=>{document.querySelector('#warning').classList.add('hidden');document.querySelector('#status').classList.remove('hidden');load()})}else load();
</script></body></html>"#;

const DECRYPT_FUNCTION_JS: &str = r"async function decrypt(raw,keyText,mime=''){
  const keyBytes=Uint8Array.from(atob(keyText),c=>c.charCodeAt(0));if(keyBytes.length!==32)throw new Error('Invalid decryption key');
  if(raw.byteLength<16)throw new Error('Invalid encrypted file header');const view=new DataView(raw),header=new Uint8Array(raw,0,16);
  if(header[0]!==83||header[1]!==50||header[2]!==77||header[3]!==49)throw new Error('Unsupported encrypted file format');
  const expectedSize=Number(view.getBigUint64(4,false)),expectedChunks=view.getUint32(12,false);if(!Number.isSafeInteger(expectedSize)||expectedSize>512*1024*1024)throw new Error('Invalid encrypted file size');
  const key=await crypto.subtle.importKey('raw',keyBytes,'AES-GCM',false,['decrypt']),parts=[];let pos=16,chunkIndex=0,totalSize=0;
  while(pos<raw.byteLength){if(chunkIndex>=expectedChunks||raw.byteLength-pos<16)throw new Error('Invalid encrypted file framing');const length=view.getUint32(pos,false);pos+=4;const iv=new Uint8Array(raw,pos,12);pos+=12;if(length<16||length>raw.byteLength-pos)throw new Error('Invalid encrypted chunk length');const ciphertext=new Uint8Array(raw,pos,length);pos+=length;const aad=new Uint8Array(20);aad.set(header);new DataView(aad.buffer).setUint32(16,chunkIndex,false);const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:aad},key,ciphertext));totalSize+=plain.byteLength;if(totalSize>expectedSize)throw new Error('Invalid encrypted file size');parts.push(plain);chunkIndex++}
  if(chunkIndex!==expectedChunks||totalSize!==expectedSize)throw new Error('Encrypted file is incomplete');return new Blob(parts,{type:mime});
}";

fn json_for_script(value: &str) -> String {
    json!(value)
        .to_string()
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_values_cannot_break_out_of_script() {
        let page = viewer_html(
            "0123456789abcdef",
            "</script><script>alert(1)</script>.txt",
            false,
            false,
            ViewerKind::Text,
            "https://localhost:8443",
        );
        assert!(!page.contains("</script><script>alert(1)"));
        assert!(page.contains("\\u003c/script\\u003e"));
        assert!(!page.contains("__DECRYPT_FUNCTION__"));
    }

    #[test]
    fn decrypt_pages_share_the_authenticated_chunk_format() {
        let page = decrypt_page_html();
        assert!(!page.contains("__DECRYPT_FUNCTION__"));
        assert!(page.contains("Unsupported encrypted file format"));
        assert!(page.contains("additionalData:aad"));
    }
}
