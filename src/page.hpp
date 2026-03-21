#pragma once

static constexpr const char* INDEX_HTML = R"html(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Share2Me</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --accent: #38bdf8; --accent-hover: #7dd3fc;
    --danger: #f87171; --radius: 12px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg); color: var(--text);
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh; padding: 1rem;
  }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 2.5rem;
    width: 100%; max-width: 460px;
    box-shadow: 0 8px 30px rgba(0,0,0,.35);
  }
  h1 { font-size: 1.6rem; margin-bottom: .25rem; }
  .sub { color: #94a3b8; font-size: .9rem; margin-bottom: 1.8rem; }
  label.file-label {
    display: flex; align-items: center; justify-content: center;
    gap: .5rem; padding: 1.2rem;
    border: 2px dashed var(--border); border-radius: var(--radius);
    cursor: pointer; transition: border-color .2s;
    font-size: .95rem; color: #94a3b8;
  }
  label.file-label:hover { border-color: var(--accent); color: var(--accent); }
  label.file-label.has-file { border-color: var(--accent); color: var(--accent); border-style: solid; }
  input[type=file] { display: none; }
  .option {
    display: flex; align-items: center; gap: .6rem;
    margin: 1.2rem 0 1.6rem; font-size: .92rem; color: #94a3b8;
    cursor: pointer; user-select: none;
  }
  .option input { accent-color: var(--accent); width: 18px; height: 18px; cursor: pointer; }
  button {
    width: 100%; padding: .85rem; border: none; border-radius: var(--radius);
    background: var(--accent); color: #0f172a; font-weight: 600;
    font-size: 1rem; cursor: pointer; transition: background .2s;
  }
  button:hover { background: var(--accent-hover); }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .result {
    margin-top: 1.4rem; padding: 1rem; border-radius: var(--radius);
    background: #0f172a; font-size: .92rem; word-break: break-all;
    display: none;
  }
  .result a { color: var(--accent); text-decoration: none; }
  .result a:hover { text-decoration: underline; }
  .error { color: var(--danger); }
  select {
    background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px;
    padding: .4rem .7rem; font-size: .9rem;
    width: 100%; cursor: pointer;
  }
  select:focus { outline: none; border-color: var(--accent); }
  .e2ee-badge {
    display: inline-flex; align-items: center; gap: .25rem;
    font-size: .72rem; font-weight: 700; letter-spacing: .02em;
    color: #4ade80; background: rgba(74,222,128,.1);
    border: 1px solid rgba(74,222,128,.25);
    border-radius: 4px; padding: .1rem .45rem;
    vertical-align: middle; margin-left: .3rem;
  }
</style>
</head>
<body>
<div class="card">
  <h1>&#128228; Share2Me</h1>
  <p class="sub">Quick &amp; simple file sharing</p>

  <form id="uploadForm" enctype="multipart/form-data">
    <label class="file-label" id="fileLabel">
      &#128193; Choose a file or drag it here
      <input type="file" name="file" id="fileInput" required />
    </label>

    <label class="option" style="margin-bottom:.4rem">
      <input type="checkbox" name="single_download" id="singleDl" />
      Single-time download (file deleted after first download)
    </label>

    <label class="option" style="margin-bottom:.4rem">
      <input type="checkbox" id="expireEnable" />
      Set expiry time
    </label>

    <div id="expireRow" style="display:none;margin:0 0 1.6rem;padding-left:1.8rem">
      <select id="expireSelect">
        <option value="5m">5 minutes</option>
        <option value="30m">30 minutes</option>
        <option value="1h">1 hour</option>
        <option value="6h">6 hours</option>
        <option value="12h">12 hours</option>
        <option value="1d">1 day</option>
        <option value="3d">3 days</option>
        <option value="7d">7 days</option>
        <option value="30d">30 days</option>
        <option value="90d">90 days</option>
        <option value="1y">1 year</option>
      </select>
    </div>

    <label class="option" style="margin-bottom:1.2rem">
      <input type="checkbox" id="e2eeEnable" />
      End-to-end encrypted <span class="e2ee-badge">&#128274; E2EE</span>
    </label>

    <button type="submit" id="btn">Upload</button>
  </form>

  <div class="result" id="result"></div>
  <div style="text-align:center;margin-top:12px;color:#94a3b8;font-size:.85rem">
    Copyright © 2026 Cassiano Martin
    <br>
    <a href="https://github.com/polaco1782/share2me" target="_blank" rel="noopener noreferrer" style="color:var(--accent);text-decoration:none">Project on GitHub</a>
  </div>
</div>
<script>
  const fileInput   = document.getElementById('fileInput');
  const fileLabel   = document.getElementById('fileLabel');
  const form        = document.getElementById('uploadForm');
  const resultDiv   = document.getElementById('result');
  const btn         = document.getElementById('btn');
  const expireEnable = document.getElementById('expireEnable');
  const expireSelect = document.getElementById('expireSelect');
  const expireRow   = document.getElementById('expireRow');
  const e2eeEnable  = document.getElementById('e2eeEnable');

  expireEnable.addEventListener('change', () => {
    expireRow.style.display = expireEnable.checked ? 'block' : 'none';
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      fileLabel.textContent = fileInput.files[0].name;
      fileLabel.classList.add('has-file');
    }
  });

  // Encrypt a File in 1 MB AES-GCM chunks.
  // Each chunk is framed as: [4-byte big-endian ciphertext length][12-byte IV][ciphertext]
  async function encryptFile(file) {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    const CHUNK = 1024 * 1024;
    const chunks = [];
    for (let offset = 0; offset < file.size; offset += CHUNK) {
      const slice = await file.slice(offset, offset + CHUNK).arrayBuffer();
      const iv    = crypto.getRandomValues(new Uint8Array(12));
      const ct    = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, slice);
      const frame = new Uint8Array(4 + 12 + ct.byteLength);
      new DataView(frame.buffer).setUint32(0, ct.byteLength, false); // big-endian length
      frame.set(iv, 4);
      frame.set(new Uint8Array(ct), 16);
      chunks.push(frame);
    }
    const rawKey = await crypto.subtle.exportKey('raw', key);
    const keyB64 = btoa(String.fromCharCode(...new Uint8Array(rawKey)));
    return { blob: new Blob(chunks, { type: 'application/octet-stream' }), keyB64 };
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!fileInput.files.length) return;

    const file   = fileInput.files[0];
    const isE2EE = e2eeEnable.checked;

    btn.disabled = true;
    btn.textContent = isE2EE ? 'Encrypting & Uploading…' : 'Uploading…';
    resultDiv.style.display = 'none';

    let uploadFile = file;
    let keyB64 = null;

    if (isE2EE) {
      try {
        const enc = await encryptFile(file);
        uploadFile = new File([enc.blob], file.name, { type: 'application/octet-stream' });
        keyB64 = enc.keyB64;
      } catch (err) {
        resultDiv.innerHTML = '<span class="error">&#10060; Encryption failed: ' + err.message + '</span>';
        resultDiv.style.display = 'block';
        btn.disabled = false;
        btn.textContent = 'Upload';
        return;
      }
    }

    const fd = new FormData();
    fd.append('file', uploadFile);
    fd.append('single_download', document.getElementById('singleDl').checked ? '1' : '0');
    fd.append('expire_after', expireEnable.checked ? expireSelect.value : '');
    if (isE2EE) fd.append('encrypted', '1');

    try {
      const res  = await fetch('/upload', { method: 'POST', body: fd });
      const data = await res.json();
      if (data.ok) {
        let link;
        if (isE2EE) {
          const p = new URLSearchParams();
          p.set('k', keyB64);
          p.set('n', file.name);
          link = location.origin + '/d/' + data.hash + '#' + p.toString();
          resultDiv.innerHTML = '&#128274; Encrypted &amp; Uploaded!<br>'
            + '<small style="color:#4ade80">Key is in the link only &#8212; never sent to the server.</small>'
            + '<br><br>Link: <a href="' + link + '">' + link + '</a>';
        } else {
          link = location.origin + '/' + data.hash;
          resultDiv.innerHTML = '&#9989; Uploaded!<br><br>Link to file: <a href="' + link + '">' + link + '</a>';
        }
      } else {
        resultDiv.innerHTML = '<span class="error">&#10060; ' + (data.error || 'Upload failed') + '</span>';
      }
    } catch (err) {
      resultDiv.innerHTML = '<span class="error">&#10060; Network error</span>';
    }

    resultDiv.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Upload';
  });
</script>
</body>
</html>
)html";

static constexpr const char* DECRYPT_PAGE_HTML = R"html(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Share2Me &#8211; Decrypt</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --accent: #38bdf8; --accent-hover: #7dd3fc;
    --danger: #f87171; --success: #4ade80; --radius: 12px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg); color: var(--text);
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh; padding: 1rem;
  }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 2.5rem;
    width: 100%; max-width: 460px;
    box-shadow: 0 8px 30px rgba(0,0,0,.35);
    text-align: center;
  }
  h1 { font-size: 1.6rem; margin-bottom: .25rem; }
  .sub { color: #94a3b8; font-size: .9rem; margin-bottom: 1.8rem; }
  .status { font-size: 1rem; margin: 1.2rem 0; line-height: 1.7; }
  .error-msg { color: var(--danger); }
  .success-msg { color: var(--success); }
  .spinner {
    display: inline-block; width: 1.1rem; height: 1.1rem;
    border: 2px solid var(--border); border-top-color: var(--accent);
    border-radius: 50%; animation: spin .7s linear infinite;
    vertical-align: middle; margin-right: .4rem;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .note {
    font-size: .8rem; color: #64748b; margin-top: 1.4rem;
    padding: .75rem 1rem; background: rgba(56,189,248,.04);
    border: 1px solid rgba(56,189,248,.1); border-radius: 8px;
    line-height: 1.5;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .home-link { display: block; margin-top: 1.2rem; font-size: .9rem; }
</style>
</head>
<body>
<div class="card">
  <h1>&#128274; Share2Me</h1>
  <p class="sub">End-to-end encrypted file</p>
  <div class="status" id="status">
    <span class="spinner"></span>Fetching &amp; decrypting&#8230;
  </div>
  <div class="note">
    &#128273; The decryption key lives only in your browser&#8217;s address bar
    and was never transmitted to the server.
  </div>
  <a class="home-link" href="/">&#8592; Upload another file</a>
  <div style="text-align:center;margin-top:12px;color:#94a3b8;font-size:.85rem">
    Copyright © 2026 Cassiano Martin
    <br>
    <a href="https://github.com/polaco1782/share2me" target="_blank" rel="noopener noreferrer" style="color:var(--accent);text-decoration:none">Project on GitHub</a>
  </div>
</div>
<script>
async function decryptAndDownload(token, keyB64, filename) {
  const statusEl = document.getElementById('status');
  try {
    // Fetch the encrypted blob from the server
    const res = await fetch('/' + token);
    if (!res.ok) {
      statusEl.innerHTML = '<span class="error-msg">&#10060; File not found or link has expired.</span>';
      return;
    }
    const raw = await res.arrayBuffer();

    // Reconstruct the AES-GCM key from the URL fragment
    const keyBytes = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      'raw', keyBytes, 'AES-GCM', false, ['decrypt']
    );

    // Decrypt frame by frame: [4-byte BE length][12-byte IV][ciphertext]
    const view = new DataView(raw);
    const decrypted = [];
    let pos = 0;
    while (pos < raw.byteLength) {
      const len = view.getUint32(pos);        pos += 4;
      const iv  = new Uint8Array(raw, pos, 12); pos += 12;
      const ct  = new Uint8Array(raw, pos, len); pos += len;
      const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      decrypted.push(new Uint8Array(pt));
    }

    // Trigger a browser download of the plaintext
    const blob = new Blob(decrypted);
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename || 'download';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 2000);
    statusEl.innerHTML = '<span class="success-msg">&#9989; Decrypted! Your download should begin shortly.</span>';
  } catch (err) {
    statusEl.innerHTML = '<span class="error-msg">&#10060; Decryption failed: ' + err.message + '</span>';
  }
}

(function () {
  const hash   = new URLSearchParams(location.hash.slice(1));
  const keyB64 = hash.get('k');
  const name   = hash.get('n') ? decodeURIComponent(hash.get('n')) : 'download';

  // Token is the last path segment of /d/<token>
  const parts = location.pathname.split('/').filter(Boolean);
  const token = parts[parts.length - 1];

  if (!keyB64) {
    document.getElementById('status').innerHTML =
      '<span class="error-msg">&#10060; No decryption key found in URL.<br>'
      + 'Make sure you opened the complete share link.</span>';
    return;
  }
  if (!token || token === 'd') {
    document.getElementById('status').innerHTML =
      '<span class="error-msg">&#10060; Invalid share link.</span>';
    return;
  }

  decryptAndDownload(token, keyB64, name);
}());
</script>
</body>
</html>
)html";
