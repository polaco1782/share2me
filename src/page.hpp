#pragma once

#include <string>

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
  .result a.copy-link { color: var(--accent); text-decoration: none; cursor: pointer; }
  .result a.copy-link:hover { text-decoration: underline; }
  .result .hint { color: #64748b; font-size: .8rem; margin-top: .6rem; }
  .toast-balloon {
    position: fixed; top: 1.2rem; left: 50%; transform: translateX(-50%);
    background: #166534; color: #bbf7d0; font-weight: 600;
    font-size: .95rem; padding: .7rem 1.6rem;
    border-radius: 10px; box-shadow: 0 6px 24px rgba(0,0,0,.45);
    opacity: 0; pointer-events: none;
    transition: opacity .35s ease, top .35s ease;
    z-index: 9999;
  }
  .toast-balloon.show { opacity: 1; top: 1.6rem; }
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
<div class="toast-balloon" id="toastBalloon">&#9989; Link copied to clipboard!</div>
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

  function copyLink(ev) {
    ev.preventDefault();
    const url = ev.currentTarget.dataset.url;
    const t = document.getElementById('toastBalloon');
    navigator.clipboard.writeText(url).then(() => {
      if (!t) return;
      t.classList.remove('show');
      void t.offsetWidth;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 2000);
    });
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
          let ehtml = '&#128274; Encrypted &amp; Uploaded!<br><br>'
            + '<small style="color:#4ade80">Key is in the link only &#8212; never sent to the server.</small>'
            + '<br><br>&#128279; Download: <a class="copy-link" href="#" data-url="' + link + '">' + link + '</a>';
          if (file.type && file.type.startsWith('image/')) {
            const vl = location.origin + '/v/' + data.hash + '#' + p.toString();
            ehtml += '<br><br>&#128444;&#65039; View: <a class="copy-link" href="#" data-url="' + vl + '">' + vl + '</a>';
          }
          ehtml += '<p class="hint">&#128161; Click a link to copy it to your clipboard.</p>';
          resultDiv.innerHTML = ehtml;
          resultDiv.querySelectorAll('.copy-link').forEach(a => a.addEventListener('click', copyLink));
        } else {
          link = location.origin + '/' + data.hash;
          let html = '&#9989; Uploaded!<br><br>&#128279; Download: <a class="copy-link" href="#" data-url="' + link + '">' + link + '</a>';
          if (data.content_type && data.content_type.startsWith('image/')) {
            const vl = location.origin + '/v/' + data.hash;
            html += '<br><br>&#128444;&#65039; View: <a class="copy-link" href="#" data-url="' + vl + '">' + vl + '</a>';
          }
          html += '<p class="hint">&#128161; Click a link to copy it to your clipboard.</p>';
          resultDiv.innerHTML = html;
          resultDiv.querySelectorAll('.copy-link').forEach(a => a.addEventListener('click', copyLink));
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

/// Generate the image viewer HTML page with embedded metadata.
std::string image_viewer_html(const std::string& token,
                                      const std::string& filename,
                                      bool single_download) {
    // Escape filename for safe embedding in a JS single-quoted string
    std::string js_name;
    js_name.reserve(filename.size());
    for (char c : filename) {
        switch (c) {
            case '\\': js_name += "\\\\"; break;
            case '\'': js_name += "\\'";  break;
            case '"':  js_name += "\\\""; break;
            case '\n': js_name += "\\n";  break;
            case '\r': js_name += "\\r";  break;
            case '<':  js_name += "\\x3c"; break;
            case '>':  js_name += "\\x3e"; break;
            default:   js_name += c;
        }
    }

    std::string sd = single_download ? "true" : "false";

    return R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Share2Me &#8211; View</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --accent: #38bdf8; --accent-hover: #7dd3fc;
    --danger: #f87171; --success: #4ade80; --warn: #fbbf24; --radius: 12px;
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
    border-radius: var(--radius); padding: 2rem;
    width: 100%; max-width: 900px;
    box-shadow: 0 8px 30px rgba(0,0,0,.35);
    text-align: center;
  }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  .sub { color: #94a3b8; font-size: .85rem; margin-bottom: 1.2rem; }
  .warning-box {
    background: rgba(251,191,36,.08);
    border: 1px solid rgba(251,191,36,.3);
    border-radius: 8px; padding: 1.2rem; margin-bottom: 1.2rem;
    color: var(--warn); font-size: .9rem; line-height: 1.6;
  }
  .consumed-box {
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.3);
    border-radius: 8px; padding: .8rem; margin-top: 1rem;
    color: var(--danger); font-size: .85rem;
  }
  .img-wrap { margin: 1rem 0; }
  .img-wrap img {
    max-width: 100%; max-height: 75vh;
    border-radius: 8px; border: 1px solid var(--border);
  }
  .fname { color: #94a3b8; font-size: .85rem; margin-top: .5rem; }
  .btn {
    display: inline-block; padding: .65rem 1.4rem;
    border: none; border-radius: var(--radius);
    background: var(--accent); color: #0f172a;
    font-weight: 600; font-size: .95rem;
    cursor: pointer; transition: background .2s;
    text-decoration: none; margin: .3rem;
  }
  .btn:hover { background: var(--accent-hover); }
  .btn-sm { padding: .45rem 1rem; font-size: .85rem; }
  .error-msg { color: var(--danger); }
  .spinner {
    display: inline-block; width: 1.1rem; height: 1.1rem;
    border: 2px solid var(--border); border-top-color: var(--accent);
    border-radius: 50%; animation: spin .7s linear infinite;
    vertical-align: middle; margin-right: .4rem;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="card">
  <h1>&#128444;&#65039; Share2Me</h1>
  <p class="sub">Image Viewer</p>

  <div id="warning" style="display:none">
    <div class="warning-box">
      &#9888;&#65039; <strong>Single-use file!</strong><br>
      Viewing <strong id="warnName"></strong> will consume the link.<br>
      It cannot be viewed or downloaded again afterwards.
    </div>
    <button class="btn" id="viewBtn">View Image</button>
  </div>

  <div id="loading" style="display:none">
    <span class="spinner"></span> Loading image&#8230;
  </div>

  <div id="errorBox" style="display:none"></div>

  <div id="imageArea" style="display:none">
    <div class="img-wrap"><img id="img" alt="Shared image" /></div>
    <p class="fname" id="fname"></p>
    <button class="btn btn-sm" id="saveBtn">&#128190; Save Image</button>
    <div id="consumed" class="consumed-box" style="display:none">
      &#9888;&#65039; This was a single-use file &#8212; it has been consumed and cannot be viewed again.
    </div>
  </div>

  <div style="margin-top:1.2rem;font-size:.85rem">
    <a href="/">&#8592; Upload another file</a>
  </div>
  <div style="text-align:center;margin-top:12px;color:#94a3b8;font-size:.85rem">
    Copyright &#169; 2026 Cassiano Martin
    <br>
    <a href="https://github.com/polaco1782/share2me" target="_blank" rel="noopener noreferrer" style="color:var(--accent);text-decoration:none">Project on GitHub</a>
  </div>
</div>
<script>
const TOKEN = ')html" + token + R"html(';
const FILENAME = ')html" + js_name + R"html(';
const SINGLE_DOWNLOAD = )html" + sd + R"html(;

let blobUrl = null;

async function loadImage() {
  document.getElementById('loading').style.display = 'block';
  document.getElementById('warning').style.display = 'none';
  try {
    const res = await fetch('/' + TOKEN);
    if (!res.ok) {
      document.getElementById('loading').style.display = 'none';
      document.getElementById('errorBox').style.display = 'block';
      document.getElementById('errorBox').innerHTML =
        '<span class="error-msg">&#10060; File not found or link has expired.</span>';
      return;
    }
    const blob = await res.blob();
    blobUrl = URL.createObjectURL(blob);
    document.getElementById('img').src = blobUrl;
    document.getElementById('fname').textContent = FILENAME;
    document.getElementById('loading').style.display = 'none';
    document.getElementById('imageArea').style.display = 'block';
    if (SINGLE_DOWNLOAD)
      document.getElementById('consumed').style.display = 'block';
  } catch (err) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('errorBox').style.display = 'block';
    document.getElementById('errorBox').innerHTML =
      '<span class="error-msg">&#10060; Failed to load image: ' + err.message + '</span>';
  }
}

document.getElementById('saveBtn').addEventListener('click', function() {
  if (!blobUrl) return;
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = FILENAME;
  document.body.appendChild(a);
  a.click();
  setTimeout(function() { a.remove(); }, 100);
});

if (SINGLE_DOWNLOAD) {
  document.getElementById('warnName').textContent = FILENAME;
  document.getElementById('warning').style.display = 'block';
  document.getElementById('viewBtn').addEventListener('click', loadImage);
} else {
  loadImage();
}
</script>
</body>
</html>
)html";
}

/// Generate the E2EE image viewer HTML page.
/// The AES key and original filename arrive via the URL fragment (#k=...&n=...).
std::string encrypted_image_viewer_html(const std::string& token,
                                         bool single_download) {
    std::string sd = single_download ? "true" : "false";

    return R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Share2Me &#8211; Encrypted View</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --accent: #38bdf8; --accent-hover: #7dd3fc;
    --danger: #f87171; --success: #4ade80; --warn: #fbbf24; --radius: 12px;
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
    border-radius: var(--radius); padding: 2rem;
    width: 100%; max-width: 900px;
    box-shadow: 0 8px 30px rgba(0,0,0,.35);
    text-align: center;
  }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  .sub { color: #94a3b8; font-size: .85rem; margin-bottom: 1.2rem; }
  .warning-box {
    background: rgba(251,191,36,.08);
    border: 1px solid rgba(251,191,36,.3);
    border-radius: 8px; padding: 1.2rem; margin-bottom: 1.2rem;
    color: var(--warn); font-size: .9rem; line-height: 1.6;
  }
  .consumed-box {
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.3);
    border-radius: 8px; padding: .8rem; margin-top: 1rem;
    color: var(--danger); font-size: .85rem;
  }
  .note {
    font-size: .8rem; color: #64748b; margin-top: 1rem;
    padding: .75rem 1rem; background: rgba(56,189,248,.04);
    border: 1px solid rgba(56,189,248,.1); border-radius: 8px;
    line-height: 1.5;
  }
  .img-wrap { margin: 1rem 0; }
  .img-wrap img {
    max-width: 100%; max-height: 75vh;
    border-radius: 8px; border: 1px solid var(--border);
  }
  .fname { color: #94a3b8; font-size: .85rem; margin-top: .5rem; }
  .btn {
    display: inline-block; padding: .65rem 1.4rem;
    border: none; border-radius: var(--radius);
    background: var(--accent); color: #0f172a;
    font-weight: 600; font-size: .95rem;
    cursor: pointer; transition: background .2s;
    text-decoration: none; margin: .3rem;
  }
  .btn:hover { background: var(--accent-hover); }
  .btn-sm { padding: .45rem 1rem; font-size: .85rem; }
  .error-msg { color: var(--danger); }
  .spinner {
    display: inline-block; width: 1.1rem; height: 1.1rem;
    border: 2px solid var(--border); border-top-color: var(--accent);
    border-radius: 50%; animation: spin .7s linear infinite;
    vertical-align: middle; margin-right: .4rem;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
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
  <h1>&#128274; Share2Me</h1>
  <p class="sub">Encrypted Image Viewer <span class="e2ee-badge">&#128274; E2EE</span></p>

  <div id="warning" style="display:none">
    <div class="warning-box">
      &#9888;&#65039; <strong>Single-use file!</strong><br>
      Viewing <strong id="warnName"></strong> will consume the link.<br>
      It cannot be viewed or downloaded again afterwards.
    </div>
    <button class="btn" id="viewBtn">Decrypt &amp; View Image</button>
  </div>

  <div id="loading" style="display:none">
    <span class="spinner"></span> Fetching &amp; decrypting&#8230;
  </div>

  <div id="errorBox" style="display:none"></div>

  <div id="imageArea" style="display:none">
    <div class="img-wrap"><img id="img" alt="Decrypted image" /></div>
    <p class="fname" id="fname"></p>
    <button class="btn btn-sm" id="saveBtn">&#128190; Save Image</button>
    <div id="consumed" class="consumed-box" style="display:none">
      &#9888;&#65039; This was a single-use file &#8212; it has been consumed and cannot be viewed again.
    </div>
  </div>

  <div class="note">
    &#128273; The decryption key lives only in your browser&#8217;s address bar
    and was never transmitted to the server.
  </div>

  <div style="margin-top:1.2rem;font-size:.85rem">
    <a href="/">&#8592; Upload another file</a>
  </div>
  <div style="text-align:center;margin-top:12px;color:#94a3b8;font-size:.85rem">
    Copyright &#169; 2026 Cassiano Martin
    <br>
    <a href="https://github.com/polaco1782/share2me" target="_blank" rel="noopener noreferrer" style="color:var(--accent);text-decoration:none">Project on GitHub</a>
  </div>
</div>
<script>
const TOKEN = ')html" + token + R"html(';
const SINGLE_DOWNLOAD = )html" + sd + R"html(;

const hash   = new URLSearchParams(location.hash.slice(1));
const keyB64 = hash.get('k');
const FILENAME = hash.get('n') ? decodeURIComponent(hash.get('n')) : 'image';

let blobUrl = null;

if (!keyB64) {
  document.getElementById('errorBox').style.display = 'block';
  document.getElementById('errorBox').innerHTML =
    '<span class="error-msg">&#10060; No decryption key found in URL.<br>'
    + 'Make sure you opened the complete share link.</span>';
} else if (SINGLE_DOWNLOAD) {
  document.getElementById('warnName').textContent = FILENAME;
  document.getElementById('warning').style.display = 'block';
  document.getElementById('viewBtn').addEventListener('click', decryptAndView);
} else {
  decryptAndView();
}

async function decryptAndView() {
  document.getElementById('warning').style.display = 'none';
  document.getElementById('loading').style.display = 'block';
  try {
    const res = await fetch('/' + TOKEN);
    if (!res.ok) {
      document.getElementById('loading').style.display = 'none';
      document.getElementById('errorBox').style.display = 'block';
      document.getElementById('errorBox').innerHTML =
        '<span class="error-msg">&#10060; File not found or link has expired.</span>';
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

    // Guess MIME from filename extension, fallback to image/png
    const ext = FILENAME.split('.').pop().toLowerCase();
    const mimeMap = {png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',
                     webp:'image/webp',svg:'image/svg+xml',bmp:'image/bmp',avif:'image/avif',
                     ico:'image/x-icon',tif:'image/tiff',tiff:'image/tiff',jxl:'image/jxl'};
    const mime = mimeMap[ext] || 'image/png';

    const blob = new Blob(decrypted, { type: mime });
    blobUrl = URL.createObjectURL(blob);
    document.getElementById('img').src = blobUrl;
    document.getElementById('fname').textContent = FILENAME;
    document.getElementById('loading').style.display = 'none';
    document.getElementById('imageArea').style.display = 'block';
    if (SINGLE_DOWNLOAD)
      document.getElementById('consumed').style.display = 'block';
  } catch (err) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('errorBox').style.display = 'block';
    document.getElementById('errorBox').innerHTML =
      '<span class="error-msg">&#10060; Decryption failed: ' + err.message + '</span>';
  }
}

document.getElementById('saveBtn').addEventListener('click', function() {
  if (!blobUrl) return;
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = FILENAME;
  document.body.appendChild(a);
  a.click();
  setTimeout(function() { a.remove(); }, 100);
});
</script>
</body>
</html>
)html";
}
