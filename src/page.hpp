// page.hpp – Embedded web UI (keeps main.cpp free of large string literals)
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

    <button type="submit" id="btn">Upload</button>
  </form>

  <div class="result" id="result"></div>
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

  expireEnable.addEventListener('change', () => {
    expireRow.style.display = expireEnable.checked ? 'block' : 'none';
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      fileLabel.textContent = fileInput.files[0].name;
      fileLabel.classList.add('has-file');
    }
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!fileInput.files.length) return;

    btn.disabled = true;
    btn.textContent = 'Uploading…';
    resultDiv.style.display = 'none';

    const fd = new FormData();
    fd.append('file', fileInput.files[0]);
    fd.append('single_download', document.getElementById('singleDl').checked ? '1' : '0');
    fd.append('expire_after', expireEnable.checked ? expireSelect.value : '');

    try {
      const res  = await fetch('/upload', { method: 'POST', body: fd });
      const data = await res.json();
      if (data.ok) {
        const link = location.origin + '/' + data.hash;
        resultDiv.innerHTML = '&#9989; Uploaded!<br><br>Link to file: <a href="' + link + '">' + link + '</a>';
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
