use serde::Serialize;
use serde_json::json;

use crate::config::{MediaMode, RtcIceServer};

const INDEX_HTML: &str = r#"<!doctype html>
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
button,.live{width:100%;padding:13px;border:0;border-radius:10px;background:var(--accent);color:#082f49;font-weight:700;font-size:1rem;cursor:pointer}button:disabled{opacity:.55}.result{display:none;margin-top:20px;padding:15px;background:var(--bg);border-radius:10px;overflow-wrap:anywhere}.result a{color:var(--accent)}.error{color:var(--danger)}.secure{color:var(--ok);font-size:.78rem;font-weight:700}.choice{display:flex;align-items:center;gap:12px;margin:22px 0;color:var(--muted)}.choice::before,.choice::after{content:"";height:1px;flex:1;background:var(--edge)}.live{display:block;text-align:center;text-decoration:none;background:#a78bfa;color:#2e1065}.foot{text-align:center;color:var(--muted);font-size:.82rem;margin-top:18px}.foot a{color:var(--accent)}
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
__LIVE_ACTION__
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

pub fn index_html(media_enabled: bool) -> String {
    let live_action = if media_enabled {
        "<div class=\"choice\">or</div>\n<a class=\"live\" href=\"/share\">🖥️ Share your screen</a>"
    } else {
        ""
    };
    INDEX_HTML.replace("__LIVE_ACTION__", live_action)
}

pub fn room_lobby_html() -> &'static str {
    ROOM_LOBBY_HTML
}

pub fn room_page_html(room_name: &str, mode: MediaMode, ice_servers: &[RtcIceServer]) -> String {
    ROOM_PAGE_HTML
        .replace("__ROOM_STYLE__", ROOM_STYLE)
        .replace("__ROOM_JS__", ROOM_JS)
        .replace("__ROOM_NAME__", &json_for_script(room_name))
        .replace("__ICE_SERVERS__", &json_value_for_script(ice_servers))
        .replace("__MEDIA_MODE__", &json_value_for_script(&mode))
}

const ROOM_LOBBY_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Share2Me – Open a room</title>
<style>
:root{color-scheme:dark;--bg:#0f172a;--panel:#1e293b;--edge:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#a78bfa;--danger:#f87171}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif;padding:20px}.card{width:min(500px,100%);padding:32px;background:var(--panel);border:1px solid var(--edge);border-radius:14px;box-shadow:0 12px 35px #0006}h1{margin:0}.sub,.note{color:var(--muted)}label{display:grid;gap:8px;margin:24px 0 16px;font-weight:700}input{width:100%;padding:12px;border:1px solid var(--edge);border-radius:9px;background:var(--bg);color:var(--text);font:inherit}button{width:100%;padding:13px;border:0;border-radius:10px;background:var(--accent);color:#2e1065;font-weight:700;font-size:1rem;cursor:pointer}.error{color:var(--danger)}a{color:#38bdf8}
</style>
</head>
<body><main class="card"><h1>🖥️ Open a screen room</h1>
<p class="sub">Choose a reusable room name. The first person to join becomes the sharer; everyone after that joins as a viewer.</p>
<form id="roomForm"><label>Room name<input id="roomName" maxlength="48" autocomplete="off" placeholder="weekly-demo" required></label><button type="submit">Open room</button></form>
<p id="status" class="note" aria-live="polite">Use lowercase letters, numbers, and hyphens.</p>
<p class="note">Room links are reusable and easy to share. Anyone who knows the name can join, so choose a less predictable name for a private room.</p>
<p><a href="/">← File sharing</a></p></main>
<script>
const form=document.querySelector('#roomForm'),input=document.querySelector('#roomName'),status=document.querySelector('#status'),ROOM_STORAGE_KEY='share2me-room-name';
function loadRoomName(){try{return localStorage.getItem(ROOM_STORAGE_KEY)||''}catch{return ''}}
function saveRoomName(value){try{localStorage.setItem(ROOM_STORAGE_KEY,value)}catch{}}
function roomSlug(value){return value.toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,48).replace(/-+$/,'')}
input.addEventListener('input',()=>{const slug=roomSlug(input.value);status.className='note';status.textContent=slug?'Room URL: '+location.origin+'/room/'+slug:'Use lowercase letters, numbers, and hyphens.'});
form.addEventListener('submit',event=>{event.preventDefault();const slug=roomSlug(input.value);if(!slug){status.className='error';status.textContent='Enter a valid room name.';return}saveRoomName(slug);location.assign('/room/'+encodeURIComponent(slug))});
input.value=loadRoomName();if(input.value)input.dispatchEvent(new Event('input'));
</script></body></html>"#;

const ROOM_STYLE: &str = r#":root{color-scheme:dark;--bg:#0f172a;--panel:#1e293b;--edge:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--purple:#a78bfa;--danger:#f87171;--ok:#4ade80}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif;padding:20px}.shell{width:min(1260px,100%);margin:0 auto}.bar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px}.bar h1{margin:0;font-size:1.5rem}.bar a,.room-link{color:var(--accent)}.panel{padding:22px;background:var(--panel);border:1px solid var(--edge);border-radius:14px;box-shadow:0 12px 35px #0006}.join-panel{width:min(480px,100%);margin:12vh auto 0}.join-panel label{display:grid;gap:8px;margin:20px 0 14px;font-weight:700}.join-panel input{width:100%;padding:12px;border:1px solid var(--edge);border-radius:9px;background:var(--bg);color:var(--text);font:inherit}.room-grid{display:grid;grid-template-columns:minmax(0,1fr) 250px;gap:18px}.media-panel{min-width:0}.stage{position:relative;display:grid;place-items:center;min-height:300px;background:#020617;border:1px solid var(--edge);border-radius:11px;overflow:hidden}.stage video{display:block;width:100%;max-height:72vh;background:#000}.controls{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}.controls button,.join-panel button{padding:11px 16px;border:0;border-radius:9px;background:var(--accent);color:#082f49;font-weight:700;cursor:pointer}.controls button.stop{background:var(--danger);color:#450a0a}.controls button:disabled,.join-panel button:disabled{opacity:.55;cursor:not-allowed}.mic-option{display:flex;align-items:center;gap:9px;margin-top:16px;color:var(--muted);cursor:pointer}.mic-option input{width:18px;height:18px;accent-color:var(--accent)}.reactions{padding-top:14px;border-top:1px solid var(--edge)}.reactions span{align-self:center;color:var(--muted);font-size:.88rem}.reaction-button{font-size:1.25rem!important;padding:8px 11px!important;background:#334155!important;color:var(--text)!important}.creeper-head{position:relative;display:inline-block;width:1.15em;height:1.15em;background:#55ad38;box-shadow:inset .12em .12em #73c94d,inset -.12em -.12em #347e2b}.creeper-head::before{content:"";position:absolute;left:.2em;top:.24em;width:.24em;height:.24em;background:#102610;box-shadow:.52em 0 #102610,.2em .3em #102610,.32em .3em #102610,.08em .42em #102610,.2em .42em #102610,.32em .42em #102610,.44em .42em #102610}.floating-reaction .creeper-head{font-size:1.45em}.reaction-layer{position:absolute;inset:0;overflow:hidden;pointer-events:none}.floating-reaction{position:absolute;left:var(--left);bottom:-60px;display:grid;place-items:center;min-width:64px;padding:7px 10px;border-radius:999px;background:#0f172add;border:1px solid #ffffff2e;font-size:2rem;animation:float-reaction 2.8s ease-out forwards}.floating-reaction small{max-width:110px;overflow:hidden;text-overflow:ellipsis;color:var(--text);font-size:.65rem;white-space:nowrap}@keyframes float-reaction{0%{transform:translateY(0) scale(.75);opacity:0}15%{opacity:1}100%{transform:translateY(-360px) scale(1.12);opacity:0}}.people h2{margin:0 0 14px;font-size:1.05rem}.people ul{display:grid;gap:8px;margin:0 0 18px;padding:0;list-style:none}.people li{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:9px 10px;background:var(--bg);border-radius:8px}.people-name{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.badge{flex:none;color:var(--purple);font-size:.72rem;font-weight:700}.room-link{display:block;overflow-wrap:anywhere;font-size:.82rem}.copy-room{width:100%;margin-top:10px;padding:9px;border:1px solid var(--edge);border-radius:8px;background:transparent;color:var(--text);cursor:pointer}.remote-audio:empty{display:none}.remote-audio{display:grid;gap:8px;margin-top:14px}.remote-audio audio{width:min(420px,100%);height:36px}.status,.note{color:var(--muted);margin:14px 0 0}.status.error{color:var(--danger)}.status.ok{color:var(--ok)}.hidden{display:none!important}@media(max-width:800px){.room-grid{grid-template-columns:1fr}.people{grid-row:1}.stage{min-height:220px}}@media(max-width:520px){body{padding:10px}.panel{padding:14px}.bar{align-items:flex-start;flex-direction:column}.floating-reaction{animation-name:float-reaction-small}@keyframes float-reaction-small{0%{transform:translateY(0) scale(.75);opacity:0}15%{opacity:1}100%{transform:translateY(-220px) scale(1.05);opacity:0}}}"#;

const ROOM_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Share2Me – Room</title>
<style>__ROOM_STYLE__</style>
</head>
<body><main class="shell"><header class="bar"><h1>🖥️ Room: <span id="roomTitle"></span></h1><a href="/share">Open another room</a></header>
<section id="joinPanel" class="panel join-panel"><h2>Join this room</h2><p class="note">The first person in an empty room becomes the sharer.</p>
<form id="joinForm"><label>Username<input id="username" maxlength="32" autocomplete="nickname" required></label><button id="joinButton" type="submit">Join room</button></form><p id="joinStatus" class="status" aria-live="polite"></p></section>
<section id="roomPanel" class="room-grid hidden">
<div class="panel media-panel"><div class="stage"><video id="video" autoplay playsinline controls></video><p id="placeholder" class="note">Waiting for the sharer…</p><div id="reactionLayer" class="reaction-layer" aria-live="polite"></div></div>
<div id="hostControls" class="hidden"><label id="micOption" class="mic-option"><input id="includeMic" type="checkbox" checked> Include microphone</label><div class="controls"><button id="start">Start sharing</button><button id="stop" class="stop hidden">Stop sharing</button><button id="hostMute" class="hidden">Mute microphone</button></div></div>
<div id="viewerControls" class="hidden"><div class="controls"><button id="play" class="hidden">Play video and audio</button><button id="viewerMic">Enable microphone</button></div><div class="controls reactions"><span>React:</span><button class="reaction-button" data-reaction="👍" aria-label="Thumbs up">👍</button><button class="reaction-button" data-reaction="❤️" aria-label="Heart">❤️</button><button class="reaction-button" data-reaction="😂" aria-label="Laugh">😂</button><button class="reaction-button" data-reaction="😮" aria-label="Surprised">😮</button><button class="reaction-button" data-reaction="👏" aria-label="Applause">👏</button><button class="reaction-button" data-reaction="🎉" aria-label="Celebrate">🎉</button><button class="reaction-button" data-reaction="creeper" aria-label="Creeper"><span class="creeper-head" aria-hidden="true"></span></button></div></div>
<div id="viewerAudio" class="remote-audio"></div><p id="audioSafety" class="note hidden" aria-live="polite">Screen audio is paused while a viewer microphone is active, preventing participant voices from being rebroadcast.</p><p id="status" class="status" aria-live="polite">Joining room…</p></div>
<aside class="panel people"><h2>People</h2><ul id="people"></ul><strong>Room link</strong><a id="roomLink" class="room-link"></a><button id="copyRoom" class="copy-room">Copy room link</button><p class="note">Viewer microphones go only to the sharer. Reactions are shown to everyone.</p></aside>
</section></main>
<script>
__ROOM_JS__
</script></body></html>"#;

const ROOM_JS: &str = r"const ROOM=__ROOM_NAME__,MEDIA_MODE=__MEDIA_MODE__,ICE_SERVERS=__ICE_SERVERS__;
const roomTitle=document.querySelector('#roomTitle'),joinPanel=document.querySelector('#joinPanel'),joinForm=document.querySelector('#joinForm'),joinButton=document.querySelector('#joinButton'),usernameInput=document.querySelector('#username'),joinStatus=document.querySelector('#joinStatus'),roomPanel=document.querySelector('#roomPanel'),video=document.querySelector('#video'),placeholder=document.querySelector('#placeholder'),reactionLayer=document.querySelector('#reactionLayer'),hostControls=document.querySelector('#hostControls'),viewerControls=document.querySelector('#viewerControls'),includeMic=document.querySelector('#includeMic'),micOption=document.querySelector('#micOption'),startButton=document.querySelector('#start'),stopButton=document.querySelector('#stop'),hostMuteButton=document.querySelector('#hostMute'),playButton=document.querySelector('#play'),viewerMicButton=document.querySelector('#viewerMic'),viewerAudio=document.querySelector('#viewerAudio'),audioSafety=document.querySelector('#audioSafety'),statusElement=document.querySelector('#status'),peopleList=document.querySelector('#people'),roomLink=document.querySelector('#roomLink'),copyRoomButton=document.querySelector('#copyRoom');
let socket=null,role=null,participantId=null,peerKey=null,participants=[],streamActive=false,screenStream=null,micStream=null,mainPeer=null,controlChannel=null,micSender=null,microphoneMuted=false,remoteStream=null,remoteIce=[],leaving=false,reconnectTimer=null,messageChain=Promise.resolve(),mediaMessageChain=Promise.resolve();
const directPeers=new Map(),microphoneSenders=new Set(),screenAudioSenders=new Map(),activeViewerMicrophones=new Set(),stableRoomUrl=location.origin+'/room/'+encodeURIComponent(ROOM),ROOM_STORAGE_KEY='share2me-room-name',USERNAME_STORAGE_KEY='share2me-username';
function loadPreference(key){try{return localStorage.getItem(key)||''}catch{return ''}}
function savePreference(key,value){try{localStorage.setItem(key,value)}catch{}}
roomTitle.textContent=ROOM;roomLink.href=stableRoomUrl;roomLink.textContent=stableRoomUrl;usernameInput.value=loadPreference(USERNAME_STORAGE_KEY);savePreference(ROOM_STORAGE_KEY,ROOM);
function setStatus(message,kind=''){statusElement.textContent=message;statusElement.className='status'+(kind?' '+kind:'')}
function send(message){if(socket&&socket.readyState===WebSocket.OPEN)socket.send(JSON.stringify(message))}
function socketUrl(username){const scheme=location.protocol==='https:'?'wss:':'ws:';return scheme+'//'+location.host+'/api/rooms/'+encodeURIComponent(ROOM)+'/signal?username='+encodeURIComponent(username)}
function newPeerConnection(){return new RTCPeerConnection({iceServers:ICE_SERVERS,iceTransportPolicy:MEDIA_MODE==='turn'?'relay':'all'})}
async function addRemoteIce(peer,queue,candidate){if(peer.remoteDescription)await peer.addIceCandidate(candidate);else queue.push(candidate)}
async function flushRemoteIce(peer,queue){for(const candidate of queue.splice(0))await peer.addIceCandidate(candidate)}
async function waitForIceGathering(peer){if(peer.iceGatheringState==='complete')return;await new Promise(resolve=>{let timeout=null;const finish=()=>{clearTimeout(timeout);peer.removeEventListener('icegatheringstatechange',changed);resolve()},changed=()=>{if(peer.iceGatheringState==='complete')finish()};peer.addEventListener('icegatheringstatechange',changed);timeout=setTimeout(finish,5000)})}
function stopMediaStream(stream){if(stream)for(const track of stream.getTracks())track.stop()}
async function addScreenTracks(peer){const audioSenders=[];if(screenStream)for(const track of screenStream.getTracks()){const sender=peer.addTransceiver(track,{direction:'sendonly',streams:[screenStream]}).sender;if(track.kind==='audio'){screenAudioSenders.set(sender,track);audioSenders.push(sender)}}if(activeViewerMicrophones.size)await syncScreenAudio();return audioSenders}
async function addMicrophoneTrack(peer){const track=microphoneTrack();if(!track)return null;const sender=peer.addTransceiver(track,{direction:'sendonly',streams:[micStream]}).sender;microphoneSenders.add(sender);if(microphoneMuted)await sender.replaceTrack(null);return sender}
function forgetSenders(state){for(const sender of state?.screenAudioSenders||[])screenAudioSenders.delete(sender);if(state?.microphoneSender)microphoneSenders.delete(state.microphoneSender)}
async function syncScreenAudio(){const paused=activeViewerMicrophones.size>0&&screenAudioSenders.size>0;await Promise.allSettled([...screenAudioSenders].map(([sender,track])=>sender.replaceTrack(paused?null:track)));audioSafety.classList.toggle('hidden',!paused)}
function addRemoteTrack(stream,track){if(!stream.getTracks().some(existing=>existing.id===track.id))stream.addTrack(track)}
function microphoneTrack(){return micStream&&micStream.getAudioTracks()[0]}
function updateMuteButton(button){if(!microphoneTrack()){button.classList.add('hidden');return}button.classList.remove('hidden');button.textContent=microphoneMuted?'Unmute microphone':'Mute microphone'}
function notifyMicrophoneState(enabled=Boolean(micSender&&micSender.track&&!microphoneMuted)){if(role==='viewer')send({type:'microphone_state',enabled})}
async function setMicrophoneMuted(button,muted){const track=microphoneTrack();if(!track)return;button.disabled=true;microphoneMuted=muted;track.enabled=!muted;try{await Promise.allSettled([...microphoneSenders].map(sender=>sender.replaceTrack(muted?null:track)));notifyMicrophoneState()}finally{button.disabled=false;updateMuteButton(button)}}
async function toggleMicrophone(button){await setMicrophoneMuted(button,!microphoneMuted)}
async function requestMicrophone(){return navigator.mediaDevices.getUserMedia({audio:{echoCancellation:true,noiseSuppression:true,autoGainControl:true},video:false})}
function attachRemoteAudio(track,label){const audio=document.createElement('audio');audio.autoplay=true;audio.controls=true;audio.setAttribute('aria-label',label);audio.srcObject=new MediaStream([track]);viewerAudio.append(audio);audio.play().catch(()=>{});track.addEventListener('ended',()=>audio.remove(),{once:true});return audio}
function renderPresence(values){participants=Array.isArray(values)?values:[];peopleList.replaceChildren();for(const person of participants){const item=document.createElement('li'),name=document.createElement('span'),badge=document.createElement('span');name.className='people-name';name.textContent=person.username+(person.id===participantId?' (you)':'');badge.className='badge';badge.textContent=person.role==='host'?'SHARING':'WATCHING';item.append(name,badge);peopleList.append(item)}}
function showReaction(message){const item=document.createElement('div'),name=document.createElement('small');item.className='floating-reaction';item.style.setProperty('--left',(8+Math.random()*78)+'%');if(message.reaction==='creeper'){const head=document.createElement('span');head.className='creeper-head';head.setAttribute('aria-label','Creeper');item.append(head)}else item.append(document.createTextNode(message.reaction));name.textContent=message.username;item.append(name);reactionLayer.append(item);setTimeout(()=>item.remove(),3000)}
function viewerName(id){return participants.find(person=>person.id===id)?.username||'Viewer'}
function updateRoleUi(){joinPanel.classList.add('hidden');roomPanel.classList.remove('hidden');const isHost=role==='host';hostControls.classList.toggle('hidden',!isHost);viewerControls.classList.toggle('hidden',isHost);video.muted=isHost;if(isHost){placeholder.textContent='Your preview will appear here. You are the first person in this room.';setStatus('You are the sharer. Start when you are ready.','ok')}else{placeholder.textContent='Waiting for the sharer…';setStatus(streamActive?'Connecting to the live screen…':'Waiting for the sharer…')}}
async function forwardExchange(description){const response=await fetch('/api/rooms/'+encodeURIComponent(ROOM)+'/forward',{method:'POST',headers:{accept:'application/json','content-type':'application/json','x-share2me-peer-key':peerKey},body:JSON.stringify(description)}),payload=await response.json().catch(()=>({}));if(!response.ok)throw new Error(payload.error||'Unable to create the media connection');return payload}
function closeDirectPeer(viewer){const state=directPeers.get(viewer);if(!state)return;forgetSenders(state);activeViewerMicrophones.delete(viewer);void syncScreenAudio();state.audio?.remove();state.peer.close();directPeers.delete(viewer)}
function closeAllDirectPeers(){for(const viewer of [...directPeers.keys()])closeDirectPeer(viewer)}
async function addDirectViewer(viewer){if(MEDIA_MODE==='forward'||role!=='host'||!screenStream||directPeers.has(viewer))return;const peer=newPeerConnection(),remoteIce=[],incoming=new MediaStream();const state={peer,remoteIce,incoming,audio:null,screenAudioSenders:[],microphoneSender:null};directPeers.set(viewer,state);state.screenAudioSenders=await addScreenTracks(peer);state.microphoneSender=await addMicrophoneTrack(peer);peer.addTransceiver('audio',{direction:'recvonly'});peer.ontrack=event=>{if(event.track.kind==='audio'){addRemoteTrack(incoming,event.track);if(!state.audio)state.audio=attachRemoteAudio(event.track,viewerName(viewer)+' microphone');else state.audio.srcObject=incoming}};peer.onicecandidate=event=>{if(event.candidate)send({type:'ice',viewer,candidate:event.candidate.toJSON()})};peer.onconnectionstatechange=()=>{if(['failed','closed'].includes(peer.connectionState))closeDirectPeer(viewer)};try{await peer.setLocalDescription(await peer.createOffer());send({type:'offer',viewer,sdp:peer.localDescription.sdp})}catch(error){closeDirectPeer(viewer);setStatus(error instanceof Error?error.message:'Unable to connect viewer','error')}}
function createDirectViewerPeer(){if(micSender)microphoneSenders.delete(micSender);micSender=null;notifyMicrophoneState();if(mainPeer)mainPeer.close();mainPeer=newPeerConnection();remoteIce=[];remoteStream=new MediaStream();video.srcObject=remoteStream;mainPeer.onicecandidate=event=>{if(event.candidate)send({type:'ice',candidate:event.candidate.toJSON()})};mainPeer.ontrack=event=>{addRemoteTrack(remoteStream,event.track);placeholder.classList.add('hidden');video.play().then(()=>{playButton.classList.add('hidden');setStatus('Watching live.','ok')}).catch(()=>{playButton.classList.remove('hidden');setStatus('The stream is ready. Press play to hear audio.','ok')})};mainPeer.onconnectionstatechange=()=>{if(mainPeer&&mainPeer.connectionState==='failed')setStatus('The peer connection failed. A TURN server may be required for these networks.','error')}}
async function handleDirectOffer(message){createDirectViewerPeer();await mainPeer.setRemoteDescription({type:'offer',sdp:message.sdp});const target=[...mainPeer.getTransceivers()].reverse().find(transceiver=>transceiver.receiver.track.kind==='audio'&&!transceiver.sender.track);if(!target)throw new Error('The sharer did not provide a microphone return path');target.direction='sendonly';micSender=target.sender;microphoneSenders.add(micSender);const track=microphoneTrack();if(track&&!microphoneMuted)await micSender.replaceTrack(track);await flushRemoteIce(mainPeer,remoteIce);await mainPeer.setLocalDescription(await mainPeer.createAnswer());send({type:'answer',sdp:mainPeer.localDescription.sdp});notifyMicrophoneState()}
async function handleMediaControl(event){const message=JSON.parse(event.data);if(message.control==='ended'){stopViewerMedia('The sharer stopped sharing.');return}if(message.type==='offer'){await mainPeer.setRemoteDescription(message);await mainPeer.setLocalDescription(await mainPeer.createAnswer());controlChannel.send(JSON.stringify(mainPeer.localDescription))}}
async function startForwardHost(){mainPeer=new RTCPeerConnection({iceServers:[]});controlChannel=mainPeer.createDataChannel('share2me-control');controlChannel.addEventListener('message',event=>{mediaMessageChain=mediaMessageChain.then(()=>handleMediaControl(event)).catch(error=>setStatus(error instanceof Error?error.message:'Media negotiation failed','error'))});await addScreenTracks(mainPeer);await addMicrophoneTrack(mainPeer);mainPeer.addEventListener('track',event=>{if(event.track.kind==='audio')attachRemoteAudio(event.track,'Viewer microphone')});mainPeer.addEventListener('connectionstatechange',()=>{if(mainPeer&&mainPeer.connectionState==='failed')setStatus('The forwarding connection failed. Check the UDP media port.','error')});await mainPeer.setLocalDescription(await mainPeer.createOffer());await waitForIceGathering(mainPeer);await mainPeer.setRemoteDescription(await forwardExchange(mainPeer.localDescription))}
async function startForwardViewer(){if(role!=='viewer'||!streamActive||mainPeer)return;try{mainPeer=new RTCPeerConnection({iceServers:[]});remoteStream=new MediaStream();video.srcObject=remoteStream;controlChannel=mainPeer.createDataChannel('share2me-control');controlChannel.addEventListener('message',event=>{mediaMessageChain=mediaMessageChain.then(()=>handleMediaControl(event)).catch(error=>stopViewerMedia(error instanceof Error?error.message:'Media negotiation failed'))});mainPeer.addEventListener('track',event=>{addRemoteTrack(remoteStream,event.track);placeholder.classList.add('hidden');video.play().then(()=>{playButton.classList.add('hidden');setStatus('Watching live.','ok')}).catch(()=>{playButton.classList.remove('hidden');setStatus('The stream is ready. Press play to hear audio.','ok')})});const track=microphoneTrack();micSender=track?mainPeer.addTransceiver(track,{direction:'sendonly',streams:[micStream]}).sender:mainPeer.addTransceiver('audio',{direction:'sendonly'}).sender;microphoneSenders.add(micSender);if(track&&microphoneMuted)await micSender.replaceTrack(null);await mainPeer.setLocalDescription(await mainPeer.createOffer());await waitForIceGathering(mainPeer);await mainPeer.setRemoteDescription(await forwardExchange(mainPeer.localDescription));notifyMicrophoneState()}catch(error){stopViewerMedia(error instanceof Error?error.message:'Unable to watch this room','error')}}
async function startSharing(){if(role!=='host')return;startButton.disabled=true;setStatus('Choose what to share…');let micNotice='';try{screenStream=await navigator.mediaDevices.getDisplayMedia({video:{frameRate:{ideal:30,max:30}},audio:true,systemAudio:'include',surfaceSwitching:'include',selfBrowserSurface:'exclude'});microphoneMuted=false;if(includeMic.checked){try{micStream=await requestMicrophone()}catch{micNotice=' Microphone permission was not granted.'}}video.srcObject=screenStream;video.muted=true;placeholder.classList.add('hidden');if(MEDIA_MODE==='forward')await startForwardHost();else await Promise.all(participants.filter(person=>person.role==='viewer').map(person=>addDirectViewer(person.id)));streamActive=true;send({type:'stream_state',active:true});startButton.classList.add('hidden');stopButton.classList.remove('hidden');micOption.classList.add('hidden');updateMuteButton(hostMuteButton);for(const track of screenStream.getVideoTracks())track.addEventListener('ended',()=>stopHostMedia(),{once:true});const screenAudio=screenStream.getAudioTracks().length?' Screen audio is included.':' No screen-audio track was provided.';const microphone=micStream?' Microphone is included.':micNotice;setStatus('Sharing in room '+ROOM+'.'+screenAudio+microphone,'ok')}catch(error){await stopHostMedia(false);setStatus(error instanceof Error?error.message:'Screen sharing was cancelled','error');startButton.disabled=false}}
async function stopHostMedia(notify=true){if(role!=='host'&&!screenStream)return;if(MEDIA_MODE==='forward'&&peerKey&&mainPeer){fetch('/api/rooms/'+encodeURIComponent(ROOM)+'/forward',{method:'DELETE',headers:{'x-share2me-peer-key':peerKey},keepalive:true}).catch(()=>{})}closeAllDirectPeers();if(mainPeer)mainPeer.close();mainPeer=null;controlChannel=null;microphoneSenders.clear();screenAudioSenders.clear();activeViewerMicrophones.clear();audioSafety.classList.add('hidden');viewerAudio.replaceChildren();stopMediaStream(screenStream);stopMediaStream(micStream);screenStream=null;micStream=null;microphoneMuted=false;video.srcObject=null;placeholder.classList.remove('hidden');streamActive=false;startButton.classList.remove('hidden');startButton.disabled=false;stopButton.classList.add('hidden');hostMuteButton.classList.add('hidden');micOption.classList.remove('hidden');if(notify){send({type:'stream_state',active:false});setStatus('Sharing stopped. The room link remains available.')}}
function stopViewerMedia(message='Waiting for the sharer…',kind=''){notifyMicrophoneState(false);if(micSender)microphoneSenders.delete(micSender);if(mainPeer)mainPeer.close();mainPeer=null;controlChannel=null;micSender=null;remoteStream=null;video.srcObject=null;placeholder.classList.remove('hidden');playButton.classList.add('hidden');stopMediaStream(micStream);micStream=null;microphoneMuted=false;viewerMicButton.textContent='Enable microphone';viewerMicButton.classList.remove('hidden');setStatus(message,kind)}
async function enableViewerMicrophone(){viewerMicButton.disabled=true;try{micStream=await requestMicrophone();microphoneMuted=false;const track=microphoneTrack();track.enabled=true;if(micSender){microphoneSenders.add(micSender);await micSender.replaceTrack(track)}notifyMicrophoneState();updateMuteButton(viewerMicButton)}catch(error){stopMediaStream(micStream);micStream=null;microphoneMuted=false;notifyMicrophoneState(false);viewerMicButton.textContent='Enable microphone';setStatus(error instanceof Error?error.message:'Microphone permission was not granted','error')}finally{viewerMicButton.disabled=false}}
async function handleRoomMessage(message){if(message.type==='ready'){role=message.role;participantId=message.participant_id;peerKey=message.peer_key;streamActive=Boolean(message.stream_active);renderPresence(message.participants);updateRoleUi();if(role==='viewer'&&streamActive&&MEDIA_MODE==='forward')await startForwardViewer();return}if(message.type==='presence'){renderPresence(message.participants);return}if(message.type==='viewer_joined'){await addDirectViewer(message.viewer);return}if(message.type==='viewer_left'){activeViewerMicrophones.delete(message.viewer);await syncScreenAudio();closeDirectPeer(message.viewer);return}if(message.type==='viewer_microphone_state'&&role==='host'){if(message.enabled)activeViewerMicrophones.add(message.viewer);else activeViewerMicrophones.delete(message.viewer);await syncScreenAudio();return}if(message.type==='offer'&&role==='viewer'&&MEDIA_MODE!=='forward'){await handleDirectOffer(message);return}if(message.type==='answer'&&role==='host'&&MEDIA_MODE!=='forward'){const state=directPeers.get(message.viewer);if(state){await state.peer.setRemoteDescription({type:'answer',sdp:message.sdp});await flushRemoteIce(state.peer,state.remoteIce)}return}if(message.type==='ice'&&MEDIA_MODE!=='forward'){if(role==='host'){const state=directPeers.get(message.viewer);if(state)await addRemoteIce(state.peer,state.remoteIce,message.candidate)}else if(mainPeer)await addRemoteIce(mainPeer,remoteIce,message.candidate);return}if(message.type==='stream_state'){streamActive=Boolean(message.active);if(role==='viewer'){if(streamActive&&MEDIA_MODE==='forward')await startForwardViewer();else if(!streamActive)stopViewerMedia()}return}if(message.type==='reaction'){showReaction(message);return}if(message.type==='ended'){role=null;peerKey=null;stopViewerMedia('The sharer left. Rejoining the persistent room…');if(socket)socket.close();return}if(message.type==='error')setStatus(message.message||'Room connection failed','error')}
function connectRoom(username){clearTimeout(reconnectTimer);joinButton.disabled=true;joinStatus.textContent='Joining…';socket=new WebSocket(socketUrl(username));socket.addEventListener('message',event=>{messageChain=messageChain.then(()=>handleRoomMessage(JSON.parse(event.data))).catch(error=>setStatus(error instanceof Error?error.message:'Room message failed','error'))});socket.addEventListener('open',()=>{joinStatus.textContent=''});socket.addEventListener('close',()=>{joinButton.disabled=false;if(leaving)return;const lostRole=role;role=null;if(lostRole==='host')void stopHostMedia(false);else if(lostRole==='viewer')stopViewerMedia('Room connection lost. Reconnecting…','error');else setStatus('Rejoining the persistent room…');reconnectTimer=setTimeout(()=>connectRoom(username),900+Math.random()*500)});socket.addEventListener('error',()=>{joinStatus.className='status error';joinStatus.textContent='Unable to connect to the room.'})}
joinForm.addEventListener('submit',event=>{event.preventDefault();const username=usernameInput.value.trim();if(!username||[...username].length>32){joinStatus.className='status error';joinStatus.textContent='Use a username between 1 and 32 characters.';return}savePreference(USERNAME_STORAGE_KEY,username);connectRoom(username)});
startButton.addEventListener('click',startSharing);stopButton.addEventListener('click',()=>stopHostMedia());hostMuteButton.addEventListener('click',()=>void toggleMicrophone(hostMuteButton));viewerMicButton.addEventListener('click',()=>{if(micStream)void toggleMicrophone(viewerMicButton);else void enableViewerMicrophone()});playButton.addEventListener('click',()=>video.play().then(()=>playButton.classList.add('hidden')));for(const button of document.querySelectorAll('[data-reaction]'))button.addEventListener('click',()=>send({type:'reaction',reaction:button.dataset.reaction}));copyRoomButton.addEventListener('click',async()=>{await navigator.clipboard.writeText(stableRoomUrl);copyRoomButton.textContent='Copied!';setTimeout(()=>copyRoomButton.textContent='Copy room link',1200)});
addEventListener('pagehide',()=>{leaving=true;clearTimeout(reconnectTimer);notifyMicrophoneState(false);if(role==='host'&&MEDIA_MODE==='forward'&&peerKey&&mainPeer)fetch('/api/rooms/'+encodeURIComponent(ROOM)+'/forward',{method:'DELETE',headers:{'x-share2me-peer-key':peerKey},keepalive:true}).catch(()=>{});if(socket)socket.close();closeAllDirectPeers();if(mainPeer)mainPeer.close();stopMediaStream(screenStream);stopMediaStream(micStream)});
";
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
    json_value_for_script(&json!(value))
}

fn json_value_for_script(value: &(impl Serialize + ?Sized)) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "null".to_owned())
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

    #[test]
    fn live_pages_embed_configuration_without_script_injection() {
        let ice_servers = vec![RtcIceServer {
            urls: "turns:turn.example.com/<script>".to_owned(),
            username: Some("</script><script>alert(1)</script>".to_owned()),
            credential: Some("secret".to_owned()),
        }];
        let page = room_page_html("weekly-demo", MediaMode::Turn, &ice_servers);
        assert!(!page.contains("</script><script>alert(1)</script>"));
        assert!(page.contains("\\u003c/script\\u003e"));
        assert!(!page.contains("__ICE_SERVERS__"));
        assert!(!page.contains("__ROOM_NAME__"));
        assert!(page.contains("new RTCPeerConnection"));
        assert!(page.contains("MEDIA_MODE=\"turn\""));
        assert!(page.contains("Include microphone"));
        assert!(page.contains("Enable microphone"));
    }

    #[test]
    fn named_room_surface_has_presence_and_reactions() {
        let index = index_html(false);
        assert!(!index.contains("href=\"/share\""));
        let lobby = room_lobby_html();
        let room = room_page_html("weekly-demo", MediaMode::Forward, &[]);
        assert!(lobby.contains("reusable room name"));
        assert!(lobby.contains("share2me-room-name"));
        assert!(room.contains("/api/rooms/"));
        assert!(room.contains("share2me-username"));
        assert!(room.contains("x-share2me-peer-key"));
        assert!(room.contains("data-reaction=\"👏\""));
        assert!(room.contains("data-reaction=\"creeper\""));
        assert!(room.contains("class=\"creeper-head\""));
        assert!(room.contains("People"));
        assert!(room.contains("Viewer microphones go only to the sharer"));
        assert!(room.contains("Screen audio is paused while a viewer microphone is active"));
        assert!(room.contains("type:'microphone_state'"));
        assert!(room.contains("sender.replaceTrack(muted?null:track)"));
        assert!(room.contains("MEDIA_MODE=\"forward\""));
    }
}
