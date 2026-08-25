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

pub fn share_page_html(mode: MediaMode, ice_servers: &[RtcIceServer]) -> String {
    let template = if mode == MediaMode::Forward {
        FORWARD_SHARE_PAGE_HTML
    } else {
        DIRECT_SHARE_PAGE_HTML
    };
    live_page_html(template, mode, ice_servers)
}

pub fn watch_page_html(token: &str, mode: MediaMode, ice_servers: &[RtcIceServer]) -> String {
    let template = if mode == MediaMode::Forward {
        FORWARD_WATCH_PAGE_HTML
    } else {
        DIRECT_WATCH_PAGE_HTML
    };
    live_page_html(template, mode, ice_servers).replace("__TOKEN__", &json_for_script(token))
}

fn live_page_html(template: &str, mode: MediaMode, ice_servers: &[RtcIceServer]) -> String {
    let ice_servers = json_value_for_script(ice_servers);
    template
        .replace("__LIVE_STYLE__", LIVE_STYLE)
        .replace("__LIVE_COMMON_JS__", LIVE_COMMON_JS)
        .replace("__ICE_SERVERS__", &ice_servers)
        .replace("__MEDIA_MODE__", &json_value_for_script(&mode))
}

const LIVE_STYLE: &str = r":root{color-scheme:dark;--bg:#0f172a;--panel:#1e293b;--edge:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--danger:#f87171;--ok:#4ade80}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif;padding:20px}.shell{width:min(1100px,100%);margin:0 auto}.bar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px}.bar h1{margin:0;font-size:1.5rem}.bar a{color:var(--accent)}.panel{padding:24px;background:var(--panel);border:1px solid var(--edge);border-radius:14px;box-shadow:0 12px 35px #0006}.stage{display:grid;place-items:center;min-height:280px;background:#020617;border:1px solid var(--edge);border-radius:11px;overflow:hidden}.stage video{display:block;width:100%;max-height:72vh;background:#000}.controls{display:flex;flex-wrap:wrap;gap:12px;margin-top:18px}.controls button{padding:12px 18px;border:0;border-radius:9px;background:var(--accent);color:#082f49;font-weight:700;cursor:pointer}.controls button.stop{background:var(--danger);color:#450a0a}.controls button:disabled{opacity:.55;cursor:not-allowed}.mic-option{display:flex;align-items:center;gap:9px;margin-top:18px;color:var(--muted);cursor:pointer}.mic-option input{width:18px;height:18px;accent-color:var(--accent)}.remote-audio:empty{display:none}.remote-audio{display:grid;gap:8px;margin-top:14px}.remote-audio audio{width:min(420px,100%);height:36px}.status{color:var(--muted);margin:14px 0 0}.status.error{color:var(--danger)}.status.ok{color:var(--ok)}.share-link{display:none;margin-top:18px;padding:14px;background:var(--bg);border-radius:9px;overflow-wrap:anywhere}.share-link a{color:var(--accent)}.note{color:var(--muted);font-size:.88rem}.hidden{display:none!important}@media(max-width:600px){body{padding:12px}.panel{padding:16px}.stage{min-height:200px}.bar{align-items:flex-start;flex-direction:column}}";

const LIVE_COMMON_JS: &str = r"const MEDIA_MODE=__MEDIA_MODE__,ICE_SERVERS=__ICE_SERVERS__,statusElement=document.querySelector('#status');
function setStatus(message,kind=''){statusElement.textContent=message;statusElement.className='status'+(kind?' '+kind:'')}
function signalingUrl(token,role){const scheme=location.protocol==='https:'?'wss:':'ws:';return scheme+'//'+location.host+'/api/live/'+token+'/signal?role='+role}
function newPeerConnection(){return new RTCPeerConnection({iceServers:ICE_SERVERS,iceTransportPolicy:MEDIA_MODE==='turn'?'relay':'all'})}
async function addRemoteIce(peer,queue,candidate){if(peer.remoteDescription)await peer.addIceCandidate(candidate);else queue.push(candidate)}
async function flushRemoteIce(peer,queue){for(const candidate of queue.splice(0))await peer.addIceCandidate(candidate)}
async function waitForIceGathering(peer){if(peer.iceGatheringState==='complete')return;await new Promise(resolve=>{let timeout=null;const finish=()=>{clearTimeout(timeout);peer.removeEventListener('icegatheringstatechange',changed);resolve()},changed=()=>{if(peer.iceGatheringState==='complete')finish()};peer.addEventListener('icegatheringstatechange',changed);timeout=setTimeout(finish,5000)})}
async function forwardOffer(token,role,description,hostKey){const headers={accept:'application/json','content-type':'application/json'};if(hostKey)headers['x-share2me-host-key']=hostKey;const response=await fetch('/api/live/'+token+'/forward?role='+role,{method:'POST',headers,body:JSON.stringify(description)}),payload=await response.json().catch(()=>({}));if(!response.ok)throw new Error(payload.error||'Unable to create the media connection');return payload}
const MICROPHONE_CONSTRAINTS={audio:{echoCancellation:true,noiseSuppression:true,autoGainControl:true},video:false};
async function requestMicrophone(){return navigator.mediaDevices.getUserMedia(MICROPHONE_CONSTRAINTS)}
function stopMediaStream(stream){if(stream)for(const track of stream.getTracks())track.stop()}
function addSendingTracks(peer,stream){if(stream)for(const track of stream.getTracks())peer.addTransceiver(track,{direction:'sendonly',streams:[stream]})}
function addRemoteTrack(stream,track){if(!stream.getTracks().some(existing=>existing.id===track.id))stream.addTrack(track)}
function updateMuteButton(button,stream){const track=stream&&stream.getAudioTracks()[0];if(!track){button.classList.add('hidden');return}button.classList.remove('hidden');button.textContent=track.enabled?'Mute microphone':'Unmute microphone'}
function toggleMicrophone(button,stream){const track=stream&&stream.getAudioTracks()[0];if(!track)return;track.enabled=!track.enabled;updateMuteButton(button,stream)}
function attachRemoteAudio(container,track){const audio=document.createElement('audio');audio.autoplay=true;audio.controls=true;audio.setAttribute('aria-label','Viewer microphone');audio.srcObject=new MediaStream([track]);container.append(audio);audio.play().catch(()=>{});track.addEventListener('ended',()=>audio.remove(),{once:true})}
";

const DIRECT_SHARE_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Share2Me – Share screen</title>
<style>__LIVE_STYLE__</style></head><body><main class="shell"><header class="bar"><h1>🖥️ Share your screen</h1><a href="/">← File sharing</a></header><section class="panel">
<div class="stage"><video id="preview" autoplay muted playsinline></video><p id="placeholder" class="note">Your preview will appear here. The browser will ask which screen, window, or tab to share.</p></div>
<label id="micOption" class="mic-option"><input id="includeMic" type="checkbox" checked> Include microphone</label><div class="controls"><button id="start">Start sharing</button><button id="stop" class="stop hidden">Stop sharing</button><button id="mute" class="hidden">Mute microphone</button><button id="copy" class="hidden">Copy viewer link</button></div><div id="viewerAudio" class="remote-audio"></div>
<p id="status" class="status">Nothing is being shared.</p><section id="shareLink" class="share-link"><strong>Viewer link</strong><br><a id="watchLink" href=""></a><p class="note">Anyone with this link can watch while this page is sharing. Up to 8 viewers can connect.</p></section>
<p class="note">Screen audio and microphone audio are separate. Viewers can optionally send microphone audio back to you, but viewers never hear one another.</p>
</section></main><script>
__LIVE_COMMON_JS__
const startButton=document.querySelector('#start'),stopButton=document.querySelector('#stop'),muteButton=document.querySelector('#mute'),copyButton=document.querySelector('#copy'),includeMic=document.querySelector('#includeMic'),micOption=document.querySelector('#micOption'),preview=document.querySelector('#preview'),placeholder=document.querySelector('#placeholder'),shareLink=document.querySelector('#shareLink'),watchLink=document.querySelector('#watchLink'),viewerAudio=document.querySelector('#viewerAudio');
let stream=null,micStream=null,socket=null,messageChain=Promise.resolve();const peers=new Map();
function send(message){if(socket&&socket.readyState===WebSocket.OPEN)socket.send(JSON.stringify(message))}
function closePeer(viewer){const state=peers.get(viewer);if(state){state.audio.pause();state.audio.srcObject=null;state.audio.remove();state.peer.close();peers.delete(viewer)}}
function updateViewerCount(){const count=peers.size;if(stream)setStatus('Sharing with '+count+' viewer'+(count===1?'':'s')+'.','ok')}
async function addViewer(viewer){if(peers.has(viewer)||!stream)return;const peer=newPeerConnection(),remoteIce=[],incoming=new MediaStream(),audio=new Audio();audio.autoplay=true;audio.controls=true;audio.setAttribute('aria-label','Viewer microphone');viewerAudio.append(audio);peers.set(viewer,{peer,remoteIce,incoming,audio});addSendingTracks(peer,stream);addSendingTracks(peer,micStream);peer.addTransceiver('audio',{direction:'recvonly'});peer.ontrack=event=>{if(event.track.kind==='audio'){addRemoteTrack(incoming,event.track);audio.srcObject=incoming;audio.play().catch(()=>{})}};peer.onicecandidate=event=>{if(event.candidate)send({type:'ice',viewer,candidate:event.candidate.toJSON()})};peer.onconnectionstatechange=()=>{if(['failed','closed'].includes(peer.connectionState)){closePeer(viewer);updateViewerCount()}};try{await peer.setLocalDescription(await peer.createOffer());send({type:'offer',viewer,sdp:peer.localDescription.sdp});updateViewerCount()}catch(error){closePeer(viewer);setStatus(error instanceof Error?error.message:'Unable to connect viewer','error')}}
async function handleSignal(message){if(message.type==='ready'){updateViewerCount();return}if(message.type==='viewer_joined'){await addViewer(message.viewer);return}if(message.type==='viewer_left'){closePeer(message.viewer);updateViewerCount();return}if(message.type==='answer'){const state=peers.get(message.viewer);if(!state)return;await state.peer.setRemoteDescription({type:'answer',sdp:message.sdp});await flushRemoteIce(state.peer,state.remoteIce);return}if(message.type==='ice'){const state=peers.get(message.viewer);if(state)await addRemoteIce(state.peer,state.remoteIce,message.candidate);return}if(message.type==='error')setStatus(message.message||'Signaling failed','error')}
async function startSharing(){startButton.disabled=true;setStatus('Choose what to share…');let micNotice='';try{stream=await navigator.mediaDevices.getDisplayMedia({video:{frameRate:{ideal:30,max:30}},audio:true,systemAudio:'include',surfaceSwitching:'include',selfBrowserSurface:'exclude'});if(includeMic.checked){try{micStream=await requestMicrophone()}catch{micNotice=' Microphone permission was not granted.'}}preview.srcObject=stream;placeholder.classList.add('hidden');const response=await fetch('/api/live',{method:'POST',headers:{accept:'application/json'}}),payload=await response.json().catch(()=>({}));if(!response.ok||!payload.ok)throw new Error(payload.error||'Unable to create a live share');watchLink.href=payload.watch_url;watchLink.textContent=payload.watch_url;shareLink.style.display='block';copyButton.classList.remove('hidden');stopButton.classList.remove('hidden');startButton.classList.add('hidden');micOption.classList.add('hidden');updateMuteButton(muteButton,micStream);socket=new WebSocket(signalingUrl(payload.id,'host'));socket.addEventListener('open',()=>send({type:'authenticate',key:payload.host_key}));socket.addEventListener('message',event=>{messageChain=messageChain.then(()=>handleSignal(JSON.parse(event.data))).catch(error=>setStatus(error instanceof Error?error.message:'Signaling failed','error'))});socket.addEventListener('close',()=>{if(stream)setStatus('The signaling connection closed. Stop and start a new share.','error')});for(const track of stream.getVideoTracks())track.addEventListener('ended',stopSharing,{once:true});const screenAudio=stream.getAudioTracks().length?' Screen audio is included.':' No screen-audio track was provided.';const microphone=micStream?' Microphone is included.':micNotice;setStatus('Viewer link ready.'+screenAudio+microphone,'ok')}catch(error){stopMediaStream(stream);stopMediaStream(micStream);stream=null;micStream=null;preview.srcObject=null;placeholder.classList.remove('hidden');setStatus(error instanceof Error?error.message:'Screen sharing was cancelled','error');startButton.disabled=false}}
function stopSharing(){if(socket&&socket.readyState===WebSocket.OPEN)send({type:'stop'});if(socket)socket.close();socket=null;for(const viewer of [...peers.keys()])closePeer(viewer);stopMediaStream(stream);stopMediaStream(micStream);stream=null;micStream=null;preview.srcObject=null;placeholder.classList.remove('hidden');shareLink.style.display='none';copyButton.classList.add('hidden');stopButton.classList.add('hidden');muteButton.classList.add('hidden');micOption.classList.remove('hidden');startButton.classList.remove('hidden');startButton.disabled=false;setStatus('Sharing stopped. The old viewer link no longer works.')}
startButton.addEventListener('click',startSharing);stopButton.addEventListener('click',stopSharing);muteButton.addEventListener('click',()=>toggleMicrophone(muteButton,micStream));copyButton.addEventListener('click',async()=>{await navigator.clipboard.writeText(watchLink.href);copyButton.textContent='Copied!';setTimeout(()=>copyButton.textContent='Copy viewer link',1200)});addEventListener('pagehide',()=>{if(socket)socket.close();stopMediaStream(stream);stopMediaStream(micStream)});
</script></body></html>"#;

const DIRECT_WATCH_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Share2Me – Live screen</title>
<style>__LIVE_STYLE__</style></head><body><main class="shell"><header class="bar"><h1>🔴 Live screen</h1><a href="/">Share something</a></header><section class="panel">
<div class="stage"><video id="video" autoplay playsinline controls></video><p id="placeholder" class="note">Waiting for the shared screen…</p></div><div class="controls"><button id="play" class="hidden">Play video and audio</button><button id="mic">Enable microphone</button></div><p id="status" class="status">Connecting… Your microphone is off.</p>
<p class="note">Your microphone is heard only by the sharer, never by other viewers. Keep this bearer link private; anyone who has it can watch while the share is active.</p>
</section></main><script>
__LIVE_COMMON_JS__
const TOKEN=__TOKEN__,video=document.querySelector('#video'),placeholder=document.querySelector('#placeholder'),playButton=document.querySelector('#play'),micButton=document.querySelector('#mic');let peer=null,socket=null,micStream=null,micSender=null,remoteStream=null,remoteIce=[],messageChain=Promise.resolve();
function send(message){if(socket&&socket.readyState===WebSocket.OPEN)socket.send(JSON.stringify(message))}
function createPeer(){if(peer)peer.close();peer=newPeerConnection();remoteIce=[];remoteStream=new MediaStream();video.srcObject=remoteStream;peer.onicecandidate=event=>{if(event.candidate)send({type:'ice',candidate:event.candidate.toJSON()})};peer.ontrack=event=>{addRemoteTrack(remoteStream,event.track);placeholder.classList.add('hidden');video.play().then(()=>{playButton.classList.add('hidden');setStatus('Watching live.','ok')}).catch(()=>{playButton.classList.remove('hidden');setStatus('The stream is ready. Press play to hear audio.','ok')})};peer.onconnectionstatechange=()=>{if(peer.connectionState==='connected')setStatus('Watching live.','ok');else if(peer.connectionState==='failed')setStatus('The peer connection failed. A TURN server may be required for these networks.','error')}}
async function reserveMicrophoneSender(){const target=[...peer.getTransceivers()].reverse().find(transceiver=>transceiver.receiver.track.kind==='audio'&&!transceiver.sender.track);if(!target)throw new Error('The sharer did not provide a microphone return path');target.direction='sendonly';micSender=target.sender;const track=micStream&&micStream.getAudioTracks()[0];if(track)await micSender.replaceTrack(track)}
async function handleSignal(message){if(message.type==='ready'){setStatus('Connected. Waiting for the sharer…');return}if(message.type==='offer'){createPeer();await peer.setRemoteDescription({type:'offer',sdp:message.sdp});await reserveMicrophoneSender();await flushRemoteIce(peer,remoteIce);await peer.setLocalDescription(await peer.createAnswer());send({type:'answer',sdp:peer.localDescription.sdp});return}if(message.type==='ice'&&peer){await addRemoteIce(peer,remoteIce,message.candidate);return}if(message.type==='ended'){if(peer)peer.close();video.srcObject=null;placeholder.classList.remove('hidden');setStatus('This screen share has ended.','error');if(socket)socket.close();return}if(message.type==='error')setStatus(message.message||'Unable to watch this share','error')}
function connect(){socket=new WebSocket(signalingUrl(TOKEN,'viewer'));socket.addEventListener('message',event=>{messageChain=messageChain.then(()=>handleSignal(JSON.parse(event.data))).catch(error=>setStatus(error instanceof Error?error.message:'Signaling failed','error'))});socket.addEventListener('close',()=>{if(!video.srcObject)setStatus('This screen share is unavailable or has ended.','error')});socket.addEventListener('error',()=>setStatus('Unable to connect to the screen share.','error'))}
async function enableMicrophone(){micButton.disabled=true;try{micStream=await requestMicrophone();const track=micStream.getAudioTracks()[0];if(micSender)await micSender.replaceTrack(track);updateMuteButton(micButton,micStream)}catch(error){stopMediaStream(micStream);micStream=null;micButton.textContent='Enable microphone';setStatus(error instanceof Error?error.message:'Microphone permission was not granted','error')}finally{micButton.disabled=false}}
micButton.addEventListener('click',()=>{if(micStream)toggleMicrophone(micButton,micStream);else enableMicrophone()});playButton.addEventListener('click',()=>video.play().then(()=>playButton.classList.add('hidden')));addEventListener('pagehide',()=>{if(socket)socket.close();if(peer)peer.close();stopMediaStream(micStream)});connect();
</script></body></html>"#;

const FORWARD_SHARE_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Share2Me – Share screen</title>
<style>__LIVE_STYLE__</style></head><body><main class="shell"><header class="bar"><h1>🖥️ Share your screen</h1><a href="/">← File sharing</a></header><section class="panel">
<div class="stage"><video id="preview" autoplay muted playsinline></video><p id="placeholder" class="note">Your preview will appear here. The browser will ask which screen, window, or tab to share.</p></div>
<label id="micOption" class="mic-option"><input id="includeMic" type="checkbox" checked> Include microphone</label><div class="controls"><button id="start">Start sharing</button><button id="stop" class="stop hidden">Stop sharing</button><button id="mute" class="hidden">Mute microphone</button><button id="copy" class="hidden">Copy viewer link</button></div><div id="viewerAudio" class="remote-audio"></div>
<p id="status" class="status">Nothing is being shared.</p><section id="shareLink" class="share-link"><strong>Viewer link</strong><br><a id="watchLink" href=""></a><p class="note">Anyone with this link can watch while this page is sharing. Up to 8 viewers can connect.</p></section>
<p class="note">The built-in media forwarder sends your screen, screen audio, and optional microphone to viewers. Viewer microphones are forwarded only back to you.</p>
</section></main><script>
__LIVE_COMMON_JS__
const startButton=document.querySelector('#start'),stopButton=document.querySelector('#stop'),muteButton=document.querySelector('#mute'),copyButton=document.querySelector('#copy'),includeMic=document.querySelector('#includeMic'),micOption=document.querySelector('#micOption'),preview=document.querySelector('#preview'),placeholder=document.querySelector('#placeholder'),shareLink=document.querySelector('#shareLink'),watchLink=document.querySelector('#watchLink'),remoteAudio=document.querySelector('#viewerAudio');
let stream=null,micStream=null,peer=null,channel=null,sessionId=null,hostKey=null,stopping=false,messageChain=Promise.resolve();
function forwardStatus(){if(!stream)return;const screenAudio=stream.getAudioTracks().length?' Screen audio is included.':' No screen-audio track was provided.';const microphone=micStream?' Microphone is included.':'';setStatus('Viewer link ready.'+screenAudio+microphone,'ok')}
async function handleForwardHostMessage(event){const message=JSON.parse(event.data);if(message.control==='ended'){stopSharing();return}if(message.type==='offer'){await peer.setRemoteDescription(message);await peer.setLocalDescription(await peer.createAnswer());channel.send(JSON.stringify(peer.localDescription))}}
async function startSharing(){startButton.disabled=true;setStatus('Choose what to share…');let micNotice='';try{stream=await navigator.mediaDevices.getDisplayMedia({video:{frameRate:{ideal:30,max:30}},audio:true,systemAudio:'include',surfaceSwitching:'include',selfBrowserSurface:'exclude'});if(includeMic.checked){try{micStream=await requestMicrophone()}catch{micNotice=' Microphone permission was not granted.'}}preview.srcObject=stream;placeholder.classList.add('hidden');const response=await fetch('/api/live',{method:'POST',headers:{accept:'application/json'}}),payload=await response.json().catch(()=>({}));if(!response.ok||!payload.ok)throw new Error(payload.error||'Unable to create a live share');sessionId=payload.id;hostKey=payload.host_key;peer=new RTCPeerConnection({iceServers:[]});channel=peer.createDataChannel('share2me-control');channel.addEventListener('open',forwardStatus);channel.addEventListener('message',event=>{messageChain=messageChain.then(()=>handleForwardHostMessage(event)).catch(error=>setStatus(error instanceof Error?error.message:'Media negotiation failed','error'))});addSendingTracks(peer,stream);addSendingTracks(peer,micStream);peer.addEventListener('track',event=>{if(event.track.kind==='audio')attachRemoteAudio(remoteAudio,event.track)});peer.addEventListener('connectionstatechange',()=>{if(peer&&peer.connectionState==='connected')forwardStatus();else if(peer&&peer.connectionState==='failed')setStatus('The media connection failed. Check that the Share2Me UDP media port is reachable.','error')});await peer.setLocalDescription(await peer.createOffer());await waitForIceGathering(peer);const answer=await forwardOffer(sessionId,'host',peer.localDescription,hostKey);await peer.setRemoteDescription(answer);watchLink.href=payload.watch_url;watchLink.textContent=payload.watch_url;shareLink.style.display='block';copyButton.classList.remove('hidden');stopButton.classList.remove('hidden');startButton.classList.add('hidden');micOption.classList.add('hidden');updateMuteButton(muteButton,micStream);for(const track of stream.getVideoTracks())track.addEventListener('ended',()=>stopSharing(),{once:true});const screenAudio=stream.getAudioTracks().length?' Screen audio is included.':' No screen-audio track was provided.';const microphone=micStream?' Microphone is included.':micNotice;setStatus('Viewer link ready.'+screenAudio+microphone,'ok')}catch(error){const message=error instanceof Error?error.message:'Screen sharing was cancelled';stopSharing(message,'error')}}
function stopSharing(message='Sharing stopped. The old viewer link no longer works.',kind=''){if(stopping)return;stopping=true;if(channel&&channel.readyState==='open')channel.send(JSON.stringify({type:'stop'}));if(sessionId&&hostKey)fetch('/api/live/'+sessionId+'/forward',{method:'DELETE',headers:{'x-share2me-host-key':hostKey},keepalive:true}).catch(()=>{});if(peer)peer.close();peer=null;channel=null;remoteAudio.replaceChildren();stopMediaStream(stream);stopMediaStream(micStream);stream=null;micStream=null;preview.srcObject=null;placeholder.classList.remove('hidden');shareLink.style.display='none';copyButton.classList.add('hidden');stopButton.classList.add('hidden');muteButton.classList.add('hidden');micOption.classList.remove('hidden');startButton.classList.remove('hidden');startButton.disabled=false;sessionId=null;hostKey=null;setStatus(message,kind);stopping=false}
startButton.addEventListener('click',startSharing);stopButton.addEventListener('click',()=>stopSharing());muteButton.addEventListener('click',()=>toggleMicrophone(muteButton,micStream));copyButton.addEventListener('click',async()=>{await navigator.clipboard.writeText(watchLink.href);copyButton.textContent='Copied!';setTimeout(()=>copyButton.textContent='Copy viewer link',1200)});addEventListener('pagehide',()=>stopSharing());
</script></body></html>"#;

const FORWARD_WATCH_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Share2Me – Live screen</title>
<style>__LIVE_STYLE__</style></head><body><main class="shell"><header class="bar"><h1>🔴 Live screen</h1><a href="/">Share something</a></header><section class="panel">
<div class="stage"><video id="video" autoplay playsinline controls></video><p id="placeholder" class="note">Waiting for the shared screen…</p></div><div class="controls"><button id="play" class="hidden">Play video and audio</button><button id="mic">Enable microphone</button></div><p id="status" class="status">Connecting… Your microphone is off.</p>
<p class="note">Your microphone is forwarded only to the sharer, never to other viewers. Keep this bearer link private; anyone who has it can watch while the share is active.</p>
</section></main><script>
__LIVE_COMMON_JS__
const TOKEN=__TOKEN__,video=document.querySelector('#video'),placeholder=document.querySelector('#placeholder'),playButton=document.querySelector('#play'),micButton=document.querySelector('#mic');let peer=null,channel=null,micStream=null,micSender=null,remoteStream=null,messageChain=Promise.resolve();
function showTrack(event){addRemoteTrack(remoteStream,event.track);placeholder.classList.add('hidden');video.play().then(()=>{playButton.classList.add('hidden');setStatus('Watching live.','ok')}).catch(()=>{playButton.classList.remove('hidden');setStatus('The stream is ready. Press play to hear audio.','ok')})}
function endShare(message='This screen share has ended.'){if(peer)peer.close();peer=null;video.srcObject=null;placeholder.classList.remove('hidden');setStatus(message,'error')}
async function handleForwardMessage(event){const message=JSON.parse(event.data);if(message.control==='ended'){endShare();return}if(message.type==='offer'){await peer.setRemoteDescription(message);await peer.setLocalDescription(await peer.createAnswer());channel.send(JSON.stringify(peer.localDescription))}}
async function connect(){try{peer=new RTCPeerConnection({iceServers:[]});remoteStream=new MediaStream();video.srcObject=remoteStream;channel=peer.createDataChannel('share2me-control');channel.addEventListener('open',()=>{if(!remoteStream.getTracks().length)setStatus('Connected. Waiting for the shared screen…')});channel.addEventListener('message',event=>{messageChain=messageChain.then(()=>handleForwardMessage(event)).catch(error=>endShare(error instanceof Error?error.message:'Media negotiation failed'))});peer.addEventListener('track',showTrack);peer.addEventListener('connectionstatechange',()=>{if(peer&&peer.connectionState==='connected'&&remoteStream.getTracks().length)setStatus('Watching live.','ok');else if(peer&&peer.connectionState==='failed')endShare('The media connection failed. Check that the Share2Me UDP media port is reachable.')});micSender=peer.addTransceiver('audio',{direction:'sendonly'}).sender;await peer.setLocalDescription(await peer.createOffer());await waitForIceGathering(peer);const answer=await forwardOffer(TOKEN,'viewer',peer.localDescription);await peer.setRemoteDescription(answer)}catch(error){endShare(error instanceof Error?error.message:'Unable to watch this share')}}
async function enableMicrophone(){micButton.disabled=true;try{micStream=await requestMicrophone();const track=micStream.getAudioTracks()[0];if(micSender)await micSender.replaceTrack(track);updateMuteButton(micButton,micStream)}catch(error){stopMediaStream(micStream);micStream=null;micButton.textContent='Enable microphone';setStatus(error instanceof Error?error.message:'Microphone permission was not granted','error')}finally{micButton.disabled=false}}
micButton.addEventListener('click',()=>{if(micStream)toggleMicrophone(micButton,micStream);else enableMicrophone()});playButton.addEventListener('click',()=>video.play().then(()=>playButton.classList.add('hidden')));addEventListener('pagehide',()=>{if(peer)peer.close();stopMediaStream(micStream)});connect();
</script></body></html>"#;

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
        let host = share_page_html(MediaMode::Turn, &ice_servers);
        let viewer = watch_page_html(
            "0123456789abcdef0123456789abcdef",
            MediaMode::Turn,
            &ice_servers,
        );
        assert!(!host.contains("</script><script>alert(1)</script>"));
        assert!(host.contains("\\u003c/script\\u003e"));
        assert!(!host.contains("__ICE_SERVERS__"));
        assert!(!viewer.contains("__TOKEN__"));
        assert!(viewer.contains("new RTCPeerConnection"));
        assert!(viewer.contains("MEDIA_MODE=\"turn\""));
        assert!(host.contains("Include microphone"));
        assert!(viewer.contains("Enable microphone"));
    }

    #[test]
    fn forwarding_and_disabled_pages_have_distinct_surfaces() {
        let index = index_html(false);
        assert!(!index.contains("href=\"/share\""));
        let host = share_page_html(MediaMode::Forward, &[]);
        let viewer = watch_page_html("0123456789abcdef0123456789abcdef", MediaMode::Forward, &[]);
        assert!(host.contains("/forward?role="));
        assert!(host.contains("built-in media forwarder"));
        assert!(viewer.contains("microphone is forwarded only to the sharer"));
        assert!(host.contains("Viewer microphones are forwarded only back to you"));
        assert!(viewer.contains("never to other viewers"));
    }
}
