// web_ui.h - HTML for the setup portal and the dashboard (stored in flash).
#pragma once
#include <Arduino.h>

// ---------------------------------------------------------------------------
// Setup portal. Placeholders %...% are filled in by main.cpp.
// ---------------------------------------------------------------------------
static const char PORTAL_HTML[] PROGMEM = R"HTML(<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESPHole32 setup</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px}
.box{max-width:420px;margin:auto;background:#1e293b;border-radius:12px;padding:20px}
h2{margin-top:0}label{display:block;margin:12px 0 4px;font-size:14px;color:#94a3b8}
input{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:16px}
button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:8px;background:#22c55e;color:#04210f;font-size:16px;font-weight:600}
details{margin-top:14px}small{color:#94a3b8}
</style></head><body><div class="box">
<h2>ESPHole32 setup</h2>
<form method="post" action="/save">
<label>Wi-Fi network</label><input name="ssid" list="nets" value="%SSID%" required autocomplete="off">
<datalist id="nets">%NETWORKS%</datalist>
<label>Wi-Fi password</label><input name="pass" type="password">
<label>Dashboard password (user: admin)</label><input name="admin" type="password" placeholder="%ADMINHINT%">
<label>Hostname</label><input name="host" value="%HOST%"><small>Use a different name on your second board, e.g. esphole2</small>
<details><summary>Static IP (recommended)</summary>
<small>A DNS server needs an address that never changes. Either fill these in, or reserve the board's IP in your router (DHCP reservation) and leave them blank.</small>
<label>IP address</label><input name="ip" value="%IP%" placeholder="e.g. 192.168.1.53">
<label>Gateway (router IP)</label><input name="gw" value="%GW%" placeholder="e.g. 192.168.1.1">
<label>Subnet mask</label><input name="mask" value="%MASK%">
</details>
<button type="submit">Save and connect</button>
</form></div></body></html>)HTML";

// ---------------------------------------------------------------------------
// Dashboard. All dynamic text is inserted with textContent (never innerHTML),
// because domain names come from the network and can't be trusted.
// ---------------------------------------------------------------------------
static const char DASHBOARD_HTML[] PROGMEM = R"HTML(<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESPHole32</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--line:#334155;--fg:#e2e8f0;--mut:#94a3b8;--red:#f87171;--grn:#4ade80;--amb:#fbbf24}
*{box-sizing:border-box}body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid var(--line)}
header h1{font-size:20px;margin:0}#state{font-size:13px;padding:4px 10px;border-radius:99px;background:#14532d;color:var(--grn)}
#state.off{background:#451a03;color:var(--amb)}
main{max-width:1100px;margin:auto;padding:16px;display:grid;gap:16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card,.panel{background:var(--card);border-radius:12px;padding:14px}
.card .v{font-size:26px;font-weight:700;margin-top:4px}.card .l{font-size:13px;color:var(--mut)}
.panel h2{font-size:16px;margin:0 0 10px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input,select{padding:8px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg)}
button{padding:8px 12px;border:0;border-radius:8px;background:#334155;color:var(--fg);cursor:pointer}
button.g{background:#166534}button.r{background:#7f1d1d}button.a{background:#78350f}
button.s{padding:3px 8px;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:6px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:500}td.d{word-break:break-all}
.b{color:var(--red)}.ok{color:var(--grn)}.p{color:var(--amb)}
.tags span{display:inline-flex;gap:6px;align-items:center;background:var(--bg);border:1px solid var(--line);border-radius:99px;padding:3px 4px 3px 10px;margin:3px;font-size:13px}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
.scroll{max-height:420px;overflow:auto}small{color:var(--mut)}#msg{min-height:18px;font-size:13px}
</style></head><body>
<header><h1>ESPHole32</h1><span id="state">Blocking on</span></header>
<main>
<div class="cards">
 <div class="card"><div class="l">Queries</div><div class="v" id="c_total">-</div></div>
 <div class="card"><div class="l">Blocked</div><div class="v b" id="c_blocked">-</div></div>
 <div class="card"><div class="l">Blocked %</div><div class="v" id="c_pct">-</div></div>
 <div class="card"><div class="l">Blocklist domains</div><div class="v" id="c_bl">-</div></div>
 <div class="card"><div class="l">Upstream latency</div><div class="v" id="c_lat">-</div></div>
 <div class="card"><div class="l">Uptime</div><div class="v" id="c_up">-</div></div>
</div>

<div class="panel"><h2>Blocking</h2><div class="row">
 <button class="a" onclick="pause(5)">Pause 5 min</button>
 <button class="a" onclick="pause(30)">Pause 30 min</button>
 <button class="a" onclick="pause(-1)">Pause until resumed</button>
 <button class="g" onclick="pause(0)">Resume</button>
 <small id="info"></small></div></div>

<div class="panel"><h2>Recent queries</h2>
 <div class="row" style="margin-bottom:8px"><input id="filter" placeholder="Filter domain or client">
 <label><input type="checkbox" id="onlyb"> blocked only</label></div>
 <div class="scroll"><table><thead><tr><th>When</th><th>Client</th><th>Type</th><th>Domain</th><th>Status</th><th></th></tr></thead>
 <tbody id="log"></tbody></table></div></div>

<div class="two">
 <div class="panel"><h2>Your block list</h2><div class="row"><input id="nb" placeholder="ads.example.com"><button class="r" onclick="list('block','add',v('nb'))">Block</button></div>
  <div class="tags" id="blk"></div><small>Blocks the domain and all its subdomains.</small></div>
 <div class="panel"><h2>Your allow list</h2><div class="row"><input id="na" placeholder="needed.example.com"><button class="g" onclick="list('allow','add',v('na'))">Allow</button></div>
  <div class="tags" id="alw"></div><small>Always wins over every block list.</small></div>
</div>

<div class="two">
 <div class="panel"><h2>Clients</h2><table><thead><tr><th>Device IP</th><th>Queries</th><th>Blocked</th><th>Last seen</th></tr></thead><tbody id="cl"></tbody></table></div>
 <div class="panel"><h2>Blocklist</h2>
  <p><small>Build <b>blocklist.bin</b> on your PC with <code>tools/build_blocklist.py</code>, then upload it here. Capacity: <span id="cap"></span> domains.</small></p>
  <div class="row"><input type="file" id="file" accept=".bin"><button class="g" onclick="upload()">Upload</button></div>
  <div id="prog"></div>
  <h2 style="margin-top:18px">Upstream DNS</h2>
  <div class="row"><input id="up1" size="14"><input id="up2" size="14"><button onclick="saveUp()">Save</button></div>
  <h2 style="margin-top:18px">Device</h2>
  <p><small id="dev"></small></p>
  <div class="row"><button onclick="post('/api/reboot',{}).then(()=>say('Rebooting...'))">Reboot</button>
  <button class="r" onclick="if(confirm('Forget Wi-Fi and reboot into setup mode?'))post('/api/wifireset',{})">Forget Wi-Fi</button></div>
 </div>
</div>
<div id="msg"></div>
</main>
<script>
const $=id=>document.getElementById(id);const v=id=>$(id).value.trim();
const TYPES={1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',64:'SVCB',65:'HTTPS',255:'ANY'};
const VERD=[['Allowed','ok'],['Blocked (list)','b'],['Blocked (yours)','b'],['Allowed (yours)','ok'],['Paused','p']];
let logData=[];
function el(t,txt,cls){const e=document.createElement(t);if(txt!==undefined)e.textContent=txt;if(cls)e.className=cls;return e}
function ago(s){if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';if(s<86400)return Math.floor(s/3600)+'h';return Math.floor(s/86400)+'d'}
function fmt(n){return n.toLocaleString()}
function say(t){$('msg').textContent=t;setTimeout(()=>{if($('msg').textContent==t)$('msg').textContent=''},5000)}
async function post(url,data){const r=await fetch(url,{method:'POST',body:new URLSearchParams(data)});const j=await r.json().catch(()=>({}));if(!r.ok)say(j.error||('Error '+r.status));return j}
async function list(l,op,d){if(!d)return;await post('/api/list',{list:l,op:op,domain:d});$('nb').value='';$('na').value='';stats()}
async function pause(m){await post('/api/pause',{minutes:m});stats()}
async function saveUp(){const j=await post('/api/settings',{up1:v('up1'),up2:v('up2')});if(j.ok)say('Upstream DNS saved')}
function tags(box,items,lname){box.replaceChildren();for(const d of items){const s=el('span',d);const b=el('button','×','s');b.onclick=()=>list(lname,'remove',d);s.appendChild(b);box.appendChild(s)}}
let upFocus=false;
async function stats(){
 const r=await fetch('/api/stats');if(!r.ok)return;const s=await r.json();
 $('c_total').textContent=fmt(s.total);$('c_blocked').textContent=fmt(s.blocked);
 $('c_pct').textContent=s.total?(100*s.blocked/s.total).toFixed(1)+'%':'0%';
 $('c_bl').textContent=fmt(s.blCount);$('cap').textContent=fmt(s.blCapacity);
 $('c_lat').textContent=s.latency?s.latency+' ms':'-';$('c_up').textContent=ago(s.uptime);
 const st=$('state');st.textContent=s.paused?(s.pauseLeft<0?'Paused':'Paused ('+ago(s.pauseLeft)+' left)'):'Blocking on';st.className=s.paused?'off':'';
 $('info').textContent=s.failed?fmt(s.failed)+' upstream timeouts':'';
 if(!upFocus&&document.activeElement!==$('up1')&&document.activeElement!==$('up2')){$('up1').value=s.up1;$('up2').value=s.up2}
 $('dev').textContent='v'+s.version+' • '+s.host+' • '+s.ip+' • Wi-Fi '+s.rssi+' dBm • free RAM '+fmt(s.heap)+' bytes';
 tags($('blk'),s.block,'block');tags($('alw'),s.allow,'allow');
 const cl=$('cl');cl.replaceChildren();
 for(const c of s.clients.sort((a,b)=>b.q-a.q)){const tr=el('tr');[c.ip,fmt(c.q),fmt(c.b),ago(c.ago)+' ago'].forEach(x=>tr.appendChild(el('td',x)));cl.appendChild(tr)}
}
function drawLog(){
 const f=v('filter').toLowerCase(),ob=$('onlyb').checked,tb=$('log');tb.replaceChildren();
 for(const e of logData){
  const blocked=e.v==1||e.v==2;if(ob&&!blocked)continue;if(f&&!e.d.includes(f)&&!e.ip.includes(f))continue;
  const tr=el('tr');tr.appendChild(el('td',ago(e.ago)));tr.appendChild(el('td',e.ip));tr.appendChild(el('td',TYPES[e.t]||e.t));
  tr.appendChild(el('td',e.d,'d'));const vd=VERD[e.v]||['?',''];tr.appendChild(el('td',vd[0],vd[1]));
  const td=el('td');const b=el('button',blocked?'Allow':'Block','s '+(blocked?'g':'r'));
  b.onclick=()=>list(blocked?'allow':'block','add',e.d);td.appendChild(b);tr.appendChild(td);tb.appendChild(tr)}
}
async function log(){const r=await fetch('/api/log');if(!r.ok)return;logData=await r.json();drawLog()}
$('filter').oninput=drawLog;$('onlyb').onchange=drawLog;
function upload(){
 const f=$('file').files[0];if(!f){say('Choose blocklist.bin first');return}
 const fd=new FormData();fd.append('file',f,f.name);const x=new XMLHttpRequest();
 x.upload.onprogress=e=>{if(e.lengthComputable)$('prog').textContent='Uploading... '+Math.round(100*e.loaded/e.total)+'%'};
 x.onload=()=>{let j={};try{j=JSON.parse(x.responseText)}catch(e){}
  $('prog').textContent=x.status==200?'Installed '+fmt(j.count)+' domains.':'Failed: '+(j.error||x.status);stats()};
 x.onerror=()=>{$('prog').textContent='Upload failed (connection lost)'};
 x.open('POST','/api/blocklist');x.send(fd)}
function tick(){stats();log()}tick();setInterval(tick,3000);
</script></body></html>)HTML";
