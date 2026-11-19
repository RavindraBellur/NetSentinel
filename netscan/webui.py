"""The dashboard: a single-page NOC console on the standard library HTTP server.

Views: Overview, Devices, Incidents, Traffic, Events, Settings.
Auth: optional sign-in (PBKDF2 + session cookie), CSRF header on every POST.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import apitokens, auth, netguard, oidc as oidc_mod, settings, store, totp, tlsutil

CSS = r"""
:root{
  --bg:#0b0f14; --bg2:#0f151c; --panel:#141b23; --panel2:#1a232d; --line:#243040;
  --text:#e8eef5; --muted:#8899ab; --muted2:#61707f;
  --accent:#3ba55d; --accent2:#3d8bfd; --warn:#e0a02c; --crit:#d9534f;
  --up:#3ba55d; --deg:#e0a02c; --down:#d9534f; --unk:#5b6b7c;
  --crit-bg:#3a1a1c; --high-bg:#3a2a14; --med-bg:#332d13; --low-bg:#152a3a;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--text);font:13.5px/1.45 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
a{color:var(--accent2);text-decoration:none}
button,input,select{font:inherit;color:inherit}
button{cursor:pointer;background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:6px 12px}
button:hover{border-color:#33465c}
button.primary{background:var(--accent2);border-color:var(--accent2);color:#04121f;font-weight:600}
button.ghost{background:transparent}
button.sm{padding:3px 9px;font-size:12px}
button:disabled{opacity:.5;cursor:not-allowed}
input[type=text],input[type=password],input[type=number],input[type=email],select{
  background:var(--bg2);border:1px solid var(--line);border-radius:6px;padding:6px 9px;width:100%}
input:focus,select:focus{outline:1px solid var(--accent2)}
label{display:block;font-size:11.5px;color:var(--muted);text-transform:uppercase;
      letter-spacing:.5px;margin:0 0 4px}
.field{margin-bottom:11px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
@media(max-width:900px){.grid2,.grid3{grid-template-columns:1fr}}

/* layout */
.app{display:flex;min-height:100vh}
.side{width:212px;flex:0 0 212px;background:var(--bg2);border-right:1px solid var(--line);
      display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:10px;padding:16px 16px 14px;border-bottom:1px solid var(--line)}
.logo{width:30px;height:30px;border-radius:7px;background:linear-gradient(135deg,#3ba55d,#1d6b3c);
      display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;color:#04120c}
.brand .t{font-weight:600;font-size:14px;letter-spacing:.2px}
.brand .s{font-size:11px;color:var(--muted)}
nav{padding:10px 8px;flex:1;overflow:auto}
nav a{display:flex;align-items:center;gap:10px;padding:9px 11px;border-radius:7px;color:#b9c7d6;
      font-size:13px;margin-bottom:2px}
nav a:hover{background:#18222c}
nav a.on{background:#1b2b3a;color:#fff;box-shadow:inset 2px 0 0 var(--accent2)}
nav a .ico{width:16px;text-align:center;opacity:.85;font-size:13px}
nav a .cnt{margin-left:auto;background:#3a1f22;color:#f3a1a1;border-radius:9px;padding:0 6px;
           font-size:11px;font-weight:600}
.side-foot{padding:10px 14px;border-top:1px solid var(--line);font-size:11.5px;color:var(--muted)}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.top{display:flex;align-items:center;gap:14px;padding:12px 20px;border-bottom:1px solid var(--line);
     background:rgba(15,21,28,.9);position:sticky;top:0;z-index:5;backdrop-filter:blur(6px)}
.top h1{font-size:15px;margin:0;font-weight:600}
.top .sub{font-size:11.5px;color:var(--muted)}
.top .right{margin-left:auto;display:flex;align-items:center;gap:10px}
.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;
      padding:4px 11px;font-size:12px;background:var(--panel)}
.content{padding:18px 20px 60px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card h2{font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:#a9bccd;margin:0 0 12px;
         font-weight:600}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:14px}
.kpi .k{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted)}
.kpi .v{font-size:23px;font-weight:600;margin-top:5px;font-variant-numeric:tabular-nums}
.kpi .n{font-size:11.5px;color:var(--muted);margin-top:3px}
.row{display:grid;gap:14px}
.row.two{grid-template-columns:1.55fr 1fr}
.row.three{grid-template-columns:1fr 1fr 1fr}
@media(max-width:1150px){.row.two,.row.three{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11px;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);
   font-weight:500;padding:7px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:8px;border-bottom:1px solid #1b242f;vertical-align:middle}
tbody tr:hover{background:#161f29}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12.5px}
.muted{color:var(--muted)}
.small{font-size:11.5px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px;vertical-align:middle}
.s-up{background:var(--up)} .s-degraded{background:var(--deg)} .s-down{background:var(--down)}
.s-unknown{background:var(--unk)}
.badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:600;
       white-space:nowrap;border:1px solid transparent}
.sev-critical{background:var(--crit-bg);color:#f08a86;border-color:#5c2a2c}
.sev-high{background:var(--high-bg);color:#f0b96a;border-color:#5a421f}
.sev-medium{background:var(--med-bg);color:#e3cf7a;border-color:#514718}
.sev-low{background:var(--low-bg);color:#8ec4ea;border-color:#1f3d55}
.sev-info{background:#1b2530;color:#9fb0c0;border-color:#2a3644}
.t-router{background:#3a2f16;color:#f0c264} .t-switch{background:#1b2f45;color:#8cc2f5}
.t-access_point{background:#20364a;color:#87d5f0} .t-kot_printer{background:#3d2418;color:#ffb27a}
.t-printer{background:#33291c;color:#e3c68f} .t-scanner{background:#2a2f3d;color:#b7c6e0}
.t-dvr,.t-nvr{background:#3a1f28;color:#f39aa8} .t-camera{background:#37213a;color:#dfa2ea}
.t-server{background:#22303a;color:#9fd4c6} .t-nas{background:#1f332f;color:#96d8bd}
.t-phone,.t-iot{background:#262b33;color:#a9b6c4} .t-unknown{background:#242a31;color:#8b98a5}
.ports{display:flex;flex-wrap:wrap;gap:3px;max-width:210px}
.port{background:#1d2732;border:1px solid #2a3949;border-radius:4px;padding:0 5px;font-size:10.5px;
      color:#a9c4dd;font-family:ui-monospace,Consolas,monospace}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.chip{background:var(--panel2);border:1px solid var(--line);border-radius:999px;padding:4px 11px;
      font-size:12px;color:var(--muted);cursor:pointer}
.chip.on{background:#1b2b3a;border-color:#2d4a68;color:#cfe2f5}
.spacer{flex:1}
.note{border-left:3px solid var(--warn);background:#1a2330;padding:9px 12px;border-radius:5px;
      font-size:12.5px;color:#c9d6e2;margin-bottom:9px}
.note.ok{border-left-color:var(--accent)} .note.bad{border-left-color:var(--crit)}
.empty{padding:26px;text-align:center;color:var(--muted)}
.gauge{display:flex;align-items:center;gap:16px}
.gauge .num{font-size:30px;font-weight:700;line-height:1}
.gauge .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
.bars{display:flex;flex-direction:column;gap:9px}
.bar{display:flex;align-items:center;gap:9px;font-size:12.5px}
.bar .nm{width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .tr{flex:1;height:7px;background:var(--panel2);border-radius:4px;overflow:hidden}
.bar .tr>i{display:block;height:100%;background:linear-gradient(90deg,var(--accent2),var(--accent))}
.bar .vl{width:88px;text-align:right;font-variant-numeric:tabular-nums;font-family:ui-monospace,Consolas,monospace;font-size:12px}
.inc{display:flex;gap:10px;align-items:flex-start;padding:10px 2px;border-bottom:1px solid #1b242f;cursor:pointer}
.inc:hover{background:#161f29}
.inc .ttl{font-size:13px;font-weight:500}
.inc .meta{font-size:11.5px;color:var(--muted);margin-top:2px}
.drawer{position:fixed;top:0;right:0;height:100%;width:min(620px,96vw);background:var(--panel);
        border-left:1px solid var(--line);box-shadow:-20px 0 50px rgba(0,0,0,.5);z-index:40;
        display:flex;flex-direction:column;transform:translateX(100%);transition:transform .16s ease}
.drawer.open{transform:translateX(0)}
.drawer .hd{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--line)}
.drawer .bd{padding:16px 18px;overflow:auto}
.drawer h3{margin:0;font-size:15px}
.kv{display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-bottom:1px solid #1b242f;font-size:12.5px}
.kv:last-child{border-bottom:0}
ol.acts{margin:6px 0 0 18px;padding:0} ol.acts li{margin-bottom:5px;font-size:12.5px}
ul.ev{margin:6px 0 0 16px;padding:0} ul.ev li{margin-bottom:4px;font-size:12.5px;color:#c2cfdb}
.tabs{display:flex;gap:6px;border-bottom:1px solid var(--line);margin-bottom:14px}
.tabs div{padding:8px 14px;font-size:12.5px;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent}
.tabs div.on{color:#fff;border-bottom-color:var(--accent2)}
.spark{width:96px;height:22px;display:block}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;background:
  radial-gradient(1200px 600px at 50% -10%,#16222e 0%,#0b0f14 60%)}
.login{width:min(380px,92vw);background:var(--panel);border:1px solid var(--line);border-radius:12px;
       padding:26px 24px}
.login h1{font-size:18px;margin:0 0 4px}
.login p{color:var(--muted);font-size:12.5px;margin:0 0 18px}
.err{background:#3a1a1c;border:1px solid #5c2a2c;color:#f0a7a3;padding:8px 11px;border-radius:6px;
     font-size:12.5px;margin-bottom:12px}
.sw{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;color:#c2cfdb}
.sw input{width:auto}
"""

APP_JS = r"""
var S = {data:null, tab:(location.hash||'#overview').slice(1), dev:{q:'',f:'all',mon:false},
         inc:null, draw:null, trafficTab:'now'};
var TABS=[['overview','Overview','&#9635;'],['devices','Devices','&#9776;'],
          ['incidents','Incidents','&#9888;'],['traffic','Traffic','&#8599;'],
          ['reports','Reports','&#9783;'],['locations','Locations','&#8853;'],
          ['users','Users','&#9787;'],
          ['events','Events','&#9776;'],
          ['settings','Settings','&#9881;']];
function can(a){ var d=S.data||{}; var p=(d.auth&&d.auth.permissions)||['read'];
  return p.indexOf(a)>=0; }

function esc(s){return (s==null?'':String(s)).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function bps(v){ if(!v||v<1) return '0';
  var u=['bps','Kbps','Mbps','Gbps'],i=0,n=+v; while(n>=1000&&i<u.length-1){n/=1000;i++;}
  return (n<10?n.toFixed(1):Math.round(n))+' '+u[i]; }
function bytes(v){ if(!v||v<1) return '0 B';
  var u=['B','KB','MB','GB','TB'],i=0,n=+v; while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return (n<10?n.toFixed(1):Math.round(n))+' '+u[i]; }
function ms(v){ return (v==null||v===0)?'&mdash;':(v<10?v.toFixed(1):Math.round(v))+' ms'; }
function ago(ts){ if(!ts) return 'never'; var d=Math.round(Date.now()/1000-ts);
  if(d<60) return d+'s ago'; if(d<3600) return Math.round(d/60)+' min ago';
  if(d<86400) return Math.round(d/3600)+' h ago'; return Math.round(d/86400)+' d ago'; }
function stDot(s){ return '<span class="dot s-'+(s||'unknown')+'"></span>'; }
function spark(hist){
  if(!hist||hist.length<2) return '<span class="muted small">no data</span>';
  var w=96,h=22,max=1;
  hist.forEach(function(p){ if(p[1]>max) max=p[1]; });
  var pts=hist.map(function(p,i){ var x=(i/(hist.length-1))*w;
    var y=h-Math.min(h-2,(p[1]/max)*(h-3)); return x.toFixed(1)+','+y.toFixed(1); }).join(' ');
  var last=hist[hist.length-1][1], col=last>300?'#d9534f':(last>150?'#e0a02c':'#3ba55d');
  return '<svg class="spark" viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none">'+
    '<polyline points="'+pts+'" fill="none" stroke="'+col+'" stroke-width="1.4"/></svg>';
}
function gauge(score){
  var r=30,c=2*Math.PI*r, off=c-(score/100)*c;
  var col=score>=90?'#3ba55d':(score>=70?'#e0a02c':'#d9534f');
  return '<svg width="76" height="76" viewBox="0 0 76 76"><circle cx="38" cy="38" r="'+r+'" '+
   'stroke="#22303c" stroke-width="7" fill="none"/><circle cx="38" cy="38" r="'+r+'" stroke="'+col+'" '+
   'stroke-width="7" fill="none" stroke-linecap="round" stroke-dasharray="'+c+'" '+
   'stroke-dashoffset="'+off+'" transform="rotate(-90 38 38)"/></svg>';
}

function api(path,opts){
  opts=opts||{}; opts.headers=Object.assign({'X-NS':'1','Content-Type':'application/json'},opts.headers||{});
  return fetch(path,opts).then(function(r){
    if(r.status===401){ location.href='/login'; return Promise.reject('auth'); }
    return r.json();
  });
}

function nav(){
  var open=(S.data&&S.data.health)?S.data.health.open_incidents:0;
  var hubOn=((S.data.sites||{}).enabled)||((S.data.branch||{}).sent>0);
  document.getElementById('nav').innerHTML=TABS.filter(function(t){
      if(t[0]==='settings' && !can('settings')) return false;
      if(t[0]==='locations' && !hubOn) return false;
      if(t[0]==='users' && !can('users')) return false;
      return true; }).map(function(t){
    var cnt=(t[0]==='incidents'&&open)?'<span class="cnt">'+open+'</span>':'';
    return '<a href="#'+t[0]+'" class="'+(S.tab===t[0]?'on':'')+'"><span class="ico">'+t[2]+
      '</span>'+t[1]+cnt+'</a>'; }).join('');
}
function head(){
  var d=S.data||{}, h=d.health||{}, loc=d.local||{}, st=d.status||{};
  var sev=h.critical?'<span class="badge sev-critical">'+h.critical+' critical</span>':
          (h.open_incidents?'<span class="badge sev-high">'+h.open_incidents+' open</span>':
          '<span class="badge sev-info">no incidents</span>');
  document.getElementById('h-title').textContent=({overview:'Overview',devices:'Devices',
    incidents:'Incidents',traffic:'Traffic',reports:'Reports',locations:'Locations',
    users:'Users',events:'Events',settings:'Settings'})[S.tab]||'Overview';
  document.getElementById('h-sub').textContent=(d.site?d.site+' · ':'')+
    (loc.network?loc.network:'')+(st.last_scan?' · last scan '+st.last_scan:'')+
    (d.monitor&&d.monitor.enabled?(' · poll '+(d.monitor.interval||60)+'s'):' · monitoring off');
  document.getElementById('h-right').innerHTML=
    '<span class="pill">'+stDot(h.down?'down':(h.degraded?'degraded':'up'))+'health '+h.score+'%</span>'+
    '<span class="pill">'+sev+'</span>'+
    (d.update&&['available','updating','restarting'].indexOf(d.update.status)>=0&&can('settings')?
      '<a class="pill" href="#settings" title="Settings → Updates">'+
      (d.update.status==='available'?'update '+esc(d.update.latest)+' available':'updating to '+esc(d.update.latest)+' ...')+
      '</a>':'')+
    (can('scan')?'<button class="sm" onclick="rescan()">Rescan</button>':'')+
    (d.auth&&d.auth.enabled&&d.auth.user?
      '<span class="pill" title="signed in">'+esc(d.auth.user)+
      ' <span class="muted">· '+esc(d.auth.role)+'</span>'+
      ' <a href="/logout" class="muted">sign out</a></span>':'');
  var src=d.sources||{}, parts=[];
  if(src.netflow&&src.netflow.active) parts.push('flow '+src.netflow.packets+' pkts');
  if(src.syslog&&src.syslog.active) parts.push('syslog '+src.syslog.received);
  if(d.traffic&&d.traffic.source&&d.traffic.source!=='none') parts.push('usage: '+d.traffic.source);
  document.getElementById('foot-src').textContent = parts.join(' · ') || 'no flow/syslog yet';
}
function rescan(){ api('/api/scan',{method:'POST',body:'{}'}).then(poll); }

// ---------------------------------------------------------------- overview --
function viewOverview(){
  var d=S.data, h=d.health||{}, t=d.traffic||{}, m=d.monitor||{};
  var incs=(d.open_incidents||[]).slice(0,6);
  var tl=t.top||[]; var max=tl.length?Math.max.apply(null,tl.map(function(x){return x.down_bps+x.up_bps;})):1;
  var ints=(d.internet||[]);
  return '<div class="kpis">'+
    kpi('Devices monitored',h.monitored||0,(h.up||0)+' up · '+(h.degraded||0)+' degraded · '+(h.down||0)+' down')+
    kpi('Open incidents',h.open_incidents||0,(h.critical||0)+' critical')+
    kpi('Internet down',bps(t.total_down_bps||0),'up '+bps(t.total_up_bps||0)+' · '+(t.source||'no flow'))+
    kpi('Public IP',d.public&&d.public.ip?d.public.ip:'&mdash;',(d.public&&d.public.isp)?d.public.isp:'not reachable')+
    kpi('Next poll',m.enabled?((m.next_poll_in!=null?m.next_poll_in+'s':'&mdash;')):'off',
        m.enabled?((m.polls||0)+' polls · '+(m.poll_seconds||0)+'s each'):'start with --monitor')+
    '</div>'+
  '<div class="row two">'+
    '<div class="card"><h2>Active incidents</h2>'+
      (incs.length?incs.map(incRow).join(''):'<div class="empty">Nothing open. All monitored devices are answering.</div>')+
    '</div>'+
    '<div class="card"><h2>Health</h2><div class="gauge">'+gauge(h.score||0)+
      '<div><div class="num">'+(h.score||0)+'%</div><div class="lbl">network health</div></div></div>'+
      '<div style="margin-top:14px">'+
      kv('Devices up',(h.up||0)+' / '+(h.monitored||0))+
      kv('Degraded',h.degraded||0)+kv('Down',h.down||0)+
      kv('Gateway',(d.gateway&&d.gateway.state)?d.gateway.state:'not polled')+
      '</div></div>'+
  '</div>'+
  '<div class="row two" style="margin-top:14px">'+
    '<div class="card"><h2>Top bandwidth users</h2>'+
      (tl.length?'<div class="bars">'+tl.slice(0,7).map(function(x){
        var tot=x.down_bps+x.up_bps, pct=max?Math.max(3,Math.round(tot/max*100)):0;
        return '<div class="bar"><span class="nm">'+esc(x.name||x.type_label||x.ip)+
          ' <span class="muted">'+esc(x.ip)+'</span></span><span class="tr"><i style="width:'+pct+'%"></i></span>'+
          '<span class="vl">'+bps(tot)+'</span></div>';}).join('')+'</div>'
        :'<div class="empty">No flow data. Export NetFlow/sFlow from the router to see per-device usage &mdash; see the Traffic tab.</div>')+
      '<div class="small muted" style="margin-top:10px">source: '+esc(t.source||'none')+
      (t.exporters&&t.exporters.length?' · exporters '+t.exporters.map(esc).join(', '):'')+'</div>'+
    '</div>'+
    '<div class="card"><h2>Host health (agents)</h2>'+
      ((d.hosts||[]).length? (d.hosts||[]).slice(0,6).map(function(h){
        var warn=(h.warnings||[]);
        return '<div class="kv"><span>'+stDot(h.stale?'down':(warn.length?'degraded':'up'))+
          esc(h.host)+' <span class="muted small">'+esc(h.ip||'')+'</span></span>'+
          '<span class="small">'+(warn.length? warn.join(', '): 'ok')+
          ' <span class="muted">cpu '+(h.cpu_pct!=null?Math.round(h.cpu_pct)+'%':'—')+
          ' · disk '+h.worst_disk_pct+'%</span></span></div>';
      }).join('') : '<div class="empty">No agents reporting. Run '+
        '<span class="mono">run.bat --agent --console https://this-pc:8777 --token nsk_...</span> '+
        'on a server to see CPU, memory, disk and service state here.</div>')+
    '</div>'+
    '<div class="card" style="margin-top:14px"><h2>Internet path</h2>'+
      '<div class="kv"><span>Gateway</span><span>'+(d.gateway&&d.gateway.ip?esc(d.gateway.ip):'&mdash;')+
        ' '+stDot(d.gateway&&d.gateway.state)+'</span></div>'+
      ints.map(function(x){ return '<div class="kv"><span>'+esc(x.name)+'</span><span>'+
        stDot(x.state)+ms(x.latency)+' <span class="muted">'+Math.round(x.loss||0)+'% loss</span></span></div>';
      }).join('')+
      (function(){ var w=d.wan||{}, ips=w.ips||[], pub=d.public||{};
        var out='';
        var shown = ips.length? ips : (pub.ip? [pub.ip] : []);
        if(shown.length){
          out += '<div class="kv"><span>Public IP'+(w.dual?' <span class="badge sev-high">dual WAN</span>':'')+
                 '</span><span class="mono">'+shown.map(esc).join('<br>')+'</span></div>';
        } else if(pub.ip){
          out += '<div class="kv"><span>Public IP</span><span class="mono">'+esc(pub.ip)+'</span></div>';
        }
        var isp = w.isp || pub.isp;
        if(isp) out += '<div class="kv"><span>ISP</span><span>'+esc(isp)+'</span></div>';
        if(w.city) out += '<div class="kv"><span>Line location</span><span>'+esc(w.city)+'</span></div>';
        var ch=(w.changes||[]);
        if(ch.length){ var last=ch[ch.length-1];
          out += '<div class="kv"><span>Last IP change</span><span class="small">'+ago(last.ts)+
                 '</span></div>'; }
        return out; })()+
      (d.local&&d.local.dns&&d.local.dns.length?'<div class="kv"><span>DNS</span><span class="mono">'+esc(d.local.dns.join(', '))+'</span></div>':'')+
    '</div>'+
  '</div>';
}
function kpi(k,v,n){ return '<div class="card kpi"><div class="k">'+k+'</div><div class="v">'+v+
  '</div><div class="n">'+n+'</div></div>'; }
function kv(k,v){ return '<div class="kv"><span class="muted">'+k+'</span><span>'+v+'</span></div>'; }
function incRow(i){
  return '<div class="inc" onclick="openInc(\''+esc(i.id)+'\')">'+
    '<span class="badge sev-'+esc(i.severity)+'">'+esc(i.severity)+'</span>'+
    '<div style="flex:1"><div class="ttl">'+esc(i.title)+'</div>'+
    '<div class="meta">'+esc(i.device_name||'')+' · '+esc(i.device_ip||'')+' · opened '+ago(i.opened_ts)+
    (i.state==='escalated'?' · <span style="color:#f0b96a">escalated</span>':'')+'</div></div>'+
    '<span class="muted small">'+((i.diagnosis&&i.diagnosis.confidence)||0)+'%</span></div>';
}

// ----------------------------------------------------------------- devices --
function viewDevices(){
  var d=S.data, devs=(d.devices||[]), q=S.dev.q.toLowerCase();
  var rows=devs.filter(function(x){
    if(S.dev.mon && !(x.state&&x.state!=='unknown')) return false;
    if(S.dev.f!=='all'){
      var g=group(x.type);
      if(S.dev.f!==g) return false;
    }
    if(!q) return true;
    return (x.ip+' '+(x.mac||'')+' '+(x.hostname||'')+' '+(x.vendor||'')+' '+(x.label||'')+' '+
      (x.type_label||'')).toLowerCase().indexOf(q)>=0;
  });
  return '<div class="card"><div class="toolbar">'+
    ['all','infra','print','video','other'].map(function(f){
      var label={all:'All',infra:'Network gear',print:'Printers & KOT',video:'CCTV',other:'Other'}[f];
      return '<span class="chip '+(S.dev.f===f?'on':'')+'" onclick="S.dev.f=\''+f+'\';render()">'+label+'</span>';
    }).join('')+
    '<span class="sw"><input type="checkbox" '+(S.dev.mon?'checked':'')+
      ' onchange="S.dev.mon=this.checked;render()"> monitored only</span>'+
    '<span class="spacer"></span>'+
    '<input type="text" placeholder="search ip, mac, name, vendor" style="width:240px" value="'+esc(S.dev.q)+
      '" oninput="S.dev.q=this.value;render()"></div>'+
    '<div style="overflow:auto"><table><thead><tr><th>Status</th><th>Device</th><th>IP</th><th>Name</th>'+
    '<th>MAC / Vendor</th><th>Latency</th><th>Loss</th><th class="num">Down</th><th class="num">Up</th>'+
    '<th>Ports</th><th></th></tr></thead><tbody>'+
    (rows.length?rows.map(devRow).join(''):'<tr><td colspan="11" class="empty">No devices match.</td></tr>')+
    '</tbody></table></div>'+
    '<div class="small muted" style="margin-top:8px">'+(d.devices||[]).length+' devices discovered · '+
    (d.health&&d.health.monitored||0)+' monitored · click a row for details</div></div>';
}
function group(t){
  if(t==='router'||t==='switch'||t==='access_point') return 'infra';
  if(t==='printer'||t==='kot_printer'||t==='scanner') return 'print';
  if(t==='dvr'||t==='nvr'||t==='camera') return 'video';
  return 'other';
}
function devRow(x){
  var ports=(x.ports||[]).slice(0,5).map(function(p){
    return '<span class="port" title="'+esc(p.service)+'">'+p.port+'</span>'; }).join('')+
    ((x.ports||[]).length>5?'<span class="port">+'+(x.ports.length-5)+'</span>':'');
  var name=x.label||x.hostname||x.snmp_name||'';
  return '<tr onclick="openDev(\''+esc(x.ip)+'\')" style="cursor:pointer">'+
    '<td>'+stDot(x.state)+'</td>'+
    '<td><span class="badge t-'+esc(x.type)+'">'+esc(x.type_label)+'</span>'+
      (x.is_gateway?' <span class="small muted">gw</span>':'')+'</td>'+
    '<td class="mono">'+esc(x.ip)+'</td>'+
    '<td class="small">'+esc(name)+(x.title?'<div class="muted small" style="max-width:200px;overflow:hidden;'+
      'text-overflow:ellipsis;white-space:nowrap">'+esc(x.title)+'</div>':'')+'</td>'+
    '<td class="small mono">'+esc(x.mac||'&mdash;')+'<div class="muted" style="font-family:inherit">'+
      esc(x.vendor||'')+'</div></td>'+
    '<td>'+spark(x.history)+'<div class="small muted">'+ms(x.latency_ms)+'</div></td>'+
    '<td class="small">'+((x.loss_pct||0)>0?('<span style="color:'+((x.loss_pct>=10)?'#d9534f':'#e0a02c')+'">'+
      Math.round(x.loss_pct)+'%</span>'):'<span class="muted">0%</span>')+'</td>'+
    '<td class="num mono">'+bps(x.rx_bps)+'</td><td class="num mono">'+bps(x.tx_bps)+'</td>'+
    '<td><div class="ports">'+(ports||'<span class="muted small">none</span>')+'</div></td>'+
    '<td>'+(can('remote')?'<button class="sm ghost" onclick="event.stopPropagation();openRemote(\''+esc(x.ip)+'\')">remote</button>':'')+'</td></tr>';
}

// --------------------------------------------------------------- incidents --
function viewIncidents(){
  var d=S.data, all=(d.incidents||[]);
  if(!all.length) return '<div class="card"><div class="empty">No incidents yet. NetSentinel opens one when a '+
    'monitored device stays down or degraded for the configured number of polls.</div></div>';
  return '<div class="card"><h2>Incident history</h2><table><thead><tr><th>Severity</th><th>Incident</th>'+
    '<th>Device</th><th>Opened</th><th>State</th><th>Confidence</th></tr></thead><tbody>'+
    all.map(function(i){ return '<tr onclick="openInc(\''+esc(i.id)+'\')" style="cursor:pointer">'+
      '<td><span class="badge sev-'+esc(i.severity)+'">'+esc(i.severity)+'</span></td>'+
      '<td>'+esc(i.title)+'</td><td class="small">'+esc(i.device_name||'')+
      '<div class="muted mono">'+esc(i.device_ip||'')+'</div></td>'+
      '<td class="small">'+(i.opened_human||ago(i.opened_ts))+'</td>'+
      '<td class="small">'+esc(i.state)+'</td>'+
      '<td class="small">'+((i.diagnosis&&i.diagnosis.confidence)||0)+'%</td></tr>'; }).join('')+
    '</tbody></table></div>';
}

// ----------------------------------------------------------------- traffic --
function viewTraffic(){
  var d=S.data, t=d.traffic||{}, top=t.top||[];
  var max=top.length?Math.max.apply(null,top.map(function(x){return x.down_bps+x.up_bps;})):1;
  var hint='';
  if(!t.active || t.source==='none'){
    hint='<div class="note"><b>No flow data yet.</b> A PC cannot see other devices\' traffic by itself, so the '+
      'router or firewall has to send it. Turn on <b>NetFlow v5/v9 or IPFIX (UDP '+((d.settings&&d.settings.netflow&&d.settings.netflow.port)||2055)+
      ')</b> or <b>sFlow (UDP '+((d.settings&&d.settings.netflow&&d.settings.netflow.sflow_port)||6343)+
      ')</b> and point it at this PC. Works with MikroTik (/ip traffic-flow set enabled=yes), Cisco (ip flow-export '+
      'destination &lt;this PC&gt; 2055 version 9), Fortinet (config system netflow), pfSense/OPNsense (Soft Flowd), '+
      'UniFi (Settings → Traffic &amp; Security → Flow), Juniper and Aruba/HPE.</div>';
  } else if(t.source==='netflow'){
    hint='<div class="note ok">Reading flow exports from '+(t.exporters.length?esc(t.exporters.join(', ')):'the router')+
      ' · '+(t.packets||0)+' flow packets received'+
      (t.last_packet_age!=null?' · last '+Math.round(t.last_packet_age)+'s ago':'')+'.</div>';
  } else {
    hint='<div class="note">Showing '+esc(t.source)+' counters. Enable NetFlow/sFlow on the router for true '+
      'per-device internet usage.</div>';
  }
  return '<div class="card"><h2>Who is using the internet</h2>'+hint+
    (top.length?'<table><thead><tr><th>#</th><th>Device</th><th>IP</th><th class="num">Down</th>'+
      '<th class="num">Up</th><th class="num">Today</th><th style="width:22%">Share</th></tr></thead><tbody>'+
      top.map(function(x,idx){
        var tot=x.down_bps+x.up_bps, pct=max?Math.max(2,Math.round(tot/max*100)):0;
        return '<tr><td class="muted">'+(idx+1)+'</td>'+
          '<td>'+esc(x.name||x.type_label||'unknown')+'</td>'+
          '<td class="mono">'+esc(x.ip)+'</td>'+
          '<td class="num mono">'+bps(x.down_bps)+'</td><td class="num mono">'+bps(x.up_bps)+'</td>'+
          '<td class="num mono">'+bytes((x.down_bytes_today||0)+(x.up_bytes_today||0))+'</td>'+
          '<td><span class="tr" style="display:block;height:7px;background:#1a232d;border-radius:4px;overflow:hidden">'+
          '<i style="display:block;height:100%;width:'+pct+'%;background:linear-gradient(90deg,#3d8bfd,#3ba55d)"></i>'+
          '</span></td></tr>'; }).join('')+'</tbody></table>'
      :'<div class="empty">Nothing to rank yet.</div>')+
    '<div class="small muted" style="margin-top:10px">Total: '+bps(t.total_down_bps||0)+' down · '+
    bps(t.total_up_bps||0)+' up · source '+esc(t.source||'none')+'</div></div>';
}

// ----------------------------------------------------------------- reports --
function loadReports(){
  if(S.reports) return;
  var days=(S.repDays||7);
  api('/api/reports?hours='+(days*24)+'&days='+days).then(function(r){
    S.reports=r; render();
  }).catch(function(){});
}
function viewReports(){
  var d=S.data||{};
  if(!S.reports){ loadReports();
    return '<div class="card"><div class="empty">loading report&hellip;</div></div>'; }
  var r=S.reports, st=r.stats||{}, rows=r.devices||[];
  var sev=st.by_severity||{};
  var maxAvail=100;
  return '<div class="toolbar">'+
    [1,7,30].map(function(dd){ return '<span class="chip '+((S.repDays||7)===dd?'on':'')+
      '" onclick="S.repDays='+dd+';S.reports=null;render()">last '+dd+' day'+(dd>1?'s':'')+'</span>'; }).join('')+
    '<span class="spacer"></span>'+
    '<a class="chip" href="/api/reports.csv?hours='+((S.repDays||7)*24)+'">Export CSV</a></div>'+
    '<div class="kpis">'+
      kpi('Average availability', (r.average_availability||0)+'%', 'across '+rows.length+' monitored devices')+
      kpi('Incidents', st.total||0, (st.open_now||0)+' still open')+
      kpi('Mean time to resolve', (st.mttr_minutes||0)+' min', (st.resolved_count||0)+' resolved incidents')+
      kpi('Critical incidents', sev.critical||0, (sev.high||0)+' high · '+(sev.medium||0)+' medium')+
    '</div>'+
    '<div class="row two">'+
      '<div class="card"><h2>Availability per device</h2>'+
        (rows.length?'<table><thead><tr><th>Device</th><th>IP</th><th class="num">Availability</th>'+
        '<th class="num">Avg latency</th><th class="num">Worst loss</th><th>Trend</th></tr></thead><tbody>'+
        rows.map(function(x){
          var pct=x.availability_pct||0;
          var col=pct>=99.5?'#3ba55d':(pct>=95?'#e0a02c':'#d9534f');
          return '<tr><td>'+esc(x.name||x.type_label||'unknown')+'</td>'+
            '<td class="mono">'+esc(x.ip)+'</td>'+
            '<td class="num" style="color:'+col+'">'+pct.toFixed(2)+'%</td>'+
            '<td class="num mono">'+ms(x.avg_latency_ms)+'</td>'+
            '<td class="num mono">'+Math.round(x.worst_loss_pct||0)+'%</td>'+
            '<td><span style="display:block;height:6px;background:#1a232d;border-radius:4px;overflow:hidden">'+
            '<i style="display:block;height:100%;width:'+Math.max(2,pct)+'%;background:'+col+'"></i></span></td></tr>';
        }).join('')+'</tbody></table>':'<div class="empty">No samples yet in this window.</div>')+
      '</div>'+
      '<div>'+
        '<div class="card"><h2>Worst offenders</h2>'+
          ((r.worst||[]).length? (r.worst||[]).map(function(x){
            return '<div class="kv"><span>'+esc(x.name||x.ip)+' <span class="muted mono">'+esc(x.ip)+'</span></span>'+
              '<span>'+(x.availability_pct||0).toFixed(2)+'%</span></div>'; }).join('')
            :'<div class="empty">Every device stayed above 99.5%.</div>')+'</div>'+
        '<div class="card" style="margin-top:14px"><h2>Internet line changes</h2>'+
          ((r.wan_changes||[]).length? (r.wan_changes||[]).slice(-6).reverse().map(function(c){
            return '<div class="kv"><span class="small">'+new Date(c.ts*1000).toLocaleString()+'</span>'+
              '<span class="small mono">'+esc((c.to||[]).join(', '))+'</span></div>'; }).join('')
            :'<div class="empty">No public IP change seen in this window.</div>')+'</div>'+
      '</div>'+
    '</div>';
}

// --------------------------------------------------------------- locations --
function viewLocations(){
  var d=S.data||{}, br=d.branch||{}, hub=d.sites||{};
  if(!hub.enabled && br.sent){
    return '<div class="card"><h2>This site reports to head office</h2>'+
      kv('Hub', esc((d.settings.branch||{}).hub_url||'&mdash;'))+
      kv('Reports sent', br.sent||0)+
      kv('Last successful report', br.age!=null? ago(Math.round(Date.now()/1000-br.age)) : 'never')+
      (br.error?'<div class="note bad" style="margin-top:10px">'+esc(br.error)+'</div>':
        '<div class="note ok" style="margin-top:10px">Head office is receiving this site\'s status.</div>')+
      '</div>';
  }
  var rows=hub.branches||[], t=hub.totals||{};
  var q=(S.siteQ||'').toLowerCase();
  if(q) rows=rows.filter(function(b){
    return (b.name||'').toLowerCase().indexOf(q)>=0 ||
           (((b.wan||{}).ips||[]).join(' ')).indexOf(q)>=0 ||
           (b.online?'':'no contact').indexOf(q)>=0;
  });
  var CAP=60;
  var shown=rows.length>CAP? rows.slice(0,CAP) : rows;
  var lastRegion=null;
  var body = rows.length? shown.map(function(b){
    var region=(b.name||'').indexOf(' - ')>0? (b.name||'').split(' - ').pop() : 'Unassigned';
    var head='';
    if(rows.length>12 && region!==lastRegion){
      lastRegion=region;
      head='<tr><td colspan="9" style="padding:10px 6px 4px;font-size:11px;'+
        'letter-spacing:.6px;text-transform:uppercase;color:#8899ab;border-bottom:1px solid #1d2733">'+
        esc(region)+'</td></tr>';
    }
    var h=b.health||{}, inc=(b.incidents||[]);
    var worst = inc.length? inc[0] : null;
    var kind=b.kind||'hotel';
    return head+'<tr onclick="openSite(\''+esc(b.name)+'\')" style="cursor:pointer">'+
      '<td>'+stDot(b.online?(h.down?'degraded':'up'):'down')+'</td>'+
      '<td>'+(kind==='corp'?'<span class="badge sev-info" style="margin-right:6px">CORP</span>'
                            :'<span class="badge" style="margin-right:6px;background:#1b2f45;'+
                             'color:#8cc2f5">HOTEL</span>')+
        esc(b.name)+(b.online?'':' <span class="badge sev-high">no contact</span>')+'</td>'+
      '<td class="num">'+(h.score!=null?h.score+'%':'&mdash;')+'</td>'+
      '<td class="num">'+(b.devices||0)+'</td>'+
      '<td class="num">'+inc.length+'</td>'+
      '<td class="small">'+(worst? '<span class="badge sev-'+esc(worst.severity)+'">'+
        esc(worst.severity)+'</span> '+esc(worst.title).slice(0,40) : '<span class="muted">none</span>')+'</td>'+
      '<td class="mono small">'+(((b.wan||{}).ips||[]).length? esc(((b.wan||{}).ips||[]).join(', '))
        : '<span class="muted">&mdash;</span>')+'</td>'+
      '<td class="num mono">'+bps((b.traffic||{}).down_bps||0)+'</td>'+
      '<td class="small">'+ago(Math.round(Date.now()/1000-(b.age||0)))+'</td></tr>';
  }).join('') : '<tr><td colspan="9" class="empty">No branch has reported yet. On each branch run '+
     '<span class="mono">run.bat --branch http://'+esc((d.local||{}).ip||'HUB-IP')+':8777 --token TOKEN</span>'+
     '</td></tr>';
  return '<div class="kpis">'+
    kpi('Locations', t.sites||0, 'corporate office + '+(t.hotels||0)+' hotel(s), '+(t.online||0)+' reporting')+
    kpi('Devices', t.devices||0, 'across all sites')+
    kpi('Open incidents', t.incidents||0, (t.critical||0)+' critical')+
    kpi('Links down', t.down_links||0, 'gateway unreachable')+
    '</div>'+
    '<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;'+
    'margin-bottom:10px"><h2 style="margin:0">All locations - corporate office and hotels</h2>'+
    '<input id="siteq" placeholder="search site, IP or no-contact" value="'+esc(S.siteQ||'')+'" '+
    'style="width:260px;padding:6px 10px;background:#0f151c;border:1px solid #243040;'+
    'border-radius:6px;color:#e8eef5;font-size:12.5px" oninput="S.siteQ=this.value;render()"></div>'+
    '<table><thead><tr><th></th><th>Location</th>'+
    '<th class="num">Health</th><th class="num">Devices</th><th class="num">Incidents</th>'+
    '<th>Worst incident</th><th>Public IP</th><th class="num">Internet</th><th>Last report</th>'+
    '</tr></thead><tbody>'+body+'</tbody></table>'+
    (rows.length>CAP? '<div class="note" style="margin-top:8px">Showing '+CAP+' of '+rows.length+
      ' locations - type in the search box to narrow it down.</div>' : '')+
    '<div class="small muted" style="margin-top:8px">A site is marked "no contact" after '+
    (hub.expect_minutes||5)+' minutes without a report, and an alert is raised.</div></div>';
}
function openSite(name){
  var b=((S.data.sites||{}).branches||[]).filter(function(x){return x.name===name;})[0];
  if(!b) return;
  var inc=(b.incidents||[]);
  document.getElementById('drawer-title').textContent=name+' - '+((b.health||{}).score||0)+'% health';
  document.getElementById('drawer-body').innerHTML=
    kv('Reporting', b.online?'yes':'no contact')+
    kv('Version', esc(b.version||'&mdash;'))+kv('Devices', b.devices||0)+
    kv('Monitored', b.monitored||0)+kv('Gateway', esc(b.gateway||'unknown'))+
    kv('Public IP', esc(((b.wan||{}).ips||[]).join(', ')||'&mdash;'))+
    kv('ISP', esc((b.wan||{}).isp||'&mdash;'))+
    kv('Internet down', bps((b.traffic||{}).down_bps||0))+
    kv('Last report', ago(Math.round(Date.now()/1000-(b.age||0))))+
    '<div style="margin:14px 0 4px" class="small muted">OPEN INCIDENTS</div>'+
    (inc.length? inc.map(function(i){
      return '<div class="kv"><span><span class="badge sev-'+esc(i.severity)+'">'+esc(i.severity)+
        '</span> '+esc(i.title)+'</span><span class="small muted">'+esc(i.device_name||'')+'</span></div>';
    }).join('') : '<div class="small muted">none</div>');
  document.getElementById('drawer').classList.add('open');
}

// ------------------------------------------------------------------- users --
function roleBadge(r){
  var cls = r==='admin'?'sev-critical':(r==='engineer'?'sev-high':'sev-info');
  var label = r==='admin'?'Administrator':(r==='engineer'?'Engineer':'Viewer');
  return '<span class="badge '+cls+'">'+label+'</span>';
}
function when(ts){
  if(!ts) return '<span class="muted">never</span>';
  return new Date(ts*1000).toLocaleString();
}
function viewUsers(){
  var users=(S.data.users||[]), me=((S.data.auth||{}).user||'');
  var adminCount=users.filter(function(u){return u.role==='admin';}).length;
  var rows=users.map(function(u){
    var you=(u.username===me);
    return '<tr'+(you?' style="background:#16222c"':'')+'>'+
      '<td><b>'+esc(u.username)+'</b>'+(you?' <span class="badge sev-info">you</span>':'')+'</td>'+
      '<td>'+roleBadge(u.role)+'</td>'+
      '<td class="small muted">'+when(u.created_ts)+'</td>'+
      '<td class="small muted">'+when(u.last_login_ts)+'</td>'+
      '<td style="text-align:right">'+
        '<button class="sm ghost" onclick="resetPw(\''+esc(u.username)+'\')">set password</button> '+
        '<button class="sm ghost" onclick="enrol2fa(\''+esc(u.username)+'\')">2FA</button> '+
        (u.username!==me? '<button class="sm ghost" onclick="delUser(\''+esc(u.username)+'\')">remove</button>'
                       : '<span class="small muted">current session</span>')+
      '</td></tr>';
  }).join('');
  return '<div class="row two">'+
    '<div class="card"><h2>Users of this console</h2>'+
      '<table><thead><tr><th>User</th><th>Role</th><th>Created</th><th>Last sign-in</th><th></th>'+
      '</tr></thead><tbody>'+(rows||'<tr><td colspan="5" class="empty">No users yet.</td></tr>')+
      '</tbody></table>'+
      '<div class="small muted" style="margin-top:10px">'+(adminCount)+' administrator'+
      (adminCount===1?'':'s')+' &middot; '+users.length+' account'+(users.length===1?'':'s')+
      '. Roles decide what the server allows: a viewer can only read, an engineer can operate '+
      'devices, an administrator can change settings and users.</div>'+
    '</div>'+
    '<div>'+
      '<div class="card"><h2>Add a user</h2>'+
        '<div class="field"><label>User name</label><input type="text" id="nu" value=""></div>'+
        '<div class="field"><label>Password (6+ characters)</label>'+
          '<input type="password" id="np" value=""></div>'+
        '<div class="field"><label>Role</label><select id="nrole">'+
          '<option value="viewer">Viewer - read only</option>'+
          '<option value="engineer" selected>Engineer - operate devices</option>'+
          '<option value="admin">Administrator - full control</option></select></div>'+
        '<button class="primary" onclick="addUser()">Create user</button>'+
        '<div id="umsg" class="small muted" style="margin-top:8px"></div>'+
      '</div>'+
      '<div class="card" style="margin-top:14px"><h2>What each role can do</h2>'+
        '<div class="kv"><span>Viewer</span><span class="small">read dashboards, devices, reports</span></div>'+
        '<div class="kv"><span>Engineer</span><span class="small">+ rescan, remote sessions, Wake-on-LAN, close incidents, label devices</span></div>'+
        '<div class="kv"><span>Administrator</span><span class="small">+ settings, alerts, users, branch tokens</span></div>'+
        '<div class="kv"><span>Audit</span><span class="small">every action is logged with the user name</span></div>'+
      '</div>'+
    '</div></div>';
}
function enrol2fa(name){
  api('/api/users/totp',{method:'POST',body:JSON.stringify({username:name})}).then(function(r){
    if(!r.ok){ alert(r.message||'failed'); return; }
    var m=document.createElement('div');
    m.style.cssText='position:fixed;inset:0;z-index:60;background:rgba(6,9,12,.74);'+
      'display:flex;align-items:center;justify-content:center;padding:16px';
    m.innerHTML='<div style="width:520px;max-width:94vw;background:#141b23;border:1px solid #2a3644;'+
      'border-radius:12px;padding:20px;font:13px -apple-system,Segoe UI,Roboto,sans-serif">'+
      '<div style="font-weight:600;font-size:15px;margin-bottom:4px">Two-factor for '+esc(name)+'</div>'+
      '<div class="small muted" style="margin-bottom:12px">Add this to Google/Microsoft '+
      'Authenticator, Authy or 1Password, then type the 6-digit code it shows.</div>'+
      '<div style="font-size:11px;color:#8899ab;text-transform:uppercase;letter-spacing:.5px">secret</div>'+
      '<div class="mono" style="background:#0b1016;border:1px solid #243040;border-radius:6px;'+
      'padding:8px;word-break:break-all;margin:4px 0 10px">'+esc(r.secret)+'</div>'+
      '<div style="font-size:11px;color:#8899ab;text-transform:uppercase;letter-spacing:.5px">'+
      'backup codes (save these)</div>'+
      '<div class="mono small" style="background:#0b1016;border:1px solid #243040;border-radius:6px;'+
      'padding:8px;margin:4px 0 12px">'+r.backup_codes.map(esc).join('  ')+'</div>'+
      '<input id="otpcode" placeholder="6-digit code" maxlength="12" style="width:100%;padding:8px;'+
      'background:#0f151c;border:1px solid #243040;border-radius:6px;color:#e8eef5;letter-spacing:3px">'+
      '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px">'+
      '<button id="otpcancel" style="padding:7px 14px">Cancel</button>'+
      '<button id="otpconfirm" style="padding:7px 16px;background:#3d8bfd;border:1px solid #3d8bfd;'+
      'color:#04121f;font-weight:600;border-radius:6px">Enable 2FA</button></div>'+
      '<div id="otpmsg" class="small" style="margin-top:8px"></div></div>';
    document.body.appendChild(m);
    document.getElementById('otpcancel').onclick=function(){ m.remove(); };
    document.getElementById('otpconfirm').onclick=function(){
      api('/api/users/totp/verify',{method:'POST',body:JSON.stringify({username:name,
        code:(document.getElementById('otpcode').value||'').trim()})}).then(function(v){
        if(v.ok){ m.remove(); poll(); }
        else { document.getElementById('otpmsg').textContent=v.message||'failed'; }
      });
    };
  });
}
function resetPw(name){
  var p=prompt('New password for '+name+' (6+ characters):','');
  if(!p) return;
  api('/api/users/password',{method:'POST',body:JSON.stringify({username:name,password:p})})
    .then(function(r){ alert(r.ok? ('Password changed for '+name) : (r.message||'failed')); });
}

// ------------------------------------------------------------------ events --
function viewEvents(){
  var ev=(S.data.events||[]);
  if(!ev.length) return '<div class="card"><div class="empty">No events yet. Firewall syslog (UDP '+
    ((S.data.settings&&S.data.settings.syslog&&S.data.settings.syslog.port)||5514)+') lands here.</div></div>';
  return '<div class="card"><h2>Events</h2><table><thead><tr><th>Time</th><th>Severity</th><th>Source</th>'+
    '<th>Message</th></tr></thead><tbody>'+ev.map(function(e){
      return '<tr><td class="small mono">'+new Date(e.ts*1000).toLocaleTimeString()+'</td>'+
        '<td><span class="badge sev-'+esc(e.severity)+'">'+esc(e.severity)+'</span></td>'+
        '<td class="small">'+esc(e.source)+'</td><td class="small">'+esc(e.message)+'</td></tr>'; }).join('')+
    '</tbody></table></div>';
}

// ---------------------------------------------------------------- settings --
function viewSettings(){
  var s=(S.data.settings||{}), th=s.thresholds||{}, mon=s.monitor||{}, nf=s.netflow||{},
      sl=s.syslog||{}, em=s.email||{}, wh=s.webhook||{}, au=s.auth||{};
  function fld(label,id,val,type){ return '<div class="field"><label>'+label+'</label><input type="'+
    (type||'text')+'" id="'+id+'" value="'+esc(val==null?'':val)+'"></div>'; }
  function chk(label,id,val){ return '<div class="field"><span class="sw"><input type="checkbox" id="'+id+'" '+
    (val?'checked':'')+'> '+label+'</span></div>'; }
  return '<div class="row two">'+
   '<div class="card"><h2>Monitoring</h2>'+
     fld('Site name','site',s.site_name)+
     fld('Poll interval (seconds)','poll',s.poll_interval_seconds,'number')+
     '<div class="grid2">'+
       fld('Latency warn (ms)','lw',th.latency_warn_ms,'number')+
       fld('Latency critical (ms)','lc',th.latency_crit_ms,'number')+
       fld('Loss warn (%)','sw1',th.loss_warn_pct,'number')+
       fld('Loss critical (%)','sc1',th.loss_crit_pct,'number')+
       fld('Open incident after N bad polls','ob',th.open_after_bad_polls,'number')+
       fld('Resolve after N good polls','rg',th.resolve_after_good_polls,'number')+
     '</div>'+
     '<div class="grid2">'+chk('Monitor printers &amp; KOT','mp',mon.printers)+
       chk('Monitor phones / IoT','mphone',mon.phones)+chk('Monitor unknown devices','munk',mon.unknown)+
       chk('Monitor servers','msrv',mon.servers)+'</div>'+
     '<div class="field"><label>Rescan network every (minutes, 0 = never)</label>'+
       '<input type="number" id="disc" value="'+esc((s.discovery||{}).interval_minutes)+'"></div>'+
   '</div>'+
   '<div class="card"><h2>Flow &amp; syslog</h2>'+
     chk('Collect NetFlow / sFlow','nfen',nf.enabled)+
     '<div class="grid2">'+fld('NetFlow / IPFIX port','nfp',nf.port,'number')+
       fld('sFlow port','sfp',nf.sflow_port,'number')+'</div>'+
     '<div class="field"><label>Allowed exporters (comma separated, empty = any)</label><input type="text" id="nfx" value="'+
       esc((nf.allowed_exporters||[]).join(', '))+'"></div>'+
     chk('Receive syslog','slen',sl.enabled)+
     fld('Syslog port','slp',sl.port,'number')+
     '<div class="small muted">Alert patterns are in config.json (regex list).</div>'+
   '</div></div>'+
   '<div class="row two" style="margin-top:14px">'+
   '<div class="card"><h2>Email alerts</h2>'+
     chk('Enable email alerts','emen',em.enabled)+
     '<div class="grid2">'+fld('SMTP host','emh',em.host)+fld('Port','emp',em.port,'number')+'</div>'+
     '<div class="grid2">'+fld('User name','emu',em.username)+
       '<div class="field"><label>Password</label><input type="password" id="empw" value="" placeholder="'+
         (em.password_set?'******** saved':'')+'"></div></div>'+
     '<div class="grid2">'+fld('From address','emf',em.from)+
       fld('To (comma separated)','emt',(em.to||[]).join(', '))+'</div>'+
     '<div class="grid2">'+chk('SSL (port 465)','emssl',em.ssl)+chk('STARTTLS (port 587)','emtl',em.starttls)+'</div>'+
     '<div class="field"><label>Minimum severity</label><select id="emsev">'+
       ['low','medium','high','critical'].map(function(v){return '<option '+(em.min_severity===v?'selected':'')+
       '>'+v+'</option>';}).join('')+'</select></div>'+
   '</div>'+
   '<div class="card"><h2>Head office (hub)</h2>'+
     chk('This PC is the head office hub','huben',(s.hub||{}).enabled)+
     fld('Mark a site lost after (minutes)','hubexp',(s.hub||{}).expect_minutes,'number')+
     '<div class="small muted" style="margin:8px 0 6px">Branch tokens (hashed on disk)</div>'+
     '<div style="max-height:280px;overflow:auto;padding-right:4px">'+
     (((s.hub||{}).sites||[]).map(function(x,i){
        var em=((x.email||[]).join(', '));
        return '<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">'+
          '<span style="min-width:170px">'+esc(x.name)+'</span>'+
          '<input type="text" id="siteemail-'+i+'" value="'+esc(em)+'" placeholder="it manager emails, comma separated" '+
          'style="flex:1;padding:5px 8px;background:#0f151c;border:1px solid #243040;'+
          'border-radius:5px;color:#e8eef5;font-size:12px">'+
          '<button class="sm ghost" onclick="delSite(\''+esc(x.name)+'\')">remove</button></div>';
      }).join('')||'<div class="small muted">no branches yet</div>')+'</div>'+
     '<div class="small muted" style="margin:2px 0 8px">The emails on a site get its '+
     '&quot;lost contact&quot; and &quot;is back&quot; mail. Leave blank to use the main '+
     'email list below.</div>'+
     '<div class="grid2" style="margin-top:10px">'+fld('New branch name','nsite','')+
       '<div class="field" style="display:flex;align-items:flex-end">'+
       '<button class="sm" onclick="addSite()">Add branch &amp; show token</button></div></div>'+
     '<div id="tokmsg" class="small" style="margin-top:6px"></div>'+
   '</div>'+
   '<div class="card" style="margin-top:14px"><h2>This site reports to a hub</h2>'+
     fld('Hub URL (e.g. http://10.0.0.5:8777)','brurl',(s.branch||{}).hub_url)+
     '<div class="field"><label>Branch token</label><input type="text" id="brtok" value="" placeholder="'+
       ((s.branch||{}).token_set?'******** saved':'paste the token head office gave you')+'"></div>'+
     fld('Report every (seconds)','brint',(s.branch||{}).interval_seconds,'number')+
     '<button class="sm" onclick="testBranch()">Send a test report</button>'+
     '<div id="brmsg" class="small muted" style="margin-top:6px"></div>'+
   '</div>'+
   '<div class="card"><h2>SIEM &amp; chat alerts</h2>'+
     chk('Forward incidents to a SIEM','sien',(s.siem||{}).enabled)+
     '<div class="grid2">'+fld('SIEM host','sih',(s.siem||{}).host)+
       fld('Port','sip',(s.siem||{}).port,'number')+'</div>'+
     '<div class="grid2">'+
       '<div class="field"><label>Transport</label><select id="siproto">'+
         ['udp','tcp'].map(function(v){return '<option '+((s.siem||{}).proto===v?'selected':'')+'>'+v+'</option>';}).join('')+
       '</select></div>'+
       '<div class="field"><label>Format</label><select id="sifmt">'+
         ['cef','rfc5424'].map(function(v){return '<option '+((s.siem||{}).format===v?'selected':'')+'>'+v+'</option>';}).join('')+
       '</select></div></div>'+
     chk('Slack alerts','slen2',(s.slack||{}).enabled)+fld('Slack webhook URL','slurl',(s.slack||{}).webhook_url)+
     chk('Microsoft Teams alerts','ten',(s.teams||{}).enabled)+fld('Teams webhook URL','teurl',(s.teams||{}).webhook_url)+
     '<div class="small muted">Incidents also go to the generic webhook above. Use the button '+
     'below to prove every channel works.</div>'+
   '</div>'+
   updateCard(s.update||{})+
   '<div class="card" style="margin-top:14px"><h2>Heartbeat (dead-man\'s switch)</h2>'+
     chk('Ping an outside service so you are told when this whole site goes dark','hben',
         (s.heartbeat||{}).enabled)+
     fld('Heartbeat URL (healthchecks.io / UptimeRobot push)','hburl',(s.heartbeat||{}).url)+
     fld('Every (seconds)','hbint',(s.heartbeat||{}).interval_seconds,'number')+
     '<div class="small muted" style="margin-bottom:10px">One check on the head-office hub is '+
     'enough for the whole chain - it already knows which hotels are reporting. Add per-site '+
     'checks only for the properties that must be watched independently.</div>'+
     '<div style="display:flex;gap:8px;align-items:center">'+
     '<button class="sm" onclick="testHeartbeat()">Send test ping</button>'+
     '<span id="hbmsg" class="small muted"></span></div>'+
     '<div class="small muted" id="hbstate" style="margin-top:8px"></div>'+
   '</div>'+
   '<div class="card" style="margin-top:14px"><h2>Access &amp; certificates</h2>'+
     '<div class="field"><label>Allow only these networks (CIDR, comma separated, empty = any)</label>'+
       '<input type="text" id="accallow" value="'+esc(((s.access||{}).allow_cidrs)||[]).replace(/,/g, ', ')+'"></div>'+
     '<div class="field"><label>Blocked networks</label>'+
       '<input type="text" id="accdeny" value="'+esc(((s.access||{}).deny_cidrs)||[]).replace(/,/g, ', ')+'"></div>'+
     '<div class="field"><label>Trusted reverse proxies (they may set X-Forwarded-For)</label>'+
       '<input type="text" id="accproxy" value="'+esc(((s.access||{}).trusted_proxies)||[]).replace(/,/g, ', ')+'"></div>'+
     '<div class="grid2">'+
       fld('Warn when the certificate has (days)','certdays',(s.certs||{}).renew_days,'number')+
       chk('Restart automatically after renewal','certrestart',(s.certs||{}).auto_restart)+'</div>'+
     '<div class="field"><label>Renewal command (win-acme / certbot / your script)</label>'+
       '<input type="text" id="certcmd" value="'+esc((s.certs||{}).renew_command)+'" '+
       'placeholder="wacs.exe --renew --force"></div>'+
     '<div class="small muted">A console published on the internet should also require 2FA on '+
     'local accounts (Users view) or SSO only.</div>'+
   '</div>'+
   '<div class="card" style="margin-top:14px"><h2>Host agent thresholds</h2>'+
     '<div class="grid3">'+fld('CPU %','hcpu',(s.hosts||{}).cpu_warn_pct,'number')+
       fld('Memory %','hmem',(s.hosts||{}).mem_warn_pct,'number')+
       fld('Disk %','hdisk',(s.hosts||{}).disk_warn_pct,'number')+'</div>'+
     fld('Flag a host as stale after (minutes)','hstale',(s.hosts||{}).stale_minutes,'number')+
     '<div class="small muted">Run on a server: <span class="mono">run.bat --agent --console '+
     'https://this-pc:8777 --token nsk_...</span></div>'+
   '</div>'+
   '<div class="card"><h2>Webhook &amp; security</h2>'+
     chk('Enable webhook','when',wh.enabled)+fld('Webhook URL','whu',wh.url)+
     '<div class="field"><label>Webhook minimum severity</label><select id="whsev">'+
       ['low','medium','high','critical'].map(function(v){return '<option '+(wh.min_severity===v?'selected':'')+
       '>'+v+'</option>';}).join('')+'</select></div>'+
     chk('Require sign-in','auen',au.enabled)+
     '<div class="small muted" style="margin:8px 0 6px">'+
       ((S.data.users||[]).length)+' account(s) - manage them in the '+
       '<a href="#users">Users</a> view</div>'+
   '</div></div>'+
   '<div class="card" style="margin-top:14px"><div class="toolbar" style="margin:0">'+
     '<button class="primary" onclick="saveSettings()">Save settings</button>'+
     '<button onclick="testAlert()">Send test alert</button>'+
     '<span id="set-msg" class="small muted"></span></div></div>';
}
function num(id,dflt){ var v=document.getElementById(id); if(!v) return dflt;
  var n=parseFloat(v.value); return isNaN(n)?dflt:n; }
function chkVal(id){ var v=document.getElementById(id); return v?v.checked:false; }
function strVal(id){ var v=document.getElementById(id); return v?v.value:''; }
function updateCard(cfg){
  var u=S.data.update||{}, when=u.last_check?new Date(u.last_check*1000).toLocaleString():'not yet';
  var state={idle:'waiting for the first check',checking:'checking ...',up_to_date:'up to date',
    available:'version '+esc(u.latest)+' is available',updating:'downloading and installing '+esc(u.latest)+' ...',
    restarting:'restarting into '+esc(u.latest)+' ...',error:'last check failed'}[u.status]||esc(u.status||'');
  var how={exe:'NetSentinel.exe replaces itself and restarts',
    source:'the app files are replaced (with a backup) and it restarts',
    notify:'this copy (.pyz / Mac app) only tells you - download the new version yourself'}[u.mode]||'';
  return '<div class="card" style="margin-top:14px"><h2>Updates</h2>'+
    '<div class="small" style="margin-bottom:8px">This copy: <b>'+esc(u.version||'?')+'</b> &middot; '+
      'newest: <b>'+esc(u.latest||'?')+'</b> &middot; '+state+
      (u.notes_url&&u.latest?' &middot; <a href="'+esc(u.notes_url)+'" target="_blank" rel="noopener">what changed</a>':'')+'</div>'+
    (u.error?'<div class="small" style="color:var(--bad,#c33);margin-bottom:8px">'+esc(u.error)+'</div>':'')+
    '<div class="field"><span class="sw"><input type="checkbox" id="upchk" '+(cfg.check!==false?'checked':'')+
      '> Check GitHub for new versions every 6 hours</span></div>'+
    (u.can_install===false?'':'<div class="field"><span class="sw"><input type="checkbox" id="upauto" '+
      (cfg.auto_install!==false?'checked':'')+'> Install them automatically</span></div>')+
    '<div class="small muted" style="margin-bottom:10px">Last check: '+esc(when)+'. '+esc(how)+
      '. Only releases signed with the NetSentinel key are installed; if a new version does not start, '+
      'the previous one is put back.</div>'+
    '<div style="display:flex;gap:8px;align-items:center">'+
      '<button class="sm" onclick="updateAction(\'check\')">Check now</button>'+
      (u.status==='available'&&u.can_install?'<button class="sm primary" onclick="updateAction(\'install\')">Install '+
        esc(u.latest)+' now</button>':'')+
      '<span id="upmsg" class="small muted"></span></div></div>';
}
function updateAction(kind){
  var el=document.getElementById('upmsg'); el.textContent=kind==='install'?'starting ...':'checking ...';
  api('/api/update/'+kind,{method:'POST',body:'{}'}).then(function(r){
    el.textContent=r.message||(r.ok?'ok':'failed');
  });
}
function testHeartbeat(){
  var el=document.getElementById('hbmsg'); el.textContent='sending ...';
  api('/api/heartbeat/test',{method:'POST',body:'{}'}).then(function(r){
    el.textContent = r.ok ? ('sent - ' + (r.message||'ok')) : ('failed - ' + (r.message||'?'));
  });
}
function saveSettings(){
  var patch={ site_name:strVal('site'), poll_interval_seconds:num('poll',60),
    thresholds:{latency_warn_ms:num('lw',150),latency_crit_ms:num('lc',300),loss_warn_pct:num('sw1',3),
      loss_crit_pct:num('sc1',10),open_after_bad_polls:num('ob',2),resolve_after_good_polls:num('rg',3)},
    monitor:{printers:chkVal('mp'),phones:chkVal('mphone'),unknown:chkVal('munk'),servers:chkVal('msrv')},
    discovery:{interval_minutes:num('disc',10)},
    netflow:{enabled:chkVal('nfen'),port:num('nfp',2055),sflow_port:num('sfp',6343),
      allowed_exporters:strVal('nfx').split(',').map(function(x){return x.trim();}).filter(Boolean)},
    syslog:{enabled:chkVal('slen'),port:num('slp',5514)},
    email:{enabled:chkVal('emen'),host:strVal('emh'),port:num('emp',465),username:strVal('emu'),
      from:strVal('emf'),to:strVal('emt').split(',').map(function(x){return x.trim();}).filter(Boolean),
      ssl:chkVal('emssl'),starttls:chkVal('emtl'),
      min_severity:(document.getElementById('emsev')||{}).value||'medium'},
    webhook:{enabled:chkVal('when'),url:strVal('whu'),
      min_severity:(document.getElementById('whsev')||{}).value||'high'},
    auth:{enabled:chkVal('auen')},
    siem:{enabled:chkVal('sien'),host:strVal('sih'),port:num('sip',514),
      proto:(document.getElementById('siproto')||{}).value||'udp',
      format:(document.getElementById('sifmt')||{}).value||'cef'},
    slack:{enabled:chkVal('slen2'),webhook_url:strVal('slurl')},
    teams:{enabled:chkVal('ten'),webhook_url:strVal('teurl')},
    hosts:{cpu_warn_pct:num('hcpu',90),mem_warn_pct:num('hmem',92),
           disk_warn_pct:num('hdisk',90),stale_minutes:num('hstale',10)},
    heartbeat:{enabled:chkVal('hben'),url:strVal('hburl'),interval_seconds:num('hbint',300)},
    update:{check:chkVal('upchk'),auto_install:document.getElementById('upauto')?chkVal('upauto'):true},
    access:{allow_cidrs:strVal('accallow').split(',').map(function(x){return x.trim();}).filter(Boolean),
            deny_cidrs:strVal('accdeny').split(',').map(function(x){return x.trim();}).filter(Boolean),
            trusted_proxies:strVal('accproxy').split(',').map(function(x){return x.trim();}).filter(Boolean)},
    certs:{renew_days:num('certdays',21),auto_restart:chkVal('certrestart'),
           renew_command:strVal('certcmd')},
    hub:{enabled:chkVal('huben'),expect_minutes:num('hubexp',5),
         sites:((S.data&&S.data.settings&&S.data.settings.hub||{}).sites||[]).map(function(x,i){
           var el=document.getElementById('siteemail-'+i);
           return {name:x.name, email:el? String(el.value||'').split(',').map(function(e){
             return e.trim(); }).filter(function(e){ return e.indexOf('@')>0; }): (x.email||[])};
         })},
    branch:{hub_url:strVal('brurl'),interval_seconds:num('brint',30)}
  };
  var bt=strVal('brtok'); if(bt) patch.branch.token=bt;
  var pw=strVal('empw'); if(pw) patch.email.password=pw;
  document.getElementById('set-msg').textContent='saving...';
  api('/api/settings',{method:'POST',body:JSON.stringify(patch)}).then(function(r){
    document.getElementById('set-msg').textContent=r.ok?'saved':'save failed: '+(r.message||'');
    poll();
  });
}
function addSite(){
  var n=strVal('nsite'); if(!n){ alert('Branch name required'); return; }
  api('/api/hub/site',{method:'POST',body:JSON.stringify({name:n})}).then(function(r){
    var el=document.getElementById('tokmsg');
    if(r.ok){
      el.innerHTML='Token for <b>'+esc(n)+'</b> (copy it now, it is not shown again):<br>'+
        '<span class="mono" style="word-break:break-all">'+esc(r.token)+'</span><br>'+
        'On that branch run: <span class="mono">run.bat --branch '+esc(location.origin)+
        ' --token '+esc(r.token)+'</span>';
    } else { el.textContent=r.message||'failed'; }
    S.reports=null; poll();
  });
}
function delSite(name){
  if(!confirm('Remove branch '+name+'?')) return;
  api('/api/hub/site/delete',{method:'POST',body:JSON.stringify({name:name})}).then(poll);
}
function testBranch(){
  document.getElementById('brmsg').textContent='sending...';
  api('/api/branch/test',{method:'POST',body:'{}'}).then(function(r){
    document.getElementById('brmsg').textContent = r.ok? ('sent - hub says '+(r.message||'ok'))
      : ('failed: '+(r.message||''));
  });
}
function testAlert(){
  document.getElementById('set-msg').textContent='sending test...';
  api('/api/alert/test',{method:'POST',body:'{}'}).then(function(r){
    var parts=['email','webhook','siem','slack','teams'].filter(function(k){return r[k];})
      .map(function(k){ return k+': '+(r[k].ok?'sent':r[k].message); });
    document.getElementById('set-msg').textContent = parts.join(' · ') || 'nothing configured';
  });
}
function addUser(){
  var u=strVal('nu'), p=strVal('np'), role=(document.getElementById('nrole')||{}).value||'engineer';
  if(!u||!p){ alert('User name and password are required'); return; }
  api('/api/users',{method:'POST',body:JSON.stringify({username:u,password:p,role:role})})
    .then(function(r){
      var m=document.getElementById('umsg');
      if(m) m.textContent = r.ok? ('user '+u+' created') : (r.message||'failed');
      else if(!r.ok) alert(r.message||'failed');
      S.reports=null; poll();
    });
}
function delUser(name){
  if(!confirm('Remove user '+name+'?')) return;
  api('/api/users/delete',{method:'POST',body:JSON.stringify({username:name})})
    .then(function(r){ if(!r.ok) alert(r.message||'failed'); poll(); });
}

// ------------------------------------------------------------------ drawer --
function hostBlock(d){
  var h=d.host; if(!h) return '';
  function bar(pct){
    var col=pct>=90?'#d9534f':(pct>=75?'#e0a02c':'#3ba55d');
    return '<span style="display:inline-block;width:90px;height:6px;background:#1a232d;'+
      'border-radius:4px;overflow:hidden;vertical-align:middle"><i style="display:block;height:100%;'+
      'width:'+Math.max(2,Math.min(100,pct||0))+'%;background:'+col+'"></i></span>';
  }
  var out='<div style="margin:14px 0 4px" class="small muted">HOST METRICS (agent)</div>';
  out+='<div class="kv"><span>CPU</span><span>'+bar(h.cpu_pct)+' '+(h.cpu_pct!=null?h.cpu_pct+'%':'—')+'</span></div>';
  out+='<div class="kv"><span>Memory</span><span>'+bar(h.mem_pct)+' '+(h.mem_pct!=null?h.mem_pct+'%':'—')+
       (h.mem_used_mb?' <span class="muted small">('+h.mem_used_mb+' / '+h.mem_total_mb+' MB)</span>':'')+'</span></div>';
  (h.disks||[]).forEach(function(k){
    out+='<div class="kv"><span>Disk '+esc(k.mount)+'</span><span>'+bar(k.used_pct)+' '+k.used_pct+'%'+
      ' <span class="muted small">'+k.free_gb+' GB free</span></span></div>';
  });
  if(h.uptime_hours!=null) out+='<div class="kv"><span>Uptime</span><span>'+Math.round(h.uptime_hours)+' h</span></div>';
  if(h.os) out+='<div class="kv"><span>OS</span><span class="small">'+esc(h.os)+'</span></div>';
  if((h.top||[]).length){
    out+='<div style="margin:10px 0 4px" class="small muted">TOP PROCESSES</div>';
    (h.top||[]).slice(0,4).forEach(function(p){
      out+='<div class="kv"><span class="small">'+esc(p.name)+'</span><span class="small mono">'+
        (p.cpu||0)+'% cpu · '+(p.mem||0)+'% mem</span></div>';
    });
  }
  var stopped=(h.services||[]).filter(function(s){
    return ['stopped','stop_pending'].indexOf((s.state||'').toLowerCase())>=0; });
  if(stopped.length){
    out+='<div style="margin:10px 0 4px" class="small muted">SERVICES NOT RUNNING</div>'+
      stopped.slice(0,5).map(function(s){
        return '<div class="kv"><span class="small">'+esc(s.name)+'</span>'+
          '<span class="badge sev-high">'+esc(s.state)+'</span></div>'; }).join('');
  }
  return out;
}

function openDev(ip){
  var d=(S.data.devices||[]).filter(function(x){return x.ip===ip;})[0]; if(!d) return;
  var ports=(d.ports||[]).map(function(p){return '<span class="port">'+p.port+' '+
    esc(p.service)+'</span>';}).join(' ');
  var acts=(d.remote||[]).map(function(a){
    return '<div class="kv"><span>'+esc(a.label)+(a.ok?'':' <span class="muted small">'+
      esc(a.why||'unavailable')+'</span>')+'</span>'+
      (a.ok?'<button class="sm" onclick="doRemote(\''+esc(ip)+'\',\''+esc(a.id)+'\')">open</button>':'<span></span>')+
      '</div>'; }).join('');
  document.getElementById('drawer-title').textContent=(d.label||d.hostname||d.type_label)+' · '+d.ip;
  document.getElementById('drawer-body').innerHTML=
    '<div class="kv"><span class="muted">Type</span><span><span class="badge t-'+esc(d.type)+'">'+
      esc(d.type_label)+'</span> '+esc(d.confidence||'')+'</span></div>'+
    kv('Status',stDot(d.state)+esc(d.state||'unknown'))+
    kv('Latency',ms(d.latency_ms))+kv('Packet loss',Math.round(d.loss_pct||0)+'%')+
    kv('MAC',esc(d.mac||'&mdash;'))+kv('Vendor',esc(d.vendor||'&mdash;'))+
    kv('Host name',esc(d.hostname||'&mdash;'))+kv('Last seen',esc(d.last_seen||'&mdash;'))+
    (d.snmp_descr?kv('SNMP',esc(d.snmp_descr)):'')+
    '<div style="margin:12px 0 4px" class="small muted">WHY THIS TYPE</div>'+
    '<ul class="ev">'+((d.evidence||[]).map(function(e){return '<li>'+esc(e)+'</li>';}).join('')||'<li>no evidence</li>')+'</ul>'+
    '<div style="margin:12px 0 4px" class="small muted">OPEN PORTS</div><div class="ports">'+(ports||'none')+'</div>'+
    '<div style="margin:14px 0 4px" class="small muted">REMOTE ACCESS</div>'+acts+
    '<div style="margin:14px 0 4px" class="small muted">LATENCY (last polls)</div>'+spark(d.history)+
    hostBlock(d);
  document.getElementById('drawer').classList.add('open');
}
function doRemote(ip,action){
  api('/api/remote',{method:'POST',body:JSON.stringify({ip:ip,action:action})}).then(function(r){
    alert(r.message||(r.ok?'started':'failed'));
  });
}
function openRemote(ip){
  openDev(ip);
}
function openInc(id){
  var i=(S.data.incidents||[]).filter(function(x){return x.id===id;})[0]; if(!i) return;
  var g=i.diagnosis||{};
  document.getElementById('drawer-title').textContent=i.title;
  document.getElementById('drawer-body').innerHTML=
    '<div class="kv"><span class="muted">Severity</span><span><span class="badge sev-'+esc(i.severity)+'">'+
      esc(i.severity)+'</span> '+esc(i.state)+'</span></div>'+
    kv('Device',esc(i.device_name||'')+' <span class="mono muted">'+esc(i.device_ip||'')+'</span>')+
    kv('Opened',esc(i.opened_human||''))+kv('Category',esc(g.category_label||'&mdash;'))+
    kv('Confidence',(g.confidence||0)+'%')+kv('Engine',esc(g.engine||'rules'))+
    '<div style="margin:14px 0 4px" class="small muted">ROOT CAUSE</div>'+
    '<div style="font-size:13px">'+esc(g.root_cause||'n/a')+'</div>'+
    '<div style="margin:14px 0 4px" class="small muted">EVIDENCE</div>'+
    '<ul class="ev">'+((g.evidence||[]).map(function(e){return '<li>'+esc(e)+'</li>';}).join(''))+'</ul>'+
    '<div style="margin:14px 0 4px" class="small muted">DO THIS</div>'+
    '<ol class="acts">'+((g.recommended_actions||[]).map(function(a){return '<li>'+esc(a)+'</li>';}).join(''))+'</ol>'+
    (g.user_impact?'<div style="margin:14px 0 4px" class="small muted">USER IMPACT</div><div style="font-size:13px">'+
      esc(g.user_impact)+'</div>':'')+
    (g.data_gaps&&g.data_gaps.length?'<div style="margin:14px 0 4px" class="small muted">DATA THAT WOULD RAISE '+
      'CONFIDENCE</div><ul class="ev">'+g.data_gaps.map(function(x){return '<li>'+esc(x)+'</li>';}).join('')+'</ul>':'')+
    '<div style="margin:14px 0 4px" class="small muted">TIMELINE</div>'+
    '<ul class="ev">'+((i.timeline||[]).map(function(t){
      return '<li>'+new Date(t.ts*1000).toLocaleString()+' — '+esc(t.text)+'</li>'; }).join(''))+'</ul>'+
    (i.state!=='resolved'&&can('incident')?'<div style="margin-top:16px"><button onclick="closeInc(\''+
      esc(i.id)+'\')">Acknowledge &amp; close</button></div>':'');
  document.getElementById('drawer').classList.add('open');
}
function closeInc(id){
  api('/api/incident/close',{method:'POST',body:JSON.stringify({id:id})}).then(function(){
    document.getElementById('drawer').classList.remove('open'); poll();
  });
}
function closeDrawer(){ document.getElementById('drawer').classList.remove('open'); }

// -------------------------------------------------------------------- shell --
function render(){
  if(!S.data) return;
  nav(); head();
  var v={overview:viewOverview,devices:viewDevices,incidents:viewIncidents,traffic:viewTraffic,
         reports:viewReports,locations:viewLocations,users:viewUsers,events:viewEvents,
         settings:viewSettings}[S.tab]||viewOverview;
  document.getElementById('view').innerHTML=v();
}
function poll(){
  return api('/api/state').then(function(d){ S.data=d; render(); }).catch(function(){});
}
window.addEventListener('hashchange',function(){
  S.tab=(location.hash||'#overview').slice(1); render();
});
document.addEventListener('keydown',function(e){ if(e.key==='Escape') closeDrawer(); });
poll(); setInterval(poll,3000);
"""

LOGIN_CSS = r"""
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
  background:radial-gradient(1100px 520px at 20% -10%,#16242f 0%,#0b0f14 55%)}
.login{width:min(920px,96vw);display:grid;grid-template-columns:1.05fr 1fr;background:var(--panel);
  border:1px solid var(--line);border-radius:14px;overflow:hidden;
  box-shadow:0 30px 80px rgba(0,0,0,.55)}
.login-left{padding:34px 32px;background:linear-gradient(160deg,#12301f 0%,#0d1c16 60%,#0b1418 100%);
  border-right:1px solid var(--line);display:flex;flex-direction:column}
.login-left .lg{display:flex;align-items:center;gap:11px;margin-bottom:26px}
.login-left .lg .logo{width:34px;height:34px;font-size:14px}
.login-left h1{font-size:20px;margin:0 0 6px;font-weight:600;letter-spacing:.2px}
.login-left .tag{color:#9fb4c4;font-size:12.5px;margin:0 0 22px}
.feature{display:flex;gap:11px;margin-bottom:13px;align-items:flex-start}
.feature .fb{width:22px;height:22px;flex:0 0 22px;border-radius:6px;background:rgba(59,165,93,.16);
  color:#7fd6a0;display:flex;align-items:center;justify-content:center;font-size:11px;margin-top:1px}
.feature .ft{font-size:12.5px;color:#c9d6e2;line-height:1.4}
.feature .ft b{color:#e8eef5;font-weight:600}
.login-left .foot{margin-top:auto;padding-top:22px;font-size:11px;color:#7d8f9e;
  border-top:1px solid rgba(255,255,255,.06)}
.login-right{padding:34px 32px;display:flex;flex-direction:column}
.login-right h2{font-size:16px;margin:0 0 4px;font-weight:600}
.login-right .sub{font-size:12.5px;color:var(--muted);margin:0 0 20px}
.login-right .field{margin-bottom:13px}
.login-right input{padding:9px 11px;font-size:13.5px}
.login-right button{width:100%;padding:10px;margin-top:4px;font-size:13.5px}
.hint{font-size:11.5px;color:var(--muted);margin-top:16px;line-height:1.5}
.hint code{background:#111a22;border:1px solid var(--line);border-radius:4px;padding:1px 5px;
  font-family:ui-monospace,Consolas,monospace;font-size:11px}
.err{background:#3a1a1c;border:1px solid #5c2a2c;color:#f0a7a3;padding:9px 12px;border-radius:7px;
  font-size:12.5px;margin-bottom:14px}
.signed{text-align:center;padding:8px 0}
.signed .ok{width:44px;height:44px;border-radius:50%;background:rgba(59,165,93,.16);color:#7fd6a0;
  display:flex;align-items:center;justify-content:center;font-size:20px;margin:0 auto 14px}
.signed a.btn{display:inline-block;margin-top:14px;background:var(--accent2);color:#04121f;
  font-weight:600;border-radius:6px;padding:9px 16px;text-decoration:none}
.spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.35);
  border-top-color:#04121f;border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px;margin-right:7px}
@keyframes sp{to{transform:rotate(360deg)}}
a.sso{display:block;text-align:center;text-decoration:none;background:#1b2b3a;border:1px solid #2d4a68;
  color:#cfe2f5;border-radius:6px;padding:10px;font-size:13.5px;font-weight:600;margin-bottom:14px}
a.sso:hover{border-color:#3d6a94;background:#20313f}
.orsep{display:flex;align-items:center;gap:10px;color:#61707f;font-size:11px;margin:0 0 14px;
  text-transform:uppercase;letter-spacing:.6px}
.orsep:before,.orsep:after{content:"";flex:1;height:1px;background:#243040}
@media(max-width:760px){.login{grid-template-columns:1fr}
  .login-left{border-right:0;border-bottom:1px solid var(--line);padding:24px}
  .login-left .foot{display:none}.login-right{padding:24px}}
"""

LOGIN_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSentinel - sign in</title><style>__CSS____LOGIN_CSS__</style></head><body>
<div class="login-wrap"><div class="login" id="card">
  <div class="login-left">
    <div class="lg"><div class="logo">NS</div>
      <div><div style="font-weight:600;font-size:14px">NetSentinel</div>
      <div style="font-size:11px;color:#8fa6b6">v__VERSION__ network operations console</div></div></div>
    <h1>Your network, watched.</h1>
    <p class="tag">Devices, incidents and internet usage for this site — running on this PC.</p>
    <div class="feature"><div class="fb">&#9673;</div><div class="ft"><b>Finds every device</b><br>
      router, switches, access points, KOT printers, printers, scanners, DVR/NVR and cameras.</div></div>
    <div class="feature"><div class="fb">&#9888;</div><div class="ft"><b>Watches them continuously</b><br>
      latency and packet loss every minute, incidents with a diagnosis and the next steps.</div></div>
    <div class="feature"><div class="fb">&#8599;</div><div class="ft"><b>Shows who is using the internet</b><br>
      per-device download/upload from your router's NetFlow, sFlow or SNMP counters.</div></div>
    <div class="feature"><div class="fb">&#9873;</div><div class="ft"><b>One console for every site</b><br>
      branches report to head office with their own token.</div></div>
    <div class="foot">Runs entirely on your network. No cloud account, no agent on the devices.</div>
  </div>
  <div class="login-right">
    <h2>Sign in to the console</h2>
    <p class="sub">Use the account created for this PC.</p>
    __ERROR__
    __SSO__
    __FORM__
    <div class="hint">First run: the installer prints the admin password once.<br>
      Locked out? On that PC run <code>run.bat --set-password NEWPASSWORD</code>.<br>
      Five wrong attempts lock this PC out for ten minutes.</div>
  </div>
</div></div></body></html>"""


FORM_PASSWORD = """<form method="post" action="/login" id="loginform">
      <div class="field"><label>User name</label>
        <input type="text" name="username" autocomplete="username" autofocus></div>
      <div class="field"><label>Password</label>
        <input type="password" name="password" autocomplete="current-password"></div>
      <button class="primary" type="submit" id="signin">Sign in</button>
    </form>"""

FORM_TOTP = """<form method="post" action="/login" id="loginform">
      <div class="small muted" style="margin-bottom:10px">Signed in as <b>{who}</b> - now the
        six-digit code from your authenticator app.</div>
      <input type="hidden" name="pending" value="{pending}">
      <div class="field"><label>Authenticator code</label>
        <input type="text" name="otp" inputmode="numeric" autocomplete="one-time-code"
               maxlength="12" autofocus style="letter-spacing:3px;font-size:16px"></div>
      <button class="primary" type="submit" id="signin">Verify and sign in</button>
      <div class="hint">Lost your phone? One of your backup codes works here too.</div>
    </form>"""


def login_page(error="", sso=None, pending="", who=""):
    err = f'<div class="err" id="errbox">{error}</div>' if error else '<div id="errbox"></div>'
    block = ""
    if sso and not pending:
        label = sso.get("label") or "Sign in with your company account"
        block = (f'<a class="sso" href="/auth/login">{label}</a>'
                 '<div class="orsep"><span>or use a local account</span></div>')
    form = (FORM_TOTP.format(who=who, pending=pending) if pending else FORM_PASSWORD)
    return (LOGIN_HTML.replace("__CSS__", CSS).replace("__LOGIN_CSS__", LOGIN_CSS)
            .replace("__ERROR__", err).replace("__SSO__", block).replace("__FORM__", form)
            .replace("__VERSION__", "1.17.0"))


def app_page(version):
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetSentinel {version}</title>
<style>{CSS}</style></head>
<body><div class="app">
  <aside class="side">
    <div class="brand"><div class="logo">NS</div><div><div class="t">NetSentinel</div>
      <div class="s">v{version}</div></div></div>
    <nav id="nav"></nav>
    <div class="side-foot">v{version} console<br><span id="foot-src" class="muted">starting&hellip;</span></div>
  </aside>
  <div class="main">
    <div class="top">
      <div><h1 id="h-title">Overview</h1><div class="sub" id="h-sub">&nbsp;</div></div>
      <div class="right" id="h-right"></div>
    </div>
    <div class="content" id="view"></div>
  </div>
</div>
<div class="drawer" id="drawer">
  <div class="hd"><h3 id="drawer-title"></h3><span class="spacer"></span>
    <button class="sm ghost" onclick="closeDrawer()">close</button></div>
  <div class="bd" id="drawer-body"></div>
</div>
<script>{APP_JS}</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "NetSentinel"
    scanner = None
    version = "1.5.0"
    auth_enabled = False
    session_hours = 12
    tls_active = False
    oidc_client = None
    oidc_error = ""

    def log_message(self, fmt, *args):
        pass

    # -- helpers ---------------------------------------------------------
    def _cookie(self):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            if "=" in part:
                name, _, value = part.strip().partition("=")
                if name == "ns_session":
                    return value
        return ""

    def _user(self):
        if not self.auth_enabled:
            return {"user": "local", "role": "admin", "anonymous": True}
        sess = auth.session(self._cookie())
        if not sess:
            return None
        return {"user": sess["user"], "role": sess["role"], "anonymous": False}

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        if getattr(self, "tls_active", False):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                             "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, default=str))

    def _need(self, action, user):
        if auth.can(user.get("role"), action):
            return True
        self._json({"ok": False, "message": f"your role ({user.get('role')}) cannot do this"}, 403)
        return False

    def _client(self):
        cfg = settings.get("access") or {}
        ip = netguard.client_ip(self.client_address[0] if self.client_address else "",
                                self.headers, cfg.get("trusted_proxies"))
        ok, why = netguard.allowed(ip, cfg.get("allow_cidrs"), cfg.get("deny_cidrs"))
        return ip, ok, why

    def _gate(self):
        """Block requests from addresses outside the allow-list."""
        self.client_ip, ok, why = self._client()
        if ok:
            return True
        try:
            store.add_event("access", "high", f"blocked {self.client_ip} {self.path} ({why})")
        except Exception:
            pass
        self._send(403, "This console is not available from your address.",
                   "text/plain; charset=utf-8")
        return False

    def _guard(self):
        """Return the user dict, or send 401 and return None."""
        user = self._user()
        if user is None:
            self._json({"error": "sign in required"}, 401)
            return None
        return user

    # -- GET -------------------------------------------------------------
    def do_GET(self):
        if not self._gate():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            if self.auth_enabled and not auth.session(self._cookie()):
                return self._send(302, b"", "text/plain", {"Location": "/login"})
            return self._send(200, app_page(self.version), "text/html; charset=utf-8")
        if path == "/login":
            sso = None
            if self.oidc_client is not None:
                sso = {"label": (settings.get("oidc") or {}).get("button_label")}
            return self._send(200, login_page("", sso), "text/html; charset=utf-8")
        if path == "/auth/login":
            if self.oidc_client is None:
                return self._send(503, "SSO is not configured on this console", "text/plain")
            try:
                url, _state = self.oidc_client.start()
            except Exception as exc:
                return self._send(502, f"identity provider unreachable: {exc}", "text/plain")
            return self._send(302, b"", "text/plain", {"Location": url})
        if path == "/auth/callback":
            if self.oidc_client is None:
                return self._send(503, "SSO is not configured", "text/plain")
            query = parse_qs(parsed.query)
            if (query.get("error") or [""])[0]:
                msg = (query.get("error_description") or query.get("error") or ["failed"])[0]
                return self._send(401, login_page(f"Sign-in refused: {msg}",
                                                  {"label": "Try again"}), "text/html; charset=utf-8")
            code = (query.get("code") or [""])[0]
            state = (query.get("state") or [""])[0]
            try:
                claims = self.oidc_client.finish(code, state)
                email = self.oidc_client.identity(claims)
                role = self.oidc_client.role_for(claims)
            except Exception as exc:
                store.add_event("auth", "high", f"SSO sign-in failed: {exc}")
                return self._send(401, login_page(f"Sign-in failed: {exc}"),
                                  "text/html; charset=utf-8")
            token = auth.login_sso(email, role, self.session_hours,
                                   provider=self.oidc_client.issuer)
            store.add_event("auth", "info", f"SSO sign-in: {email} as {role}")
            cookie = (f"ns_session={token}; Path=/; HttpOnly; SameSite=Strict"
                      + ("; Secure" if self.tls_active else ""))
            return self._send(302, b"", "text/plain", {"Location": "/", "Set-Cookie": cookie})
        if path == "/logout":
            auth.logout(self._cookie())
            return self._send(302, b"", "text/plain",
                              {"Location": "/login" if self.auth_enabled else "/",
                               "Set-Cookie": "ns_session=; Path=/; Max-Age=0"})
        if path.startswith("/api/v1/"):
            token = ""
            authz = self.headers.get("Authorization") or ""
            if authz.lower().startswith("bearer "):
                token = authz[7:].strip()
            token = token or (self.headers.get("X-API-Token") or "")
            need = "write" if self.command == "POST" else "read"
            rec = apitokens.check(token, need)
            if not rec:
                return self._json({"error": "invalid or insufficient API token"}, 401)
            return self._api_v1(path, parsed, rec)

        if path == "/api/state":
            user = self._guard()
            if user is None:
                return
            data = self.scanner.snapshot()
            data["version"] = self.version
            data["settings"] = _mask_branch(data.get("settings") or {})
            upd = getattr(self.scanner, "updater", None)
            data["update"] = upd.snapshot() if upd else None
            role = user.get("role") or "viewer"
            data["auth"] = {
                "enabled": self.auth_enabled, "user": user["user"], "role": role,
                "role_label": auth.role_label(role),
                "permissions": sorted(auth.ROLE_ACTIONS.get(role, {"read"})),
                "anonymous": user.get("anonymous", False),
            }
            return self._json(data)
        if path == "/api/history":
            if self._guard() is None:
                return
            ip = (parse_qs(parsed.query).get("ip") or [""])[0]
            return self._json({"ip": ip, "samples": store.history(ip, 180)})
        if path == "/api/reports":
            if self._guard() is None:
                return
            query = parse_qs(parsed.query)
            try:
                hours = int((query.get("hours") or ["24"])[0])
                days = int((query.get("days") or ["7"])[0])
            except ValueError:
                hours, days = 24, 7
            return self._json(self.scanner.reports(max(1, min(hours, 720)), max(1, min(days, 90))))
        if path == "/api/reports.csv":
            if self._guard() is None:
                return
            query = parse_qs(parsed.query)
            try:
                hours = int((query.get("hours") or ["24"])[0])
            except ValueError:
                hours = 24
            return self._send(200, _reports_csv(self.scanner.reports(hours)),
                              "text/csv; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="netsentinel-availability.csv"'})
        if path == "/api/export.csv":
            if self._guard() is None:
                return
            return self._send(200, _csv(self.scanner),
                              "text/csv; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="netsentinel-devices.csv"'})
        if path == "/api/report.txt":
            if self._guard() is None:
                return
            from .report import text_report
            return self._send(200, text_report(self.scanner.snapshot()), "text/plain; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="netsentinel-report.txt"'})
        if path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")
        return self._json({"error": "not found"}, 404)

    def _api_v1(self, path, parsed, rec):
        """Small, stable REST surface for automation."""
        scanner = self.scanner
        if path in ("/api/v1/state", "/api/v1/"):
            snap = scanner.snapshot()
            snap.pop("settings", None)
            snap["version"] = self.version
            return self._json(snap)
        if path == "/api/v1/devices":
            snap = scanner.snapshot()
            return self._json({"count": len(snap["devices"]), "devices": [
                {k: d.get(k) for k in ("ip", "mac", "vendor", "hostname", "label", "type",
                                       "type_label", "state", "latency_ms", "loss_pct",
                                       "ports", "is_gateway")} for d in snap["devices"]]})
        if path == "/api/v1/incidents":
            snap = scanner.snapshot()
            query = parse_qs(parsed.query)
            state = (query.get("state") or ["all"])[0]
            items = snap["incidents"]
            if state == "open":
                items = [i for i in items if i.get("state") != "resolved"]
            return self._json({"count": len(items), "incidents": items})
        if path == "/api/v1/reports":
            query = parse_qs(parsed.query)
            try:
                hours = int((query.get("hours") or ["24"])[0])
            except ValueError:
                hours = 24
            return self._json(scanner.reports(max(1, min(hours, 720)), 7))
        if path == "/api/v1/sites":
            from . import sites as sites_mod
            return self._json(sites_mod.hub_overview())
        if path == "/api/v1/traffic":
            return self._json(scanner.traffic_view())
        if path == "/api/v1/hosts":
            return self._json({"count": len(scanner.snapshot()["hosts"]),
                               "hosts": scanner.snapshot()["hosts"]})
        if path == "/api/v1/health":
            return self._json({"health": scanner.snapshot()["health"],
                               "version": self.version,
                               "polling": bool(scanner.poller)})
        return self._json({"error": "not found"}, 404)

    # -- POST ------------------------------------------------------------
    def do_POST(self):
        if not self._gate():
            return
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            payload = {}

        if path == "/login":
            form = parse_qs(raw.decode("utf-8", "replace"))
            username = (form.get("username") or [""])[0].strip()
            password = (form.get("password") or [""])[0]
            otp = (form.get("otp") or [""])[0].strip()
            pending = (form.get("pending") or [""])[0].strip()

            # ---- second step: the six-digit code for a password already accepted
            if pending:
                who = auth.second_factor_user(pending)
                if not who:
                    return self._send(401, login_page("That sign-in attempt expired - start again."),
                                      "text/html; charset=utf-8")
                rec = store.user_record(who) or {}
                ok = False
                if rec.get("totp_enabled") and totp.verify(rec.get("totp_secret"), otp):
                    ok = True
                elif rec.get("backup_codes"):
                    used, remaining = totp.use_backup(rec.get("backup_codes"), otp)
                    if used:
                        store.set_backup_codes(who, remaining)
                        ok = True
                        store.add_event("auth", "medium",
                                        f"backup code used for {who} ({len(remaining)} left)")
                if not ok:
                    auth.note_failure(self.client_ip)
                    return self._send(401, login_page("Wrong code - try again.",
                                                      None, pending=pending),
                                      "text/html; charset=utf-8")
                auth.finish_second_factor(pending)
                auth.clear_failures(self.client_ip)
                role = rec.get("role") or "viewer"
                token = auth.login_sso(who, role, self.session_hours, provider="local+totp")
                store.add_event("auth", "info", f"sign-in with 2FA: {who} as {role}")
                return self._send(302, b"", "text/plain",
                                  {"Location": "/", "Set-Cookie":
                                   f"ns_session={token}; Path=/; HttpOnly; SameSite=Strict"
                                   + ("; Secure" if self.tls_active else "")})

            # ---- first step: user name and password
            user = store.check_user(username, password)
            if not user:
                auth.note_failure(self.client_ip)
                wait = auth.locked(self.client_ip)
                msg = ("Too many failed attempts. Try again in %d minutes." % (wait // 60 + 1)
                       if wait else "Wrong user name or password.")
                return self._send(401, login_page(msg), "text/html; charset=utf-8")

            rec = store.user_record(username) or {}
            need_totp = bool(rec.get("totp_enabled"))
            if need_totp or (settings.get("auth_extra") or {}).get("require_totp_for_local") \
                    and not (settings.get("oidc") or {}).get("enabled"):
                if not need_totp:
                    return self._send(403, login_page(
                        "This console requires two-factor authentication. Ask an administrator to "
                        "enrol your account, or sign in with SSO."), "text/html; charset=utf-8")
                pending_token = auth.start_second_factor(username)
                return self._send(200, login_page("", None, pending=pending_token, who=username),
                                  "text/html; charset=utf-8")

            auth.clear_failures(self.client_ip)
            token = auth.login_sso(username, user["role"], self.session_hours, provider="local")
            store.add_event("auth", "info", f"sign-in: {username} as {user['role']}")
            return self._send(302, b"", "text/plain",
                              {"Location": "/", "Set-Cookie":
                               f"ns_session={token}; Path=/; HttpOnly; SameSite=Strict"
                               + ("; Secure" if self.tls_active else "")})
        if path == "/api/login":
            token, err = auth.login(self.client_ip, payload.get("username", ""),
                                    payload.get("password", ""), self.session_hours)
            if not token:
                return self._json({"ok": False, "message": err}, 401)
            return self._send(200, json.dumps({"ok": True}), extra={
                "Set-Cookie": f"ns_session={token}; Path=/; HttpOnly; SameSite=Strict"
                              + ("; Secure" if self.tls_active else "")})
        if path.startswith("/api/v1/"):
            token = ""
            authz = self.headers.get("Authorization") or ""
            if authz.lower().startswith("bearer "):
                token = authz[7:].strip()
            token = token or (self.headers.get("X-API-Token") or "")
            rec = apitokens.check(token, "write")
            if not rec:
                return self._json({"error": "a write-scoped API token is required"}, 401)
            if path == "/api/v1/agent/report":
                result = self.scanner.ingest_agent(payload)
                return self._json(result)
            parts = path.strip("/").split("/")          # api, v1, incidents, <id>, close
            if len(parts) == 5 and parts[2] == "incidents" and parts[4] == "close":
                ok = self.scanner.dismiss_incident(parts[3])
                self.scanner.audit(f"api:{rec['name']}",
                                   "incident closed" if ok else "incident close failed", parts[3])
                return self._json({"ok": ok, "message": "" if ok else "no such open incident"},
                                  200 if ok else 404)
            return self._json({"error": "not found"}, 404)

        if path == "/api/branch/report":
            token = self.headers.get("X-Branch-Token") or ""
            result, code = self.scanner.accept_branch_report(payload, token)
            return self._json(result, code)
        if path == "/api/logout":
            auth.logout(self._cookie())
            return self._json({"ok": True})

        # every other POST is a state change: require the CSRF header and a session
        if self.headers.get("X-NS") != "1":
            return self._json({"ok": False, "message": "missing X-NS header (CSRF guard)"}, 400)
        user = self._guard()
        if user is None:
            return

        who = user.get("user", "?")

        if path == "/api/scan":
            if not self._need("scan", user):
                return
            self.scanner.audit(who, "rescan")
            return self._json({"started": self.scanner.start_scan()})
        if path == "/api/label":
            if not self._need("label", user):
                return
            ok = self.scanner.set_label(payload.get("mac", ""), payload.get("label", ""))
            self.scanner.audit(who, "label", f"{payload.get('mac','')} = {payload.get('label','')}")
            return self._json({"ok": ok})
        if path == "/api/remote":
            if not self._need("remote", user):
                return
            client = getattr(self, "client_ip", "") or ""
            is_local = client in ("127.0.0.1", "::1", "localhost")
            result = self.scanner.launch_remote(payload.get("ip", ""), payload.get("action", ""), is_local)
            self.scanner.audit(who, "remote " + str(payload.get("action", "")),
                               f"{payload.get('ip','')} -> {result.get('message','')[:60]}")
            return self._json(result)
        if path == "/api/settings":
            if not self._need("settings", user):
                return
            self.scanner.update_settings(payload)
            self.scanner.audit(who, "settings changed",
                               ", ".join(sorted(payload.keys()))[:120])
            return self._json({"ok": True})
        if path in ("/api/update/check", "/api/update/install"):
            if not self._need("settings", user):
                return
            upd = getattr(self.scanner, "updater", None)
            if upd is None:
                return self._json({"ok": False, "message": "updates are not running in this mode"})
            install = path.endswith("install")
            if install and upd.mode == "notify":
                return self._json({"ok": False, "message": "this copy can't install updates itself"})
            self.scanner.audit(who, "update " + ("install" if install else "check"))
            upd.check_now(install=install)
            return self._json({"ok": True, "message": "installing - the console restarts in a minute"
                               if install else "checking ..."})
        if path == "/api/heartbeat/test":
            if not self._need("settings", user):
                return
            from . import heartbeat as hb_mod
            hb = hb_mod.Heartbeat()
            ok = hb.ping()
            return self._json({"ok": ok,
                               "message": hb.state.get("last_error") or hb.state.get("url") or "sent"})
        if path == "/api/alert/test":
            if not self._need("alerts", user):
                return
            from . import alerts
            self.scanner.audit(who, "test alert")
            return self._json(alerts.test_channels(settings.load()))
        if path == "/api/incident/close":
            if not self._need("incident", user):
                return
            ok = self.scanner.dismiss_incident(payload.get("id", ""))
            self.scanner.audit(who, "incident closed", str(payload.get("id", "")))
            return self._json({"ok": ok})
        if path == "/api/users":
            if not self._need("users", user):
                return
            name = (payload.get("username") or "").strip()
            password = payload.get("password") or ""
            role = (payload.get("role") or "engineer").lower()
            if role not in auth.ROLE_ACTIONS:
                return self._json({"ok": False, "message": "role must be viewer, engineer or admin"})
            if len(name) < 2 or len(password) < 6:
                return self._json({"ok": False, "message": "user name (2+) and password (6+) required"})
            ok = store.create_user(name, password, role)
            store.add_event("auth", "info", f"user {name} created as {role} by {who}")
            return self._json({"ok": ok})
        if path == "/api/hub/site":
            if not self._need("settings", user):
                return
            name = (payload.get("name") or "").strip()[:64]
            if len(name) < 2:
                return self._json({"ok": False, "message": "branch name required"})
            from . import sites as sites_mod
            token = sites_mod.new_token()
            cfg = settings.load()
            hub = dict(cfg.get("hub") or {})
            rows = [x for x in (hub.get("sites") or []) if x.get("name") != name]
            rows.append({"name": name, "token_hash": sites_mod.token_hash(token),
                         "created_ts": int(time.time())})
            hub["sites"] = rows
            settings.save({"hub": hub})
            self.scanner.audit(who, "branch token created", name)
            return self._json({"ok": True, "token": token, "name": name})
        if path == "/api/hub/site/delete":
            if not self._need("settings", user):
                return
            name = (payload.get("name") or "").strip()
            cfg = settings.load()
            hub = dict(cfg.get("hub") or {})
            hub["sites"] = [x for x in (hub.get("sites") or []) if x.get("name") != name]
            settings.save({"hub": hub})
            store.delete_branch(name)
            self.scanner.audit(who, "branch removed", name)
            return self._json({"ok": True})
        if path == "/api/branch/test":
            if not self._need("settings", user):
                return
            if not self.scanner.branch_reporter:
                from . import sites as sites_mod
                self.scanner.branch_reporter = sites_mod.BranchReporter(self.scanner,
                                                                        log=self.scanner.log)
            ok = self.scanner.branch_reporter.push()
            return self._json({"ok": ok, "message": self.scanner.branch_reporter.last_error or "ok"})
        if path == "/api/users/totp":
            if not self._need("users", user):
                return
            name = (payload.get("username") or "").strip().lower()
            rec = store.user_record(name)
            if not rec:
                return self._json({"ok": False, "message": "no such user"})
            secret = totp.new_secret()
            plain, hashed = totp.new_backup_codes()
            store.set_totp(name, secret, enabled=False, backup_hashes=hashed)
            self.scanner.audit(who, "2FA enrolment started", name)
            return self._json({"ok": True, "secret": secret, "backup_codes": plain,
                               "uri": totp.provisioning_uri(secret, name)})
        if path == "/api/users/totp/verify":
            if not self._need("users", user):
                return
            name = (payload.get("username") or "").strip().lower()
            rec = store.user_record(name) or {}
            if not rec.get("totp_secret"):
                return self._json({"ok": False, "message": "start the enrolment first"})
            if not totp.verify(rec["totp_secret"], payload.get("code", "")):
                return self._json({"ok": False, "message": "that code did not match - check the "
                                                          "clock on your phone and try again"})
            store.set_totp(name, rec["totp_secret"], enabled=True)
            store.add_event("auth", "info", f"2FA enabled for {name} by {who}")
            self.scanner.audit(who, "2FA enabled", name)
            return self._json({"ok": True})
        if path == "/api/users/totp/disable":
            if not self._need("users", user):
                return
            name = (payload.get("username") or "").strip().lower()
            store.set_totp(name, "", enabled=False, backup_hashes=[])
            store.add_event("auth", "medium", f"2FA disabled for {name} by {who}")
            self.scanner.audit(who, "2FA disabled", name)
            return self._json({"ok": True})
        if path == "/api/users/password":
            if not self._need("users", user):
                return
            name = (payload.get("username") or "").strip()
            password = payload.get("password") or ""
            if not name or len(password) < 6:
                return self._json({"ok": False, "message": "user name and a 6+ character password are required"})
            ok = store.set_password(name, password)
            store.add_event("auth", "info", f"password changed for {name} by {who}")
            return self._json({"ok": ok})
        if path == "/api/users/delete":
            if not self._need("users", user):
                return
            name = (payload.get("username") or "").strip()
            if not name or name.lower() == "admin":
                return self._json({"ok": False, "message": "the admin account cannot be removed"})
            ok = store.delete_user(name)
            store.add_event("auth", "info", f"user {name} removed by {who}")
            return self._json({"ok": ok})
        return self._json({"error": "not found"}, 404)


def _csv(scanner):
    snap = scanner.snapshot()
    cols = ["ip", "mac", "vendor", "hostname", "label", "type", "type_label", "confidence",
            "state", "latency_ms", "loss_pct", "ports", "title", "server", "snmp_descr",
            "rx_bps", "tx_bps"]
    lines = [",".join(cols)]
    for dev in snap["devices"]:
        row = []
        for col in cols:
            value = dev.get(col, "")
            if col == "ports":
                value = " ".join(str(p["port"]) for p in dev.get("ports", []))
            row.append('"' + str(value).replace('"', "'").replace("\n", " ") + '"')
        lines.append(",".join(row))
    return "\n".join(lines) + "\n"


def _mask_branch(view):
    branch = view.get("branch") or {}
    if branch.get("token"):
        branch["token"] = ""
        branch["token_set"] = True
    else:
        branch["token_set"] = False
    hub = view.get("hub") or {}
    hub["sites"] = [{k: v for k, v in x.items() if k != "token_hash"}
                    for x in (hub.get("sites") or [])]
    view["hub"] = hub
    view["branch"] = branch
    return view


def _reports_csv(report):
    rows = ["device,ip,type,availability_pct,samples,down_samples,degraded_samples,avg_latency_ms,worst_loss_pct"]
    for d in report.get("devices", []):
        rows.append(",".join([
            '"' + str(d.get("name", "")).replace('"', "'") + '"',
            d.get("ip", ""), '"' + str(d.get("type_label", "")).replace('"', "'") + '"',
            str(d.get("availability_pct", "")), str(d.get("samples", "")),
            str(d.get("down_samples", "")), str(d.get("degraded_samples", "")),
            str(d.get("avg_latency_ms", "")), str(d.get("worst_loss_pct", "")),
        ]))
    return "\n".join(rows) + "\n"


def _app_window_cmd(url):
    if os.name != "nt":
        return None
    for exe in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"):
        if os.path.exists(exe):
            return [exe, f"--app={url}", "--window-size=1500,950"]
    return None


def open_dashboard(url, app_mode=True):
    if app_mode:
        cmd = _app_window_cmd(url)
        if cmd:
            try:
                subprocess.Popen(cmd, creationflags=0x08000000 if os.name == "nt" else 0)
                return "app"
            except Exception:
                pass
    try:
        import webbrowser
        if webbrowser.open(url):
            return "browser"
    except Exception:
        pass
    return "none"


def lan_urls(port, host="127.0.0.1"):
    from . import netinfo
    urls = {"local": f"http://127.0.0.1:{port}/", "lan": "", "bind": host}
    try:
        ip = netinfo.primary_ipv4()
        if ip and not ip.startswith("127."):
            urls["lan"] = f"http://{ip}:{port}/"
    except Exception:
        pass
    return urls


def serve(scanner, host="127.0.0.1", port=8777, version="1.17.0", open_browser=True,
          app_mode=True, auth_enabled=False, session_hours=12, tls=None):
    client = None
    client_error = ""
    oidc_cfg = settings.get("oidc") or {}
    if oidc_cfg.get("enabled"):
        candidate = oidc_mod.OIDCClient(oidc_cfg)
        ok, why = candidate.ready()
        if ok:
            try:
                candidate.metadata()          # fail early if the provider is unreachable
                client = candidate
            except Exception as exc:
                client_error = str(exc)[:200]
        else:
            client_error = why
    handler = type("BoundHandler", (Handler,), {
        "scanner": scanner, "version": version,
        "auth_enabled": auth_enabled, "session_hours": session_hours,
        "tls_active": bool(tls), "oidc_client": client, "oidc_error": client_error,
    })
    serve.oidc_error = client_error
    httpd = None
    last_error = None
    for candidate in range(port, port + 12):
        try:
            httpd = ThreadingHTTPServer((host, candidate), handler)
            port = candidate
            break
        except OSError as exc:
            last_error = exc
            continue
    if httpd is None:
        raise RuntimeError(f"could not bind a local port: {last_error}")

    scheme = "https" if tls else "http"
    if tls:
        try:
            ctx = tlsutil.context(tls.get("cert"), tls.get("key"))
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        except Exception as exc:
            try:
                httpd.server_close()
            except Exception:
                pass
            raise RuntimeError(f"TLS could not start: {exc}")
    httpd.tls_active = bool(tls)
    url = f"{scheme}://127.0.0.1:{port}/"
    httpd.dashboard_port = port
    if open_browser:
        def _open():
            time.sleep(1.4)
            open_dashboard(url, app_mode)
        threading.Thread(target=_open, daemon=True).start()
    return httpd, url
