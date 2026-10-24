/* SecureFlow shared helpers + demo data (loaded by both pages).
 * Privacy: source code lives only in this tab's memory (the `state` object below and the scan worker).
 * Nothing is written to localStorage / sessionStorage / IndexedDB / cookies, and no network request carries code. */
(function(){
'use strict';
var SF = window.SF = {};
var E = window.SFEngine;
function $(id){ return document.getElementById(id); }
function clamp(v,a,b){ a=a===undefined?0:a; b=b===undefined?1:b; return Math.max(a,Math.min(b,v)); }
function ease(t){ return t<.5 ? 4*t*t*t : 1-Math.pow(-2*t+2,3)/2; }
function smooth(a,b,x){ var t=clamp((x-a)/(b-a)); return t*t*(3-2*t); }
function esc(s){ return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
function txt(id){ return String((window.SF_DEMO||{})[id]||'').replace(/^\s*\n/,'').replace(/\s+$/,''); }
var RM=matchMedia('(prefers-reduced-motion: reduce)').matches;
SF.clamp=clamp; SF.ease=ease; SF.smooth=smooth; SF.mask=E.mask;
SF.u={ $:$, clamp:clamp, ease:ease, smooth:smooth, esc:esc, E:E, RM:RM };

/* ============================== STORY (demo data) ============================== */
SF.layers=[
  {key:'client', name:'Client', file:'src/client/app.js', desc:'What runs in every visitor’s browser. Anything here is public.', vuln:txt('v-client'), fixed:txt('f-client')},
  {key:'api',    name:'API',    file:'api/orders/route.js', desc:'The server routes. Where user input meets your business logic.', vuln:txt('v-api'), fixed:txt('f-api')},
  {key:'data',   name:'Data',   file:'lib/db.js', desc:'Database access, passwords and sessions. The layer attackers want.', vuln:txt('v-data'), fixed:txt('f-data')}
];
SF.layers.forEach(function(L){ L.vf=E.scanProject([{name:L.file,code:L.vuln}]).findings; L.ff=E.scanProject([{name:L.file,code:L.fixed}]).findings; });
SF.demoVuln=function(){ return SF.layers.map(function(L){ return {name:L.file, code:L.vuln}; }); };
SF.demoFixed=function(){ return SF.layers.map(function(L){ return {name:L.file, code:L.fixed}; }); };
function snapOf(files){ var r=E.scanProject(files), m={}; files.forEach(function(f){ m[f.name]=f.code; }); return {findings:r.findings, files:m}; }
var demoA=snapOf(SF.demoVuln()), demoB=snapOf(SF.demoFixed()), demoCmp=E.compareScans(demoA,demoB);
var allV=demoA.findings;
SF.before=E.score(demoA.findings); SF.after=E.score(demoB.findings); SF.demoCmp=demoCmp; SF.allV=allV;

var WIN=[[.16,.39],[.39,.635],[.635,.88]];
SF.evidence=function(p){
  var active = p<WIN[0][0]?-1 : p<WIN[0][1]?0 : p<WIN[1][1]?1 : p<WIN[2][1]?2 : 3;
  return { explode:smooth(0,.14,p), active:active, reveal:WIN.map(function(w){ return clamp((p-w[0]-.04)/(w[1]-w[0]-.09)); }) };
};
SF.verifyState=function(p){ return { explode:1-smooth(0,.24,p), fixed:p>.36, reveal:clamp((p-.38)/.32) }; };

SF.makeGauge=function(svg){
  var NS='http://www.w3.org/2000/svg',cx=160,cy=160;
  function pt(d,r){ var a=d*Math.PI/180; return [cx+r*Math.sin(a), cy-r*Math.cos(a)]; }
  function el(t,at){ var e=document.createElementNS(NS,t); for (var k in at) e.setAttribute(k,at[k]); svg.appendChild(e); return e; }
  for (var v=0;v<=100;v+=2){ var d=-135+v*2.7, mj=v%10===0, p1=pt(d,mj?112:118), p2=pt(d,128);
    el('line',{x1:p1[0],y1:p1[1],x2:p2[0],y2:p2[1],'class':'tick'+(mj?' major':'')+(v>=70?' hot':'')});
    if (mj){ var lp=pt(d,96), t=el('text',{x:lp[0],y:lp[1],'class':'lbl'}); t.textContent=v; } }
  var s=pt(-135,142), e=pt(135,142), arc='M'+s[0]+' '+s[1]+' A142 142 0 1 1 '+e[0]+' '+e[1];
  el('path',{d:arc,'class':'track'});
  var val=el('path',{d:arc,'class':'val',pathLength:100,'stroke-dasharray':'0 100'});
  var nd=el('line',{x1:cx,y1:cy+16,x2:cx,y2:cy-118,'class':'needle'});
  el('circle',{cx:cx,cy:cy,r:7,'class':'hub'});
  var num=el('text',{x:cx,y:cy+70,'class':'num'}); num.textContent='0';
  var unit=el('text',{x:cx,y:cy+92,'class':'unit'}); unit.textContent='RISK / 100';
  var cur=-1;
  return { set:function(v,label){ v=clamp(v,0,100); if (label) unit.textContent=label; if (Math.abs(v-cur)<.05) return; cur=v;
      nd.setAttribute('transform','rotate('+(-135+v*2.7)+' '+cx+' '+cy+')'); val.setAttribute('stroke-dasharray',v+' 100');
      val.style.stroke=v>=70?'#d4513f':v>=35?'#d98a3e':'#9bb08f'; num.textContent=Math.round(v); },
    text:function(t){ num.textContent=t; cur=-1; } };
};

})();
