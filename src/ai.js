/* SecureFlow AI layer for the workspace page: AI deep check (Gemini via the SecureFlow Worker), seriousness scores,
 * risk-chain visuals, fix guidance verified over 10 rounds, Ask SecureFlow, and Codebase memory (Cloudflare D1).
 * Everything here is opt-in and session-only: consent lives in memory, nothing is written to browser storage. */
(function(){
'use strict';
var SF=window.SF, U=SF.u, $=U.$, esc=U.esc, E=U.E, W=SF.ws, H=SF.hooks;
var SEVS=['critical','high','medium','low','info'], ROUNDS=10;
var srv={ checked:false, ai:false, memory:false, models:[] }, on={ ai:false, mem:false };
var aiState={}, busy={ ai:false, mem:false }, aiAbort=null;
var mem={ phase:'idle', error:null, match:null, data:null, salt:null, id:null, report:null, savedAt:null, created:false };
var ANALYSIS_STAGES=['Validate project inventory','Complete deterministic local scan','Mask secrets in source','Build contextual model input','Gemini contextual review','Parse and validate model response','Independent reviewer challenge','Validate quoted evidence and file references','Deduplicate and merge findings','Build combined analysis report'];

/* ---------------- server ---------------- */
function serverMode(){ return /^https?:$/.test(location.protocol) && !/claude\.ai|claudeusercontent/.test(location.hostname); }
function api(path, body){
  return fetch(path,{ method:'POST', headers:{'content-type':'application/json'}, credentials:'same-origin', body:JSON.stringify(Object.assign({consent:true},body)) })
    .then(function(r){ return r.json().catch(function(){ return {}; }).then(function(j){ if (!r.ok){ var e=new Error(j.error||('http_'+r.status)); e.code=j.error||('http_'+r.status); e.extra=j; throw e; } return j; }); });
}
var ERR={ ai_unavailable:'Gemini is busy or unavailable right now (Google returned an error for every model). Your engine results are unaffected; try again in a minute.',
  ai_not_configured:'The server has no Gemini API key configured.', rate_limited:'Hourly AI limit reached for your network. Try again later.', too_large:'The project is too large for one AI request.',
  gemini_auth_failed:'Gemini rejected the configured API credentials. Check the key and enabled API in Google AI Studio.', gemini_invalid_shape:'Gemini returned JSON in an unexpected format. Local findings are preserved.', gemini_invalid_diagnostic_response:'Gemini replied, but the diagnostic response did not match the expected shape.',
  memory_not_configured:'The server has no database configured.', not_found:'That record no longer exists or does not match this code.', network:'The SecureFlow server could not be reached.' };
function errText(e){ var c=(e&&e.code)||'network'; if(ERR[c])return ERR[c]; var d=e&&e.detail; if(d===401||d===403||d==='http_401'||d==='http_403')return 'Gemini rejected the API key or project access (HTTP '+String(d).replace('http_','')+'). Check the key and API access.'; if(d==='busy_429')return 'Gemini quota or rate limit reached (HTTP 429). Wait for the provider limit to reset.';if(d&&/^busy_5/.test(d))return 'Gemini is temporarily unavailable ('+d.slice(5)+'). Try again later.';if(d==='timeout')return 'Gemini request timed out. Check connectivity and try again.';if(d==='network')return 'The server could not reach Gemini. Check outbound network access.';if(d==='bad_json')return 'Gemini returned malformed JSON. Try again or check the selected model.';return 'Request failed ('+c+').'; }
function diagnosticButton(enabled){ var host=document.querySelector('.conn'); if(!host)return; var old=$('ai-diagnostic'); if(!enabled){if(old)old.remove();return;} if(old)return; var b=document.createElement('button');b.type='button';b.className='tog';b.id='ai-diagnostic';b.textContent='Test Gemini connection';b.title='Development-only, authenticated harmless diagnostic request';host.appendChild(b);b.addEventListener('click',runDiagnostic); }
function health(){
  var tA=$('ai-toggle'), tM=$('mem-toggle');
  if (!serverMode()){ srv.checked=true; [tA,tM].forEach(function(t){ t.title='Needs the SecureFlow server (Cloudflare deployment or npm run dev). This copy runs the local engine only.'; }); return; }
  fetch('/api/health',{credentials:'same-origin'}).then(function(r){ return r.ok?r.json():{}; }).catch(function(){ return {}; }).then(function(j){
    srv.checked=true; srv.ai=!!j.ai; srv.memory=!!j.memory; srv.models=j.models||[];srv.diagnostic=!!j.diagnosticEnabled;diagnosticButton(srv.diagnostic);
    tA.disabled=!srv.ai; tA.title=srv.ai?'Opt-in: masked code is reviewed by Google Gemini through the SecureFlow server':'The server has no Gemini key configured';
    tM.disabled=!srv.memory; tM.title=srv.memory?'Opt-in: remember this codebase by line fingerprints (never code)':'The server has no database configured';
    W.renderAll();
  });
}
function runDiagnostic(){
  var token=localStorage.getItem('sf_id_token');if(!token){bar('Diagnostic requires a signed-in, verified account. Sign in, then retry.','bad');return;}
  var started=performance.now();bar('<b>Gemini diagnostic:</b> request started. Waiting for the authenticated Worker response…','run');
  fetch('/api/ai/diagnostic',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token},body:'{}',credentials:'same-origin'}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){if(!r.ok){var e=new Error(j.error||'diagnostic_failed');e.code=j.error;e.status=r.status;e.detail=j.detail;throw e;}return j;});}).then(function(r){bar('<b>Gemini diagnostic succeeded.</b> Real provider response validated · HTTP '+r.status+' · '+r.durationMs+' ms · <span class="fine mono">'+esc(r.model)+'</span>. No prompt or credential is shown.','ok');}).catch(function(e){var reason=errText(e),status=e.status?' HTTP '+e.status:'';bar('<b>Gemini diagnostic failed.</b>'+esc(status+' '+reason)+' Request started · '+Math.round(performance.now()-started)+' ms elapsed. Check Worker configuration and server logs; credentials are never displayed.','bad');});
}

/* ---------------- consent ---------------- */
function totalKB(){ return Math.round(W.state.files.reduce(function(a,f){ return a+f.code.length; },0)/1024); }
function consent(kind){
  var d=$('consent-dlg'), ai=kind==='ai';
  $('cs-title').textContent=ai?'Turn on AI deep check?':'Turn on Codebase memory?';
  $('cs-body').innerHTML= ai ?
    '<ul class="cs-list"><li><b>What is sent:</b> the code of this project ('+W.state.files.length+' file'+(W.state.files.length===1?'':'s')+', about '+totalKB()+' KB) with secrets masked in your browser and masked again on the server. Fix guidance and questions send only the affected file or a window around the issue.</li>'+
    '<li><b>Where it goes:</b> the SecureFlow server on Cloudflare, which forwards it to the Google Gemini API for that request. SecureFlow does not store it. Google’s API terms apply; on Google’s free tier, Google may use inputs to improve its products.</li>'+
    '<li><b>What you get:</b> a second, deeper review challenged by a second AI pass. Every AI finding must quote a real line of your code, or it is dropped.</li>'+
    '<li>You can switch it off at any time. It stays off after a reload.</li></ul><label class="chk"><input type="checkbox" id="cs-own"> I am allowed to share this code with an AI service.</label>'
  : '<ul class="cs-list"><li><b>What is stored:</b> an 8-character fingerprint of each line (salted per project), file paths, and for each finding its title, severity, score, location and short fix directions. <b>No source code.</b></li>'+
    '<li><b>Why:</b> next time you bring this codebase (even after a reload), SecureFlow recognises it, checks which recommended fixes you made, and shows the ones still to do.</li>'+
    '<li><b>Where:</b> SecureFlow’s Cloudflare D1 database. Anyone holding most of the same code can open this record; nobody else can find it.</li>'+
    '<li>“Forget this codebase” deletes it. You can switch memory off at any time.</li></ul>';
  var ok=$('cs-ok'); ok.disabled=ai;
  var own=$('cs-own'); if (own) own.addEventListener('change',function(){ ok.disabled=!own.checked; });
  return new Promise(function(res){
    function done(v){ ok.removeEventListener('click',yes); $('cs-cancel').removeEventListener('click',no); d.removeEventListener('cancel',no); if (d.open) d.close(); res(v); }
    function yes(){ done(true); } function no(){ done(false); }
    ok.addEventListener('click',yes); $('cs-cancel').addEventListener('click',no); d.addEventListener('cancel',no);
    if (d.showModal) d.showModal(); else res(window.confirm($('cs-title').textContent));
  });
}
function setToggle(kind, v){ on[kind]=v; var t=$(kind==='ai'?'ai-toggle':'mem-toggle'); t.setAttribute('aria-pressed',v?'true':'false'); t.classList.toggle('on',v); }
function toggle(kind){
  if (on[kind]){ setToggle(kind,false); if(kind==='ai'&&busy.ai&&aiAbort)aiAbort.abort(); W.toast(kind==='ai'?'AI deep check is off. Nothing more is sent to Gemini.':'Codebase memory is off for this session.'); W.renderAll(); return; }
  consent(kind).then(function(yes){ if (!yes) return; setToggle(kind,true);
    W.log('consent', kind==='ai'?'AI deep check switched on (consent given)':'Codebase memory switched on (consent given)');
    var c=W.current();
    if (kind==='ai'){ if (c && !c.ai) runAI(c); else if (!c) W.toast('AI deep check is on. It runs after your next scan.'); }
    else { if (c) runMemory(c); else W.toast('Codebase memory is on. It runs after your next scan.'); }
    W.renderAll();
  });
}
$('ai-toggle').addEventListener('click',function(){ toggle('ai'); });
$('mem-toggle').addEventListener('click',function(){ toggle('mem'); });

/* ---------------- status bar ---------------- */
var barTimer=null;
function bar(html, kind){ var b=$('ai-bar'); clearInterval(barTimer); if (!html){ b.hidden=true; return; } b.hidden=false; b.className='ai-bar '+(kind||''); b.innerHTML=html; }
function barRunning(label){ var t0=Date.now(); bar('<span class="spin" aria-hidden="true"></span><span>'+esc(label)+' <b class="mono" id="bar-t">0 s</b></span>','run');
  barTimer=setInterval(function(){ var el=$('bar-t'); if (el) el.textContent=Math.round((Date.now()-t0)/1000)+' s'; },1000); }
$('ai-bar').addEventListener('click',function(e){ var b=e.target.closest('[data-bar]'); if (!b) return; var a=b.dataset.bar, c=W.current();
  if (a==='retry-ai' && c) runAI(c); if (a==='stop-ai'&&aiAbort)aiAbort.abort(); if (a==='memory') W.showView('memory'); if (a==='close') bar(null); });

/* ---------------- AI deep check ---------------- */
function lineArr(code){ return String(code).split(/\r\n|\r|\n/); }
function evidenceFor(code, line){ var L=lineArr(code), out=[]; for (var i=Math.max(1,line-2); i<=Math.min(L.length,line+2); i++) out.push({ n:i, text:E.mask(L[i-1]), hit:i===line }); return out; }
function norm(s){ return String(s||'').replace(/\s+/g,' ').trim(); }
function toFinding(x, files){
  return { id:x.id, ruleId:'ai-'+String(x.category||'issue').toLowerCase().replace(/[^a-z0-9]+/g,'-').slice(0,30), rule:{ id:'ai', title:x.title }, source:'ai', title:x.title, severity:x.severity, confidence:x.confidence,
    category:x.category, cwe:x.cwe||'—', file:x.file, line:x.line, endLine:x.line, column:1, code:x.snippet, evidence:evidenceFor(files[x.file]||'', x.line),
    why:x.explainTechnical, fix:(x.howToFix||[]).join(' '), tests:'Add a test that sends the attacker input from the risk chain and asserts it is rejected or neutralised.',
    detection:'AI review (Gemini), challenged by a second pass', fp:'ai|'+norm(x.snippet)+'|'+x.title.toLowerCase(), ai:x };
}
function mergeAI(scan, res){
  var engine=scan.result.findings.filter(function(f){ return f.source!=='ai'; }), added=0, confirmed=0;
  scan.result.findings=engine;   // a re-run replaces earlier AI results for this scan
  engine.forEach(function(f){ if (f.ai){ delete f.ai; delete f.source; } });
  res.issues.forEach(function(x){
    var twin=engine.find(function(f){ return !f.ai && f.file===x.file && Math.abs(f.line-x.line)<=3 && (x.relatedRule===f.ruleId || f.category.toLowerCase()===String(x.category).toLowerCase()); });
    if (twin){ twin.ai=x; twin.source='both'; confirmed++; } else { scan.result.findings.push(toFinding(x, scan.files)); added++; }
  });
  scan.ai=true; scan.aiStatus='completed'; scan.combinedStatus='building_report'; scan.aiMeta={ model:res.model, guard:res.guard, coverage:res.coverage, passes:res.passes, reviewerStatus:res.reviewerStatus, reviewerError:res.reviewerError, at:new Date(), added:added, confirmed:confirmed };
}
function drawAnalysis(scan, message, kind){
  var state=scan.aiProgress, b=$('ai-bar'); if(!state||!b)return;
  var statuses={pending:'Pending',running:'Running',completed:'Completed',failed:'Failed',skipped:'Skipped'};
  var items=state.stages.map(function(s,i){return '<li class="'+s.status+'"><b>Stage '+(i+1)+' of 10</b> · '+esc(s.name)+' · <span>'+statuses[s.status]+'</span>'+(s.note?' · '+esc(s.note):'')+'</li>';}).join('');
  b.hidden=false; b.className='ai-bar '+(kind||'run');
  b.innerHTML='<b>Local scan: '+esc(scan.localStatus||'completed')+' · Gemini: '+esc(scan.aiStatus||'not_started')+' · Combined: '+esc(scan.combinedStatus||'local_only')+'</b>'+(message?'<p>'+esc(message)+'</p>':'')+'<ol class="ai-stages">'+items+'</ol>'+(busy.ai?'<button class="btn btn-ghost btn-sm" data-bar="stop-ai">Cancel Gemini review</button>':'')+(scan.aiStatus==='failed'?'<button class="btn btn-ghost btn-sm" data-bar="retry-ai">Retry Gemini review</button>':'');
}
function setStage(scan,index,status,note){ var s=scan.aiProgress.stages[index-1]; if(!s)return; s.status=status; s.note=note||''; drawAnalysis(scan,scan.aiProgress.provider||''); }
async function streamAnalyze(payload,signal,onEvent){
  var response=await fetch('/api/ai/analyze/stream',{method:'POST',headers:{'content-type':'application/json','accept':'text/event-stream'},credentials:'same-origin',body:JSON.stringify(Object.assign({consent:true},payload)),signal:signal});
  if(!response.ok){var j=await response.json().catch(function(){return {};});var e=new Error(j.error||('http_'+response.status));e.code=j.error||'network';e.status=response.status;e.detail=j.detail;throw e;}
  if(!response.body||!response.body.getReader)throw Object.assign(new Error('stream_unavailable'),{code:'network'});
  var reader=response.body.getReader(),decoder=new TextDecoder(),buffer='',result=null;
  function consume(block){var line=block.split(/\r?\n/).find(function(x){return x.indexOf('data: ')===0;});if(!line)return;var event=JSON.parse(line.slice(6));onEvent(event);if(event.type==='error')throw Object.assign(new Error(event.error),{code:event.error,status:event.status,detail:event.detail});if(event.type==='done')result=event.result;}
  while(true){var chunk=await reader.read();buffer+=decoder.decode(chunk.value||new Uint8Array(),{stream:!chunk.done});var parts=buffer.split(/\r?\n\r?\n/);buffer=parts.pop();for(var i=0;i<parts.length;i++)consume(parts[i]);if(chunk.done)break;}
  if(buffer.trim())consume(buffer);if(!result)throw Object.assign(new Error('incomplete_response'),{code:'network'});return result;
}
async function runAI(scan){
  if(busy.ai||!on.ai)return;
  busy.ai=true;scan.aiStatus='connecting';scan.combinedStatus='local_only';scan.aiProgress={provider:'',stages:ANALYSIS_STAGES.map(function(name,i){return {name:name,status:i<2?'completed':'pending',note:i===0?'Project inventory available':i===1?'Deterministic engine finished':''};})};
  drawAnalysis(scan,'Preparing a contextual Gemini review. The local scan is already complete.');
  try{
    setStage(scan,3,'running','Masking source secrets in browser');
    var files=W.filesArr(scan.files).map(function(f){return {name:f.name,code:lineArr(f.code).map(E.mask).join('\n')};});
    setStage(scan,3,'completed','Source masked before transmission');
    setStage(scan,4,'running','Selecting relevant local findings and building file context');
    var engine=W.openFindings(scan.result.findings).filter(function(f){return f.source!=='ai';}).map(function(f){return {ruleId:f.ruleId,title:f.title,severity:f.severity,file:f.file,line:f.line};});
    setStage(scan,4,'completed','Context ready for one primary Gemini review');
    setStage(scan,5,'running','Connecting to Gemini'); scan.aiStatus='connecting';
    aiAbort=new AbortController();
    var res=await streamAnalyze({files:files,engine:engine},aiAbort.signal,function(ev){
      if(ev.type==='provider'){
        var labels={request_sent:'Request sent to Gemini',response_received:'Gemini response received (HTTP '+ev.status+')',response_validated:'Gemini JSON response parsed',timeout:'Gemini request timed out',network:'Gemini network request failed',invalid_response:'Provider response was not valid JSON'};
        scan.aiProgress.provider=labels[ev.state]||''; scan.aiStatus=ev.state==='response_received'?'response_received':(ev.state==='request_sent'?'request_sent':scan.aiStatus);drawAnalysis(scan,scan.aiProgress.provider,'run');
      } else if(ev.type==='stage') { setStage(scan,ev.index,ev.status,ev.reason||ev.model||''); if(ev.index===5&&ev.status==='running')scan.aiStatus='request_sent'; }
    });
    busy.ai=false;aiAbort=null;
    setStage(scan,9,'running','Merging validated AI issues with local findings');
    mergeAI(scan,res);setStage(scan,9,'completed','Deduplicated against local findings; matching evidence retained');
    setStage(scan,10,'running','Preparing source-aware combined results');
    await Promise.resolve();W.renderAll();W.renderFindings();setStage(scan,10,'completed','Combined report uses the sources shown above');scan.combinedStatus='completed';drawAnalysis(scan,'Combined local and Gemini report is ready.','ok');
    var g=res.guard,m=scan.aiMeta,reviewer=res.reviewerStatus==='failed'?'The independent reviewer failed; primary findings remain explicitly unchallenged.':(res.reviewerStatus==='skipped'?'No primary AI claims required a second-pass challenge.':'Second reviewer rejected '+g.rejectedByReviewer+' claims.');
    W.log('scan','Gemini analysis completed; '+res.issues.length+' validated issue(s), '+m.added+' additional, '+m.confirmed+' matched local findings.');
    drawAnalysis(scan,'Gemini analysis completed. '+res.issues.length+' validated finding(s); '+m.added+' new beyond the engine and '+m.confirmed+' confirmed by local rules. '+g.droppedUnlocated+' claim'+(g.droppedUnlocated===1?' could':'s could')+' not be quoted against real code, so '+(g.droppedUnlocated===1?'it was':'they were')+' dropped. '+reviewer+(res.coverage.skipped.length?' Not sent (size limit): '+res.coverage.skipped.length+' file(s).':''),'ok');
  }catch(e){
    busy.ai=false;aiAbort=null;scan.aiStatus=e.name==='AbortError'?'skipped':'failed';scan.combinedStatus='local_only';
    var failed=scan.aiProgress.stages.find(function(s){return s.status==='running';});if(failed)failed.status=e.name==='AbortError'?'skipped':'failed';
    scan.aiProgress.stages.forEach(function(s){if(s.status==='pending')s.status='skipped';});
    var detail=e.status?'HTTP '+e.status:(e.detail==='timeout'?'request timed out':e.detail==='network'?'network or CORS failure':e.detail==='bad_json'?'provider returned malformed JSON':'');
    var reason=errText(e)+(detail?' ('+detail+')':'');drawAnalysis(scan,e.name==='AbortError'?'Gemini review was cancelled. Local findings remain available.':reason,'bad');
    W.log('warn','Gemini analysis '+scan.aiStatus+': '+((e&&e.code)||'error')+(detail?' '+detail:''));
  }
}

/* ---------------- seriousness, meta, risk chain ---------------- */
var EST={ critical:9.1, high:7.4, medium:5.2, low:3.0, info:1.0 }, CONFD={ high:0, medium:.5, low:1 };
function scoreOf(f){ if (f.ai) return { v:f.ai.score, ai:true, x:f.ai.exploitability, i:f.ai.impact }; return { v:Math.max(0,Math.round((EST[f.severity]-CONFD[f.confidence])*10)/10), ai:false }; }
function scoreColor(v){ return v>=9?'#d4513f':v>=7?'#d98a3e':v>=4?'#c9a56b':'#9bb08f'; }
H.metaAI=function(f){
  var x=f.ai, s=x.score, cwe=/^CWE-(\d+)$/.exec(x.cwe||'');
  var refs=[{ title:'OWASP Top 10', url:'https://owasp.org/Top10/' }]; if (cwe) refs.unshift({ title:x.cwe, url:'https://cwe.mitre.org/data/definitions/'+cwe[1]+'.html' });
  return { impact:{ confidentiality:x.cia.confidentiality, integrity:x.cia.integrity, availability:x.cia.availability }, flow:x.chain.map(function(c){ return c.label; }),
    context:x.reviewReason?('Second reviewer: '+x.reviewReason):'Exploitability depends on how this code is deployed and reached.',
    limits:'AI review of the code you shared. It cannot see runtime configuration, infrastructure or code you did not upload, and it can be wrong; the quoted line is real.',
    refs:refs, priority:s>=9?'P1':s>=7?'P2':s>=4?'P3':'P4' };
};
H.detailTop=function(f){
  var s=scoreOf(f), c=scoreColor(s.v), x=f.ai;
  return '<div class="sev-score"><div class="ring" style="--v:'+(s.v*10)+';--c:'+c+'"><b>'+s.v.toFixed(1)+'</b><small>/ 10</small></div><div><b>Seriousness '+s.v.toFixed(1)+'</b> '+
    (s.ai?'<span class="fine">AI assessment · exploitability '+(+s.x).toFixed(1)+' · impact '+(+s.i).toFixed(1)+' · '+esc(x.confidence)+' confidence'+(x.review==='confirmed'?' · confirmed by second reviewer':x.review==='uncertain'?' · second reviewer unsure':'')+'</span>'
      :'<span class="fine">Estimated from severity ('+f.severity+') and confidence ('+f.confidence+'). Turn on AI deep check for a code-specific assessment.</span>')+
    (x?'<div class="explain"><div class="seg" role="group" aria-label="Explanation level"><button class="on" data-exp="simple">For founders</button><button data-exp="tech">For developers</button></div><p data-exp-body="simple">'+esc(x.explainSimple)+'</p><p data-exp-body="tech" hidden>'+esc(x.explainTechnical)+'</p></div>':'')+'</div></div>';
};
function chainOf(f){
  if (f.ai && f.ai.chain && f.ai.chain.length) return { steps:f.ai.chain, cutAt:f.ai.cutAt, after:f.ai.afterFix, ai:true };
  var m=E.metaFor(f); if (!m.flow.length) return null;
  return { steps:m.flow.map(function(t,i){ return { kind:i===0?'weakness':(i===m.flow.length-1?'impact':'propagation'), label:t, file:i===0?f.file:'', line:i===0?f.line:0, observed:i===0 }; }),
    cutAt:0, after:'With the fix in place, the weakness at line '+f.line+' no longer gives an attacker the next step.', ai:false };
}
var KIND={ source:'Attacker input', propagation:'Flows through', weakness:'Weakness', sink:'Dangerous use', impact:'Impact' };
H.chain=function(f){
  var ch=chainOf(f); if (!ch) return '';
  var items=[];
  ch.steps.forEach(function(st,i){
    items.push('<li class="cn k-'+st.kind+(st.observed?' obs':'')+(i>ch.cutAt?' post':'')+'"'+(st.observed?' data-jump="'+esc(st.file)+'|'+st.line+'" tabindex="0" role="button" title="Open this line"':'')+'><small>'+KIND[st.kind]+(st.observed?' · observed in your code · '+esc(st.file.split('/').pop())+':'+st.line:' · illustrative step')+'</small><span>'+esc(st.label)+'</span></li>');
    if (i===ch.cutAt && i<ch.steps.length-1) items.push('<li class="cut" aria-label="A fix breaks the chain here"><span>✂ fix breaks it here</span></li>');
  });
  return '<div class="chain"><ol>'+items.join('')+'</ol><p class="after" hidden><b>After the fix:</b> '+esc(ch.after)+'</p>'+
    '<div class="chain-foot"><button class="btn btn-ghost btn-sm" data-chain="toggle" aria-pressed="false">Show what the fix changes</button><span class="fine">Only solid steps are evidence from your code (click to open the line). Dashed steps are an illustrative scenario, not a demonstrated attack'+(ch.ai?' (from the AI review)':'')+'.</span></div></div>';
};

/* ---------------- detail: guidance (10 rounds) + Ask ---------------- */
function st(id){ return aiState[id]||(aiState[id]={ guide:null, chat:[], busyChat:false }); }
function issuePayload(f){ return { title:f.title, severity:f.severity, file:f.file, line:f.line, category:f.category, why:(f.ai?f.ai.explainTechnical:f.why)||'', snippet:f.code||'' }; }
function codeWindow(f){
  var file=W.state.files.find(function(x){ return x.name===f.file; }); if (!file) return null;
  var L=lineArr(file.code); if (L.length<=400) return { code:L.map(E.mask).join('\n'), startLine:1 };
  var a=Math.max(1,f.line-80), b=Math.min(L.length,f.line+80); return { code:L.slice(a-1,b).map(E.mask).join('\n'), startLine:a };
}
H.detail=function(f, D){
  var s=st(f.id);
  var html='<div class="d-sec ai-sec"><h4>Verified Fix Guidance (AI)</h4><div id="ai-guide">'+guideHTML(f,s)+'</div></div>'+
    '<div class="d-sec ai-sec"><h4>Ask SecureFlow how to fix it</h4><div id="ai-chat">'+chatHTML(f,s)+'</div></div>';
  var acts=D.querySelector('.d-actions'); if (acts) acts.insertAdjacentHTML('beforebegin',html); else D.insertAdjacentHTML('beforeend',html);
  var log=$('chat-log'); if (log) log.scrollTop=log.scrollHeight;
};
function offHTML(what){ return srv.ai ? '<p class="fine">'+what+' <button class="btn btn-ghost btn-sm" data-ai="enable">Turn on AI deep check</button></p>' : '<p class="fine">'+what+' Needs the SecureFlow server with a Gemini key (this copy runs the local engine only).</p>'; }
function guideHTML(f, s){
  if (!on.ai) return offHTML('SecureFlow drafts how to fix this, then verifies its advice against your code before showing it. It never writes the fix for you.');
  var g=s.guide;
  if (!g) return '<button class="btn btn-solid btn-sm" data-ai="guide">Get verified fix guidance</button> <span class="fine">Deep 10-round AI verification ladder.</span>';
  var ladder='<ol class="ladder" aria-label="Verification rounds">'+Array.from({length:ROUNDS},function(_,i){ var r=g.rounds[i], cls=!r?(g.running&&i===g.rounds.length?'run':''):r.error?'err':(i===0?'draft':(r.ok?'ok':'fix'));
    return '<li class="'+cls+'" title="'+(r?esc(r.label):'Round '+(i+1))+'">'+(i===0?'1. Draft':(i===ROUNDS-1?'10. Final':(i+1)+'. Verify'))+'</li>'; }).join('')+'</ol>';
  var notes='<ul class="rnotes">'+g.rounds.map(function(r,i){ return '<li><b>Round '+(i+1)+'</b>: '+esc(r.label)+(r.problems&&r.problems.length?'<ul>'+r.problems.map(function(p){ return '<li><span class="pchip '+esc(p.severity)+'">'+esc(p.severity)+'</span> '+esc(p.text)+'</li>'; }).join('')+'</ul>':'')+'</li>'; }).join('')+'</ul>';
  var done=(g.rounds.length>=ROUNDS) && !g.running, out='';
  if (g.running) out='<p class="fine"><span class="spin" aria-hidden="true"></span> Round '+(g.rounds.length+1)+' of '+ROUNDS+' ('+(g.rounds.length===0?'Drafting fix from your code':'Verifying against security rules')+')… <button class="btn btn-ghost btn-sm" data-ai="stop">Stop</button></p>';
  if (g.error) out='<p class="bad-note">'+esc(g.error)+' <button class="btn btn-ghost btn-sm" data-ai="resume">Resume from round '+(g.rounds.length+1)+'</button></p>';
  var body=g.guidance?guidanceHTML(g.guidance):'';
  var fixes=g.rounds.filter(function(r){ return r.problems&&r.problems.length; }).length;
  return ladder+out+(done?'<p class="verified-note">✓ Verified fix guidance: completed in '+g.rounds.length+' round'+(g.rounds.length===1?'':'s')+(fixes?' ('+fixes+' issue'+(fixes===1?'':'s')+' corrected)':' (clean review)')+'. Follow the steps, then rescan.</p>'+body
    :(body?'<details class="peek"><summary>Peek at current draft</summary>'+body+'</details>':''))+(g.rounds.length?'<details class="peek"><summary>Verification details</summary>'+notes+'</details>':'');
}
function md(t){ return esc(t).replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>').replace(/\n/g,'<br>'); }
function guidanceHTML(g){
  return '<div class="guide"><p><b>'+md(g.summary||'')+'</b></p><ol class="gsteps">'+(g.steps||[]).map(function(x){ return '<li><b>'+md(x.title||'')+'</b><span>'+md(x.detail||'')+'</span></li>'; }).join('')+'</ol>'+
    ((g.pitfalls||[]).length?'<p class="gh">Avoid</p><ul>'+g.pitfalls.map(function(x){ return '<li>'+md(x)+'</li>'; }).join('')+'</ul>':'')+
    ((g.verify||[]).length?'<p class="gh">Prove it works</p><ul>'+g.verify.map(function(x){ return '<li>'+md(x)+'</li>'; }).join('')+'</ul>':'')+
    (g.afterFix?'<p class="fine">After the fix: '+md(g.afterFix)+'</p>':'')+'<p class="fine">SecureFlow explains the fix; it does not write it for you. Confidence: '+esc(g.confidence||'medium')+'.</p></div>';
}
function rerenderGuide(id){ var D=$('detail'); if (D.dataset.id!==id) return; var f=W.findById(id), el=$('ai-guide'); if (f && el) el.innerHTML=guideHTML(f,st(id)); }
function runGuide(f){
  var s=st(f.id), g=s.guide||(s.guide={ rounds:[], guidance:null, running:false, error:null, stop:false });
  var ctx=codeWindow(f); if (!ctx){ W.toast('That file is no longer in the project.'); return; }
  var ch=chainOf(f); g.running=true; g.error=null; g.stop=false; rerenderGuide(f.id);
  (function next(){
    if (g.stop){ g.running=false; g.error='Stopped by you.'; rerenderGuide(f.id); return; }
    if (g.rounds.length>=ROUNDS){
      g.running=false;
      W.log('patch-proposed','Fix guidance verified over '+g.rounds.length+' rounds for “'+f.title+'”');
      rerenderGuide(f.id);
      return;
    }
    var round=g.rounds.length+1;
    api('/api/ai/guide',{ issue:issuePayload(f), code:ctx.code, startLine:ctx.startLine, round:round, draft:g.guidance, chain:ch?ch.steps:[] }).then(function(r){
      g.guidance=r.guidance;
      var probs=(r.review&&r.review.problems)||[];
      g.rounds.push({ ok:round>1&&(r.review&&r.review.ok), problems:probs, label:round===1?'First draft written from your code.':(probs.length?probs.length+' problem'+(probs.length===1?'':'s')+' found → guidance revised.':'No problems found.') });
      rerenderGuide(f.id); next();
    }, function(e){ g.running=false; g.error='Stopped at round '+round+': '+errText(e); rerenderGuide(f.id); });
  })();
}
function chatHTML(f, s){
  if (!on.ai) return offHTML('Ask how to fix this in your own code: where to change it, which API to use, how to test it. Answers explain the fix; they do not write it for you.');
  var chips=['Where exactly do I change this?','Why is this dangerous in my app?','How do I test that it is fixed?','Are there other places with the same problem?'];
  return '<div class="chat-log" id="chat-log" aria-live="polite">'+(s.chat.length?s.chat.map(function(m){ return '<div class="msg '+m.role+'">'+(m.role==='user'?esc(m.text):md(m.text))+'</div>'; }).join(''):'<p class="fine">No questions yet.</p>')+(s.busyChat?'<div class="msg bot"><span class="spin" aria-hidden="true"></span> Thinking…</div>':'')+'</div>'+
    '<div class="chips qchips">'+chips.map(function(c){ return '<button class="chip" data-ask="'+esc(c)+'">'+esc(c)+'</button>'; }).join('')+'</div>'+
    '<form class="ask-form" id="ask-form"><input name="q" maxlength="1200" placeholder="Ask about this finding…" aria-label="Your question" autocomplete="off"'+(s.busyChat?' disabled':'')+'><button class="btn btn-solid btn-sm"'+(s.busyChat?' disabled':'')+'>Ask</button></form>';
}
function rerenderChat(id){ var D=$('detail'); if (D.dataset.id!==id) return; var f=W.findById(id), el=$('ai-chat'); if (f&&el){ el.innerHTML=chatHTML(f,st(id)); var l=$('chat-log'); if (l) l.scrollTop=l.scrollHeight; } }
function ask(f, q){
  var s=st(f.id); q=String(q||'').trim(); if (!q||s.busyChat) return; var ctx=codeWindow(f); if (!ctx){ W.toast('That file is no longer in the project.'); return; }
  var hist=s.chat.slice(-8); s.chat.push({ role:'user', text:q }); s.busyChat=true; rerenderChat(f.id);
  api('/api/ai/ask',{ issue:issuePayload(f), code:ctx.code, startLine:ctx.startLine, question:q, history:hist }).then(function(r){
    s.busyChat=false; s.chat.push({ role:'bot', text:r.answer }); rerenderChat(f.id); var n=$('ask-form'); if (n) n.q.focus();
  }, function(e){ s.busyChat=false; s.chat.push({ role:'bot', text:errText(e) }); rerenderChat(f.id); });
}
$('detail').addEventListener('click',function(e){
  var D=$('detail'), f=W.findById(D.dataset.id); if (!f) return;
  var t=e.target.closest('[data-ai],[data-ask],[data-chain],[data-exp],[data-jump]'); if (!t) return;
  if (t.dataset.ai==='enable') toggle('ai');
  if (t.dataset.ai==='guide'||t.dataset.ai==='resume') runGuide(f);
  if (t.dataset.ai==='stop' && st(f.id).guide) st(f.id).guide.stop=true;
  if (t.dataset.ask) ask(f,t.dataset.ask);
  if (t.dataset.chain){ var ch=t.closest('.chain'), v=!ch.classList.contains('fixed'); ch.classList.toggle('fixed',v); ch.querySelector('.after').hidden=!v; t.setAttribute('aria-pressed',v); t.textContent=v?'Show the risk again':'Show what the fix changes'; }
  if (t.dataset.exp){ D.querySelectorAll('[data-exp]').forEach(function(b){ b.classList.toggle('on',b===t); }); D.querySelectorAll('[data-exp-body]').forEach(function(p){ p.hidden=p.dataset.expBody!==t.dataset.exp; }); }
  if (t.dataset.jump){ var p=t.dataset.jump.split('|'); W.jumpTo({ file:p[0], line:+p[1] }); }
});
$('detail').addEventListener('keydown',function(e){ if ((e.key==='Enter'||e.key===' ') && e.target.dataset && e.target.dataset.jump){ e.preventDefault(); e.target.click(); } });
$('detail').addEventListener('submit',function(e){ if (e.target.id!=='ask-form') return; e.preventDefault(); e.stopImmediatePropagation(); var f=W.findById($('detail').dataset.id); if (f) ask(f,e.target.q.value); },true);

/* ---------------- Codebase memory ---------------- */
function fmix(h){ h^=h>>>16; h=Math.imul(h,0x85ebca6b); h^=h>>>13; h=Math.imul(h,0xc2b2ae35); h^=h>>>16; return h>>>0; }
function fnv(s){ var h=0x811c9dc5; for (var i=0;i<s.length;i++){ h^=s.charCodeAt(i); h=Math.imul(h,0x01000193); } return h>>>0; }
var SEEDS=Array.from({length:64},function(_,k){ return fmix((k+1)*0x9e3779b1); });
function signature(files){
  var set=new Set(); files.forEach(function(f){ lineArr(f.code).forEach(function(l){ var n=norm(l); if (n.length>=4) set.add(fnv(n)); }); });
  var sig=SEEDS.map(function(){ return 0xffffffff; });
  set.forEach(function(x){ for (var k=0;k<64;k++){ var h=fmix(x^SEEDS[k]); if (h<sig[k]) sig[k]=h; } });
  var paths=Array.from(new Set(files.map(function(f){ return fnv('path:'+f.name).toString(16).padStart(8,'0'); })));
  return { sig:sig, size:set.size, paths:paths };
}
function hex(buf){ return Array.from(new Uint8Array(buf)).map(function(b){ return b.toString(16).padStart(2,'0'); }).join(''); }
function sha(t){ return crypto.subtle.digest('SHA-256',new TextEncoder().encode(t)).then(hex); }
function saltedFile(code, salt){ return Promise.all(lineArr(code).map(function(l){ return sha(salt+'\u0000'+norm(l)).then(function(h){ return h.slice(0,8); }); })); }
function memKey(f){ return f.source==='ai' ? f.id : 'e-'+fnv(f.ruleId+'|'+f.file+'|'+norm(f.code)).toString(16).padStart(8,'0')+fnv(f.ruleId+norm(f.code)).toString(16).slice(0,2); }
function ctxOf(H, i){ return [i-2,i-1,i+1,i+2].map(function(k){ return H[k]||'00000000'; }).join(''); }
function locateAnchor(H, anchor, ctx){
  var best=-1, bestScore=-1, hits=0, c=[0,1,2,3].map(function(k){ return ctx.slice(k*8,k*8+8); });
  for (var i=0;i<H.length;i++) if (H[i]===anchor){ hits++; var sc=[i-2,i-1,i+1,i+2].reduce(function(a,k,j){ return a+(H[k]&&H[k]===c[j]?1:0); },0); if (sc>bestScore){ bestScore=sc; best=i; } }
  return { idx:best, score:bestScore, hits:hits };
}
function estimateLine(H, ctx, oldLine){ var c=[0,1,2,3].map(function(k){ return ctx.slice(k*8,k*8+8); }), off=[-2,-1,1,2];
  for (var j=0;j<4;j++){ if (c[j]==='00000000') continue; var i=H.indexOf(c[j]); if (i>=0) return i-off[j]+1; } return oldLine; }

function runMemory(scan){
  if (busy.mem || !on.mem) return Promise.resolve();
  busy.mem=true; mem.phase='matching'; mem.error=null; renderMemoryNav(); if (W.state.view==='memory') renderMemory();
  var files=W.filesArr(scan.files), sg=signature(files);
  var digestP=sha(files.map(function(f){ return f.name+'\n'+lineArr(f.code).map(norm).join('\n'); }).sort().join('\u0001'));
  return digestP.then(function(digest){
    return api('/api/memory/match',{ sig:sg.sig, paths:sg.paths, digest:digest }).then(function(m){
      mem.match=m.match;
      if (!m.match){ mem.data=null; mem.id=null; mem.salt=Array.from(crypto.getRandomValues(new Uint8Array(8))).map(function(b){ return b.toString(16).padStart(2,'0'); }).join(''); return null; }
      return api('/api/memory/'+m.match.id+'/load',{ sig:sg.sig, paths:sg.paths }).then(function(d){ mem.data=d; mem.id=d.codebase.id; mem.salt=d.salt; return d; });
    }).then(function(d){
      return Promise.all(files.map(function(f){ return saltedFile(f.code, mem.salt).then(function(h){ return { path:f.name, H:h }; }); })).then(function(hashed){
        var byPath={}; hashed.forEach(function(x){ byPath[x.path]=x.H; });
        mem.phase='checking'; renderMemory();
        return (d ? compareIssues(d, byPath, scan) : Promise.resolve([])).then(function(checked){ return saveMemory(scan, sg, digest, hashed, byPath, checked); });
      });
    });
  }).then(function(){ busy.mem=false; mem.phase='done'; renderMemoryNav(); if (W.state.view==='memory') renderMemory(); },
    function(e){ busy.mem=false; mem.phase='error'; mem.error=errText(e); renderMemoryNav(); if (W.state.view==='memory') renderMemory(); });
}
function compareIssues(d, byPath, scan){
  var stored=d.issues.filter(function(x){ return x.status!=='dismissed'; }), fileHashes={};
  d.files.forEach(function(f){ fileHashes[f.path]=f.hashes.match(/.{8}/g)||[]; });
  var curEngine=scan.result.findings.filter(function(f){ return f.source!=='ai' && !W.state.dismissed[f.id]; });
  function findFile(x){
    if (byPath[x.file]) return x.file;
    var old=new Set(fileHashes[x.file]||[]), best=null, bs=0;
    Object.keys(byPath).forEach(function(p){ var n=byPath[p].reduce(function(a,h){ return a+(old.has(h)?1:0); },0); if (n>bs){ bs=n; best=p; } });
    return bs>=Math.max(3,old.size*.3) ? best : null;
  }
  return stored.reduce(function(chain, x){ return chain.then(function(acc){
    var r={ x:x, status:x.status, note:'', file:x.file, line:x.line };
    var path=findFile(x); if (!path){ r.status='file_removed'; r.note='This file is not in the code you brought, so the fix could not be checked.'; acc.push(r); return acc; }
    r.file=path; var H=byPath[path], loc=x.anchor?locateAnchor(H,x.anchor,x.ctx||''):{ idx:-1, score:0, hits:0 };
    if (loc.idx>=0 && (loc.score>=1 || loc.hits===1)){ r.line=loc.idx+1;
      r.status='still_open'; r.note=x.status==='verified_fixed'?'This line is back: the earlier fix was undone.':'The flagged line is still here, unchanged.'; acc.push(r); return acc; }
    var est=estimateLine(H,x.ctx||'',x.line); r.line=Math.max(1,Math.min(H.length,est));
    if (x.status==='verified_fixed'){ r.note='Still fixed (the old line has not come back).'; acc.push(r); return acc; }
    var eng=x.source==='engine' && curEngine.find(function(f){ return f.file===path && f.ruleId===x.rule_id && Math.abs(f.line-r.line)<=12; });
    if (eng){ r.status='still_open'; r.line=eng.line; r.note='The line was reworded, but the same rule still flags it.'; acc.push(r); return acc; }
    if (!on.ai){ r.status='changed_unverified'; r.note='The flagged line changed and the engine no longer flags it. Not confirmed: turn on AI deep check to verify.'; acc.push(r); return acc; }
    var code=W.state.files.find(function(f){ return f.name===path; }); var L=lineArr(code?code.code:''), a=Math.max(1,r.line-30), b=Math.min(L.length,r.line+30);
    return api('/api/ai/verify-fix',{ issue:{ title:x.title, severity:x.severity, file:path, line:r.line, category:x.category, why:(x.howto||[]).join(' '), snippet:'' }, code:L.slice(a-1,b).map(E.mask).join('\n'), startLine:a }).then(function(v){
      r.status=v.status==='fixed'?'verified_fixed':(v.status==='cannot_tell'?'changed_unverified':'still_open');
      r.note=(v.status==='fixed'?'Verified fixed: ':v.status==='partially_fixed'?'Partly fixed: ':v.status==='not_fixed'?'Still exploitable: ':'Could not tell: ')+v.evidence+(v.remaining?' Remaining: '+v.remaining:''); acc.push(r); return acc;
    }, function(e){ r.status='changed_unverified'; r.note='Changed, but the AI check failed ('+errText(e)+').'; acc.push(r); return acc; });
  }); }, Promise.resolve([]));
}
function saveMemory(scan, sg, digest, hashed, byPath, checked){
  var open=W.openFindings(scan.result.findings), have={}, issues=[];
  checked.forEach(function(r){ have[r.x.id]=r; });
  open.forEach(function(f){ var k=memKey(f), H=byPath[f.file]||[], prev=have[k];
    var item={ id:k, source:f.source==='ai'?'ai':'engine', ruleId:f.ruleId, title:f.title, severity:f.severity, score:scoreOf(f).v, category:f.category, file:f.file, line:f.line, anchor:H[f.line-1]||'', ctx:ctxOf(H,f.line-1),
      howto:(f.ai?f.ai.howToFix:[f.fix]).slice(0,6), status:'open', note:'' };
    if (prev){ item.status='still_open'; item.note=prev.note; prev.merged=true; } issues.push(item); });
  checked.forEach(function(r){ if (r.merged) return; var x=r.x;
    issues.push({ id:x.id, source:x.source, ruleId:x.rule_id, title:x.title, severity:x.severity, score:x.score, category:x.category, file:r.file, line:r.line, anchor:x.anchor, ctx:x.ctx, howto:x.howto, status:r.status, note:r.note }); });
  mem.report={ checked:checked, newIssues:issues.filter(function(i){ return i.status==='open'; }), at:new Date() };
  var fixed=checked.filter(function(r){ return r.status==='verified_fixed'; }).length;
  var body={ id:mem.id||undefined, sig:sg.sig, paths:sg.paths, digest:digest, salt:mem.salt, files:hashed.map(function(x){ return { path:x.path, hashes:x.H.join('') }; }), issues:issues,
    visit:{ score:E.score(open), open:issues.filter(function(i){ return i.status==='open'||i.status==='still_open'; }).length, fixed:fixed } };
  return api('/api/memory/save',body).then(function(r){ mem.id=r.id; mem.created=r.created; mem.savedAt=new Date();
    W.log('scan', r.created?'Codebase memory: new codebase saved (fingerprints only)':'Codebase memory: recognised this codebase; '+fixed+' fix(es) verified, '+checked.filter(function(c){ return c.status==='still_open'; }).length+' still to do');
    return api('/api/memory/'+r.id+'/load',{ sig:sg.sig, paths:sg.paths }).then(function(d){ mem.data=d; }, function(){}); });
}
function counts(){ var c={ still_open:0, verified_fixed:0, changed_unverified:0, file_removed:0 }; ((mem.report&&mem.report.checked)||[]).forEach(function(r){ c[r.status]=(c[r.status]||0)+1; }); return c; }
function memBar(){
  if (!mem.report) return;
  var c=counts(), n=mem.report.checked.length;
  if (!mem.match){ return; }
  var ok=c.still_open===0 && c.changed_unverified===0 && n>0;
  // Memory results stay in the Codebase memory view and do not overwrite Gemini progress.
}
function renderMemoryNav(){ var c=counts(); $('n-m').textContent=mem.phase==='done'&&mem.match?(c.still_open||'✓'):''; }
function fmtDate(s){ try { return new Date(s).toLocaleString(undefined,{ dateStyle:'medium', timeStyle:'short' }); } catch(_){ return s; } }
var STAT={ still_open:['Still to fix','bad'], verified_fixed:['Verified fixed','ok'], changed_unverified:['Changed, not confirmed','warn'], file_removed:['File not in this upload','muted'] };
function timelineSVG(visits){
  if (!visits || visits.length<2) return '<p class="fine">The timeline appears after your second visit.</p>';
  var w=560, h=120, n=visits.length, max=100, pts=visits.map(function(v,i){ return [20+i*(w-40)/(n-1), h-16-(v.score/max)*(h-36)]; });
  return '<svg class="mem-tl" viewBox="0 0 '+w+' '+h+'" role="img" aria-label="Risk score over '+n+' visits"><polyline points="'+pts.map(function(p){ return p.join(','); }).join(' ')+'"/>'+
    pts.map(function(p,i){ return '<circle cx="'+p[0]+'" cy="'+p[1]+'" r="4"><title>'+esc(fmtDate(visits[i].at))+': risk '+visits[i].score+', '+visits[i].open_count+' open, '+visits[i].fixed_count+' fixed</title></circle><text x="'+p[0]+'" y="'+(p[1]-9)+'">'+visits[i].score+'</text>'; }).join('')+'</svg>'+
    '<p class="fine">Risk score per visit (lower is better). Hover a point for details.</p>';
}
function renderMemory(){
  var el=$('memory'); if (!el) return;
  var head='<h3>Codebase memory</h3><p class="fine" style="margin-top:6px">Bring the same project back later, even after a reload, and SecureFlow recognises it from line fingerprints. It then checks which recommended fixes you made, double-checks the ones that look fixed, and lists what is still open. No source code is stored.</p>';
  if (!srv.memory){ el.innerHTML=head+'<div class="card" style="margin-top:14px"><p>Not available in this copy. Codebase memory needs the SecureFlow server with its database (the Cloudflare deployment, or <span class="mono">npm run dev</span> locally).</p></div>'; return; }
  if (!on.mem){ el.innerHTML=head+'<div class="card" style="margin-top:14px"><p>Memory is off for this session.</p><p style="margin-top:10px"><button class="btn btn-solid btn-sm" data-mem="enable">Turn on Codebase memory</button></p></div>'; return; }
  if (!W.current()){ el.innerHTML=head+'<div class="card" style="margin-top:14px"><p>Scan the project first. Memory runs after each scan.</p></div>'; return; }
  if (busy.mem){ el.innerHTML=head+'<div class="card" style="margin-top:14px"><p><span class="spin" aria-hidden="true"></span> '+(mem.phase==='checking'?'Checking each recommended fix against your current code…':'Looking for this codebase…')+'</p></div>'; return; }
  if (mem.phase==='error'){ el.innerHTML=head+'<div class="card" style="margin-top:14px"><p class="bad-note">'+esc(mem.error)+'</p><button class="btn btn-ghost btn-sm" data-mem="retry">Retry</button></div>'; return; }
  if (!mem.report){ el.innerHTML=head; return; }
  var c=counts(), checked=mem.report.checked, d=mem.data, n=checked.length, ok=mem.match && c.still_open===0 && c.changed_unverified===0 && n>0;
  var id=mem.match?('<div class="mem-id"><b>Recognised</b> · '+Math.round(mem.match.similarity*100)+'% of lines and '+Math.round(mem.match.pathSimilarity*100)+'% of files the same'+(mem.match.exact?' (identical)':'')+' · first seen '+esc(fmtDate(mem.match.createdAt))+' · visit '+(d?d.codebase.visits:'')+'</div>')
    :'<div class="mem-id"><b>New codebase</b> · fingerprints of '+W.state.files.length+' file(s) saved'+(mem.savedAt?' at '+esc(fmtDate(mem.savedAt)):'')+'</div>';
  var verdict=!mem.match?'<div class="mem-verdict new"><b>Saved.</b> '+mem.report.newIssues.length+' finding(s) to fix are remembered. Fix them, then bring the code back (upload it again, even after a reload) with memory on.</div>'
    : ok?'<div class="mem-verdict ok"><b>OK report.</b> All '+c.verified_fixed+' recommended fix'+(c.verified_fixed===1?' was':'es were')+' made and verified.'+(mem.report.newIssues.length?' '+mem.report.newIssues.length+' new finding(s) appeared since; see below.':'')+'</div>'
    : '<div class="mem-verdict bad"><b>'+c.still_open+' fix'+(c.still_open===1?'':'es')+' still to do.</b> '+c.verified_fixed+' verified'+(c.changed_unverified?', '+c.changed_unverified+' changed but not confirmed':'')+(c.file_removed?', '+c.file_removed+' in files you did not bring':'')+'.</div>';
  var groups=['still_open','changed_unverified','verified_fixed','file_removed'].map(function(k){
    var rows=checked.filter(function(r){ return r.status===k; }); if (!rows.length) return '';
    return '<h4 class="mem-h">'+STAT[k][0]+' ('+rows.length+')</h4><div class="mem-list">'+rows.map(function(r){ var x=r.x, cur=findCurrent(r);
      return '<div class="mem-row '+STAT[k][1]+'"><span class="sev sev-'+esc(x.severity)+'">'+esc(x.severity)+'</span><div><b>'+esc(x.title)+'</b> <span class="fine mono">'+esc(r.file)+':'+r.line+' · '+(+x.score).toFixed(1)+'/10</span><p class="fine">'+esc(r.note)+'</p>'+
        (k==='still_open'&&x.howto&&x.howto.length?'<ol class="howto">'+x.howto.map(function(h){ return '<li>'+esc(h)+'</li>'; }).join('')+'</ol>':'')+'</div>'+(cur?'<button class="btn btn-ghost btn-sm" data-mem-open="'+esc(cur.id)+'">Open</button>':'<span></span>')+'</div>'; }).join('')+'</div>';
  }).join('');
  var fresh=mem.match&&mem.report.newIssues.length?'<h4 class="mem-h">New since last visit ('+mem.report.newIssues.length+')</h4><div class="mem-list">'+mem.report.newIssues.map(function(x){ var cur=W.openFindings(W.current().result.findings).find(function(f){ return memKey(f)===x.id; });
    return '<div class="mem-row warn"><span class="sev sev-'+esc(x.severity)+'">'+esc(x.severity)+'</span><div><b>'+esc(x.title)+'</b> <span class="fine mono">'+esc(x.file)+':'+x.line+'</span></div>'+(cur?'<button class="btn btn-ghost btn-sm" data-mem-open="'+esc(cur.id)+'">Open</button>':'<span></span>')+'</div>'; }).join('')+'</div>':'';
  el.innerHTML=head+id+verdict+groups+fresh+
    '<div class="card" style="margin-top:16px"><div class="card-h"><h3>Security timeline across visits</h3><span class="fine">Stored per visit: score and counts only.</span></div>'+timelineSVG(d&&d.visits)+'</div>'+
    '<div class="rep-actions" style="margin-top:14px"><button class="btn btn-solid btn-sm" data-mem="report">Download fix-verification report</button><button class="btn btn-danger btn-sm" data-mem="forget">Forget this codebase</button></div>';
}
function findCurrent(r){ var c=W.current(); if (!c) return null; var fs=W.openFindings(c.result.findings);
  return fs.find(function(f){ return memKey(f)===r.x.id; }) || fs.find(function(f){ return f.file===r.file && Math.abs(f.line-r.line)<=3 && f.title===r.x.title; }) || null; }
function verificationReport(){
  var c=counts(), L=['# SecureFlow fix-verification report','', 'Project: '+W.state.name, 'Generated: '+new Date().toISOString(), mem.match?'Recognised codebase: '+Math.round(mem.match.similarity*100)+'% the same as first seen '+mem.match.createdAt:'New codebase (first visit)', '',
    c.still_open===0&&c.changed_unverified===0&&mem.report.checked.length?'**OK: every recommended fix was made and verified.**':'**'+c.still_open+' fix(es) still to do**, '+c.verified_fixed+' verified, '+c.changed_unverified+' changed but not confirmed.', ''];
  ['still_open','changed_unverified','verified_fixed','file_removed'].forEach(function(k){ var rows=mem.report.checked.filter(function(r){ return r.status===k; }); if (!rows.length) return;
    L.push('## '+STAT[k][0],''); rows.forEach(function(r){ L.push('- **'+r.x.title+'** ('+r.x.severity+', '+(+r.x.score).toFixed(1)+'/10) `'+r.file+':'+r.line+'`: '+r.note); if (k==='still_open') (r.x.howto||[]).forEach(function(h){ L.push('  - '+h); }); }); L.push(''); });
  L.push('## How this was checked','','Line fingerprints locate each earlier finding. An unchanged flagged line means not fixed. A reworded line that the same rule still flags means not fixed. Changed lines are re-checked by the AI review when AI deep check is on; otherwise they are reported as not confirmed. No test was executed and SecureFlow did not run your code.');
  return L.join('\n');
}
$('memory').addEventListener('click',function(e){ var b=e.target.closest('[data-mem],[data-mem-open]'); if (!b) return; var c=W.current();
  if (b.dataset.memOpen){ var f=W.findById(b.dataset.memOpen); if (f){ W.state.focus=f.id; W.state.filters.status='open'; W.showView('findings'); } return; }
  var a=b.dataset.mem;
  if (a==='enable') toggle('mem');
  if (a==='retry' && c) runMemory(c);
  if (a==='report'){ var t=verificationReport(); try { var u=URL.createObjectURL(new Blob([t],{type:'text/markdown'})), l=document.createElement('a'); l.href=u; l.download='secureflow-fix-verification-'+new Date().toISOString().slice(0,10)+'.md'; document.body.appendChild(l); l.click(); l.remove(); setTimeout(function(){ URL.revokeObjectURL(u); },4000); W.toast('Fix-verification report saved.'); } catch(_){ W.copy(t,'Report copied as Markdown.'); } }
  if (a==='forget' && c && mem.id){ if (!window.confirm('Delete everything SecureFlow remembers about this codebase? This cannot be undone.')) return;
    var sg=signature(W.filesArr(c.files)); api('/api/memory/'+mem.id+'/forget',{ sig:sg.sig, paths:sg.paths }).then(function(){ W.log('edit','Codebase memory deleted'); mem.match=null; mem.data=null; mem.report=null; mem.id=null; mem.phase='idle'; setToggle('mem',false); bar(null); renderMemory(); renderMemoryNav(); W.toast('Deleted. SecureFlow no longer remembers this codebase.'); },
      function(e){ W.toast('Could not delete: '+errText(e)); }); }
});

/* ---------------- hooks ---------------- */
H.memory=renderMemory;
H.afterScan=function(scan){
  scan.localStatus='completed';scan.aiStatus='not_started';scan.combinedStatus='local_only';
  if(on.ai)runAI(scan);
  else { scan.aiStatus='skipped';drawAnalysis(scan,'Local scan completed. Gemini was skipped because AI deep check is turned off.',''); }
  if(on.mem)runMemory(scan);
};
H.reset=function(){ aiState={}; mem.match=null; mem.data=null; mem.report=null; mem.id=null; mem.salt=null; mem.phase='idle'; if ($('ai-bar')) bar(null); if ($('n-m')) renderMemoryNav(); };
SF.aiDebug={ srv:srv, on:on, mem:mem, aiState:aiState, signature:signature, setOn:function(k,v){ setToggle(k,v); }, health:health };
health();
})();
