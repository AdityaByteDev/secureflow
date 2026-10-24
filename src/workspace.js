(function(){
'use strict';
var SF=window.SF, U=SF.u, $=U.$, clamp=U.clamp, ease=U.ease, smooth=U.smooth, esc=U.esc, E=U.E, RM=U.RM;
/* SecureFlow workspace page (app.html). Code stays in this tab unless you explicitly opt in to AI analysis. */
var DEMO_NAME='Demo project';
var STATUS_LABEL={ 'complete':'Scan complete', 'complete-with-exclusions':'Scan complete with exclusions', 'incomplete':'Assessment incomplete', 'failed':'Scan failed', 'cancelled':'Scan cancelled' };
var REASON={ 'unsupported-type':'unsupported file type', 'too-large':'over 400 KB', 'duplicate-path':'duplicate path', 'over-file-limit':'over the 300-file limit', 'over-total-size':'over the 20 MB total',
  'unsafe-path':'unsafe path (absolute or ../)', 'excluded-folder-or-lockfile':'dependency/build folder or lockfile', 'binary':'binary content', 'empty':'empty file', 'minified-or-generated':'minified or generated',
  'encrypted':'encrypted zip entry', 'unsupported-compression':'unsupported zip compression', 'compression-ratio':'suspicious compression ratio (zip-bomb guard)', 'zip-too-large':'.zip over 30 MB',
  'zip-corrupt':'corrupt or unreadable .zip', 'zip64-unsupported':'zip64 archives not supported', 'zip-too-many-entries':'too many entries in .zip', 'zip-unsupported-browser':'this browser cannot unzip; upload the folder instead',
  'zip-entry-exceeds-declared-size':'zip entry larger than it claimed', 'read-error':'could not be read', 'too-many-archives':'more than 5 .zip files at once' };
var MAX_ARCHIVES=5;
var state={ files:SF.demoVuln(), name:DEMO_NAME, demo:true, active:0, gen:0, scans:[], baseline:0, importSkipped:[], dismissed:{}, selected:{}, focus:null, fixFocus:null, proposal:null,
  patches:[], events:[], scanning:null, pending:null, view:'overview', repair:null, filters:{sev:'',cat:'',file:'',conf:'',status:'open',sort:'severity'} };
var scanSeq=0, worker=null, workerURL=null;
var code=$('code'), gutter=$('gutter'), ed=$('editor'), smallGauge=SF.makeGauge($('small-gauge'));
$('engine-note').textContent='Engine '+E.VERSION+' · '+E.RULE_COUNT+' rules · '+E.LIMITATIONS.join(' ');
var SEVS=['critical','high','medium','low','info'];

function current(){ return state.scans.length ? state.scans[state.scans.length-1] : null; }
function openFindings(fs){ return fs.filter(function(f){ return !state.dismissed[f.id]; }); }
function filesArr(map){ return Object.keys(map).map(function(k){ return {name:k, code:map[k]}; }); }
function announce(m){ var a=$('announce'); a.textContent=''; setTimeout(function(){ a.textContent=m; },30); }
var tt; function toast(m){ var el=$('toast'); el.textContent=m; el.classList.add('on'); clearTimeout(tt); tt=setTimeout(function(){el.classList.remove('on');},3400); announce(m); }
function logEvent(type, text){ state.events.push({ type:type, text:text, at:new Date() }); if (state.view==='proof') renderTimeline(); }
function hhmm(d){ return d.toTimeString().slice(0,8); }

/* ---------- views ---------- */
var VIEWS=['overview','source','findings','fix','proof','memory','ready','reports','trust'];
SF.hooks=SF.hooks||{};
function hook(name){ var h=SF.hooks[name]; return h ? h.apply(null,Array.prototype.slice.call(arguments,1)) : undefined; }
function metaOf(f){ return (f.ai && SF.hooks.metaAI) ? SF.hooks.metaAI(f) : E.metaFor(f); }
function showView(v, focusTab){
  state.view=v;
  VIEWS.forEach(function(k){ var on=k===v, b=$('vn-'+k); b.classList.toggle('on',on); b.setAttribute('aria-selected',on); b.tabIndex=on?0:-1; $('view-'+k).hidden=!on; $('view-'+k).classList.toggle('on',on); });
  if (focusTab) $('vn-'+v).focus();
  if (v==='findings') renderFindingsView(); if (v==='fix') renderFix(); if (v==='proof') { renderVerify(); renderTimeline(); }
  if (v==='ready') renderReady(); if (v==='reports') renderReports(); if (v==='trust') renderTrust(); if (v==='overview') drawEdges(); if (v==='memory') hook('memory');
  if (v==='source') placeHL();
}
document.querySelectorAll('.vn').forEach(function(b){
  b.addEventListener('click',function(){ showView(b.dataset.view); });
  b.addEventListener('keydown',function(e){ var i=VIEWS.indexOf(b.dataset.view), d=(e.key==='ArrowDown'||e.key==='ArrowRight')?1:(e.key==='ArrowUp'||e.key==='ArrowLeft')?-1:0; if (!d) return; e.preventDefault(); showView(VIEWS[(i+d+VIEWS.length)%VIEWS.length],true); });
});
document.querySelectorAll('[data-go]').forEach(function(b){ b.addEventListener('click',function(){
  var g=b.dataset.go; if (g==='demo'){ if (!state.demo) loadDemo(false); showView('source'); toast('Demo loaded. Press Scan project.'); $('run').focus(); }
  if (g==='upload'){ showView('source'); $('up-files').click(); } if (g==='paste'){ showView('source'); $('new-file').click(); } }); });

/* ---------- project & editor ---------- */
function countFor(name){ var c=current(); return c ? openFindings(c.result.findings).filter(function(f){return f.file===name;}).length : null; }
function renderTree(){
  $('proj-name').textContent=state.name; $('proj-name').title=state.name; $('demo-badge').hidden=!state.demo; $('n-files').textContent=state.files.length||'';
  if (!state.files.length){ $('tree').innerHTML='<div class="tree-empty">No files. Upload a folder, a .zip or files, paste code, or load the demo.</div>'; return; }
  $('tree').innerHTML=state.files.map(function(f,i){ var c=countFor(f.name);
    return '<button class="tf'+(i===state.active?' on':'')+'" data-i="'+i+'" title="'+esc(f.name)+'" aria-current="'+(i===state.active)+'"><span class="p">'+esc(f.name)+'</span>'+(c===null?'':'<i class="'+(c?'bad':'ok')+'" aria-label="'+c+' findings">'+(c||'✓')+'</i>')+'</button>'; }).join('');
}
function renderGutter(){ var n=code.value.split('\n').length, s=''; for (var i=1;i<=n;i++) s+=i+'\n'; gutter.textContent=s; gutter.scrollTop=code.scrollTop; }
function openFile(i){ state.active=clamp(i,0,Math.max(0,state.files.length-1)); var f=state.files[state.active]; code.value=f?f.code:''; $('fname').value=f?f.name:''; hideHL(); renderGutter(); renderTree(); updateMeta(); }
function updateMeta(){ var lines=state.files.reduce(function(a,f){return a+f.code.split('\n').length;},0); $('meta').textContent=state.files.length+' file'+(state.files.length===1?'':'s')+' · '+lines+' lines'; }
function isStale(){ var c=current(); if (!c) return false; var cur={}; state.files.forEach(function(f){ cur[f.name]=f.code; });
  var a=Object.keys(c.files), b=Object.keys(cur); return a.length!==b.length || b.some(function(k){ return c.files[k]!==cur[k]; }); }
function checkStale(){ $('stale').hidden=!isStale(); }
var hlLine=0;
function placeHL(){ var el=$('lnhl'); if (!hlLine){ el.hidden=true; return; } el.hidden=false; el.style.top=(14+(hlLine-1)*20-code.scrollTop)+'px'; }
function hideHL(){ hlLine=0; placeHL(); }
$('tree').addEventListener('click',function(e){ if (state.scanning) return; var b=e.target.closest('.tf'); if (b) openFile(+b.dataset.i); });
code.addEventListener('input',function(){ if (state.scanning) return;
  if (!state.files.length){ state.files.push({name:'pasted.js',code:''}); state.active=0; state.name='Pasted code'; state.demo=false; $('fname').value='pasted.js'; }
  state.files[state.active].code=code.value; if (state.demo){ state.demo=false; state.name=DEMO_NAME+' (edited)'; }
  hideHL(); renderGutter(); updateMeta(); checkStale(); renderTree(); });
code.addEventListener('scroll',function(){ gutter.scrollTop=code.scrollTop; placeHL(); });
code.addEventListener('keydown',function(e){ if (e.key==='Tab'&&!e.shiftKey&&!e.ctrlKey&&!e.altKey&&!e.metaKey){ e.preventDefault(); code.setRangeText('  ',code.selectionStart,code.selectionEnd,'end'); code.dispatchEvent(new Event('input')); } });
$('fname').addEventListener('change',function(){ var f=state.files[state.active]; if (!f) return;
  if (state.scanning){ $('fname').value=f.name; return; }
  var nn=E.safePath($('fname').value.trim());
  if (!nn){ toast('That file name is not allowed. Use a relative path like src/app.js.'); $('fname').value=f.name; return; }
  if (nn!==f.name && state.files.some(function(x){ return x.name===nn; })){ toast('A file with that name already exists.'); $('fname').value=f.name; return; }
  logEvent('edit','Renamed '+f.name+' → '+nn); f.name=nn; $('fname').value=nn; renderTree(); checkStale(); });
$('rm-file').addEventListener('click',function(){
  if (state.scanning) return; var f=state.files[state.active]; if (!f) return;
  state.files.splice(state.active,1); if (state.demo){ state.demo=false; state.name=DEMO_NAME+' (edited)'; }
  logEvent('edit','Removed '+f.name+' from the in-memory project');
  openFile(Math.min(state.active,state.files.length-1)); renderAll();
  toast('Removed '+f.name+' from this tab’s project. The file on your computer is untouched.'); });

/* ---------- busy state ---------- */
function lockUI(on){
  code.readOnly=on; $('fname').readOnly=on; $('tree').classList.toggle('locked',on);
  ['up-folder','up-files','new-file','load-demo','load-fixed','run','rm-file'].forEach(function(id){ var e=$(id); if (e) e.disabled=on; });
  document.querySelectorAll('.file-btn').forEach(function(l){ l.classList.toggle('disabled',on); });
  document.querySelectorAll('[data-fix-act]').forEach(function(b){ b.disabled=on; });
  $('cancel-scan').hidden=!on; $('workspace').setAttribute('aria-busy',on?'true':'false');
}
function progress(done,total,label){ var p=$('progress'); p.hidden=false; p.querySelector('i').style.width=(total?Math.round(done/total*100):0)+'%'; $('r-status').innerHTML='<span class="pill run">Scanning</span> '+esc(label||(done+' / '+total+' files')); }
function hideProgress(){ $('progress').hidden=true; }

/* ---------- scan worker ---------- */
function getWorker(){
  if (worker) return worker;
  try {
    var src='var E=('+window.SecureFlowEngine.toString()+')();\nonmessage=function(e){var d=e.data;try{var r=E.scanProject(d.files,{onProgress:function(a,b){postMessage({type:"progress",id:d.id,done:a,total:b});}});postMessage({type:"result",id:d.id,result:r});}catch(err){postMessage({type:"error",id:d.id,error:"Internal scanner error"});}};';
    workerURL=URL.createObjectURL(new Blob([src],{type:'text/javascript'}));
    worker=new Worker(workerURL);
    worker.onmessage=function(e){ var d=e.data, s=state.scanning; if (!s || d.id!==s.id) return;
      if (d.type==='progress') progress(d.done,d.total,'Scanned '+d.done+' of '+d.total+' files');
      else if (d.type==='result') onScanResult(d.id,d.result); else onScanError(d.id,d.error); };
    worker.onerror=function(){ var s=state.scanning; killWorker(); if (s) onScanError(s.id,'The scan worker stopped unexpectedly.'); };
  } catch(e){ killWorker(); }
  return worker;
}
function killWorker(){ if (worker){ try{ worker.terminate(); }catch(_){} worker=null; } if (workerURL){ URL.revokeObjectURL(workerURL); workerURL=null; } }
SF.debug={ state:state, hasWorker:function(){ return !!worker; } };
SF.ws={ state:state, current:function(){ return current(); }, renderAll:function(j){ renderAll(j); }, renderFindings:function(){ renderFindingsView(); }, showView:function(v){ showView(v); }, toast:function(m){ toast(m); }, log:function(t,x){ logEvent(t,x); },
  findById:function(id){ return findById(id); }, openFindings:function(fs){ return openFindings(fs); }, copy:function(t,m){ copy(t,m); }, jumpTo:function(f){ jumpTo(f); }, verification:function(){ return verification(); }, filesArr:filesArr, run:function(){ run(); } };

function run(){
  if (state.scanning) return;
  if (!state.files.length){ toast('Add some code first.'); return; }
  var snap=state.files.map(function(f){ return {name:f.name, code:f.code}; });
  var id=++scanSeq; state.scanning={ id:id, gen:state.gen, files:snap };
  lockUI(true); hideHL(); progress(0,snap.length,'Reading '+snap.length+' file'+(snap.length>1?'s':'')+' locally…');
  ed.classList.remove('scanning'); void ed.offsetWidth; ed.classList.add('scanning');
  var w=getWorker();
  if (w) w.postMessage({id:id, files:snap});
  else setTimeout(function(){ var r; try { r=E.scanProject(snap); } catch(e){ return onScanError(id,'Internal scanner error'); } onScanResult(id,r); }, 20);
}
function onScanResult(id,r){
  var s=state.scanning; if (!s || s.id!==id || s.gen!==state.gen) return;
  state.scanning=null; lockUI(false); hideProgress();
  if (r.status==='failed'){ renderFailed(r); logEvent('warn','Scan failed: no supported files analysed'); toast('Scan failed: no supported source files could be analysed.'); return; }
  var map={}; s.files.forEach(function(f){ map[f.name]=f.code; });
  state.scans.push({ id:id, result:r, files:map, at:new Date() });
  if (state.scans.length===1) state.baseline=0;
  state.selected={}; state.proposal=null;
  var open=openFindings(r.findings), c=E.counts(open);
  logEvent('scan','Scan '+state.scans.length+': '+open.length+' open findings ('+c.critical+' critical, '+c.high+' high) in '+r.coverage.analyzed+' file'+(r.coverage.analyzed===1?'':'s'));
  var first=open[0]; state.focus=first?first.id:null; state.fixFocus=state.fixFocus&&open.some(function(f){return f.id===state.fixFocus;})?state.fixFocus:(first?first.id:null);
  renderAll(true);
  hook('afterScan', state.scans[state.scans.length-1]);
  showView(state.scans.length>1?'proof':'overview');
  toast(STATUS_LABEL[r.status]+': '+open.length+' findings in '+r.coverage.analyzed+' file'+(r.coverage.analyzed===1?'':'s')+'.');
}
function onScanError(id,msg){ var s=state.scanning; if (!s || s.id!==id) return; state.scanning=null; lockUI(false); hideProgress();
  $('r-status').innerHTML='<span class="pill bad">Scan failed</span> '+esc(msg)+' Your previous results are unchanged.'; logEvent('warn','Scan failed'); toast('Scan failed. Your previous results are unchanged.'); }
function cancelScan(){ if (!state.scanning) return; state.scanning=null; killWorker(); lockUI(false); hideProgress();
  $('r-status').innerHTML='<span class="pill">Scan cancelled</span> No partial results were kept.'+(current()?' Showing the previous scan.':''); logEvent('warn','Scan cancelled'); toast('Scan cancelled. No partial results were kept.'); }
$('run').addEventListener('click',run);
$('cancel-scan').addEventListener('click',cancelScan);

/* ---------- import ---------- */
function importFiles(list){
  if (state.scanning) return;
  var arr=Array.prototype.slice.call(list||[]); if (!arr.length) return;
  var cands=[], zipJobs=[], notes=[], gen=state.gen, nz=0;
  var root=arr[0].webkitRelativePath ? arr[0].webkitRelativePath.split('/')[0] : (arr.length===1 ? arr[0].name.replace(/\.zip$/i,'') : 'Uploaded files');
  arr.forEach(function(f){ var p=f.webkitRelativePath ? f.webkitRelativePath.split('/').slice(1).join('/') : f.name;
    if (/\.zip$/i.test(p)){
      if (++nz>MAX_ARCHIVES){ notes.push({path:p,reason:'too-many-archives'}); return; }
      if (f.size>E.LIMITS.maxZipBytes){ notes.push({path:p,reason:'zip-too-large'}); return; }
      zipJobs.push(f.arrayBuffer().then(function(buf){ return E.readZip(buf); }).then(function(z){ return {entries:z.entries.map(function(en){ return {path:en.path,size:en.size,read:en.read}; }), rejected:z.rejected}; },
        function(err){ return {entries:[], rejected:[{path:p, reason:(err&&err.message)||'zip-corrupt'}]}; }));
    } else cands.push({path:p, size:f.size, read:function(){ return f.text(); }});
  });
  showImport('Reading '+arr.length+' item'+(arr.length>1?'s':'')+'…');
  Promise.all(zipJobs).then(function(zs){
    zs.forEach(function(z){ cands=cands.concat(z.entries); notes=notes.concat(z.rejected); });
    var v=E.validateIncoming(cands); notes=notes.concat(v.skipped);
    return readAll(v.keep, notes);
  }).then(function(files){
    if (gen!==state.gen) return;
    hideImport();
    var p={ name:root, files:files, skipped:notes };
    if (!files.length){ toast('No supported source files found. Nothing was changed. '+skippedSummary(notes)); showImport('Import found nothing to scan: 0 accepted, '+notes.length+' skipped. '+skippedSummary(notes), true); return; }
    var untouched=!state.files.length || state.demo;
    if (untouched) return applyImport(p,'replace');
    state.pending=p;
    showChoice(files.length+' file'+(files.length>1?'s':'')+' accepted from “'+p.name+'”'+(notes.length?', '+notes.length+' skipped':'')+'. '+skippedSummary(notes)+' Your current project “'+state.name+'” has '+state.files.length+' file'+(state.files.length>1?'s':'')+(state.scans.length?' and scan results':'')+'.',
      [['replace','Replace project'],['add','Add to project'],['cancel','Cancel']]);
  }).catch(function(){ hideImport(); toast('Import failed. Your current project was not changed.'); });
}
function readAll(keep, notes){
  var out=[], i=0, total=0;
  function next(){
    if (i>=keep.length) return Promise.resolve(out);
    var c=keep[i++];
    if (i%5===0) showImport('Reading '+i+' of '+keep.length+' files…');
    return Promise.resolve().then(function(){ return c.read(); }).then(function(t){
      t=String(t);
      if (!t.trim()) notes.push({path:c.path,reason:'empty'});
      else if (E.isBinary(t)) notes.push({path:c.path,reason:'binary'});
      else if (total+t.length>E.LIMITS.maxTotalBytes) notes.push({path:c.path,reason:'over-total-size'});
      else { total+=t.length; out.push({name:c.path, code:t}); }
    }, function(err){ notes.push({path:c.path, reason:(err&&/zip/.test(err.message))?err.message:'read-error'}); })
    .then(function(){ return i%20===0 ? new Promise(function(r){ setTimeout(r,0); }).then(next) : next(); });
  }
  return next();
}
function skippedSummary(notes){ if (!notes.length) return ''; var by={}; notes.forEach(function(n){ var r=REASON[n.reason]||n.reason; by[r]=(by[r]||0)+1; });
  return 'Skipped '+notes.length+': '+Object.keys(by).map(function(k){ return by[k]+' '+k; }).join(', ')+'.'; }
function showImport(m,stay){ var el=$('import-status'); el.hidden=false; el.textContent=m; el.classList.toggle('stay',!!stay); }
function hideImport(){ var el=$('import-status'); if (!el.classList.contains('stay')) el.hidden=true; }
function newProject(name, files, demo){
  state.gen++; state.files=files; state.name=name; state.demo=!!demo; state.scans=[]; state.baseline=0; state.dismissed={}; state.selected={}; state.focus=null; state.fixFocus=null; state.proposal=null;
  state.patches=[]; state.importSkipped=[]; state.pending=null; state.repair=null; hook('reset'); $('choice').hidden=true; $('import-status').classList.remove('stay'); $('import-status').hidden=true;
}
function applyImport(p, mode, conflict){
  var merged=E.mergeProject(state.files, p.files, mode, conflict);
  if (mode==='replace'){ newProject(p.name, merged.files, false); state.importSkipped=p.skipped.slice(); }
  else { state.files=merged.files; state.demo=false; state.importSkipped=state.importSkipped.concat(p.skipped); if (/^Demo project/.test(state.name)) state.name=p.name; }
  state.pending=null; $('choice').hidden=true;
  openFile(0); renderAll();
  var s=merged.summary, msg= mode==='replace' ? p.files.length+' file'+(p.files.length>1?'s':'')+' accepted.' : s.added+' added'+(s.replaced?', '+s.replaced+' replaced':'')+(s.renamed?', '+s.renamed+' renamed':'')+(s.kept?', '+s.kept+' existing kept':'')+'.';
  logEvent('import','Imported “'+p.name+'”: '+msg+(p.skipped.length?' '+p.skipped.length+' skipped.':''));
  toast(msg+' '+skippedSummary(p.skipped)+' Press Scan project.');
  if (p.skipped.length) showImport(msg+' '+skippedSummary(p.skipped)+' Details are in Overview → Coverage after a scan.', true);
}
function showChoice(msg, buttons){
  $('choice-msg').textContent=msg;
  $('choice-btns').innerHTML=buttons.map(function(b,i){ return '<button class="btn '+(i===0?'btn-solid':'btn-ghost')+' btn-sm" data-ch="'+b[0]+'">'+esc(b[1])+'</button>'; }).join('');
  if (state.view!=='source') showView('source');
  $('choice').hidden=false; $('choice-btns').querySelector('button').focus();
}
$('choice').addEventListener('click',function(e){
  var b=e.target.closest('[data-ch]'); if (!b) return; var c=b.dataset.ch, p=state.pending;
  if (c==='cancel'){ state.pending=null; $('choice').hidden=true; toast('Cancelled. Nothing was changed.'); return; }
  if (c==='demo'){ $('choice').hidden=true; loadDemo(true); return; }
  if (!p) return;
  if (c==='replace') return applyImport(p,'replace');
  if (c==='add'){
    var clash=E.conflicts(state.files,p.files);
    if (!clash.length) return applyImport(p,'add');
    showChoice(clash.length+' incoming file'+(clash.length>1?'s have':' has')+' the same path as a file already in “'+state.name+'”'+(clash.length<=3?' ('+clash.map(function(f){return f.name;}).join(', ')+')':'')+'. Nothing is overwritten unless you choose to.',
      [['keep','Keep existing'],['overwrite','Replace those files'],['rename','Rename incoming'],['cancel','Cancel']]); return; }
  applyImport(p,'add',c==='overwrite'?'replace':c);
});
$('up-folder').addEventListener('change',function(e){ importFiles(e.target.files); e.target.value=''; });
$('up-files').addEventListener('change',function(e){ importFiles(e.target.files); e.target.value=''; });
['dragenter','dragover'].forEach(function(t){ ed.addEventListener(t,function(e){ e.preventDefault(); if (!state.scanning) ed.classList.add('drag'); }); });
['dragleave','drop'].forEach(function(t){ ed.addEventListener(t,function(e){ e.preventDefault(); ed.classList.remove('drag'); }); });
ed.addEventListener('drop',function(e){ if (e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files.length) importFiles(e.dataTransfer.files); });
window.addEventListener('dragover',function(e){ e.preventDefault(); });
window.addEventListener('drop',function(e){ if (e.target&&e.target.closest('#editor')) return; e.preventDefault(); if (e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files.length) importFiles(e.dataTransfer.files); });
$('new-file').addEventListener('click',function(){ if (state.scanning) return;
  if (state.demo && !state.scans.length) newProject('Pasted code',[],false);
  var n=1; while (state.files.some(function(f){return f.name==='pasted-'+n+'.js';})) n++;
  state.files.push({name:'pasted-'+n+'.js',code:''}); openFile(state.files.length-1); renderAll(); code.focus(); toast('Paste your code, rename the file if needed, then press Scan project.'); });
function loadDemo(force){
  if (state.scanning) return;
  var hasWork=state.files.length && !(state.demo && !state.scans.length) || state.scans.length;
  if (hasWork && !force){ state.pending=null; showChoice('Loading the demo replaces “'+state.name+'” and its results in this tab.',[['demo','Replace with demo'],['cancel','Cancel']]); return; }
  newProject(DEMO_NAME, SF.demoVuln(), true); openFile(0); renderAll(); logEvent('import','Loaded the demo project (prepared example data)'); toast('Demo project loaded: 3 prepared files with known issues.');
}
$('load-demo').addEventListener('click',function(){ loadDemo(false); });
$('load-fixed').addEventListener('click',function(){
  SF.demoFixed().forEach(function(nf){ var f=state.files.find(function(x){return x.name===nf.name;}); if (f) f.code=nf.code; });
  state.name=DEMO_NAME; openFile(state.active); $('load-fixed').hidden=true; $('fixed-note').hidden=false; checkStale(); renderTree();
  logEvent('patch','Loaded the prepared patched demo files (example, not generated by SecureFlow)');
  toast('Prepared patched demo loaded. Press Scan project to compare.'); $('run').focus();
});

/* ---------- Clear project & data ---------- */
var dlg=$('clear-dlg');
$('clear-btn').addEventListener('click',function(){
  var has=state.files.length||state.scans.length;
  if (!has){ clearAll(); return; }
  $('dlg-text').textContent='This removes '+state.files.length+' file'+(state.files.length===1?'':'s')+(state.scans.length?', '+state.scans.length+' scan result'+(state.scans.length>1?'s':''):'')+(state.patches.length?', '+state.patches.length+' applied patch'+(state.patches.length>1?'es':''):'')+(state.scanning?' and stops the running scan':'')+' from this tab. Files on your computer are not touched.';
  if (dlg.showModal) dlg.showModal(); else if (window.confirm && confirm($('dlg-text').textContent)) clearAll();
});
$('dlg-cancel').addEventListener('click',function(){ dlg.close(); });
$('dlg-confirm').addEventListener('click',function(){ dlg.close(); clearAll(); });
function clearAll(){
  if (state.scanning){ state.scanning=null; lockUI(false); hideProgress(); }
  killWorker(); revokeAll();
  newProject('Untitled project',[],false); state.events=[];
  code.value=''; $('fname').value=''; hideHL(); renderGutter(); ed.classList.remove('scanning');
  $('fixed-note').hidden=true; $('load-fixed').hidden=true;
  renderAll(); showView('overview');
  toast('Cleared. Files, results, patches and history were removed from this tab. Your original files were not touched.');
}
SF.clearAll=clearAll;

/* ---------- verification ---------- */
var STATE_LABEL=E.STATE_LABEL;
function verification(){ if (state.scans.length<2) return null; var b=state.scans[Math.min(state.baseline,state.scans.length-2)], c=current();
  var both=!!(b.ai&&c.ai), keep=function(f){ return both || f.source!=='ai'; };   // AI findings are compared only when both scans had an AI check
  var a={ findings:openFindings(b.result.findings).filter(keep), files:b.files }, n={ findings:openFindings(c.result.findings).filter(keep), files:c.files };
  var v=E.compareScans(a,n); v.base=b; v.cur=c; v.score=E.scoreChange(a.findings,n.findings,v); return v; }

/* ---------- render: all ---------- */
function renderAll(justScanned){ renderTree(); updateMeta(); checkStale(); renderStatus(); renderOverview(justScanned); renderNavCounts();
  if (state.view==='findings') renderFindingsView(); if (state.view==='fix') renderFix(); if (state.view==='proof'){ renderVerify(); renderTimeline(); }
  if (state.view==='ready') renderReady(); if (state.view==='reports') renderReports(); if (state.view==='trust') renderTrust(); if (state.view==='memory') hook('memory'); hook('afterRender'); }
function renderNavCounts(){ var c=current(), open=c?openFindings(c.result.findings):[], cnt=E.counts(open);
  $('n-f').textContent=c?open.length:''; $('n-f').classList.toggle('hot',!!(cnt.critical||cnt.high));
  $('n-p').textContent=state.patches.filter(function(p){return !p.undone;}).length||''; var v=verification(); $('n-v').textContent=v?(v.summary.gone+'↓ '+v.summary.new+'↑'):'';
  ['exp-json','exp-md','copy-md','exp-html','btn-export-fixed-zip'].forEach(function(id){ if ($(id)) $(id).disabled=!c; });
  var demoVulnLoaded=SF.layers.every(function(L){ return state.files.some(function(f){ return f.name===L.file && f.code===L.vuln; }); });
  $('load-fixed').hidden=!(c&&demoVulnLoaded);
}
function renderStatus(){
  var c=current();
  if (!c){ $('r-status').innerHTML='<span class="pill">Not scanned</span> '+(state.files.length?state.files.length+' file'+(state.files.length>1?'s':'')+' ready. Press Scan project.':'Add code to begin.'); return; }
  var r=c.result, cov=r.coverage;
  $('r-status').innerHTML='<span class="pill '+(r.status==='complete'?'ok':'warn')+'">'+STATUS_LABEL[r.status]+'</span> '+cov.analyzed+'/'+cov.imported+' files · '+cov.lines+' lines · '+cov.durationMs+' ms · scan '+state.scans.length+(state.demo||/^Demo project/.test(state.name)?' · <b class="demo-tag">demo data</b>':'');
}
function renderFailed(r){
  $('r-status').innerHTML='<span class="pill bad">Scan failed</span> '+r.coverage.imported+' file'+(r.coverage.imported===1?'':'s')+' imported, 0 analysed. '+esc(skippedSummary(r.coverage.skipped));
  $('ov-empty').hidden=false; $('ov-results').hidden=true;
}

/* ---------- OVERVIEW + scan-completion moment ---------- */
function countUp(el,to){ if (RM){ el.textContent=to; return; } var t0=performance.now(); (function f(t){ var p=Math.min(1,(t-t0)/700); el.textContent=Math.round(to*ease(p)); if (p<1) requestAnimationFrame(f); })(t0); }
function renderOverview(justScanned){
  var c=current(); $('ov-empty').hidden=!!c; $('ov-results').hidden=!c;
  if (!c) return;
  var r=c.result, fs=openFindings(r.findings), cnt=E.counts(fs), v=E.verdict(fs,r.status), sc=E.score(fs);
  SEVS.forEach(function(k){ if (justScanned) countUp($('c-'+k),cnt[k]); else $('c-'+k).textContent=cnt[k]; });
  smallGauge.set(sc,'RISK / 100');
  var label=r.status!=='complete'?'Assessment Incomplete':cnt.critical?'Critical Issues Detected':(cnt.high||cnt.medium)?'Findings Detected':(cnt.low||cnt.info)?'Review Recommended':'No Supported Patterns Detected';
  $('verdict').innerHTML='<span class="eyebrow" style="margin-bottom:6px">'+esc(label)+'</span>'+esc(v.title)+'<small>'+esc(v.detail)+'</small>';
  var tot=fs.length||1;
  $('sevbar').innerHTML=fs.length?SEVS.filter(function(k){return cnt[k];}).map(function(k){ return '<i class="sb-'+k+'" style="flex:'+cnt[k]/tot+'" title="'+cnt[k]+' '+k+'"></i>'; }).join(''):'';
  $('sevbar').setAttribute('aria-label','Severity distribution: '+SEVS.map(function(k){ return cnt[k]+' '+k; }).join(', '));
  renderCoverage(r);
  renderRiskMap(c, fs);
  // priorities
  var top=fs.slice().sort(function(a,b){ return metaOf(a).priority.localeCompare(metaOf(b).priority) || E.SEV_ORDER[a.severity]-E.SEV_ORDER[b.severity]; }).slice(0,4);
  $('priority').innerHTML=top.length?top.map(function(f){ var m=metaOf(f);
    return '<li><span class="p">'+m.priority+'</span><span><b>'+esc(f.title)+'</b><span class="pl">'+esc(f.file)+':'+f.line+' · '+esc(E.PRIORITY_TEXT[m.priority])+'</span></span><span class="acts"><button class="btn btn-ghost btn-sm" data-open="'+f.id+'">Evidence</button><button class="btn btn-ghost btn-sm" data-fixit="'+f.id+'">Fix</button></span></li>'; }).join('')
    :'<li><span class="p">—</span><span>No open findings from the enabled rules. That is not proof of security: review authentication, authorisation and data access by hand.</span></li>';
  var crit=fs.find(function(f){ return f.severity==='critical'; }) || fs[0];
  $('next-action').innerHTML=crit?'<button class="btn btn-solid" data-open="'+crit.id+'">Next: review “'+esc(crit.title)+'” →</button>':'<button class="btn btn-ghost" data-view-go="ready">Next: check production readiness →</button>';
  if (justScanned){ var el=$('ov-results'); el.classList.remove('just-done'); void el.offsetWidth; el.classList.add('just-done'); }
}
function renderCoverage(r){
  var cov=r.coverage, excl=cov.skipped.length+state.importSkipped.length;
  $('coverage-sum').textContent='Coverage: '+cov.analyzed+' of '+cov.imported+' files analysed'+(excl?', '+excl+' excluded':'')+(cov.failed.length?', '+cov.failed.length+' failed':'')+' · '+cov.rules+' rules';
  var skippedAll=state.importSkipped.concat(cov.skipped);
  $('coverage-body').innerHTML='<dl class="cov"><div><dt>Imported</dt><dd>'+cov.imported+'</dd></div><div><dt>Analysed</dt><dd>'+cov.analyzed+'</dd></div><div><dt>Excluded</dt><dd>'+excl+'</dd></div><div><dt>Failed</dt><dd>'+cov.failed.length+'</dd></div><div><dt>Rules run</dt><dd>'+cov.rules+'</dd></div><div><dt>Duration</dt><dd>'+cov.durationMs+' ms</dd></div></dl>'+
    (skippedAll.length?'<ul class="skips">'+skippedAll.slice(0,200).map(function(s){ return '<li><span class="mono">'+esc(s.path)+'</span> · '+esc(REASON[s.reason]||s.reason)+'</li>'; }).join('')+(skippedAll.length>200?'<li>… and '+(skippedAll.length-200)+' more</li>':'')+'</ul>':'')+
    (cov.failed.length?'<ul class="skips">'+cov.failed.map(function(f){ return '<li><span class="mono">'+esc(f.path)+'</span> · failed</li>'; }).join('')+'</ul>':'')+
    '<p class="lim">Not checked: dependency vulnerabilities (no CVE data), build and runtime behaviour, hosting configuration. '+E.LIMITATIONS.map(esc).join(' ')+'</p>';
}
var LAYER_LABEL={client:'Client / browser',server:'Server / API',data:'Data',config:'Config',other:'Other'};
function renderRiskMap(c, fs){
  var files=filesArr(c.files), g=E.dependencyGraph(files), worst={}, n={};
  fs.forEach(function(f){ n[f.file]=(n[f.file]||0)+1; if (!worst[f.file] || E.SEV_ORDER[f.severity]<E.SEV_ORDER[worst[f.file]]) worst[f.file]=f.severity; });
  var nodes=g.nodes.slice().sort(function(a,b){ return (n[b.file]||0)-(n[a.file]||0); }), shown=nodes.slice(0,36), cols={};
  shown.forEach(function(x){ (cols[x.layer]=cols[x.layer]||[]).push(x); });
  var order=['client','server','data','config','other'].filter(function(k){ return cols[k]; });
  var shownSet={}; shown.forEach(function(x){ shownSet[x.file]=1; });
  var edges=g.edges.filter(function(e){ return shownSet[e.from]&&shownSet[e.to]; });
  $('riskmap').innerHTML='<svg class="rm-edges" id="rm-edges" aria-hidden="true"></svg>'+order.map(function(k){ return '<div class="rm-col"><h4>'+LAYER_LABEL[k]+'</h4>'+cols[k].map(function(x){ var w=worst[x.file];
    return '<button class="rm-node'+(w?' w-'+w:'')+'" data-file="'+esc(x.file)+'" title="'+esc(x.file)+'"><span class="nm">'+esc(x.file.split('/').pop())+'</span><span class="b">'+(n[x.file]||0)+'</span></button>'; }).join('')+'</div>'; }).join('')+
    '<ul class="sr-only">'+shown.map(function(x){ return '<li>'+esc(x.file)+': '+(n[x.file]||0)+' findings, layer '+LAYER_LABEL[x.layer]+'</li>'; }).join('')+edges.map(function(e){ return '<li>'+esc(e.from)+' imports '+esc(e.to)+'</li>'; }).join('')+'</ul>';
  $('riskmap').dataset.edges=JSON.stringify(edges);
  var note=(nodes.length>shown.length?'Showing the '+shown.length+' files with the most findings of '+nodes.length+'. ':'')+(edges.length?edges.length+' import relationship'+(edges.length>1?'s':'')+' found.':'No relative imports between uploaded files were found, so no relationships are drawn. That does not mean the files are unrelated.');
  var old=$('riskmap').nextElementSibling; if (old&&old.classList.contains('rm-note')) old.remove();
  $('riskmap').insertAdjacentHTML('afterend','<p class="rm-note">'+esc(note)+'</p>');
  requestAnimationFrame(drawEdges);
}
function drawEdges(){
  var map=$('riskmap'), svg=$('rm-edges'); if (!map||!svg||$('ov-results').hidden||map.offsetParent===null) return;
  var edges=[]; try { edges=JSON.parse(map.dataset.edges||'[]'); } catch(_){}
  var box=map.getBoundingClientRect(), d='';
  function node(f){ return map.querySelector('.rm-node[data-file="'+(window.CSS&&CSS.escape?CSS.escape(f):f)+'"]'); }
  edges.forEach(function(e){ var a=node(e.from), b=node(e.to); if (!a||!b) return; var ra=a.getBoundingClientRect(), rb=b.getBoundingClientRect();
    var x1=ra.right-box.left, y1=ra.top+ra.height/2-box.top, x2=rb.left-box.left, y2=rb.top+rb.height/2-box.top;
    if (rb.left<ra.left){ x1=ra.left-box.left; x2=rb.right-box.left; }
    var mx=(x1+x2)/2; d+='M'+x1+','+y1+' C'+mx+','+y1+' '+mx+','+y2+' '+x2+','+y2+' '; });
  svg.setAttribute('viewBox','0 0 '+box.width+' '+box.height); svg.innerHTML=d?'<path d="'+d+'"/>':'';
}
addEventListener('resize',function(){ if (state.view==='overview') drawEdges(); });
$('riskmap').addEventListener('click',function(e){ var b=e.target.closest('.rm-node'); if (!b) return; state.filters.file=b.dataset.file; state.filters.status='open'; showView('findings'); });
$('workspace').addEventListener('click',function(e){
  var o=e.target.closest('[data-open]'); if (o){ state.focus=o.dataset.open; state.filters.status='open'; showView('findings'); return; }
  var f=e.target.closest('[data-fixit]'); if (f){ state.fixFocus=f.dataset.fixit; state.proposal=null; showView('fix'); return; }
  var g=e.target.closest('[data-view-go]'); if (g){ showView(g.dataset.viewGo); }
});

/* ---------- FINDINGS: list + detail ---------- */
function buildFilters(all){
  function opts(id, vals, label){ var sel=$(id), cur=state.filters[sel.dataset.k]; if (cur && vals.indexOf(cur)<0){ state.filters[sel.dataset.k]=''; cur=''; }
    sel.innerHTML='<option value="">'+label+'</option>'+vals.map(function(v){ return '<option value="'+esc(v)+'"'+(v===cur?' selected':'')+'>'+esc(v)+'</option>'; }).join(''); }
  function uniq(k){ var o={}; all.forEach(function(f){ o[f[k]]=1; }); return Object.keys(o); }
  opts('f-sev', SEVS.filter(function(s){ return all.some(function(f){return f.severity===s;}); }), 'All severities');
  opts('f-cat', uniq('category').sort(), 'All categories');
  opts('f-file', uniq('file').sort(), 'All files');
  opts('f-conf', ['high','medium','low'].filter(function(s){ return all.some(function(f){return f.confidence===s;}); }), 'Any confidence');
  $('f-status').value=state.filters.status; $('f-sort').value=state.filters.sort;
  $('f-status').querySelectorAll('[data-needs-v]').forEach(function(o){ o.disabled=state.scans.length<2; });
}
['f-sev','f-cat','f-file','f-conf','f-status','f-sort'].forEach(function(id){ $(id).addEventListener('change',function(e){ state.filters[e.target.dataset.k]=e.target.value; renderFindingsView(); }); });
function visibleFindings(){
  var c=current(); if (!c) return {list:[],vstate:{}};
  var F=state.filters, ver=verification(), vstate={};
  if (ver) ver.rows.forEach(function(row){ if (row.cur) vstate[row.cur.id]=row.state; });
  var list=c.result.findings.filter(function(f){
    var dis=!!state.dismissed[f.id];
    if (F.status==='open' && dis) return false; if (F.status==='dismissed' && !dis) return false;
    if ((F.status==='new'||F.status==='still') && (dis || vstate[f.id]!==F.status)) return false;
    return (!F.sev||f.severity===F.sev) && (!F.cat||f.category===F.cat) && (!F.file||f.file===F.file) && (!F.conf||f.confidence===F.conf); });
  var so=E.SEV_ORDER, co={high:0,medium:1,low:2};
  list.sort(F.sort==='file' ? function(a,b){ return a.file.localeCompare(b.file)||a.line-b.line; } :
            F.sort==='confidence' ? function(a,b){ return co[a.confidence]-co[b.confidence]||so[a.severity]-so[b.severity]; } :
            function(a,b){ return so[a.severity]-so[b.severity]||co[a.confidence]-co[b.confidence]||a.file.localeCompare(b.file)||a.line-b.line; });
  return { list:list, vstate:vstate };
}
function renderFindingsView(){
  var c=current();
  $('filters').hidden=!c;
  if (!c){ $('list').innerHTML='<div class="empty">Run a scan to see findings.</div>'; $('detail').innerHTML=''; return; }
  buildFilters(c.result.findings);
  var res=visibleFindings(), list=res.list, vs=res.vstate;
  var nsel=Object.keys(state.selected).length; $('copy-selected').disabled=!nsel; $('copy-selected').textContent='Copy prompt for selected ('+nsel+')';
  $('sel-all').checked=list.length>0 && list.every(function(f){ return state.selected[f.id]; });
  $('f-count').textContent=list.length+' shown';
  if (!list.length){ $('list').innerHTML='<div class="empty">'+(!openFindings(c.result.findings).length&&state.filters.status==='open'?'No findings detected by the enabled rules. That is not proof of security.':'No findings match these filters.')+'</div>'; $('detail').innerHTML='<div class="empty">Nothing selected.</div>'; return; }
  if (!list.some(function(f){ return f.id===state.focus; })) state.focus=list[0].id;
  $('list').innerHTML=list.map(function(f){ var dis=state.dismissed[f.id];
    return '<div class="frow'+(f.id===state.focus?' on':'')+(dis?' dismissed':'')+'" data-id="'+f.id+'" role="option" aria-selected="'+(f.id===state.focus)+'" tabindex="'+(f.id===state.focus?0:-1)+'">'+
      '<input type="checkbox" class="f-sel" aria-label="Select '+esc(f.title)+'"'+(state.selected[f.id]?' checked':'')+'>'+
      '<span class="sev sev-'+f.severity+'">'+f.severity+'</span><span class="t">'+esc(f.title)+(dis?' <em class="dis">false positive</em>':'')+(vs[f.id]?'<span class="vtag v-'+vs[f.id]+'">'+STATE_LABEL[vs[f.id]]+'</span>':'')+(f.ai?'<span class="vtag v-ai">'+(f.source==='both'?'Engine + AI':'AI')+'</span>':'')+'</span>'+
      '<span class="l" title="'+esc(f.file)+':'+f.line+'">'+esc(f.file)+':'+f.line+' · '+esc(f.confidence)+' confidence</span></div>'; }).join('');
  renderDetail(c.result.findings.find(function(f){ return f.id===state.focus; }));
}
function flowHTML(f){
  var hv=hook('chain',f); if (hv) return hv;
  var m=metaOf(f); if (!m.flow.length) return '';
  return '<div class="flow" role="list" aria-label="Illustrative risk flow">'+m.flow.map(function(s,i){
    var cls=i===0?'obs':(i===m.flow.length-1?'hyp out':'hyp'), tag=i===0?'Observed in your code':(i===m.flow.length-1?'Illustrative consequence':'Illustrative step');
    return '<div class="st '+cls+'" role="listitem"><small>'+tag+'</small>'+esc(s)+'</div>'; }).join('')+'</div>'+
    '<p class="fine" style="margin-top:6px">Only the first step is evidence from your code (line '+f.line+'). The rest is an illustrative scenario, not a demonstrated attack. Text version: '+esc(m.flow.join(' → '))+'.</p>';
}
function renderDetail(f){
  var D=$('detail'); if (!f){ D.innerHTML=''; return; }
  var m=metaOf(f), dis=state.dismissed[f.id], pat=f.ai&&f.source==='ai'?{available:false}:E.proposePatch(f,state.files);
  D.innerHTML='<div class="d-h"><div class="chips"><span class="sev sev-'+f.severity+'">'+f.severity+'</span><span class="chip">'+esc(f.confidence)+' confidence</span><span class="chip prio" title="'+esc(E.PRIORITY_TEXT[m.priority])+'">'+m.priority+' · '+esc(E.PRIORITY_TEXT[m.priority])+'</span><span class="chip">'+esc(f.category)+'</span><span class="chip">'+esc(f.cwe)+'</span></div>'+
    '<h3>'+esc(f.title)+(dis?' <em class="dis">marked false positive</em>':'')+'</h3><span class="fine mono">'+esc(f.file)+':'+f.line+':'+f.column+' · '+f.id+' · '+(f.source==='ai'?'AI finding, quoted from your code and challenged by a second review':f.source==='both'?'engine rule confirmed by the AI review':'static heuristic, not verified by a test')+'</span></div>'+(hook('detailTop',f)||'')+
    '<div class="d-sec"><h4>Evidence (secrets masked)</h4><div class="ev">'+f.evidence.map(function(e){ return '<div'+(e.hit?' class="hit"':'')+'><span>'+e.n+'</span>'+esc(e.text)+'</div>'; }).join('')+'</div></div>'+
    '<div class="d-sec"><h4>How this could play out</h4>'+flowHTML(f)+'</div>'+
    '<div class="d-sec"><h4>Potential impact if exploitable (not observed damage)</h4><div class="cia">'+['confidentiality','integrity','availability'].map(function(k){ return '<div class="'+m.impact[k]+'"><b>'+m.impact[k]+'</b>'+k+'</div>'; }).join('')+'</div>'+
      '<p class="fine" style="margin-top:6px">Business view: '+(m.impact.confidentiality==='high'?'customer or company data could be exposed. ':'')+(m.impact.integrity==='high'?'records or actions could be changed by someone who shouldn’t. ':'')+(m.impact.availability==='high'?'the service could be disrupted. ':'')+'These are possibilities that depend on how the code is deployed; SecureFlow has not observed any breach or loss.</p></div>'+
    '<div class="d-sec"><h4>Why it may be risky</h4><p>'+esc(f.why)+'</p></div>'+
    '<div class="d-sec"><h4>What could change this result</h4><p>'+esc(m.context)+'</p></div>'+
    '<div class="d-sec"><h4>Recommended fix</h4><p>'+esc(f.fix)+'</p><p><b>Regression test:</b> '+esc(f.tests)+'</p></div>'+
    '<div class="d-sec"><h4>Detection limits</h4><p>'+esc(m.limits)+'</p></div>'+
    '<div class="d-sec"><h4>References</h4><ul class="refs">'+m.refs.map(function(r){ return '<li><a href="'+esc(r.url)+'" target="_blank" rel="noopener noreferrer">'+esc(r.title)+'</a></li>'; }).join('')+'</ul></div>'+
    (dis?'<p class="dis-note">Marked as a false positive: “'+esc(dis)+'”. Excluded from the score for this session.</p>':'')+
    '<div class="d-actions"><button class="btn btn-solid btn-sm" data-act="copy">Copy repair prompt</button><button class="btn btn-ghost btn-sm" data-act="jump">Show in source</button>'+
    '<button class="btn btn-ghost btn-sm" data-fixit="'+f.id+'">Open in Fix Studio'+(pat.available?' (patch available)':'')+'</button>'+
    '<button class="btn btn-crimson btn-sm" data-act="deploy-gh">🚀 Deploy Fix to GitHub →</button>'+
    (dis?'<button class="btn btn-ghost btn-sm" data-act="restore">Restore finding</button>':'<button class="btn btn-ghost btn-sm" data-act="fp">Mark false positive</button>')+'</div>'+
    '<form class="fp-form" hidden><label>Why is this a false positive? <input name="reason" maxlength="200" required placeholder="e.g. test fixture, value is not a real key"></label><button class="btn btn-solid btn-sm">Save</button><button type="button" class="btn btn-ghost btn-sm" data-act="fp-cancel">Cancel</button></form>';
  D.dataset.id=f.id; hook('detail',f,D);
}
function findById(id){ var c=current(); return c && c.result.findings.find(function(f){ return f.id===id; }); }
$('list').addEventListener('click',function(e){
  var row=e.target.closest('.frow'); if (!row) return; var id=row.dataset.id;
  if (e.target.classList.contains('f-sel')){ if (e.target.checked) state.selected[id]=1; else delete state.selected[id]; var n=Object.keys(state.selected).length; $('copy-selected').disabled=!n; $('copy-selected').textContent='Copy prompt for selected ('+n+')'; return; }
  state.focus=id; renderFindingsView(); var r=$('list').querySelector('[data-id="'+id+'"]'); if (r) r.focus();
});
$('list').addEventListener('keydown',function(e){ var rows=Array.prototype.slice.call($('list').querySelectorAll('.frow')), i=rows.findIndex(function(r){ return r.dataset.id===state.focus; });
  if (e.key==='ArrowDown'||e.key==='ArrowUp'){ e.preventDefault(); var n=rows[clamp(i+(e.key==='ArrowDown'?1:-1),0,rows.length-1)]; if (n){ state.focus=n.dataset.id; renderFindingsView(); $('list').querySelector('[data-id="'+state.focus+'"]').focus(); } }
  if ((e.key===' '||e.key==='Enter') && e.target.classList.contains('frow')){ e.preventDefault(); var cb=e.target.querySelector('.f-sel'); cb.checked=!cb.checked; cb.dispatchEvent(new Event('click',{bubbles:true})); if (cb.checked) state.selected[state.focus]=1; else delete state.selected[state.focus]; renderFindingsView(); } });
$('detail').addEventListener('click',function(e){
  var act=e.target.closest('[data-act]'); if (!act) return; var id=$('detail').dataset.id, f=findById(id); if (!f) return; var a=act.dataset.act;
  if (a==='copy') copy(E.promptFor(f),'Repair prompt copied (secrets masked). Paste it into your AI tool. It is a prompt, not a verified patch.');
  if (a==='jump') jumpTo(f);
  if (a==='deploy-gh'){
    if (isUserLoggedIn()) window.location.href = 'dashboard.html#repos';
    else openAuthDialog('dashboard.html#billing');
    return;
  }
  if (a==='fp'){ var form=$('detail').querySelector('.fp-form'); form.hidden=false; form.querySelector('input').focus(); }
  if (a==='fp-cancel') $('detail').querySelector('.fp-form').hidden=true;
  if (a==='restore'){ delete state.dismissed[id]; logEvent('edit','Restored a finding previously marked false positive'); renderAll(); renderFindingsView(); toast('Finding restored.'); }
});
$('detail').addEventListener('submit',function(e){ e.preventDefault(); var id=$('detail').dataset.id, reason=e.target.reason.value.trim(); if (!reason) return;
  state.dismissed[id]=reason.slice(0,200); delete state.selected[id]; logEvent('edit','Marked a finding as false positive: “'+reason.slice(0,60)+'”'); renderAll(); renderFindingsView(); toast('Marked as a false positive for this session. It no longer counts toward the score.'); });
$('sel-all').addEventListener('change',function(e){ visibleFindings().list.forEach(function(f){ if (e.target.checked) state.selected[f.id]=1; else delete state.selected[f.id]; }); renderFindingsView(); });
$('copy-selected').addEventListener('click',function(){ var c=current(); if (!c) return; var fs=c.result.findings.filter(function(f){ return state.selected[f.id]; }); if (!fs.length) return;
  copy(E.batchPrompt(fs),'Combined repair prompt for '+fs.length+' finding'+(fs.length>1?'s':'')+' copied (secrets masked).'); });
function jumpTo(f){
  var i=state.files.findIndex(function(x){return x.name===f.file;});
  if (i<0){ toast(f.file+' is no longer in the project.'); return; }
  showView('source'); openFile(i);
  var ls=code.value.split(/\r\n|\r|\n/), st=0; for (var k=0;k<f.line-1&&k<ls.length;k++) st+=ls[k].length+1;
  code.focus({preventScroll:true}); code.setSelectionRange(st,st+(ls[f.line-1]||'').length); code.scrollTop=Math.max(0,(f.line-6)*20); gutter.scrollTop=code.scrollTop;
  hlLine=f.line; placeHL();
  if (isStale()) toast('This project changed after the scan, so the line may have moved. Rescan to refresh.');
}

/* ---------- FIX STUDIO ---------- */
function renderFix(){
  var c=current(), L=$('fix-list'), D=$('fix-detail');
  if (!c){ L.innerHTML='<div class="empty">Scan first. Fix Studio works from your findings.</div>'; D.innerHTML=fixIntro(); renderPaid(); return; }
  var fs=openFindings(c.result.findings);
  if (!fs.length){ L.innerHTML='<div class="empty">No open findings.</div>'; D.innerHTML=fixIntro(); renderPaid(); return; }
  if (!fs.some(function(f){ return f.id===state.fixFocus; })) state.fixFocus=fs[0].id;
  L.innerHTML=fs.map(function(f){ var p=E.proposePatch(f,state.files), applied=state.patches.some(function(x){ return x.findingId===f.id && !x.undone; });
    return '<div class="frow'+(f.id===state.fixFocus?' on':'')+'" data-id="'+f.id+'" tabindex="0" role="button"><span></span><span class="sev sev-'+f.severity+'">'+f.severity+'</span><span class="t">'+esc(f.title)+' '+(applied?'<span class="tagp done">patch applied</span>':p.available?'<span class="tagp">patch available</span>':'<span class="tagp no">prompt only</span>')+'</span><span class="l">'+esc(f.file)+':'+f.line+'</span></div>'; }).join('');
  var f=fs.find(function(x){ return x.id===state.fixFocus; });
  var prop=state.proposal && state.proposal.findingId===f.id ? state.proposal : null;
  var h='<div class="fs-h"><div class="chips"><span class="sev sev-'+f.severity+'">'+f.severity+'</span><span class="chip">'+esc(f.confidence)+' confidence</span><span class="chip mono">'+esc(f.ruleId)+'</span></div><h3>'+esc(f.title)+'</h3><span class="fine mono">'+esc(f.file)+':'+f.line+'</span></div>'+
    '<div class="d-sec"><h4>Evidence</h4><div class="ev">'+f.evidence.map(function(e){ return '<div'+(e.hit?' class="hit"':'')+'><span>'+e.n+'</span>'+esc(e.text)+'</div>'; }).join('')+'</div></div>';
  if (!prop){
    var p=E.proposePatch(f,state.files);
    h+= p.available ? '<div class="d-actions"><button class="btn btn-solid btn-sm" data-fix-act="propose">Generate patch proposal</button><button class="btn btn-ghost btn-sm" data-fix-act="prompt">Copy repair prompt instead</button></div><p class="fine" style="margin-top:8px">Proposals come from fixed rewrite rules (no AI, nothing leaves the browser). You review the diff before anything changes.</p>'
      : '<div class="disclaim">'+esc(p.reason)+' A safe automatic rewrite needs context SecureFlow cannot see (validation, data flow, framework choices).</div><div class="d-actions"><button class="btn btn-solid btn-sm" data-fix-act="prompt">Copy repair prompt</button></div>';
  } else h+=proposalHTML(prop);
  var mine=state.patches.filter(function(x){ return x.file===f.file; });
  var appliedCount=state.patches.filter(function(x){ return !x.undone; }).length;
  if (appliedCount > 0) {
    h+='<div class="d-sec" style="background:rgba(200,150,60,0.08); border:1px solid var(--gold); border-radius:6px; padding:12px 16px; margin-top:12px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">' +
       '<div><h4 style="margin:0 0 2px; color:var(--gold);">Fixed Code Ready for Download</h4>' +
       '<p class="fine" style="margin:0;">'+appliedCount+' patch(es) applied to in-memory project files. Download complete project ZIP with manifest.</p></div>' +
       '<button class="btn btn-solid btn-sm" id="btn-fix-download-zip" style="background:var(--gold); color:#12100e; font-weight:700;">📦 Download Fixed Project (.zip)</button>' +
       '</div>';
  }
  if (state.patches.length) h+='<div class="d-sec"><h4>Patches in this session</h4><ul class="applied">'+state.patches.slice().reverse().map(function(x){ return '<li><span class="tagp '+(x.undone?'no':'done')+'">'+(x.undone?'undone':'applied')+'</span><span>'+esc(x.title)+' · <span class="mono">'+esc(x.file)+'</span>'+(x.edited?' · edited by you':'')+'</span>'+(x.undone?'':'<button class="btn btn-ghost btn-sm" data-undo="'+x.id+'">Undo</button>')+'</li>'; }).join('')+'</ul></div>';
  D.innerHTML=h; D.dataset.id=f.id;
  renderPaid();
}
function fixIntro(){
  var appliedCount = state.patches.filter(function(x){ return !x.undone; }).length;
  var zipBtn = appliedCount > 0 ? '<div style="margin-top:12px;"><button class="btn btn-solid btn-sm" id="btn-fix-download-zip" style="background:var(--gold); color:#12100e; font-weight:700;">📦 Download Fixed Project (.zip)</button></div>' : '';
  return '<div class="pad" style="padding:0">' +
    '<div style="margin-bottom:14px; padding:14px; border:1px solid var(--gold); background:rgba(200,150,60,0.08); border-radius:6px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">' +
      '<div><h4 style="margin:0 0 4px; color:var(--gold);">🚀 Automated GitHub Fix &amp; 1-Click Deploy</h4><p class="fine" style="margin:0;">Sign in to your dashboard, pay via Cashfree, link your repositories, and deploy clean fixes back to GitHub in 1 click.</p></div>' +
      '<button class="btn btn-solid btn-sm" id="btn-fix-to-dash">Sign In &amp; Deploy to GitHub →</button>' +
    '</div>' +
    '<h3>Fix Studio</h3><p class="fine" style="margin-top:6px">Pick a finding, review a proposed patch and its diff, then accept or reject it. Accepted patches change only the in-memory copy and can be undone. Rescan afterwards: ProofLoop compares the results.</p>' +
    zipBtn +
    '</div>';
}
function proposalHTML(prop){
  var file=state.files.find(function(x){ return x.name===prop.file; });
  var r=file?E.applyPatch(state.files,prop):{ok:false,error:'File not found.'};
  var diff=r.ok?E.diffLines(file.code, r.files.find(function(x){ return x.name===prop.file; }).code, 2):[];
  return '<div class="d-sec"><h4>Proposed change (not applied yet)</h4>'+
    (r.ok?'<div class="diff" role="table" aria-label="Proposed diff">'+diff.map(function(d){ return '<div class="'+(d.t==='-'?'m':d.t==='+'?'p':'')+'" role="row"><span>'+(d.a||'')+'</span><span>'+(d.b||'')+'</span><span>'+(d.t===' '?'':d.t)+'</span><code>'+esc(d.text)+'</code></div>'; }).join('')+'</div>':'')+
    '<p class="valid '+(r.ok?'ok':'bad')+'">'+(r.ok?'✓ Validated: the target line still matches the file, and the change applies cleanly.':'✗ '+esc(r.error))+'</p>'+
    '<div class="edit-box">'+prop.edits.map(function(e,i){ return '<label for="pe-'+i+'">'+(e.op==='replace'?'Replacement for line '+e.line:'Inserted line at '+e.line)+' (you can edit)</label><textarea id="pe-'+i+'" data-edit="'+i+'" spellcheck="false">'+esc(e.after)+'</textarea>'; }).join('')+'</div>'+
    '<p class="disclaim">'+esc(prop.note)+' '+esc(prop.disclaimer)+'</p>'+
    '<div class="d-actions"><button class="btn btn-solid btn-sm" data-fix-act="accept"'+(r.ok?'':' disabled')+'>Accept and apply to the in-memory copy</button><button class="btn btn-ghost btn-sm" data-fix-act="reject">Reject</button></div></div>';
}
$('fix-list').addEventListener('click',function(e){ var r=e.target.closest('.frow'); if (!r) return; state.fixFocus=r.dataset.id; state.proposal=null; renderFix(); });
$('fix-list').addEventListener('keydown',function(e){ if (e.key==='Enter'||e.key===' '){ var r=e.target.closest('.frow'); if (r){ e.preventDefault(); state.fixFocus=r.dataset.id; state.proposal=null; renderFix(); } } });
$('fix-detail').addEventListener('input',function(e){ var t=e.target.closest('[data-edit]'); if (!t||!state.proposal) return; state.proposal.edits[+t.dataset.edit].after=t.value; state.proposal.edited=true;
  var sel=t.selectionStart, id=t.id; renderFix(); var n=$(id); if (n){ n.focus(); n.setSelectionRange(sel,sel); } });
$('fix-detail').addEventListener('click',function(e){
  var u=e.target.closest('[data-undo]'); if (u){ undoPatch(u.dataset.undo); return; }
  if (e.target.closest('#btn-fix-download-zip')){ downloadFixedProjectZip(); return; }
  var b=e.target.closest('[data-fix-act]'); if (!b||state.scanning) return; var f=findById($('fix-detail').dataset.id); if (!f) return; var a=b.dataset.fixAct;
  if (a==='prompt') copy(E.promptFor(f),'Repair prompt copied (secrets masked). It is a prompt, not a verified patch.');
  if (a==='propose'){ var p=E.proposePatch(f,state.files); if (!p.available){ toast(p.reason); return; } state.proposal=p; logEvent('patch-proposed','Patch proposed for “'+f.title+'” in '+f.file); renderFix(); }
  if (a==='reject'){ logEvent('warn','Patch rejected for “'+f.title+'”'); state.proposal=null; renderFix(); toast('Proposal rejected. Nothing was changed.'); }
  if (a==='accept'){
    var prop=state.proposal, r=E.applyPatch(state.files,prop);
    if (!r.ok){ toast(r.error); return; }
    var before=state.files.find(function(x){ return x.name===prop.file; }).code, after=r.files.find(function(x){ return x.name===prop.file; }).code;
    var rec={ id:'p'+(state.patches.length+1), findingId:f.id, ruleId:f.ruleId, title:f.title, file:prop.file, kind:'deterministic rewrite', edited:!!prop.edited, undo:r.undo, diff:E.diffLines(before,after,1), at:new Date(), undone:false };
    state.patches.push(rec); state.files=r.files; state.proposal=null;
    var ai=state.files.findIndex(function(x){ return x.name===prop.file; }); if (state.active===ai) openFile(ai);
    if (state.demo){ state.demo=false; state.name=DEMO_NAME+' (patched)'; }
    logEvent('patch','Patch applied to '+prop.file+' for “'+f.title+'”'+(rec.edited?' (edited)':''));
    renderAll(); renderFix(); toast('Applied to the in-memory copy only. Press Scan project to check it with ProofLoop.');
  }
});
function undoPatch(id){
  var p=state.patches.find(function(x){ return x.id===id; }); if (!p||p.undone) return;
  var f=state.files.find(function(x){ return x.name===p.undo.file; });
  if (!f){ toast('That file is no longer in the project, so the patch cannot be undone.'); return; }
  var later=state.patches.filter(function(x){ return x.file===p.file && !x.undone && x.at>p.at; });
  if (later.length){ toast('Undo the later patch to '+p.file+' first.'); return; }
  f.code=p.undo.code; p.undone=true; var ai=state.files.indexOf(f); if (state.active===ai) openFile(ai);
  logEvent('patch','Patch undone in '+p.file); renderAll(); renderFix(); toast('Patch undone. The file is back to how it was before the patch.');
}

/* ---------- Paid repair (₹699, Cashfree TEST MODE via the SecureFlow Worker) ---------- */
var payCfg={ checked:false, available:false, data:null };
function serverMode(){ return /^https?:$/.test(location.protocol) && !/claude\.ai|claudeusercontent/.test(location.hostname); }
function api(method, path, body, token){
  var headers={'content-type':'application/json'}, auth=localStorage.getItem('sf_id_token');
  if (auth) headers.authorization='Bearer '+auth;
  if (token) headers['x-repair-token']=token;
  return fetch(path,{ method:method, headers:headers, body: body?JSON.stringify(body):undefined, credentials:'same-origin' })
    .then(function(r){ return r.json().catch(function(){ return {}; }).then(function(j){ j._status=r.status; return j; }); });
}
function projectApi(method,path,sessionToken,body,contentType){
  var headers={}, auth=localStorage.getItem('sf_id_token');
  if (auth) headers.authorization='Bearer '+auth;
  if (sessionToken) headers['x-project-session']=sessionToken;
  if (body!==undefined && contentType) headers['content-type']=contentType;
  var payload=contentType==='application/json'&&body!==undefined?JSON.stringify(body):body;
  return fetch(path,{method:method,headers:headers,body:payload,credentials:'same-origin'}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){j._status=r.status;return j;});});
}
function checkPay(){ if (payCfg.checked) return Promise.resolve(payCfg); payCfg.checked=true;
  if (!serverMode()) return Promise.resolve(payCfg);
  return api('GET','/api/pay/config').then(function(j){ if (j._status===200 && j.offers){ payCfg.available=true; payCfg.data=j; } return payCfg; }, function(){ return payCfg; }); }
var LIFE=[['draft','Draft'],['awaiting_consent','Awaiting consent'],['awaiting_payment','Awaiting payment'],['payment_confirmed','Payment confirmed'],['submitted','Submitted'],['in_review','In review'],['patch_ready','Patch ready'],['completed','Completed']];
var PAY_PROBLEM={ payments_not_configured:'the server has no Cashfree keys yet', live_payments_not_approved:'live payments are switched off until the owner approves them', sandbox_needs_test_credentials:'test mode needs Cashfree TEST credentials', project_storage_not_configured:'the server needs its secure project storage bucket before checkout can start' };
function renderPaid(){
  var host=$('fix-detail'); var old=$('paid'); if (old) old.remove();
  var div=document.createElement('div'); div.className='paid'; div.id='paid'; host.appendChild(div);
  checkPay().then(function(){ if (!$('paid')) return; paidInner($('paid')); });
}
function paidInner(el){
  var f=findById(state.fixFocus), o=payCfg.data&&payCfg.data.offers[0], rq=state.repair, mode=payCfg.data&&payCfg.data.mode;
  var head='<h3>Paid repair <span class="price">₹699</span><span class="fine">'+(mode==='production'?'Cashfree':'Cashfree test mode (no real money)')+' · one selected issue</span></h3>';
  if (!payCfg.available){
    el.innerHTML=head+'<p class="fine" style="margin-top:6px">Not available in this view. Payments are created and verified only by the SecureFlow server (the Cloudflare deployment or <span class="mono">npm run dev</span>), never in the browser. Nothing is sent anywhere from here.</p><p class="fine">No turnaround is promised.</p>'+
      '<p class="fine" style="margin-top:6px">Payments need a server with Cashfree and durable project storage configured. This local copy does not send uploaded files to a payment flow.</p>';
    return;
  }
  var step=rq?rq.status:'draft';
  var lifeHTML='<ol class="lifecycle" aria-label="Request status">'+LIFE.map(function(s,i){ var idx=LIFE.findIndex(function(x){return x[0]===step;}); var staffedOnly=i>=5;
    return '<li class="'+(staffedOnly?'off':(i<idx?'done':(i===idx?'now':'')))+'"'+(staffedOnly?' title="Needs a staffed repair team, not available"':'')+'>'+s[1]+'</li>'; }).join('')+(step==='payment_failed'?'<li class="now">Payment failed</li>':'')+(step==='cancelled'?'<li class="now">Cancelled</li>':'')+'</ol>';
  var h=head+'<div class="cols"><div><b class="fine">Scope</b><p class="fine">'+esc(o.scope)+'</p><b class="fine">Deliverables</b><ul>'+o.deliverables.map(function(d){ return '<li>'+esc(d)+'</li>'; }).join('')+'</ul></div><div><b class="fine">Not included</b><ul>'+o.exclusions.map(function(d){ return '<li>'+esc(d)+'</li>'; }).join('')+'</ul>'+
    '<p class="fine" style="margin-top:6px">No turnaround is promised. Supported findings receive an automated patch attempt and follow-up scan; syntax checks and project tests are not run. Unsupported findings require manual review. Refund policy: not configured. Any extra cost would need your approval first.</p></div></div>'+lifeHTML;
  if (!payCfg.data.configured) h+='<p class="fine" style="margin-top:8px">Checkout is unavailable: '+esc(PAY_PROBLEM[payCfg.data.problem]||payCfg.data.problem)+'.</p>';
  if (!rq){
    if (!f){ el.innerHTML=h+'<p class="fine">Select a finding first.</p>'; return; }
    var payload={ offerId:o.id, finding:{ ruleId:f.ruleId, title:f.title, severity:f.severity, file:f.file, line:f.line } };
    h+='<div class="consent"><label><input type="checkbox" id="pc-scope"> I understand the scope, exclusions'+(mode==='production'?'':' and that this is <b>test mode</b> (no real money)')+'.</label>'+
      '<label><input type="checkbox" id="pc-ev"> Also send the masked evidence lines for this finding (optional).</label>'+
      '<details><summary class="fine">Exactly what will be sent to the SecureFlow server</summary><pre id="pc-preview">'+esc(JSON.stringify(payload,null,2))+'</pre><p class="fine">After you continue, supported project source files are uploaded to SecureFlow storage so the server can reproduce and repair the selected finding. Optional masked evidence is sent only if selected. Card and UPI details go directly to Cashfree checkout.</p></details>'+
      '<div class="d-actions"><button class="btn btn-solid btn-sm" id="pc-create" disabled>Continue to secure checkout</button></div></div>';
    el.innerHTML=h;
    var upd=function(){ var p=Object.assign({},payload); if ($('pc-ev').checked) p.evidence=f.evidence.map(function(e){ return {n:e.n,text:e.text}; }); $('pc-preview').textContent=JSON.stringify(p,null,2); $('pc-create').disabled=!$('pc-scope').checked; };
    $('pc-scope').addEventListener('change',upd); $('pc-ev').addEventListener('change',upd);
    $('pc-create').addEventListener('click',function(){
      var begin=function(){ continueToCheckout(f,$('pc-ev').checked,el); };
      if (!localStorage.getItem('sf_id_token')) { openAuthDialog(null,begin); return; }
      begin();
    });
    return;
  }
  h+='<p class="fine" style="margin-top:8px">Request <span class="mono">'+esc(rq.id)+'</span> · status from the server: <b>'+esc(rq.status.replace(/_/g,' '))+'</b>'+(rq.data&&rq.data.lastError?' · '+esc(rq.data.lastError):'')+'. The access key lives only in this tab; it is lost on reload.</p>';
  if(rq.repair){ h+='<p class="fine">'+esc(rq.repair.summary||'')+'</p>';
    if(rq.repair.status==='completed_with_limitations') {
      h+='<p class="fine">Validation: '+esc(rq.repair.validation&&rq.repair.validation.followUpScan||'not available')+'. Syntax checks and project tests: not run.</p>';
      (rq.repair.manifest&&rq.repair.manifest.diffs||[]).forEach(function(d){h+='<details><summary class="fine">Review diff · '+esc(d.file)+'</summary><pre class="repair-diff">'+esc(d.text)+'</pre><button class="btn btn-ghost btn-sm" data-repair-file="'+esc(d.file)+'">Download this file</button></details>';});
      h+='<button class="btn btn-solid btn-sm" id="pc-download">Download repaired project ZIP</button>';
    }
    else if(rq.repair.status==='manual_review') h+='<p class="fine">Status: manual developer review required; no repaired files are available to download.</p>';
  }
  var btns='';
  if ((rq.status==='awaiting_payment'||rq.status==='payment_failed') && payCfg.data.configured){
    h+='<label class="fine pc-phone">Mobile number for the Cashfree receipt '+(mode==='production'?'(required)':'(optional in test mode)')+' <input id="pc-phone" inputmode="numeric" maxlength="10" autocomplete="tel-national" placeholder="10 digits"></label>';
    btns+='<button class="btn btn-solid btn-sm" id="pc-pay">Pay ₹699 with Cashfree'+(mode==='production'?'':' (test mode)')+'</button><button class="btn btn-ghost btn-sm" id="pc-cancel">Cancel request</button>';
  }
  btns+='<button class="btn btn-ghost btn-sm" id="pc-refresh">Check payment status</button>';
  el.innerHTML=h+'<div class="d-actions">'+btns+'</div>'+
    '<div style="margin-top:14px; padding:12px; border:1px solid var(--gold); background:rgba(200,150,60,0.08); border-radius:6px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">'+
      '<div><b style="color:var(--gold);font-size:0.85rem;">Continuous GitHub Protection &amp; Deploy</b><p class="fine" style="margin:0;">Pay via Cashfree in your dashboard to connect repositories and 1-click deploy verified fixes.</p></div>'+
      '<button class="btn btn-solid btn-sm" id="btn-paid-to-dash">Open in Dashboard →</button>'+
    '</div>';
  if ($('btn-paid-to-dash')) $('btn-paid-to-dash').addEventListener('click', function(){ ensureAuthAndRedirect('dashboard.html#billing'); });
  if ($('btn-fix-to-dash')) $('btn-fix-to-dash').addEventListener('click', function(){ ensureAuthAndRedirect('dashboard.html#billing'); });
  if ($('pc-pay')) $('pc-pay').addEventListener('click',function(){ pay(el); });
  if ($('pc-cancel')) $('pc-cancel').addEventListener('click',function(){ api('POST','/api/repair-requests/'+rq.id+'/cancel',{},rq.token).then(function(j){ if (j.request){ setRepair(j.request); logEvent('repair','Repair request cancelled'); } else toast('Could not cancel ('+(j.error||j._status)+').'); paidInner(el); }); });
  if ($('pc-refresh')) $('pc-refresh').addEventListener('click',function(){ verifyPay(el,null); });
  if ($('pc-download')) $('pc-download').addEventListener('click',function(){ downloadRepair(rq); });
  el.querySelectorAll('[data-repair-file]').forEach(function(button){button.addEventListener('click',function(){downloadRepairFile(rq,button.getAttribute('data-repair-file'));});});
}
function downloadRepairFile(rq,path){
  var headers={'x-repair-token':rq.token},idToken=localStorage.getItem('sf_id_token');if(idToken)headers.Authorization='Bearer '+idToken;
  fetch('/api/repair-requests/'+encodeURIComponent(rq.id)+'/files?path='+encodeURIComponent(path),{headers:headers,credentials:'same-origin'}).then(function(r){if(!r.ok)throw new Error('File download unavailable ('+r.status+').');return r.blob();}).then(function(blob){var url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=path.split('/').pop();a.click();setTimeout(function(){URL.revokeObjectURL(url);},1000);}).catch(function(e){toast(e.message||'Download failed.');});
}
function downloadRepair(rq){
  var headers={'x-repair-token':rq.token}; var idToken=localStorage.getItem('sf_id_token'); if(idToken) headers.Authorization='Bearer '+idToken;
  fetch('/api/repair-requests/'+encodeURIComponent(rq.id)+'/download.zip',{headers:headers,credentials:'same-origin'}).then(function(r){ if(!r.ok) throw new Error('Download unavailable ('+r.status+').'); return r.blob(); }).then(function(blob){ var url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='secureflow-repair-'+rq.id+'.zip';a.click();setTimeout(function(){URL.revokeObjectURL(url);},1000); }).catch(function(e){toast(e.message||'Download failed.');});
}
async function continueToCheckout(f, shareEvidence, el){
  var button=$('pc-create'); if(button){button.disabled=true;button.textContent='Saving project securely…';}
  try {
    var files=state.files.filter(function(x){return x&&typeof x.name==='string'&&typeof x.code==='string'&&x.code.length;});
    if(!files.length) throw new Error('No supported source files are available to preserve.');
    var manifest=files.map(function(x){return {path:x.name,size:new TextEncoder().encode(x.code).length};});
    var created=await projectApi('POST','/api/projects','',{name:state.name,files:manifest},'application/json');
    if(created._status!==201) throw new Error(created.message||created.error||'Could not save the project.');
    var session=created.sessionToken, projectId=created.id;
    sessionStorage.setItem('sf-project-session',JSON.stringify({id:projectId,token:session,name:state.name,expiresAt:created.expiresAt}));
    for(var i=0;i<files.length;i++){
      var type=/\.(?:html?|ejs|vue|svelte)$/i.test(files[i].name)?'text/html':/\.css$/i.test(files[i].name)?'text/css':/\.(?:json|ya?ml|toml|xml)$/i.test(files[i].name)?'application/json':'text/javascript';
      var put=await projectApi('POST','/api/projects/'+projectId+'/files?path='+encodeURIComponent(files[i].name),session,files[i].code,type);
      if(put._status!==200) throw new Error('Could not preserve '+files[i].name+': '+(put.error||put._status));
    }
    var fin=await projectApi('POST','/api/projects/'+projectId+'/finalize',session,{},'application/json');
    if(fin._status!==200) throw new Error(fin.error||'Project upload did not complete.');
    var scanned=await projectApi('POST','/api/projects/'+projectId+'/scan',session,{},'application/json');
    if(scanned._status!==200) throw new Error(scanned.error||'Server-side scan did not complete.');
    var serverFinding=(scanned.findings||[]).find(function(x){return x.id===f.id;})||(scanned.findings||[]).find(function(x){return x.ruleId===f.ruleId&&x.file===f.file&&x.line===f.line;});
    if(!serverFinding) throw new Error('The selected finding did not reproduce in the server-side scan. Nothing was charged.');
    var claimed=await projectApi('POST','/api/projects/'+projectId+'/claim','',{sessionToken:session},'application/json');
    if(claimed._status!==200) throw new Error(claimed.message||claimed.error||'Could not associate this project with the verified account.');
    var body={offerId:'starter-fix',projectId:projectId,findingId:serverFinding.id,finding:{ruleId:serverFinding.ruleId,title:serverFinding.title,severity:serverFinding.severity,file:serverFinding.file,line:serverFinding.line},consent:{scope:true,shareEvidence:shareEvidence}};
    if(shareEvidence) body.evidence=(serverFinding.evidence||[]).map(function(e){return {n:e.n,text:e.text};});
    var result=await api('POST','/api/repair-requests',body);
    if(result._status!==201) throw new Error(result.message||result.error||'Could not create the paid repair request.');
    state.repair={id:result.request.id,token:result.accessToken,status:result.request.status,data:result.request,projectId:projectId};
    sessionStorage.setItem('sf-repair-request',JSON.stringify({id:result.request.id,token:result.accessToken,projectId:projectId}));
    logEvent('repair','Project saved and scoped repair request created');
    paidInner(el);
  } catch(e) {
    toast(e.message||'Could not prepare secure checkout.');
    if(button){button.disabled=false;button.textContent='Continue to secure checkout';}
  }
}
function setRepair(r){ state.repair.status=r.status; state.repair.data=r; }
function loadCashfree(){ return window.Cashfree?Promise.resolve():new Promise(function(res,rej){ var s=document.createElement('script'); s.src='https://sdk.cashfree.com/js/v3/cashfree.js'; s.onload=res; s.onerror=function(){ rej(new Error('checkout')); }; document.head.appendChild(s); }); }
function verifyPay(el, outcome){
  var rq=state.repair;
  return api('POST','/api/repair-requests/'+rq.id+'/verify',outcome?{ outcome:outcome }:{},rq.token).then(function(v){
    if (v.request) setRepair(v.request);
    if (v.paid){
      logEvent('repair','Payment confirmed by Cashfree (checked by the server): repair processing started');
      toast('Payment confirmed. SecureFlow is preparing and validating the repair.');
      return api('POST','/api/repair-requests/'+rq.id+'/repair',{},rq.token).then(function(result){
        if(result.repair){ rq.repair=result.repair; setRepair(result.request||rq.data); logEvent('repair','Server repair status: '+result.repair.status); }
        else toast('Payment confirmed, but repair processing returned no result ('+(result.error||result._status)+').');
        paidInner($('paid')||el);
      });
    }
    else if (v._status===200) toast(outcome==='failed'?'Payment did not complete. Nothing was unlocked.':'Cashfree reports the order as '+String(v.orderStatus||'not paid').toLowerCase()+'. Nothing was unlocked.');
    else toast('Could not check the payment ('+(v.error||v._status)+').');
    var targetEl = $('paid') || el;
    paidInner(targetEl);
  });
}
function pay(el){
  var rq=state.repair, phone=($('pc-phone')&&$('pc-phone').value||'').replace(/\D/g,'');
  var payBtn=$('pc-pay'); if (payBtn){ payBtn.disabled=true; payBtn.textContent='Opening Cashfree…'; }
  api('POST','/api/repair-requests/'+rq.id+'/order',{ phone:phone },rq.token).then(function(j){
    if (j._status===503){ toast('Payments are not configured on the server.'); if (payBtn){ payBtn.disabled=false; payBtn.textContent='Pay ₹699 with Cashfree'; } return; }
    if (j.error==='invalid_phone'||j.error==='phone_required'){ toast('Enter a valid 10-digit Indian mobile number.'); if (payBtn){ payBtn.disabled=false; payBtn.textContent='Pay ₹699 with Cashfree'; } return; }
    if (j.error==='already_paid'){ if (j.request) setRepair(j.request); paidInner(el); return; }
    if (!j.paymentSessionId){ toast('Could not create the order ('+(j.error||j._status)+').'); if (payBtn){ payBtn.disabled=false; payBtn.textContent='Pay ₹699 with Cashfree'; } return; }
    return loadCashfree().then(function(){
      var cfMode = j.mode==='production'?'production':'sandbox';
      var cashfree = window.Cashfree({ mode: cfMode });
      try {
        cashfree.checkout({ paymentSessionId: j.paymentSessionId, redirectTarget: '_modal' }).then(function(result){
          return verifyPay(el, result && result.error ? 'failed' : null);
        }).catch(function(err){
          console.warn('Cashfree checkout modal catch:', err);
          return verifyPay(el, 'failed');
        });
      } catch (e) {
        console.warn('Cashfree exception, redirecting directly:', e);
        cashfree.checkout({ paymentSessionId: j.paymentSessionId, redirectTarget: '_self' });
      }
    }, function(){
      toast('Could not load Cashfree checkout.');
      if (payBtn){ payBtn.disabled=false; payBtn.textContent='Pay ₹699 with Cashfree'; }
    });
  }).catch(function(){
    toast('Network error creating order.');
    if (payBtn){ payBtn.disabled=false; payBtn.textContent='Pay ₹699 with Cashfree'; }
  });
}

/* ---------- PROOFLOOP ---------- */
function renderVerify(){
  var V=$('vlist'), ver=verification();
  if (!ver){ V.innerHTML='<h3>ProofLoop: don’t trust the fix, verify it</h3><ol class="fine" style="margin:8px 0 0 18px;display:grid;gap:6px"><li>Fix findings in <b>Fix Studio</b> (reviewed patches) or with a repair prompt in your AI tool.</li><li>Bring the updated code back: patches apply automatically; otherwise edit, upload with <b>Replace</b>, or use <b>Load patched demo</b>.</li><li>Press <b>Scan project</b>. This view then compares the scans finding by finding.</li></ol>'; return; }
  var s=ver.summary, b=ver.base, c=ver.cur, sc=ver.score;
  var addF=Object.keys(c.files).filter(function(k){return !(k in b.files);}), remF=Object.keys(b.files).filter(function(k){return !(k in c.files);});
  var isDemoFix=SF.layers.every(function(L){ return c.files[L.file]===L.fixed && b.files[L.file]===L.vuln; });
  var order={new:0,inconclusive:1,notrechecked:2,still:3,gone:4,verified:5};
  var rows=ver.rows.slice().sort(function(x,y){ return order[x.state]-order[y.state]; });
  V.innerHTML=
    '<div class="vhead"><span>Comparing scan '+(state.scans.indexOf(b)+1)+' (baseline) → scan '+state.scans.length+'</span><button class="btn btn-ghost btn-sm" id="set-baseline">Use latest scan as baseline</button></div>'+
    '<div class="score-delta">Score <b>'+sc.before+'</b> → <b>'+sc.after+'</b> <span>('+(sc.delta>0?'+':'')+sc.delta+')</span><span>'+esc(sc.reasons.join('; ')||'No change in findings.')+'</span></div>'+
    (isDemoFix?'<p class="known">Known test case: the prepared patched demo, rescanned and compared. It is an example, not a fix SecureFlow made.</p>':'')+
    '<div class="vsum">'+['still','new','gone','notrechecked','inconclusive','verified'].map(function(k){ return '<div class="vs-'+k+'"><b>'+s[k]+'</b>'+STATE_LABEL[k]+'</div>'; }).join('')+'</div>'+
    '<p class="vnote"><b>Tests executed:</b> none. SecureFlow never runs your code, so nothing here is “Verified by test”. This is a static recheck: “No longer detected” means the pattern stopped matching, which is not proof the vulnerability is fixed.</p>'+
    (addF.length||remF.length?'<p class="vnote">Coverage changed: '+(addF.length?addF.length+' file'+(addF.length>1?'s':'')+' added':'')+(addF.length&&remF.length?', ':'')+(remF.length?remF.length+' file'+(remF.length>1?'s':'')+' no longer present ('+remF.slice(0,3).map(esc).join(', ')+')':'')+'.</p>':'')+
    '<div class="vrows">'+rows.map(function(r,i){ var f=r.cur||r.prev, p=r.prev&&state.patches.find(function(x){ return x.findingId===r.prev.id && !x.undone; });
      return '<div class="vrow x" data-i="'+i+'" tabindex="0" role="button" aria-expanded="false"><span class="pill st-'+r.state+'">'+STATE_LABEL[r.state]+'</span><span>'+esc(f.title)+(p?' <span class="tagp done">patched here</span>':'')+'<small>'+esc(r.reason)+'</small></span><span class="f-loc" title="'+esc(f.file)+'">'+esc(f.file)+':'+f.line+'</span></div>'; }).join('')+'</div>';
  V._rows=rows;
  $('set-baseline').addEventListener('click',function(){ state.baseline=state.scans.length-1; logEvent('scan','Baseline moved to scan '+state.scans.length); renderAll(); renderVerify(); toast('The latest scan is now the baseline.'); });
}
function evHTML(f){ return '<div class="ev">'+f.evidence.map(function(e){ return '<div'+(e.hit?' class="hit"':'')+'><span>'+e.n+'</span>'+esc(e.text)+'</div>'; }).join('')+'</div>'; }
$('vlist').addEventListener('click',function(e){ var row=e.target.closest('.vrow.x'); if (row) toggleVrow(row); });
$('vlist').addEventListener('keydown',function(e){ if ((e.key==='Enter'||e.key===' ')&&e.target.classList.contains('vrow')){ e.preventDefault(); toggleVrow(e.target); } });
function toggleVrow(row){
  var open=row.getAttribute('aria-expanded')==='true', nx=row.nextElementSibling;
  if (open){ if (nx&&nx.classList.contains('vx')) nx.remove(); row.setAttribute('aria-expanded','false'); return; }
  var r=$('vlist')._rows[+row.dataset.i], p=r.prev&&state.patches.find(function(x){ return x.findingId===r.prev.id && !x.undone; });
  var h='<div class="vx">'+(r.prev?'<h5>Before (baseline)</h5>'+evHTML(r.prev):'')+(r.cur?'<h5>Now</h5>'+evHTML(r.cur):'')+
    (p?'<h5>Patch applied in Fix Studio</h5><div class="diff">'+p.diff.map(function(d){ return '<div class="'+(d.t==='-'?'m':d.t==='+'?'p':'')+'"><span>'+(d.a||'')+'</span><span>'+(d.b||'')+'</span><span>'+(d.t===' '?'':d.t)+'</span><code>'+esc(d.text)+'</code></div>'; }).join('')+'</div>':'')+
    '<p class="fine">Test result: none executed.</p></div>';
  row.insertAdjacentHTML('afterend',h); row.setAttribute('aria-expanded','true');
}
function renderTimeline(){
  $('timeline').innerHTML=state.events.length?state.events.slice().reverse().map(function(e){ var cls=e.type==='scan'?'scan':(e.type==='patch'?'patch':(e.type==='warn'?'warn':''));
    return '<li class="'+cls+'"><time>'+hhmm(e.at)+'</time>'+esc(e.text)+'</li>'; }).join(''):'<li>No events yet.</li>';
}

/* ---------- READINESS ---------- */
function renderReady(){
  var c=current(), R=$('ready');
  if (!c){ R.innerHTML='<h3>Production readiness</h3><p class="fine" style="margin-top:6px">Run a scan first. Every check says whether it actually ran.</p>'; return; }
  var rd=E.readiness(c.result, filesArr(c.files), openFindings(c.result.findings)), specs=E.testSpecs(filesArr(c.files));
  var cls=rd.overall==='Fix Before Deployment'||rd.overall==='Failed Check'?'fail':rd.overall==='Assessment Incomplete'?'warn':'ok';
  var SL={pass:'Passed',warn:'Review',fail:'Fix needed',notchecked:'Not checked',incomplete:'Incomplete'};
  R.innerHTML='<div class="rd-head"><h3>Production readiness</h3><span class="rd-badge '+cls+'">'+esc(rd.overall)+'</span></div><p class="fine">'+esc(rd.scope)+'</p>'+
    '<div class="checks" style="margin-top:12px">'+rd.checks.map(function(k){ return '<div class="check"><b>'+esc(k.name)+'</b><span class="st-'+k.status+'">'+SL[k.status]+(k.ran?'':' · did not run')+'</span><div><p class="ev">'+esc(k.evidence)+'</p><span class="act">Impact: '+esc(k.impact)+' Action: '+esc(k.action)+'</span></div></div>'; }).join('')+'</div>'+
    '<div class="d-sec"><div class="rd-head"><h3>Business-logic test builder</h3><button class="btn btn-ghost btn-sm" id="copy-specs">Copy as Markdown</button></div><p class="fine">Manual test specifications. These are suggestions, not discovered vulnerabilities, and SecureFlow does not run them.</p>'+
    '<div class="specs">'+specs.map(function(s){ return '<div class="spec'+(s.relevant?' rel':'')+'"><b>'+esc(s.title)+'</b> <span class="fine">'+esc(s.reason)+'</span><ol>'+s.steps.map(function(x){ return '<li>'+esc(x)+'</li>'; }).join('')+'</ol>Expected: '+esc(s.expected)+'</div>'; }).join('')+'</div></div>';
  $('copy-specs').addEventListener('click',function(){ copy('# Business-logic test specs (manual)\n\n'+specs.map(function(s){ return '## '+s.title+'\n'+s.reason+'\n\n'+s.steps.map(function(x,i){ return (i+1)+'. '+x; }).join('\n')+'\n\nExpected: '+s.expected+'\n'; }).join('\n'),'Test specs copied as Markdown.'); });
}

/* ---------- REPORTS ---------- */
function reportObj(){
  var c=current(); if (!c) return null;
  var fs=c.result.findings.map(function(f){ return state.dismissed[f.id]?Object.assign({},f,{dismissed:state.dismissed[f.id]}):f; });
  var report=E.reportData({ project:state.name, demo:state.demo||/^Demo project/.test(state.name), generatedAt:new Date().toISOString(), scan:c.result, findings:fs, verification:verification(), importSkipped:state.importSkipped,
    readiness:E.readiness(c.result, filesArr(c.files), openFindings(c.result.findings)), patches:state.patches.map(function(p){ return {title:p.title, file:p.file, kind:p.kind, undone:p.undone}; }) });
  report.analysisSources={ local:{status:c.localStatus||'completed',engine:c.result.engine}, gemini:{status:c.aiStatus||'skipped',model:c.aiMeta&&c.aiMeta.model||null,passes:c.aiMeta&&c.aiMeta.passes||0,reviewerStatus:c.aiMeta&&c.aiMeta.reviewerStatus||'not_run',reviewerError:c.aiMeta&&c.aiMeta.reviewerError||null}, combined:{status:c.combinedStatus||'local_only'} };
  return report;
}
function renderReports(){
  var d=reportObj(), P=$('report-preview');
  if (!d){ P.innerHTML='<div class="empty">Run a scan to build a report.</div>'; return; }
  P.innerHTML='<div class="card"><h3>Executive summary</h3><p style="margin-top:6px"><b>'+esc(d.verdict.title)+'.</b> '+esc(d.verdict.detail)+'</p><p class="fine" style="margin-top:6px">Open findings: '+SEVS.map(function(k){ return d.counts[k]+' '+k; }).join(', ')+' · score '+d.score+'/100 · readiness: '+esc(d.readiness.overall)+'</p></div>'+
    '<div class="card"><h3>What the report contains</h3><ul class="fine" style="margin:6px 0 0 18px;display:grid;gap:3px"><li>Scope and coverage, including excluded files and checks that did not run</li><li>'+d.findings.length+' findings with masked evidence, potential impact, priority, fix and regression test</li><li>Production readiness checks</li><li>'+(d.verification?'ProofLoop comparison of the latest scans':'No ProofLoop comparison yet (scan again after changes)')+'</li><li>'+(d.patches.length?d.patches.length+' patch'+(d.patches.length>1?'es':'')+' applied in this session':'No patches applied')+'</li><li>Tests executed: none (SecureFlow does not run your code)</li></ul></div>';
}
var urls=[];
function revokeAll(){ urls.forEach(function(u){ try{ URL.revokeObjectURL(u); }catch(_){} }); urls=[]; }
var dlCap=null;
try { if (window.claude && typeof window.claude.use==='function') window.claude.use('downloads').then(function(d){ dlCap=d; },function(){}); } catch(_){}
function download(name, text, type){
  if (dlCap){ dlCap.save({ filename:name, data:text }).then(function(){ toast('Report saved as '+name+'.'); }, function(e){ toast(e&&e.code==='declined'?'Download cancelled.':'Download isn’t available here. Use Copy Markdown instead.'); }); return; }
  try {
    var u=URL.createObjectURL(new Blob([text],{type:type})); urls.push(u);
    var a=document.createElement('a'); a.href=u; a.download=name; a.rel='noopener'; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function(){ try{ URL.revokeObjectURL(u); }catch(_){} urls=urls.filter(function(x){return x!==u;}); }, 4000);
    toast('Report saved as '+name+'. It may contain code snippets from your project (secrets masked).');
  } catch(e){ toast('Download is blocked here. Use Copy Markdown instead.'); }
}
function fileBase(){ return 'secureflow-'+state.name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,40)+'-'+new Date().toISOString().slice(0,10); }
$('exp-json').addEventListener('click',function(){ var d=reportObj(); if (d) download(fileBase()+'.json', JSON.stringify(d,null,2), 'application/json'); });
$('exp-md').addEventListener('click',function(){ var d=reportObj(); if (d) download(fileBase()+'.md', E.reportMarkdown(d), 'text/markdown'); });
$('exp-html').addEventListener('click',function(){ var d=reportObj(); if (d) download(fileBase()+'.html', E.reportHTML(d), 'text/html'); });
$('copy-md').addEventListener('click',function(){ var d=reportObj(); if (d) copy(E.reportMarkdown(d),'Report copied as Markdown (secrets masked).'); });

function downloadFixedProjectZip(){
  if (!state.files || !state.files.length){
    toast('No project files loaded to download.');
    return;
  }
  var cleanFiles = state.files.map(function(f){
    return { name: f.name, code: f.code };
  });
  var applied = state.patches.filter(function(p){ return !p.undone; });
  var manifest = {
    generatedBy: 'SecureFlow AI Security Reviewer',
    timestamp: new Date().toISOString(),
    filesCount: cleanFiles.length,
    patchesAppliedCount: applied.length,
    patches: applied.map(function(p){
      return { id: p.id, findingId: p.findingId, file: p.file, ruleId: p.ruleId, title: p.title };
    }),
    guidance: 'All security patches have been integrated. Run your test suite and re-scan on SecureFlow to verify with ProofLoop.'
  };
  cleanFiles.push({
    name: 'SECUREFLOW_FIX_MANIFEST.json',
    code: JSON.stringify(manifest, null, 2)
  });
  var blob = SF.writeZip(cleanFiles);
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  var projName = 'secureflow-fixed-project';
  if (state.files[0] && state.files[0].name) {
    var p0 = state.files[0].name.split(/[/\\]/);
    if (p0.length > 1) projName = p0[0] + '-fixed';
  }
  a.download = projName + '.zip';
  document.body.appendChild(a);
  a.click();
  setTimeout(function(){
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 1000);
  toast('Fixed project downloaded as ' + a.download);
}
if ($('btn-export-fixed-zip')) {
  $('btn-export-fixed-zip').addEventListener('click', downloadFixedProjectZip);
}

/* ---------- TRUST CENTER ---------- */
function renderTrust(){
  var c=current(), cov=c&&c.result.coverage;
  $('trust').innerHTML='<h3>Security Trust Center</h3><p class="fine" style="margin-top:6px">This describes what this build actually does.</p>'+
    '<div class="trust-grid" style="margin-top:14px"><div class="card"><h3>What SecureFlow checks</h3><ul><li>'+E.RULES.length+' statement-level pattern rules plus '+E.PROJECT_RULES.length+' project-level checks across secrets, injection, XSS, auth and sessions, access control, crypto, transport and config.</li><li>JS/TS, Python, PHP, HTML templates, SQL, config, .env and Dockerfiles.</li><li>Comments are ignored; multi-line statements are joined.</li></ul></div>'+
    '<div class="card"><h3>What it does not check</h3><ul><li>Business logic, authorisation design and data flow across files.</li><li>Dependency vulnerabilities (no CVE database), builds, runtime behaviour, hosting and network configuration.</li><li>It never executes your code, so nothing is “verified by test” unless you supply an executed test result.</li></ul></div>'+
    '<div class="card"><h3>This session</h3><ul>'+(cov?'<li>Rules run: '+cov.rules+'. Files analysed: '+cov.analyzed+' of '+cov.imported+'.</li><li>Skipped: '+(cov.skipped.length+state.importSkipped.length)+' (listed in Overview → Coverage).</li>':'<li>No scan yet.</li>')+'<li>Patches applied: '+state.patches.filter(function(p){return !p.undone;}).length+' (deterministic rewrites, no AI).</li><li>Paid repair: '+(payCfg.available?(payCfg.data.configured?'Cashfree '+esc(payCfg.data.mode)+' mode':'server reachable, payments not configured'):'not available in this view')+'.</li></ul></div>'+
    '<div class="card"><h3>ProofLoop in one line</h3><p class="fine" style="margin-top:6px">After a change, SecureFlow rescans and labels each earlier finding: still detected, no longer detected, newly detected, not rechecked, inconclusive, or verified by test (only with an executed passing test). “No longer detected” is not called “fixed”.</p></div></div>'+
    '<h3 style="margin-top:18px">What leaves the browser</h3><table class="flows"><tr><th>Workflow</th><th>Data sent</th><th>To</th><th>When</th></tr>'+
    '<tr><td>Opening the page</td><td>Standard page requests (no code)</td><td>Google Fonts, jsDelivr (3D library)</td><td>On load</td></tr>'+
    '<tr><td>Import, engine scan, Fix Studio, ProofLoop, reports</td><td>Nothing</td><td>—</td><td>Never: all local</td></tr>'+
    '<tr><td>AI deep check, fix guidance, Ask SecureFlow (opt-in)</td><td>Your code with secrets masked (in the browser and again on the server); for guidance and questions only the affected file or a window around the issue</td><td>Your SecureFlow server, which forwards it to the Google Gemini API for that request; SecureFlow does not store it</td><td>Only while AI deep check is on, after you accept the notice</td></tr>'+
    '<tr><td>Codebase memory (opt-in)</td><td>Line fingerprints (8-character hashes, salted per project), file paths, finding titles, locations, scores and short fix directions. No source code</td><td>SecureFlow’s Cloudflare D1 database</td><td>Only while Codebase memory is on; “Forget this codebase” deletes it</td></tr>'+
    '<tr><td>Repair prompt</td><td>Masked evidence for the finding</td><td>Your clipboard; you choose where to paste it</td><td>When you click Copy</td></tr>'+
    '<tr><td>Export</td><td>Report file</td><td>Your device</td><td>When you click Export</td></tr>'+
    '<tr><td>Paid repair (optional, server mode only)</td><td>Finding metadata; masked evidence lines only if you tick the box</td><td>Your SecureFlow server; card and UPI details go directly to Cashfree’s checkout</td><td>Only after explicit consent</td></tr></table>'+
    '<p class="fine" style="margin-top:12px">AI services: only Google Gemini, and only after you switch on AI deep check. Browser storage: nothing is written. “Clear project &amp; data” removes everything this page holds; browsers cannot guarantee memory is erased instantly.</p>';
}

/* ---------- copy helpers ---------- */
function copy(t,msg){
  function done(){ toast(msg); }
  function fb(){ var ta=document.createElement('textarea'); ta.value=t; ta.setAttribute('readonly',''); ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select(); var ok=false; try{ ok=document.execCommand('copy'); }catch(_){} ta.remove(); if (ok) done(); else showManualCopy(t); }
  try { if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(t).then(done,fb); else fb(); } catch(_) { fb(); }
}
function showManualCopy(t){ $('manual-copy-text').value=t; var d=$('copy-dlg'); if (d.showModal) d.showModal(); $('manual-copy-text').select(); toast('Clipboard access is blocked. Select the text and copy it manually.'); }
$('copy-dlg-close').addEventListener('click',function(){ $('copy-dlg').close(); $('manual-copy-text').value=''; });

/* ---------- AUTH MODAL & USER FLOW ---------- */
function isUserLoggedIn(){
  return !!(localStorage.getItem('sf_rt') || localStorage.getItem('sf_id_token'));
}

var authState = { otpSent: false, email: '' };

function openAuthDialog(targetUrl, callback){
  var d = $('auth-dlg');
  if (!d) return;
  d._target = targetUrl || null;
  d._callback = callback || null;
  var errEl = $('dlg-auth-err');
  var msgEl = $('dlg-auth-msg');
  if (errEl) errEl.textContent = '';
  if (msgEl) msgEl.textContent = '';
  
  authState.otpSent = false;
  authState.email = '';
  if ($('dlg-otp-code-box')) $('dlg-otp-code-box').style.display = 'none';
  if ($('dlg-otp-dev-hint')) $('dlg-otp-dev-hint').style.display = 'none';
  if ($('dlg-otp-action-btn')) {
    $('dlg-otp-action-btn').disabled = false;
    $('dlg-otp-action-btn').textContent = 'Send Verification Code →';
  }
  if ($('dlg-auth-otp')) $('dlg-auth-otp').value = '';
  
  if (d.showModal) d.showModal();
}

function ensureAuthAndRedirect(targetUrl){
  if (isUserLoggedIn()) {
    window.location.href = targetUrl || 'dashboard.html#billing';
  } else {
    openAuthDialog(targetUrl || 'dashboard.html#billing');
  }
}

// Tab Switching (OTP vs Password)
if ($('auth-tab-otp') && $('auth-tab-pass')) {
  $('auth-tab-otp').addEventListener('click', function(){
    $('auth-tab-otp').style.color = 'var(--gold)';
    $('auth-tab-otp').style.borderBottom = '2px solid var(--gold)';
    $('auth-tab-pass').style.color = 'var(--fg-muted)';
    $('auth-tab-pass').style.borderBottom = 'none';
    if ($('dlg-auth-otp-sec')) $('dlg-auth-otp-sec').style.display = 'block';
    if ($('dlg-auth-form')) $('dlg-auth-form').style.display = 'none';
  });
  $('auth-tab-pass').addEventListener('click', function(){
    $('auth-tab-pass').style.color = 'var(--gold)';
    $('auth-tab-pass').style.borderBottom = '2px solid var(--gold)';
    $('auth-tab-otp').style.color = 'var(--fg-muted)';
    $('auth-tab-otp').style.borderBottom = 'none';
    if ($('dlg-auth-otp-sec')) $('dlg-auth-otp-sec').style.display = 'none';
    if ($('dlg-auth-form')) $('dlg-auth-form').style.display = 'block';
    if ($('dlg-auth-email-pass') && $('dlg-auth-email')) {
      $('dlg-auth-email-pass').value = $('dlg-auth-email').value;
    }
  });
}

// OTP Action Button (Send OTP / Verify OTP)
if ($('dlg-otp-action-btn')) {
  $('dlg-otp-action-btn').addEventListener('click', async function(){
    var email = ($('dlg-auth-email').value || '').trim();
    var errEl = $('dlg-auth-err');
    var msgEl = $('dlg-auth-msg');
    var btn = $('dlg-otp-action-btn');
    if (errEl) errEl.textContent = '';
    if (msgEl) msgEl.textContent = '';

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (errEl) errEl.textContent = 'Please enter a valid email address.';
      return;
    }

    if (!authState.otpSent) {
      // STEP 1: Send OTP
      btn.disabled = true;
      btn.textContent = 'Sending code…';
      try {
        var res = await fetch('/api/auth/send-otp', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email: email })
        });
        var data = await res.json().catch(function(){ return {}; });
        if (!res.ok) {
          throw new Error(data.message || data.error || 'Failed to send verification code');
        }
        authState.otpSent = true;
        authState.email = email;
        if ($('dlg-otp-code-box')) $('dlg-otp-code-box').style.display = 'block';
        btn.disabled = false;
        btn.textContent = 'Verify Code & Continue →';
        if (msgEl) msgEl.textContent = data.message || 'Verification code sent to your email. It expires in 5 minutes.';
        if (data.devOtp && $('dlg-otp-dev-hint')) {
          $('dlg-otp-dev-hint').style.display = 'block';
          $('dlg-otp-dev-hint').textContent = 'Test Code: ' + data.devOtp;
        }
        if ($('dlg-auth-otp')) {
          if (data.devOtp) $('dlg-auth-otp').value = data.devOtp;
          $('dlg-auth-otp').focus();
        }
      } catch (err) {
        btn.disabled = false;
        btn.textContent = 'Send Verification Code →';
        if (errEl) errEl.textContent = err.message || 'Error sending code';
      }
    } else {
      // STEP 2: Verify OTP
      var otp = ($('dlg-auth-otp') && $('dlg-auth-otp').value || '').trim();
      if (!otp || otp.length < 4) {
        if (errEl) errEl.textContent = 'Please enter the verification code.';
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Verifying…';
      try {
        var vRes = await fetch('/api/auth/verify-otp', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email: authState.email, otp: otp })
        });
        var vData = await vRes.json().catch(function(){ return {}; });
        if (!vRes.ok || !vData.token) {
          throw new Error(vData.message || vData.error || 'Invalid or expired verification code');
        }
        localStorage.setItem('sf_id_token', vData.token);
        if (vData.user) localStorage.setItem('sf_user', JSON.stringify(vData.user));
        toast('Signed in as ' + authState.email);
        
        var d = $('auth-dlg');
        if (d && d.close) d.close();
        if (d && d._callback) {
          var cb = d._callback;
          d._callback = null;
          cb();
        } else if (d && d._target) {
          window.location.href = d._target;
        }
      } catch (err) {
        btn.disabled = false;
        btn.textContent = 'Verify Code & Continue →';
        if (errEl) errEl.textContent = err.message || 'Verification error';
      }
    }
  });
}

// Password mode form submit
var authForm = $('dlg-auth-form');
if (authForm) {
  authForm.addEventListener('submit', async function(e){
    e.preventDefault();
    var email = ($('dlg-auth-email-pass').value || '').trim();
    var pass = $('dlg-auth-pass').value;
    var subBtn = $('dlg-auth-submit');
    var errEl = $('dlg-auth-err');
    if (!email || !pass) return;
    if (subBtn) { subBtn.disabled = true; subBtn.textContent = 'Signing in…'; }
    if (errEl) errEl.textContent = '';

    try {
      var res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: email, password: pass })
      });
      var data = await res.json().catch(function(){ return {}; });
      if (!res.ok || !data.token) {
        throw new Error(data.message || data.error || 'Authentication failed');
      }

      localStorage.setItem('sf_id_token', data.token);
      if (data.refreshToken) localStorage.setItem('sf_rt', data.refreshToken);
      if (data.user) localStorage.setItem('sf_user', JSON.stringify(data.user));
      if (data.verification_required) {
        if (errEl) errEl.textContent = '';
        if ($('dlg-auth-msg')) $('dlg-auth-msg').textContent = 'Account created. Open the verification link sent by Firebase, then sign in to continue.';
        if (subBtn) { subBtn.disabled = false; subBtn.textContent = 'Sign In'; }
        return;
      }
      if (data.user && data.user.email_verified === false) throw new Error('Please open the Firebase verification link sent to your email, then sign in again.');
      toast('Signed in as ' + email);

      var d = $('auth-dlg');
      if (d && d.close) d.close();
      if (d && d._callback) {
        var cb = d._callback;
        d._callback = null;
        cb();
      } else if (d && d._target) {
        window.location.href = d._target;
      }
    } catch (err) {
      if (errEl) errEl.textContent = err.message || 'Authentication error';
      if (subBtn) { subBtn.disabled = false; subBtn.textContent = 'Sign In / Sign Up →'; }
    }
  });
}

if ($('dlg-auth-cancel')) {
  $('dlg-auth-cancel').addEventListener('click', function(){
    var d = $('auth-dlg');
    if (d && d.close) d.close();
  });
}
if ($('dlg-auth-cancel-pass')) {
  $('dlg-auth-cancel-pass').addEventListener('click', function(){
    var d = $('auth-dlg');
    if (d && d.close) d.close();
  });
}

/* ---------- boot ---------- */
openFile(0); renderAll(); showView('overview');
logEvent('import','Session started with the demo project (prepared example data)');
function restorePaidSession(){
  var saved; try{ saved=JSON.parse(sessionStorage.getItem('sf-repair-request')||'null'); }catch(_){ saved=null; }
  if(!localStorage.getItem('sf_id_token')) return;
  function restore(saved){
    if(!saved||!saved.id||!saved.projectId) return;
    Promise.all([
      api('GET','/api/repair-requests/'+encodeURIComponent(saved.id),{},saved.token),
      projectApi('GET','/api/projects/'+encodeURIComponent(saved.projectId),'')
    ]).then(function(items){
    var request=items[0], project=items[1];
    if(request._status!==200||project._status!==200) return;
    return projectApi('GET','/api/projects/'+encodeURIComponent(saved.projectId)+'/files','').then(function(list){
      if(list._status!==200||!Array.isArray(list.files)) return;
      if(!list.files.length) return;
      return Promise.all(list.files.map(function(f){return fetch('/api/projects/'+encodeURIComponent(saved.projectId)+'/files?path='+encodeURIComponent(f.path),{headers:{authorization:'Bearer '+localStorage.getItem('sf_id_token')},credentials:'same-origin'}).then(function(r){return r.ok?r.text():'';});})).then(function(contents){
          var files=list.files.map(function(f,i){return {name:f.path,code:contents[i]};}).filter(function(f){return !!f.code;});
          if(!files.length) return;
          state.gen++; state.files=files; state.name=project.name||'Saved project'; state.demo=false;
          var result=E.scanProject(files); if(result.status==='failed') return;
          state.scans=[{id:project.scan&&project.scan.id||'restored',result:result,files:files.reduce(function(m,f){m[f.name]=f.code;return m;},{}),at:new Date()}];
          state.fixFocus=request.request.finding&&request.request.finding.id||null;
          state.repair={id:saved.id,token:saved.token,status:request.request.status,data:request.request,projectId:saved.projectId,repair:request.repair||null};
          openFile(0); renderAll(true); renderFix(); showView('fix');
          logEvent('repair','Restored the saved project and repair request from secure storage');
      });
    });
    }).catch(function(){ /* retain the local workspace if server recovery is temporarily unavailable */ });
  }
  if(saved&&saved.id&&saved.projectId) return restore(saved);
  api('GET','/api/user/repairs').then(function(list){
    var prior=(list.repairs||[]).find(function(r){return r.projectId&&r.status==='submitted';});
    if(prior){ saved={id:prior.id,projectId:prior.projectId,token:null}; sessionStorage.setItem('sf-repair-request',JSON.stringify(saved)); restore(saved); }
  }).catch(function(){});
}
restorePaidSession();

})();
