(function(){
'use strict';
var SF=window.SF, U=SF.u, $=U.$, clamp=U.clamp, ease=U.ease, smooth=U.smooth, esc=U.esc, E=U.E, RM=U.RM;
var demoCmp=SF.demoCmp, allV=SF.allV;
SF.progress={hero:0,unveil:0,scan:0,verify:0,work:0};
var scenes={}; document.querySelectorAll('[data-scene]').forEach(function(s){ scenes[s.dataset.scene]=s; });
var ranges=Array.prototype.map.call(document.querySelectorAll('[data-range]'),function(el){ var r=el.dataset.range.split(',').map(Number); return {el:el,a:r[0],b:r[1],scene:el.closest('[data-scene]').dataset.scene}; });
function rangeO(p,a,b){ var f=.04; if (p<a-f||p>b+f) return 0; if (p<a) return (p-(a-f))/f; if (p>b) return 1-(p-b)/f; return 1; }
var navLinks=document.querySelectorAll('[data-nav]'), bigGauge=SF.makeGauge($('big-gauge'));
$('v-before').textContent=SF.before; $('d-res').textContent=demoCmp.summary.gone; $('d-rem').textContent=demoCmp.summary.still; $('d-new').textContent=demoCmp.summary.new;
$('layer-tabs').innerHTML=SF.layers.map(function(L,k){ return '<div class="lt" data-k="'+k+'"><span class="n">0'+(k+1)+'</span><span class="nm">'+L.name+'<small>'+L.file+'</small></span><span class="ct" id="ct-'+k+'">0 / '+L.vf.length+'</span></div>'; }).join('');
$('ann').innerHTML=SF.layers.map(function(L,k){ return L.vf.slice().sort(function(a,b){return a.line-b.line;}).map(function(f){
  return '<li data-k="'+k+'" data-line="'+f.line+'"><span class="ln">L'+String(f.line).padStart(2,'0')+'</span><span>'+esc(f.title)+'</span><span class="sev sev-'+f.severity+'">'+f.severity+'</span></li>'; }).join(''); }).join('');
var annItems=Array.prototype.slice.call(document.querySelectorAll('#ann li')), tabs=Array.prototype.slice.call(document.querySelectorAll('.lt'));
var lineCount=SF.layers.map(function(L){ return L.vuln.split('\n').length; });

var lastActive=null, fbArt=document.querySelector('.fallback'), lastNav=null;
SF.sp={hero:0,unveil:0,scan:0,verify:0,work:0};

/* Cache layout geometry so scroll handlers never trigger forced reflows */
var geom = { ih: window.innerHeight || 800, unveil: 0, scan: 0, verify: 0, work: 0 };
function updateGeom(){
  geom.ih = window.innerHeight || 800;
  var heroH = scenes.hero ? scenes.hero.offsetHeight : geom.ih;
  geom.unveil = scenes.unveil ? scenes.unveil.offsetTop : heroH;
  geom.scan = scenes.scan ? scenes.scan.offsetTop : (geom.unveil + geom.ih * 1.8);
  geom.verify = scenes.verify ? scenes.verify.offsetTop : (geom.scan + geom.ih * 3.0);
  geom.work = scenes.work ? scenes.work.offsetTop : (geom.verify + geom.ih * 1.7);
}
updateGeom();

/* Continuous scroll mapping with NO dead gaps */
function getProgressAndTarget(sy){
  var P = SF.progress, ih = geom.ih;
  var target = 0;

  if (sy < geom.unveil) {
    P.hero = clamp(sy / Math.max(1, geom.unveil));
    P.unveil = 0; P.scan = 0; P.verify = 0; P.work = 0;
    target = 0;
  } else if (sy < geom.scan) {
    P.hero = 1;
    var u = (sy - geom.unveil) / Math.max(1, geom.scan - geom.unveil);
    P.unveil = clamp(u); P.scan = 0; P.verify = 0; P.work = 0;
    target = P.unveil;
  } else if (sy < geom.verify) {
    P.hero = 1; P.unveil = 1;
    var s = (sy - geom.scan) / Math.max(1, geom.verify - geom.scan);
    P.scan = clamp(s); P.verify = 0; P.work = 0;
    target = 1 + P.scan;
  } else if (sy < geom.work) {
    P.hero = 1; P.unveil = 1; P.scan = 1;
    var v = (sy - geom.verify) / Math.max(1, geom.work - geom.verify);
    P.verify = clamp(v); P.work = 0;
    target = 2 + P.verify;
  } else {
    P.hero = 1; P.unveil = 1; P.scan = 1; P.verify = 1;
    var w = (sy - geom.work) / Math.max(1, ih * 0.75);
    P.work = clamp(w);
    target = 3 + P.work;
  }
  return target;
}

function renderDOM(S){
  SF.chapter = S.work > 0.5 ? 'work' : S.verify > 0.001 ? 'verify' : S.scan > 0.001 ? 'scan' : S.unveil > 0.001 ? 'unveil' : 'hero';

  // Navigation header active pill
  var nav = SF.chapter;
  if (nav !== lastNav) {
    lastNav = nav;
    navLinks.forEach(function(a){
      var match = a.dataset.nav === nav;
      a.classList.toggle('active', match);
      if (match) a.setAttribute('aria-current', 'true');
      else a.removeAttribute('aria-current');
    });
  }

  // Ranges: guarded GPU transforms
  ranges.forEach(function(r){
    var o = rangeO(S[r.scene], r.a, r.b);
    if (r.lastO === undefined || Math.abs(o - r.lastO) > 0.005) {
      r.lastO = o;
      r.el.style.opacity = o;
      r.el.style.transform = 'translate3d(0,' + ((1 - o) * 24).toFixed(1) + 'px,0)';
      r.el.style.visibility = o < 0.01 ? 'hidden' : 'visible';
    }
  });

  // Scene CSS progress variable
  ['unveil','scan','verify'].forEach(function(k){
    var pv = S[k].toFixed(3);
    if (scenes[k].lastP !== pv) {
      scenes[k].lastP = pv;
      scenes[k].style.setProperty('--p', pv);
    }
  });

  if (fbArt) fbArt.style.opacity = (1 - smooth(0.15, 0.85, S.work)).toFixed(3);

  var ev = SF.evidence(S.scan), act = ev.active;
  tabs.forEach(function(t, k){
    var n = SF.layers[k].vf.filter(function(f){ return f.line - 0.5 < ev.reveal[k] * lineCount[k]; }).length;
    if (t.lastN !== n) {
      t.lastN = n;
      $('ct-' + k).textContent = n + ' / ' + SF.layers[k].vf.length;
    }
    t.classList.toggle('on', k === act);
    t.classList.toggle('done', ev.reveal[k] >= 1 && k !== act);
  });

  if (act !== lastActive){
    lastActive = act;
    $('layer-desc').textContent = act < 0 ? 'Three files from one AI-generated demo shop. SecureFlow separates them by layer and reads each statement.' :
      act === 3 ? allV.length + ' findings across three layers, ' + allV.filter(function(f){ return f.severity === 'critical'; }).length + ' of them critical.' : SF.layers[act].desc;
  }

  var latest = null;
  annItems.forEach(function(li){
    var k = +li.dataset.k, on = +li.dataset.line - 0.5 < ev.reveal[k] * lineCount[k];
    var show = (k === act);
    if (li.lastShow !== show) { li.lastShow = show; li.classList.toggle('show', show); }
    if (li.lastOn !== on) { li.lastOn = on; li.classList.toggle('on', on); }
    li.classList.remove('latest');
    if (on && show) latest = li;
  });
  if (latest) latest.classList.add('latest');

  var vs = SF.verifyState(S.verify), g = !vs.fixed ? SF.before * ease(clamp(S.verify / 0.3)) : SF.before + (SF.after - SF.before) * ease(vs.reveal);
  bigGauge.set(g, vs.fixed ? (vs.reveal < 1 ? 'RESCANNING' : 'RISK · AFTER') : 'RISK · BEFORE');
}

var ticking = false, lastT = 0, story = 0, CHAIN = ['unveil','scan','verify','work'];
function tick(now){
  var dt = lastT ? Math.min(0.05, (now - lastT) / 1000) : 0.016;
  lastT = now;
  var sy = window.scrollY || window.pageYOffset || 0;
  var target = getProgressAndTarget(sy);
  var S = SF.sp;
  var d = target - story, moving = false;

  if (RM || Math.abs(d) < 1e-4) {
    story = target;
  } else {
    // Ultra-responsive, fluid smoothing without artificial clamp choking
    var spring = 1 - Math.exp(-dt * 15);
    story += d * spring;
    moving = true;
  }

  CHAIN.forEach(function(k, i){ S[k] = clamp(story - i); });
  S.hero = SF.progress.hero;
  renderDOM(S);

  if (moving) {
    requestAnimationFrame(tick);
  } else {
    ticking = false;
    lastT = 0;
  }
}

function kick(){
  if (!ticking){
    ticking = true;
    requestAnimationFrame(tick);
  }
}

function onScroll(){ kick(); }
function onResize(){ updateGeom(); kick(); }
SF.onScroll = onScroll;
addEventListener('scroll', onScroll, { passive: true });
addEventListener('resize', onResize);

updateGeom();
var initTarget = getProgressAndTarget(window.scrollY || 0);
story = initTarget;
CHAIN.forEach(function(k, i){ SF.sp[k] = clamp(story - i); });
SF.sp.hero = SF.progress.hero;
renderDOM(SF.sp);

/* ---------- 3D failure recovery ---------- */
function fallback3D(){ if (window.SF_3D_READY) return; document.documentElement.classList.add('no-webgl'); $('loader').classList.add('done'); }
SF.fallback3D = fallback3D;
(function(){ try { var c = document.createElement('canvas'); if (!(c.getContext('webgl2') || c.getContext('webgl'))) fallback3D(); } catch(_) { fallback3D(); } })();
addEventListener('error', function(e){ var src = (e && e.filename) || ''; if (/three|jsdelivr/.test(src) || (e && e.target && e.target.tagName === 'SCRIPT' && (/jsdelivr|three/.test(e.target.src || '') || e.target.type === 'module'))) fallback3D(); }, true);
setTimeout(fallback3D, 8000);
function moduleWatch(){ setTimeout(function(){ if (!window.SF_3D_STARTED) fallback3D(); }, 600); }
if (document.readyState === 'complete') moduleWatch(); else addEventListener('load', moduleWatch);
})();
