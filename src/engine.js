/*!
 * SecureFlow engine: static, pattern-based security review for source code.
 * Runs entirely locally (browser main thread, a Web Worker, or Node for tests).
 * It never executes the code it reads, and it makes no network requests.
 *
 * The whole engine lives inside ONE self-contained factory function so it can be
 * stringified into a Blob-backed Web Worker (works from file:// and sandboxed hosts).
 */
(function (root) {
'use strict';

function SecureFlowEngine() {
  'use strict';
  var VERSION = '0.4.0';

  /* ------------------------------------------------------------------ limits */
  var LIMITS = {
    maxFiles: 300,                 // files kept per import
    maxFileBytes: 400 * 1024,      // per file (uncompressed)
    maxTotalBytes: 20 * 1024 * 1024, // all kept files together (uncompressed)
    maxZipBytes: 30 * 1024 * 1024, // the .zip archive itself
    maxZipEntries: 5000,           // central-directory entries we are willing to look at
    maxRatio: 100,                 // uncompressed / compressed, per entry (zip-bomb guard)
    maxLineLength: 5000            // longer lines are skipped (minified / generated)
  };

  /* ------------------------------------------------------------ file types */
  var EXT_LANG = {
    js:'js', jsx:'js', ts:'js', tsx:'js', mjs:'js', cjs:'js', vue:'js', svelte:'js', astro:'js',
    html:'html', htm:'html',
    ejs:'tpl', hbs:'tpl', handlebars:'tpl', njk:'tpl', jinja:'tpl', j2:'tpl', liquid:'tpl',
    py:'py', php:'php', rb:'rb', go:'go', java:'java', kt:'java', cs:'java',
    c:'c', cpp:'cpp', cc:'cpp', cxx:'cpp', h:'cpp', hpp:'cpp', hxx:'cpp',
    sql:'sql',
    json:'config', yaml:'config', yml:'config', toml:'config', ini:'config', conf:'config', xml:'config',
    sh:'shell', bash:'shell'
  };
  function language(path) {
    var p = String(path || '');
    var base = p.split('/').pop();
    if (/^\.env(\.[\w.-]+)?$/i.test(base) || /\.env$/i.test(base)) return 'env';
    if (/^dockerfile(\..+)?$/i.test(base) || /\.dockerfile$/i.test(base)) return 'docker';
    var m = base.match(/\.([a-z0-9]+)$/i);
    return m && EXT_LANG[m[1].toLowerCase()] || null;
  }
  function isSupported(path) { return !!language(path); }
  var JSF = ['js', 'html', 'tpl'];            // browser / node family
  var CODE = ['js', 'html', 'tpl', 'py', 'php', 'rb', 'go', 'java', 'cpp', 'c'];
  var SKIP_DIR = /(?:^|\/)(?:node_modules|\.git|dist|build|\.next|\.nuxt|\.svelte-kit|vendor|coverage|\.cache|out|__pycache__|\.venv|venv)\//;
  var SKIP_FILE = /(?:\.min\.(?:js|css)|\.map|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|(^|\/)__MACOSX\/.*)$/i;

  /* ---------------------------------------------------- path & content safety */
  // Normalises an archive / folder path and rejects anything that could escape the project.
  function safePath(p) {
    if (typeof p !== 'string' || !p || p.length > 512) return null;
    if (p.indexOf('\0') >= 0) return null;
    var s = p.replace(/\\/g, '/');
    if (/^[a-zA-Z]:/.test(s) || s.charAt(0) === '/' || /^~/.test(s)) return null;
    var parts = s.split('/'), out = [];
    for (var i = 0; i < parts.length; i++) {
      var seg = parts[i];
      if (seg === '' || seg === '.') continue;
      if (seg === '..') return null;
      out.push(seg);
    }
    return out.length ? out.join('/') : null;
  }
  function isBinary(text) {
    var n = Math.min(text.length, 8192), ctrl = 0;
    for (var i = 0; i < n; i++) {
      var c = text.charCodeAt(i);
      if (c === 0) return true;
      if (c < 9 || (c > 13 && c < 32)) ctrl++;
    }
    return n > 0 && ctrl / n > 0.1;
  }
  function looksMinified(text) {
    var lines = text.split('\n');
    if (lines.length > 20) return false;
    var longest = 0; for (var i = 0; i < lines.length; i++) if (lines[i].length > longest) longest = lines[i].length;
    return longest > LIMITS.maxLineLength;
  }

  /* --------------------------------------------------------- secret masking */
  var SECRET_NAME = /(?:secret|api[_-]?key|access[_-]?key|auth[_-]?token|token|passw(?:or)?d|pwd|private[_-]?key|client[_-]?secret|bearer|credential)\w*["']?\s*[:=]/i;
  function maskVal(v) { return v.length <= 4 ? '••••' : v.slice(0, 4) + '••••••'; }
  // Applied to EVERY line SecureFlow displays, stores in a finding, or copies out.
  function mask(line) {
    var l = String(line);
    l = l.replace(/\b(sk_live_|sk_test_|rk_live_|pk_live_|AKIA|ASIA|ghp_|gho_|github_pat_|glpat-|xox[bpars]-|AIza|eyJ|SG\.|sbp_)[A-Za-z0-9_\-\.]{4,}/g, '$1••••••');
    l = l.replace(/(\/\/[^\s:\/@'"`]+:)([^\s@'"`]+)(@)/g, '$1••••••$3');
    l = l.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*/g, '-----BEGIN PRIVATE KEY----- ••••••');
    if (SECRET_NAME.test(l)) {
      l = l.replace(/(["'`])([^"'`\s]{6,})\1/g, function (m, q, v) { return /^(?:https?:|process\.env|import\.meta)/.test(v) ? m : q + maskVal(v) + q; });
      l = l.replace(/^(\s*[A-Za-z_][\w.]*\s*=\s*)([^\s'"`#][^\s#]{5,})/, function (m, a, v) { return v.indexOf('••') >= 0 ? m : a + maskVal(v); }); // KEY=value (.env)
    }
    l = l.replace(/(["'`])([A-Za-z0-9+\/_\-]{24,}={0,2})\1/g, function (m, q, v) {
      return (/[0-9]/.test(v) && /[A-Za-z]/.test(v) && !/^(?:https?|[a-z]+\/)/.test(v)) ? q + maskVal(v) + q : m; });
    return l;
  }

  /* ------------------------------------------------------- comment stripping */
  // Produces, per line: `code` (comments blanked, strings kept) and `skel`
  // (comments AND string contents blanked) so rules never fire on comments.
  function family(lang) {
    if (lang === 'py' || lang === 'rb' || lang === 'shell' || lang === 'env' || lang === 'docker' || lang === 'config') return 'hash';
    if (lang === 'sql') return 'sql';
    return 'c';
  }
  var HTML_COMMENT_OPEN = '<' + '!--';   // written split so the engine can be inlined in an HTML <script>
  function lex(text, lang) {
    var fam = family(lang), lines = text.split(/\r\n|\r|\n/), out = [];
    var block = false, html = false, str = null;  // str: '`', "'''", '"""' carry across lines
    for (var li = 0; li < lines.length; li++) {
      var s = lines[li], code = '', skel = '', i = 0;
      if (s.length > LIMITS.maxLineLength) { out.push({ raw: s, code: '', skel: '', long: true }); continue; }
      while (i < s.length) {
        var ch = s[i], two = s.substr(i, 2), three = s.substr(i, 3);
        if (block) { if (two === '*/') { block = false; code += '  '; skel += '  '; i += 2; } else { code += ' '; skel += ' '; i++; } continue; }
        if (html) { if (three === '-->') { html = false; code += '   '; skel += '   '; i += 3; } else { code += ' '; skel += ' '; i++; } continue; }
        if (str) {
          if (ch === '\\') { code += s.substr(i, 2); skel += '  '; i += 2; continue; }
          if (s.substr(i, str.length) === str) { code += str; skel += str; i += str.length; str = null; continue; }
          if (str === '`' && two === '${') { code += '${'; skel += '${'; i += 2; continue; } // keep interpolation visible
          code += ch; skel += ' '; i++; continue;
        }
        if ((lang === 'html' || lang === 'tpl') && s.substr(i, 4) === HTML_COMMENT_OPEN) { html = true; code += '    '; skel += '    '; i += 4; continue; }
        if (fam === 'c' && two === '//' && !(i > 0 && s[i - 1] === ':')) { code += ' '.repeat(s.length - i); skel += ' '.repeat(s.length - i); break; }
        if ((fam === 'c' || fam === 'sql') && two === '/*') { block = true; code += '  '; skel += '  '; i += 2; continue; }
        if (fam === 'sql' && two === '--') break;
        if (fam === 'hash' && ch === '#' && lang !== 'config') { break; }
        if (fam === 'hash' && (three === '"""' || three === "'''")) { str = three; code += three; skel += three; i += 3; continue; }
        if (ch === '"' || ch === "'" || ch === '`') {
          // single-line string: scan to its end on this line
          if (ch === '`' && fam === 'c') { str = '`'; code += ch; skel += ch; i++; continue; }
          var j = i + 1; while (j < s.length && s[j] !== ch) { if (s[j] === '\\') j++; j++; }
          code += s.slice(i, j + 1); skel += ch + ' '.repeat(Math.max(0, Math.min(j, s.length) - i - 1)) + (j < s.length ? ch : '');
          i = j + 1; continue;
        }
        code += ch; skel += ch; i++;
      }
      out.push({ raw: s, code: code, skel: skel, open: !!str || block });
    }
    return out;
  }

  // Groups lexed lines into short "statements" so rules can see code that spans lines
  // (multi-line SQL strings, chained calls) and report ONE finding per statement.
  function statements(lx, lang) {
    var res = [], cur = null, depth = 0;
    function flush() { if (cur) { res.push(cur); cur = null; depth = 0; } }
    for (var i = 0; i < lx.length; i++) {
      var L = lx[i];
      if (!cur) cur = { start: i, end: i, parts: [], skels: [] };
      cur.end = i; cur.parts.push(L.code); cur.skels.push(L.skel);
      var sk = L.skel;
      for (var k = 0; k < sk.length; k++) { var c = sk[k]; if (c === '(' || c === '[') depth++; else if (c === ')' || c === ']') depth--; }
      var t = sk.trim(), next = (lx[i + 1] && lx[i + 1].skel.trim()) || '';
      var cont = L.open || depth > 0 || (lang === 'sql' && t !== '' && !/;$/.test(t)) || /[+\-*\/=,(\[&|?:]$/.test(t) || /^[.+?:]/.test(next) && next !== '';
      if (!cont || cur.parts.length >= 12) flush();
    }
    flush();
    return res;
  }

  /* ------------------------------------------------------------------- rules */
  // sev: critical | high | medium | low | info     conf: high | medium | low
  function R(o) { return o; }
  var RULES = [
    R({ id:'hardcoded-secret', cat:'Secrets', sev:'critical', conf:'high', cwe:'CWE-798', langs:null,
      title:'Hardcoded secret in source',
      test:function (t) {
        if (/\b(?:sk_live_|rk_live_|AKIA[0-9A-Z]{12}|ASIA[0-9A-Z]{12}|ghp_|gho_|github_pat_|glpat-|xox[bpars]-|AIza|SG\.[\w-]{10,}\.|sbp_)[A-Za-z0-9_\-]{8,}/.test(t)) return { conf:'high' };
        if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(t)) return { conf:'high' };
        var m = t.match(/(?:secret|api[_-]?key|access[_-]?key|auth[_-]?token|\btoken|passw(?:or)?d|\bpwd|private[_-]?key|client[_-]?secret)\w*["']?\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/i);
        if (m && !/^(?:your|xxx|changeme|example|placeholder|dummy|test|<|\*|\$\{|process\.env)/i.test(m[1]) && !/example|placeholder|xxxx/i.test(m[1])) return { conf:'medium' };
        return false; },
      why:'Anyone who can read the bundle or the repository can use this credential. Keys committed to git stay in its history even after deletion.',
      fix:'Move the value to a server-side environment variable or secret manager, rotate the exposed key, and never reference it from client code.',
      tests:'Add a CI secret scan (e.g. gitleaks) and a test that the built client bundle contains no key prefixes.' }),
    R({ id:'public-env-secret', cat:'Secrets', sev:'critical', conf:'high', cwe:'CWE-200', langs:JSF.concat(['env','config']),
      title:'Server secret exposed to the browser',
      test:function (t) { return /\b(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|EXPO_PUBLIC|NUXT_PUBLIC)_\w*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD)/i.test(t) || /\bservice_role\b/i.test(t) && /createClient|supabase|key/i.test(t); },
      why:'Variables with a public prefix are inlined into the client bundle. A service-role or secret key there gives anyone full backend access.',
      fix:'Use the public anon key in the browser. Keep secret and service-role keys in server-only code.',
      tests:'Assert the production bundle does not contain the service-role key or any *_SECRET variable.' }),
    R({ id:'db-credentials-url', cat:'Secrets', sev:'critical', conf:'high', cwe:'CWE-798', langs:null,
      title:'Database credentials inside a connection string',
      test:function (t) { return /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql):\/\/[^\s:'"`\/@$]+:[^\s@'"`${}]{3,}@/.test(t); },
      why:'A username and password are written directly into the code or config, so anyone with read access can log in to the database.',
      fix:'Load the connection string from an environment variable or secret manager and rotate the password.',
      tests:'Add a secret-scanning step that fails the build on credentials in connection URLs.' }),
    R({ id:'env-file', cat:'Secrets', sev:'high', conf:'medium', cwe:'CWE-538', langs:['env'], oncePerFile:true,
      title:'Environment file with values included in the project',
      test:function (t, ctx) { return !/(?:example|sample|template|dist|defaults?)$/i.test(ctx.path) && /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+/.test(t); },
      why:'.env files usually hold real credentials. If this file is committed or deployed with the site, those values are exposed.',
      fix:'Remove the file from the repository and deployment, add it to .gitignore, commit a .env.example with empty values, and rotate anything it contained.',
      tests:'Add a CI check that fails if any .env file (other than .env.example) is tracked.' }),

    R({ id:'sql-injection', cat:'Injection', sev:'critical', conf:'high', cwe:'CWE-89', langs:CODE, multiline:true,
      title:'SQL query built from user input',
      test:function (t) {
        return /`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{/i.test(t) ||
          /["']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+\s*[\w.\[\]]+/i.test(t) ||
          /\bf["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{/i.test(t) ||
          /(?:execute|query|raw)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*(?:%|\.format)/i.test(t) ||
          /\$(?:wpdb|pdo|mysqli|conn|db)->(?:query|prepare)\s*\(\s*["'][^"']*\$_(?:GET|POST|REQUEST)/.test(t); },
      why:'Putting request data straight into SQL lets an attacker rewrite the query to read other users’ rows, bypass login or delete data.',
      fix:'Use parameterised queries ($1 or ? placeholders) or the ORM’s query builder, and pass user values as bound parameters.',
      tests:'Add a test that sends \' OR 1=1 -- and a UNION payload to this endpoint and asserts no extra rows are returned.' }),
    R({ id:'nosql-injection', cat:'Injection', sev:'high', cwe:'CWE-943', conf:'high', langs:JSF,
      title:'Raw request object used as a database filter',
      test:function (t) { return /\.(?:find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\(\s*req\.(?:body|query|params)\s*[,)]/.test(t); },
      why:'Passing req.body directly allows operators such as {"password":{"$ne":null}} that bypass checks.',
      fix:'Build the filter from explicitly picked, type-checked fields, e.g. { email: String(req.body.email) }.',
      tests:'Send {"email":{"$ne":null}} and assert the request is rejected.' }),
    R({ id:'command-injection', cat:'Injection', sev:'critical', conf:'high', cwe:'CWE-78', langs:CODE, multiline:true,
      title:'Shell command built from input',
      test:function (t) {
        return /\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*`[^`]*\$\{/.test(t) || /\b(?:exec|execSync)\s*\(\s*["'][^"']*["']\s*\+/.test(t) ||
          /subprocess\.\w+\([^)]*shell\s*=\s*True/.test(t) || /os\.system\s*\(\s*(?:f["']|[^)]*\+)/.test(t) ||
          /\b(?:shell_exec|system|passthru|exec|popen)\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST)/.test(t); },
      why:'Shell metacharacters in the input (; | $( )) run arbitrary commands on your server.',
      fix:'Use execFile or spawn with an argument array and no shell, and validate input against an allowlist.',
      tests:'Pass "; touch /tmp/pwned" as input and assert the file is not created and the call is rejected.' }),
    R({ id:'code-eval', cat:'Injection', sev:'critical', conf:'high', cwe:'CWE-95', langs:CODE, skel:true,
      title:'Dynamic code execution (eval)',
      test:function (t, ctx) {
        if (ctx.lang === 'py') return /\b(?:eval|exec)\s*\(\s*(?:request|input|data|payload|body|params)\b/.test(t) || /\b(?:eval|exec)\s*\(\s*\w+\.(?:args|form|json|data)/.test(t);
        if (ctx.lang === 'php') return /\beval\s*\(/.test(t);
        return /(?:^|[^\w.$])eval\s*\(/.test(t) || /new\s+Function\s*\(/.test(t) || /\bset(?:Timeout|Interval)\s*\(\s*["'`]/.test(t); },
      why:'eval() runs whatever string it receives. With user-controlled input that is remote code execution.',
      fix:'Replace it with a parser for the expected format (JSON.parse, a math-expression library, or an explicit allowlist).',
      tests:'Pass "process.exit()" or "__import__(\'os\')" and assert it is rejected, not executed.' }),
    R({ id:'ssrf', cat:'Injection', sev:'high', conf:'medium', cwe:'CWE-918', langs:['js','py','php'], multiline:true,
      title:'Server request to a URL taken from the request',
      test:function (t) {
        return /\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got|request|needle|superagent\.get|https?\.get|urllib\.request\.urlopen|requests\.(?:get|post|put|request)|httpx\.(?:get|post)|file_get_contents|curl_init)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:args|form|json|GET|POST)|\$_(?:GET|POST|REQUEST))/.test(t) ||
          /\b(?:fetch|axios\.get|requests\.get)\s*\(\s*`[^`]*\$\{\s*req\.(?:query|body|params)/.test(t); },
      why:'Letting a user choose the URL your server fetches can expose internal services and cloud metadata endpoints.',
      fix:'Validate the URL against an allowlist of hosts, block private and link-local IP ranges, and disable redirects.',
      tests:'Request http://169.254.169.254/ and http://localhost:22 through this endpoint and assert both are refused.' }),
    R({ id:'path-traversal', cat:'Injection', sev:'high', conf:'high', cwe:'CWE-22', langs:CODE,
      title:'File path taken from the request',
      test:function (t) {
        return /(?:readFile|readFileSync|createReadStream|sendFile|res\.download|unlink|unlinkSync|writeFile)\s*\([^)]*req\.(?:query|params|body)/.test(t) ||
          /\bopen\s*\([^)]*request\.(?:args|form|GET|POST)/.test(t) || /send_file\s*\([^)]*request\.(?:args|form)/.test(t) ||
          /\b(?:include|require|include_once|require_once|file_get_contents|fopen|readfile)\s*\(?\s*[^;]*\$_(?:GET|POST|REQUEST)/.test(t); },
      why:'../ sequences let an attacker read or overwrite files outside the intended folder, such as .env.',
      fix:'Reduce input to a bare file name (path.basename), serve it from a fixed root, and check the resolved path stays inside that root.',
      tests:'Request ../../.env and %2e%2e%2f variants and assert a 400/404 without file contents.' }),
    R({ id:'insecure-deserialization', cat:'Injection', sev:'high', conf:'high', cwe:'CWE-502', langs:CODE,
      title:'Unsafe deserialisation',
      test:function (t) { return /pickle\.loads?\s*\(/.test(t) || /yaml\.load\s*\((?![^)]*(?:SafeLoader|safe_load))/.test(t) || /\bunserialize\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST)/.test(t) || /require\(['"]node-serialize['"]\)/.test(t) || /\bmarshal\.loads\s*\(/.test(t); },
      why:'Deserialising attacker-controlled data with pickle, yaml.load or unserialize can execute code.',
      fix:'Use JSON or yaml.safe_load for untrusted input.',
      tests:'Feed a crafted payload and assert it is rejected without side effects.' }),

    R({ id:'reflected-xss', cat:'XSS & output', sev:'high', conf:'high', cwe:'CWE-79', langs:CODE, multiline:true,
      title:'User input reflected into HTML',
      test:function (t) { return /res\.(?:send|write|end)\s*\(\s*`[^`]*<[^`]*\$\{/.test(t) || /res\.(?:send|write)\s*\(\s*["'][^"']*<[^"']*["']\s*\+\s*req\./.test(t) || /render_template_string\s*\([^)]*request/.test(t) || /\becho\s+[^;]*\$_(?:GET|POST|REQUEST)/.test(t) || /make_response\s*\(\s*f["'][^"']*<[^"']*\{/.test(t); },
      why:'Values inserted into raw HTML responses can carry script payloads that run in your users’ browsers.',
      fix:'Return JSON, or render through a template engine with auto-escaping. Escape any value placed in HTML.',
      tests:'Send <script>alert(1)</script> and assert the response contains it escaped (&lt;script&gt;).' }),
    R({ id:'dom-xss', cat:'XSS & output', sev:'high', conf:'high', cwe:'CWE-79', langs:JSF,
      title:'Unsanitised HTML injected into the page',
      test:function (t) {
        var m = t.match(/\.(?:innerHTML|outerHTML)\s*\+?=\s*([^;]+)/);
        if (m && !/^\s*(["'`])[^"'`$]*\1\s*$/.test(m[1]) && !/DOMPurify\.sanitize|escapeHtml|sanitize\(/.test(m[1])) return true;
        return /insertAdjacentHTML\s*\(\s*["'][^"']+["']\s*,\s*(?!["'`][^"'`$]*["'`]\s*\))/.test(t) || /document\.write(?:ln)?\s*\(\s*(?!["'`][^"'`$]*["'`]\s*\))/.test(t) ||
          /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:(?!\s*(?:DOMPurify|sanitize))/.test(t) || /\bv-html\s*=/.test(t) || /\{@html\s/.test(t); },
      why:'Assigning dynamic strings to innerHTML (or dangerouslySetInnerHTML / v-html) runs any markup and event handlers inside them.',
      fix:'Use textContent or normal JSX/template rendering. If HTML is truly required, sanitise it with DOMPurify first.',
      tests:'Render the value <img src=x onerror=alert(1)> and assert no script runs and the markup is escaped or stripped.' }),
    R({ id:'unsafe-template', cat:'XSS & output', sev:'high', conf:'medium', cwe:'CWE-79', langs:['tpl','html','py','js'],
      title:'Template output with escaping turned off',
      test:function (t) { return /<%-\s*(?!\s*include\b)[\w.]+/.test(t) || /\{\{\{\s*[\w.]+\s*\}\}\}/.test(t) || /\{\{[^}]*\|\s*safe\b/.test(t) || /\bmark_safe\s*\(/.test(t) || /\bMarkup\s*\(\s*(?:request|f["'])/.test(t) || /\{%\s*autoescape\s+false/.test(t); },
      why:'Unescaped template output renders user-controlled HTML, which allows stored or reflected XSS.',
      fix:'Use the escaped form ({{ }}, <%= %>) and sanitise any HTML you must allow.',
      tests:'Store <script> in the field and assert the rendered page shows it as text.' }),
    R({ id:'dynamic-script', cat:'XSS & output', sev:'medium', conf:'low', cwe:'CWE-829', langs:JSF,
      title:'Script loaded from a dynamic URL',
      test:function (t) { return /\b(?:script|scr|s|tag|el)\w*\.src\s*=\s*(?!\s*["'`][^"'`$+]*["'`]\s*;?\s*$)[^;]*(?:location|search|hash|params|query|url|input|\+)/i.test(t) && !/\.(?:png|jpe?g|gif|svg|webp)/.test(t) || /\bimportScripts\s*\(\s*(?!["'`][^"'`$]*["'`]\s*\))/.test(t); },
      why:'If the URL can be influenced by a visitor or a third party, an attacker can load their own script into your page.',
      fix:'Load scripts only from fixed, trusted URLs and add Subresource Integrity (integrity="…") where possible.',
      tests:'Assert the script URL is built only from an allowlist.' }),

    R({ id:'jwt-unverified', cat:'Auth & sessions', sev:'high', conf:'high', cwe:'CWE-347', langs:['js','py'],
      title:'Login token read without verification',
      test:function (t) { return (/jwt\.decode\s*\(/.test(t) && !/verify_signature["']?\s*:\s*True|algorithms\s*=/.test(t)) || /algorithms?\s*[:=]\s*\[?\s*["']none["']/i.test(t) || /verify_signature["']?\s*:\s*False/.test(t) || /ignoreExpiration\s*:\s*true/.test(t); },
      why:'decode() only reads the token. Anyone can forge one with any user id and it will be trusted.',
      fix:'Use jwt.verify(token, secret, { algorithms: [\'HS256\'] }) (or the library’s verify call) and reject the request on failure.',
      tests:'Send a token signed with a different key and one with alg "none"; assert both get 401.' }),
    R({ id:'plaintext-password', cat:'Auth & sessions', sev:'high', conf:'medium', cwe:'CWE-256', langs:['js','py','php'],
      title:'Password compared or stored in plain text',
      test:function (t) { return /\.password\s*={2,3}\s*(?:req\.body|request\.(?:form|json)|password\b)/.test(t) || /(?:req\.body|request\.form)\.?\[?["']?password["']?\]?\s*={2,3}\s*\w+\.password/.test(t) || /password\s*:\s*req\.body\.password\b/.test(t) && /(?:create|insert|save)/i.test(t); },
      why:'Comparing or saving the raw password means it is stored unhashed; one database leak exposes every account.',
      fix:'Hash passwords with bcrypt, scrypt or Argon2 when storing them, and compare with the library’s constant-time verify function.',
      tests:'Assert stored password fields never equal the submitted password and that login uses the hash verify call.' }),
    R({ id:'token-localstorage', cat:'Auth & sessions', sev:'medium', conf:'high', cwe:'CWE-922', langs:JSF,
      title:'Login token stored in localStorage',
      test:function (t) { return /(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'`][^"'`]*(?:token|jwt|auth|session)/i.test(t); },
      why:'Any XSS on the page can read localStorage and steal the session.',
      fix:'Have the server set the session in an httpOnly, Secure, SameSite cookie.',
      tests:'Assert no auth token is written to localStorage after login.' }),
    R({ id:'cookie-flags', cat:'Auth & sessions', sev:'medium', conf:'high', cwe:'CWE-1004', langs:['js','py','php'],
      title:'Session cookie missing protective flags',
      test:function (t) { return /httpOnly\s*:\s*false/i.test(t) || /\bsecure\s*:\s*false/.test(t) || (/sameSite\s*:\s*["']none["']/i.test(t) && !/secure\s*:\s*true/.test(t)) || /SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False/.test(t) || /set_cookie\([^)]*httponly\s*=\s*False/.test(t); },
      why:'Cookies without httpOnly and Secure can be read by scripts or sent over plain HTTP.',
      fix:'Set { httpOnly: true, secure: true, sameSite: \'lax\' } (or the framework’s equivalent) on session cookies.',
      tests:'Assert the Set-Cookie header for the session contains HttpOnly; Secure; SameSite=Lax.' }),
    R({ id:'missing-auth', cat:'Access control', sev:'medium', conf:'low', cwe:'CWE-862', langs:['js'],
      title:'Sensitive route with no visible auth middleware',
      test:function (t) { return /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["'`][^"'`]*\/(?:admin|users?|accounts?|settings|billing|delete|internal)\b[^"'`]*["'`]\s*,\s*(?:async\s*)?(?:\(\s*req|function\s*\(\s*req|req\s*=>)/.test(t); },
      why:'The handler is attached directly to a sensitive path with no auth middleware in the route definition. Auth may be applied elsewhere (globally or in a parent router), so treat this as a prompt to check.',
      fix:'Add authentication and an authorisation check (e.g. requireAuth, requireRole(\'admin\')) to this route, or confirm a parent router already enforces it.',
      tests:'Call the route without a session and as a normal user; assert 401 and 403 respectively.' }),
    R({ id:'open-redirect', cat:'Access control', sev:'medium', conf:'high', cwe:'CWE-601', langs:['js','py','php'],
      title:'Open redirect from a URL parameter',
      test:function (t) { return /res\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?req\.(?:query|body|params)/.test(t) || /\bredirect\s*\(\s*request\.(?:args|GET)/.test(t) || /location(?:\.href)?\s*=\s*(?:new URLSearchParams\([^)]*\)\.get|params\.get|searchParams\.get)/.test(t) || /header\s*\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|REQUEST)/.test(t); },
      why:'Attackers send links on your domain that bounce victims to a phishing page, which makes the link look trustworthy.',
      fix:'Only redirect to relative paths or an allowlist of hosts. Fall back to "/" otherwise.',
      tests:'Request ?next=https://evil.example and ?next=//evil.example and assert the redirect stays on your site.' }),

    R({ id:'weak-hash', cat:'Crypto', sev:'high', conf:'high', cwe:'CWE-327', langs:CODE,
      title:'Weak hash (MD5 / SHA-1)',
      test:function (t, ctx) {
        var hit = /createHash\s*\(\s*["'](?:md5|sha1)["']/i.test(t) || /hashlib\.(?:md5|sha1)\s*\(/.test(t) || /\b(?:md5|sha1)\s*\(\s*\$/.test(t);
        if (!hit) return false;
        return { conf: /pass(?:word)?|pw\b|pwd|secret|token/i.test(t + ' ' + (ctx.prev || '')) ? 'high' : 'medium' }; },
      why:'MD5 and SHA-1 are fast and broken. Password hashes made with them are cracked in seconds once leaked.',
      fix:'Use bcrypt, scrypt or Argon2 for passwords; SHA-256 or better for integrity checks.',
      tests:'Assert stored password hashes start with the bcrypt/argon2 prefix ($2b$ / $argon2id$).' }),
    R({ id:'insecure-random', cat:'Crypto', sev:'medium', conf:'medium', cwe:'CWE-338', langs:['js','py','php'],
      title:'Predictable random value used for a security token',
      test:function (t, ctx) {
        if (!/Math\.random\s*\(/.test(t) && !/\brandom\.(?:random|randint|choice|choices)\s*\(/.test(t) && !/\b(?:rand|mt_rand)\s*\(/.test(t)) return false;
        return /token|secret|password|nonce|otp|session|reset|apikey|api_key|code|salt/i.test(t + ' ' + (ctx.prev || '')); },
      why:'Math.random and friends are not cryptographically secure, so tokens made with them can be predicted.',
      fix:'Use crypto.randomBytes / crypto.randomUUID (Node), crypto.getRandomValues (browser) or secrets.token_hex (Python).',
      tests:'Assert tokens are at least 128 bits and generated by the crypto API (mock it in the test).' }),

    R({ id:'tls-disabled', cat:'Transport & config', sev:'high', conf:'high', cwe:'CWE-295', langs:null,
      title:'TLS certificate checks turned off',
      test:function (t) { return /rejectUnauthorized\s*:\s*false/.test(t) || /tlsAllowInvalidCertificates\s*:\s*true/.test(t) || /\bverify\s*=\s*False/.test(t) || /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/.test(t) || /CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)/.test(t) || /InsecureSkipVerify\s*:\s*true/.test(t); },
      why:'Without certificate checks, anyone on the network path can read and alter the traffic.',
      fix:'Remove the override. For a private CA, pass the CA certificate explicitly.',
      tests:'Point the client at a server with a self-signed certificate and assert the connection fails.' }),
    R({ id:'cors-wildcard', cat:'Transport & config', sev:'medium', conf:'high', cwe:'CWE-942', langs:['js','py','php','config'],
      title:'API accepts requests from any website',
      test:function (t) { return /origin\s*:\s*["'`]\*["'`]/.test(t) || /Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*/i.test(t) || /\borigin\s*:\s*true\b/.test(t) || /allow_origins\s*=\s*\[\s*["']\*["']/.test(t) || /CORS_ALLOW_ALL_ORIGINS\s*=\s*True/.test(t) || /CORS\s*\(\s*app\s*\)/.test(t) && !/origins/.test(t); },
      why:'Any site can call your API from a visitor’s browser. With credentials allowed, that can leak user data.',
      fix:'List the exact origins you serve, e.g. origin: [\'https://yourapp.com\'].',
      tests:'Send a request with Origin: https://evil.example and assert no Access-Control-Allow-Origin header is returned.' }),
    R({ id:'error-leak', cat:'Transport & config', sev:'medium', conf:'medium', cwe:'CWE-209', langs:['js','py','php'],
      title:'Internal error details sent to the client',
      test:function (t) { return /res\.(?:send|json)\s*\(\s*(?:err|error|e)(?:\.stack|\.message)?\s*\)/.test(t) || /res\.status\(\s*5\d\d\s*\)\.(?:send|json)\(\s*(?:err|error|e)\b/.test(t) || /\bstack\s*:\s*(?:err|error|e)\.stack/.test(t) || /traceback\.format_exc\(\)/.test(t) && /return|jsonify|Response/.test(t) || /\bdie\s*\(\s*mysqli_error/.test(t); },
      why:'Stack traces and raw error messages reveal file paths, library versions and query details to attackers.',
      fix:'Log the full error on the server and return a generic message with a request id.',
      tests:'Force an error and assert the response body contains no stack trace or SQL text.' }),
    R({ id:'debug-mode', cat:'Transport & config', sev:'medium', conf:'high', cwe:'CWE-489', langs:['py','js','config','env','php'],
      title:'Debug mode enabled',
      test:function (t) { return /\bdebug\s*=\s*True/.test(t) || /^\s*DEBUG\s*=\s*(?:True|true|1)\b/.test(t) || /app\.run\([^)]*debug\s*=\s*True/.test(t) || /display_errors["']?\s*,\s*["']?(?:1|On)/i.test(t); },
      why:'Debug pages expose stack traces, settings and sometimes an interactive console.',
      fix:'Drive it from an environment variable and keep it off in production.',
      tests:'Assert the production config has debug disabled.' }),
    R({ id:'plain-http', cat:'Transport & config', sev:'low', conf:'high', cwe:'CWE-319', langs:null,
      title:'Request over unencrypted HTTP',
      test:function (t) { return /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|example\.(?:com|org))/.test(t); },
      why:'Plain HTTP can be read or altered in transit.',
      fix:'Switch the URL to https://.',
      tests:'Assert all outbound URLs in config use https.' }),
    R({ id:'docker-root', cat:'Transport & config', sev:'low', conf:'medium', cwe:'CWE-250', langs:['docker'],
      title:'Container explicitly runs as root',
      test:function (t) { return /^\s*USER\s+(?:root|0)\s*$/i.test(t); },
      why:'If the app is compromised, the attacker gets root inside the container.',
      fix:'Create and switch to an unprivileged user (USER node / USER app).',
      tests:'Assert `id -u` inside the container is not 0.' }),
    R({ id:'permissive-rls', cat:'Access control', sev:'high', conf:'medium', cwe:'CWE-284', langs:['sql'], multiline:true,
      title:'Database policy allows every row',
      test:function (t) { return /create\s+policy\b[\s\S]*\busing\s*\(\s*true\s*\)/i.test(t) || /with\s+check\s*\(\s*true\s*\)/i.test(t) || /disable\s+row\s+level\s+security/i.test(t); },
      why:'A row-level-security policy of USING (true) lets every user read or change every row, the same as having no policy.',
      fix:'Restrict policies to the owner, e.g. USING (auth.uid() = user_id), and keep RLS enabled on every table.',
      tests:'Query the table as user A for user B’s rows and assert zero rows are returned.' }),
    R({ id:'cpp-buffer-overflow', cat:'Memory Safety', sev:'critical', conf:'high', cwe:'CWE-120', langs:['cpp','c'],
      title:'Unbounded buffer copy (buffer overflow)',
      test:function (t) { return /\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(/.test(t); },
      why:'Unbounded functions copy data without checking the destination buffer size, enabling stack-based buffer overflows and arbitrary code execution.',
      fix:'Use bounded alternatives like snprintf(), strncpy() with null-termination, or modern C++ std::string.',
      tests:'Supply an input string larger than the destination buffer and verify no memory corruption or crash occurs.' }),
    R({ id:'cpp-format-string', cat:'Injection', sev:'critical', conf:'high', cwe:'CWE-134', langs:['cpp','c'],
      title:'Uncontrolled format string',
      test:function (t) { return /\b(?:printf|fprintf|syslog)\s*\(\s*(?!(?:["'`]|(?:stderr|stdout)\s*,\s*["'`]))(?:[A-Za-z_$][\w$]*|req\w*|\w+->\w+)\s*[,)]/.test(t); },
      why:'Passing user-controlled strings directly as the format argument allows attackers to leak memory (%x, %s) or overwrite memory addresses (%n).',
      fix:'Always specify a format string literal, for example: printf("%s", user_str);',
      tests:'Pass "%x %x %n" as input and verify the string is printed literally without formatting evaluation.' })
  ];
  // Project-level checks: they look at the whole upload, report low confidence, and say so.
  var PROJECT_RULES = [
    { id:'no-security-headers', cat:'Transport & config', sev:'info', conf:'low', cwe:'CWE-693', title:'No security-headers middleware found in the uploaded files',
      why:'No helmet (or equivalent header setup) appears anywhere in the uploaded code. Headers may still be set by your host or a proxy, which SecureFlow cannot see.',
      fix:'Add helmet() (Express) or set Content-Security-Policy, X-Content-Type-Options, Referrer-Policy and frame-ancestors at your host.',
      tests:'Assert responses include Content-Security-Policy and X-Content-Type-Options headers.' },
    { id:'no-rate-limit', cat:'Auth & sessions', sev:'info', conf:'low', cwe:'CWE-307', title:'Login route with no rate limiting found in the uploaded files',
      why:'A login or auth route exists, but no rate-limiting library or limiter appears in the uploaded code. It may be enforced by your host or gateway.',
      fix:'Add a limiter (e.g. express-rate-limit) to login and password-reset routes.',
      tests:'Send 20 failed logins in a minute and assert later attempts are throttled (429).' }
  ];
  var ALL_RULES = RULES.concat(PROJECT_RULES);
  var RULE_BY_ID = {}; ALL_RULES.forEach(function (r) { RULE_BY_ID[r.id] = r; });

  /* ---------------------------------------------------------------- helpers */
  function hash(s) { var h = 5381; for (var i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0; return (h >>> 0).toString(16).padStart(8, '0'); }
  function norm(s) { return String(s).replace(/\s+/g, ' ').trim(); }
  var SEV_ORDER = { critical:0, high:1, medium:2, low:3, info:4 };
  var SEV_W = { critical:.35, high:.2, medium:.1, low:.03, info:0 };
  var CONF_ORDER = { high:0, medium:1, low:2 };
  function ruleInfo(r) { return { id:r.id, title:r.title, sev:r.sev, conf:r.conf, cat:r.cat, cwe:r.cwe, why:r.why, fix:r.fix, tests:r.tests }; }

  function makeFinding(r, file, rawLines, line, endLine, conf) {
    var s = Math.max(1, line - 2), e = Math.min(rawLines.length, Math.max(endLine, line) + 2), ev = [];
    for (var n = s; n <= e; n++) ev.push({ n: n, text: mask(rawLines[n - 1] || ''), hit: n >= line && n <= endLine });
    var code = mask(rawLines[line - 1] || '');
    return {
      ruleId: r.id, rule: ruleInfo(r), title: r.title, severity: r.sev, confidence: conf || r.conf, category: r.cat, cwe: r.cwe,
      file: file, line: line, endLine: endLine, column: ((rawLines[line - 1] || '').search(/\S/) + 1) || 1, code: code, evidence: ev,
      why: r.why, fix: r.fix, tests: r.tests, detection: 'static-heuristic',
      fp: r.id + '|' + norm(code).slice(0, 200)
    };
  }

  /* -------------------------------------------------------------- scanning */
  function scanFile(file) {
    var lang = language(file.name);
    if (!lang) return { skipped: 'unsupported-type' };
    if (isBinary(file.code)) return { skipped: 'binary' };
    if (looksMinified(file.code)) return { skipped: 'minified-or-generated' };
    var lx = lex(file.code, lang), raw = lx.map(function (l) { return l.raw; }), st = statements(lx, lang), out = [], once = {}, seen = {};
    var rules = RULES.filter(function (r) { return !r.langs || r.langs.indexOf(lang) >= 0; });
    var prevText = '';
    for (var si = 0; si < st.length; si++) {
      var S = st[si], text = S.parts.join(' '), skelText = S.skels.join(' ');
      if (!text.trim()) { continue; }
      var ctx = { lang: lang, path: file.name, prev: prevText };
      for (var ri = 0; ri < rules.length; ri++) {
        var r = rules[ri];
        if (r.oncePerFile && once[r.id]) continue;
        var res = r.test(r.skel ? skelText : text, ctx);
        if (!res) continue;
        // attribute to the first single line that matches by itself; otherwise the statement's first line
        var at = S.start, hitEnd = S.end, single = false;
        for (var k = S.start; k <= S.end; k++) { if (lx[k].code.trim() && r.test(r.skel ? lx[k].skel : lx[k].code, ctx)) { at = k; hitEnd = k; single = true; break; } }
        if (!single) { while (at < S.end && !lx[at].code.trim()) at++; }
        var key = r.id + ':' + at; if (seen[key]) continue; seen[key] = 1;
        out.push(makeFinding(r, file.name, raw, at + 1, hitEnd + 1, res && res.conf));
        if (r.oncePerFile) once[r.id] = 1;
      }
      prevText = text;
    }
    return { findings: out, lines: raw.length, lang: lang };
  }

  function projectChecks(files) {
    var out = [], js = files.filter(function (f) { var l = language(f.name); return l === 'js'; });
    if (!js.length) return out;
    var all = js.map(function (f) { return f.code; }).join('\n');
    function firstLine(re) { for (var i = 0; i < js.length; i++) { var ls = js[i].code.split(/\r\n|\r|\n/); for (var j = 0; j < ls.length; j++) if (re.test(ls[j]) && !/^\s*\/\//.test(ls[j])) return { f: js[i], ls: ls, n: j + 1 }; } return null; }
    var expressLine = firstLine(/\bexpress\s*\(\s*\)/);
    if (expressLine && !/\bhelmet\b|Content-Security-Policy|X-Content-Type-Options/i.test(all))
      out.push(makeFinding(RULE_BY_ID['no-security-headers'], expressLine.f.name, expressLine.ls, expressLine.n, expressLine.n));
    var login = firstLine(/\.(?:post|get|all)\s*\(\s*["'`][^"'`]*(?:login|signin|sign-in|auth\/token|session|reset-password|forgot)/i);
    if (login && !/rate-?limit|rateLimit|slowDown|limiter|throttle/i.test(all))
      out.push(makeFinding(RULE_BY_ID['no-rate-limit'], login.f.name, login.ls, login.n, login.n));
    return out;
  }

  function sortFindings(fs) {
    return fs.sort(function (a, b) { return SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || CONF_ORDER[a.confidence] - CONF_ORDER[b.confidence] || a.file.localeCompare(b.file) || a.line - b.line; });
  }
  function assignIds(fs) {
    var count = {};
    fs.forEach(function (f) { var base = f.file + '|' + f.fp; count[base] = (count[base] || 0) + 1; f.id = 'SF-' + hash(base + '#' + count[base]).toUpperCase(); });
    return fs;
  }

  // files: [{name, code}]  opts: {onProgress(done,total,path), shouldCancel()}
  function scanProject(files, opts) {
    opts = opts || {};
    var t0 = now(), findings = [], skipped = [], failed = [], analyzed = 0, lines = 0;
    for (var i = 0; i < files.length; i++) {
      if (opts.shouldCancel && opts.shouldCancel()) return { status: 'cancelled', findings: [], coverage: null };
      var f = files[i];
      try {
        if (!f.code || !f.code.trim()) { skipped.push({ path: f.name, reason: 'empty' }); continue; }
        var r = scanFile(f);
        if (r.skipped) { skipped.push({ path: f.name, reason: r.skipped }); continue; }
        analyzed++; lines += r.lines; findings = findings.concat(r.findings);
      } catch (e) { failed.push({ path: f.name, error: String(e && e.message || e) }); }
      if (opts.onProgress) opts.onProgress(i + 1, files.length, f.name);
    }
    try { findings = findings.concat(projectChecks(files.filter(function (f) { return f.code && isSupported(f.name); }))); } catch (e) { failed.push({ path: '(project checks)', error: String(e) }); }
    assignIds(sortFindings(findings));
    var status = !files.length ? 'failed' : (analyzed === 0 ? 'failed' : (failed.length ? 'incomplete' : (skipped.length ? 'complete-with-exclusions' : 'complete')));
    return { status: status, findings: findings, coverage: {
      imported: files.length, analyzed: analyzed, skipped: skipped, failed: failed, lines: lines,
      rules: ALL_RULES.length, durationMs: Math.round(now() - t0), engine: VERSION } };
  }
  function now() { return (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now(); }

  /* ------------------------------------------------------- score & verdict */
  function counts(fs) { var c = { critical:0, high:0, medium:0, low:0, info:0 }; fs.forEach(function (f) { c[f.severity]++; }); return c; }
  // Secondary indicator only: 100 × (1 − Π(1 − weight)). Not a probability of compromise.
  function score(fs) { return score2(fs); }   // see score2: severity weight × confidence factor
  function verdict(fs, status) {
    if (status === 'failed') return { level:'failed', title:'Scan failed', detail:'No supported source files could be analysed, so there is no score.' };
    if (status === 'cancelled') return { level:'failed', title:'Scan cancelled', detail:'Partial results were discarded.' };
    var c = counts(fs), n = fs.length;
    var excl = status === 'complete-with-exclusions' ? ' Some files were excluded, so coverage is partial.' : status === 'incomplete' ? ' Some files failed to analyse, so coverage is partial.' : '';
    if (!n) return { level:'clear', title:'No findings detected by the enabled rules', detail:'That is not proof of security: these checks cannot see business logic, authorisation design or multi-file data flows.' + excl };
    if (c.critical) return { level:'critical', title:'Do not ship yet', detail: c.critical + ' critical issue' + (c.critical > 1 ? 's' : '') + (c.high ? ' and ' + c.high + ' high' : '') + '. Fix the critical ones first.' + excl };
    if (c.high) return { level:'high', title:'Fix before launch', detail:'No critical issues, but ' + c.high + ' high-risk issue' + (c.high > 1 ? 's' : '') + ' remain.' + excl };
    if (c.medium) return { level:'medium', title:'Fix soon', detail:'No critical or high issues. ' + c.medium + ' medium issue' + (c.medium > 1 ? 's' : '') + ' left.' + excl };
    if (c.low) return { level:'low', title:'Nearly there', detail:'Only ' + c.low + ' low-severity item' + (c.low > 1 ? 's' : '') + ' left' + (c.info ? ', plus ' + c.info + ' informational' : '') + '.' + excl };
    return { level:'low', title:'Informational notes only', detail: c.info + ' informational note' + (c.info > 1 ? 's' : '') + ' to review.' + excl };
  }

  /* ---------------------------------------------------- ProofLoop compare */
  function similarity(a, b) {
    function set(t) { var s = {}; String(t || '').split(/\r\n|\r|\n/).forEach(function (l) { l = l.trim(); if (l) s[l] = 1; }); return s; }
    var A = set(a), B = set(b), inter = 0, uni = 0, k;
    for (k in A) { uni++; if (B[k]) inter++; } for (k in B) if (!A[k]) uni++;
    return uni ? inter / uni : 1;
  }
  // prev / cur: { findings, files: {path: content} }
  // States: still | gone | new | notrechecked | inconclusive | verified (only with an executed test result)
  function compareScans(prev, cur, testResults) {
    var rows = [], used = {};
    var curIdx = cur.findings.map(function (f, i) { return { f: f, i: i }; });
    function take(pred) { for (var k = 0; k < curIdx.length; k++) { var c = curIdx[k]; if (!used[c.i] && pred(c.f)) { used[c.i] = 1; return c.f; } } return null; }
    prev.findings.forEach(function (p) {
      var inCur = Object.prototype.hasOwnProperty.call(cur.files, p.file), m;
      if (inCur && (m = take(function (c) { return c.file === p.file && c.fp === p.fp; })))
        return rows.push({ state:'still', prev:p, cur:m, reason:'Same code still matches' + (m.line !== p.line ? ' (now line ' + m.line + ')' : '') + '.' });
      if (inCur && (m = take(function (c) { return c.file === p.file && c.ruleId === p.ruleId && Math.abs(c.line - p.line) <= 15; })))
        return rows.push({ state:'still', prev:p, cur:m, reason:'The same rule still matches near the original line (line ' + m.line + ').' });
      if ((m = take(function (c) { return c.file !== p.file && c.fp === p.fp && (!inCur || !Object.prototype.hasOwnProperty.call(prev.files, c.file)); })))
        return rows.push({ state:'still', prev:p, cur:m, reason:'The same code moved to ' + m.file + ':' + m.line + '.' });
      if (!inCur) return rows.push({ state:'notrechecked', prev:p, cur:null, reason:p.file + ' is not in the latest scan, so this finding could not be rechecked.' });
      var sim = similarity(prev.files[p.file], cur.files[p.file]);
      if (sim < 0.3) return rows.push({ state:'inconclusive', prev:p, cur:null, reason:'The file changed too much (' + Math.round(sim * 100) + '% of lines unchanged) to compare reliably. Review it again.' });
      if (testResults && testResults[p.id] && testResults[p.id].passed && testResults[p.id].executed)
        return rows.push({ state:'verified', prev:p, cur:null, reason:'Pattern gone and an executed test passed: ' + testResults[p.id].name + '.' });
      rows.push({ state:'gone', prev:p, cur:null, reason:'The pattern no longer matches in this file. That is not proof of a fix; review the change.' });
    });
    curIdx.forEach(function (c) { if (!used[c.i]) rows.push({ state:'new', prev:null, cur:c.f, reason: Object.prototype.hasOwnProperty.call(prev.files, c.f.file) ? 'Not present in the earlier scan of this file.' : 'Found in a file that was not in the earlier scan.' }); });
    var sum = { still:0, gone:0, new:0, notrechecked:0, inconclusive:0, verified:0 };
    rows.forEach(function (r) { sum[r.state]++; });
    return { rows: rows, summary: sum };
  }

  /* ------------------------------------------------------- repair prompts */
  function evidenceText(f) { return f.evidence.map(function (e) { return (e.hit ? '>' : ' ') + String(e.n).padStart(4) + ' | ' + e.text; }).join('\n'); }
  function promptFor(f) {
    return [
      'Fix this potential security issue flagged by SecureFlow (static pattern check, not yet verified by a test).',
      '',
      'Issue: ' + f.title + ' [' + f.severity + ' severity, ' + f.confidence + ' confidence, ' + f.cwe + ']',
      'Location: ' + f.file + ', line ' + f.line + (f.endLine > f.line ? '-' + f.endLine : ''),
      'Evidence (secret values masked):',
      evidenceText(f),
      '',
      'Why it is risky: ' + f.why,
      'Desired secure behaviour: ' + f.fix,
      '',
      'Constraints:',
      '- Change only what is needed for this issue; keep existing behaviour and public APIs.',
      '- Do not introduce new vulnerabilities, disable security checks, or hard-code secrets.',
      '- Avoid new dependencies unless clearly necessary, and say why if you add one.',
      '- Handle edge cases: empty, very long, unicode and malicious input; missing or invalid auth.',
      '',
      'Regression test to add: ' + f.tests,
      '',
      'Finally, show the full updated code and explain exactly what you changed and why.'
    ].join('\n');
  }
  function batchPrompt(fs) {
    var head = [
      'Fix the following ' + fs.length + ' potential security issues flagged by SecureFlow (static pattern checks, not yet verified by tests).',
      'Work through them one at a time, keep existing behaviour, do not introduce new vulnerabilities or hard-coded secrets, and add the listed regression tests.',
      'At the end, list every file you changed and explain each change.', ''
    ];
    var body = fs.map(function (f, i) {
      return ['### ' + (i + 1) + '. ' + f.title + ' [' + f.severity + ', ' + f.confidence + ' confidence, ' + f.cwe + ']',
        'Location: ' + f.file + ':' + f.line, 'Evidence (secrets masked):', evidenceText(f),
        'Why: ' + f.why, 'Fix: ' + f.fix, 'Regression test: ' + f.tests, ''].join('\n');
    });
    return head.concat(body).join('\n');
  }

  /* --------------------------------------------------------------- reports */
  function fence(text) { var m = String(text).match(/`+/g), n = 3; if (m) m.forEach(function (x) { if (x.length >= n) n = x.length + 1; }); return '`'.repeat(n); }
  function mdText(s) { return String(s).replace(/[<>]/g, function (c) { return c === '<' ? '&lt;' : '&gt;'; }).replace(/\r?\n/g, ' '); }
  function reportData(o) {
    return {
      tool: 'SecureFlow', engine: VERSION, generatedAt: o.generatedAt, project: o.project,
      demo: !!o.demo, status: o.scan.status, coverage: o.scan.coverage, importSkipped: o.importSkipped || [],
      score: score(o.findings.filter(function (f) { return !f.dismissed; })), verdict: verdict(o.findings.filter(function (f) { return !f.dismissed; }), o.scan.status), counts: counts(o.findings.filter(function (f) { return !f.dismissed; })),
      readiness: o.readiness || null, patches: o.patches || [], testsRun: [],
      limitations: LIMITATIONS,
      findings: o.findings.map(function (f) { return {
        id: f.id, ruleId: f.ruleId, title: f.title, severity: f.severity, confidence: f.confidence, category: f.category, cwe: f.cwe,
        file: f.file, line: f.line, endLine: f.endLine, evidence: f.evidence, explanation: f.why, remediation: f.fix, regressionTest: f.tests,
        detection: 'static heuristic (not verified by a test)', dismissed: f.dismissed ? { reason: f.dismissed } : undefined,
        column: f.column, impact: metaFor(f).impact, priority: metaFor(f).priority, limits: metaFor(f).limits, references: metaFor(f).refs }; }),
      verification: o.verification ? { summary: o.verification.summary, rows: o.verification.rows.map(function (r) {
        var f = r.cur || r.prev; return { state: r.state, ruleId: f.ruleId, title: f.title, file: f.file, line: f.line, reason: r.reason }; }) } : null
    };
  }
  var STATE_LABEL = { still:'Still detected', gone:'No longer detected', new:'Newly detected', notrechecked:'Not rechecked', inconclusive:'Inconclusive', verified:'Verified by test' };
  function reportMarkdown(d) {
    var L = [];
    L.push('# SecureFlow report: ' + mdText(d.project) + (d.demo ? ' (demo project)' : ''));
    L.push('');
    L.push('Generated ' + d.generatedAt + ' · engine ' + d.engine + ' · status: **' + d.status + '**');
    if (d.analysisSources) { var a=d.analysisSources, g=a.gemini; L.push('','## Analysis sources','- Local deterministic engine: '+mdText(a.local.status)+' ('+mdText(a.local.engine||d.engine)+')','- Gemini: '+mdText(g.status)+(g.model?' · '+mdText(g.model):'')+(g.passes?' · '+g.passes+' successful model call(s)':''),'- Independent reviewer: '+mdText(g.reviewerStatus)+(g.reviewerError?' ('+mdText(g.reviewerError)+')':''),'- Combined report: '+mdText(a.combined.status),''); }
    if (d.coverage) L.push('Coverage: ' + d.coverage.analyzed + ' of ' + d.coverage.imported + ' files analysed, ' + d.coverage.lines + ' lines, ' + d.coverage.rules + ' rules, ' + d.coverage.durationMs + ' ms.');
    var sk = (d.coverage ? d.coverage.skipped : []).concat(d.importSkipped || []);
    if (sk.length) L.push('Excluded: ' + sk.map(function (s) { return mdText(s.path) + ' (' + s.reason + ')'; }).join(', ') + '.');
    L.push('');
    L.push('**' + mdText(d.verdict.title) + '.** ' + mdText(d.verdict.detail));
    L.push('Risk score (secondary indicator, not a probability of compromise): ' + d.score + '/100. Counts: ' + Object.keys(d.counts).map(function (k) { return d.counts[k] + ' ' + k; }).join(', ') + '.');
    L.push('');
    L.push('> ' + d.limitations.join(' '));
    if (d.verification) {
      L.push(''); L.push('## Rescan comparison (ProofLoop)');
      L.push(Object.keys(d.verification.summary).map(function (k) { return STATE_LABEL[k] + ': ' + d.verification.summary[k]; }).join(' · '));
      L.push('');
      d.verification.rows.forEach(function (r) { L.push('- **' + STATE_LABEL[r.state] + '** · ' + mdText(r.title) + ' · `' + mdText(r.file) + ':' + r.line + '` · ' + mdText(r.reason)); });
    }
    L.push(''); L.push('## Findings');
    d.findings.forEach(function (f, i) {
      var code = f.evidence.map(function (e) { return (e.hit ? '>' : ' ') + String(e.n).padStart(4) + ' | ' + e.text; }).join('\n'), fn = fence(code);
      L.push(''); L.push('### ' + (i + 1) + '. ' + mdText(f.title) + (f.dismissed ? ' (marked false positive: ' + mdText(f.dismissed.reason) + ')' : ''));
      L.push('`' + f.id + '` · ' + f.severity + ' severity · ' + f.confidence + ' confidence · ' + f.category + ' · ' + f.cwe + ' · `' + mdText(f.file) + ':' + f.line + '` · ' + f.detection);
      L.push(''); L.push(fn); L.push(code); L.push(fn); L.push('');
      L.push(mdText(f.explanation)); L.push(''); L.push('**Fix:** ' + mdText(f.remediation)); L.push(''); L.push('**Regression test:** ' + mdText(f.regressionTest));
    });
    return L.join('\n') + '\n';
  }
  var LIMITATIONS = [
    'SecureFlow runs line- and statement-level pattern rules locally; it does not execute your code.',
    'It cannot see business-logic flaws, authorisation design, multi-file data flows, runtime configuration or your hosting setup.',
    'A finding is a potential issue; “no longer detected” after a rescan is not proof that a vulnerability is fixed.',
    'Dependency (CVE) checks are not performed.'
  ];

  /* ------------------------------------------------- import validation */
  // cands: [{path, size, read?:fn}] from any source (folder, files, zip)  →  {keep, skipped}
  function validateIncoming(cands, limits) {
    limits = limits || LIMITS;
    var seen = {}, keep = [], skipped = [], total = 0;
    cands.forEach(function (c) {
      var p = safePath(c.path);
      if (!p) return skipped.push({ path: String(c.path).slice(0, 120), reason: 'unsafe-path' });
      if (SKIP_DIR.test(p) || SKIP_FILE.test(p)) return skipped.push({ path: p, reason: 'excluded-folder-or-lockfile' });
      if (!isSupported(p)) return skipped.push({ path: p, reason: 'unsupported-type' });
      if (seen[p]) return skipped.push({ path: p, reason: 'duplicate-path' });
      seen[p] = 1;
      if (c.size > limits.maxFileBytes) return skipped.push({ path: p, reason: 'too-large' });
      if (keep.length >= limits.maxFiles) return skipped.push({ path: p, reason: 'over-file-limit' });
      if (total + c.size > limits.maxTotalBytes) return skipped.push({ path: p, reason: 'over-total-size' });
      total += c.size; keep.push({ path: p, size: c.size, read: c.read });
    });
    return { keep: keep, skipped: skipped, totalBytes: total };
  }
  function conflicts(existing, incoming) { var names = {}; existing.forEach(function (f) { names[f.name] = 1; }); return incoming.filter(function (f) { return names[f.name]; }); }
  function renameFor(name, taken) { var m = name.match(/^(.*?)(\.[^.\/]+)?$/), n = 2, out; do { out = m[1] + ' (' + n + ')' + (m[2] || ''); n++; } while (taken[out]); return out; }
  // mode: 'replace' | 'add';  conflict: 'keep' | 'replace' | 'rename'  (required when there are clashes in add mode)
  function mergeProject(existing, incoming, mode, conflict) {
    var files = mode === 'replace' ? [] : existing.map(function (f) { return { name: f.name, code: f.code }; });
    var idx = {}; files.forEach(function (f, i) { idx[f.name] = i; });
    var sum = { added:0, replaced:0, kept:0, renamed:0 };
    incoming.forEach(function (f) {
      if (!(f.name in idx)) { idx[f.name] = files.length; files.push({ name: f.name, code: f.code }); sum.added++; return; }
      if (conflict === 'replace') { files[idx[f.name]].code = f.code; sum.replaced++; }
      else if (conflict === 'rename') { var nn = renameFor(f.name, idx); idx[nn] = files.length; files.push({ name: nn, code: f.code }); sum.renamed++; }
      else if (conflict === 'keep') sum.kept++;
      else throw new Error('conflict-choice-required');
    });
    files.sort(function (a, b) { return a.name.localeCompare(b.name); });
    return { files: files, summary: sum };
  }

  /* ------------------------------------------------------------ ZIP reader */
  // Minimal, dependency-free reader (stored + deflate) using the platform's DecompressionStream.
  // Rejects traversal paths, encrypted entries, zip64, oversized and over-compressed entries.
  function readZip(buffer, limits) {
    limits = limits || LIMITS;
    var u8 = new Uint8Array(buffer), dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    if (u8.length > limits.maxZipBytes) return Promise.reject(new Error('zip-too-large'));
    if (u8.length < 22) return Promise.reject(new Error('zip-corrupt'));
    var eocd = -1;
    for (var i = u8.length - 22; i >= Math.max(0, u8.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) return Promise.reject(new Error('zip-corrupt'));
    var count = dv.getUint16(eocd + 10, true), cdSize = dv.getUint32(eocd + 12, true), cdOff = dv.getUint32(eocd + 16, true);
    if (count === 0xffff || cdOff === 0xffffffff) return Promise.reject(new Error('zip64-unsupported'));
    if (count > limits.maxZipEntries) return Promise.reject(new Error('zip-too-many-entries'));
    if (cdOff + cdSize > u8.length) return Promise.reject(new Error('zip-corrupt'));
    var dec = new TextDecoder('utf-8'), entries = [], rejected = [], p = cdOff, declaredTotal = 0;
    for (var n = 0; n < count; n++) {
      if (p + 46 > u8.length || dv.getUint32(p, true) !== 0x02014b50) return Promise.reject(new Error('zip-corrupt'));
      var flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true), usize = dv.getUint32(p + 24, true);
      var nlen = dv.getUint16(p + 28, true), elen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true), loff = dv.getUint32(p + 42, true);
      var rawName = dec.decode(u8.subarray(p + 46, p + 46 + nlen));
      p += 46 + nlen + elen + clen;
      if (/\/$/.test(rawName)) continue;                                  // directory
      var safe = safePath(rawName);
      if (!safe) { rejected.push({ path: rawName.slice(0, 120), reason: 'unsafe-path' }); continue; }
      if (flags & 1) { rejected.push({ path: safe, reason: 'encrypted' }); continue; }
      if (method !== 0 && method !== 8) { rejected.push({ path: safe, reason: 'unsupported-compression' }); continue; }
      if (usize > limits.maxFileBytes) { rejected.push({ path: safe, reason: 'too-large' }); continue; }
      if (csize > 0 && usize / csize > limits.maxRatio && usize > 64 * 1024) { rejected.push({ path: safe, reason: 'compression-ratio' }); continue; }
      declaredTotal += usize;
      entries.push(entryReader(u8, dv, safe, method, csize, usize, loff, limits));
    }
    return Promise.resolve({ entries: entries, rejected: rejected, declaredTotal: declaredTotal });
  }
  function entryReader(u8, dv, path, method, csize, usize, loff, limits) {
    return { path: path, size: usize, read: function () {
      if (loff + 30 > u8.length || dv.getUint32(loff, true) !== 0x04034b50) return Promise.reject(new Error('zip-corrupt'));
      var start = loff + 30 + dv.getUint16(loff + 26, true) + dv.getUint16(loff + 28, true);
      if (start + csize > u8.length) return Promise.reject(new Error('zip-corrupt'));
      var data = u8.subarray(start, start + csize), cap = Math.min(limits.maxFileBytes, usize || limits.maxFileBytes);
      if (method === 0) return Promise.resolve(new TextDecoder('utf-8').decode(data.subarray(0, cap)));
      return inflateCapped(data, cap).then(function (bytes) { return new TextDecoder('utf-8').decode(bytes); });
    } };
  }
  // Inflates with a hard byte cap, so an entry that lies about its size cannot exhaust memory.
  function inflateCapped(data, cap) {
    if (typeof DecompressionStream === 'undefined') return Promise.reject(new Error('zip-unsupported-browser'));
    var ds = new DecompressionStream('deflate-raw'), writer = ds.writable.getWriter(), reader = ds.readable.getReader(), chunks = [], got = 0;
    writer.write(data).catch(function () {}); writer.close().catch(function () {});
    function pump() {
      return reader.read().then(function (r) {
        if (r.done) { var out = new Uint8Array(got), o = 0; chunks.forEach(function (c) { out.set(c, o); o += c.length; }); return out; }
        got += r.value.length; if (got > cap) { reader.cancel().catch(function () {}); throw new Error('zip-entry-exceeds-declared-size'); }
        chunks.push(r.value); return pump();
      });
    }
    return pump();
  }

  /* ------------------------------------------------------------ ZIP writer */
  // Minimal standard uncompressed ZIP generator (valid, universally extractable)
  function writeZip(files) {
    var enc = new TextEncoder();
    var entries = [], offset = 0, parts = [];
    var crcTable = new Uint32Array(256);
    for (var i = 0; i < 256; i++) {
      var c = i;
      for (var k = 0; k < 8; k++) c = ((c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1));
      crcTable[i] = c;
    }
    function crc32(bytes) {
      var crc = 0xffffffff;
      for (var j = 0; j < bytes.length; j++) crc = (crc >>> 8) ^ crcTable[(crc ^ bytes[j]) & 0xff];
      return (crc ^ 0xffffffff) >>> 0;
    }
    files.forEach(function (f) {
      var nameBytes = enc.encode(f.name.replace(/\\/g, '/'));
      var dataBytes = enc.encode(f.code || '');
      var crc = crc32(dataBytes), sz = dataBytes.length;
      var lfh = new Uint8Array(30 + nameBytes.length);
      var dv = new DataView(lfh.buffer);
      dv.setUint32(0, 0x04034b50, true);
      dv.setUint16(4, 20, true);
      dv.setUint16(6, 0, true);
      dv.setUint16(8, 0, true);
      dv.setUint16(10, 0, true);
      dv.setUint16(12, 0, true);
      dv.setUint32(14, crc, true);
      dv.setUint32(18, sz, true);
      dv.setUint32(22, sz, true);
      dv.setUint16(26, nameBytes.length, true);
      dv.setUint16(28, 0, true);
      lfh.set(nameBytes, 30);
      parts.push(lfh); parts.push(dataBytes);
      entries.push({ nameBytes: nameBytes, sz: sz, crc: crc, offset: offset });
      offset += lfh.length + dataBytes.length;
    });
    var cdOffset = offset, cdSize = 0;
    entries.forEach(function (e) {
      var cdh = new Uint8Array(46 + e.nameBytes.length);
      var cdv = new DataView(cdh.buffer);
      cdv.setUint32(0, 0x02014b50, true);
      cdv.setUint16(4, 20, true);
      cdv.setUint16(6, 20, true);
      cdv.setUint16(8, 0, true);
      cdv.setUint16(10, 0, true);
      cdv.setUint16(12, 0, true);
      cdv.setUint16(14, 0, true);
      cdv.setUint32(16, e.crc, true);
      cdv.setUint32(20, e.sz, true);
      cdv.setUint32(24, e.sz, true);
      cdv.setUint16(28, e.nameBytes.length, true);
      cdv.setUint16(30, 0, true);
      cdv.setUint16(32, 0, true);
      cdv.setUint16(34, 0, true);
      cdv.setUint16(36, 0, true);
      cdv.setUint32(38, 0, true);
      cdv.setUint32(42, e.offset, true);
      cdh.set(e.nameBytes, 46);
      parts.push(cdh); cdSize += cdh.length;
    });
    var eocd = new Uint8Array(22);
    var edv = new DataView(eocd.buffer);
    edv.setUint32(0, 0x06054b50, true);
    edv.setUint16(4, 0, true);
    edv.setUint16(6, 0, true);
    edv.setUint16(8, entries.length, true);
    edv.setUint16(10, entries.length, true);
    edv.setUint32(12, cdSize, true);
    edv.setUint32(16, cdOffset, true);
    edv.setUint16(20, 0, true);
    parts.push(eocd);
    return new Blob(parts, { type: 'application/zip' });
  }


  /* ================================================================ v0.4 additions */
  var CWE_URL = function (cwe) { var n = String(cwe || '').replace(/\D/g, ''); return n ? 'https://cwe.mitre.org/data/definitions/' + n + '.html' : null; };
  var OWASP = 'https://cheatsheetseries.owasp.org/cheatsheets/';
  // Potential impact (c/i/a), an ILLUSTRATIVE flow, the context that could change the verdict, and detection limits.
  var META = {
    'hardcoded-secret': { cia:['high','medium','low'], flow:['Credential written in source','Shipped in the repo or bundle','Anyone with read access copies it','Potential: your account or paid service used by someone else'], context:'Test keys, revoked keys or values already rotated lower the risk. Whether the file is public (client bundle, public repo) raises it.', limits:'Recognises known key prefixes and values assigned to secret-like names. Keys with unusual names or built at runtime are missed.', refs:['Secrets_Management_Cheat_Sheet.html'] },
    'public-env-secret': { cia:['high','high','medium'], flow:['Secret placed in a public env variable','Build inlines it into browser code','Visitor opens dev tools','Potential: full backend access with that key'], context:'If the variable actually holds an anon/public key despite its name, there is no exposure.', limits:'Matches variable names; it cannot see the value at build time.', refs:['Secrets_Management_Cheat_Sheet.html'] },
    'db-credentials-url': { cia:['high','high','medium'], flow:['Password inside connection string','Committed with the code','Reader connects to the database','Potential: read or change stored data'], context:'If the database is only reachable on a private network the exposure is smaller, but the password still needs rotating.', limits:'Only literal user:password@ URLs are detected.', refs:['Secrets_Management_Cheat_Sheet.html'] },
    'env-file': { cia:['high','medium','low'], flow:['.env file with values in the project','Committed or deployed with the site','Values read by others','Potential: credentials reused against your services'], context:'Placeholder values or a file that is git-ignored and never deployed reduce the risk.', limits:'SecureFlow sees that the file was uploaded, not whether it is committed or deployed.', refs:['Secrets_Management_Cheat_Sheet.html'] },
    'sql-injection': { cia:['high','high','medium'], flow:['Request input','Query string built in code','Database runs the combined query','Potential: other users’ rows read or changed'], context:'If the value is strictly validated (e.g. parsed to an integer) before use, exploitation may not be possible.', limits:'Single statements only; values cleaned in another function or file are not tracked.', refs:['SQL_Injection_Prevention_Cheat_Sheet.html'] },
    'nosql-injection': { cia:['high','high','low'], flow:['JSON body from the request','Used directly as a query filter','Database evaluates operators like $ne','Potential: login or ownership checks bypassed'], context:'Schema validation middleware that rejects objects would prevent this.', limits:'Only direct req.body / req.query use in a call is detected.', refs:['NodeJS_Security_Cheat_Sheet.html'] },
    'command-injection': { cia:['high','high','high'], flow:['Request input','Shell command string built','Server shell runs it','Potential: arbitrary commands on the server'], context:'Strict allowlisting of the value before use would prevent exploitation.', limits:'Indirect flows through helper functions are missed.', refs:['OS_Command_Injection_Defense_Cheat_Sheet.html'] },
    'code-eval': { cia:['high','high','high'], flow:['String from outside the code','Passed to eval / Function','Runtime executes it as code','Potential: attacker-controlled code runs'], context:'If the argument is a constant or fully trusted, the risk is low; eval is still discouraged.', limits:'Does not trace where the evaluated string comes from.', refs:['NodeJS_Security_Cheat_Sheet.html'] },
    'ssrf': { cia:['high','medium','medium'], flow:['URL from the request','Server makes the request','Internal service or metadata endpoint answers','Potential: internal data exposed'], context:'A strict host allowlist or an egress proxy would block this.', limits:'Only URLs taken directly from the request in the same call are detected.', refs:['Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'] },
    'path-traversal': { cia:['high','medium','low'], flow:['File name from the request','Joined into a path','File system reads ../ paths','Potential: files outside the folder read'], context:'path.basename or a resolved-path check elsewhere would prevent this.', limits:'Sanitisation done in another function is not tracked.', refs:['Input_Validation_Cheat_Sheet.html'] },
    'insecure-deserialization': { cia:['high','high','high'], flow:['Serialized data from outside','Deserialised with an unsafe loader','Loader builds objects / runs hooks','Potential: code execution'], context:'If the data only ever comes from a trusted internal source, the risk is lower.', limits:'Detects the unsafe call, not the data source.', refs:['Deserialization_Cheat_Sheet.html'] },
    'reflected-xss': { cia:['medium','medium','low'], flow:['Untrusted input','Inserted into an HTML response','Browser parses it as markup','Potential: script runs in the visitor’s session'], context:'If the value is escaped before this point, or the response type is not HTML, it may be safe.', limits:'Single-statement check; escaping in a helper is not tracked.', refs:['Cross_Site_Scripting_Prevention_Cheat_Sheet.html'] },
    'dom-xss': { cia:['medium','medium','low'], flow:['Untrusted value','Assigned as HTML in the page','Browser parses and runs handlers','Potential: script runs in the visitor’s session'], context:'If the value is a constant or already sanitised (DOMPurify), it is safe.', limits:'Does not trace where the value comes from.', refs:['DOM_based_XSS_Prevention_Cheat_Sheet.html'] },
    'unsafe-template': { cia:['medium','medium','low'], flow:['Stored or request data','Template prints it unescaped','Browser parses it as markup','Potential: stored or reflected XSS'], context:'Values that are always trusted HTML (from your own CMS) are lower risk.', limits:'Recognises common unescaped syntaxes (EJS, Handlebars, Jinja, Django).', refs:['Cross_Site_Scripting_Prevention_Cheat_Sheet.html'] },
    'dynamic-script': { cia:['high','high','low'], flow:['URL influenced by the page address or input','Set as a script source','Browser loads and runs it','Potential: third-party code runs in your page'], context:'If the URL is built only from constants, there is no risk.', limits:'Low confidence: the heuristic looks for variable script URLs.', refs:['Third_Party_Javascript_Management_Cheat_Sheet.html'] },
    'jwt-unverified': { cia:['high','high','low'], flow:['Token from the request','Decoded without checking its signature','App trusts the claims inside','Potential: anyone can act as any user'], context:'If a gateway verifies tokens before this code runs, impact is lower.', limits:'Detects decode/none-algorithm patterns, not every JWT library.', refs:['JSON_Web_Token_for_Java_Cheat_Sheet.html'] },
    'plaintext-password': { cia:['high','medium','low'], flow:['Password submitted','Compared or saved as plain text','Database leak exposes it','Potential: accounts taken over, password reuse elsewhere'], context:'If the field actually holds a hash and the comparison is constant-time, it is fine.', limits:'Matches common variable names only.', refs:['Password_Storage_Cheat_Sheet.html'] },
    'token-localstorage': { cia:['medium','medium','none'], flow:['Session token in localStorage','Any script on the page can read it','An XSS bug sends it away','Potential: session hijacked'], context:'With a strict CSP and no XSS the risk is reduced, not removed.', limits:'Matches key names containing token/jwt/auth/session.', refs:['HTML5_Security_Cheat_Sheet.html'] },
    'cookie-flags': { cia:['medium','medium','none'], flow:['Session cookie without protective flags','Readable by scripts or sent over HTTP','Captured by XSS or network attacker','Potential: session hijacked'], context:'Non-session cookies may not need these flags.', limits:'Detects explicit false values, not missing flags.', refs:['Session_Management_Cheat_Sheet.html'] },
    'missing-auth': { cia:['high','high','medium'], flow:['Request to a sensitive route','No auth middleware in the route definition','Handler runs for anyone','Potential: admin or user actions by strangers'], context:'Auth applied globally or on a parent router makes this a false positive.', limits:'Low confidence: SecureFlow cannot see router-level middleware in other files.', refs:['Authorization_Cheat_Sheet.html'] },
    'open-redirect': { cia:['low','low','none'], flow:['next= parameter from the URL','Used as the redirect target','Visitor lands on another site','Potential: convincing phishing links on your domain'], context:'An allowlist check before the redirect would prevent this.', limits:'Detects direct use of request parameters only.', refs:['Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'] },
    'weak-hash': { cia:['high','low','none'], flow:['Password or secret hashed with MD5/SHA-1','Hashes stored','Leaked hashes cracked offline','Potential: original passwords recovered'], context:'For non-security uses (cache keys) MD5 is acceptable.', limits:'Confidence is high only when password-like names are nearby.', refs:['Password_Storage_Cheat_Sheet.html'] },
    'insecure-random': { cia:['medium','medium','none'], flow:['Token made with Math.random','Values follow a predictable sequence','Attacker predicts a valid token','Potential: password-reset or session tokens guessed'], context:'For non-security values (UI jitter) this is fine.', limits:'Flags randomness near token-like names.', refs:['Cryptographic_Storage_Cheat_Sheet.html'] },
    'tls-disabled': { cia:['high','high','none'], flow:['Certificate checks disabled','Connection accepts any certificate','Network attacker intercepts','Potential: data read or altered in transit'], context:'Local development against a self-signed cert is the usual reason; it must not ship.', limits:'Detects common flags in Node, Python, PHP and Go.', refs:['Transport_Layer_Security_Cheat_Sheet.html'] },
    'cors-wildcard': { cia:['medium','low','none'], flow:['Any website calls your API from a visitor’s browser','API answers with data','Malicious site reads the response','Potential: user data read by other sites'], context:'Public, unauthenticated APIs can safely allow all origins.', limits:'Detects wildcard configs, not reflected-origin logic.', refs:['HTTP_Headers_Cheat_Sheet.html'] },
    'error-leak': { cia:['low','none','none'], flow:['Error thrown','Raw error sent to the client','Attacker reads paths, versions, queries','Potential: easier targeting of other bugs'], context:'If a global error handler sanitises responses before sending, it is fine.', limits:'Direct sends of error objects only.', refs:['Error_Handling_Cheat_Sheet.html'] },
    'debug-mode': { cia:['medium','low','low'], flow:['Debug mode on in deployed config','Errors show stack traces / consoles','Attacker reads internals','Potential: information exposure or code execution (some debuggers)'], context:'Fine for local development if production config overrides it.', limits:'Literal flags only.', refs:['Error_Handling_Cheat_Sheet.html'] },
    'plain-http': { cia:['low','low','none'], flow:['Request over HTTP','Travels unencrypted','Network attacker reads or alters it','Potential: data tampering'], context:'Internal-only traffic on a trusted network lowers the risk.', limits:'Literal http:// URLs only.', refs:['Transport_Layer_Security_Cheat_Sheet.html'] },
    'docker-root': { cia:['medium','medium','medium'], flow:['Container runs as root','App is compromised','Attacker has root in the container','Potential: easier escape or tampering'], context:'Rootless runtimes reduce impact.', limits:'Only explicit USER root lines are detected.', refs:['Docker_Security_Cheat_Sheet.html'] },
    'permissive-rls': { cia:['high','high','low'], flow:['Row-level policy USING (true)','Every user passes the check','Client reads or writes any row','Potential: all users’ data exposed'], context:'Tables that are intentionally public (e.g. product catalogue) are fine.', limits:'Only literal true policies or disabled RLS are detected.', refs:['Authorization_Cheat_Sheet.html'] },
    'cpp-buffer-overflow': { cia:['high','high','high'], flow:['Unbounded input copied to buffer','Stack or heap memory exceeded','Adjacent memory/return address overwritten','Potential: arbitrary code execution or crash'], context:'If input length is strictly checked before the call, overflow is avoided.', limits:'Flags unbounded string functions; size assertions outside the statement are not tracked.', refs:['C-Based_Toolchain_Hardening_Cheat_Sheet.html'] },
    'cpp-format-string': { cia:['high','high','high'], flow:['User input used as format specifier','Format parser reads/writes stack values','Attacker extracts memory or rewrites bytes','Potential: information leak or remote code execution'], context:'If the string contains no % specifiers, it will not corrupt memory.', limits:'Looks for non-literal format strings passed to printf family functions.', refs:['Format_String_Vulnerability.html'] },
    'no-security-headers': { cia:['low','low','none'], flow:['Responses without security headers','Browser applies no extra protections','XSS or clickjacking is easier','Potential: other bugs become more exploitable'], context:'Headers set by your host, CDN or proxy are invisible to SecureFlow.', limits:'Informational: looks for helmet or header names in uploaded code only.', refs:['HTTP_Headers_Cheat_Sheet.html'] },
    'no-rate-limit': { cia:['low','low','medium'], flow:['Login route without throttling','Attacker sends many guesses','Weak passwords guessed','Potential: accounts taken over'], context:'Rate limits at a gateway or host are invisible to SecureFlow.', limits:'Informational: looks for limiter libraries in uploaded code only.', refs:['Authentication_Cheat_Sheet.html'] }
  };
  function metaFor(f) {
    var m = META[f.ruleId] || { cia:['low','low','low'], flow:[], context:'', limits:'', refs:[] };
    var refs = [{ title: f.cwe, url: CWE_URL(f.cwe) }].concat(m.refs.map(function (r) { return { title: 'OWASP ' + r.replace(/_Cheat_Sheet\.html$/, '').replace(/_/g, ' ') + ' cheat sheet', url: OWASP + r }; })).filter(function (r) { return r.url; });
    return { impact: { confidentiality: m.cia[0], integrity: m.cia[1], availability: m.cia[2] }, flow: m.flow, context: m.context, limits: m.limits, refs: refs, priority: priorityOf(f) };
  }
  function priorityOf(f) {
    if (f.severity === 'critical') return f.confidence === 'low' ? 'P2' : 'P1';
    if (f.severity === 'high') return f.confidence === 'low' ? 'P3' : 'P2';
    if (f.severity === 'medium') return 'P3';
    return 'P4';
  }
  var PRIORITY_TEXT = { P1:'Fix before the next deploy', P2:'Fix before launch', P3:'Schedule a fix', P4:'Review when convenient' };

  /* Score v2: severity weight × confidence factor. Deterministic, documented, explainable. */
  var CONF_F = { high:1, medium:.75, low:.5 };
  function weightOf(f) { return SEV_W[f.severity] * (CONF_F[f.confidence] || 1); }
  function score2(fs) { var keep = 1; fs.forEach(function (f) { keep *= (1 - weightOf(f)); }); return Math.round((1 - keep) * 100); }
  function scoreChange(prev, cur, cmp) {
    var before = score2(prev), after = score2(cur), why = [];
    if (cmp) {
      var gone = cmp.rows.filter(function (r) { return r.state === 'gone' || r.state === 'verified'; }), add = cmp.rows.filter(function (r) { return r.state === 'new'; }), nr = cmp.rows.filter(function (r) { return r.state === 'notrechecked' || r.state === 'inconclusive'; });
      if (gone.length) why.push(gone.length + ' finding' + (gone.length > 1 ? 's' : '') + ' no longer detected');
      if (add.length) why.push(add.length + ' newly detected');
      if (nr.length) why.push(nr.length + ' not rechecked or inconclusive (they no longer count toward the score, which can make it look better than it is)');
    }
    return { before: before, after: after, delta: after - before, reasons: why };
  }

  /* ---------- deterministic patch proposals (never applied without the user accepting) ---------- */
  function lineOf(code, n) { return code.split(/\r\n|\r|\n/)[n - 1]; }
  function rep1(line, re, to) { return re.test(line) ? line.replace(re, to) : null; }
  var PATCHERS = {
    'dom-xss': function (L) { var a = rep1(L, /\.(?:innerHTML|outerHTML)\s*=(?!=)/, '.textContent ='); return a && { edits:[{ op:'replace', after:a }], note:'Renders the value as text instead of HTML. If you really need HTML, sanitise it with DOMPurify instead.' }; },
    'hardcoded-secret': function (L, f) {
      var m = L.match(/^(\s*(?:export\s+)?(?:const|let|var)\s+)([A-Za-z_$][\w$]*)(\s*=\s*)["'`][^"'`]*["'`]/);
      if (m) return { edits:[{ op:'replace', after: m[1] + m[2] + m[3] + 'process.env.' + m[2].replace(/[^A-Za-z0-9_]/g, '_').toUpperCase() + L.slice(m[0].length) }], note:'Reads the value from an environment variable instead. Also rotate the exposed key: it is still in your git history.' };
      var p = L.match(/^(\s*)([A-Z_][A-Z0-9_]*)(\s*=\s*)["'][^"']*["']\s*$/);
      if (p && /\.py$/.test(f.file)) return { edits:[{ op:'replace', after: p[1] + p[2] + p[3] + 'os.environ["' + p[2] + '"]' }], note:'Reads from the environment (needs `import os`). Rotate the exposed value.' };
      var o = L.match(/^(\s*)([A-Za-z_$][\w$]*)(\s*:\s*)["'`][^"'`]*["'`]/);
      if (o) return { edits:[{ op:'replace', after: o[1] + o[2] + o[3] + 'process.env.' + o[2].replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase() + L.slice(o[0].length) }], note:'Reads the value from an environment variable instead. Rotate the exposed key.' };
      return null; },
    'jwt-unverified': function (L) { var a = rep1(L, /jwt\.decode\s*\(\s*([^,)]+)\)/, "jwt.verify($1, process.env.JWT_SECRET, { algorithms: ['HS256'] })"); return a && { edits:[{ op:'replace', after:a }], note:'Verifies the signature before trusting the token. Set JWT_SECRET, and wrap the call in try/catch to return 401 on failure.' }; },
    'insecure-random': function (L) { var a = rep1(L, /Math\.random\(\)(?:\.toString\(\s*\d+\s*\))?(?:\.(?:slice|substr|substring)\([^)]*\))?/, 'crypto.randomUUID()'); return a && { edits:[{ op:'replace', after:a }], note:'Uses the cryptographically secure generator (Node: `import crypto from "node:crypto"`; browsers have crypto.randomUUID built in).' }; },
    'token-localstorage': function (L) { var ind = (L.match(/^\s*/) || [''])[0]; return { edits:[{ op:'replace', after: ind + '// SecureFlow: token no longer stored in localStorage. Have the server set an httpOnly, Secure, SameSite cookie.' }], note:'Removes the localStorage write. Your server must now set the session cookie, so check login still works.' }; },
    'cors-wildcard': function (L) { var a = rep1(L, /origin\s*:\s*(["'`])\*\1/, "origin: (process.env.ALLOWED_ORIGINS || '').split(',')"); return a && { edits:[{ op:'replace', after:a }], note:'Allows only the origins listed in ALLOWED_ORIGINS (comma-separated).' }; },
    'cookie-flags': function (L) { var a = L.replace(/httpOnly\s*:\s*false/i, 'httpOnly: true').replace(/\bsecure\s*:\s*false/, 'secure: true'); return a !== L && { edits:[{ op:'replace', after:a }], note:'Turns on httpOnly and Secure. Add sameSite: \'lax\' if it is missing.' }; },
    'plain-http': function (L) { var a = rep1(L, /(["'`])http:\/\//, '$1https://'); return a && { edits:[{ op:'replace', after:a }], note:'Switches to HTTPS. Confirm the host serves HTTPS.' }; },
    'open-redirect': function (L) {
      var m = L.match(/res\.redirect\s*\(\s*(req\.(?:query|body|params)\.[\w$]+)\s*\)/);
      if (m) return { edits:[{ op:'replace', after: L.replace(m[0], "res.redirect(isSafeRedirect(" + m[1] + ") ? " + m[1] + " : '/')") }, { op:'insert', line:1, after:"const isSafeRedirect = (u) => typeof u === 'string' && u.startsWith('/') && !u.startsWith('//');" }], note:'Only relative paths on your own site are allowed; anything else goes to "/".' };
      var l = L.match(/^(\s*)location(?:\.href)?\s*=\s*(.+?);?\s*$/);
      if (l) return { edits:[{ op:'replace', after: l[1] + '{ const next = ' + l[2] + "; location.href = next && next.startsWith('/') && !next.startsWith('//') ? next : '/'; }" }], note:'Only relative paths are followed.' };
      return null; },
    'weak-hash': function (L, f) { if (f.confidence === 'high') return null; var a = rep1(L, /createHash\s*\(\s*(["'])(?:md5|sha1)\1\s*\)/i, "createHash('sha256')"); return a && { edits:[{ op:'replace', after:a }], note:'SHA-256 for integrity checks. For passwords use bcrypt or Argon2 instead (use the repair prompt).' }; },
    'tls-disabled': function (L) { var a = L.replace(/rejectUnauthorized\s*:\s*false/, 'rejectUnauthorized: true').replace(/tlsAllowInvalidCertificates\s*:\s*true/, 'tlsAllowInvalidCertificates: false').replace(/\bverify\s*=\s*False/, 'verify=True'); return a !== L && { edits:[{ op:'replace', after:a }], note:'Turns certificate checks back on. For a private CA, pass its certificate explicitly.' }; },
    'debug-mode': function (L) { var a = L.replace(/\bdebug\s*=\s*True/, 'debug=False').replace(/^(\s*DEBUG\s*=\s*)(?:True|true|1)\b/, '$1False'); return a !== L && { edits:[{ op:'replace', after:a }], note:'Turns debug off. Prefer reading it from an environment variable.' }; },
    'error-leak': function (L) {
      var m = L.match(/res(\.status\(\s*(\d{3})\s*\))?\.(?:send|json)\(\s*(?:err|error|e)(?:\.stack|\.message)?\s*\)/);
      return m && { edits:[{ op:'replace', after: L.replace(m[0], 'res.status(' + (m[2] || '500') + ").json({ error: 'Internal error' })") }], note:'Sends a generic message. Log the real error on the server (console.error or your logger).' }; },
    'insecure-deserialization': function (L) { var a = rep1(L, /yaml\.load\s*\(/, 'yaml.safe_load('); return a && { edits:[{ op:'replace', after:a }], note:'safe_load only builds plain data types.' }; },
    'unsafe-template': function (L) { var a = L.replace(/<%-\s*/, '<%= ').replace(/\{\{\{\s*([\w.]+)\s*\}\}\}/, '{{ $1 }}').replace(/\s*\|\s*safe\b/, ''); return a !== L && { edits:[{ op:'replace', after:a }], note:'Uses the escaped form. Content that must stay HTML needs a sanitiser.' }; },
    'docker-root': function (L) { var a = rep1(L, /^(\s*USER\s+)(?:root|0)\s*$/i, '$1node'); return a && { edits:[{ op:'replace', after:a }], note:'Runs as the unprivileged "node" user. Use a user that exists in your base image.' }; },
    'no-security-headers': function (L) { var ind = (L.match(/^\s*/) || [''])[0]; return { edits:[{ op:'insert', line:'after', after: ind + 'app.use(helmet()); // SecureFlow: security headers (npm install helmet; import helmet from "helmet")' }], note:'Adds helmet after the app is created. Install it and add the import.' }; },
    'sql-injection': function (L) {
      var m = L.match(/([\w$.]+\.(?:query|execute))\(\s*`([^`]*)`\s*\)/); if (!m || !/\$\{/.test(m[2])) return null;
      var params = [], q = m[2].replace(/'?\$\{([^}]+)\}'?/g, function (_, e) { params.push(e.trim()); return '$' + params.length; });
      return { edits:[{ op:'replace', after: L.replace(m[0], m[1] + "('" + q.replace(/'/g, "\\'") + "', [" + params.join(', ') + '])') }], note:'Passes values as bound parameters ($1, $2…, PostgreSQL style). For MySQL use ? placeholders.' }; },
    'db-credentials-url': function (L) {
      var m = L.match(/(["'`])\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql):\/\/[^\s:'"`\/@$]+:[^\s@'"`${}]{3,}@[^"'`]*\1/);
      if (m) return { edits:[{ op:'replace', after: L.replace(m[0], 'process.env.DATABASE_URL') }], note:'Loads the database connection string from the DATABASE_URL environment variable.' };
      return null;
    },
    'cpp-buffer-overflow': function (L) {
      var m1 = L.match(/\bgets\s*\(\s*([^)]+)\s*\)/);
      if (m1) return { edits:[{ op:'replace', after: L.replace(m1[0], 'fgets(' + m1[1] + ', sizeof(' + m1[1] + '), stdin)') }], note:'Replaced unsafe gets() with bounded fgets().' };
      var m2 = L.match(/\bstrcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/);
      if (m2) return { edits:[{ op:'replace', after: L.replace(m2[0], 'strncpy(' + m2[1] + ', ' + m2[2] + ', sizeof(' + m2[1] + ') - 1); ' + m2[1].trim() + '[sizeof(' + m2[1] + ') - 1] = 0') }], note:'Replaced unsafe strcpy() with bounded strncpy() and null-termination.' };
      var m3 = L.match(/\bsprintf\s*\(\s*([^,]+)\s*,\s*(.+)\)/);
      if (m3) return { edits:[{ op:'replace', after: L.replace(m3[0], 'snprintf(' + m3[1] + ', sizeof(' + m3[1] + '), ' + m3[2] + ')') }], note:'Replaced sprintf() with bounded snprintf().' };
      return null;
    },
    'cpp-format-string': function (L) {
      var m = L.match(/\bprintf\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/);
      if (m) return { edits:[{ op:'replace', after: L.replace(m[0], 'printf("%s", ' + m[1] + ')') }], note:'Supplied constant format string "%s" to prevent format string exploits.' };
      return null;
    }
  };
  // Returns a proposal for review. Nothing changes until applyPatch() is called with the user's accepted proposal.
  function proposePatch(f, files) {
    var file = files.find(function (x) { return x.name === f.file; });
    if (!file) return { available:false, reason:'The file is no longer in the project.' };
    var L = lineOf(file.code, f.line);
    if (L === undefined) return { available:false, reason:'The line no longer exists. Rescan first.' };
    var fn = PATCHERS[f.ruleId], r = fn ? fn(L, f) : null;
    if (!r) return { available:false, reason: fn ? 'This occurrence does not match the safe automatic pattern. Use the repair prompt.' : 'No safe automatic patch for this rule. Use the repair prompt.' };
    var edits = r.edits.map(function (e) {
      if (e.op === 'replace') return { op:'replace', line:f.line, before:L, after:e.after };
      var at = e.line === 'after' ? f.line + 1 : e.line; return { op:'insert', line:at, before:null, after:e.after };
    });
    return { available:true, file:f.file, findingId:f.id, ruleId:f.ruleId, kind:'deterministic', edits:edits, note:r.note,
      disclaimer:'Generated by a fixed rewrite rule, not by AI. It has not been compiled or tested; review it before applying, then rescan.' };
  }
  // Validates every edit against the CURRENT file content, then returns a new files array (input untouched).
  function applyPatch(files, patch) {
    var idx = files.findIndex(function (x) { return x.name === patch.file; });
    if (idx < 0) return { ok:false, error:'Target file not found.' };
    if (!safePath(patch.file)) return { ok:false, error:'Unsafe target path.' };
    var eol = /\r\n/.test(files[idx].code) ? '\r\n' : '\n', lines = files[idx].code.split(/\r\n|\r|\n/);
    var sorted = patch.edits.slice().sort(function (a, b) { return b.line - a.line || (a.op === 'insert' ? 1 : -1); });
    for (var i = 0; i < sorted.length; i++) {
      var e = sorted[i];
      if (typeof e.after !== 'string' || /[\u0000]/.test(e.after)) return { ok:false, error:'Invalid replacement text.' };
      if (e.op === 'replace' && lines[e.line - 1] !== e.before) return { ok:false, error:'Line ' + e.line + ' changed since the proposal was made. Rescan and try again.' };
      if (e.op === 'insert' && (e.line < 1 || e.line > lines.length + 1)) return { ok:false, error:'Insert position out of range.' };
    }
    var before = files[idx].code;
    sorted.forEach(function (e) { var add = e.after.split(/\r\n|\r|\n/); if (e.op === 'replace') lines.splice.apply(lines, [e.line - 1, 1].concat(add)); else lines.splice.apply(lines, [e.line - 1, 0].concat(add)); });
    var out = files.map(function (f) { return { name:f.name, code:f.code }; });
    out[idx].code = lines.join(eol);
    return { ok:true, files:out, undo:{ file:patch.file, code:before } };
  }
  // Line diff (LCS on the changed middle; prefix/suffix trimmed). Returns rows {t:' '|'-'|'+', a, b, text}.
  function diffLines(aText, bText, ctx) {
    ctx = ctx == null ? 2 : ctx;
    var A = aText.split(/\r\n|\r|\n/), B = bText.split(/\r\n|\r|\n/), p = 0, s = 0;
    while (p < A.length && p < B.length && A[p] === B[p]) p++;
    while (s < A.length - p && s < B.length - p && A[A.length - 1 - s] === B[B.length - 1 - s]) s++;
    var a = A.slice(p, A.length - s), b = B.slice(p, B.length - s), mid = [];
    if (a.length * b.length > 250000) { a.forEach(function (t) { mid.push(['-', t]); }); b.forEach(function (t) { mid.push(['+', t]); }); }
    else {
      var n = a.length, m = b.length, dp = []; for (var i = 0; i <= n; i++) { dp.push(new Int32Array(m + 1)); }
      for (i = n - 1; i >= 0; i--) for (var j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
      i = 0; j = 0; while (i < n && j < m) { if (a[i] === b[j]) { mid.push([' ', a[i]]); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) { mid.push(['-', a[i++]]); } else { mid.push(['+', b[j++]]); } }
      while (i < n) mid.push(['-', a[i++]]); while (j < m) mid.push(['+', b[j++]]);
    }
    var rows = [], ai = p, bi = p;
    for (var k = Math.max(0, p - ctx); k < p; k++) rows.push({ t:' ', a:k + 1, b:k + 1, text:A[k] });
    mid.forEach(function (x) { if (x[0] === ' ') rows.push({ t:' ', a:++ai, b:++bi, text:x[1] }); else if (x[0] === '-') rows.push({ t:'-', a:++ai, b:null, text:x[1] }); else rows.push({ t:'+', a:null, b:++bi, text:x[1] }); });
    for (k = 0; k < Math.min(ctx, s); k++) rows.push({ t:' ', a:ai + k + 1, b:bi + k + 1, text:A[A.length - s + k] });
    return rows.map(function (r) { r.text = mask(r.text); return r; });
  }

  /* ---------- file relationships (only real import/require edges) ---------- */
  function layerOf(path, code) {
    var p = path.toLowerCase(), lang = language(path);
    if (lang === 'sql' || /(?:^|\/)(?:db|database|models?|prisma|migrations?|schema|supabase)(?:\/|\.)/.test(p) || /\b(?:MongoClient|mongoose\.|prisma\.|createPool|knex\(|sequelize)/.test(code)) return 'data';
    if (/(?:^|\/)(?:api|functions|backend)\//.test(p) || /(?:^|\/)(?:server|routes?|controllers?|middleware)(?:\/|\.)/.test(p) || /\b(?:express\(\)|app\.(?:get|post|put|delete)\(|req,\s*res|@app\.route|FastAPI\()/.test(code)) return 'server';
    if (lang === 'html' || lang === 'tpl' || /(?:^|\/)(?:public|client|frontend|components|pages|views|ui)(?:\/|\.)/.test(p) || /\b(?:document\.|window\.|localStorage|useState\()/.test(code)) return 'client';
    if (lang === 'env' || lang === 'config' || lang === 'docker') return 'config';
    return 'other';
  }
  function dependencyGraph(files) {
    var names = {}; files.forEach(function (f) { names[f.name] = 1; });
    var edges = [], seen = {};
    function resolve(from, spec) {
      var dir = from.split('/').slice(0, -1), parts = dir.concat(spec.split('/')), out = [];
      for (var i = 0; i < parts.length; i++) { if (parts[i] === '.' || parts[i] === '') continue; if (parts[i] === '..') { if (!out.length) return null; out.pop(); } else out.push(parts[i]); }
      var base = out.join('/'), tries = ['', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '/index.js', '/index.ts', '/index.jsx', '/index.tsx'];
      for (var t = 0; t < tries.length; t++) if (names[base + tries[t]]) return base + tries[t];
      return null;
    }
    files.forEach(function (f) {
      if (language(f.name) !== 'js' && language(f.name) !== 'html') return;
      var re = /(?:import\s+(?:[\w*{}\s,$]+\s+from\s+)?|import\s*\(\s*|require\s*\(\s*|export\s+[\w*{}\s,$]+\s+from\s+)["'](\.{1,2}\/[^"']+)["']/g, m;
      while ((m = re.exec(f.code))) { var to = resolve(f.name, m[1]); if (to && to !== f.name && !seen[f.name + '>' + to]) { seen[f.name + '>' + to] = 1; edges.push({ from:f.name, to:to }); } }
    });
    return { nodes: files.map(function (f) { return { file:f.name, layer:layerOf(f.name, f.code) }; }), edges: edges };
  }

  /* ---------- production readiness (scoped to what the browser can actually see) ---------- */
  function readiness(scan, files, open) {
    var fs = open || scan.findings, c = counts(fs), cov = scan.coverage || { imported:0, analyzed:0, skipped:[], failed:[] };
    var all = files.map(function (f) { return f.code; }).join('\n'), checks = [];
    function add(id, name, status, ran, evidence, impact, action) { checks.push({ id:id, name:name, status:status, ran:ran, evidence:evidence, impact:impact, action:action }); }
    var by = function (ids) { return fs.filter(function (f) { return ids.indexOf(f.ruleId) >= 0; }); };
    add('findings', 'Security findings', c.critical || c.high ? 'fail' : (c.medium || c.low ? 'warn' : 'pass'), true,
      fs.length ? c.critical + ' critical, ' + c.high + ' high, ' + c.medium + ' medium, ' + c.low + ' low, ' + c.info + ' info (open findings)' : 'No open findings from the enabled rules',
      'Critical and high findings are likely to be exploitable if the evidence holds.', c.critical || c.high ? 'Fix critical and high findings, then rescan.' : 'Review remaining items.');
    var excl = cov.skipped.length;
    add('coverage', 'Scan coverage', scan.status === 'complete' ? 'pass' : (scan.status === 'failed' ? 'fail' : 'incomplete'), true,
      cov.analyzed + ' of ' + cov.imported + ' files analysed' + (excl ? ', ' + excl + ' excluded' : '') + (cov.failed.length ? ', ' + cov.failed.length + ' failed' : ''),
      'Anything not analysed was not checked at all.', excl ? 'Review the excluded files manually or upload them in a supported format.' : 'None.');
    var sec = by(['hardcoded-secret','public-env-secret','db-credentials-url','env-file']);
    add('secrets', 'Secrets in code and config', sec.length ? 'fail' : 'pass', true, sec.length ? sec.length + ' secret-related finding' + (sec.length > 1 ? 's' : '') : 'No hardcoded secrets matched',
      'Exposed keys can be used by anyone who reads them.', sec.length ? 'Move secrets to server-side environment variables and rotate every exposed key.' : 'Keep secrets in environment variables.');
    var au = by(['missing-auth','jwt-unverified','plaintext-password','cookie-flags','token-localstorage','permissive-rls']);
    add('auth', 'Authentication and access indicators', au.length ? 'warn' : 'pass', true, au.length ? au.length + ' indicator' + (au.length > 1 ? 's' : '') + ' (' + au.map(function (f) { return f.ruleId; }).filter(function (v, i, a) { return a.indexOf(v) === i; }).join(', ') + ')' : 'No auth-related patterns matched',
      'Broken access control lets users act as others. Pattern checks cannot prove your authorisation logic is correct.', 'Test each protected route as a logged-out user and as a different user.');
    var hasExpress = /\bexpress\s*\(\s*\)/.test(all);
    add('headers', 'Security headers', !hasExpress ? 'notchecked' : (/\bhelmet\b|Content-Security-Policy/i.test(all) ? 'pass' : 'warn'), hasExpress,
      !hasExpress ? 'No Express server code found; headers set by your host are invisible here.' : (/\bhelmet\b|Content-Security-Policy/i.test(all) ? 'helmet or CSP found in code' : 'No helmet or CSP header found in uploaded code'),
      'Headers add browser-side protection against XSS and clickjacking.', 'Check response headers on the deployed site (e.g. securityheaders.com).');
    var er = by(['error-leak','debug-mode']);
    add('errors', 'Error handling and debug settings', er.length ? 'warn' : 'pass', true, er.length ? er.length + ' finding' + (er.length > 1 ? 's' : '') : 'No raw error responses or debug flags matched', 'Leaked errors help attackers map your system.', er.length ? 'Return generic errors; log details server-side.' : 'None.');
    var testFiles = files.filter(function (f) { return /(?:^|\/)(?:tests?|__tests__|spec)\/|\.(?:test|spec)\.[jt]sx?$|(?:^|\/)test_[\w-]+\.py$/.test(f.name); });
    add('tests', 'Automated tests present', testFiles.length ? 'warn' : 'warn', true, testFiles.length ? testFiles.length + ' test file' + (testFiles.length > 1 ? 's' : '') + ' found (not executed by SecureFlow)' : 'No test files found in the upload',
      'Without tests, a fix can silently break something else.', 'Run your test suite yourself and add the regression tests suggested for each finding.');
    add('build', 'Build succeeds', 'notchecked', false, 'SecureFlow never builds or runs your code.', 'A broken build blocks deployment.', 'Run your production build locally or in CI.');
    var hasPkg = files.some(function (f) { return /(?:^|\/)package\.json$|requirements\.txt$|pyproject\.toml$|composer\.json$/.test(f.name); });
    add('deps', 'Dependency vulnerabilities', 'notchecked', false, hasPkg ? 'Dependency manifest found, but SecureFlow has no vulnerability database.' : 'No dependency manifest uploaded.', 'Known-vulnerable packages are a common entry point.', 'Run npm audit / pip-audit, or enable Dependabot.');
    var pay = /\b(?:razorpay|stripe|paypal|cashfree|paytm|phonepe)\b/i.test(all);
    var verify = /validatePaymentVerification|createHmac\(\s*['"]sha256['"]|webhooks\.constructEvent|verifyWebhookSignature|payment_signature|razorpay_signature/i.test(all);
    add('payments', 'Payment verification', !pay ? 'notchecked' : (verify ? 'warn' : 'fail'), pay,
      !pay ? 'No payment provider code found.' : (verify ? 'Signature verification code found; its correctness was not tested.' : 'Payment code found but no server-side signature verification in the uploaded files.'),
      'Trusting the browser’s "payment succeeded" lets anyone unlock paid features.', pay ? 'Verify payment and webhook signatures on the server and make fulfilment idempotent.' : 'Not applicable.');
    add('deploy', 'Hosting configuration', 'notchecked', false, 'Your host, CDN, TLS and firewall settings are not visible to a browser-based scan.', 'Misconfigured hosting can expose otherwise safe code.', 'Review your host’s security settings.');
    var overall = scan.status === 'failed' ? 'Failed Check' : (c.critical || c.high ? 'Fix Before Deployment' : (scan.status !== 'complete' ? 'Assessment Incomplete' : 'Ready for Review'));
    return { overall: overall, checks: checks, scope:'Based only on the uploaded files and the enabled pattern rules. It is not a certification that the application is secure or production ready.' };
  }

  /* ---------- business-logic test specifications (manual; never auto-run) ---------- */
  var SPEC_LIB = [
    { id:'pay-replay', hint:/razorpay|stripe|paypal|checkout|payment/i, title:'Repeated payment callbacks', steps:['Complete a test payment.', 'Replay the same success callback / webhook twice.'], expected:'The order is fulfilled exactly once; the second call is ignored and logged.' },
    { id:'pay-client-price', hint:/razorpay|stripe|checkout|amount|price/i, title:'Client-supplied price', steps:['Intercept the order-creation request.', 'Change the amount to 1.'], expected:'The server ignores client prices and charges the configured amount.' },
    { id:'order-idor', hint:/order|invoice|userId|user_id|ownerId|req\.user/i, title:'Unauthorised order access', steps:['Log in as user A and note an order id.', 'Log in as user B and request user A’s order.'], expected:'403 or 404; no data from user A is returned.' },
    { id:'coupon-expired', hint:/coupon|promo|discount|voucher/i, title:'Expired or reused coupon', steps:['Apply a coupon after its expiry date.', 'Apply a single-use coupon twice.'], expected:'Both are rejected by the server.' },
    { id:'qty-negative', hint:/quantity|qty|cart|items/i, title:'Negative or huge quantity', steps:['Add an item with quantity -1, 0 and 1000000.'], expected:'Rejected with a validation error; totals never go negative.' },
    { id:'double-submit', hint:/submit|post\(|create|insert/i, title:'Repeated submissions', steps:['Click submit twice quickly, or resend the same request.'], expected:'One record is created (idempotency key or unique constraint).' },
    { id:'ownership', hint:/update|delete|patch|put\(/i, title:'Ownership checks on update and delete', steps:['As user B, send an update/delete for user A’s resource id.'], expected:'403 or 404, and the resource is unchanged.' },
    { id:'auth-bruteforce', hint:/login|signin|password/i, title:'Login brute force', steps:['Send 20 wrong passwords for one account within a minute.'], expected:'Requests are throttled (429) or the account is temporarily locked.' }
  ];
  function testSpecs(files) {
    var all = files.map(function (f) { return f.code; }).join('\n');
    return SPEC_LIB.map(function (s) { var m = all.match(s.hint); return { id:s.id, title:s.title, steps:s.steps, expected:s.expected, relevant:!!m, reason: m ? 'Your code mentions “' + m[0] + '”.' : 'General check; no matching code was found.' }; })
      .sort(function (a, b) { return (b.relevant ? 1 : 0) - (a.relevant ? 1 : 0); });
  }

  /* ---------- founder-friendly HTML report (every value escaped) ---------- */
  function h(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]; }); }
  function reportHTML(d) {
    var css = 'body{font:15px/1.55 system-ui,sans-serif;color:#1d1b18;background:#faf8f4;margin:0;padding:32px;max-width:900px;margin:auto}h1{font-size:28px;margin:0 0 6px}h2{font-size:19px;margin:28px 0 10px;border-bottom:1px solid #ddd6c8;padding-bottom:6px}h3{font-size:16px;margin:18px 0 6px}.meta{color:#6b655a;font-size:13px}.box{background:#fff;border:1px solid #e4ddcf;border-radius:10px;padding:14px 16px;margin:10px 0}.sev{display:inline-block;font:600 11px/1 ui-monospace,monospace;text-transform:uppercase;padding:4px 7px;border-radius:5px;background:#eee}.critical{background:#fbe1dc;color:#9b2c1d}.high{background:#fbe9d6;color:#8a4b12}.medium{background:#f4ecd9;color:#6e5520}.low,.info{background:#ecebe7;color:#555}pre{background:#1d1b18;color:#ede6d9;padding:10px;border-radius:8px;overflow:auto;font-size:12.5px}table{border-collapse:collapse;width:100%;font-size:13.5px}td,th{border-bottom:1px solid #e4ddcf;padding:6px 8px;text-align:left;vertical-align:top}';
    var o = [];
    o.push('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>SecureFlow report: ' + h(d.project) + '</title><style>' + css + '</style></head><body>');
    o.push('<h1>Security review: ' + h(d.project) + (d.demo ? ' (demo project)' : '') + '</h1><p class="meta">Generated ' + h(d.generatedAt) + ' by SecureFlow engine ' + h(d.engine) + ' · scan status: ' + h(d.status) + '</p>');
    o.push('<h2>Executive summary</h2><div class="box"><p><b>' + h(d.verdict.title) + '.</b> ' + h(d.verdict.detail) + '</p><p>Open findings: ' + Object.keys(d.counts).map(function (k) { return d.counts[k] + ' ' + k; }).join(', ') + '. Risk score ' + d.score + '/100 (a summary of these findings, not a probability of being hacked).</p>' + (d.readiness ? '<p>Readiness: <b>' + h(d.readiness.overall) + '</b>. ' + h(d.readiness.scope) + '</p>' : '') + '</div>');
    if (d.analysisSources) { var a=d.analysisSources,g=a.gemini; o.push('<h2>Analysis sources</h2><div class="box"><p>Local deterministic engine: '+h(a.local.status)+' ('+h(a.local.engine||d.engine)+')</p><p>Gemini: '+h(g.status)+(g.model?' · '+h(g.model):'')+(g.passes?' · '+g.passes+' successful model call(s)':'')+'</p><p>Independent reviewer: '+h(g.reviewerStatus)+(g.reviewerError?' ('+h(g.reviewerError)+')':'')+'</p><p>Combined report: '+h(a.combined.status)+'</p></div>'); }
    o.push('<h2>Scope</h2><div class="box"><p>' + (d.coverage ? d.coverage.analyzed + ' of ' + d.coverage.imported + ' files analysed, ' + d.coverage.lines + ' lines, ' + d.coverage.rules + ' pattern rules.' : '') + '</p><p>' + d.limitations.map(h).join(' ') + '</p><p>Tests executed by SecureFlow: none. SecureFlow does not run your code.</p></div>');
    if (d.readiness) { o.push('<h2>Production readiness checks</h2><table><tr><th>Check</th><th>Status</th><th>Ran</th><th>Evidence</th><th>Action</th></tr>'); d.readiness.checks.forEach(function (c) { o.push('<tr><td>' + h(c.name) + '</td><td>' + h(c.status) + '</td><td>' + (c.ran ? 'yes' : 'no') + '</td><td>' + h(c.evidence) + '</td><td>' + h(c.action) + '</td></tr>'); }); o.push('</table>'); }
    if (d.verification) { o.push('<h2>ProofLoop: rescan comparison</h2><p>' + Object.keys(d.verification.summary).map(function (k) { return h(STATE_LABEL[k]) + ': ' + d.verification.summary[k]; }).join(' · ') + '</p><table><tr><th>Status</th><th>Finding</th><th>Location</th><th>Why</th></tr>'); d.verification.rows.forEach(function (r) { o.push('<tr><td>' + h(STATE_LABEL[r.state]) + '</td><td>' + h(r.title) + '</td><td>' + h(r.file) + ':' + r.line + '</td><td>' + h(r.reason) + '</td></tr>'); }); o.push('</table>'); }
    if (d.patches && d.patches.length) { o.push('<h2>Patches applied in this session</h2><ul>' + d.patches.map(function (p) { return '<li>' + h(p.title) + ' in ' + h(p.file) + ' (' + h(p.kind) + (p.undone ? ', undone' : '') + ')</li>'; }).join('') + '</ul>'); }
    o.push('<h2>Findings</h2>');
    d.findings.forEach(function (f, i) {
      var code = f.evidence.map(function (e) { return (e.hit ? '>' : ' ') + String(e.n).padStart(4) + ' | ' + e.text; }).join('\n');
      o.push('<div class="box"><h3>' + (i + 1) + '. ' + h(f.title) + (f.dismissed ? ' (marked false positive)' : '') + '</h3><p><span class="sev ' + h(f.severity) + '">' + h(f.severity) + '</span> ' + h(f.confidence) + ' confidence · ' + h(f.category) + ' · ' + h(f.cwe) + ' · ' + h(f.priority || '') + ' · <code>' + h(f.file) + ':' + f.line + '</code></p><pre>' + h(code) + '</pre><p>' + h(f.explanation) + '</p>' +
        (f.impact ? '<p><b>Potential impact if exploitable</b> (not observed damage): confidentiality ' + h(f.impact.confidentiality) + ', integrity ' + h(f.impact.integrity) + ', availability ' + h(f.impact.availability) + '.</p>' : '') +
        '<p><b>Fix:</b> ' + h(f.remediation) + '</p><p><b>Regression test:</b> ' + h(f.regressionTest) + '</p>' + (f.limits ? '<p class="meta">Detection limits: ' + h(f.limits) + '</p>' : '') + '</div>');
    });
    o.push('<p class="meta">Secret values are masked. This report was generated locally in the browser.</p></body></html>');
    return o.join('\n');
  }

  return {
    VERSION: VERSION, LIMITS: LIMITS, RULES: RULES.map(ruleInfo), PROJECT_RULES: PROJECT_RULES.map(ruleInfo), RULE_COUNT: ALL_RULES.length, LIMITATIONS: LIMITATIONS, STATE_LABEL: STATE_LABEL,
    language: language, isSupported: isSupported, safePath: safePath, isBinary: isBinary, mask: mask, lex: lex,
    scanFile: scanFile, scanProject: scanProject, counts: counts, score: score, verdict: verdict,
    similarity: similarity, compareScans: compareScans, promptFor: promptFor, batchPrompt: batchPrompt,
    reportData: reportData, reportMarkdown: reportMarkdown, validateIncoming: validateIncoming, conflicts: conflicts, mergeProject: mergeProject,
    readZip: readZip, writeZip: writeZip, SEV_ORDER: SEV_ORDER,
    metaFor: metaFor, PRIORITY_TEXT: PRIORITY_TEXT, weightOf: weightOf, scoreChange: scoreChange, proposePatch: proposePatch, applyPatch: applyPatch, diffLines: diffLines,
    dependencyGraph: dependencyGraph, layerOf: layerOf, readiness: readiness, testSpecs: testSpecs, reportHTML: reportHTML, PATCHABLE: Object.keys(PATCHERS)
  };
}

root.SecureFlowEngine = SecureFlowEngine;
root.SFEngine = SecureFlowEngine();
if (typeof module !== 'undefined' && module.exports) module.exports = SecureFlowEngine;
})(typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : globalThis));
