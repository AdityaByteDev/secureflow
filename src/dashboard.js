// SecureFlow Platform Dashboard: 3-Step Flow (1. Login -> 2. Plan & Pay with Cashfree -> 3. Connect GitHub)
// Automated scanning, Findings Explorer, Fix Studio with honest validations & safe push,
// ProofLoop verification matrix, Cashfree Pro Pass billing, and Resend alerts.
(function() {
  'use strict';

  // State
  const state = {
    cfg: null,
    user: null,
    plan: null,
    token: null,
    refreshToken: localStorage.getItem('sf_rt') || null,
    tokenExpiresAt: 0,
    repos: [],
    scans: [],
    findings: [],
    activeScanId: null,
    activePatch: null,
    selectedFinding: null,
    cashfreeInstance: null
  };

  // DOM Elements
  const el = id => document.getElementById(id);
  const qsa = sel => Array.from(document.querySelectorAll(sel));

  // Initialize
  window.addEventListener('DOMContentLoaded', init);

  async function init() {
    setupTabNavigation();
    setupAuthListeners();
    setupFeatureListeners();

    try {
      const cfgRes = await fetch('/api/public-config');
      state.cfg = await cfgRes.json();
    } catch (e) {
      console.warn('Failed to fetch public config', e);
    }

    // Check existing session
    if (state.refreshToken) {
      const ok = await refreshToken();
      if (ok) {
        await loadUserData();
      } else {
        showAuthScreen();
      }
    } else {
      showAuthScreen();
    }

    // Check URL hashes & queries (e.g. #github=connected, #order_id=...)
    handleUrlHash();
  }

  /* ---------------------- Tab Navigation ---------------------- */
  function setupTabNavigation() {
    qsa('.views-nav .vn').forEach(btn => {
      btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        switchTab(view);
      });
    });
  }

  function switchTab(viewName) {
    qsa('.views-nav .vn').forEach(b => {
      const on = b.dataset.view === viewName;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    qsa('.views .view').forEach(v => {
      const on = v.id === `dview-${viewName}`;
      v.classList.toggle('on', on);
      v.hidden = !on;
      v.style.display = on ? 'block' : 'none';
    });
    window.location.hash = viewName;

    // Refresh view specific data
    if (viewName === 'billing') updateBillingView();
    if (viewName === 'codebases') loadCodebasesAndRepairs();
    if (viewName === 'repos') loadRepos();
    if (viewName === 'scans') loadScans();
    if (viewName === 'findings') loadFindingsForActiveScan();
    if (viewName === 'proof') populateProofLoopSelectors();
  }

  /* ---------------------- Firebase Auth (STEP 1) ---------------------- */
  function showAuthScreen() {
    el('auth-screen').style.display = 'block';
    el('dash-workspace').style.display = 'none';
    el('nav-user-area').innerHTML = '';
  }

  function showWorkspace() {
    el('auth-screen').style.display = 'none';
    el('dash-workspace').style.display = 'block';
    renderNavUser();
  }

  function setupAuthListeners() {
    let mode = 'login';
    let otpSent = false;
    let otpEmail = '';

    el('tab-login').addEventListener('click', () => {
      mode = 'login';
      el('tab-login').classList.add('active');
      el('tab-signup').classList.remove('active');
      if (el('tab-otp')) el('tab-otp').classList.remove('active');
      el('auth-form').style.display = 'block';
      if (el('dash-otp-sec')) el('dash-otp-sec').style.display = 'none';
      el('field-name').style.display = 'none';
      el('auth-submit-btn').textContent = 'Sign In';
      el('auth-err').textContent = '';
      el('auth-msg').textContent = '';
    });
    el('tab-signup').addEventListener('click', () => {
      mode = 'signup';
      el('tab-signup').classList.add('active');
      el('tab-login').classList.remove('active');
      if (el('tab-otp')) el('tab-otp').classList.remove('active');
      el('auth-form').style.display = 'block';
      if (el('dash-otp-sec')) el('dash-otp-sec').style.display = 'none';
      el('field-name').style.display = 'block';
      el('auth-submit-btn').textContent = 'Create Account';
      el('auth-err').textContent = '';
      el('auth-msg').textContent = '';
    });
    if (el('tab-otp')) {
      el('tab-otp').addEventListener('click', () => {
        mode = 'otp';
        el('tab-otp').classList.add('active');
        el('tab-login').classList.remove('active');
        el('tab-signup').classList.remove('active');
        el('auth-form').style.display = 'none';
        if (el('dash-otp-sec')) el('dash-otp-sec').style.display = 'block';
        el('auth-err').textContent = '';
        el('auth-msg').textContent = '';
        if (el('dash-otp-email') && el('auth-input-email')) {
          el('dash-otp-email').value = el('auth-input-email').value;
        }
      });
    }

    if (el('dash-otp-action-btn')) {
      el('dash-otp-action-btn').addEventListener('click', async () => {
        el('auth-err').textContent = '';
        el('auth-msg').textContent = '';
        const email = (el('dash-otp-email')?.value || '').trim();
        const btn = el('dash-otp-action-btn');

        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          el('auth-err').textContent = 'Please enter a valid email address.';
          return;
        }

        if (!otpSent) {
          btn.disabled = true;
          btn.textContent = 'Sending code…';
          try {
            const res = await fetch('/api/auth/send-otp', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ email })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.message || data.error || 'Failed to send verification code');
            otpSent = true;
            otpEmail = email;
            if (el('dash-otp-code-box')) el('dash-otp-code-box').style.display = 'block';
            btn.disabled = false;
            btn.textContent = 'Verify Code & Continue →';
            el('auth-msg').textContent = data.message || 'Verification code sent to your email. It expires in 5 minutes.';
            if (data.devOtp && el('dash-otp-dev-hint')) {
              el('dash-otp-dev-hint').style.display = 'block';
              el('dash-otp-dev-hint').textContent = `Test Code: ${data.devOtp}`;
            }
            if (el('dash-otp-code')) {
              if (data.devOtp) el('dash-otp-code').value = data.devOtp;
              el('dash-otp-code').focus();
            }
          } catch (err) {
            btn.disabled = false;
            btn.textContent = 'Send Verification Code →';
            el('auth-err').textContent = err.message;
          }
        } else {
          const otp = (el('dash-otp-code')?.value || '').trim();
          if (!otp || otp.length < 4) {
            el('auth-err').textContent = 'Please enter the verification code.';
            return;
          }
          btn.disabled = true;
          btn.textContent = 'Verifying…';
          try {
            const vRes = await fetch('/api/auth/verify-otp', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ email: otpEmail, otp })
            });
            const vData = await vRes.json().catch(() => ({}));
            if (!vRes.ok || !vData.token) {
              throw new Error(vData.message || vData.error || 'Invalid or expired verification code');
            }
            state.token = vData.token;
            state.refreshToken = vData.token;
            localStorage.setItem('sf_id_token', vData.token);
            localStorage.setItem('sf_rt', vData.token);
            await loadUserData();
          } catch (err) {
            btn.disabled = false;
            btn.textContent = 'Verify Code & Continue →';
            el('auth-err').textContent = err.message;
          }
        }
      });
    }

    el('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      el('auth-err').textContent = '';
      el('auth-msg').textContent = '';
      const email = el('auth-input-email').value.trim();
      const password = el('auth-input-pass').value;
      const name = el('auth-input-name').value.trim();

      const btn = el('auth-submit-btn');
      btn.disabled = true;
      btn.textContent = 'Signing in…';

      try {
        const res = await fetch(mode === 'signup' ? '/api/auth/signup' : '/api/auth/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email, password, action: mode })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(data.message || data.error || 'Authentication failed');
        }
        if (data.verification_required) {
          el('auth-msg').textContent = 'Account created. Open the verification link sent by Firebase, then sign in.';
          btn.disabled = false;
          btn.textContent = 'Create Account';
          return;
        }
        if (!data.token) throw new Error('Authentication failed: the server did not return a session.');
        if (data.user && data.user.email_verified === false) throw new Error('Please verify your email using the Firebase link, then sign in again.');

        state.token = data.token;
        state.refreshToken = data.refreshToken || data.token;
        state.tokenExpiresAt = Date.now() + 3600 * 1000;
        localStorage.setItem('sf_id_token', data.token);
        localStorage.setItem('sf_rt', data.refreshToken || data.token);

        if (mode === 'signup' && name) {
          await api('/api/me', { method: 'PATCH', body: { name } }).catch(() => null);
        }

        await loadUserData();
      } catch (err) {
        btn.disabled = false;
        btn.textContent = mode === 'signup' ? 'Create Account' : 'Sign In';
        el('auth-err').textContent = err.message;
      }
    });

    el('logout-btn').addEventListener('click', logout);

    const triggerInstantVerify = async () => {
      try {
        if (state.user?.email_verified) { alert('This email is already verified.'); return; }
        const apiKey = state.cfg?.firebase?.apiKey;
        if (!apiKey || !state.token) throw new Error('Firebase email verification is not configured.');
        const res = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ requestType: 'VERIFY_EMAIL', idToken: state.token })
        });
        if (!res.ok) {
          const d = await res.json().catch(() => ({}));
          throw new Error(d.error?.message || 'Firebase could not send the verification email.');
        }
        alert('Verification link sent. Open it, then sign in again to continue.');
      } catch (e) {
        alert('Could not send the verification link: ' + e.message);
      }
    };

    el('instant-verify-btn')?.addEventListener('click', triggerInstantVerify);
    el('acc-verify-btn')?.addEventListener('click', triggerInstantVerify);
    el('send-verify-btn')?.addEventListener('click', triggerInstantVerify);
  }

  async function refreshToken() {
    const apiKey = state.cfg?.firebase?.apiKey;
    if (!apiKey || !state.refreshToken) return false;
    try {
      const res = await fetch(`https://securetoken.googleapis.com/v1/token?key=${apiKey}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(state.refreshToken)}`
      });
      const data = await res.json();
      if (!res.ok) {
        localStorage.removeItem('sf_rt');
        state.refreshToken = null;
        return false;
      }
      state.token = data.id_token;
      state.refreshToken = data.refresh_token;
      state.tokenExpiresAt = Date.now() + (parseInt(data.expires_in, 10) || 3600) * 1000;
      localStorage.setItem('sf_rt', data.refresh_token);
      return true;
    } catch (_) {
      return false;
    }
  }

  function logout() {
    state.token = null;
    state.refreshToken = null;
    state.user = null;
    localStorage.removeItem('sf_rt');
    showAuthScreen();
  }

  /* ---------------------- API Helper ---------------------- */
  async function api(path, opts = {}) {
    if (state.tokenExpiresAt && Date.now() > state.tokenExpiresAt - 60000) {
      await refreshToken();
    }
    const headers = Object.assign({}, opts.headers, {
      'authorization': `Bearer ${state.token}`
    });
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
      headers['content-type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    const res = await fetch(path, Object.assign({}, opts, { headers }));
    if (res.status === 401 && state.refreshToken) {
      const ok = await refreshToken();
      if (ok) {
        headers['authorization'] = `Bearer ${state.token}`;
        return fetch(path, Object.assign({}, opts, { headers }));
      }
    }
    return res;
  }

  /* ---------------------- Load User Data ---------------------- */
  async function loadUserData() {
    try {
      const res = await api('/api/me');
      if (!res.ok) {
        logout();
        return;
      }
      const data = await res.json();
      if (!data.user.email_verified) {
        state.user = data.user;
        showAuthScreen();
        el('auth-err').textContent = 'Your email is not verified yet. Open the Firebase verification link, then sign in again.';
        return;
      }
      state.user = data.user;
      state.plan = data.plan;

      showWorkspace();
      renderUserProfile(data);
      updateStepperFlow(data);
      loadRepos();
      loadScans();
      loadCodebasesAndRepairs();
    } catch (e) {
      console.error('Failed to load user data', e);
      logout();
    }
  }

  function renderNavUser() {
    const area = el('nav-user-area');
    if (!state.user) {
      area.innerHTML = '';
      return;
    }
    const planBadge = state.plan?.id === 'pro'
      ? `<span class="badge-status badge-pro">PRO PASS</span>`
      : `<span class="badge-status badge-free">FREE</span>`;
    area.innerHTML = `
      <span class="fine" style="color: var(--fg);">${escapeHtml(state.user.name || state.user.email)}</span>
      ${planBadge}
      <button class="btn btn-ghost btn-sm" id="nav-logout-btn">Log out</button>
    `;
    el('nav-logout-btn')?.addEventListener('click', logout);
  }

  function renderUserProfile(data) {
    el('d-user-name').textContent = data.user.name || 'Developer';
    el('d-user-email').textContent = data.user.email;
    el('d-plan-badge').textContent = data.plan.name;
    el('d-plan-badge').className = `badge ${data.plan.id === 'pro' ? 'badge-pro' : ''}`;

    // Verification banner
    if (!data.user.email_verified) {
      el('verify-banner').style.display = 'flex';
      el('acc-verify-badge').textContent = 'Unverified';
      el('acc-verify-badge').className = 'badge-status badge-queued';
    } else {
      el('verify-banner').style.display = 'none';
      el('acc-verify-badge').textContent = 'Verified';
      el('acc-verify-badge').className = 'badge-status badge-active';
    }

    // Overview cards
    el('ov-plan-name').textContent = data.plan.name;
    el('ov-plan-desc').textContent = `${data.plan.repos} Repositories · ${data.plan.aiFixesPerMonth} AI Fixes/mo`;

    if (data.github?.connected) {
      el('ov-gh-status').innerHTML = `<img src="${escapeHtml(data.github.avatarUrl)}" class="avatar-sm"> ${escapeHtml(data.github.login)}`;
      el('ov-gh-desc').textContent = `Scopes: ${data.github.scopes || 'default'}`;
    } else {
      el('ov-gh-status').textContent = 'Not Connected';
      el('ov-gh-desc').textContent = 'Connect GitHub to monitor repositories and auto-scan pushes.';
    }

    // Account settings form
    el('acc-name').value = data.user.name || '';
    el('acc-email').value = data.user.email || '';

    // Alert settings
    if (data.alerts) {
      el('pref-alerts-enabled').checked = data.alerts.enabled;
      el('pref-min-sev').value = data.alerts.minSeverity;
      qsa('.pref-type').forEach(cb => {
        cb.checked = (data.alerts.types || []).includes(cb.value);
      });
    }
  }

  /* ---------------------- 3-Step Flow Stepper ---------------------- */
  function updateStepperFlow(data) {
    // Step 1: Account
    el('fstep-1-title').textContent = data.user.name || data.user.email.split('@')[0];
    el('fstep-1-desc').textContent = `${data.user.email} (${data.user.email_verified ? 'Verified' : 'Unverified'})`;

    // Step 2: Plan & Pay
    const isPro = data.plan?.id === 'pro';
    const fstep2 = el('fstep-2');
    if (isPro) {
      fstep2.className = 'flow-step-box done';
      el('fstep-2-check').textContent = '✓';
      el('fstep-2-title').textContent = 'Pro Pass Active';
      el('fstep-2-desc').textContent = '10 Repos, 100 AI Fixes, Direct Push';
      el('fstep-2-action').innerHTML = '<span class="badge-status badge-active">ACTIVE SUBSCRIBER</span>';
    } else {
      fstep2.className = 'flow-step-box active';
      el('fstep-2-check').textContent = '2';
      el('fstep-2-title').textContent = 'Pro Pass (₹699)';
      el('fstep-2-desc').textContent = 'Unlock 10 repos, 100 AI fixes, direct push & alerts';
      el('fstep-2-action').innerHTML = `
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-solid btn-sm" id="fstep-pay-btn" style="flex:1;">Pay ₹699 with Cashfree →</button>
          <button class="btn btn-ghost btn-sm" id="fstep-free-btn">Use Free</button>
        </div>
      `;
      el('fstep-pay-btn')?.addEventListener('click', () => initiateCashfreeCheckout({ plan: 'pro' }));
      el('fstep-free-btn')?.addEventListener('click', () => switchTab('repos'));
    }

    // Step 3: GitHub Connection
    const isGh = data.github?.connected;
    const fstep3 = el('fstep-3');
    if (isGh) {
      fstep3.className = 'flow-step-box done';
      el('fstep-3-check').textContent = '✓';
      el('fstep-3-title').textContent = `@${data.github.login}`;
      el('fstep-3-desc').textContent = 'GitHub Connected & Repositories Active';
      el('fstep-3-action').innerHTML = '<span class="badge-status badge-active">CONNECTED</span>';
    } else {
      fstep3.className = `flow-step-box ${isPro ? 'active' : 'pending'}`;
      el('fstep-3-check').textContent = '3';
      el('fstep-3-title').textContent = 'Connect GitHub';
      el('fstep-3-desc').textContent = 'Link your repositories for automated vulnerability scanning';
      el('fstep-3-action').innerHTML = '<button class="btn btn-crimson btn-sm" id="fstep-gh-btn" style="width:100%;">Connect GitHub Account →</button>';
      el('fstep-gh-btn')?.addEventListener('click', connectGitHub);
    }
  }

  /* ---------------------- Billing (Cashfree) (STEP 2) ---------------------- */
  function updateBillingView() {
    const isPro = state.plan?.id === 'pro';
    const buyBtn = el('buy-pro-btn');
    if (buyBtn) {
      buyBtn.textContent = isPro ? 'Extend Pro Pass (₹699)' : 'Pay ₹699 with Cashfree →';
    }
  }

  async function initiateCashfreeCheckout(options = {}) {
    const plan = options.plan || 'pro';
    const phone = options.phone || '9876543210';
    const statusEl = el('cf-pay-status');
    if (statusEl) statusEl.innerHTML = '<span style="color:var(--gold);">Creating secure Cashfree order…</span>';

    try {
      const res = await api('/api/billing/checkout', {
        method: 'POST',
        body: { plan, phone }
      });
      const data = await res.json();
      if (!res.ok) {
        if (res.status === 409) {
          if (statusEl) statusEl.innerHTML = `<span style="color:#4ade80;">${escapeHtml(data.message || 'Your Pro Pass is already active!')}</span>`;
          await loadUserData();
          return;
        }
        throw new Error(data.message || data.error || 'Failed to initiate checkout');
      }

      const cfMode = state.cfg?.cashfree?.mode || 'sandbox';
      const checkoutUrl = cfMode === 'production'
        ? `https://payments.cashfree.com/pg/view/sessions/checkout?payment_session_id=${data.paymentSessionId}`
        : `https://sandbox.cashfree.com/pg/view/sessions/checkout?payment_session_id=${data.paymentSessionId}`;

      if (statusEl) {
        statusEl.innerHTML = `
          <div style="background: rgba(200, 150, 60, 0.12); border: 1px solid var(--gold); border-radius: 6px; padding: 14px; margin-top: 14px; text-align: center;">
            <p style="margin: 0 0 8px; color: var(--gold); font-weight: bold;">Cashfree Checkout Created (${escapeHtml(data.orderId)})</p>
            <div style="display: flex; gap: 8px; justify-content: center; flex-wrap: wrap;">
              <a href="${checkoutUrl}" target="_blank" class="btn btn-solid btn-sm" id="cf-open-direct">Open Cashfree Checkout in New Tab ↗</a>
              <button class="btn btn-ghost btn-sm" id="cf-recheck-btn">Verify Payment</button>
            </div>
            <p class="fine" style="margin: 8px 0 0;">Cards, UPI, NetBanking &amp; Wallets supported via Cashfree.</p>
          </div>
        `;
        el('cf-recheck-btn')?.addEventListener('click', () => checkOrderPaid(data.orderId));
      }

      if (!window.Cashfree) {
        await new Promise((resolve, reject) => {
          const s = document.createElement('script');
          s.src = 'https://sdk.cashfree.com/js/v3/cashfree.js';
          s.onload = resolve;
          s.onerror = () => reject(new Error('Cashfree SDK could not be loaded'));
          document.head.appendChild(s);
        }).catch(() => null);
      }

      if (window.Cashfree) {
        const cashfree = window.Cashfree({ mode: cfMode });
        try {
          cashfree.checkout({
            paymentSessionId: data.paymentSessionId,
            redirectTarget: '_modal'
          }).then(async (result) => {
            if (result && result.error) {
              console.warn('Cashfree modal closed/error:', result.error);
              checkOrderPaid(data.orderId);
            } else if (result && result.paymentDetails) {
              checkOrderPaid(data.orderId);
            }
          }).catch((err) => {
            console.warn('Cashfree modal catch, checkout link active:', err);
          });
        } catch (e) {
          console.warn('Cashfree exception, checkout link active:', e);
        }
      }
    } catch (e) {
      alert('Checkout error: ' + e.message);
      if (statusEl) statusEl.innerHTML = `<span style="color:#f87171;">Error: ${escapeHtml(e.message)}</span>`;
    }
  }

  async function checkOrderPaid(orderId) {
    try {
      const vRes = await api('/api/billing/verify', {
        method: 'POST',
        body: { orderId }
      });
      const vData = await vRes.json();
      if (vData.paid) {
        alert('Pro Pass activated successfully!');
        await loadUserData();
        switchTab('repos');
      }
    } catch (_) {}
  }

  /* ---------------------- Codebases & Repairs (D1 Recovery) ---------------------- */
  async function loadCodebasesAndRepairs() {
    try {
      const [cbRes, repRes] = await Promise.all([
        api('/api/user/codebases').catch(() => null),
        api('/api/user/repairs').catch(() => null)
      ]);
      const cbData = cbRes && cbRes.ok ? await cbRes.json().catch(() => ({})) : {};
      const repData = repRes && repRes.ok ? await repRes.json().catch(() => ({})) : {};
      const codebases = cbData.codebases || [];
      const repairs = repData.repairs || [];

      if (el('dn-codebases')) {
        el('dn-codebases').textContent = codebases.length ? String(codebases.length) : '';
      }
      renderCodebasesTable(codebases);
      renderRepairsTable(repairs);
    } catch (e) {
      console.warn('Failed to load codebases and repairs', e);
    }
  }

  function renderCodebasesTable(codebases) {
    const container = el('codebases-table-container');
    if (!container) return;
    if (!codebases || !codebases.length) {
      container.innerHTML = '<div style="text-align: center; color: var(--fg-muted); padding: 24px;">No codebases recorded in memory yet. Upload a project in the workspace to store and track fingerprints.</div>';
      return;
    }
    container.innerHTML = `
      <div style="overflow-x: auto;">
        <table class="dash-table">
          <thead>
            <tr>
              <th>Project Name</th>
              <th>Files / Lines</th>
              <th>Fingerprint / ID</th>
              <th>Recorded Issues</th>
              <th>Visits</th>
              <th>Last Seen</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${codebases.map(c => `
              <tr>
                <td><b>${escapeHtml(c.name)}</b><br><span class="fine mono" style="color:var(--fg-muted);">${(c.files || []).slice(0, 3).map(escapeHtml).join(', ')}${(c.files || []).length > 3 ? '…' : ''}</span></td>
                <td>${c.fileCount} files<br><span class="fine">${c.lineCount} lines</span></td>
                <td><code class="mono" style="font-size:0.75rem;">${c.id.slice(0, 12)}…</code></td>
                <td>${c.issueCount > 0 ? `<span class="sev-high" style="font-weight:600;">${c.issueCount} issues</span>` : '<span style="color:#4ade80;">Clean</span>'}</td>
                <td>${c.visits}</td>
                <td><span class="fine">${new Date(c.updatedAt).toLocaleString()}</span></td>
                <td>
                  <a href="app.html" class="btn btn-ghost btn-sm" style="text-decoration:none;">Open Scanner →</a>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderRepairsTable(repairs) {
    const container = el('repairs-table-container');
    if (!container) return;
    if (!repairs || !repairs.length) {
      container.innerHTML = '<div style="text-align: center; color: var(--fg-muted); padding: 24px;">No repair requests created yet.</div>';
      return;
    }
    container.innerHTML = `
      <div style="overflow-x: auto;">
        <table class="dash-table">
          <thead>
            <tr>
              <th>Request ID</th>
              <th>Finding &amp; Target</th>
              <th>Status</th>
              <th>Cashfree Order</th>
              <th>Created</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${repairs.map(r => `
              <tr>
                <td><code class="mono">${r.id}</code></td>
                <td>
                  <b>${escapeHtml(r.finding.title || 'Security Repair')}</b>
                  <br><span class="fine mono">${escapeHtml(r.finding.file || '')}${r.finding.line ? ':' + r.finding.line : ''}</span>
                </td>
                <td>
                  <span class="badge-status ${r.status === 'submitted' || r.status === 'fulfilled' || r.status === 'paid' ? 'badge-completed' : 'badge-queued'}">${escapeHtml(r.status.replace(/_/g, ' '))}</span>
                </td>
                <td><code class="mono" style="font-size:0.8rem;">${escapeHtml(r.orderId || '—')}</code></td>
                <td><span class="fine">${new Date(r.createdAt).toLocaleString()}</span></td>
                <td>
                  <a href="app.html" class="btn btn-ghost btn-sm" style="text-decoration:none;">View in Fix Studio →</a>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  /* ---------------------- Repositories (STEP 3) ---------------------- */
  async function loadRepos() {
    try {
      const res = await api('/api/repos');
      if (!res.ok) return;
      const data = await res.json();
      state.repos = data.repos || [];
      renderReposTable();
      updateOverviewStats();
      checkGitHubConnection();
    } catch (e) {
      console.warn('Failed to load repos', e);
    }
  }

  function renderReposTable() {
    const tbody = el('repos-tbody');
    if (!state.repos.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--fg-muted); padding: 32px;">No monitored repositories yet. Click "Add Repository" above.</td></tr>`;
      return;
    }
    tbody.innerHTML = state.repos.map(r => `
      <tr>
        <td><b>${escapeHtml(r.full_name)}</b> ${r.private ? '<span class="fine">(private)</span>' : ''}</td>
        <td><code class="mono">${escapeHtml(r.branch)}</code></td>
        <td><span class="badge-status badge-queued">${escapeHtml(r.monitoring)}</span></td>
        <td><span class="badge-status ${r.status === 'active' ? 'badge-active' : 'badge-failed'}">${escapeHtml(r.status)}</span></td>
        <td><code class="mono">${escapeHtml((r.last_sha || 'none').slice(0, 7))}</code></td>
        <td>
          <button class="btn btn-crimson btn-sm btn-scan-repo" data-id="${r.id}">Scan</button>
          <button class="btn btn-ghost btn-sm btn-del-repo" data-id="${r.id}" style="color: #f87171;">Remove</button>
        </td>
      </tr>
    `).join('');

    qsa('.btn-scan-repo').forEach(b => {
      b.addEventListener('click', () => triggerRepoScan(b.dataset.id));
    });
    qsa('.btn-del-repo').forEach(b => {
      b.addEventListener('click', () => deleteRepo(b.dataset.id));
    });
  }

  async function checkGitHubConnection() {
    try {
      const meRes = await api('/api/me');
      const me = await meRes.json();
      const connected = me.github?.connected;
      const topActions = el('repo-top-actions');

      if (!connected) {
        if (el('repo-connect-banner')) el('repo-connect-banner').style.display = 'block';
        if (el('all-repos-container')) el('all-repos-container').style.display = 'none';
        if (topActions) {
          topActions.innerHTML = `<button class="btn btn-crimson btn-sm" id="top-connect-gh">Connect GitHub</button>`;
          el('top-connect-gh')?.addEventListener('click', connectGitHub);
        }
      } else {
        if (el('repo-connect-banner')) el('repo-connect-banner').style.display = 'none';
        if (el('all-repos-container')) el('all-repos-container').style.display = 'block';
        if (topActions) {
          topActions.innerHTML = `
            <button class="btn btn-crimson btn-sm" id="top-scan-all">⚡ Auto-Scan All Repos</button>
            <button class="btn btn-solid btn-sm" id="btn-show-add-repo">+ Add Repository</button>
          `;
          el('top-scan-all')?.addEventListener('click', autoScanAllRepos);
          el('btn-show-add-repo')?.addEventListener('click', openAddRepoDialog);
        }
        await loadAndRenderDiscoveredRepos();
      }
    } catch (_) {}
  }

  async function loadAndRenderDiscoveredRepos() {
    const grid = el('repos-cards-grid');
    if (!grid) return;
    grid.innerHTML = '<div style="padding: 24px; text-align: center; color: var(--fg-muted);">Discovering repositories from your connected GitHub account…</div>';

    try {
      const ghRes = await api('/api/github/repos');
      const ghData = await ghRes.json();
      const ghRepos = ghData.repos || [];

      if (!ghRepos.length) {
        grid.innerHTML = '<div class="card" style="padding: 24px; text-align: center;"><p class="fine">No repositories found in your GitHub account. Create or push a repository to GitHub to get started.</p></div>';
        return;
      }

      // Fetch latest scan findings for all monitored repos
      const repoFindingsMap = {};
      const repoScanMap = {};
      for (const mr of state.repos) {
        try {
          const sRes = await api(`/api/repos/${mr.id}`);
          if (sRes.ok) {
            const sData = await sRes.json();
            const recent = (sData.recentScans || [])[0];
            if (recent) {
              repoScanMap[mr.gh_repo_id] = recent;
              const fRes = await api(`/api/scans/${recent.id}/findings`);
              if (fRes.ok) {
                const fData = await fRes.json();
                repoFindingsMap[mr.gh_repo_id] = fData.findings || [];
              }
            }
          }
        } catch (_) {}
      }

      grid.innerHTML = ghRepos.map(r => {
        const monitored = state.repos.find(x => x.gh_repo_id === r.id);
        const scan = repoScanMap[r.id];
        const findings = repoFindingsMap[r.id] || [];
        const isScanned = !!scan;

        let statusBadge = '<span class="badge-status badge-queued">READY TO SCAN</span>';
        if (isScanned) {
          if (findings.length === 0) {
            statusBadge = '<span class="badge-status badge-complete">CLEAN · 0 BUGS</span>';
          } else {
            statusBadge = `<span class="badge-status badge-failed">VULNERABILITIES FOUND (${findings.length})</span>`;
          }
        }

        let findingsHtml = '';
        if (isScanned && findings.length > 0) {
          const highCount = findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
          const medCount = findings.filter(f => f.severity === 'medium').length;
          const lowCount = findings.filter(f => f.severity === 'low' || f.severity === 'info').length;

          const findingCards = findings.map(f => {
            let evLines = [];
            try { evLines = JSON.parse(f.evidence || '[]'); } catch (_) {}
            const evSnippet = evLines.map(e => `
              <div style="display: flex; gap: 8px;">
                <span style="color: var(--fg-muted); width: 28px; text-align: right;">${e.line}</span>
                <span class="mono">${escapeHtml(e.text)}</span>
              </div>
            `).join('');

            return `
              <div class="card" style="background: rgba(0,0,0,0.3); border: 1px solid var(--border); padding: 14px; margin-top: 10px; border-radius: 6px;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:8px;">
                  <div>
                    <span class="sev sev-${f.severity}">${escapeHtml(f.severity.toUpperCase())}</span>
                    <span class="mono fine" style="margin-left:8px;">${escapeHtml(f.rule_id)}</span>
                    <h4 style="margin:6px 0 2px; font-size:1.05rem; color:var(--fg);">${escapeHtml(f.title)}</h4>
                    <span class="mono fine" style="color:var(--gold);">${escapeHtml(f.file)}:${f.line}</span>
                  </div>
                  <div>
                    <button class="btn btn-solid btn-sm btn-one-click-deploy"
                      data-scan-id="${scan.id}"
                      data-finding-id="${f.id}"
                      data-repo-id="${monitored ? monitored.id : ''}">
                      🚀 1-Click Deploy Fix to GitHub
                    </button>
                  </div>
                </div>
                ${evSnippet ? `<div style="background:#0c0a09; border:1px solid var(--border); border-radius:4px; padding:8px 12px; margin:10px 0; font-family:var(--font-mono); font-size:0.8rem; overflow-x:auto;">${evSnippet}</div>` : ''}
                <p class="fine" style="margin:4px 0;"><b>Guidance:</b> ${escapeHtml(f.fix)}</p>
                <div class="deploy-result-box" id="res-${f.id}"></div>
              </div>
            `;
          }).join('');

          findingsHtml = `
            <div style="margin-top: 14px; border-top: 1px solid var(--border); padding-top: 12px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="font-size:0.85rem; font-weight:bold; color:var(--fg-muted); text-transform:uppercase;">
                  Scan Findings Summary:
                  <span style="color:#f87171; margin-left:6px;">${highCount} High</span> ·
                  <span style="color:#fbbf24; margin-left:4px;">${medCount} Medium</span> ·
                  <span style="color:#94a3b8; margin-left:4px;">${lowCount} Low</span>
                </span>
              </div>
              ${findingCards}
            </div>
          `;
        } else if (isScanned) {
          findingsHtml = `
            <div style="margin-top: 12px; padding: 12px; background: rgba(5,150,105,0.08); border: 1px solid #059669; border-radius: 6px; color: #6ee7b7; font-size: 0.9rem;">
              ✓ All pattern security rules passed cleanly. 0 vulnerabilities detected in <code>${escapeHtml(r.full_name)}</code>.
            </div>
          `;
        }

        return `
          <div class="card" style="padding: 20px; border: 1px solid var(--border); border-radius: 8px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
              <div>
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                  <h3 style="margin:0; font-size:1.15rem;">
                    <a href="https://github.com/${escapeHtml(r.full_name)}" target="_blank" style="color:var(--fg); text-decoration:none;">${escapeHtml(r.full_name)} ↗</a>
                  </h3>
                  <span class="fine" style="padding:2px 6px; background:var(--bg); border:1px solid var(--border); border-radius:4px;">${r.private ? 'Private' : 'Public'}</span>
                  <span class="mono fine" style="color:var(--gold);">branch: ${escapeHtml(r.default_branch || 'main')}</span>
                </div>
                <div style="margin-top:6px;">
                  ${statusBadge}
                </div>
              </div>
              <div style="display:flex; gap:8px;">
                <button class="btn btn-crimson btn-sm btn-quick-scan"
                  data-gh-id="${r.id}"
                  data-full-name="${escapeHtml(r.full_name)}"
                  data-branch="${escapeHtml(r.default_branch || 'main')}">
                  ${isScanned ? 'Rescan Repository' : 'Scan Repository'}
                </button>
              </div>
            </div>
            ${findingsHtml}
          </div>
        `;
      }).join('');

      // Wire up scan buttons
      qsa('.btn-quick-scan').forEach(b => {
        b.addEventListener('click', async () => {
          b.disabled = true;
          b.textContent = 'Scanning…';
          await performQuickScan(b.dataset.ghId, b.dataset.fullName, b.dataset.branch);
        });
      });

      // Wire up 1-click deploy buttons
      qsa('.btn-one-click-deploy').forEach(b => {
        b.addEventListener('click', () => executeOneClickDeploy(b));
      });

      el('btn-auto-scan-all')?.addEventListener('click', autoScanAllRepos);

    } catch (e) {
      grid.innerHTML = `<div class="card" style="padding: 20px; color:#f87171;">Failed to load GitHub repositories: ${escapeHtml(e.message)}</div>`;
    }
  }

  async function performQuickScan(ghRepoId, fullName, branch) {
    try {
      let monitored = state.repos.find(x => x.gh_repo_id === parseInt(ghRepoId, 10));
      if (!monitored) {
        const regRes = await api('/api/repos', {
          method: 'POST',
          body: { ghRepoId: parseInt(ghRepoId, 10), branch: branch || 'main', monitor: 'webhook' }
        });
        const regData = await regRes.json();
        if (!regRes.ok) throw new Error(regData.error || 'Failed to register repository');
        monitored = regData.repo;
        state.repos.push(monitored);
      }

      const scanRes = await api(`/api/repos/${monitored.id}/scan`, { method: 'POST' });
      const scanData = await scanRes.json();
      if (!scanRes.ok) throw new Error(scanData.error || 'Scan failed');

      await loadRepos();
    } catch (err) {
      alert(`Error scanning ${fullName}: ${err.message}`);
      await loadRepos();
    }
  }

  async function autoScanAllRepos() {
    const btn = el('btn-auto-scan-all') || el('top-scan-all');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '⚡ Auto-Scanning All Repositories…';
    }

    const scanButtons = Array.from(qsa('.btn-quick-scan'));
    for (const b of scanButtons) {
      b.disabled = true;
      b.textContent = 'Scanning…';
      await performQuickScan(b.dataset.ghId, b.dataset.fullName, b.dataset.branch);
    }

    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Auto-Scan All Repositories';
    }
    await loadRepos();
  }

  async function executeOneClickDeploy(btn) {
    const scanId = btn.dataset.scanId;
    const findingId = btn.dataset.findingId;
    const resBox = el(`res-${findingId}`);

    btn.disabled = true;
    btn.textContent = '1/3 Generating AI fix…';
    if (resBox) resBox.innerHTML = '<span style="color:var(--gold);font-size:0.85rem;">Generating verified fix using Gemini AI…</span>';

    try {
      // Step 1: Generate AI patch
      const patchRes = await api('/api/patches', {
        method: 'POST',
        body: { scanId, findingId }
      });
      const patchData = await patchRes.json();
      if (!patchRes.ok) throw new Error(patchData.error || 'Failed to generate patch');
      const patch = patchData.patch;

      // Step 2: Auto-accept patch
      btn.textContent = '2/3 Running validations…';
      if (resBox) resBox.innerHTML = '<span style="color:var(--gold);font-size:0.85rem;">Validating safety checks & diff…</span>';
      const acceptRes = await api(`/api/patches/${patch.id}`, {
        method: 'PATCH',
        body: { action: 'accept' }
      });
      if (!acceptRes.ok) {
        const accData = await acceptRes.json();
        throw new Error(accData.error || 'Patch validation failed');
      }

      // Step 3: Push commit to fix branch & open Pull Request on GitHub
      btn.textContent = '3/3 Pushing to GitHub & creating PR…';
      if (resBox) resBox.innerHTML = '<span style="color:var(--gold);font-size:0.85rem;">Pushing fix branch and creating GitHub Pull Request…</span>';

      const pushRes = await api(`/api/patches/${patch.id}/push`, {
        method: 'POST',
        body: { confirm: true, mode: 'pr' }
      });
      const pushData = await pushRes.json();
      if (!pushRes.ok) throw new Error(pushData.error || 'Push to GitHub failed');

      btn.textContent = '✓ Pull Request opened';
      btn.className = 'btn btn-ghost btn-sm';
      if (resBox) {
        resBox.innerHTML = `
          <div style="background:#064e3b; border:1px solid #047857; color:#6ee7b7; padding:12px 16px; border-radius:6px; font-size:0.9rem; margin-top:8px;">
            <b>✓ Pull Request Created!</b> Clean fix pushed to branch <code class="mono" style="color:#fff;">${escapeHtml(pushData.branch || pushData.fixBranch || 'fix')}</code>.<br>
            <a href="${pushData.prUrl}" target="_blank" style="color:#fff; text-decoration:underline; font-weight:bold; display:inline-block; margin-top:6px;">
              View Pull Request on GitHub (${escapeHtml(pushData.prUrl)}) →
            </a>
          </div>
        `;
      }
    } catch (err) {
      btn.disabled = false;
      btn.textContent = 'Retry 1-Click Deploy';
      if (resBox) {
        resBox.innerHTML = `<div style="color:#f87171; font-size:0.85rem; margin-top:6px;">Deploy error: ${escapeHtml(err.message)}</div>`;
      }
    }
  }

  async function connectGitHub() {
    try {
      const res = await api('/api/github/connect', { method: 'POST', body: { scope: 'public' } });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      }
    } catch (e) {
      alert('Failed to initiate GitHub connection: ' + e.message);
    }
  }

  async function openAddRepoDialog() {
    el('add-repo-card').style.display = 'block';
    const sel = el('add-repo-select');
    sel.innerHTML = '<option value="">Loading repositories from GitHub…</option>';
    try {
      const res = await api('/api/github/repos');
      const data = await res.json();
      const repos = data.repos || [];
      if (!repos.length) {
        sel.innerHTML = '<option value="">No accessible repositories found</option>';
        return;
      }
      sel.innerHTML = repos.map(r => `
        <option value="${r.id}" data-name="${escapeHtml(r.full_name)}" data-branch="${escapeHtml(r.default_branch || 'main')}">
          ${escapeHtml(r.full_name)} ${r.private ? '(private)' : ''}
        </option>
      `).join('');

      sel.addEventListener('change', () => {
        const opt = sel.options[sel.selectedIndex];
        el('add-repo-branch').value = opt.dataset.branch || 'main';
      });
    } catch (e) {
      sel.innerHTML = '<option value="">Error loading repositories</option>';
    }
  }

  async function triggerRepoScan(repoId) {
    try {
      const res = await api(`/api/repos/${repoId}/scan`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed');
      alert('Security scan queued! Check Scans & History for results.');
      switchTab('scans');
    } catch (e) {
      alert('Error triggering scan: ' + e.message);
    }
  }

  async function deleteRepo(repoId) {
    if (!confirm('Are you sure you want to stop monitoring this repository?')) return;
    try {
      const res = await api(`/api/repos/${repoId}`, { method: 'DELETE' });
      if (res.ok) {
        loadRepos();
      }
    } catch (e) {
      alert('Error removing repository: ' + e.message);
    }
  }

  /* ---------------------- Scans & History ---------------------- */
  async function loadScans() {
    try {
      const res = await api('/api/scans');
      if (!res.ok) return;
      const data = await res.json();
      state.scans = data.scans || [];
      renderScansTable();
      populateScanFilters();
    } catch (e) {
      console.warn('Failed to load scans', e);
    }
  }

  function renderScansTable() {
    const tbody = el('scans-tbody');
    if (!state.scans.length) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--fg-muted); padding: 32px;">No scans recorded yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = state.scans.map(s => {
      let counts = { critical: 0, high: 0, medium: 0, low: 0 };
      try { counts = JSON.parse(s.counts || '{}'); } catch (_) {}
      const countsStr = `
        <span class="sev-critical">C:${counts.critical || 0}</span>
        <span class="sev-high">H:${counts.high || 0}</span>
        <span class="sev-medium">M:${counts.medium || 0}</span>
      `;
      const dateStr = s.created_at ? new Date(s.created_at).toLocaleString() : '–';
      return `
        <tr>
          <td><code class="mono">${escapeHtml(s.id.slice(0, 10))}</code></td>
          <td><b>${escapeHtml(s.repo_name || '–')}</b></td>
          <td><code class="mono">${escapeHtml(s.commit_sha.slice(0, 7))}</code></td>
          <td><span class="fine">${escapeHtml(s.trigger)}</span></td>
          <td><span class="badge-status badge-${s.status}">${escapeHtml(s.status)}</span></td>
          <td>${countsStr}</td>
          <td><span class="fine">${escapeHtml(dateStr)}</span></td>
          <td>
            <a href="/api/scans/${s.id}/report?format=html" target="_blank" class="btn btn-ghost btn-sm">HTML</a>
            <a href="/api/scans/${s.id}/report?format=json" target="_blank" class="btn btn-ghost btn-sm">JSON</a>
            <button class="btn btn-solid btn-sm btn-view-findings" data-id="${s.id}">Findings</button>
          </td>
        </tr>
      `;
    }).join('');

    qsa('.btn-view-findings').forEach(b => {
      b.addEventListener('click', () => {
        state.activeScanId = b.dataset.id;
        switchTab('findings');
      });
    });
  }

  function populateScanFilters() {
    const filter = el('scan-repo-filter');
    filter.innerHTML = '<option value="">All Repositories</option>' + state.repos.map(r => `
      <option value="${r.id}">${escapeHtml(r.full_name)}</option>
    `).join('');
  }

  /* ---------------------- Findings Explorer ---------------------- */
  async function loadFindingsForActiveScan() {
    const container = el('findings-container');
    if (!state.activeScanId && state.scans.length) {
      state.activeScanId = state.scans[0].id;
    }
    if (!state.activeScanId) {
      container.innerHTML = '<p class="fine">No scans available yet. Trigger a scan first.</p>';
      return;
    }

    try {
      const res = await api(`/api/scans/${state.activeScanId}/findings`);
      if (!res.ok) return;
      const data = await res.json();
      state.findings = data.findings || [];
      renderFindingsList();
    } catch (e) {
      container.innerHTML = '<p class="fine">Failed to load findings.</p>';
    }
  }

  function renderFindingsList() {
    const container = el('findings-container');
    const filterSev = el('findings-sev-filter')?.value || 'all';
    const list = state.findings.filter(f => filterSev === 'all' || f.severity === filterSev);

    if (!list.length) {
      container.innerHTML = '<div class="card" style="padding: 24px; text-align: center;"><h3 style="color: #4ade80;">No vulnerabilities found</h3><p class="fine">Scan clean under current rules and filters.</p></div>';
      return;
    }

    container.innerHTML = list.map(f => {
      let evidenceLines = [];
      try { evidenceLines = JSON.parse(f.evidence || '[]'); } catch (_) {}
      const codeSnippet = evidenceLines.map(e => `
        <div style="display: flex; gap: 8px;">
          <span style="color: var(--fg-muted); width: 36px; text-align: right;">${e.line}</span>
          <span class="mono">${escapeHtml(e.text)}</span>
        </div>
      `).join('');

      return `
        <div class="card" style="padding: 20px; margin-bottom: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
            <div>
              <span class="sev sev-${f.severity}">${escapeHtml(f.severity)}</span>
              <span class="mono fine" style="margin-left: 8px;">${escapeHtml(f.rule_id)}</span>
              <h3 style="margin: 6px 0 2px;">${escapeHtml(f.title)}</h3>
              <span class="mono fine">${escapeHtml(f.file)}:${f.line}</span>
            </div>
            <button class="btn btn-crimson btn-sm btn-open-fix" data-id="${f.id}">Open in Fix Studio →</button>
          </div>
          <div style="background: rgba(0,0,0,0.3); border-radius: 4px; padding: 12px; margin: 12px 0;">
            ${codeSnippet || '<span class="fine">No direct evidence snippet</span>'}
          </div>
          <p class="fine" style="margin: 6px 0;"><b>Why:</b> ${escapeHtml(f.why)}</p>
          <p class="fine" style="margin: 6px 0;"><b>Guidance:</b> ${escapeHtml(f.fix)}</p>
        </div>
      `;
    }).join('');

    qsa('.btn-open-fix').forEach(b => {
      b.addEventListener('click', () => {
        const finding = state.findings.find(x => x.id === b.dataset.id);
        if (finding) {
          state.selectedFinding = finding;
          switchTab('fix');
          setupFixStudio(finding);
        }
      });
    });
  }

  /* ---------------------- Fix Studio ---------------------- */
  function setupFixStudio(finding) {
    el('fix-prompt-box').style.display = 'none';
    el('fix-active-box').style.display = 'block';
    el('fix-patch-title').textContent = `Fix: ${finding.title}`;
    el('fix-patch-file').textContent = `${finding.file}:${finding.line}`;
    el('fix-diff-container').innerHTML = '<div style="padding: 24px; text-align: center; color: var(--fg-muted);">Generating structured AI patch proposal…</div>';

    generatePatch(finding);
  }

  async function generatePatch(finding) {
    try {
      const res = await api('/api/patches', {
        method: 'POST',
        body: { scanId: finding.scan_id || state.activeScanId, findingId: finding.id }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to generate patch');
      state.activePatch = data.patch;
      renderPatchDetails(data.patch);
    } catch (e) {
      el('fix-diff-container').innerHTML = `<div style="padding: 24px; color: #f87171;">Patch generation failed: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderPatchDetails(patch) {
    el('fix-patch-status').textContent = patch.status.toUpperCase();
    el('fix-patch-status').className = `badge-status badge-${patch.status === 'accepted' ? 'complete' : 'queued'}`;

    // Render honest checks
    const c = patch.checks || {};
    el('fix-checks-grid').innerHTML = `
      <div class="check-item ${c.appliesCleanly ? 'pass' : 'fail'}">
        <b>Applies Cleanly:</b> ${c.appliesCleanly ? 'Yes (exact match)' : 'No (conflict)'}
      </div>
      <div class="check-item ${c.secretScanPassed ? 'pass' : 'fail'}">
        <b>Secret Scan:</b> ${c.secretScanPassed ? 'Clean (No leaked secrets)' : 'Secrets Detected!'}
      </div>
      <div class="check-item ${c.targetEliminated ? 'pass' : 'warn'}">
        <b>Target Eliminated:</b> ${c.targetEliminated ? 'Verified by Pattern Rescan' : 'Still Detected'}
      </div>
      <div class="check-item ${c.newFindingsIntroduced === 0 ? 'pass' : 'fail'}">
        <b>Side Effects:</b> ${c.newFindingsIntroduced === 0 ? '0 New Findings' : `${c.newFindingsIntroduced} New Findings!`}
      </div>
    `;

    // Render diff
    const diff = patch.diff || [];
    el('fix-diff-container').innerHTML = diff.map(d => {
      const cls = d.added ? 'diff-add' : (d.removed ? 'diff-del' : 'diff-ctx');
      const prefix = d.added ? '+' : (d.removed ? '-' : ' ');
      return `<div class="diff-line ${cls}"><span>${prefix}</span><span>${escapeHtml(d.value)}</span></div>`;
    }).join('');

    // Push panel visibility
    if (patch.status === 'accepted') {
      el('push-panel').style.display = 'block';
      el('fix-actions-row').style.display = 'none';
    } else {
      el('push-panel').style.display = 'none';
      el('fix-actions-row').style.display = 'flex';
    }

    setupPatchButtons(patch);
  }

  function setupPatchButtons(patch) {
    el('btn-accept-patch').onclick = async () => {
      const res = await api(`/api/patches/${patch.id}`, { method: 'PATCH', body: { action: 'accept' } });
      if (res.ok) {
        patch.status = 'accepted';
        renderPatchDetails(patch);
      }
    };
    el('btn-reject-patch').onclick = async () => {
      const res = await api(`/api/patches/${patch.id}`, { method: 'PATCH', body: { action: 'reject' } });
      if (res.ok) {
        patch.status = 'rejected';
        renderPatchDetails(patch);
      }
    };

    const confirmCheck = el('push-confirm-check');
    const pushBtn = el('btn-execute-push');
    confirmCheck.onchange = () => {
      pushBtn.disabled = !confirmCheck.checked;
    };

    pushBtn.onclick = async () => {
      pushBtn.disabled = true;
      pushBtn.textContent = 'Pushing to GitHub…';
      const mode = el('push-mode-select').value;
      const targetBranch = el('push-target-branch').value.trim();
      try {
        const res = await api(`/api/patches/${patch.id}/push`, {
          method: 'POST',
          body: { confirm: true, mode, targetBranch }
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Push failed');
        el('push-result-msg').innerHTML = data.prUrl
          ? `<div class="dash-banner" style="background:#064e3b;border-color:#047857;color:#6ee7b7;">PR Created: <a href="${data.prUrl}" target="_blank" style="color:#fff;text-decoration:underline;">${escapeHtml(data.prUrl)}</a></div>`
          : `<div class="dash-banner" style="background:#064e3b;border-color:#047857;color:#6ee7b7;">Direct Push Successful! Commit SHA: ${data.commitSha.slice(0, 7)}</div>`;
        pushBtn.textContent = 'Pushed';
      } catch (e) {
        el('push-result-msg').innerHTML = `<div style="color:#f87171;margin-top:8px;">Push error: ${escapeHtml(e.message)}</div>`;
        pushBtn.disabled = false;
        pushBtn.textContent = 'Retry Push';
      }
    };
  }

  /* ---------------------- ProofLoop Verification ---------------------- */
  function populateProofLoopSelectors() {
    const rSel = el('pl-repo-select');
    rSel.innerHTML = state.repos.map(r => `<option value="${r.id}">${escapeHtml(r.full_name)}</option>`).join('');

    rSel.onchange = updateProofLoopScans;
    updateProofLoopScans();

    el('pl-compare-btn').onclick = runProofLoopComparison;
  }

  function updateProofLoopScans() {
    const repoId = el('pl-repo-select').value;
    const rScans = state.scans.filter(s => s.repo_id === repoId && s.status === 'complete');
    const fSel = el('pl-from-select');
    const tSel = el('pl-to-select');

    if (rScans.length < 2) {
      fSel.innerHTML = '<option value="">Need at least 2 scans to compare</option>';
      tSel.innerHTML = '<option value="">Need at least 2 scans to compare</option>';
      return;
    }

    fSel.innerHTML = rScans.map(s => `<option value="${s.id}">Scan ${s.commit_sha.slice(0, 7)} (${new Date(s.created_at).toLocaleDateString()})</option>`).join('');
    tSel.innerHTML = rScans.map((s, i) => `<option value="${s.id}" ${i === 0 ? 'selected' : ''}>Scan ${s.commit_sha.slice(0, 7)} (${new Date(s.created_at).toLocaleDateString()})</option>`).join('');
  }

  async function runProofLoopComparison() {
    const from = el('pl-from-select').value;
    const to = el('pl-to-select').value;
    if (!from || !to) {
      alert('Please select both a baseline and a newer scan.');
      return;
    }
    const tbody = el('pl-matrix-tbody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--fg-muted);">Running ProofLoop comparative analysis…</td></tr>';

    try {
      const res = await api(`/api/proofloop?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'ProofLoop failed');

      const items = data.comparison || [];
      if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #4ade80;">No vulnerabilities detected across either scan.</td></tr>';
        return;
      }

      tbody.innerHTML = items.map(it => {
        let statusBadge = '';
        if (it.status === 'VERIFIED BY TEST') statusBadge = '<span class="badge-status badge-complete">VERIFIED BY TEST</span>';
        else if (it.status === 'NO LONGER DETECTED') statusBadge = '<span class="badge-status badge-active">NO LONGER DETECTED</span>';
        else if (it.status === 'NEW FINDING') statusBadge = '<span class="badge-status badge-failed">NEW FINDING</span>';
        else statusBadge = '<span class="badge-status badge-queued">STILL DETECTED</span>';

        return `
          <tr>
            <td><b>${escapeHtml(it.finding.title)}</b><br><span class="fine mono">${escapeHtml(it.finding.rule_id)}</span></td>
            <td><code class="mono">${escapeHtml(it.finding.file)}:${it.finding.line}</code></td>
            <td>${statusBadge}</td>
            <td>${it.testCheck ? `<span class="badge-status badge-active">${escapeHtml(it.testCheck)}</span>` : '<span class="fine">None mapped</span>'}</td>
            <td><span class="fine">${it.reappeared ? '<b style="color:#f87171;">Reappeared!</b>' : 'Baseline'}</span></td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="5" style="color: #f87171; text-align: center;">Error running ProofLoop: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  /* ---------------------- Monitoring & Account Settings ---------------------- */
  el('alerts-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const enabled = el('pref-alerts-enabled').checked;
    const minSev = el('pref-min-sev').value;
    const types = qsa('.pref-type:checked').map(cb => cb.value);

    try {
      const res = await api('/api/me', {
        method: 'PATCH',
        body: { alertsEnabled: enabled, alertMinSeverity: minSev, alertTypes: types }
      });
      if (res.ok) {
        const msg = el('alerts-saved-msg');
        msg.style.display = 'inline';
        setTimeout(() => { msg.style.display = 'none'; }, 2500);
      }
    } catch (_) {}
  });

  el('account-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = el('acc-name').value.trim();
    try {
      const res = await api('/api/me', { method: 'PATCH', body: { name } });
      if (res.ok) {
        alert('Profile updated successfully!');
        await loadUserData();
      }
    } catch (_) {}
  });

  el('delete-account-btn')?.addEventListener('click', async () => {
    const ok = confirm('CAUTION: This will delete your SecureFlow account, all repositories, scans, findings, and revoke GitHub access. This cannot be undone. Proceed?');
    if (!ok) return;
    try {
      const res = await api('/api/me', { method: 'DELETE' });
      if (res.ok) {
        alert('Your account and all associated data have been deleted.');
        logout();
      }
    } catch (e) {
      alert('Delete failed: ' + e.message);
    }
  });

  /* ---------------------- Feature Listeners ---------------------- */
  function setupFeatureListeners() {
    el('buy-pro-btn')?.addEventListener('click', () => initiateCashfreeCheckout({ plan: 'pro' }));
    el('buy-repair-btn')?.addEventListener('click', () => initiateCashfreeCheckout({ plan: 'repair' }));
    el('continue-free-btn')?.addEventListener('click', () => switchTab('repos'));
    el('connect-gh-btn')?.addEventListener('click', connectGitHub);
    el('d-quick-scan-btn')?.addEventListener('click', () => {
      switchTab('repos');
      autoScanAllRepos();
    });
    el('btn-auto-scan-all')?.addEventListener('click', autoScanAllRepos);

    el('cancel-add-repo')?.addEventListener('click', () => {
      el('add-repo-card').style.display = 'none';
    });

    el('submit-add-repo')?.addEventListener('click', async () => {
      const sel = el('add-repo-select');
      const ghRepoId = parseInt(sel.value, 10);
      const branch = el('add-repo-branch').value.trim() || 'main';
      const monitoring = el('add-repo-mode').value;

      if (!ghRepoId) {
        alert('Please select a repository');
        return;
      }

      try {
        const res = await api('/api/repos', {
          method: 'POST',
          body: { ghRepoId, branch, monitoring }
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to add repository');
        el('add-repo-card').style.display = 'none';
        loadRepos();
      } catch (e) {
        alert('Error adding repository: ' + e.message);
      }
    });

    el('findings-sev-filter')?.addEventListener('change', renderFindingsList);
  }

  function updateOverviewStats() {
    el('ov-repo-count').textContent = state.repos.length;
    const planLimit = state.plan?.repos || 1;
    el('ov-repo-limit').textContent = `${state.plan?.name || 'Free'}: ${state.repos.length} of ${planLimit} used`;
  }

  function handleUrlHash() {
    const hash = window.location.hash;
    const urlParams = new URLSearchParams(window.location.search);
    const orderId = new URLSearchParams(hash.slice(1)).get('order_id') || urlParams.get('order_id') || urlParams.get('cf_order');
    if (orderId) {
      setTimeout(() => {
        checkOrderPaid(orderId);
      }, 500);
    }
    if (hash.includes('github=connected')) {
      alert('GitHub account successfully connected!');
      window.location.hash = 'repos';
      switchTab('repos');
    } else if (hash.startsWith('#repo=')) {
      switchTab('repos');
    } else if (hash) {
      const v = hash.slice(1);
      if (['overview', 'repos', 'scans', 'findings', 'fix', 'proof', 'billing', 'alerts', 'account'].includes(v)) {
        switchTab(v);
      }
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
})();
