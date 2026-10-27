/**
 * SecureID Guardian - Client-side Architecture & Real-Time Security Operations
 */

class SecureIDApp {
  constructor() {
    this.currentView = 'overview';
    this.totpSecret = '';
    this.totpRemaining = 30;
    this.totpTimerInterval = null;
    this.activeModalAction = null;
    this.selectedUserId = null;
    this.pollInterval = null;

    this.init();
  }

  init() {
    this.setupNavigation();
    this.setupClock();
    this.setupEventListeners();
    this.setupPasswordAuditor();
    this.setupDomainScanner();
    this.setupTOTPLab();
    
    // Initial fetch of platform state
    this.refreshAllData();

    // Start background telemetry polling every 4 seconds
    this.pollInterval = setInterval(() => this.pollTelemetry(), 4000);
  }

  // --- Clock & Telemetry Sync ---
  setupClock() {
    const clockEl = document.getElementById('system-clock');
    const update = () => {
      const d = new Date();
      clockEl.textContent = `UTC ${d.toISOString().slice(11, 19)}`;
    };
    update();
    setInterval(update, 1000);
  }

  // --- Navigation & View Switching ---
  setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', () => {
        const viewId = item.getAttribute('data-view');
        this.switchView(viewId);
      });
    });
  }

  switchView(viewId) {
    this.currentView = viewId;

    // Update active nav button
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.getAttribute('data-view') === viewId);
    });

    // Update view panels
    document.querySelectorAll('.view-section').forEach(sec => {
      sec.classList.remove('active');
    });

    const activeSec = document.getElementById(`view-${viewId}`);
    if (activeSec) {
      activeSec.classList.add('active');
    }

    // Update Header Title
    const titles = {
      'overview': 'SOC Command Center & Live Telemetry',
      'identities': 'Enterprise Identity Directory & Risk Matrix',
      'access-logs': 'Access Logs & UEBA Anomaly Inspector',
      'breach-fortress': 'Password Entropy & Dark Web Breach Fortress',
      'mfa-lab': 'RFC-6238 TOTP Multi-Factor Authentication Lab',
      'policies': 'Zero-Trust Adaptive Security Governance',
      'incidents': 'Active Threat Incidents & Containment Room'
    };
    document.getElementById('current-view-title').textContent = titles[viewId] || 'SecureID Guardian';
  }

  // --- Global Event Listeners ---
  setupEventListeners() {
    document.getElementById('btn-refresh-telemetry').addEventListener('click', () => {
      this.refreshAllData();
      this.showToast('Telemetry synchronized from cloud security edge', 'success');
    });

    // Threat Simulations
    document.getElementById('btn-sim-impossible-travel').addEventListener('click', () => {
      this.triggerSimulation('usr-104', 'impossible_travel');
    });
    document.getElementById('btn-sim-brute-force').addEventListener('click', () => {
      this.triggerSimulation('usr-102', 'brute_force');
    });
    document.getElementById('btn-sim-normal-login').addEventListener('click', () => {
      this.triggerSimulation('usr-101', 'normal');
    });

    // Modal Confirmation Handlers
    document.getElementById('btn-modal-cancel').addEventListener('click', () => {
      this.hideModal();
    });
    document.getElementById('btn-modal-confirm').addEventListener('click', () => {
      if (this.activeModalAction) {
        this.activeModalAction();
      }
      this.hideModal();
    });

    // Identity Search filter
    const searchInput = document.getElementById('identity-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.filterIdentities(e.target.value);
      });
    }
  }

  // --- API Integrations & Data Loading ---
  async refreshAllData() {
    await Promise.all([
      this.fetchDashboardStats(),
      this.fetchIdentities(),
      this.fetchAccessLogs(),
      this.fetchPolicies(),
      this.fetchIncidents()
    ]);
  }

  async pollTelemetry() {
    // Silent background poll to keep telemetry fresh
    try {
      await this.fetchDashboardStats();
      await this.fetchAccessLogs();
      if (this.currentView === 'identities') {
        await this.fetchIdentities();
      }
      if (this.currentView === 'incidents') {
        await this.fetchIncidents();
      }
    } catch (e) {
      console.warn('Polling error:', e);
    }
  }

  async fetchDashboardStats() {
    try {
      const res = await fetch('/api/dashboard/stats');
      const data = await res.json();
      
      const postureEl = document.getElementById('stat-posture-score');
      postureEl.innerHTML = `${data.security_posture_score}<span style="font-size: 1rem; color: var(--text-muted);">/100</span>`;
      
      document.getElementById('stat-total-identities').textContent = data.total_identities;
      document.getElementById('stat-quarantined-subtext').textContent = 
        `${data.quarantined_count} Quarantined • ${data.high_risk_count} Elevated`;
      document.getElementById('stat-high-risk').textContent = data.high_risk_count;
      document.getElementById('stat-active-policies').innerHTML = 
        `${data.active_policies_count}<span style="font-size: 1rem; color: var(--text-muted);">/${data.total_policies_count}</span>`;
      
      const threatPill = document.getElementById('global-threat-pill');
      const threatText = document.getElementById('global-threat-text');
      if (data.threat_level === 'ELEVATED') {
        threatPill.className = 'threat-gauge-pill';
        threatText.textContent = `DEFENSE LEVEL: ELEVATED (${data.active_incidents_count} ALERTS)`;
      } else {
        threatPill.className = 'threat-gauge-pill';
        threatPill.style.borderColor = 'var(--cyber-emerald)';
        threatPill.style.color = '#6ee7b7';
        threatText.textContent = 'DEFENSE LEVEL: NORMAL';
      }
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  }

  async fetchIdentities() {
    try {
      const res = await fetch('/api/identities');
      this.identitiesCache = await res.json();
      this.renderIdentities(this.identitiesCache);
    } catch (err) {
      console.error('Failed to load identities:', err);
    }
  }

  filterIdentities(query) {
    if (!this.identitiesCache) return;
    const q = query.toLowerCase().trim();
    const filtered = this.identitiesCache.filter(u => 
      u.name.toLowerCase().includes(q) || 
      u.email.toLowerCase().includes(q) || 
      u.role.toLowerCase().includes(q) ||
      u.department.toLowerCase().includes(q)
    );
    this.renderIdentities(filtered);
  }

  renderIdentities(identities) {
    const tbody = document.getElementById('identities-table-body');
    tbody.innerHTML = '';

    identities.forEach(u => {
      const tr = document.createElement('tr');
      
      let badgeClass = 'badge-low';
      if (u.risk_level === 'CRITICAL') badgeClass = 'badge-critical';
      else if (u.risk_level === 'HIGH') badgeClass = 'badge-high';
      else if (u.risk_level === 'MODERATE') badgeClass = 'badge-moderate';

      let statusBadge = 'badge-active';
      if (u.status === 'QUARANTINED') statusBadge = 'badge-quarantined';
      else if (u.status === 'STEP_UP_REQUIRED') statusBadge = 'badge-stepup';

      tr.innerHTML = `
        <td>
          <div style="font-weight: 600; color: #fff;">${u.name}</div>
          <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${u.email}</div>
        </td>
        <td>
          <div>${u.department}</div>
          <div style="font-size: 0.75rem; color: var(--text-secondary);">${u.role}</div>
        </td>
        <td>
          <span class="badge ${u.privilege_tier === 'SuperAdmin' ? 'badge-critical' : 'badge-low'}" style="text-transform: none;">
            ${u.privilege_tier}
          </span>
        </td>
        <td>
          <span class="badge ${badgeClass}">${u.risk_score} • ${u.risk_level}</span>
        </td>
        <td>
          <span style="font-family: var(--font-mono); font-size: 0.8rem; color: ${u.mfa_enabled ? 'var(--cyber-emerald)' : 'var(--cyber-crimson)'};">
            ${u.mfa_enabled ? '✓ Enforced' : '✗ Disabled'}
          </span>
        </td>
        <td>
          <span class="badge ${statusBadge}">${u.status}</span>
        </td>
        <td>
          <div style="font-size: 0.8rem;">${u.last_location}</div>
          <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${u.last_ip}</div>
        </td>
        <td style="text-align: right;">
          ${u.status === 'QUARANTINED' ? `
            <button class="btn btn-success btn-sm" onclick="app.confirmUnquarantine('${u.id}', '${u.name}')">Restore</button>
          ` : `
            <button class="btn btn-outline btn-sm" onclick="app.stepUpMfa('${u.id}')" title="Challenge Step-up MFA">Step-Up</button>
            <button class="btn btn-danger btn-sm" onclick="app.confirmQuarantine('${u.id}', '${u.name}')">Quarantine</button>
          `}
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  async fetchAccessLogs() {
    try {
      const res = await fetch('/api/access-logs?limit=30');
      const logs = await res.json();
      this.renderAccessLogs(logs);
    } catch (err) {
      console.error('Failed to load logs:', err);
    }
  }

  renderAccessLogs(logs) {
    // Populate Overview snippet table (first 5)
    const overviewBody = document.getElementById('overview-logs-body');
    if (overviewBody) {
      overviewBody.innerHTML = '';
      logs.slice(0, 5).forEach(log => {
        const tr = document.createElement('tr');
        const timeStr = new Date(log.timestamp).toLocaleTimeString();
        tr.innerHTML = `
          <td style="font-family: var(--font-mono); font-size: 0.78rem;">${timeStr}</td>
          <td style="font-weight: 600;">${log.user_name}</td>
          <td>
            <div>${log.location}</div>
            <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${log.ip_address}</div>
          </td>
          <td style="font-size: 0.78rem; color: var(--text-secondary); max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${log.device}
          </td>
          <td>
            <span class="badge ${log.risk_score >= 60 ? 'badge-critical' : log.risk_score >= 30 ? 'badge-moderate' : 'badge-low'}">
              ${log.risk_score}
            </span>
          </td>
          <td>
            <span class="badge ${log.decision === 'GRANTED' ? 'badge-low' : log.decision === 'CHALLENGED' ? 'badge-moderate' : 'badge-critical'}">
              ${log.decision}
            </span>
          </td>
        `;
        overviewBody.appendChild(tr);
      });
    }

    // Populate Detailed Logs View
    const detailedBody = document.getElementById('detailed-logs-body');
    if (detailedBody) {
      detailedBody.innerHTML = '';
      document.getElementById('logs-count-badge').textContent = `${logs.length} Events Logged`;

      logs.forEach(log => {
        const tr = document.createElement('tr');
        const dt = new Date(log.timestamp);
        const timeStr = `${dt.toLocaleTimeString()} (${dt.toLocaleDateString()})`;

        let factorsHtml = log.risk_factors.map(f => 
          `<span style="display: inline-block; font-size: 0.72rem; background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px; margin: 2px 2px 0 0;">${f}</span>`
        ).join('');

        tr.innerHTML = `
          <td>
            <div style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-highlight);">${log.id}</div>
            <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${timeStr}</div>
          </td>
          <td style="font-weight: 600; color: #fff;">${log.user_name}</td>
          <td>
            <div style="font-size: 0.82rem;">${log.location}</div>
            <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${log.ip_address} [${log.coordinates.join(', ')}]</div>
          </td>
          <td style="font-size: 0.78rem; color: var(--text-secondary); max-width: 200px;">${log.device}</td>
          <td style="font-family: var(--font-mono); font-size: 0.8rem; color: ${log.velocity_kmh > 950 ? 'var(--cyber-crimson)' : 'var(--text-secondary)'};">
            ${log.velocity_kmh ? `${log.velocity_kmh.toLocaleString()} km/h` : '0 km/h'}
          </td>
          <td>${factorsHtml}</td>
          <td>
            <span class="badge ${log.decision === 'GRANTED' ? 'badge-low' : log.decision === 'CHALLENGED' ? 'badge-moderate' : 'badge-critical'}">
              ${log.decision}
            </span>
          </td>
        `;
        detailedBody.appendChild(tr);
      });
    }
  }

  async fetchPolicies() {
    try {
      const res = await fetch('/api/policies');
      const policies = await res.json();
      this.renderPolicies(policies);
    } catch (err) {
      console.error('Failed to load policies:', err);
    }
  }

  renderPolicies(policies) {
    const tbody = document.getElementById('policies-table-body');
    tbody.innerHTML = '';

    policies.forEach(p => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>
          <div style="font-weight: 600; color: #fff;">${p.name}</div>
          <div style="font-size: 0.78rem; color: var(--text-secondary); max-width: 500px;">${p.description}</div>
        </td>
        <td>
          <span class="badge badge-low" style="text-transform: none;">${p.category}</span>
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--cyber-cyan);">
          ${p.risk_threshold ? `Risk > ${p.risk_threshold}` : 'Condition Based'}
        </td>
        <td>
          <span class="badge ${p.action === 'Block' ? 'badge-critical' : p.action === 'Quarantine Identity' ? 'badge-critical' : 'badge-moderate'}">
            ${p.action}
          </span>
        </td>
        <td style="text-align: right;">
          <label class="toggle-switch">
            <input type="checkbox" ${p.enabled ? 'checked' : ''} onchange="app.togglePolicy('${p.id}', this.checked)">
            <span class="toggle-slider"></span>
          </label>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  async togglePolicy(policyId, enabled) {
    try {
      const res = await fetch(`/api/policies/${policyId}/toggle?enabled=${enabled}`, { method: 'POST' });
      if (res.ok) {
        this.showToast(`Zero-Trust Policy rule ${policyId} updated`, 'success');
        this.fetchDashboardStats();
      }
    } catch (err) {
      this.showToast('Failed to update policy state', 'danger');
    }
  }

  async fetchIncidents() {
    try {
      const res = await fetch('/api/incidents');
      const incidents = await res.json();
      this.renderIncidents(incidents);
    } catch (err) {
      console.error('Failed to load incidents:', err);
    }
  }

  renderIncidents(incidents) {
    const container = document.getElementById('incidents-container');
    container.innerHTML = '';
    const activeCount = incidents.filter(i => i.status === 'ACTIVE').length;
    document.getElementById('incident-counter-badge').textContent = `${activeCount} Active Incidents`;

    incidents.forEach(inc => {
      const card = document.createElement('div');
      card.className = 'cyber-panel';
      card.style.marginBottom = '0';
      card.style.borderColor = inc.status === 'RESOLVED' ? 'rgba(56, 189, 248, 0.1)' : 'var(--border-glow)';

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;">
          <div>
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
              <span class="badge ${inc.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${inc.severity}</span>
              <span style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-highlight);">${inc.id}</span>
              <span class="badge badge-low" style="background: rgba(168, 85, 247, 0.15); border-color: var(--cyber-purple); color: #c084fc;">
                MITRE ${inc.mitre_attack_id}
              </span>
            </div>
            <h3 style="font-size: 1.05rem; font-weight: 700; color: #fff; margin-bottom: 6px;">${inc.title}</h3>
            <p style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5; margin-bottom: 12px;">${inc.description}</p>
            <div style="font-size: 0.78rem; font-family: var(--font-mono); color: var(--cyber-amber);">
              <strong>Recommended SOC Action:</strong> ${inc.recommended_action}
            </div>
          </div>
          <div style="text-align: right; flex-shrink: 0;">
            <div style="margin-bottom: 10px;">
              <span class="badge ${inc.status === 'ACTIVE' ? 'badge-critical' : 'badge-low'}">${inc.status}</span>
            </div>
            ${inc.status === 'ACTIVE' ? `
              <button class="btn btn-success btn-sm" onclick="app.resolveIncident('${inc.id}')">Mark Resolved</button>
            ` : `
              <span style="font-size: 0.78rem; color: var(--text-muted); font-family: var(--font-mono);">Contained</span>
            `}
          </div>
        </div>
      `;
      container.appendChild(card);
    });
  }

  async resolveIncident(incidentId) {
    try {
      const res = await fetch(`/api/incidents/${incidentId}/resolve`, { method: 'POST' });
      if (res.ok) {
        this.showToast(`Incident ${incidentId} marked as RESOLVED`, 'success');
        this.fetchIncidents();
        this.fetchDashboardStats();
      }
    } catch (err) {
      this.showToast('Failed to resolve incident', 'danger');
    }
  }

  // --- Attack & Event Simulation Sandbox ---
  async triggerSimulation(userId, scenario) {
    this.showToast(`Dispatching ${scenario} telemetry attack simulation...`, 'warning');
    try {
      const res = await fetch('/api/access-logs/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId, scenario: scenario })
      });
      const log = await res.json();
      
      this.showToast(`Simulation Complete: Access decision was ${log.decision} (Risk Score: ${log.risk_score})`, 
        log.decision === 'GRANTED' ? 'success' : 'danger');

      // Refresh data
      await this.refreshAllData();

    } catch (err) {
      this.showToast('Simulation failed', 'danger');
    }
  }

  // --- Quarantine & Identity Actions ---
  confirmQuarantine(userId, userName) {
    this.selectedUserId = userId;
    document.getElementById('modal-title').textContent = `Quarantine Identity: ${userName}`;
    document.getElementById('modal-desc').textContent = 
      `Are you sure you want to quarantine ${userName}? This will invalidate all tokens and block all authentication attempts immediately.`;
    
    this.activeModalAction = async () => {
      try {
        const res = await fetch(`/api/identities/${userId}/quarantine`, { method: 'POST' });
        if (res.ok) {
          this.showToast(`Identity ${userName} has been QUARANTINED`, 'danger');
          this.refreshAllData();
        }
      } catch (err) {
        this.showToast('Quarantine request failed', 'danger');
      }
    };
    this.showModal();
  }

  confirmUnquarantine(userId, userName) {
    this.selectedUserId = userId;
    document.getElementById('modal-title').textContent = `Restore Identity: ${userName}`;
    document.getElementById('modal-desc').textContent = 
      `Restore normal Zero-Trust privileges for ${userName}? Identity risk score will reset to baseline.`;

    this.activeModalAction = async () => {
      try {
        const res = await fetch(`/api/identities/${userId}/unquarantine`, { method: 'POST' });
        if (res.ok) {
          this.showToast(`Identity ${userName} restored to ACTIVE`, 'success');
          this.refreshAllData();
        }
      } catch (err) {
        this.showToast('Restore request failed', 'danger');
      }
    };
    this.showModal();
  }

  async stepUpMfa(userId) {
    try {
      const res = await fetch(`/api/identities/${userId}/step-up`, { method: 'POST' });
      if (res.ok) {
        this.showToast('Step-up MFA challenge initiated for user', 'warning');
        this.refreshAllData();
      }
    } catch (err) {
      this.showToast('Step-up MFA request failed', 'danger');
    }
  }

  showModal() {
    document.getElementById('quarantine-modal').classList.add('active');
  }

  hideModal() {
    document.getElementById('quarantine-modal').classList.remove('active');
    this.activeModalAction = null;
    this.selectedUserId = null;
  }

  // --- Password Strength & Entropy Lab ---
  setupPasswordAuditor() {
    const input = document.getElementById('password-test-input');
    let debounceTimer;

    const audit = async (pwd) => {
      if (!pwd) return;
      try {
        const res = await fetch('/api/audit/password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: pwd })
        });
        const d = await res.json();
        this.renderPasswordAudit(d);
      } catch (err) {
        console.error('Password audit error:', err);
      }
    };

    input.addEventListener('input', (e) => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => audit(e.target.value), 200);
    });

    // Run initial on default value
    audit(input.value);
  }

  renderPasswordAudit(data) {
    document.getElementById('entropy-text').textContent = `Strength: ${data.strength} (${data.entropy_bits} bits)`;
    
    const badge = document.getElementById('entropy-score-badge');
    badge.textContent = `Score: ${data.score}/100`;
    
    const bar = document.getElementById('entropy-meter-bar');
    bar.style.width = `${data.score}%`;

    if (data.score <= 30) {
      bar.style.backgroundColor = 'var(--cyber-crimson)';
      badge.className = 'badge badge-critical';
    } else if (data.score <= 60) {
      bar.style.backgroundColor = 'var(--cyber-amber)';
      badge.className = 'badge badge-moderate';
    } else {
      bar.style.backgroundColor = 'var(--cyber-emerald)';
      badge.className = 'badge badge-low';
    }

    document.getElementById('metric-entropy-bits').textContent = `${data.entropy_bits} bits`;
    document.getElementById('metric-crack-time').textContent = data.estimated_crack_time;

    const breachEl = document.getElementById('metric-breach-count');
    if (data.is_compromised) {
      breachEl.textContent = `${data.breach_count.toLocaleString()} breaches (LEAKED)`;
      breachEl.style.color = 'var(--cyber-crimson)';
    } else {
      breachEl.textContent = '0 breaches (Clean)';
      breachEl.style.color = 'var(--cyber-emerald)';
    }

    const criteria = [];
    if (data.has_uppercase) criteria.push('Uppercase');
    if (data.has_lowercase) criteria.push('Lowercase');
    if (data.has_numbers) criteria.push('Numbers');
    if (data.has_special) criteria.push('Special Symbols');
    document.getElementById('metric-complexity').textContent = criteria.join(', ') || 'None';

    const feedbackList = document.getElementById('password-feedback-list');
    feedbackList.innerHTML = '';
    data.feedback.forEach(f => {
      const li = document.createElement('li');
      li.textContent = f;
      if (f.startsWith('Critical') || f.startsWith('ALERT')) {
        li.style.color = 'var(--cyber-crimson)';
      } else if (f.startsWith('Zero-Trust')) {
        li.style.color = 'var(--cyber-emerald)';
      } else {
        li.style.color = 'var(--cyber-amber)';
      }
      feedbackList.appendChild(li);
    });
  }

  // --- Corporate Domain Dark Web Scanner ---
  setupDomainScanner() {
    const btn = document.getElementById('btn-scan-domain');
    const input = document.getElementById('domain-scan-input');

    const scan = async () => {
      const query = input.value.trim();
      if (!query) return;

      btn.disabled = true;
      btn.textContent = 'Scanning Dark Web...';

      try {
        const res = await fetch('/api/audit/domain-breach', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: query })
        });
        const records = await res.json();
        this.renderDomainBreachResults(records, query);
      } catch (err) {
        this.showToast('Breach scan request failed', 'danger');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Scan Dark Web';
      }
    };

    btn.addEventListener('click', scan);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') scan();
    });

    // Run initial scan
    scan();
  }

  renderDomainBreachResults(records, query) {
    const container = document.getElementById('domain-scan-results');
    container.innerHTML = '';

    if (!records || records.length === 0) {
      container.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--cyber-emerald); border-radius: var(--radius-md); padding: 16px; text-align: center;">
          <div style="color: #6ee7b7; font-weight: 600; font-size: 0.95rem;">No Breaches Detected</div>
          <div style="color: var(--text-secondary); font-size: 0.8rem; margin-top: 4px;">
            Target "${query}" was not identified in recent public dark-web database collections.
          </div>
        </div>
      `;
      return;
    }

    container.innerHTML = `
      <div style="font-size: 0.82rem; font-family: var(--font-mono); color: var(--cyber-crimson); margin-bottom: 12px; font-weight: 600;">
        ⚠️ Found ${records.length} dark web leak exposure record(s) matching "${query}":
      </div>
    `;

    records.forEach(r => {
      const item = document.createElement('div');
      item.style.background = 'rgba(12, 18, 34, 0.7)';
      item.style.border = '1px solid rgba(239, 68, 68, 0.4)';
      item.style.borderRadius = 'var(--radius-md)';
      item.style.padding = '14px';
      item.style.marginBottom = '10px';

      item.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
          <strong style="color: #fff; font-size: 0.88rem;">${r.source}</strong>
          <span class="badge ${r.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${r.severity}</span>
        </div>
        <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); margin-bottom: 8px;">
          Detected Date: ${r.date_leaked}
        </div>
        <div style="font-size: 0.78rem; color: var(--text-secondary);">
          Compromised Data: <strong style="color: #fca5a5;">${r.compromised_data.join(', ')}</strong>
        </div>
      `;
      container.appendChild(item);
    });
  }

  // --- TOTP MFA Authenticator Simulator ---
  async setupTOTPLab() {
    await this.generateNewMFA();

    document.getElementById('btn-generate-new-mfa').addEventListener('click', () => {
      this.generateNewMFA();
    });

    document.getElementById('btn-verify-mfa-token').addEventListener('click', () => {
      this.verifyMFAToken();
    });
  }

  async generateNewMFA() {
    try {
      const res = await fetch('/api/mfa/generate');
      const data = await res.json();
      this.totpSecret = data.secret;
      this.totpRemaining = data.time_remaining;

      document.getElementById('totp-token-code').textContent = data.current_token;
      document.getElementById('totp-secret-text').textContent = `Base32 Secret: ${data.secret}`;

      this.startTOTPTimer();
    } catch (err) {
      console.error('Failed to generate MFA secret:', err);
    }
  }

  startTOTPTimer() {
    if (this.totpTimerInterval) {
      clearInterval(this.totpTimerInterval);
    }

    const ring = document.getElementById('totp-ring');
    const secondsEl = document.getElementById('totp-seconds');
    const circumference = 2 * Math.PI * 60; // r=60 -> ~377

    const tick = async () => {
      secondsEl.textContent = this.totpRemaining;
      const offset = circumference - (this.totpRemaining / 30) * circumference;
      ring.style.strokeDashoffset = offset;

      if (this.totpRemaining <= 5) {
        ring.style.stroke = 'var(--cyber-crimson)';
      } else {
        ring.style.stroke = 'var(--cyber-cyan)';
      }

      if (this.totpRemaining <= 0) {
        // Regenerate current token
        this.totpRemaining = 30;
        try {
          const res = await fetch('/api/mfa/generate');
          const data = await res.json();
          document.getElementById('totp-token-code').textContent = data.current_token;
        } catch (e) {}
      } else {
        this.totpRemaining--;
      }
    };

    tick();
    this.totpTimerInterval = setInterval(tick, 1000);
  }

  async verifyMFAToken() {
    const input = document.getElementById('verify-token-input');
    const token = input.value.trim();
    const resultBox = document.getElementById('mfa-verify-result');

    if (!token || token.length !== 6) {
      this.showToast('Please enter a valid 6-digit numeric token', 'warning');
      return;
    }

    try {
      const res = await fetch('/api/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: this.totpSecret, token: token })
      });
      const data = await res.json();

      resultBox.style.display = 'block';
      if (data.valid) {
        resultBox.style.background = 'rgba(16, 185, 129, 0.15)';
        resultBox.style.border = '1px solid var(--cyber-emerald)';
        resultBox.style.color = '#6ee7b7';
        resultBox.innerHTML = `<strong>✓ Verification Successful</strong><div style="font-size: 0.8rem; margin-top: 4px;">${data.message}</div>`;
        this.showToast('Cryptographic OTP assertion verified!', 'success');
      } else {
        resultBox.style.background = 'rgba(239, 68, 68, 0.15)';
        resultBox.style.border = '1px solid var(--cyber-crimson)';
        resultBox.style.color = '#fca5a5';
        resultBox.innerHTML = `<strong>✗ Verification Rejected</strong><div style="font-size: 0.8rem; margin-top: 4px;">${data.message}</div>`;
        this.showToast('Token rejected or expired', 'danger');
      }
    } catch (err) {
      this.showToast('Token verification request failed', 'danger');
    }
  }

  // --- Toast Notifications ---
  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="var(--cyber-emerald)" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
    } else if (type === 'danger') {
      iconSvg = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="var(--cyber-crimson)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
    } else {
      iconSvg = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="var(--cyber-amber)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
    }

    toast.innerHTML = `
      ${iconSvg}
      <span style="font-size: 0.82rem; color: #fff;">${message}</span>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(30px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
}

// Instantiate global app instance
const app = new SecureIDApp();
