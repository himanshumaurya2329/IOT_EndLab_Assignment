/**
 * IoTShield — app.js
 * Main application coordinator for split-screen security dashboard.
 */
'use strict';

class IoTShieldApp {
  constructor() {
    this._sseSource     = null;
    this._sseRetryDelay = 1000;
    this._sseMaxDelay   = 10000;
    this._sseRetryTimer = null;
    this._statusTimer   = null;
    this._clockTimer    = null;

    this._isConnected   = false;

    // Module references
    this.dashboard = null;
    this.topology  = null;
    this.charts    = null;
  }

  /* ─── Public init ──────────────────────────────────────── */
  init() {
    this._startLoadingSequence();
  }

  /* ─── Loading sequence ─────────────────────────────────── */
  _startLoadingSequence() {
    const fill   = document.getElementById('loadingFill');
    const status = document.getElementById('loadingStatus');
    const steps  = [
      [15,  'Initializing core SDN modules…'],
      [40,  'Rendering network topology…'],
      [70,  'Connecting to backend & OpenFlow stream…'],
      [100, 'Security Dashboard Ready'],
    ];

    let idx = 0;
    const advance = () => {
      if (idx >= steps.length) return;
      const [pct, msg] = steps[idx++];
      if (fill)   fill.style.width = pct + '%';
      if (status) status.textContent = msg;
      setTimeout(advance, 250);
    };
    advance();

    // Boot modules
    setTimeout(() => { this._initModules(); }, 300);

    // Connect to SSE stream
    setTimeout(() => { this._connectSSE(); }, 600);

    // Sync authoritative status and existing events
    setTimeout(() => { this._fetchStatus(); }, 750);
    setTimeout(() => { this._fetchInitialEvents(); }, 900);

    // Dismiss loading screen quickly
    setTimeout(() => { this._hideLoadingScreen(); }, 1400);
  }

  _hideLoadingScreen() {
    const screen = document.getElementById('loadingScreen');
    if (!screen) return;
    screen.classList.add('fade-out');
    setTimeout(() => screen.classList.add('hidden'), 400);
  }

  /* ─── Module bootstrap ─────────────────────────────────── */
  _initModules() {
    try {
      this.charts = new ChartsModule();
      this.charts.init();
      window.chartsModule = this.charts;
    } catch(e) { console.warn('[IoTShield] ChartsModule init failed:', e); }

    try {
      this.dashboard = new DashboardModule();
      this.dashboard.init();
      window.dashboardModule = this.dashboard;
    } catch(e) { console.warn('[IoTShield] DashboardModule init failed:', e); }

    try {
      this.topology = new TopologyModule('topologyContainer');
      this.topology.init();
      window.topologyModule = this.topology;
    } catch(e) { console.warn('[IoTShield] TopologyModule init failed:', e); }

    // Start clock & polling
    this._startClock();
    this._startStatusPolling();
  }

  /* ─── SSE connection ───────────────────────────────────── */
  _connectSSE() {
    if (this._sseSource) {
      this._sseSource.close();
      this._sseSource = null;
    }

    try {
      this._sseSource = new EventSource('/api/events/stream');
    } catch(e) {
      this._onSSEError();
      return;
    }

    this._sseSource.addEventListener('open', () => this._onSSEOpen());
    this._sseSource.addEventListener('error', () => this._onSSEError());

    // Generic messages
    this._sseSource.addEventListener('message', (e) => {
      this._handleRawEvent(e.data);
    });

    // Named OpenFlow / Security events
    const namedTypes = [
      'ARP_LEGITIMATE', 'PACKET_FORWARDED', 'ARP_SPOOFING_DETECTED', 'FLOW_RULE_INSTALLED',
      'PACKET_BLOCKED', 'SWITCH_CONNECTED', 'STATUS_UPDATE', 'RESET'
    ];
    namedTypes.forEach(type => {
      this._sseSource.addEventListener(type, (e) => {
        this._handleRawEvent(e.data, type);
      });
    });
  }

  _onSSEOpen() {
    this._isConnected   = true;
    this._sseRetryDelay = 1000;
    this._setConnectionState('connected');
    if (this._sseRetryTimer) { clearTimeout(this._sseRetryTimer); this._sseRetryTimer = null; }
  }

  _onSSEError() {
    this._isConnected = false;
    this._setConnectionState('disconnected');

    if (this._sseSource) { this._sseSource.close(); this._sseSource = null; }

    this._sseRetryTimer = setTimeout(() => {
      this._connectSSE();
    }, this._sseRetryDelay);

    this._sseRetryDelay = Math.min(this._sseRetryDelay * 1.5, this._sseMaxDelay);
  }

  /* ─── Event handling ───────────────────────────────────── */
  _handleRawEvent(raw, explicitType) {
    let evt;
    try {
      evt = JSON.parse(raw);
    } catch(e) {
      return;
    }

    if (explicitType && !evt.type) evt.type = explicitType;
    if (!evt.timestamp) evt.timestamp = new Date().toISOString();

    // Live event: isLive = true
    if (this.dashboard) this.dashboard.onEvent(evt, true);
    if (this.topology)  this.topology.onEvent(evt);
    if (this.charts)    this.charts.onEvent(evt);
  }

  /* ─── Status polling ───────────────────────────────────── */
  _startStatusPolling() {
    this._fetchStatus();
    this._statusTimer = setInterval(() => this._fetchStatus(), 4000);
  }

  async _fetchStatus() {
    try {
      const resp = await fetch('/api/status', { signal: AbortSignal.timeout(3000) });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();

      if (!this._isConnected) {
        this._isConnected = true;
        this._setConnectionState('connected');
      }

      if (this.dashboard) this.dashboard.onStatus(data);
    } catch(e) {
      // Backend temporarily busy
    }
  }

  /* ─── Fetch existing events on page load (No double counting) ── */
  async _fetchInitialEvents() {
    try {
      const resp = await fetch('/api/events?limit=100', { signal: AbortSignal.timeout(3000) });
      if (!resp.ok) return;
      const data = await resp.json();
      if (Array.isArray(data.events)) {
        if (data.events.length === 0) {
          if (this.dashboard) this.dashboard.clear();
        } else {
          // Clear table first to avoid any duplicate rendering
          if (this.dashboard) this.dashboard.clearEvents();

          // Feed historical events in chronological order (oldest to newest)
          for (const ev of data.events) {
            // isLive = false -> DOES NOT increment counters or trigger live animations!
            if (this.dashboard) this.dashboard.onEvent(ev, false);
            if (this.topology)  this.topology.onEvent(ev, false);
            if (this.charts)    this.charts.onEvent(ev, false);
          }
        }
      }
    } catch(e) {
      console.warn('[IoTShield] Failed to load initial events:', e);
    }
  }

  /* ─── Refresh button ────────────────────────────────────── */
  refresh() {
    this._fetchStatus();
    this._fetchInitialEvents();
  }

  /* ─── Reset / Clear Data ────────────────────────────────── */
  async resetLab() {
    if (!confirm('Are you sure you want to clear all security records and reset the lab?')) {
      return;
    }

    try {
      // Reset modules locally
      if (this.dashboard) this.dashboard.clear();
      if (this.topology)  this.topology.reset();
      if (this.charts)    this.charts.reset();

      // Send reset request to backend (localhost endpoint)
      await fetch('/api/reset', { method: 'POST' });
    } catch(e) {
      console.warn('[IoTShield] Reset request finished:', e);
    }

    // Resync status
    setTimeout(() => { this.refresh(); }, 500);
  }

  /* ─── Connection state UI ──────────────────────────────── */
  _setConnectionState(state) {
    const liveBadge = document.getElementById('liveBadge');
    const liveText  = document.getElementById('liveBadgeText');
    if (!liveBadge || !liveText) return;

    if (state === 'connected') {
      liveBadge.style.color = 'var(--clr-green)';
      liveBadge.style.borderColor = 'rgba(0, 255, 136, 0.3)';
      liveText.textContent = 'LIVE';
    } else {
      liveBadge.style.color = 'var(--clr-red)';
      liveBadge.style.borderColor = 'rgba(255, 51, 102, 0.3)';
      liveText.textContent = 'RECONNECTING';
    }
  }

  /* ─── Live Clock ────────────────────────────────────────── */
  _startClock() {
    const el = document.getElementById('footerClock');
    const tick = () => {
      if (el) el.textContent = 'Local Time: ' + new Date().toLocaleTimeString('en-US', { hour12: false });
    };
    tick();
    this._clockTimer = setInterval(tick, 1000);
  }
}

window.IoTShieldApp = IoTShieldApp;
