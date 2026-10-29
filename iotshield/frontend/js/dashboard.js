/**
 * IoTShield — dashboard.js
 * Dashboard module: status cards, event feed, overlays.
 */
'use strict';

class DashboardModule {
  constructor() {
    this._counters = {
      arpInspected: 0,
      suspicious:   0,
      blocked:      0,
      dropRules:    0,
    };
    this._events        = [];      // max 100
    this._attackCount   = 0;
    this._latencies     = [];      // track detection latency samples
    this._overlayTimer  = null;
  }

  /* ─── Init ──────────────────────────────────────────────── */
  init() {
    this._render();
    console.log('[Dashboard] module ready');
  }

  _render() {
    this._updateCards();
  }

  /* ─── Status update (from /api/status polling) ──────────── */
  onStatus(data) {
    if (!data) return;

    // Network / controller status
    this._setNetworkStatus(data.network_status || 'healthy');
    this._setControllerStatus(data.controller_status || 'Online');

    // Authoritative counters directly from backend
    if (typeof data.arp_inspected === 'number') this._counters.arpInspected = data.arp_inspected;
    if (typeof data.suspicious    === 'number') this._counters.suspicious   = data.suspicious;
    if (typeof data.blocked       === 'number') this._counters.blocked      = data.blocked;
    if (typeof data.drop_rules    === 'number') this._counters.dropRules    = data.drop_rules;

    if (typeof data.detection_latency_ms === 'number') {
      this._setEl('stat-latency', data.detection_latency_ms.toFixed(1) + ' ms');
    } else {
      this._setEl('stat-latency', '—');
    }

    if (typeof data.prevention_rate === 'number') {
      this._setEl('stat-preventionRate', data.prevention_rate.toFixed(1) + '%');
    } else {
      this._setEl('stat-preventionRate', '100%');
    }

    this._updateCards();
  }

  /* ─── Live event handler ────────────────────────────────── */
  onEvent(evt, isLive = true) {
    const type = evt.type || 'UNKNOWN';

    if (type === 'RESET') {
      this.clear();
      return;
    }

    // Always add event row to the table
    this._addEventRow(evt);

    // CRITICAL: If NOT a live event (loading past history on page load/refresh),
    // DO NOT touch counters! Counters are set authoritatively by onStatus()!
    if (!isLive) {
      return;
    }

    const severity = (evt.severity || 'INFO').toUpperCase();

    // Live packet counter
    if (type === 'ARP_LEGITIMATE' || type === 'PACKET_FORWARDED' || type === 'ARP_SPOOFING_DETECTED' || type === 'ARP_UNKNOWN_SENDER' || type === 'PACKET_BLOCKED') {
      this._counters.arpInspected++;
    }

    if (severity === 'CRITICAL' || type === 'ARP_SPOOFING_DETECTED') {
      this._counters.suspicious++;
      this._counters.blocked++;
      this._attackCount++;
      this._showAttackOverlay();
      this._setNetworkStatus('attack');

      // Update Host Table status for h3 in real time
      const h3Status = document.getElementById('hostStatus-h3');
      if (h3Status) {
        h3Status.innerHTML = '<span class="badge badge--red"><i class="fa-solid fa-ban"></i> QUARANTINED (Drop Rule)</span>';
      }
    } else if (severity === 'WARNING') {
      this._counters.suspicious++;
    }

    if (type === 'FLOW_RULE_INSTALLED') {
      this._counters.dropRules++;
    }

    // Latency sample from event
    const lat = evt.detection_latency_ms || evt.latency_ms;
    if (typeof lat === 'number') {
      this._latencies.push(lat);
      if (this._latencies.length > 50) this._latencies.shift();
      const avg = this._latencies.reduce((a, b) => a + b, 0) / this._latencies.length;
      this._setEl('stat-latency', avg.toFixed(1) + ' ms');
    }

    this._updateCards();
  }

  /* ─── Status cards ──────────────────────────────────────── */
  _updateCards() {
    this._setEl('stat-arpInspected', (this._counters.arpInspected || 0).toLocaleString());
    this._setEl('stat-suspicious',   (this._counters.suspicious || 0).toLocaleString());
    this._setEl('stat-blocked',      (this._counters.blocked || 0).toLocaleString());
  }

  _setNetworkStatus(state) {
    const el = document.getElementById('stat-networkStatus');
    if (!el) return;
    if (state === 'attack') {
      el.innerHTML = '<span class="badge badge--red"><i class="fa-solid fa-triangle-exclamation"></i> Under Attack</span>';
    } else {
      el.innerHTML = '<span class="badge badge--green"><i class="fa-solid fa-circle-check"></i> System Healthy</span>';
    }
  }

  _setControllerStatus(status) {
    const el = document.getElementById('stat-controllerStatus');
    if (!el) return;
    const lower = String(status).toLowerCase();
    if (lower.includes('online') || lower.includes('connected') || lower.includes('active') || lower.includes('running')) {
      el.innerHTML = `<span class="badge badge--green"><i class="fa-solid fa-microchip"></i> Controller: Online (OF 1.3)</span>`;
    } else {
      el.innerHTML = `<span class="badge badge--amber"><i class="fa-solid fa-clock"></i> Controller: ${status}</span>`;
    }
  }

  /* ─── Event table ───────────────────────────────────────── */
  _addEventRow(evt) {
    const tbody = document.getElementById('eventsTableBody');
    const empty = document.getElementById('tableEmptyRow');
    if (!tbody) return;

    if (empty) empty.style.display = 'none';

    this._events.unshift(evt);
    if (this._events.length > 100) this._events.pop();

    const severity = (evt.severity || 'INFO').toUpperCase();
    const type     = evt.type     || 'UNKNOWN';

    const badgeType = this._typeBadge(type);
    const ts        = this._formatTimestamp(evt.timestamp);
    const targetOrReason = evt.reason || (evt.dst_ip ? `Target: ${evt.dst_ip}` : (evt.message || '—'));

    const tr = document.createElement('tr');
    tr.className = severity === 'CRITICAL' ? 'event-row--critical' : '';
    tr.innerHTML = `
      <td>${badgeType}</td>
      <td><code>${this._esc(evt.src_ip  || evt.source_ip  || '—')}</code></td>
      <td><code>${this._esc(evt.src_mac || evt.source_mac || '—')}</code></td>
      <td class="cell-reason" title="${this._esc(targetOrReason)}">${this._esc(targetOrReason)}</td>
      <td>${this._actionBadge(evt.action || '—')}</td>
      <td style="color:var(--clr-text-muted);font-size:10.5px;">${this._esc(ts)}</td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);

    // Trim to 100
    while (tbody.rows.length > 100) tbody.deleteRow(tbody.rows.length - 1);

    // Update count badge
    const countEl = document.getElementById('eventCount');
    if (countEl) countEl.textContent = this._events.length + ' event' + (this._events.length !== 1 ? 's' : '');
  }

  clear() {
    this._counters = {
      arpInspected: 0,
      suspicious:   0,
      blocked:      0,
      dropRules:    0,
    };
    this._latencies = [];
    this._attackCount = 0;
    this._setEl('stat-latency', '—');
    this._setEl('stat-preventionRate', '100%');
    this._setNetworkStatus('healthy');
    this._updateCards();
    this.clearEvents();

    const h3Status = document.getElementById('hostStatus-h3');
    if (h3Status) {
      h3Status.innerHTML = '<span class="badge badge--gray">NORMAL</span>';
    }
  }

  clearEvents() {
    this._events = [];
    const tbody = document.getElementById('eventsTableBody');
    if (!tbody) return;
    tbody.innerHTML = `
      <tr class="table-empty-row" id="tableEmptyRow">
        <td colspan="6">
          <div class="table-empty">
            <i class="fa-solid fa-satellite-dish"></i>
            <span>Listening for OpenFlow events... No traffic logged yet.</span>
          </div>
        </td>
      </tr>`;
    const countEl = document.getElementById('eventCount');
    if (countEl) countEl.textContent = '0 events';
  }

  /* ─── Attack notification toast (Quick 1.2s non-blocking) ── */
  _showAttackOverlay() {
    const overlay = document.getElementById('attackOverlay');
    if (!overlay) return;

    overlay.classList.remove('hidden');

    if (this._overlayTimer) clearTimeout(this._overlayTimer);
    // User requested short duration for smooth detection to prevention animation
    this._overlayTimer = setTimeout(() => {
      overlay.classList.add('hidden');
    }, 1200);
  }

  /* ─── Badge helpers ─────────────────────────────────────── */
  _typeBadge(type) {
    const map = {
      PACKET_FORWARDED:     `<span class="badge badge--green"><i class="fa-solid fa-arrow-right-arrow-left"></i> Safe ICMP</span>`,
      ARP_LEGITIMATE:       `<span class="badge badge--green"><i class="fa-solid fa-circle-check"></i> ARP Legit</span>`,
      ARP_SPOOFING_DETECTED:`<span class="badge badge--red"><i class="fa-solid fa-skull-crossbones"></i> ARP Spoof</span>`,
      FLOW_RULE_INSTALLED:  `<span class="badge badge--amber"><i class="fa-solid fa-shield"></i> Flow Rule</span>`,
      PACKET_BLOCKED:       `<span class="badge badge--red"><i class="fa-solid fa-ban"></i> Blocked</span>`,
      SWITCH_CONNECTED:     `<span class="badge badge--blue"><i class="fa-solid fa-plug"></i> Switch OVS</span>`,
      CONTROLLER_STARTUP:   `<span class="badge badge--purple"><i class="fa-solid fa-microchip"></i> Controller</span>`,
    };
    return map[type] || `<span class="badge badge--gray">${this._esc(type)}</span>`;
  }

  _actionBadge(action) {
    const a = (action || '').toUpperCase();
    if (a === 'ALLOW' || a === 'PERMIT')
      return `<span class="badge badge--green">ALLOW</span>`;
    if (a.includes('DROP') || a.includes('BLOCK'))
      return `<span class="badge badge--red">DROP &amp; ISOLATE</span>`;
    return `<span class="badge badge--gray">${this._esc(action)}</span>`;
  }

  /* ─── Utilities ─────────────────────────────────────────── */
  _setEl(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  _esc(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  _formatTimestamp(iso) {
    try {
      const d = new Date(iso);
      if (isNaN(d)) return iso || '—';
      return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return iso || '—'; }
  }
}

window.DashboardModule = DashboardModule;
