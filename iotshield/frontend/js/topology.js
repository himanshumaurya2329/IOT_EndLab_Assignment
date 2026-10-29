/**
 * IoTShield — topology.js
 * SVG-based network topology with packet animations.
 */
'use strict';

class TopologyModule {
  constructor(containerId) {
    this._containerId = containerId;
    this._svg         = null;
    this._nodes       = {};   // id → { el, cx, cy, role, state }
    this._links       = [];   // { from, to, el }
    this._packetId    = 0;
    this._logEntries  = [];
  }

  /* ─── Init ──────────────────────────────────────────────── */
  init() {
    this._buildSVG();
    console.log('[Topology] module ready');
  }

  onTabActive() {
    // Re-render if needed
    if (!this._svg) this._buildSVG();
  }

  /* ─── SVG layout ─────────────────────────────────────────── */
  _buildSVG() {
    const container = document.getElementById(this._containerId);
    if (!container) return;

    // Clear loading placeholder
    container.innerHTML = '';

    const W = 800, H = 460;

    const svgNS = 'http://www.w3.org/2000/svg';
    const svg   = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('class', 'topo-svg');
    svg.style.maxWidth = '100%';
    this._svg = svg;

    // ── Background grid ────────────────────────────────────
    const defs = document.createElementNS(svgNS, 'defs');
    const pattern = document.createElementNS(svgNS, 'pattern');
    pattern.setAttribute('id', 'grid');
    pattern.setAttribute('width', '40');
    pattern.setAttribute('height', '40');
    pattern.setAttribute('patternUnits', 'userSpaceOnUse');
    const gridLine1 = document.createElementNS(svgNS, 'path');
    gridLine1.setAttribute('d', 'M 40 0 L 0 0 0 40');
    gridLine1.setAttribute('fill', 'none');
    gridLine1.setAttribute('stroke', 'rgba(0,212,255,0.06)');
    gridLine1.setAttribute('stroke-width', '1');
    pattern.appendChild(gridLine1);
    defs.appendChild(pattern);

    // Arrow marker
    const marker = document.createElementNS(svgNS, 'marker');
    marker.setAttribute('id', 'arrow');
    marker.setAttribute('markerWidth', '8');
    marker.setAttribute('markerHeight', '8');
    marker.setAttribute('refX', '6');
    marker.setAttribute('refY', '3');
    marker.setAttribute('orient', 'auto');
    const arrowPath = document.createElementNS(svgNS, 'path');
    arrowPath.setAttribute('d', 'M0,0 L0,6 L8,3 z');
    arrowPath.setAttribute('fill', 'rgba(0,212,255,0.6)');
    marker.appendChild(arrowPath);
    defs.appendChild(marker);

    svg.appendChild(defs);

    const bg = document.createElementNS(svgNS, 'rect');
    bg.setAttribute('width', W);
    bg.setAttribute('height', H);
    bg.setAttribute('fill', 'url(#grid)');
    svg.appendChild(bg);

    // ── Node positions ─────────────────────────────────────
    const positions = {
      ryu: { cx: 400, cy: 60,  role: 'controller', label: 'Ryu Controller', icon: '⚙', color: '#00ff88' },
      s1:  { cx: 400, cy: 220, role: 'switch',      label: 'OVS Switch s1',  icon: '⊞', color: '#00d4ff' },
      h1:  { cx: 120, cy: 360, role: 'host',        label: 'h1 (victim)',    icon: '⬡', color: '#00d4ff' },
      h2:  { cx: 680, cy: 360, role: 'host',        label: 'h2 (server)',    icon: '⬡', color: '#00d4ff' },
      // h3 starts cyan (normal); turns red only when attack is detected
      h3:  { cx: 400, cy: 400, role: 'attacker',    label: 'h3 (attacker)',  icon: '⬡', color: '#00d4ff' },
    };
    // ── Links ──────────────────────────────────────────────
    const linkDefs = [
      { from: 'ryu', to: 's1', dashed: true  },
      { from: 's1',  to: 'h1', dashed: false },
      { from: 's1',  to: 'h2', dashed: false },
      { from: 's1',  to: 'h3', dashed: false },
    ];

    this._links = [];
    linkDefs.forEach(ld => {
      const a  = positions[ld.from];
      const b  = positions[ld.to];
      const el = document.createElementNS(svgNS, 'line');
      el.setAttribute('x1', a.cx); el.setAttribute('y1', a.cy);
      el.setAttribute('x2', b.cx); el.setAttribute('y2', b.cy);
      el.setAttribute('class', 'topo-link');
      if (ld.dashed) el.setAttribute('stroke-dasharray', '6 4');
      el.setAttribute('id', `link-${ld.from}-${ld.to}`);
      svg.appendChild(el);
      this._links.push({ from: ld.from, to: ld.to, el });
    });

    // ── Nodes ──────────────────────────────────────────────
    this._nodes = {};
    Object.entries(positions).forEach(([id, cfg]) => {
      const g = document.createElementNS(svgNS, 'g');
      g.setAttribute('id', 'node-' + id);
      g.setAttribute('class', 'topo-node');
      g.style.cursor = 'default';

      const R = cfg.role === 'controller' ? 36 : cfg.role === 'switch' ? 32 : 28;

      // Outer glow circle
      const glow = document.createElementNS(svgNS, 'circle');
      glow.setAttribute('cx', cfg.cx); glow.setAttribute('cy', cfg.cy);
      glow.setAttribute('r', R + 6);
      glow.setAttribute('class', 'topo-node__glow');
      glow.setAttribute('fill', cfg.color);
      glow.setAttribute('opacity', '0.07');
      g.appendChild(glow);

      // Main circle
      const circle = document.createElementNS(svgNS, 'circle');
      circle.setAttribute('cx', cfg.cx); circle.setAttribute('cy', cfg.cy);
      circle.setAttribute('r', R);
      circle.setAttribute('class', 'topo-node__circle');
      circle.setAttribute('fill', '#111827');
      circle.setAttribute('stroke', cfg.color);
      circle.setAttribute('stroke-width', '2');
      circle.style.filter = `drop-shadow(0 0 6px ${cfg.color}40)`;
      g.appendChild(circle);

      // Role label inside node (short text)
      const roleLabel = document.createElementNS(svgNS, 'text');
      roleLabel.setAttribute('x', cfg.cx);
      roleLabel.setAttribute('y', cfg.cy + 1);
      roleLabel.setAttribute('text-anchor', 'middle');
      roleLabel.setAttribute('dominant-baseline', 'middle');
      roleLabel.setAttribute('class', 'topo-node__text');
      roleLabel.setAttribute('fill', cfg.color);
      roleLabel.setAttribute('font-family', 'monospace');
      roleLabel.setAttribute('font-size', cfg.role === 'controller' ? '14' : '12');
      roleLabel.setAttribute('font-weight', 'bold');
      roleLabel.textContent = id.toUpperCase();
      g.appendChild(roleLabel);

      // Bottom label
      const label = document.createElementNS(svgNS, 'text');
      label.setAttribute('x', cfg.cx);
      label.setAttribute('y', cfg.cy + R + 14);
      label.setAttribute('class', 'topo-node__label');
      label.setAttribute('fill', '#94a3b8');
      label.setAttribute('font-size', '10');
      label.setAttribute('font-family', 'monospace');
      label.textContent = cfg.label;
      g.appendChild(label);

      // Attacker badge
      if (cfg.role === 'attacker') {
        const badge = document.createElementNS(svgNS, 'text');
        badge.setAttribute('x', cfg.cx);
        badge.setAttribute('y', cfg.cy - R - 6);
        badge.setAttribute('text-anchor', 'middle');
        badge.setAttribute('fill', '#ff3366');
        badge.setAttribute('font-size', '9');
        badge.setAttribute('font-weight', 'bold');
        badge.setAttribute('font-family', 'sans-serif');
        badge.setAttribute('id', 'badge-attacker');
        badge.style.display = 'none';
        badge.textContent = '⚠ ATTACKER';
        g.appendChild(badge);
      }

      // Rule badge on switch
      if (id === 's1') {
        const ruleBadge = document.createElementNS(svgNS, 'text');
        ruleBadge.setAttribute('x', cfg.cx + R + 8);
        ruleBadge.setAttribute('y', cfg.cy - 10);
        ruleBadge.setAttribute('fill', '#ffaa00');
        ruleBadge.setAttribute('font-size', '9');
        ruleBadge.setAttribute('font-weight', 'bold');
        ruleBadge.setAttribute('font-family', 'sans-serif');
        ruleBadge.setAttribute('id', 'badge-rule');
        ruleBadge.style.display = 'none';
        ruleBadge.textContent = '📋 RULE INSTALLED';
        g.appendChild(ruleBadge);
      }

      svg.appendChild(g);
      this._nodes[id] = { el: g, cx: cfg.cx, cy: cfg.cy, role: cfg.role, state: 'normal', R };
    });

    container.appendChild(svg);
  }

  /* ─── Event handler ─────────────────────────────────────── */
  onEvent(evt, isLive = true) {
    const type = evt.type || '';

    if (type === 'RESET') {
      this.reset();
      return;
    }

    if (!isLive) {
      // Replaying historical event on load: only restore persistent node state, no animation
      if (type === 'ARP_SPOOFING_DETECTED') {
        this._setNodeState('h3', 'attacker');
        const badge = document.getElementById('badge-attacker');
        if (badge) badge.style.display = 'block';
      } else if (type === 'FLOW_RULE_INSTALLED') {
        const ruleBadge = document.getElementById('badge-rule');
        if (ruleBadge) ruleBadge.style.display = 'block';
      }
      return;
    }

    switch (type) {
      case 'PACKET_FORWARDED':
      case 'ARP_LEGITIMATE':
        this._onLegitimate(evt);
        break;
      case 'ARP_SPOOFING_DETECTED':
        this._onSpoofing(evt);
        break;
      case 'FLOW_RULE_INSTALLED':
        this._onFlowRule(evt);
        break;
      case 'PACKET_BLOCKED':
        this._onPacketBlocked(evt);
        break;
    }
  }

  reset() {
    this._setNodeState('h1', 'normal');
    this._setNodeState('h2', 'normal');
    this._setNodeState('h3', 'normal');
    const badge = document.getElementById('badge-attacker');
    if (badge) badge.style.display = 'none';
    const ruleBadge = document.getElementById('badge-rule');
    if (ruleBadge) ruleBadge.style.display = 'none';
    this._highlightLink('h3', 's1', null);
    this._highlightLink('s1', 'ryu', null);
  }

  _onLegitimate(evt) {
    const ipMap = { '10.0.0.1': 'h1', '10.0.0.2': 'h2', '10.0.0.3': 'h3' };
    const src = ipMap[evt.src_ip] || 'h1';
    const dst = ipMap[evt.dst_ip] || 'h2';
    const label = evt.protocol || 'SAFE';

    this._topoLog('info', `Legitimate ${label}: ${src} → s1 → ${dst}`);
    this.animatePacket(src, 's1', '#00ff88', label);
    setTimeout(() => this.animatePacket('s1', dst, '#00ff88', label), 450);
    this._setNodeState(src, 'normal');
    this._setNodeState(dst, 'normal');
  }

  _onSpoofing(evt) {
    this._topoLog('critical', 'ARP SPOOFING DETECTED: h3 → s1 (blocked)');

    // Mark h3 as attacker
    this._setNodeState('h3', 'attacker');
    const badge = document.getElementById('badge-attacker');
    if (badge) badge.style.display = 'block';

    // Red packet h3 → s1
    this.animatePacket('h3', 's1', '#ff3366', 'SPOOF');

    // After packet arrives: show blocked X + mitigation
    setTimeout(() => {
      this._showBlockedAt('s1');
      this._topoLog('warning', 'Mitigation: s1 → Ryu Controller (flow install)');
      setTimeout(() => {
        this.animatePacket('s1', 'ryu', '#00d4ff', 'MITIGATE');
        this._highlightLink('s1', 'ryu', '#00d4ff');
      }, 400);
    }, 900);

    // Highlight attack link
    this._highlightLink('h3', 's1', '#ff3366');
    setTimeout(() => this._highlightLink('h3', 's1', null), 4000);
  }

  _onFlowRule(evt) {
    this._topoLog('success', 'Flow rule installed on s1');
    const badge = document.getElementById('badge-rule');
    if (badge) {
      badge.style.display = 'block';
      setTimeout(() => { badge.style.display = 'none'; }, 5000);
    }
    this.animatePacket('ryu', 's1', '#ffaa00', 'RULE');
  }

  _onPacketBlocked(evt) {
    this._topoLog('warning', 'Packet BLOCKED at s1');
    this.animatePacket('h3', 's1', '#ff3366', 'DROP');
    setTimeout(() => this._showBlockedAt('s1'), 700);
  }

  /* ─── Packet animation ──────────────────────────────────── */
  animatePacket(fromId, toId, color, label) {
    if (!this._svg) return;
    const a = this._nodes[fromId];
    const b = this._nodes[toId];
    if (!a || !b) return;

    const svgNS = 'http://www.w3.org/2000/svg';
    const pid   = ++this._packetId;

    // Animated circle
    const circle = document.createElementNS(svgNS, 'circle');
    circle.setAttribute('r', '5');
    circle.setAttribute('fill', color);
    circle.style.filter = `drop-shadow(0 0 5px ${color})`;

    // Calculate midpoint for label placement
    const mx = (a.cx + b.cx) / 2;
    const my = (a.cy + b.cy) / 2;

    // Animate with animateMotion
    const animMotion = document.createElementNS(svgNS, 'animateMotion');
    animMotion.setAttribute('dur', '0.75s');
    animMotion.setAttribute('repeatCount', '1');
    animMotion.setAttribute('fill', 'freeze');
    animMotion.setAttribute('calcMode', 'spline');
    animMotion.setAttribute('keySplines', '0.4 0 0.2 1');
    const mpath = document.createElementNS(svgNS, 'mpath');
    // Use a path element
    const pathEl = document.createElementNS(svgNS, 'path');
    const pathId = `pkt-path-${pid}`;
    pathEl.setAttribute('id', pathId);
    pathEl.setAttribute('d', `M${a.cx},${a.cy} L${b.cx},${b.cy}`);
    pathEl.setAttribute('fill', 'none');
    pathEl.setAttribute('stroke', 'none');
    this._svg.appendChild(pathEl);
    mpath.setAttributeNS('http://www.w3.org/1999/xlink', 'href', '#' + pathId);
    animMotion.appendChild(mpath);
    circle.appendChild(animMotion);

    // Label text
    const txt = document.createElementNS(svgNS, 'text');
    txt.setAttribute('x', mx);
    txt.setAttribute('y', my - 10);
    txt.setAttribute('text-anchor', 'middle');
    txt.setAttribute('fill', color);
    txt.setAttribute('font-size', '9');
    txt.setAttribute('font-family', 'monospace');
    txt.setAttribute('font-weight', 'bold');
    txt.setAttribute('opacity', '0.85');
    txt.textContent = label || '';

    this._svg.appendChild(circle);
    this._svg.appendChild(txt);

    // Cleanup after animation
    setTimeout(() => {
      try { this._svg.removeChild(circle); } catch(e) {}
      try { this._svg.removeChild(txt); }    catch(e) {}
      try { this._svg.removeChild(pathEl); } catch(e) {}
    }, 900);
  }

  /* ─── Show blocked X ────────────────────────────────────── */
  _showBlockedAt(nodeId) {
    const node = this._nodes[nodeId];
    if (!node || !this._svg) return;

    const svgNS = 'http://www.w3.org/2000/svg';
    const txt = document.createElementNS(svgNS, 'text');
    txt.setAttribute('x', node.cx);
    txt.setAttribute('y', node.cy - node.R - 20);
    txt.setAttribute('text-anchor', 'middle');
    txt.setAttribute('fill', '#ff3366');
    txt.setAttribute('font-size', '20');
    txt.setAttribute('font-weight', 'bold');
    txt.textContent = '✕';
    txt.style.filter = 'drop-shadow(0 0 6px #ff3366)';
    this._svg.appendChild(txt);
    setTimeout(() => { try { this._svg.removeChild(txt); } catch(e) {} }, 1200);
  }

  /* ─── Link highlight ────────────────────────────────────── */
  _highlightLink(fromId, toId, color) {
    const key   = `link-${fromId}-${toId}`;
    const altKey= `link-${toId}-${fromId}`;
    const el    = document.getElementById(key) || document.getElementById(altKey);
    if (!el) return;
    if (color) {
      el.setAttribute('stroke', color);
      el.setAttribute('stroke-width', '3');
      el.style.filter = `drop-shadow(0 0 6px ${color})`;
    } else {
      el.setAttribute('stroke', 'var(--clr-surface-3, #1e2a3a)');
      el.setAttribute('stroke-width', '2');
      el.style.filter = 'none';
    }
  }

  /* ─── Node state ────────────────────────────────────────── */
  _setNodeState(nodeId, state) {
    const node = this._nodes[nodeId];
    if (!node) return;
    node.state = state;

    const circle = node.el.querySelector('circle.topo-node__circle');
    const glow   = node.el.querySelector('circle.topo-node__glow');
    const text   = node.el.querySelector('text.topo-node__text');

    const colorMap = { normal: '#00d4ff', attacker: '#ff3366', quarantine: '#ffaa00' };
    const shadowMap= { normal: '#00d4ff40', attacker: '#ff336640', quarantine: '#ffaa0040' };
    const color    = colorMap[state] || '#00d4ff';

    if (circle) {
      circle.setAttribute('stroke', color);
      circle.setAttribute('stroke-width', state === 'attacker' ? '2.5' : '2');
      circle.style.filter = `drop-shadow(0 0 8px ${shadowMap[state] || color + '40'})`;
    }
    if (glow) {
      glow.setAttribute('fill', color);
    }
    if (text) {
      text.setAttribute('fill', color);
    }

    node.el.className.baseVal =
      'topo-node' +
      (state === 'attacker'  ? ' topo-node--attacker'  : '') +
      (state === 'quarantine'? ' topo-node--quarantine' : '');
  }

  /* ─── Topology log ──────────────────────────────────────── */
  _topoLog(level, msg) {
    const container = document.getElementById('topologyLog');
    if (!container) return;

    const ts   = new Date().toLocaleTimeString('en-US', { hour12: false });
    const entry= document.createElement('div');
    entry.className = `tlog-entry tlog-entry--${level}`;
    entry.innerHTML = `<span class="tlog-time">${ts}</span><span>${this._esc(msg)}</span>`;

    // Remove placeholder
    const placeholder = container.querySelector('.tlog-entry:only-child');
    if (placeholder && placeholder.querySelector('span:last-child')?.textContent.includes('Waiting')) {
      placeholder.remove();
    }

    container.insertBefore(entry, container.firstChild);

    // Trim
    while (container.children.length > 30) container.removeChild(container.lastChild);
  }

  _esc(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
}

window.TopologyModule = TopologyModule;
