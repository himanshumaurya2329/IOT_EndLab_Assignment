/**
 * IoTShield — charts.js
 * Chart.js-based visualizations: traffic timeline + packet donut.
 */
'use strict';

class ChartsModule {
  constructor() {
    this._trafficChart = null;
    this._donutChart   = null;
    this._timeline     = [];   // last 60 seconds of data
    this._donutData    = { legitimate: 0, suspicious: 0, unknown: 0 };
    this._timelineMax  = 60;
    this._initInterval = null;
  }

  /* ─── Init ──────────────────────────────────────────────── */
  init() {
    // Wait for Chart.js CDN to be ready, then build
    if (typeof Chart !== 'undefined') {
      this._buildCharts();
    } else {
      // Retry up to 10 times
      let retries = 0;
      this._initInterval = setInterval(() => {
        if (typeof Chart !== 'undefined') {
          clearInterval(this._initInterval);
          this._buildCharts();
        } else if (++retries > 20) {
          clearInterval(this._initInterval);
          console.warn('[Charts] Chart.js not loaded');
        }
      }, 200);
    }
    console.log('[Charts] module ready');
  }

  _buildCharts() {
    Chart.defaults.color          = '#64748b';
    Chart.defaults.borderColor    = 'rgba(0,212,255,0.08)';
    Chart.defaults.font.family    = "'Inter', system-ui, sans-serif";
    Chart.defaults.font.size      = 11;

    this._buildTrafficChart();
    this._buildDonutChart();
  }

  /* ─── Traffic timeline ──────────────────────────────────── */
  _buildTrafficChart() {
    const canvas = document.getElementById('trafficChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Pre-fill 60 empty slots
    const now = Date.now();
    for (let i = this._timelineMax - 1; i >= 0; i--) {
      this._timeline.push({
        ts:          new Date(now - i * 1000).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        legitimate:  0,
        suspicious:  0,
      });
    }

    this._trafficChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels:   this._timeline.map(d => d.ts),
        datasets: [
          {
            label:           'Legitimate',
            data:            this._timeline.map(d => d.legitimate),
            borderColor:     '#00d4ff',
            backgroundColor: 'rgba(0,212,255,0.08)',
            borderWidth:     2,
            pointRadius:     0,
            tension:         0.4,
            fill:            true,
          },
          {
            label:           'Suspicious',
            data:            this._timeline.map(d => d.suspicious),
            borderColor:     '#ff3366',
            backgroundColor: 'rgba(255,51,102,0.08)',
            borderWidth:     2,
            pointRadius:     0,
            tension:         0.4,
            fill:            true,
          },
        ],
      },
      options: {
        responsive:          true,
        maintainAspectRatio: false,
        animation:           { duration: 200 },
        interaction:         { mode: 'index', intersect: false },
        plugins: {
          legend: {
            labels: {
              boxWidth:  12,
              padding:   16,
              color:     '#94a3b8',
              font:      { size: 11 },
            },
          },
          tooltip: {
            backgroundColor: '#1a2235',
            borderColor:     'rgba(0,212,255,0.3)',
            borderWidth:     1,
            padding:         10,
            titleColor:      '#e2e8f0',
            bodyColor:       '#94a3b8',
          },
        },
        scales: {
          x: {
            ticks: {
              maxTicksLimit: 8,
              color:         '#64748b',
              font:          { size: 10 },
              maxRotation:   0,
            },
            grid: { color: 'rgba(0,212,255,0.05)' },
          },
          y: {
            beginAtZero:  true,
            suggestedMax: 5,
            ticks: {
              stepSize: 1,
              color:    '#64748b',
              font:     { size: 10 },
            },
            grid: { color: 'rgba(0,212,255,0.05)' },
          },
        },
      },
    });
  }

  /* ─── Donut chart ───────────────────────────────────────── */
  _buildDonutChart() {
    const canvas = document.getElementById('donutChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    this._donutChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels:   ['Legitimate', 'Suspicious', 'Unknown'],
        datasets: [{
          data:            [0, 0, 1],
          backgroundColor: ['rgba(0,212,255,0.7)', 'rgba(255,51,102,0.7)', 'rgba(100,116,139,0.4)'],
          borderColor:     ['#00d4ff', '#ff3366', '#475569'],
          borderWidth:     1.5,
          hoverOffset:     6,
        }],
      },
      options: {
        responsive:          true,
        maintainAspectRatio: false,
        cutout:              '70%',
        animation:           { duration: 300 },
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              boxWidth: 10,
              padding:  12,
              color:    '#94a3b8',
              font:     { size: 11 },
            },
          },
          tooltip: {
            backgroundColor: '#1a2235',
            borderColor:     'rgba(0,212,255,0.3)',
            borderWidth:     1,
            padding:         10,
            titleColor:      '#e2e8f0',
            bodyColor:       '#94a3b8',
          },
        },
      },
    });
  }

  /* ─── Event handler ─────────────────────────────────────── */
  onEvent(evt, isLive = true) {
    const type = evt.type || '';
    if (type === 'RESET') {
      this.reset();
      return;
    }

    // Historical replay should not create artificial live-traffic spikes
    if (!isLive) return;

    const severity = (evt.severity || 'INFO').toUpperCase();

    const isLegit = type === 'ARP_LEGITIMATE' || (severity === 'INFO' && type !== 'SWITCH_CONNECTED' && type !== 'CONTROLLER_STARTUP');
    const isSusp  = type === 'ARP_SPOOFING_DETECTED' || severity === 'CRITICAL' || severity === 'WARNING';

    if (isLegit && !isSusp) {
      this._addTimelinePoint(1, 0);
      this._donutData.legitimate++;
    } else if (isSusp) {
      this._addTimelinePoint(0, 1);
      this._donutData.suspicious++;
    } else {
      this._donutData.unknown++;
    }

    this._updateDonut();
  }

  reset() {
    this._timeline = [];
    const now = Date.now();
    for (let i = this._timelineMax - 1; i >= 0; i--) {
      this._timeline.push({
        ts: new Date(now - i * 1000).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        legitimate: 0,
        suspicious: 0,
      });
    }
    this._donutData = { legitimate: 0, suspicious: 0, unknown: 0 };
    this._updateTrafficChart();
    this._updateDonut();
  }

  /* ─── Timeline update ───────────────────────────────────── */
  _addTimelinePoint(legit, susp) {
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // Accumulate into current second if last ts matches
    const last = this._timeline[this._timeline.length - 1];
    if (last && last.ts === ts) {
      last.legitimate += legit;
      last.suspicious += susp;
    } else {
      this._timeline.push({ ts, legitimate: legit, suspicious: susp });
    }

    // Trim to window
    while (this._timeline.length > this._timelineMax) this._timeline.shift();

    this._updateTrafficChart();
  }

  _updateTrafficChart() {
    if (!this._trafficChart) return;
    this._trafficChart.data.labels          = this._timeline.map(d => d.ts);
    this._trafficChart.data.datasets[0].data = this._timeline.map(d => d.legitimate);
    this._trafficChart.data.datasets[1].data = this._timeline.map(d => d.suspicious);
    this._trafficChart.update('none');
  }

  _updateDonut() {
    if (!this._donutChart) return;
    const d = this._donutData;
    const total = d.legitimate + d.suspicious + d.unknown;
    this._donutChart.data.datasets[0].data = total > 0
      ? [d.legitimate, d.suspicious, d.unknown]
      : [0, 0, 1];
    this._donutChart.update('none');
  }
}

window.ChartsModule = ChartsModule;
