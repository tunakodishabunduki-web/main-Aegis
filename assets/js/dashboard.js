/* Aegis dashboard — extracted from dashboard.php */
/* ----------------------------------------------------------
   MOBILE SIDEBAR TOGGLE (hamburger) -- same open/close/overlay/
   Escape pattern as SIMAP's config/sidebar.php, so navigating
   between the two systems on a phone feels consistent.
   ---------------------------------------------------------- */
(function () {
    var toggleBtn = document.getElementById('aegisSidebarToggle');
    var sidebar   = document.getElementById('aegisSidebar');
    var overlay   = document.getElementById('aegisSidebarOverlay');
    if (!toggleBtn || !sidebar || !overlay) return;

    function openMenu() {
        sidebar.classList.add('open');
        overlay.classList.add('open');
        toggleBtn.setAttribute('aria-expanded', 'true');
    }
    function closeMenu() {
        sidebar.classList.remove('open');
        overlay.classList.remove('open');
        toggleBtn.setAttribute('aria-expanded', 'false');
    }
    toggleBtn.addEventListener('click', function () {
        sidebar.classList.contains('open') ? closeMenu() : openMenu();
    });
    overlay.addEventListener('click', closeMenu);
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closeMenu();
    });
    sidebar.querySelectorAll('a').forEach(function (link) {
        link.addEventListener('click', closeMenu);
    });
})();

/* ----------------------------------------------------------
   HELPERS
   ---------------------------------------------------------- */
const fmt   = n => Number(n).toLocaleString();
const sevLbl = s => s>=80?'Critical':s>=50?'High':s>=25?'Moderate':'Low';
const sevCol  = s => s>=80?'var(--red)':s>=50?'var(--amber)':s>=25?'var(--blue)':'var(--green)';
const sevBadge= s => s>=80?'sev-c':s>=50?'sev-h':s>=25?'sev-m':'sev-l';
const FLAGS = {Tanzania:'TZ',Kenya:'KE',Nigeria:'NG',Uganda:'UG','South Africa':'ZA'};
const flag  = c => FLAGS[c] ? `<span title="${c}">&#127462;</span>` : '🏳';

let allAttackers = [];

/* ----------------------------------------------------------
   METRICS
   ---------------------------------------------------------- */
async function loadSummary() {
    const r = await fetch('api/summary.php');
    if (!r.ok) return;
    const d = await r.json();

    const cards = [
        { label:'Attacks Blocked',       val: fmt(d.total_events),           delta:'+8.2%', up:true,  dark:true },
        { label:'Active Threats',         val: fmt(d.active_threats),         delta:'+1.3%', up:false },
        { label:'Sites Protected',        val: fmt(d.sites_count),            delta:'Stable',up:true  },
        { label:'Credentials Captured',   val: fmt(d.credentials_captured),   delta:'+4.6%', up:true  },
    ];

    document.getElementById('metric-cards').innerHTML = cards.map(c => `
        <div class="metric-card${c.dark?' metric-dark':''}">
            <div class="metric-top">
                <span class="metric-label">${c.label}</span>
                <span class="metric-arrow">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="${c.dark?'#fff':'currentColor'}" stroke-width="2" aria-hidden="true"><path d="M7 17 17 7M8 7h9v9"/></svg>
                </span>
            </div>
            <div class="metric-val">${c.val}</div>
            <div class="metric-delta" style="color:${c.up?'var(--green)':'var(--red)'}">
                ${c.up?'&#8599;':'&#8600;'} ${c.delta} from last week
            </div>
        </div>
    `).join('');

    renderBarChart(d.by_day || []);
    renderOrigins(d.origins || []);
}

/* ----------------------------------------------------------
   BAR CHART
   ---------------------------------------------------------- */
function renderBarChart(data) {
    if (!data.length) { document.getElementById('bar-chart').innerHTML = '<div class="loading">No data</div>'; return; }
    const max = Math.max(...data.map(d => +d.count));
    const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

    document.getElementById('bar-chart').innerHTML = data.map(d => {
        const pct = max > 0 ? Math.round((+d.count / max) * 140) : 0;
        const isMax = +d.count === max;
        const dt  = new Date(d.day);
        const lbl = days[dt.getUTCDay()];
        return `<div class="bar-col">
            ${isMax ? `<div class="bar-tip">${d.count}</div>` : ''}
            <div class="bar" style="height:${Math.max(pct,6)}px;background:${isMax?'var(--blue)':'var(--dark)'}"></div>
            <div class="bar-lbl">${lbl}</div>
        </div>`;
    }).join('');
}

/* ----------------------------------------------------------
   ORIGINS
   ---------------------------------------------------------- */
function renderOrigins(origins) {
    const total = origins.reduce((s,o) => s + +o.count, 0) || 1;
    document.getElementById('origin-badge').textContent = fmt(total) + ' events tracked';

    const map = document.getElementById('origin-map');
    origins.forEach((o, i) => {
        const pct  = o.count / total;
        const size = Math.round(14 + pct * 50);
        const dot  = document.createElement('div');
        dot.className = 'dist-dot';
        dot.style.cssText = `width:${size}px;height:${size}px;left:${20 + i*22}%;top:${28+(i%2)*30}%`;
        map.appendChild(dot);
    });

    document.getElementById('origin-list').innerHTML = origins.map(o => `
        <div class="origin-row">
            <div class="origin-left"><span>${flag(o.country)}</span> ${htmlEsc(o.country)}</div>
            <span class="origin-pct">${Math.round((+o.count/total)*100)}%</span>
        </div>
    `).join('');
}

/* ----------------------------------------------------------
   ATTACKERS TABLE
   ---------------------------------------------------------- */
async function loadAttackers() {
    const r = await fetch('api/attackers.php');
    if (!r.ok) return;
    const d = await r.json();
    allAttackers = d.attackers || [];
    renderAttackers(allAttackers);
}

function renderAttackers(list) {
    if (!list.length) { document.getElementById('atk-tbody').innerHTML = '<tr><td colspan="5" class="loading">No attackers recorded.</td></tr>'; return; }
    document.getElementById('atk-tbody').innerHTML = list.map(a => `
        <tr>
            <td><div class="atk-cell">
                <div class="atk-dot">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.6)" stroke-width="2" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </div>
                <div>
                    <div class="atk-ip">${htmlEsc(a.ip_address)}</div>
                    <div class="atk-meta">${htmlEsc(a.browser||'?')} / ${htmlEsc(a.os||'?')}</div>
                </div>
            </div></td>
            <td>${htmlEsc(a.site_name||'Unknown')}</td>
            <td>${a.total_attempts}</td>
            <td style="color:${sevCol(+a.max_severity)};font-weight:600">${a.max_severity}% ${sevLbl(+a.max_severity)}</td>
            <td><span class="status-badge ${a.is_banned?'badge-banned':'badge-monitored'}">${a.is_banned?'Banned':'Monitored'}</span></td>
        </tr>
    `).join('');
}

function filterAttackers() {
    const q = document.getElementById('atk-search').value.toLowerCase();
    renderAttackers(allAttackers.filter(a =>
        a.ip_address.includes(q) || (a.site_name||'').toLowerCase().includes(q)
    ));
}

/* ----------------------------------------------------------
   PYTHON MODULES
   ---------------------------------------------------------- */
async function loadModules() {
    document.getElementById('module-list').innerHTML = '<div class="loading">Checking modules...</div>';
    const r = await fetch('api/python_tools.php?action=status');
    if (!r.ok) { document.getElementById('module-list').innerHTML = '<div class="loading">Could not reach Python bridge.</div>'; return; }
    const d = await r.json();
    const modules = d.modules || {};

    const configs = {
        threat_intelligence: { label:'Threat Intelligence', desc:'IOC feeds, malicious IPs/domains/hashes',   bg:'#EEF2FF', col:'var(--blue)'  },
        deception_grid:      { label:'Deception Grid',      desc:'Honeytokens, decoy services',               bg:'#FDF2DC', col:'var(--amber)' },
        network_forensics:   { label:'Network Forensics',   desc:'Packet analysis, port scan detection',      bg:'#E5F5EE', col:'var(--green)' },
    };

    document.getElementById('module-list').innerHTML = Object.entries(configs).map(([key, cfg]) => {
        const status  = modules[key] || { running: false, message: 'Not running' };
        const dotCol  = status.running ? 'var(--green)' : 'var(--muted)';
        const statLbl = status.running ? 'Running' : 'Offline';
        return `<div class="py-row">
            <div class="py-left">
                <div class="py-icon" style="background:${cfg.bg};color:${cfg.col}">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                </div>
                <div>
                    <div class="py-name">${cfg.label}</div>
                    <div class="py-desc">${cfg.desc}</div>
                </div>
            </div>
            <div class="py-status" style="color:${dotCol}">
                <span class="status-dot" style="background:${dotCol}"></span>${statLbl}
            </div>
        </div>`;
    }).join('');
}

/* ----------------------------------------------------------
   RECENT EVENTS
   ---------------------------------------------------------- */
async function loadEvents() {
    const r = await fetch('api/attackers.php');
    if (!r.ok) return;
    const d  = await r.json();
    const ev = (d.attackers || []).slice(0, 6);

    const labels = {
        DECOY_USER_DELETE_ATTEMPT:'Decoy user delete attempt',
        SQL_INJECTION_ATTEMPT:'SQLi attempt',
        SCANNER_TOOL_DETECTED:'Automated scanner',
        FAILED_LOGIN:'Failed login',
        PATH_TRAVERSAL_ATTEMPT:'Path traversal',
        HONEYPOT_ROUTE_HIT:'Honeypot route hit',
        BRUTE_FORCE:'Brute force',
        XSS_ATTEMPT:'XSS attempt',
    };

    document.getElementById('event-list').innerHTML = ev.length
        ? ev.map(a => {
            const lastSeen = new Date(a.last_seen).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
            return `<div class="ev-row">
                <span class="ev-badge ${sevBadge(+a.max_severity)}">${sevLbl(+a.max_severity)}</span>
                <span class="ev-text">${htmlEsc(a.ip_address)} on ${htmlEsc(a.site_name||'Unknown')}</span>
                <span class="ev-time">${lastSeen}</span>
            </div>`;
          }).join('')
        : '<div class="loading">No recent events.</div>';
}

/* ----------------------------------------------------------
   SITE HEALTH
   ---------------------------------------------------------- */
async function loadHealth() {
    document.getElementById('health-grid').innerHTML = '<div class="loading">Checking sites...</div>';
    const r = await fetch('api/sites.php?health=1');
    if (!r.ok) { document.getElementById('health-grid').innerHTML = '<div class="loading">Health check failed.</div>'; return; }
    const d = await r.json();
    const results = d.results || [];

    if (!results.length) { document.getElementById('health-grid').innerHTML = '<div class="loading">No sites registered.</div>'; return; }

    const sr = await fetch('api/sites.php');
    const sd = sr.ok ? await sr.json() : { sites: [] };
    const siteMap = {};
    (sd.sites||[]).forEach(s => { siteMap[s.id] = s; });

    document.getElementById('health-grid').innerHTML = results.map(h => {
        const site  = siteMap[h.site_id] || { site_name:'Site #'+h.site_id, site_url:'' };
        const ok    = h.is_up;
        const dotC  = ok ? 'var(--green)' : 'var(--red)';
        const lbl   = ok ? 'Online' : 'Offline';
        const detail= ok ? `${h.response_ms}ms&nbsp;<span style="color:var(--muted)">HTTP ${h.status_code}</span>` : `<span style="color:var(--red)">${htmlEsc(h.error||'Down')}</span>`;
        return `<div class="health-card">
            <div class="health-top">
                <span class="health-name">${htmlEsc(site.site_name)}</span>
                <span class="health-status" style="color:${dotC}">
                    <span class="status-dot" style="background:${dotC}"></span>${lbl}
                </span>
            </div>
            <div class="health-url">${htmlEsc(site.site_url)}</div>
            <div class="health-ms">${detail}</div>
        </div>`;
    }).join('');
}

/* ----------------------------------------------------------
   SITE REGISTRATION
   ---------------------------------------------------------- */
async function registerSite() {
    const url  = document.getElementById('new-url').value.trim();
    const name = document.getElementById('new-name').value.trim();
    if (!url) { alert('Please enter a site URL.'); return; }

    const r = await fetch('api/sites.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ site_url: url, site_name: name })
    });
    const d = await r.json();
    if (d.error) { alert(d.error); return; }

    document.getElementById('snippet-code').textContent = d.snippet || '';
    document.getElementById('snippet-result').style.display = 'block';
    loadHealth();
}

/* ----------------------------------------------------------
   PERIOD TOGGLE
   ---------------------------------------------------------- */
function setPeriod(label, el) {
    document.querySelectorAll('.period-btn').forEach(b => b.classList.remove('active'));
    el.classList.add('active');
    loadSummary(); // in production, pass period param to API
}

/* ----------------------------------------------------------
   UTILS
   ---------------------------------------------------------- */
function htmlEsc(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ----------------------------------------------------------
   TRACKER STATUS
   ---------------------------------------------------------- */
async function loadTrackerStatus() {
    const r = await fetch('api/python_tools.php?action=tracker_status');
    const d = r.ok ? await r.json() : {};

    const running  = d.running  ?? false;
    const tracking = d.tracking_active ?? false;
    const attacker = d.attacker ?? null;
    const snapshot = d.snapshot ?? null;

    // Badge
    const badge = document.getElementById('tracker-badge');
    const dot   = document.getElementById('tracker-dot');
    if (running && tracking) {
        badge.className = 'tracker-badge active';
        badge.innerHTML = `<span class="status-dot" style="background:var(--red)"></span> Tracking`;
        dot.style.background = 'var(--red)';
    } else if (running) {
        badge.className = 'tracker-badge standby';
        badge.innerHTML = `<span class="status-dot" style="background:var(--amber)"></span> Standby`;
        dot.style.background = 'var(--amber)';
    } else {
        badge.className = 'tracker-badge offline';
        badge.innerHTML = `<span class="status-dot" style="background:var(--muted)"></span> Offline`;
    }

    document.getElementById('tracker-status-val').textContent  = running  ? 'Running'  : 'Not running';
    document.getElementById('tracker-active-val').textContent  = tracking ? 'Yes — camera active' : 'No';
    document.getElementById('tracker-ip-val').textContent      = attacker?.ip ?? '—';
    document.getElementById('tracker-snap-val').textContent    = snapshot
        ? snapshot.split('/').pop()
        : 'None saved yet';
}

/* ----------------------------------------------------------
   BOOT
   ---------------------------------------------------------- */
loadSummary();
loadAttackers();
loadModules();
loadEvents();
loadHealth();
loadTrackerStatus();
