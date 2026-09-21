<?php
/**
 * admin/dashboard.php
 * The main Aegis dashboard page. Server-renders the shell; data panels
 * load via fetch() from the api/ endpoints so the page stays fast.
 *
 * To integrate with SIMAP:
 *   1. Copy the aegis/ folder alongside SIMAP's existing files.
 *   2. Make sure SIMAP's session sets $_SESSION['aegis_admin'] = true
 *      for your admin user.
 *   3. Link to /aegis/admin/dashboard.php from SIMAP's sidebar.
 */

declare(strict_types=1);

session_start();

// --- Auth gate: trusts the SIMAP session that redirected us here -------
// aegis-transition.php sets $_SESSION['aegis_admin'] only after confirming
// the visitor is a logged-in SIMAP Admin, so this stays a simple flag
// check rather than a second, separate login system.
if (empty($_SESSION['aegis_admin'])) {
    header('Location: /aegis/admin/login.php');
    exit;
}
// -----------------------------------------------------------------------

$pageTitle = 'Aegis Security Dashboard';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($pageTitle) ?></title>
<meta name="description" content="Aegis — deception layer and threat intelligence for the network it protects.">
<meta name="robots" content="noindex, nofollow, noarchive">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* =========================================================
   RESET + TOKENS
   ========================================================= */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
    --bg:         #F5F6FA;
    --card:       #FFFFFF;
    --border:     rgba(0, 0, 0, .08);
    --text:       #111317;
    --muted:      #7A7E8A;
    --blue:       #3B6CF6;
    --dark:       #13151A;
    --red:        #E5484D;
    --red-bg:     #FCEAEA;
    --green:      #1A9E6E;
    --green-bg:   #E5F5EE;
    --amber:      #D98C1A;
    --amber-bg:   #FDF2DC;
    --font:       'Inter', sans-serif;
    --mono:       'IBM Plex Mono', monospace;
}

@media (prefers-color-scheme: dark) {
    :root {
        --bg:   #0F1014;
        --card: #1A1D24;
        --border: rgba(255,255,255,.07);
        --text: #E4E6EC;
        --muted:#636778;
    }
}

body { font-family: var(--font); background: var(--bg); color: var(--text); min-height: 100vh; }

/* =========================================================
   LAYOUT SHELL
   ========================================================= */
.shell   { display: grid; grid-template-rows: 56px 1fr; grid-template-columns: 200px 1fr; min-height: 100vh; }
.topbar  { grid-column: 1 / -1; display: flex; align-items: center; gap: 20px; padding: 0 20px; background: var(--card); border-bottom: 1px solid var(--border); z-index: 10; }
.sidebar { background: var(--card); border-right: 1px solid var(--border); padding: 16px 10px; display: flex; flex-direction: column; overflow-y: auto; }
.main    { padding: 22px 26px; overflow-y: auto; }

/* =========================================================
   TOPBAR
   ========================================================= */
.logo { font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 8px; color: var(--text); text-decoration: none; }
.logo svg { color: var(--blue); }

.nav-pills { display: flex; gap: 4px; margin-left: 12px; }
.nav-pill  { padding: 6px 14px; border-radius: 20px; font-size: 12.5px; font-weight: 500; color: var(--muted); cursor: pointer; text-decoration: none; transition: background .15s; }
.nav-pill:hover   { background: var(--bg); }
.nav-pill.active  { background: var(--dark); color: #fff; }

.topbar-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
.return-to-simap {
    display: flex; align-items: center; gap: 6px;
    font-size: 12px; font-weight: 600; color: var(--muted);
    text-decoration: none; padding: 7px 12px; border-radius: 8px;
    border: 1px solid var(--border); white-space: nowrap;
    transition: color .15s ease, border-color .15s ease, background .15s ease;
}
.return-to-simap:hover { color: var(--text); border-color: var(--blue); background: rgba(59,108,246,.08); }
.search-box   { display: flex; align-items: center; gap: 7px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 7px 12px; min-width: 170px; font-size: 12.5px; color: var(--muted); }
.search-box input { border: none; outline: none; background: transparent; font-size: 12.5px; color: var(--text); width: 100%; }
.avatar { width: 30px; height: 30px; border-radius: 50%; background: var(--blue); color: #fff; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 600; }

/* =========================================================
   SIDEBAR
   ========================================================= */
.section-label { font-size: 10px; font-weight: 600; color: var(--muted); letter-spacing: .06em; text-transform: uppercase; padding: 0 8px; margin: 14px 0 6px; }

.sitem { display: flex; align-items: center; gap: 9px; padding: 8px 10px; border-radius: 8px; font-size: 12.5px; font-weight: 500; color: var(--text); cursor: pointer; text-decoration: none; transition: background .12s; }
.sitem:hover    { background: var(--bg); }
.sitem.active   { background: #EEF2FF; color: var(--blue); }
.sitem svg      { flex-shrink: 0; width: 16px; height: 16px; }
.nav-badge      { margin-left: auto; background: var(--red); color: #fff; font-size: 9px; font-weight: 700; border-radius: 10px; padding: 1px 6px; }
.sidebar-footer { margin-top: auto; border-top: 1px solid var(--border); padding-top: 10px; }

/* =========================================================
   PAGE HEADER
   ========================================================= */
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; flex-wrap: wrap; gap: 12px; }
.page-title  { font-size: 22px; font-weight: 700; color: var(--text); }

.controls     { display: flex; align-items: center; gap: 8px; }
.period-group { display: flex; background: var(--card); border: 1px solid var(--border); border-radius: 20px; padding: 3px; }
.period-btn   { padding: 5px 12px; border-radius: 16px; font-size: 11.5px; font-weight: 500; color: var(--muted); cursor: pointer; transition: background .12s; }
.period-btn.active { background: var(--blue); color: #fff; }

.btn-primary { background: var(--blue); color: #fff; border: none; border-radius: 8px; padding: 8px 14px; font-size: 12px; font-weight: 600; cursor: pointer; transition: opacity .12s; }
.btn-primary:hover { opacity: .88; }

/* =========================================================
   METRIC CARDS
   ========================================================= */
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 14px; }

@media (max-width: 1100px) { .cards { grid-template-columns: repeat(2, 1fr); } }

.metric-card  { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 18px 18px 14px; }
.metric-dark  { background: var(--dark) !important; border: none !important; }
.metric-top   { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.metric-label { font-size: 11px; font-weight: 600; color: var(--muted); }
.metric-dark .metric-label { color: #9CA0B0; }

.metric-arrow { width: 24px; height: 24px; border-radius: 50%; background: var(--bg); display: flex; align-items: center; justify-content: center; }
.metric-dark .metric-arrow { background: rgba(255,255,255,.1); }

.metric-val  { font-size: 28px; font-weight: 700; color: var(--text); margin-bottom: 6px; font-variant-numeric: tabular-nums; }
.metric-dark .metric-val { color: #fff; }
.metric-delta { font-size: 11px; font-weight: 600; }

/* =========================================================
   CARDS (general)
   ========================================================= */
.card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 18px; box-shadow: 0 1px 1px rgba(0,0,0,.03), 0 6px 20px rgba(0,0,0,.05); }
.card-head  { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
.card-title { font-size: 13.5px; font-weight: 600; color: var(--text); }
.dropdown-pill { font-size: 11px; font-weight: 600; border: 1px solid var(--border); border-radius: 16px; padding: 5px 10px; color: var(--text); cursor: pointer; }

/* =========================================================
   BAR CHART
   ========================================================= */
.chart-area { display: flex; align-items: flex-end; gap: 6px; height: 160px; padding-top: 4px; }
.bar-col    { display: flex; flex-direction: column; align-items: center; gap: 4px; flex: 1; }
.bar        { border-radius: 5px 5px 0 0; width: 100%; }
.bar-lbl    { font-size: 10px; color: var(--muted); font-family: var(--mono); }
.bar-tip    { font-size: 9px; color: var(--text); font-weight: 600; }

/* =========================================================
   MID ROW (chart + distribution)
   ========================================================= */
.mid-row { display: grid; grid-template-columns: 1.6fr 1fr; gap: 12px; margin-bottom: 14px; }
@media (max-width: 900px) { .mid-row { grid-template-columns: 1fr; } }

.dist-area  { height: 110px; background: linear-gradient(135deg, #EEF2FF 0%, var(--bg) 100%); border-radius: 10px; margin-bottom: 12px; position: relative; overflow: hidden; }
.dist-dot   { position: absolute; border-radius: 50%; background: var(--blue); opacity: .5; }
.dist-badge { position: absolute; top: 8px; left: 8px; background: var(--card); border-radius: 8px; padding: 3px 9px; font-size: 10px; font-weight: 600; color: var(--text); box-shadow: 0 1px 4px rgba(0,0,0,.06); }

.origin-row  { display: flex; justify-content: space-between; align-items: center; padding: 7px 0; border-top: 1px solid var(--border); font-size: 12px; }
.origin-left { display: flex; align-items: center; gap: 6px; font-weight: 500; color: var(--text); }
.origin-pct  { font-size: 12px; font-weight: 600; color: var(--muted); }

/* =========================================================
   BOTTOM ROW (table + modules)
   ========================================================= */
.bottom-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; }
@media (max-width: 900px) { .bottom-row { grid-template-columns: 1fr; } }

.t-controls { display: flex; align-items: center; gap: 6px; }
.t-search   { display: flex; align-items: center; gap: 5px; background: var(--bg); border: 1px solid var(--border); border-radius: 7px; padding: 5px 10px; font-size: 11px; color: var(--muted); }
.t-search input { border: none; outline: none; background: transparent; font-size: 11px; color: var(--text); width: 110px; }
.export-btn { display: flex; align-items: center; gap: 5px; background: var(--blue); color: #fff; border: none; border-radius: 7px; padding: 6px 11px; font-size: 11.5px; font-weight: 600; cursor: pointer; text-decoration: none; }
.export-btn:hover { opacity: .88; }

.atk-table       { width: 100%; border-collapse: collapse; }
.atk-table th    { font-size: 10px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; padding: 0 8px 8px; text-align: left; border-bottom: 1px solid var(--border); }
.atk-table td    { font-size: 11.5px; padding: 10px 8px; border-bottom: 1px solid var(--border); vertical-align: middle; color: var(--text); }
.atk-cell        { display: flex; align-items: center; gap: 8px; }
.atk-dot         { width: 28px; height: 28px; border-radius: 50%; background: var(--dark); flex-shrink: 0; display: flex; align-items: center; justify-content: center; }
.atk-ip          { font-size: 12px; font-weight: 600; font-family: var(--mono); color: var(--text); }
.atk-meta        { font-size: 10px; color: var(--muted); }
.status-badge    { font-size: 10px; font-weight: 600; border-radius: 16px; padding: 3px 9px; display: inline-block; }
.badge-banned    { background: var(--red-bg); color: var(--red); }
.badge-monitored { background: var(--green-bg); color: var(--green); }

/* =========================================================
   PYTHON MODULES PANEL
   ========================================================= */
.py-row  { display: flex; align-items: center; justify-content: space-between; padding: 9px 10px; background: var(--bg); border-radius: 8px; border: 1px solid var(--border); margin-bottom: 6px; }
.py-left { display: flex; align-items: center; gap: 9px; }
.py-icon { width: 30px; height: 30px; border-radius: 7px; display: flex; align-items: center; justify-content: center; font-size: 14px; }
.py-name { font-size: 12px; font-weight: 600; color: var(--text); }
.py-desc { font-size: 10.5px; color: var(--muted); }
.py-status { display: flex; align-items: center; gap: 4px; font-size: 10.5px; font-weight: 600; }
.status-dot { width: 6px; height: 6px; border-radius: 50%; }

/* =========================================================
   EVENT LIST
   ========================================================= */
.ev-row   { display: flex; align-items: center; gap: 7px; padding: 7px 0; border-bottom: 1px solid var(--border); font-size: 11.5px; }
.ev-badge { font-size: 9.5px; font-weight: 600; border-radius: 4px; padding: 2px 7px; flex-shrink: 0; }
.ev-text  { flex: 1; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ev-time  { font-size: 10px; color: var(--muted); flex-shrink: 0; font-family: var(--mono); }
.sev-c   { background: var(--red-bg);   color: var(--red);   }
.sev-h   { background: var(--amber-bg); color: var(--amber); }
.sev-m   { background: #EEF2FF; color: var(--blue);  }
.sev-l   { background: var(--green-bg); color: var(--green); }

/* =========================================================
   SITE HEALTH
   ========================================================= */
.health-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
@media (max-width: 900px) { .health-grid { grid-template-columns: 1fr 1fr; } }
.health-card { background: var(--bg); border-radius: 8px; padding: 10px 12px; border: 1px solid var(--border); }
.health-top  { display: flex; justify-content: space-between; align-items: center; margin-bottom: 3px; }
.health-name { font-size: 12.5px; font-weight: 600; color: var(--text); }
.health-url  { font-size: 10.5px; color: var(--muted); font-family: var(--mono); }
.health-ms   { font-size: 11px; color: var(--text); margin-top: 6px; }
.health-status { display: flex; align-items: center; gap: 4px; font-size: 10.5px; font-weight: 600; }

/* =========================================================
   SNIPPETS / LOADING STATES
   ========================================================= */
.loading { padding: 16px; text-align: center; color: var(--muted); font-size: 12px; }
pre.snippet { font-family: var(--mono); font-size: 11px; background: var(--dark); color: #D7DAE0; border-radius: 8px; padding: 12px; overflow-x: auto; line-height: 1.6; }

/* Physical tracker panel */
.tracker-card   { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 18px; margin-top: 14px; }
.tracker-grid   { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; }
.tracker-stat   { background: var(--bg); border-radius: 8px; padding: 12px; border: 1px solid var(--border); }
.tracker-stat-label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin-bottom: 4px; }
.tracker-stat-val   { font-size: 18px; font-weight: 700; color: var(--text); }
.tracker-badge  { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 600; border-radius: 20px; padding: 4px 10px; }
.tracker-badge.active  { background: var(--red-bg);   color: var(--red);   }
.tracker-badge.standby { background: var(--amber-bg); color: var(--amber); }
.tracker-badge.offline { background: var(--bg);       color: var(--muted); }
.snap-thumb { width: 100%; border-radius: 8px; object-fit: cover; max-height: 140px; background: #0F1014; display: flex; align-items: center; justify-content: center; font-size: 12px; color: var(--muted); }

/* =========================================================
   MODAL
   ========================================================= */
.modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.45); z-index: 100; align-items: center; justify-content: center; }
.modal-overlay.open { display: flex; }
.modal   { background: var(--card); border-radius: 16px; padding: 24px; width: 440px; max-width: 92vw; max-height: 85vh; overflow-y: auto; }
.modal h3 { font-size: 15px; font-weight: 600; margin-bottom: 6px; }
.modal p  { font-size: 12.5px; color: var(--muted); line-height: 1.6; margin-bottom: 14px; }
.field   { width: 100%; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 9px 12px; font-size: 12.5px; color: var(--text); margin-bottom: 10px; font-family: var(--font); }
.field:focus { outline: 2px solid var(--blue); }
.btn-secondary { width: 100%; background: transparent; border: 1px solid var(--border); border-radius: 8px; padding: 9px; font-size: 12.5px; font-weight: 500; color: var(--muted); cursor: pointer; margin-top: 8px; }

/* =========================================================
   MOBILE RESPONSIVE (phones) -- matches SIMAP's own hamburger
   pattern for a consistent feel when moving between the two
   systems. Desktop layout above is untouched.
   ========================================================= */
.hamburger-btn {
    display: none;
    align-items: center; justify-content: center;
    width: 34px; height: 34px;
    background: transparent; border: 1px solid var(--border); border-radius: 8px;
    color: var(--text); cursor: pointer; flex-shrink: 0;
}
.sidebar-overlay {
    display: none;
    position: fixed; inset: 0; background: rgba(0,0,0,.5);
    z-index: 19; opacity: 0; transition: opacity .2s ease;
}
.sidebar-overlay.open { display: block; opacity: 1; }

@media (max-width: 768px) {
    .hamburger-btn { display: flex; }
    .nav-pills { display: none; } /* duplicated by the sidebar drawer on mobile */
    .search-box { display: none; } /* reclaim topbar space on narrow screens */
    .return-to-simap span { display: none; }

    .shell { grid-template-columns: 1fr; }

    .sidebar {
        position: fixed; top: 56px; left: 0; bottom: 0;
        width: 240px; max-width: 80vw;
        transform: translateX(-100%);
        transition: transform .22s ease;
        z-index: 20;
        box-shadow: 8px 0 24px rgba(0,0,0,.25);
    }
    .sidebar.open { transform: translateX(0); }

    .main { padding: 16px; }
    .cards { grid-template-columns: 1fr !important; }
    .health-grid { grid-template-columns: 1fr 1fr !important; }
}
</style>
</head>
<body>
<div class="shell">

<!-- ============================================================ TOPBAR -->
<header class="topbar">
    <button type="button" class="hamburger-btn" id="aegisSidebarToggle" aria-label="Open menu" aria-expanded="false" aria-controls="aegisSidebar">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
    </button>
    <a href="dashboard.php" class="logo">
        <img src="../assets/aegis-logo.svg" width="28" height="28" alt="Aegis Shield Logo"
             style="filter:drop-shadow(0 0 4px rgba(229,72,77,.5))">
        Aegis
    </a>
    <nav class="nav-pills" aria-label="Main navigation">
        <a href="dashboard.php"         class="nav-pill active">Summary</a>
        <a href="dashboard.php?view=sites"     class="nav-pill">Sites</a>
        <a href="dashboard.php?view=attackers" class="nav-pill">Attackers</a>
        <a href="dashboard.php?view=reports"   class="nav-pill">Reports</a>
    </nav>
    <div class="topbar-right">
        <div class="search-box">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
            <input type="search" placeholder="Search..." aria-label="Search">
        </div>
        <a href="../../dashboard.php" class="return-to-simap" title="Return to SIMAP">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
            Return to SIMAP
        </a>
        <div class="avatar" title="Mmari">M</div>
    </div>
</header>

<!-- ============================================================ SIDEBAR -->
<div class="sidebar-overlay" id="aegisSidebarOverlay"></div>
<nav class="sidebar" id="aegisSidebar" aria-label="Dashboard sections">
    <div class="section-label">General Menu</div>
    <a href="dashboard.php"                     class="sitem active">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
        Dashboard
    </a>
    <a href="dashboard.php?view=sites"           class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z"/></svg>
        Sites
    </a>
    <a href="dashboard.php?view=log"             class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M6 6h12M6 12h12M6 18h8"/></svg>
        Attack Log
    </a>
    <a href="api/credentials.php"               class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="6" width="18" height="12" rx="2"/><path d="M3 10h18"/></svg>
        Credentials
    </a>
    <a href="dashboard.php?view=charts"          class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 20V10M12 20V4M20 20v-7"/></svg>
        Charts
    </a>
    <a href="dashboard.php?view=lessons"         class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V4H6.5A2.5 2.5 0 0 0 4 6.5v13z"/></svg>
        Lessons Learned
    </a>
    <a href="dashboard.php?view=notifications"   class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg>
        Notifications
        <span class="nav-badge" id="notif-count" aria-label="3 notifications">3</span>
    </a>

    <div class="section-label">Python Modules</div>
    <a href="dashboard.php?view=threat-intel"    class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        Threat Intel
    </a>
    <a href="dashboard.php?view=deception"       class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
        Deception Grid
    </a>
    <a href="dashboard.php?view=network"         class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v4M5 17l7-6M19 17l-7-6"/></svg>
        Network Forensics
    </a>
    <a href="dashboard.php?view=tracker"         class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M3 12h2M19 12h2M12 3v2M12 19v2"/><circle cx="12" cy="12" r="8" stroke-dasharray="3 2"/></svg>
        Physical Tracker
    </a>

    <div class="section-label">Support</div>
    <a href="#" class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.8.4-1.3 1-1.3 1.9v.3"/><circle cx="12" cy="17" r=".5" fill="currentColor"/></svg>
        Help
    </a>
    <a href="#" class="sitem">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>
        Settings
    </a>

    <div class="sidebar-footer">
        <a href="../../dashboard.php" class="sitem">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
            Return to SIMAP
        </a>
        <a href="../../logout.php" class="sitem">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/></svg>
            Logout
        </a>
    </div>
</nav>

<!-- ============================================================ MAIN -->
<main class="main" id="main-content">
    <div class="page-header">
        <h1 class="page-title">Summary</h1>
        <div class="controls">
            <div class="period-group" role="group" aria-label="Time period">
                <div class="period-btn" onclick="setPeriod('Day',   this)">Day</div>
                <div class="period-btn active" onclick="setPeriod('Week',  this)">Week</div>
                <div class="period-btn" onclick="setPeriod('Month', this)">Month</div>
                <div class="period-btn" onclick="setPeriod('Year',  this)">Year</div>
            </div>
            <button class="btn-primary" onclick="document.getElementById('add-site-modal').classList.add('open')">+ Add Site</button>
        </div>
    </div>

    <!-- METRIC CARDS -->
    <div class="cards" id="metric-cards">
        <div class="loading">Loading metrics...</div>
    </div>

    <!-- CHART + DISTRIBUTION -->
    <div class="mid-row">
        <div class="card">
            <div class="card-head">
                <span class="card-title">Statistic</span>
                <div class="dropdown-pill" id="chart-filter">All Attack Types &#9660;</div>
            </div>
            <div class="chart-area" id="bar-chart">
                <div class="loading">Loading chart...</div>
            </div>
        </div>
        <div class="card">
            <div class="card-head">
                <span class="card-title">Attacker Origin</span>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M7 17 17 7M8 7h9v9"/></svg>
            </div>
            <div class="dist-area" id="origin-map">
                <div class="dist-badge" id="origin-badge">Loading...</div>
            </div>
            <div id="origin-list"></div>
        </div>
    </div>

    <!-- ATTACKER TABLE + PYTHON MODULES -->
    <div class="bottom-row">
        <div class="card">
            <div class="card-head">
                <span class="card-title">Recent Attackers</span>
                <div class="t-controls">
                    <div class="t-search">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
                        <input type="search" id="atk-search" placeholder="Search IP or site..." onkeyup="filterAttackers()" aria-label="Search attackers">
                    </div>
                    <a class="export-btn" href="api/export.php" target="_blank">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 3v12M7 8l5-5 5 5"/><path d="M5 21h14"/></svg>
                        Export
                    </a>
                </div>
            </div>
            <table class="atk-table" id="atk-table">
                <thead>
                    <tr>
                        <th>Attacker</th>
                        <th>Site</th>
                        <th>Attempts</th>
                        <th>Damage</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="atk-tbody">
                    <tr><td colspan="5" class="loading">Loading attackers...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="card">
            <div class="card-head">
                <span class="card-title">Security Modules</span>
                <button onclick="loadModules()" style="background:none;border:none;cursor:pointer;color:var(--muted)">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                </button>
            </div>
            <div id="module-list" aria-live="polite">
                <div class="loading">Loading module status...</div>
            </div>
            <div style="margin-top:14px">
                <div class="card-title" style="font-size:12px;margin-bottom:8px">Recent events</div>
                <div id="event-list" aria-live="polite">
                    <div class="loading">Loading events...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- SITE HEALTH -->
    <div class="card">
        <div class="card-head">
            <span class="card-title">Site Health</span>
            <button class="dropdown-pill" onclick="loadHealth()">Refresh</button>
        </div>
        <div class="health-grid" id="health-grid">
            <div class="loading">Checking sites...</div>
        </div>
    </div>

    <!-- PHYSICAL TRACKER -->
    <div class="tracker-card">
        <div class="card-head">
            <span class="card-title">Physical Tracker</span>
            <div style="display:flex;gap:8px;align-items:center">
                <span id="tracker-badge" class="tracker-badge offline">
                    <span class="status-dot" id="tracker-dot" style="background:var(--muted)"></span>
                    Offline
                </span>
                <button class="dropdown-pill" onclick="loadTrackerStatus()">Refresh</button>
            </div>
        </div>
        <p style="font-size:12px;color:var(--muted);margin-bottom:10px;line-height:1.6">
            YOLOv5 camera-based person detection. Activates automatically when any attack
            reaches <strong style="color:var(--text)">Critical (80%+)</strong> severity.
            Requires the tracker process to be running on a machine with a camera.
        </p>
        <div class="tracker-grid" id="tracker-grid">
            <div class="tracker-stat">
                <div class="tracker-stat-label">Tracker Status</div>
                <div class="tracker-stat-val" id="tracker-status-val">Unknown</div>
            </div>
            <div class="tracker-stat">
                <div class="tracker-stat-label">Last Snapshot</div>
                <div class="tracker-stat-val" id="tracker-snap-val" style="font-size:12px">None</div>
            </div>
            <div class="tracker-stat">
                <div class="tracker-stat-label">Tracking Active</div>
                <div class="tracker-stat-val" id="tracker-active-val">No</div>
            </div>
            <div class="tracker-stat">
                <div class="tracker-stat-label">Attacker IP on Camera</div>
                <div class="tracker-stat-val" id="tracker-ip-val" style="font-size:13px;font-family:var(--mono)">—</div>
            </div>
        </div>

        <div style="margin-top:12px;background:var(--bg);border-radius:8px;padding:12px;border:1px solid var(--border)">
            <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:8px">
                Start command (run on the camera machine)
            </div>
            <pre class="snippet">python3 aegis/python/physical_tracker.py --source 0 --view-img --save-video</pre>
            <div style="font-size:11px;color:var(--muted);margin-top:6px">
                Once running, Aegis signals it automatically on Critical events.
                Works only when the attacker is physically present in camera view.
            </div>
        </div>
    </div>
</main>

</div><!-- .shell -->

<!-- ============================================================ ADD SITE MODAL -->
<div class="modal-overlay" id="add-site-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"
     onclick="if(event.target===this) this.classList.remove('open')">
    <div class="modal">
        <h3 id="modal-title">Register a site you control</h3>
        <p>Registering generates an install key. The site sends data to Aegis only after you drop the middleware snippet into its own server — registering a URL alone does nothing.</p>
        <input class="field" type="url" id="new-url"  placeholder="https://yoursite.co.tz">
        <input class="field" type="text" id="new-name" placeholder="Site name (optional)">
        <button class="btn-primary" style="width:100%" onclick="registerSite()">Register Site</button>
        <div id="snippet-result" style="display:none;margin-top:14px">
            <div style="font-size:11.5px;font-weight:600;color:var(--blue);margin-bottom:6px">Install key generated — add this to your site:</div>
            <pre class="snippet" id="snippet-code"></pre>
        </div>
        <button class="btn-secondary" onclick="document.getElementById('add-site-modal').classList.remove('open')">Close</button>
    </div>
</div>

<script src="../assets/js/dashboard.js" defer></script>

</body>
</html>
