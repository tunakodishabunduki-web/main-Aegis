<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aegis — Multi-Site Honeypot & Attack Intelligence Platform</title>
<style>
/* ── Reset ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:      #0B0D12;
  --card:    #13151C;
  --border:  rgba(255,255,255,.07);
  --text:    #E4E6EC;
  --muted:   #636778;
  --red:     #E53E3E;
  --blue:    #3B82F6;
  --green:   #22C55E;
  --amber:   #F59E0B;
  --purple:  #8B5CF6;
  --mono:    'Fira Code', 'Cascadia Code', monospace;
}
html { scroll-behavior: smooth; }
body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.65; overflow-x: hidden; }

/* ── Animated hero gradient ── */
.hero {
  position: relative;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 60px 20px;
  overflow: hidden;
}
.hero::before {
  content: '';
  position: absolute; inset: 0;
  background: radial-gradient(ellipse 80% 60% at 50% 0%, rgba(229,72,77,.18) 0%, transparent 70%),
              radial-gradient(ellipse 60% 40% at 80% 80%, rgba(59,130,246,.12) 0%, transparent 70%),
              radial-gradient(ellipse 50% 50% at 20% 60%, rgba(139,92,246,.10) 0%, transparent 70%);
  animation: bgShift 8s ease-in-out infinite alternate;
}
@keyframes bgShift {
  0%   { opacity: .7; transform: scale(1); }
  100% { opacity: 1;  transform: scale(1.06); }
}

/* ── Particle grid ── */
.grid-bg {
  position: absolute; inset: 0;
  background-image:
    linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.03) 1px, transparent 1px);
  background-size: 48px 48px;
  animation: gridDrift 20s linear infinite;
}
@keyframes gridDrift {
  0%   { transform: translate(0, 0); }
  100% { transform: translate(48px, 48px); }
}

/* ── Shield logo ── */
.shield-wrap {
  position: relative;
  width: 120px; height: 120px;
  margin: 0 auto 28px;
  animation: shieldFloat 4s ease-in-out infinite;
}
@keyframes shieldFloat {
  0%, 100% { transform: translateY(0);   }
  50%       { transform: translateY(-10px); }
}
.shield-glow {
  position: absolute; inset: -20px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(229,72,77,.35) 0%, transparent 70%);
  animation: glowPulse 2.5s ease-in-out infinite;
}
@keyframes glowPulse {
  0%, 100% { opacity: .5; transform: scale(.9); }
  50%       { opacity: 1;  transform: scale(1.1); }
}
.shield-wrap svg { width: 120px; height: 120px; position: relative; z-index: 1; }

/* ── Hero text ── */
.hero-title {
  font-size: clamp(2.4rem, 6vw, 4.2rem);
  font-weight: 700;
  letter-spacing: -.03em;
  line-height: 1.1;
  position: relative;
  background: linear-gradient(135deg, #fff 30%, #E53E3E 70%, #F87171 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  animation: titleReveal .8s ease both;
}
@keyframes titleReveal {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: none; }
}
.hero-sub {
  font-size: 1.1rem;
  color: var(--muted);
  max-width: 600px;
  margin: 14px auto 0;
  animation: titleReveal .8s .15s ease both;
}

/* ── Badges ── */
.badges {
  display: flex; flex-wrap: wrap; gap: 8px;
  justify-content: center;
  margin: 28px 0;
  animation: titleReveal .8s .25s ease both;
}
.badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 5px 12px; border-radius: 20px;
  font-size: 12px; font-weight: 600;
  border: 1px solid;
}
.badge-red    { color: #F87171; border-color: rgba(248,113,113,.3); background: rgba(229,72,77,.12); }
.badge-blue   { color: #60A5FA; border-color: rgba(96,165,250,.3);  background: rgba(59,130,246,.1); }
.badge-green  { color: #4ADE80; border-color: rgba(74,222,128,.3);  background: rgba(34,197,94,.1); }
.badge-purple { color: #A78BFA; border-color: rgba(167,139,250,.3); background: rgba(139,92,246,.1); }
.badge-amber  { color: #FCD34D; border-color: rgba(252,211,77,.3);  background: rgba(245,158,11,.1); }

/* ── Typing animation for tagline ── */
.typing-wrap { position: relative; height: 1.6em; margin: 4px 0 24px; }
.typing {
  font-family: var(--mono);
  font-size: .9rem;
  color: var(--green);
  border-right: 2px solid var(--green);
  white-space: nowrap;
  overflow: hidden;
  animation: typeIn 2.8s steps(60, end) .6s both,
             blink .75s step-end infinite;
  display: inline-block;
}
@keyframes typeIn {
  from { width: 0; }
  to   { width: 100%; }
}
@keyframes blink {
  from, to { border-color: transparent; }
  50%      { border-color: var(--green); }
}

/* ── CTA buttons ── */
.cta-row {
  display: flex; flex-wrap: wrap; gap: 12px;
  justify-content: center;
  animation: titleReveal .8s .35s ease both;
}
.btn {
  padding: 12px 24px; border-radius: 10px; font-size: 14px;
  font-weight: 600; cursor: pointer; text-decoration: none;
  transition: transform .15s, box-shadow .15s;
  border: none;
}
.btn:hover { transform: translateY(-2px); }
.btn-primary {
  background: var(--red); color: #fff;
  box-shadow: 0 0 24px rgba(229,72,77,.4);
}
.btn-primary:hover { box-shadow: 0 0 32px rgba(229,72,77,.6); }
.btn-ghost {
  background: transparent; color: var(--text);
  border: 1px solid var(--border);
}
.btn-ghost:hover { background: rgba(255,255,255,.05); }

/* ── Scroll arrow ── */
.scroll-hint {
  position: absolute; bottom: 32px;
  animation: bounce 2s ease-in-out infinite;
}
@keyframes bounce {
  0%, 100% { transform: translateY(0);   opacity: .5; }
  50%       { transform: translateY(8px); opacity: 1;  }
}

/* ── Section layout ── */
.section { padding: 80px 24px; max-width: 1100px; margin: 0 auto; }
.section-tag {
  display: inline-block;
  font-size: 11px; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; color: var(--red);
  margin-bottom: 10px;
}
.section-title {
  font-size: clamp(1.6rem, 4vw, 2.4rem);
  font-weight: 700; letter-spacing: -.02em;
  margin-bottom: 12px;
}
.section-body { color: var(--muted); font-size: .95rem; max-width: 640px; }

/* ── Feature cards ── */
.features { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; margin-top: 40px; }
.feat {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 14px; padding: 22px;
  transition: border-color .2s, transform .2s, box-shadow .2s;
  position: relative; overflow: hidden;
}
.feat::before {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, var(--accent, var(--red)), transparent);
  opacity: 0;
  transition: opacity .3s;
}
.feat:hover { transform: translateY(-4px); border-color: rgba(229,72,77,.3); box-shadow: 0 12px 40px rgba(0,0,0,.4); }
.feat:hover::before { opacity: 1; }
.feat-icon {
  width: 42px; height: 42px; border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  font-size: 20px; margin-bottom: 14px;
}
.feat-title { font-size: 15px; font-weight: 600; margin-bottom: 7px; }
.feat-body  { font-size: 13px; color: var(--muted); line-height: 1.6; }

/* ── Architecture flow ── */
.arch {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 16px; padding: 32px;
  margin-top: 40px; overflow-x: auto;
}
.flow {
  display: flex; align-items: center; gap: 0;
  min-width: 900px;
}
.flow-node {
  flex: 1; text-align: center;
  animation: nodeIn .5s ease both;
}
.flow-node:nth-child(1)  { animation-delay: .1s; }
.flow-node:nth-child(3)  { animation-delay: .2s; }
.flow-node:nth-child(5)  { animation-delay: .3s; }
.flow-node:nth-child(7)  { animation-delay: .4s; }
.flow-node:nth-child(9)  { animation-delay: .5s; }
@keyframes nodeIn {
  from { opacity: 0; transform: scale(.8); }
  to   { opacity: 1; transform: none; }
}
.flow-box {
  background: #1A1D26; border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 10px;
  font-size: 12px; font-weight: 500;
  position: relative;
}
.flow-box.red    { border-color: rgba(229,72,77,.4);   color: #F87171; }
.flow-box.blue   { border-color: rgba(59,130,246,.4);  color: #60A5FA; }
.flow-box.green  { border-color: rgba(34,197,94,.4);   color: #4ADE80; }
.flow-box.purple { border-color: rgba(139,92,246,.4);  color: #A78BFA; }
.flow-box.amber  { border-color: rgba(245,158,11,.4);  color: #FCD34D; }
.flow-box .sub   { font-size: 10px; color: var(--muted); margin-top: 3px; font-weight: 400; }
.flow-arrow {
  flex: 0 0 32px; text-align: center; color: var(--muted); font-size: 18px;
  position: relative;
}
.flow-arrow::after {
  content: '';
  position: absolute; top: 50%; left: 50%;
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--red);
  transform: translate(-50%, -50%);
  animation: dotPulse 1.5s ease-in-out infinite;
}
@keyframes dotPulse {
  0%, 100% { opacity: 0; transform: translate(-50%, -50%) scale(0); }
  50%       { opacity: 1; transform: translate(-50%, -50%) scale(1); }
}

/* ── Code block ── */
.code-wrap {
  background: #080A0F; border: 1px solid var(--border);
  border-radius: 12px; overflow: hidden; margin-top: 24px;
  box-shadow: 0 20px 60px rgba(0,0,0,.5);
}
.code-bar {
  background: #13151C; padding: 10px 16px;
  display: flex; align-items: center; gap: 8px;
  border-bottom: 1px solid var(--border);
}
.dot-r { width:10px;height:10px;border-radius:50%;background:#FF5F57; }
.dot-y { width:10px;height:10px;border-radius:50%;background:#FFBD2E; }
.dot-g { width:10px;height:10px;border-radius:50%;background:#28CA41; }
.code-file { font-size:11px;color:var(--muted);margin-left:8px;font-family:var(--mono); }
pre.code {
  font-family: var(--mono); font-size: 13px; line-height: 1.7;
  padding: 20px; overflow-x: auto; color: #ABB2BF;
  margin: 0;
}
.t-kw  { color: #C678DD; } /* keyword  */
.t-fn  { color: #61AFEF; } /* function */
.t-str { color: #98C379; } /* string   */
.t-cm  { color: #5C6370; } /* comment  */
.t-const{ color: #E5C07B;} /* constant */
.t-num { color: #D19A66; } /* number   */

/* ── Stats row ── */
.stats {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 12px; margin: 40px 0;
}
.stat {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 12px; padding: 18px; text-align: center;
}
.stat-val { font-size: 2.2rem; font-weight: 700; line-height: 1; }
.stat-lbl { font-size: 12px; color: var(--muted); margin-top: 5px; }
.stat:hover .stat-val { animation: countUp .4s ease; }
@keyframes countUp {
  from { transform: scale(.85); opacity: .5; }
  to   { transform: none; opacity: 1; }
}

/* ── Timeline steps ── */
.steps { list-style: none; margin-top: 32px; position: relative; }
.steps::before {
  content: '';
  position: absolute; left: 18px; top: 0; bottom: 0;
  width: 2px; background: var(--border);
}
.step {
  display: flex; gap: 20px; margin-bottom: 28px;
  opacity: 0; transform: translateX(-16px);
  transition: opacity .4s, transform .4s;
}
.step.visible { opacity: 1; transform: none; }
.step-num {
  flex: 0 0 36px; height: 36px; border-radius: 50%;
  background: var(--card); border: 1px solid var(--border);
  display: flex; align-items: center; justify-content: center;
  font-size: 13px; font-weight: 700; color: var(--red);
  position: relative; z-index: 1;
}
.step-content { padding-top: 4px; }
.step-title { font-size: 15px; font-weight: 600; margin-bottom: 5px; }
.step-body  { font-size: 13px; color: var(--muted); line-height: 1.6; }
.step-code  {
  display: inline-block; background: #0D0F16;
  border: 1px solid var(--border); border-radius: 7px;
  padding: 8px 14px; font-family: var(--mono); font-size: 12px;
  color: var(--green); margin-top: 8px; white-space: pre;
}

/* ── Tech stack table ── */
.tbl { width: 100%; border-collapse: collapse; margin-top: 28px; }
.tbl th { text-align: left; padding: 10px 14px; font-size: 11px; font-weight: 600;
          text-transform: uppercase; letter-spacing: .05em; color: var(--muted);
          border-bottom: 1px solid var(--border); }
.tbl td { padding: 12px 14px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,.04); }
.tbl tr:hover td { background: rgba(255,255,255,.02); }
.pill {
  display: inline-block; padding: 2px 9px; border-radius: 20px;
  font-size: 11px; font-weight: 600;
}

/* ── Floating particles ── */
.particles { position: fixed; inset: 0; pointer-events: none; z-index: 0; overflow: hidden; }
.particle {
  position: absolute; width: 2px; height: 2px; border-radius: 50%;
  background: rgba(229,72,77,.6);
  animation: particleFloat linear infinite;
}
@keyframes particleFloat {
  0%   { transform: translateY(100vh) scale(0); opacity: 0; }
  10%  { opacity: 1; }
  90%  { opacity: .8; }
  100% { transform: translateY(-10vh) scale(1); opacity: 0; }
}

/* ── Footer ── */
.footer {
  text-align: center; padding: 40px 20px;
  color: var(--muted); font-size: 13px;
  border-top: 1px solid var(--border);
}
.footer strong { color: var(--text); }

/* ── Nav ── */
.nav {
  position: fixed; top: 0; left: 0; right: 0; z-index: 100;
  background: rgba(11,13,18,.85);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  display: flex; align-items: center; justify-content: space-between;
}
.nav-logo {
  display: flex; align-items: center; gap: 8px;
  font-weight: 700; font-size: 16px; color: var(--text);
  text-decoration: none;
}
.nav-logo svg { width: 28px; height: 28px; }
.nav-links { display: flex; gap: 24px; }
.nav-links a { color: var(--muted); text-decoration: none; font-size: 13.5px; font-weight: 500; transition: color .15s; }
.nav-links a:hover { color: var(--text); }
@media (max-width: 640px) { .nav-links { display: none; } .flow { min-width: 600px; } }
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>

<!-- Floating particles -->
<div class="particles" id="particles"></div>

<!-- Nav -->
<nav class="nav">
  <a class="nav-logo" href="#">
    <svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-label="Aegis Logo">
      <circle cx="100" cy="100" r="97" fill="#0A0C14"/>
      <circle cx="100" cy="100" r="94" fill="#2D3748" stroke="#4A5568" stroke-width="0.5"/>
      <circle cx="100" cy="100" r="77" fill="#111827"/>
      <circle cx="100" cy="100" r="77" fill="none" stroke="#2D3748" stroke-width="1.2"/>
      <polygon points="100,28 73,148 88,148 106,52" fill="#C53030"/>
      <polygon points="100,28 127,148 112,148 94,52" fill="#C53030"/>
      <polygon points="100,28 88,62 106,52" fill="#E05252" opacity="0.7"/>
      <rect x="74" y="104" width="52" height="14" rx="2" fill="#C53030"/>
    </svg>
    Aegis
  </a>
  <div class="nav-links">
    <a href="#features">Features</a>
    <a href="#architecture">Architecture</a>
    <a href="#install">Install</a>
    <a href="#ai">AI Engine</a>
    <a href="#testing">Testing</a>
  </div>
</nav>

<!-- Hero -->
<section class="hero">
  <div class="grid-bg"></div>

  <div class="shield-wrap">
    <div class="shield-glow"></div>
    <svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-label="Aegis Shield">
      <circle cx="100" cy="100" r="97" fill="#0A0C14"/>
      <circle cx="100" cy="100" r="94" fill="#2D3748" stroke="#4A5568" stroke-width="0.5"/>
      <g stroke="#1A202C" stroke-width="1.2" fill="none" opacity="0.8">
        <path d="M100 6 A94 94 0 0 1 181 53"/><path d="M181 53 A94 94 0 0 1 194 100"/>
        <path d="M194 100 A94 94 0 0 1 160 172"/><path d="M160 172 A94 94 0 0 1 100 194"/>
        <path d="M100 194 A94 94 0 0 1 40 172"/><path d="M40 172 A94 94 0 0 1 6 100"/>
        <path d="M6 100 A94 94 0 0 1 19 53"/><path d="M19 53 A94 94 0 0 1 100 6"/>
      </g>
      <g fill="#4A5568"><circle cx="100" cy="8" r="3"/><circle cx="176" cy="40" r="3"/><circle cx="192" cy="100" r="3"/><circle cx="176" cy="160" r="3"/><circle cx="100" cy="192" r="3"/><circle cx="24" cy="160" r="3"/><circle cx="8" cy="100" r="3"/><circle cx="24" cy="40" r="3"/></g>
      <g fill="#718096"><circle cx="100" cy="8" r="1.5"/><circle cx="176" cy="40" r="1.5"/><circle cx="192" cy="100" r="1.5"/><circle cx="176" cy="160" r="1.5"/><circle cx="100" cy="192" r="1.5"/><circle cx="24" cy="160" r="1.5"/><circle cx="8" cy="100" r="1.5"/><circle cx="24" cy="40" r="1.5"/></g>
      <circle cx="100" cy="100" r="77" fill="#111827"/>
      <circle cx="100" cy="100" r="77" fill="none" stroke="#2D3748" stroke-width="1.2"/>
      <polygon points="100,28 73,148 88,148 106,52" fill="#C53030"/>
      <polygon points="100,28 127,148 112,148 94,52" fill="#C53030"/>
      <polygon points="100,28 88,62 106,52" fill="#E05252" opacity="0.7"/>
      <rect x="74" y="104" width="52" height="14" rx="2" fill="#C53030"/>
      <circle cx="100" cy="100" r="63" fill="none" stroke="#E53E3E" stroke-width="0.7" stroke-dasharray="4 6" opacity="0.3"/>
    </svg>
  </div>

  <h1 class="hero-title">Aegis</h1>
  <p class="hero-sub">Multi-Site Honeypot &amp; AI-Powered Attack Intelligence Platform</p>

  <div class="typing-wrap">
    <span class="typing">$ python3 ai_model.py --args '{"action":"generate_users","system_type":"EDUCATION"}'</span>
  </div>

  <div class="badges">
    <span class="badge badge-red">PHP 8.0+ OOP</span>
    <span class="badge badge-blue">Python 3.8+</span>
    <span class="badge badge-green">Local AI — No API</span>
    <span class="badge badge-purple">39 Files</span>
    <span class="badge badge-amber">SIMAP Compatible</span>
    <span class="badge badge-red">East Africa Ready</span>
  </div>

  <div class="cta-row">
    <a class="btn btn-primary" href="#install">Get Started</a>
    <a class="btn btn-ghost" href="#architecture">View Architecture</a>
  </div>

  <div class="scroll-hint">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.3)" stroke-width="2"><path d="M7 10l5 5 5-5"/></svg>
  </div>
</section>

<!-- Stats -->
<section class="section">
  <div class="section-tag">By the numbers</div>
  <h2 class="section-title">Built for production</h2>
  <div class="stats">
    <div class="stat"><div class="stat-val" style="color:var(--red)">39</div><div class="stat-lbl">PHP + Python Files</div></div>
    <div class="stat"><div class="stat-val" style="color:var(--blue)">21</div><div class="stat-lbl">PHP Classes</div></div>
    <div class="stat"><div class="stat-val" style="color:var(--green)">7</div><div class="stat-lbl">Fake Tech Stacks</div></div>
    <div class="stat"><div class="stat-val" style="color:var(--purple)">8</div><div class="stat-lbl">System Types Detected</div></div>
    <div class="stat"><div class="stat-val" style="color:var(--amber)">5</div><div class="stat-lbl">Attack Phases Tracked</div></div>
    <div class="stat"><div class="stat-val" style="color:var(--red)">0</div><div class="stat-lbl">External AI APIs</div></div>
  </div>
</section>

<!-- Features -->
<section class="section" id="features">
  <div class="section-tag">Capabilities</div>
  <h2 class="section-title">What Aegis does</h2>
  <p class="section-body">A complete defensive platform — detects, deceives, tracks, and reports attackers across multiple sites.</p>

  <div class="features">
    <div class="feat" style="--accent:var(--red)">
      <div class="feat-icon" style="background:rgba(229,72,77,.12)">🛡️</div>
      <div class="feat-title">AI-Adaptive Honeypot</div>
      <div class="feat-body">Detects the system type under attack and generates contextually appropriate fake data. A student portal attack returns student records — a WiFi attack returns subscriber/MAC data. Never the wrong data.</div>
    </div>
    <div class="feat" style="--accent:var(--blue)">
      <div class="feat-icon" style="background:rgba(59,130,246,.12)">🕵️</div>
      <div class="feat-title">Language Fingerprint Deception</div>
      <div class="feat-body">Every response header, cookie name, error format, and HTML meta tag matches a fake tech stack — Django, Spring Boot, Rails, Node.js, ASP.NET, or Go. WhatWeb and Wappalyzer see the fake, never PHP.</div>
    </div>
    <div class="feat" style="--accent:var(--green)">
      <div class="feat-icon" style="background:rgba(34,197,94,.12)">🤖</div>
      <div class="feat-title">Local AI Model</div>
      <div class="feat-body">Generates realistic fake data using Faker + East African name banks + system templates. No external API, no token cost, no internet required. Students have Tanzanian names and CBE student IDs.</div>
    </div>
    <div class="feat" style="--accent:var(--purple)">
      <div class="feat-icon" style="background:rgba(139,92,246,.12)">📊</div>
      <div class="feat-title">Attacker Profiling</div>
      <div class="feat-body">Classifies skill level (script kiddie / intermediate / advanced) and tracks attack phase from recon through destruction. Advanced attackers get highly convincing fabrications; script kiddies get simple bait.</div>
    </div>
    <div class="feat" style="--accent:var(--amber)">
      <div class="feat-icon" style="background:rgba(245,158,11,.12)">📱</div>
      <div class="feat-title">WhatsApp Alerts</div>
      <div class="feat-body">Real-time alerts via Meta Cloud API when severity crosses the threshold. "Boss Mmari njoo uku uone jinsi attacker anafanya uharibifu" — sends attacker IP, attack type, and severity in Swahili.</div>
    </div>
    <div class="feat" style="--accent:var(--red)">
      <div class="feat-icon" style="background:rgba(229,72,77,.12)">🎥</div>
      <div class="feat-title">Physical Tracker (YOLOv5)</div>
      <div class="feat-body">For physically-present attackers in camera-covered areas. Auto-triggered when severity ≥ 80%. Saves snapshots with the attacker's IP overlaid, records video evidence.</div>
    </div>
    <div class="feat" style="--accent:var(--blue)">
      <div class="feat-icon" style="background:rgba(59,130,246,.12)">🔍</div>
      <div class="feat-title">8-Layer Payload Decoder</div>
      <div class="feat-body">URL decode ×3, HTML entities ×2, hex escapes, base64 blobs, full-width Unicode, SQL comment stripping. Encoded payloads (%27 OR %271%27%3D%271) are decoded before pattern matching.</div>
    </div>
    <div class="feat" style="--accent:var(--green)">
      <div class="feat-icon" style="background:rgba(34,197,94,.12)">🔐</div>
      <div class="feat-title">RBAC + Anti-IDOR</div>
      <div class="feat-body">Role hierarchy (GUEST→CLIENT→SUPPORT→FINANCE→MANAGER→ADMIN) with double-lock ownership: PHP class check + DB WHERE owner_id=? so even if the class has a bug, the query still enforces ownership.</div>
    </div>
    <div class="feat" style="--accent:var(--purple)">
      <div class="feat-icon" style="background:rgba(139,92,246,.12)">🌐</div>
      <div class="feat-title">Multi-Site + Remote Reporting</div>
      <div class="feat-body">Shared DB mode for your own servers, or HTTPS POST via RemoteReporter for client sites. One Aegis dashboard monitors all sites with per-site attack stats, origin maps, and credential logs.</div>
    </div>
  </div>
</section>

<!-- Architecture -->
<section class="section" id="architecture">
  <div class="section-tag">System Design</div>
  <h2 class="section-title">Request flow</h2>
  <p class="section-body">Every incoming request passes through Aegis before reaching the real application. The attacker never knows.</p>

  <div class="arch">
    <div class="flow">
      <div class="flow-node">
        <div class="flow-box red">Incoming<br>Request<div class="sub">Any attacker</div></div>
      </div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">
        <div class="flow-box blue">LanguageDeception<br><span class="sub">Fake headers on every req</span></div>
      </div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">
        <div class="flow-box amber">AdvancedDetection<br><span class="sub">8-layer decode + classify</span></div>
      </div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">
        <div class="flow-box purple">AttackerProfiler<br><span class="sub">Skill + Phase</span></div>
      </div>
      <div class="flow-arrow">→</div>
      <div class="flow-node">
        <div class="flow-box green">Diversion<br><span class="sub">AI fake data → exit</span></div>
      </div>
    </div>
    <p style="font-size:12px;color:var(--muted);margin-top:16px;text-align:center">
      Severity &lt; 60: request reaches your real app &nbsp;|&nbsp; Severity ≥ 60 or banned: silently diverted forever
    </p>
  </div>
</section>

<!-- Installation -->
<section class="section" id="install">
  <div class="section-tag">Quick Start</div>
  <h2 class="section-title">Up in 4 steps</h2>

  <ul class="steps" id="steps">
    <li class="step">
      <div class="step-num">1</div>
      <div class="step-content">
        <div class="step-title">Import the database</div>
        <div class="step-body">All tables are prefixed <code style="color:var(--amber)">aegis_</code> — safe to run alongside SIMAP or any existing schema.</div>
        <div class="step-code">mysql -u root -p simap_db &lt; aegis/sql/schema.sql</div>
      </div>
    </li>
    <li class="step">
      <div class="step-num">2</div>
      <div class="step-content">
        <div class="step-title">Install Python dependencies</div>
        <div class="step-body">Only Faker is required. All other modules use Python stdlib.</div>
        <div class="step-code">pip install faker</div>
      </div>
    </li>
    <li class="step">
      <div class="step-num">3</div>
      <div class="step-content">
        <div class="step-title">Drop the bootstrap into your site</div>
        <div class="step-body">One line at the top of your <code style="color:var(--amber)">index.php</code> — before any output or routing.</div>
        <div class="step-code">define('AEGIS_INSTALL_KEY', 'hp_your_key');
require_once __DIR__ . '/aegis/aegis-bootstrap.php';</div>
      </div>
    </li>
    <li class="step">
      <div class="step-num">4</div>
      <div class="step-content">
        <div class="step-title">Set environment variables</div>
        <div class="step-body">Add to your <code style="color:var(--amber)">.env</code> or Apache/Nginx virtual host config.</div>
        <div class="step-code">DB_HOST=127.0.0.1
DB_NAME=simap_db
DB_USER=your_user
DB_PASS=your_password
WHATSAPP_ACCESS_TOKEN=your_token
HONEYPOT_ALERT_RECIPIENT=255698741459</div>
      </div>
    </li>
  </ul>
</section>

<!-- AI Engine -->
<section class="section" id="ai">
  <div class="section-tag">Local AI</div>
  <h2 class="section-title">No external API needed</h2>
  <p class="section-body">The local Python model generates contextually convincing fake data for 8 system types — offline, free, and fast.</p>

  <div class="code-wrap">
    <div class="code-bar">
      <div class="dot-r"></div><div class="dot-y"></div><div class="dot-g"></div>
      <span class="code-file">python/ai_model.py</span>
    </div>
    <pre class="code"><span class="t-cm"># Generate 6 fake student records for an education portal</span>
$ python3 ai_model.py --args <span class="t-str">'{"action":"generate_users","system_type":"EDUCATION","count":6}'</span>

<span class="t-cm"># Response — Tanzanian names, CBE student IDs, GPA, program</span>
{
  <span class="t-str">"users"</span>: [
    { <span class="t-str">"id"</span>: <span class="t-num">1</span>, <span class="t-str">"username"</span>: <span class="t-str">"amina.juma"</span>, <span class="t-str">"role"</span>: <span class="t-str">"Student"</span>,
      <span class="t-str">"student_id"</span>: <span class="t-str">"CBE2024001"</span>, <span class="t-str">"program"</span>: <span class="t-str">"BIT"</span>, <span class="t-str">"gpa"</span>: <span class="t-num">3.42</span> },
    { <span class="t-str">"id"</span>: <span class="t-num">2</span>, <span class="t-str">"username"</span>: <span class="t-str">"baraka.hassan"</span>, <span class="t-str">"role"</span>: <span class="t-str">"Lecturer"</span>,
      <span class="t-str">"staff_id"</span>: <span class="t-str">"LEC2019042"</span>, <span class="t-str">"program"</span>: <span class="t-str">"BCOM"</span>, <span class="t-str">"gpa"</span>: <span class="t-num">null</span> }
  ]
}

<span class="t-cm"># Select fake tech (consistent per site — seeded by site_id)</span>
$ python3 ai_model.py --args <span class="t-str">'{"action":"fake_tech","real":"PHP","site_id":1}'</span>

{ <span class="t-str">"key"</span>: <span class="t-str">"DJANGO"</span>, <span class="t-str">"server"</span>: <span class="t-str">"nginx/1.24.0"</span>,
  <span class="t-str">"framework"</span>: <span class="t-str">"Django/4.2.7"</span>, <span class="t-str">"language"</span>: <span class="t-str">"Python 3.11"</span>,
  <span class="t-str">"session_cookie"</span>: <span class="t-str">"sessionid"</span>, <span class="t-str">"token_header"</span>: <span class="t-str">"Token"</span> }</pre>
  </div>
</section>

<!-- Tech Stack table -->
<section class="section" id="testing">
  <div class="section-tag">Tech Deception</div>
  <h2 class="section-title">What scanners see</h2>
  <p class="section-body">PHP is never revealed. The fake tech is consistent per site — every scan of the same site always shows the same false stack.</p>

  <table class="tbl">
    <thead>
      <tr>
        <th>Real Stack</th>
        <th>Possible Fake Stacks Shown</th>
        <th>Fake Cookie</th>
        <th>Fake Server Header</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><span class="pill" style="background:rgba(229,72,77,.15);color:#F87171">PHP 8.x</span></td>
        <td>Django · Spring Boot · Rails · Node.js · ASP.NET · Go</td>
        <td><code style="color:var(--amber);font-family:var(--mono);font-size:12px">sessionid / JSESSIONID / connect.sid</code></td>
        <td><code style="color:var(--green);font-family:var(--mono);font-size:12px">nginx/1.24.0 · Puma/6.3.1 · IIS/10.0</code></td>
      </tr>
      <tr>
        <td><span class="pill" style="background:rgba(59,130,246,.15);color:#60A5FA">Python</span></td>
        <td>Spring Boot · ASP.NET · Node.js · Go · Laravel</td>
        <td><code style="color:var(--amber);font-family:var(--mono);font-size:12px">JSESSIONID / ASP.NET_SessionId</code></td>
        <td><code style="color:var(--green);font-family:var(--mono);font-size:12px">Apache/2.4.57 · Microsoft-IIS/10.0</code></td>
      </tr>
    </tbody>
  </table>

  <div class="code-wrap" style="margin-top:28px">
    <div class="code-bar">
      <div class="dot-r"></div><div class="dot-y"></div><div class="dot-g"></div>
      <span class="code-file">Terminal — attacker's Kali machine</span>
    </div>
    <pre class="code"><span class="t-cm"># Attacker scans your PHP site with WhatWeb</span>
$ whatweb https://yoursite.co.tz

<span class="t-const">yoursite.co.tz</span> [200 OK]
  <span class="t-str">Django</span>[4.2.7]
  <span class="t-str">Python</span>[3.11.4]
  <span class="t-str">nginx</span>[1.24.0]
  <span class="t-str">Cookies</span>[sessionid]
  <span class="t-str">Meta-Generator</span>[Django]

<span class="t-cm"># Attacker checks headers with curl</span>
$ curl -I https://yoursite.co.tz

HTTP/2 200
<span class="t-fn">Server:</span>       nginx/1.24.0
<span class="t-fn">X-Framework:</span>  Django/4.2.7
<span class="t-fn">Set-Cookie:</span>   sessionid=a3f8b2...; HttpOnly
<span class="t-fn">X-Request-ID:</span> 7e2a4f8c1b3d9e0a
<span class="t-fn">Vary:</span>         Accept-Encoding, Accept

<span class="t-cm"># Attacker now wastes hours targeting Django — not PHP</span></pre>
  </div>
</section>

<!-- File map -->
<section class="section">
  <div class="section-tag">Project Structure</div>
  <h2 class="section-title">39 files, zero dependencies for core features</h2>

  <div class="code-wrap">
    <div class="code-bar">
      <div class="dot-r"></div><div class="dot-y"></div><div class="dot-g"></div>
      <span class="code-file">aegis/</span>
    </div>
    <pre class="code">aegis/
├── <span class="t-fn">aegis-bootstrap.php</span>        <span class="t-cm">← drop-in, one line in your index.php</span>
├── <span class="t-fn">composer.json</span>               <span class="t-cm">← FPDF for PDF reports</span>
├── config/
│   └── <span class="t-fn">Database.php</span>            <span class="t-cm">← PDO singleton</span>
├── classes/
│   ├── <span class="t-kw">AdvancedDetection.php</span>   <span class="t-cm">← 8-layer decode pipeline</span>
│   ├── <span class="t-kw">AIDeceptionEngine.php</span>   <span class="t-cm">← bridges PHP → Python AI</span>
│   ├── <span class="t-kw">AlertNotifier.php</span>       <span class="t-cm">← WhatsApp + tracker trigger</span>
│   ├── <span class="t-kw">AttackerProfiler.php</span>    <span class="t-cm">← skill level + phase detection</span>
│   ├── <span class="t-kw">Authorization.php</span>       <span class="t-cm">← RBAC + anti-IDOR double-lock</span>
│   ├── <span class="t-kw">Diversion.php</span>           <span class="t-cm">← AI-adaptive honeypot engine</span>
│   ├── <span class="t-kw">LanguageDeception.php</span>   <span class="t-cm">← fires on EVERY request</span>
│   ├── <span class="t-kw">SystemProfiler.php</span>      <span class="t-cm">← detects system type</span>
│   └── <span class="t-kw">TechDeception.php</span>       <span class="t-cm">← fake headers, cookies, errors</span>
├── honeypot/
│   ├── <span class="t-fn">Middleware.php</span>          <span class="t-cm">← shared DB install</span>
│   └── <span class="t-fn">RemoteReporter.php</span>      <span class="t-cm">← HTTPS POST for remote sites</span>
├── bridge/
│   └── <span class="t-fn">PythonBridge.php</span>        <span class="t-cm">← subprocess → JSON</span>
├── python/
│   ├── <span class="t-str">ai_model.py</span>             <span class="t-cm">← local AI, no API</span>
│   ├── <span class="t-str">threat_intelligence.py</span>  <span class="t-cm">← IOC feeds, SQLite</span>
│   ├── <span class="t-str">deception_grid.py</span>       <span class="t-cm">← honeytokens</span>
│   ├── <span class="t-str">network_forensics.py</span>    <span class="t-cm">← port scan detection</span>
│   └── <span class="t-str">physical_tracker.py</span>     <span class="t-cm">← YOLOv5 camera tracker</span>
├── admin/
│   ├── <span class="t-fn">dashboard.php</span>           <span class="t-cm">← main browser UI</span>
│   └── api/ …                  <span class="t-cm">← 9 JSON API endpoints</span>
└── sql/
    └── <span class="t-fn">schema.sql</span>              <span class="t-cm">← all tables prefixed aegis_</span></pre>
  </div>
</section>

<!-- Footer -->
<footer class="footer">
  <p>Built by <strong>Mmari</strong> · CBE Tanzania BIT Level 2 · Aegis v1.0.0</p>
  <p style="margin-top:6px">PHP 8.0+ · Python 3.8+ · MySQL 8 · YOLOv5 · No external AI APIs</p>
</footer>

<script>
// ── Generate floating particles ──
(function() {
  const container = document.getElementById('particles');
  const count = 25;
  for (let i = 0; i < count; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.cssText = [
      `left:${Math.random()*100}%`,
      `animation-duration:${6 + Math.random()*12}s`,
      `animation-delay:${Math.random()*10}s`,
      `width:${1 + Math.random()*2}px`,
      `height:${1 + Math.random()*2}px`,
      `opacity:${0.3 + Math.random()*0.7}`,
    ].join(';');
    container.appendChild(p);
  }
})();

// ── Scroll-triggered step animation ──
const steps = document.querySelectorAll('.step');
const obs = new IntersectionObserver(entries => {
  entries.forEach((e, i) => {
    if (e.isIntersecting) {
      setTimeout(() => e.target.classList.add('visible'), i * 120);
    }
  });
}, { threshold: 0.2 });
steps.forEach(s => obs.observe(s));

// ── Animate stat values ──
document.querySelectorAll('.stat-val').forEach(el => {
  const target = parseInt(el.textContent);
  if (isNaN(target)) return;
  const io = new IntersectionObserver(([entry]) => {
    if (!entry.isIntersecting) return;
    io.disconnect();
    let start = 0;
    const step = () => {
      start += Math.ceil(target / 20);
      el.textContent = Math.min(start, target);
      if (start < target) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, { threshold: 0.5 });
  io.observe(el);
});
</script>
</body>
</html>
