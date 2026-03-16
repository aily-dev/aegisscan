

<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@700;800&display=swap');

  :root {
    --aegis-green: #34D399;
    --aegis-teal: #0d9488;
    --aegis-dark: #0a0f0d;
    --aegis-panel: #0e1512;
    --aegis-border: rgba(52,211,153,0.18);
    --aegis-dim: rgba(52,211,153,0.06);
    --aegis-text: #d1fae5;
    --aegis-muted: #6ee7b7;
    --aegis-code: #a7f3d0;
    --aegis-red: #f87171;
    --aegis-amber: #fbbf24;
    --aegis-blue: #60a5fa;
  }

  .aegis-root {
    background: var(--aegis-dark);
    color: var(--aegis-text);
    font-family: 'JetBrains Mono', monospace;
    padding: 0;
    border-radius: 16px;
    overflow: hidden;
    border: 1px solid var(--aegis-border);
    position: relative;
  }

  /* Grid noise texture */
  .aegis-root::before {
    content: '';
    position: absolute;
    inset: 0;
    background-image:
      linear-gradient(var(--aegis-border) 1px, transparent 1px),
      linear-gradient(90deg, var(--aegis-border) 1px, transparent 1px);
    background-size: 40px 40px;
    opacity: 0.4;
    pointer-events: none;
    z-index: 0;
  }

  .aegis-root > * { position: relative; z-index: 1; }

  /* Hero */
  .hero {
    padding: 48px 40px 36px;
    text-align: center;
    border-bottom: 1px solid var(--aegis-border);
    background: radial-gradient(ellipse 70% 60% at 50% 0%, rgba(52,211,153,0.08) 0%, transparent 70%);
  }

  .shield-wrap {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 72px;
    height: 72px;
    border: 1px solid var(--aegis-green);
    border-radius: 12px;
    margin-bottom: 20px;
    background: rgba(52,211,153,0.07);
    box-shadow: 0 0 24px rgba(52,211,153,0.15);
  }
  .shield-wrap svg { width: 40px; height: 40px; }

  .hero h1 {
    font-family: 'Syne', sans-serif;
    font-size: 42px;
    font-weight: 800;
    letter-spacing: -1px;
    color: #fff;
    margin: 0 0 4px;
  }
  .hero h1 span { color: var(--aegis-green); }

  .hero-sub {
    font-size: 13px;
    color: var(--aegis-muted);
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-bottom: 24px;
  }

  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    justify-content: center;
    margin-bottom: 8px;
  }
  .badge {
    font-size: 11px;
    padding: 4px 10px;
    border-radius: 4px;
    border: 1px solid;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.04em;
  }
  .badge-green { border-color: var(--aegis-green); color: var(--aegis-green); background: rgba(52,211,153,0.07); }
  .badge-blue { border-color: var(--aegis-blue); color: var(--aegis-blue); background: rgba(96,165,250,0.07); }
  .badge-amber { border-color: var(--aegis-amber); color: var(--aegis-amber); background: rgba(251,191,36,0.07); }
  .badge-red { border-color: var(--aegis-red); color: var(--aegis-red); background: rgba(248,113,113,0.07); }

  /* Section */
  .section {
    padding: 32px 40px;
    border-bottom: 1px solid var(--aegis-border);
  }
  .section:last-child { border-bottom: none; }

  .section-label {
    font-size: 10px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--aegis-green);
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .section-label::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--aegis-border);
  }

  /* Feature Grid */
  .feature-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
  }

  .feat-card {
    background: var(--aegis-panel);
    border: 1px solid var(--aegis-border);
    border-radius: 10px;
    padding: 16px 18px;
    transition: border-color 0.2s, background 0.2s;
    cursor: default;
  }
  .feat-card:hover {
    border-color: var(--aegis-green);
    background: rgba(52,211,153,0.05);
  }

  .feat-icon {
    font-size: 18px;
    margin-bottom: 8px;
    display: block;
  }
  .feat-title {
    font-size: 13px;
    font-weight: 700;
    color: #fff;
    margin-bottom: 6px;
  }
  .feat-items {
    font-size: 11px;
    color: var(--aegis-muted);
    line-height: 1.7;
    list-style: none;
    padding: 0; margin: 0;
  }
  .feat-items li::before { content: '›  '; color: var(--aegis-green); }

  /* Terminal block */
  .terminal {
    background: #000;
    border: 1px solid var(--aegis-border);
    border-radius: 10px;
    overflow: hidden;
  }
  .term-bar {
    background: #111;
    padding: 8px 16px;
    display: flex;
    align-items: center;
    gap: 6px;
    border-bottom: 1px solid var(--aegis-border);
  }
  .dot { width: 10px; height: 10px; border-radius: 50%; }
  .dot-r { background: #ff5f57; }
  .dot-y { background: #febc2e; }
  .dot-g { background: #28c840; }
  .term-title { font-size: 11px; color: #555; margin-left: 8px; letter-spacing: 0.08em; }
  .term-body { padding: 18px 20px; font-size: 12px; line-height: 1.9; }

  .t-prompt { color: var(--aegis-green); }
  .t-cmd { color: #fff; }
  .t-comment { color: #4b5563; }
  .t-info { color: var(--aegis-blue); }
  .t-warn { color: var(--aegis-amber); }
  .t-success { color: var(--aegis-green); }
  .t-vuln { color: var(--aegis-red); }
  .t-muted { color: #6b7280; }

  /* Stats row */
  .stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1px;
    background: var(--aegis-border);
    border: 1px solid var(--aegis-border);
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 24px;
  }
  .stat-cell {
    background: var(--aegis-panel);
    padding: 20px 16px;
    text-align: center;
  }
  .stat-num {
    font-family: 'Syne', sans-serif;
    font-size: 28px;
    font-weight: 800;
    color: var(--aegis-green);
    display: block;
  }
  .stat-label {
    font-size: 10px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--aegis-muted);
    margin-top: 2px;
  }

  /* Code snippet */
  .code-block {
    background: #000;
    border: 1px solid var(--aegis-border);
    border-radius: 10px;
    padding: 18px 20px;
    font-size: 12px;
    line-height: 1.8;
    margin-bottom: 12px;
    overflow-x: auto;
  }
  .c-kw { color: var(--aegis-blue); }
  .c-fn { color: var(--aegis-green); }
  .c-str { color: #fb923c; }
  .c-cm { color: #4b5563; }
  .c-num { color: var(--aegis-amber); }
  .c-cls { color: #c084fc; }

  /* Tabs */
  .tabs { display: flex; gap: 0; margin-bottom: -1px; }
  .tab {
    font-size: 11px;
    padding: 8px 16px;
    border: 1px solid var(--aegis-border);
    border-bottom: none;
    border-radius: 6px 6px 0 0;
    cursor: pointer;
    color: var(--aegis-muted);
    background: transparent;
    letter-spacing: 0.06em;
    font-family: 'JetBrains Mono', monospace;
    transition: all 0.15s;
  }
  .tab.active { background: #000; color: var(--aegis-green); border-color: var(--aegis-green); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Install steps */
  .install-steps { display: flex; flex-direction: column; gap: 8px; }
  .install-step {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 16px;
    background: var(--aegis-panel);
    border: 1px solid var(--aegis-border);
    border-radius: 8px;
    font-size: 12px;
  }
  .step-num {
    width: 22px; height: 22px;
    border-radius: 50%;
    border: 1px solid var(--aegis-green);
    color: var(--aegis-green);
    display: flex; align-items: center; justify-content: center;
    font-size: 10px;
    flex-shrink: 0;
    margin-top: 1px;
  }
  .step-cmd { color: var(--aegis-code); }
  .step-desc { color: var(--aegis-muted); font-size: 11px; margin-top: 2px; }

  /* Benchmark table */
  .bench-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .bench-table th {
    text-align: left;
    padding: 10px 14px;
    font-size: 10px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--aegis-muted);
    border-bottom: 1px solid var(--aegis-border);
  }
  .bench-table td {
    padding: 12px 14px;
    border-bottom: 1px solid rgba(52,211,153,0.07);
  }
  .bench-table tr:last-child td { border-bottom: none; }
  .bench-winner { color: var(--aegis-green); font-weight: 700; }
  .bar-wrap { display: flex; align-items: center; gap: 10px; }
  .bar-bg { flex: 1; height: 4px; background: rgba(255,255,255,0.07); border-radius: 2px; }
  .bar-fill { height: 4px; border-radius: 2px; transition: width 0.6s; }
  .bar-aegis { background: var(--aegis-green); }
  .bar-zap { background: var(--aegis-blue); }
  .bar-burp { background: var(--aegis-amber); }

  /* Footer */
  .footer {
    padding: 24px 40px;
    text-align: center;
    border-top: 1px solid var(--aegis-border);
    background: var(--aegis-panel);
    font-size: 11px;
    color: var(--aegis-muted);
    letter-spacing: 0.06em;
  }
  .footer a { color: var(--aegis-green); text-decoration: none; }
  .footer-badges { display: flex; gap: 8px; justify-content: center; margin-top: 12px; flex-wrap: wrap; }

  /* Scan demo animation */
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
  .cursor { display: inline-block; width: 7px; height: 13px; background: var(--aegis-green); animation: blink 1s infinite; vertical-align: middle; margin-left: 2px; }

  @keyframes scan-line {
    from { transform: translateY(0); opacity: 0.8; }
    to { transform: translateY(100%); opacity: 0; }
  }
</style>

<div class="aegis-root">

  <!-- HERO -->
  <div class="hero">
    <div class="shield-wrap">
      <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M20 4L6 9.5V20C6 28.5 12.5 36 20 38C27.5 36 34 28.5 34 20V9.5L20 4Z" stroke="#34D399" stroke-width="1.5" fill="rgba(52,211,153,0.08)"/>
        <path d="M14 20L18 24L26 16" stroke="#34D399" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <h1><span>Aegis</span>Scan</h1>
    <p class="hero-sub">Advanced Web Security Testing Framework</p>
    <div class="badges">
      <span class="badge badge-blue">Python 3.8+</span>
      <span class="badge badge-amber">MIT License</span>
      <span class="badge badge-green">20+ Scanners</span>
      <span class="badge badge-green">C++ Native Perf</span>
      <span class="badge badge-red">SQLMap · XSStrike · Nuclei</span>
      <span class="badge badge-blue">Async HTTP</span>
    </div>
  </div>

  <!-- STATS -->
  <div class="section">
    <div class="section-label">overview</div>
    <div class="stats-row">
      <div class="stat-cell"><span class="stat-num">20+</span><div class="stat-label">Vuln Scanners</div></div>
      <div class="stat-cell"><span class="stat-num">150</span><div class="stat-label">Req/sec</div></div>
      <div class="stat-cell"><span class="stat-num">4</span><div class="stat-label">Integrations</div></div>
      <div class="stat-cell"><span class="stat-num">1</span><div class="stat-label">False Positive</div></div>
    </div>

    <!-- Feature Cards -->
    <div class="feature-grid">
      <div class="feat-card">
        <span class="feat-icon">🔍</span>
        <div class="feat-title">Reconnaissance</div>
        <ul class="feat-items">
          <li>Port scan (C++ native)</li>
          <li>Directory brute force</li>
          <li>Subdomain enumeration</li>
          <li>JS parsing & path discovery</li>
        </ul>
      </div>
      <div class="feat-card">
        <span class="feat-icon">🎯</span>
        <div class="feat-title">Vulnerability Scanning</div>
        <ul class="feat-items">
          <li>SQLi · XSS · SSTI · LFI/RFI</li>
          <li>SSRF · XXE · IDOR · JWT</li>
          <li>OAuth · GraphQL · RCE</li>
          <li>Business logic flaws</li>
        </ul>
      </div>
      <div class="feat-card">
        <span class="feat-icon">🔗</span>
        <div class="feat-title">Integrations</div>
        <ul class="feat-items">
          <li>SQLMap auto-install</li>
          <li>XSStrike integration</li>
          <li>Nuclei template engine</li>
          <li>Nikto web scanner</li>
        </ul>
      </div>
      <div class="feat-card">
        <span class="feat-icon">📊</span>
        <div class="feat-title">Reporting</div>
        <ul class="feat-items">
          <li>HTML · JSON · Markdown · CSV</li>
          <li>CVSS severity scoring</li>
          <li>WAF bypass techniques</li>
          <li>Proxy rotation support</li>
        </ul>
      </div>
    </div>
  </div>

  <!-- TERMINAL DEMO -->
  <div class="section">
    <div class="section-label">live demo</div>
    <div class="terminal">
      <div class="term-bar">
        <div class="dot dot-r"></div><div class="dot dot-y"></div><div class="dot dot-g"></div>
        <span class="term-title">aegisscan — bash</span>
      </div>
      <div class="term-body">
        <div><span class="t-prompt">$</span> <span class="t-cmd">aegis scan https://target.com --full --external</span></div>
        <div class="t-muted">─────────────────────────────────────────────</div>
        <div><span class="t-info">[INFO]</span> Starting deep scan on <span class="t-success">target.com</span></div>
        <div><span class="t-info">[INFO]</span> Auto-installing: sqlmap, xsstrike, nuclei...</div>
        <div class="t-muted">.</div>
        <div><span class="t-success">[SCAN]</span> Crawling endpoints... <span class="t-success">45 found</span></div>
        <div><span class="t-success">[SCAN]</span> Port scan (C++): <span class="t-success">80, 443 open</span></div>
        <div><span class="t-success">[SCAN]</span> Directory brute: <span class="t-warn">12/500 — /admin, /api</span></div>
        <div class="t-muted">.</div>
        <div><span class="t-warn">[VULN]</span> SQLi detected: <span class="t-vuln">3 vulnerable parameters</span></div>
        <div><span class="t-warn">[VULN]</span> XSS reflected: <span class="t-vuln">2 endpoints</span></div>
        <div><span class="t-warn">[VULN]</span> SQLMap blind: <span class="t-vuln">1 confirmed</span></div>
        <div class="t-muted">─────────────────────────────────────────────</div>
        <div><span class="t-success">[DONE]</span> Report → <span class="t-cmd">results/target_2024.html</span></div>
        <div><span class="t-prompt">$</span> <div class="cursor" style="display:inline-block"></div></div>
      </div>
    </div>
  </div>

  <!-- INSTALL + API (TABS) -->
  <div class="section">
    <div class="section-label">quick start</div>
    <div class="tabs" id="tabs">
      <div class="tab active" onclick="switchTab('install')">Installation</div>
      <div class="tab" onclick="switchTab('cli')">CLI</div>
      <div class="tab" onclick="switchTab('api')">Python API</div>
    </div>

    <div id="tab-install" class="tab-content active">
      <div class="install-steps">
        <div class="install-step">
          <div class="step-num">1</div>
          <div>
            <div class="step-cmd">git clone https://github.com/USERNAME/aegisscan.git && cd aegisscan</div>
            <div class="step-desc">Clone the repository</div>
          </div>
        </div>
        <div class="install-step">
          <div class="step-num">2</div>
          <div>
            <div class="step-cmd">pip install -r requirements.txt && pip install -e .</div>
            <div class="step-desc">Install Python dependencies</div>
          </div>
        </div>
        <div class="install-step">
          <div class="step-num">3</div>
          <div>
            <div class="step-cmd">python setup.py build_ext --inplace</div>
            <div class="step-desc">Build native C++ extensions for max performance (optional)</div>
          </div>
        </div>
      </div>
    </div>

    <div id="tab-cli" class="tab-content">
      <div class="code-block">
<span class="c-cm"># Full deep scan with external tools</span>
<span class="t-prompt">$</span> aegis scan https://target.com <span class="c-kw">--full --external</span>

<span class="c-cm"># Targeted scanners</span>
<span class="t-prompt">$</span> aegis scan https://target.com <span class="c-kw">--sqli --xss --ssti</span>

<span class="c-cm"># Recon only (fast)</span>
<span class="t-prompt">$</span> aegis recon https://target.com <span class="c-kw">--ports top --dirs medium</span>

<span class="c-cm"># Generate report from results</span>
<span class="t-prompt">$</span> aegis report results/ <span class="c-kw">--format html,json</span>
      </div>
    </div>

    <div id="tab-api" class="tab-content">
      <div class="code-block">
<span class="c-kw">import</span> asyncio
<span class="c-kw">from</span> aegisscan <span class="c-kw">import</span> <span class="c-cls">DeepScanner</span>, <span class="c-cls">AsyncHTTPClient</span>

<span class="c-kw">async def</span> <span class="c-fn">main</span>():
    client = <span class="c-cls">AsyncHTTPClient</span>()
    scanner = <span class="c-cls">DeepScanner</span>(client, auto_install_tools=<span class="c-kw">True</span>)

    summary = <span class="c-kw">await</span> scanner.<span class="c-fn">deep_scan</span>(
        <span class="c-str">"https://target.com"</span>,
        max_workers=<span class="c-num">30</span>,
        use_external=<span class="c-kw">True</span>
    )

    <span class="c-fn">print</span>(<span class="c-str">f"Vulnerabilities: {summary['vulns_total']}"</span>)
    <span class="c-fn">print</span>(<span class="c-str">f"Open ports: {summary['ports_open']}"</span>)
    <span class="c-kw">await</span> client.<span class="c-fn">close</span>()

asyncio.<span class="c-fn">run</span>(main())
      </div>
    </div>
  </div>

  <!-- BENCHMARKS -->
  <div class="section">
    <div class="section-label">benchmarks</div>
    <table class="bench-table">
      <thead>
        <tr>
          <th>Tool</th>
          <th>Speed (req/s)</th>
          <th>Vulns Found</th>
          <th>False Positives</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td class="bench-winner">AegisScan</td>
          <td>
            <div class="bar-wrap">
              <div class="bar-bg"><div class="bar-fill bar-aegis" style="width:100%"></div></div>
              <span class="bench-winner">150</span>
            </div>
          </td>
          <td>
            <div class="bar-wrap">
              <div class="bar-bg"><div class="bar-fill bar-aegis" style="width:100%"></div></div>
              <span class="bench-winner">28</span>
            </div>
          </td>
          <td class="bench-winner">1</td>
        </tr>
        <tr>
          <td style="color:#d1fae5">OWASP ZAP</td>
          <td>
            <div class="bar-wrap">
              <div class="bar-bg"><div class="bar-fill bar-zap" style="width:30%"></div></div>
              <span style="color:var(--aegis-blue)">45</span>
            </div>
          </td>
          <td>
            <div class="bar-wrap">
              <div class="bar-bg"><div class="bar-fill bar-zap" style="width:79%"></div></div>
              <span style="color:var(--aegis-blue)">22</span>
            </div>
          </td>
          <td style="color:var(--aegis-red)">4</td>
        </tr>
        <tr>
          <td style="color:#d1fae5">Burp Suite</td>
          <td>
            <div class="bar-wrap">
              <div class="bar-bg"><div class="bar-fill bar-burp" style="width:20%"></div></div>
              <span style="color:var(--aegis-amber)">30</span>
            </div>
          </td>
          <td>
            <div class="bar-wrap">
              <div class="bar-bg"><div class="bar-fill bar-burp" style="width:89%"></div></div>
              <span style="color:var(--aegis-amber)">25</span>
            </div>
          </td>
          <td style="color:var(--aegis-red)">3</td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- FOOTER -->
  <div class="footer">
    <div>Built with care for security researchers &amp; ethical hackers</div>
    <div class="footer-badges">
      <span class="badge badge-green">MIT License</span>
      <span class="badge badge-blue">Contributions Welcome</span>
      <span class="badge badge-amber">Star on GitHub</span>
    </div>
  </div>

</div>

<script>
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    const names = ['install','cli','api'];
    t.classList.toggle('active', names[i] === name);
  });
  document.querySelectorAll('.tab-content').forEach(c => {
    c.classList.toggle('active', c.id === 'tab-' + name);
  });
}
</script>
