// =============================================
// OWASP Dependency Check — Report Visualizer
// app.js — Core Logic
// =============================================

// ── DOM References ──────────────────────────
const landing        = document.getElementById('landing-section');
const dashboard      = document.getElementById('dashboard-section');
const scanOverlay    = document.getElementById('scan-overlay');
const fileInput      = document.getElementById('file-input');
const uploadCard     = document.getElementById('upload-card');
const terminalBody   = document.getElementById('terminal-body');
const scanProgress   = document.getElementById('scan-progress');
const scanProjectLbl = document.getElementById('scan-project-label');
const modalOverlay   = document.getElementById('modal-overlay');
const modalContent   = document.getElementById('modal-content');

// ── State ─────────────────────────────────
let reportData       = null;
let activeFilter     = 'ALL';
let severityChart    = null;

// ── Severity Config ────────────────────────
const SEV_CONFIG = {
  CRITICAL: { color: '#ff3e6c', label: 'Critical', order: 0 },
  HIGH:     { color: '#ff8c42', label: 'High',     order: 1 },
  MEDIUM:   { color: '#ffd166', label: 'Medium',   order: 2 },
  LOW:      { color: '#06d6a0', label: 'Low',      order: 3 },
  NONE:     { color: '#4a5568', label: 'None',      order: 4 },
};

function getSeverityColor(sev) {
  return SEV_CONFIG[sev?.toUpperCase()]?.color || '#4a5568';
}

function scoreToCSSClass(score) {
  if (score >= 9.0) return 'score-critical';
  if (score >= 7.0) return 'score-high';
  if (score >= 4.0) return 'score-medium';
  if (score > 0)   return 'score-low';
  return 'score-none';
}

function scoreToSeverity(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0)   return 'LOW';
  return 'NONE';
}

// ── File Upload / Drag & Drop ─────────────
uploadCard.addEventListener('click', () => fileInput.click());

uploadCard.addEventListener('dragover', (e) => {
  e.preventDefault();
  uploadCard.classList.add('drag-over');
});

uploadCard.addEventListener('dragleave', () => {
  uploadCard.classList.remove('drag-over');
});

uploadCard.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadCard.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) handleFile(file);
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files[0]) handleFile(e.target.files[0]);
});

function handleFile(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (!data.dependencies) {
        alert('⚠ This doesn\'t look like a valid OWASP Dependency Check JSON report.\n\nExpected a file with a "dependencies" array.');
        return;
      }
      processReport(data);
    } catch (err) {
      alert('⚠ Could not parse JSON file. Make sure it\'s a valid OWASP DC JSON report.');
    }
  };
  reader.readAsText(file);
}

// ── Demo Presets ───────────────────────────
// Inline data so the tool works by double-clicking index.html (no server needed)
const SAMPLE_REPORT = {"reportSchema":"1.1","scanInfo":{"engineVersion":"9.0.9","dataSource":[{"name":"NVD CVE Checked","timestamp":"2024-11-01T00:00:00Z"},{"name":"NPM Public Advisories","timestamp":"2024-10-30T00:00:00Z"}]},"projectInfo":{"name":"VulnerableWebApp","reportDate":"2024-11-01T10:23:45.000Z","credits":{"NVD":"This report contains data from the National Vulnerability Database (NVD), a product of NIST."}},"dependencies":[{"isVirtual":false,"fileName":"lodash-4.17.4.js","filePath":"/project/node_modules/lodash/lodash.js","md5":"cf65f0d33640f2cd0a0b06dd86a5c6a2","sha1":"5a0b814b7a2a72b8bb8bc4b82ea0c6a34e048c4e","packages":[{"id":"pkg:npm/lodash@4.17.4","confidence":"HIGH","url":"https://ossindex.sonatype.org/component/pkg:npm/lodash@4.17.4"}],"vulnerabilityIds":[{"id":"cpe:2.3:a:lodash:lodash:4.17.4:*:*:*:*:node.js:*:*","confidence":"HIGH"}],"vulnerabilities":[{"name":"CVE-2021-23337","severity":"HIGH","cvssv3":{"baseScore":7.2,"attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"HIGH","userInteraction":"NONE","scope":"UNCHANGED","confidentialityImpact":"HIGH","integrityImpact":"HIGH","availabilityImpact":"HIGH","baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"},"cwes":["CWE-78"],"description":"Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function. An attacker can exploit this to execute arbitrary commands on the server.","notes":"","references":[{"source":"MISC","url":"https://snyk.io/vuln/SNYK-JS-LODASH-1040724","name":"Snyk Advisory"},{"source":"NVD","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-23337","name":"NVD Entry"}],"vulnerableSoftware":[{"software":{"id":"cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*","versionEndExcluding":"4.17.21"}}]},{"name":"CVE-2021-23440","severity":"CRITICAL","cvssv3":{"baseScore":9.8,"attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"NONE","userInteraction":"NONE","scope":"UNCHANGED","confidentialityImpact":"HIGH","integrityImpact":"HIGH","availabilityImpact":"HIGH","baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},"cwes":["CWE-1321"],"description":"This affects the package set-value before 4.0.1; all versions of package lodash prior to 4.17.17 are vulnerable to Prototype Pollution via the set function. An attacker can modify the prototype of the base object Object to add or modify an existing property that will then exist on all objects.","notes":"","references":[{"source":"MISC","url":"https://snyk.io/vuln/SNYK-JS-SETVALUE-1540541","name":"Snyk Advisory"},{"source":"NVD","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-23440","name":"NVD Entry"}],"vulnerableSoftware":[{"software":{"id":"cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*","versionEndExcluding":"4.17.21"}}]}]},{"isVirtual":false,"fileName":"log4j-core-2.14.1.jar","filePath":"/project/lib/log4j-core-2.14.1.jar","md5":"cf65f0d33640f2cd0a0b06dd86a5c6a2","sha1":"5a0b814b7a2a72b8bb8bc4b82ea0c6a34e048c4e","packages":[{"id":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1","confidence":"HIGH","url":"https://ossindex.sonatype.org/component/pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],"vulnerabilityIds":[{"id":"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*","confidence":"HIGH"}],"vulnerabilities":[{"name":"CVE-2021-44228","severity":"CRITICAL","cvssv3":{"baseScore":10.0,"attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"NONE","userInteraction":"NONE","scope":"CHANGED","confidentialityImpact":"HIGH","integrityImpact":"HIGH","availabilityImpact":"HIGH","baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},"cwes":["CWE-917","CWE-400"],"description":"Log4Shell — Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or parameters can execute arbitrary code loaded from LDAP servers.","notes":"This is one of the most critical vulnerabilities ever discovered. CVSS Score: 10.0","references":[{"source":"MISC","url":"https://logging.apache.org/log4j/2.x/security.html","name":"Apache Security Advisory"},{"source":"NVD","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228","name":"NVD Entry"},{"source":"CISA","url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","name":"CISA KEV"}],"vulnerableSoftware":[{"software":{"id":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","versionEndExcluding":"2.15.0"}}]},{"name":"CVE-2021-45046","severity":"CRITICAL","cvssv3":{"baseScore":9.0,"attackVector":"NETWORK","attackComplexity":"HIGH","privilegesRequired":"NONE","userInteraction":"NONE","scope":"CHANGED","confidentialityImpact":"HIGH","integrityImpact":"HIGH","availabilityImpact":"HIGH","baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"},"cwes":["CWE-917"],"description":"It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allow attackers with control over Thread Context Map data to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution.","notes":"","references":[{"source":"NVD","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-45046","name":"NVD Entry"}],"vulnerableSoftware":[{"software":{"id":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","versionEndExcluding":"2.16.0"}}]}]},{"isVirtual":false,"fileName":"axios-0.19.0.js","filePath":"/project/node_modules/axios/dist/axios.js","packages":[{"id":"pkg:npm/axios@0.19.0","confidence":"HIGH"}],"vulnerabilityIds":[{"id":"cpe:2.3:a:axios:axios:0.19.0:*:*:*:*:node.js:*:*","confidence":"HIGH"}],"vulnerabilities":[{"name":"CVE-2020-28168","severity":"MEDIUM","cvssv3":{"baseScore":5.9,"attackVector":"NETWORK","attackComplexity":"HIGH","privilegesRequired":"NONE","userInteraction":"NONE","scope":"UNCHANGED","confidentialityImpact":"HIGH","integrityImpact":"NONE","availabilityImpact":"NONE","baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"},"cwes":["CWE-918"],"description":"Axios NPM package 0.21.0 contains a Server-Side Request Forgery (SSRF) vulnerability where an attacker may be able to bypass a proxy and access an internal network by causing redirection to an internal server-side URL.","notes":"","references":[{"source":"MISC","url":"https://snyk.io/vuln/SNYK-JS-AXIOS-1038255","name":"Snyk Advisory"},{"source":"NVD","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-28168","name":"NVD Entry"}],"vulnerableSoftware":[{"software":{"id":"cpe:2.3:a:axios:axios:*:*:*:*:*:node.js:*:*","versionEndExcluding":"0.21.1"}}]}]},{"isVirtual":false,"fileName":"requests-2.6.0-py2.py3-none-any.whl","filePath":"/project/venv/lib/python3.9/site-packages/requests-2.6.0.dist-info","packages":[{"id":"pkg:pypi/requests@2.6.0","confidence":"HIGH"}],"vulnerabilityIds":[{"id":"cpe:2.3:a:python-requests:requests:2.6.0:*:*:*:*:python:*:*","confidence":"HIGH"}],"vulnerabilities":[{"name":"CVE-2023-32681","severity":"MEDIUM","cvssv3":{"baseScore":6.1,"attackVector":"NETWORK","attackComplexity":"HIGH","privilegesRequired":"NONE","userInteraction":"REQUIRED","scope":"CHANGED","confidentialityImpact":"HIGH","integrityImpact":"NONE","availabilityImpact":"NONE","baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"},"cwes":["CWE-601"],"description":"Requests is a HTTP library for Python. Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint. This is a product of how Requests handles redirects and HTTP headers when following a redirection from HTTP to HTTPS.","notes":"","references":[{"source":"MISC","url":"https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q","name":"GitHub Advisory"},{"source":"NVD","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-32681","name":"NVD Entry"}],"vulnerableSoftware":[{"software":{"id":"cpe:2.3:a:python-requests:requests:*:*:*:*:*:python:*:*","versionEndExcluding":"2.31.0"}}]}]},{"isVirtual":false,"fileName":"express-4.16.0.js","filePath":"/project/node_modules/express/index.js","packages":[{"id":"pkg:npm/express@4.16.0","confidence":"HIGH"}],"vulnerabilityIds":[],"vulnerabilities":[]},{"isVirtual":false,"fileName":"react-16.8.0.js","filePath":"/project/node_modules/react/index.js","packages":[{"id":"pkg:npm/react@16.8.0","confidence":"HIGH"}],"vulnerabilityIds":[],"vulnerabilities":[]},{"isVirtual":false,"fileName":"moment-2.24.0.js","filePath":"/project/node_modules/moment/moment.js","packages":[{"id":"pkg:npm/moment@2.24.0","confidence":"HIGH"}],"vulnerabilityIds":[{"id":"cpe:2.3:a:momentjs:moment:2.24.0:*:*:*:*:node.js:*:*","confidence":"HIGH"}],"vulnerabilities":[{"name":"CVE-2022-24785","severity":"HIGH","cvssv3":{"baseScore":7.5,"attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"NONE","userInteraction":"NONE","scope":"UNCHANGED","confidentialityImpact":"NONE","integrityImpact":"HIGH","availabilityImpact":"NONE","baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"},"cwes":["CWE-22"],"description":"Moment.js is a JavaScript date library. A path traversal vulnerability impacts npm (server) users of Moment.js between versions 1.0.1 and 2.29.1, especially if a user-provided locale string is directly used to switch moment locale.","notes":"","references":[{"source":"MISC","url":"https://github.com/moment/moment/security/advisories/GHSA-8hfj-j24r-96c4","name":"GitHub Advisory"},{"source":"NVD","url":"https://nvd.nist.gov/vuln/detail/CVE-2022-24785","name":"NVD Entry"}],"vulnerableSoftware":[{"software":{"id":"cpe:2.3:a:momentjs:moment:*:*:*:*:*:node.js:*:*","versionEndExcluding":"2.29.2"}}]}]},{"isVirtual":false,"fileName":"webpack-4.46.0.js","filePath":"/project/node_modules/webpack/lib/webpack.js","packages":[{"id":"pkg:npm/webpack@4.46.0","confidence":"HIGH"}],"vulnerabilityIds":[],"vulnerabilities":[]}]};

function loadDemo(demoName) {
  const data = JSON.parse(JSON.stringify(SAMPLE_REPORT)); // deep clone
  const names = {
    'log4shell': 'Log4Shell Vulnerable Server',
    'nodeapp':   'Legacy Node.js Application',
    'pythonapp': 'Python Web Service',
  };
  if (data.projectInfo) {
    data.projectInfo.name = names[demoName] || data.projectInfo.name;
  }
  processReport(data);
}

// ── Report Processing ─────────────────────
function processReport(data) {
  reportData = data;

  // Flatten: collect all vulnerabilities with their parent dep
  const allVulns = [];
  const vulnDeps = [];

  data.dependencies.forEach(dep => {
    const vulns = dep.vulnerabilities || [];
    if (vulns.length > 0) vulnDeps.push(dep);
    vulns.forEach(v => allVulns.push({ ...v, _dep: dep }));
  });

  reportData._processed = {
    allVulns,
    vulnDeps,
    totalDeps: data.dependencies.length,
    counts: countBySeverity(allVulns),
  };

  runScanAnimation(data, allVulns).then(() => {
    renderDashboard();
  });
}

function countBySeverity(vulns) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  vulns.forEach(v => {
    const sev = v.severity?.toUpperCase();
    if (sev && counts[sev] !== undefined) counts[sev]++;
    else if (!sev) {
      // infer from CVSS
      const score = v.cvssv3?.baseScore || v.cvssv2?.score || 0;
      const s = scoreToSeverity(score);
      if (counts[s] !== undefined) counts[s]++;
    }
  });
  return counts;
}

// ── Scan Animation ────────────────────────
async function runScanAnimation(data, allVulns) {
  const projectName = data.projectInfo?.name || 'Unknown Project';
  scanProjectLbl.textContent = `→ ${projectName}`;
  terminalBody.innerHTML = '';
  scanProgress.style.width = '0%';

  landing.style.opacity = '0';
  landing.style.pointerEvents = 'none';
  scanOverlay.style.display = 'flex';
  await sleep(100);
  landing.style.display = 'none';

  const deps = data.dependencies || [];
  const initLines = [
    { text: 'Initializing OWASP Dependency Check Engine v9.0.9...', cls: 'info', delay: 400 },
    { text: 'Loading National Vulnerability Database (NVD)...', cls: 'info', delay: 500 },
    { text: 'Connecting to data sources... OK', cls: 'ok', delay: 350 },
    { text: `Project: ${projectName}`, cls: 'info', delay: 200 },
    { text: `Found ${deps.length} dependencies to analyze.`, cls: 'info', delay: 300 },
    { text: '─'.repeat(50), cls: 'info', delay: 100 },
  ];

  for (const line of initLines) {
    appendTerminalLine('>', line.text, line.cls);
    await sleep(line.delay);
    scanProgress.style.width = `${(initLines.indexOf(line) / initLines.length) * 30}%`;
  }

  // Animate each dependency
  for (let i = 0; i < deps.length; i++) {
    const dep = deps[i];
    const vulns = dep.vulnerabilities || [];
    const pkgId = dep.packages?.[0]?.id || dep.fileName;
    const pkgName = pkgId.replace(/^pkg:(npm|maven|pypi)\//, '');

    if (vulns.length === 0) {
      appendTerminalLine('✓', `Scanning: ${pkgName.padEnd(40, '.')} SAFE`, 'ok');
    } else {
      const worstSev = getWorstSeverity(vulns);
      const icon = worstSev === 'CRITICAL' ? '🔴' : worstSev === 'HIGH' ? '⚠' : '⚡';
      appendTerminalLine(icon, `Scanning: ${pkgName.padEnd(40, '.')} ${worstSev}  ${vulns.map(v => v.name).join(', ')}`, 'vuln');
    }

    scanProgress.style.width = `${30 + ((i / deps.length) * 55)}%`;
    terminalBody.scrollTop = terminalBody.scrollHeight;
    await sleep(260 + Math.random() * 140);
  }

  const { counts } = reportData._processed;
  const totalVulns = Object.values(counts).reduce((a, b) => a + b, 0);

  await sleep(300);
  appendTerminalLine('─', '─'.repeat(50), 'info');
  appendTerminalLine('✔', `Analysis complete. ${totalVulns} vulnerabilities found across ${deps.length} dependencies.`, 'ok');

  // Update stat counters in overlay
  document.getElementById('overlay-total').textContent = deps.length;
  document.getElementById('overlay-vulns').textContent = totalVulns;
  document.getElementById('overlay-critical').textContent = counts.CRITICAL;

  scanProgress.style.width = '100%';
  await sleep(1800);

  // Transition to dashboard
  scanOverlay.style.opacity = '0';
  scanOverlay.style.transition = 'opacity 0.5s ease';
  await sleep(500);
  scanOverlay.style.display = 'none';
  scanOverlay.style.opacity = '1';
  scanOverlay.style.transition = '';
}

function appendTerminalLine(prompt, text, cls) {
  const div = document.createElement('div');
  div.className = `terminal-line ${cls}`;
  div.innerHTML = `<span class="prompt">${prompt}</span><span class="status">${escapeHtml(text)}</span>`;
  terminalBody.appendChild(div);
}

function getWorstSeverity(vulns) {
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };
  let best = 4;
  vulns.forEach(v => {
    const s = v.severity?.toUpperCase() || 'NONE';
    if ((order[s] ?? 4) < best) best = order[s] ?? 4;
  });
  return Object.keys(order).find(k => order[k] === best) || 'NONE';
}

// ── Dashboard Rendering ───────────────────
function renderDashboard() {
  landing.style.display = 'none';
  dashboard.style.display = 'block';
  requestAnimationFrame(() => {
    dashboard.style.opacity = '0';
    dashboard.style.transform = 'translateY(20px)';
    dashboard.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    requestAnimationFrame(() => {
      dashboard.style.opacity = '1';
      dashboard.style.transform = 'translateY(0)';
    });
  });

  const { totalDeps, allVulns, counts } = reportData._processed;
  const projectName = reportData.projectInfo?.name || 'Unknown Project';
  const reportDate  = reportData.projectInfo?.reportDate
    ? new Date(reportData.projectInfo.reportDate).toLocaleDateString('en-US', { dateStyle: 'long' })
    : 'Unknown';
  const engineVer   = reportData.scanInfo?.engineVersion || 'N/A';

  // Project info bar
  document.getElementById('project-name').textContent = projectName;
  document.getElementById('project-date').textContent = `Scanned: ${reportDate}`;
  document.getElementById('project-engine').textContent = `Engine: v${engineVer}`;
  document.getElementById('project-deps').textContent   = `${totalDeps} dependencies`;

  // Stat cards (animated)
  const vulnDepsCount = reportData._processed.vulnDeps.length;
  animateCounter('stat-total',    totalDeps);
  animateCounter('stat-critical', counts.CRITICAL);
  animateCounter('stat-high',     counts.HIGH);
  animateCounter('stat-medium',   counts.MEDIUM);
  animateCounter('stat-low',      counts.LOW);
  animateCounter('stat-clean',    totalDeps - vulnDepsCount);

  // Severity chart
  renderSeverityChart(counts);
  renderSeverityLegend(counts, allVulns.length);

  // Vulnerability table
  renderVulnTable(reportData.dependencies);

  // Fix recommendations
  renderFixPanel(allVulns);
}

// ── Severity Chart (Chart.js) ────────────
function renderSeverityChart(counts) {
  const ctx = document.getElementById('severity-chart').getContext('2d');

  if (severityChart) severityChart.destroy();

  const labels = ['Critical', 'High', 'Medium', 'Low'];
  const values = [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW];
  const colors = ['#ff3e6c', '#ff8c42', '#ffd166', '#06d6a0'];
  const total  = values.reduce((a, b) => a + b, 0);

  if (total === 0) {
    // No vulnerabilities
    document.getElementById('chart-center-value').textContent = '0';
    document.getElementById('chart-center-label').textContent = 'Vulnerabilities';
  } else {
    document.getElementById('chart-center-value').textContent = total;
    document.getElementById('chart-center-label').textContent = 'Total CVEs';
  }

  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: total === 0 ? [1] : values,
        backgroundColor: total === 0 ? ['rgba(74,85,104,0.3)'] : colors.map(c => c + 'dd'),
        borderColor:     total === 0 ? ['#4a5568'] : colors,
        borderWidth: 2,
        hoverOffset: 6,
      }],
    },
    options: {
      cutout: '72%',
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.raw} (${total > 0 ? Math.round(ctx.raw / total * 100) : 0}%)`,
          },
          backgroundColor: '#111927',
          borderColor: '#1a2840',
          borderWidth: 1,
          titleColor: '#e8f0fe',
          bodyColor: '#8899bb',
          padding: 10,
        },
      },
      animation: {
        animateRotate: true,
        duration: 1000,
        easing: 'easeOutQuart',
      },
    },
  });
}

function renderSeverityLegend(counts, total) {
  const legendEl = document.getElementById('severity-legend');
  legendEl.innerHTML = '';
  const rows = [
    { key: 'CRITICAL', label: 'Critical', color: '#ff3e6c' },
    { key: 'HIGH',     label: 'High',     color: '#ff8c42' },
    { key: 'MEDIUM',   label: 'Medium',   color: '#ffd166' },
    { key: 'LOW',      label: 'Low',      color: '#06d6a0' },
  ];

  rows.forEach(({ key, label, color }) => {
    const count = counts[key] || 0;
    const pct   = total > 0 ? (count / total * 100) : 0;
    const row   = document.createElement('div');
    row.className = 'severity-legend-row';
    row.innerHTML = `
      <div class="severity-dot" style="background:${color}"></div>
      <span class="severity-name">${label}</span>
      <div class="severity-bar-wrap">
        <div class="severity-bar" data-width="${pct}" style="background:${color}"></div>
      </div>
      <span class="severity-count" style="color:${color}">${count}</span>
    `;
    legendEl.appendChild(row);
  });

  // Animate bars
  requestAnimationFrame(() => {
    document.querySelectorAll('.severity-bar').forEach(bar => {
      setTimeout(() => { bar.style.width = bar.dataset.width + '%'; }, 100);
    });
  });
}

// ── Vulnerability Table ───────────────────
function renderVulnTable(dependencies, filter = 'ALL') {
  const tbody = document.getElementById('vuln-tbody');
  tbody.innerHTML = '';

  let rendered = 0;

  dependencies.forEach(dep => {
    const vulns = dep.vulnerabilities || [];
    const pkgId      = dep.packages?.[0]?.id || dep.fileName;
    const pkgDisplay = formatPackageId(pkgId);
    const worstSev   = vulns.length > 0 ? getWorstSeverity(vulns) : 'SAFE';

    if (filter !== 'ALL' && worstSev !== filter) return;
    rendered++;

    if (vulns.length === 0) {
      if (filter !== 'ALL') return;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="package-name">${escapeHtml(pkgDisplay.name)}</span></td>
        <td><span class="package-version">${escapeHtml(pkgDisplay.version)}</span></td>
        <td><span class="severity-badge NONE">✓ SAFE</span></td>
        <td><span class="cvss-score score-none">—</span></td>
        <td style="color:var(--text-muted);font-size:0.78rem">No vulnerabilities detected</td>
      `;
      tbody.appendChild(tr);
      return;
    }

    // One row per vulnerability
    vulns.forEach((vuln, idx) => {
      const sev   = vuln.severity?.toUpperCase() || scoreToSeverity(vuln.cvssv3?.baseScore || 0);
      const score = vuln.cvssv3?.baseScore || vuln.cvssv2?.score || null;
      const tr    = document.createElement('tr');
      tr.className = 'has-vuln';
      tr.dataset.cveId = vuln.name;
      tr.innerHTML = `
        <td>${idx === 0 ? `<span class="package-name">${escapeHtml(pkgDisplay.name)}</span>` : ''}</td>
        <td>${idx === 0 ? `<span class="package-version">${escapeHtml(pkgDisplay.version)}</span>` : ''}</td>
        <td><span class="severity-badge ${sev}">${sev}</span></td>
        <td><span class="cvss-score ${scoreToCSSClass(score || 0)}">${score !== null ? score.toFixed(1) : '—'}</span></td>
        <td>
          <span class="cve-id">${escapeHtml(vuln.name)}</span>
          <span class="cve-count" style="color:var(--text-muted);font-size:0.76rem">${escapeHtml(truncate(vuln.description || '', 80))}</span>
        </td>
      `;
      tr.addEventListener('click', () => openCveModal(vuln, dep));
      tbody.appendChild(tr);
    });
  });

  if (rendered === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="5" style="text-align:center;color:var(--text-muted);padding:2rem;font-size:0.85rem">No results for this filter</td>`;
    tbody.appendChild(tr);
  }
}

function formatPackageId(pkgId) {
  // "pkg:npm/lodash@4.17.4" → { name: 'lodash', version: '4.17.4' }
  // "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" → { name: 'log4j-core', version: '2.14.1' }
  const match = pkgId.match(/([^/]+)@([^@\s]+)$/);
  if (match) return { name: match[1], version: match[2] };
  // fallback — just show filename
  const parts = pkgId.split('/');
  return { name: parts[parts.length - 1], version: '' };
}

// ── Filter Buttons ────────────────────────
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    renderVulnTable(reportData.dependencies, activeFilter);
  });
});

// ── Fix Recommendations ───────────────────
function renderFixPanel(allVulns) {
  const fixGrid = document.getElementById('fix-grid');
  fixGrid.innerHTML = '';

  // Group by dependency
  const depMap = {};
  allVulns.forEach(v => {
    const pkgId = v._dep?.packages?.[0]?.id || v._dep?.fileName || 'unknown';
    if (!depMap[pkgId]) depMap[pkgId] = { dep: v._dep, vulns: [], worstSev: 'LOW' };
    depMap[pkgId].vulns.push(v);
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    const sev = v.severity?.toUpperCase() || 'LOW';
    if ((order[sev] ?? 4) < (order[depMap[pkgId].worstSev] ?? 4)) {
      depMap[pkgId].worstSev = sev;
    }
  });

  Object.values(depMap).forEach(({ dep, vulns, worstSev }) => {
    const pkg     = formatPackageId(dep.packages?.[0]?.id || dep.fileName);
    const fixVers = getFixVersion(vulns);
    const card    = document.createElement('div');
    card.className = `fix-card ${worstSev}`;
    card.innerHTML = `
      <div class="fix-card-header">
        <span class="fix-package">${escapeHtml(pkg.name)} @ ${escapeHtml(pkg.version)}</span>
        <span class="severity-badge ${worstSev}">${worstSev}</span>
      </div>
      <p class="fix-desc">${vulns.length} CVE${vulns.length > 1 ? 's' : ''} detected: ${vulns.map(v => v.name).join(', ')}</p>
      <span class="fix-action">${fixVers ? `Upgrade to ${pkg.name} ≥ ${fixVers}` : 'Update to latest stable version'}</span>
    `;
    fixGrid.appendChild(card);
  });
}

function getFixVersion(vulns) {
  // Try to extract versionEndExcluding from vulnerableSoftware
  for (const v of vulns) {
    const sw = v.vulnerableSoftware?.[0]?.software;
    if (sw?.versionEndExcluding) return sw.versionEndExcluding;
  }
  return null;
}

// ── CVE Detail Modal ──────────────────────
function openCveModal(vuln, dep) {
  const score   = vuln.cvssv3?.baseScore || vuln.cvssv2?.score || null;
  const sev     = vuln.severity?.toUpperCase() || scoreToSeverity(score || 0);
  const cvss3   = vuln.cvssv3 || {};
  const pkg     = formatPackageId(dep.packages?.[0]?.id || dep.fileName);

  const scoreColor  = getSeverityColor(sev);
  const metricsHtml = cvss3.attackVector ? `
    <div class="cvss-metrics-grid">
      ${metricRow('Attack Vector', cvss3.attackVector)}
      ${metricRow('Attack Complexity', cvss3.attackComplexity)}
      ${metricRow('Privileges Required', cvss3.privilegesRequired)}
      ${metricRow('User Interaction', cvss3.userInteraction)}
      ${metricRow('Scope', cvss3.scope)}
      ${metricRow('Confidentiality', cvss3.confidentialityImpact)}
      ${metricRow('Integrity', cvss3.integrityImpact)}
      ${metricRow('Availability', cvss3.availabilityImpact)}
    </div>
  ` : '<p style="color:var(--text-muted);font-size:0.82rem">CVSSv3 metrics not available.</p>';

  const refsHtml = (vuln.references || []).map(r => `
    <a class="modal-ref-link" href="${escapeHtml(r.url || '#')}" target="_blank" rel="noopener">
      <span>🔗</span>
      <span>${escapeHtml(r.name || r.source || r.url || 'Reference')}</span>
    </a>
  `).join('');

  const cwesHtml = (vuln.cwes || []).map(c => `
    <span class="format-tag">${escapeHtml(c)}</span>
  `).join(' ');

  modalContent.innerHTML = `
    <div class="modal-header">
      <div>
        <div class="modal-cve-id">${escapeHtml(vuln.name)}</div>
        <div style="display:flex;align-items:center;gap:10px;margin-top:6px;flex-wrap:wrap">
          <span class="severity-badge ${sev}">${sev}</span>
          <span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--text-muted)">
            ${escapeHtml(pkg.name)} @ ${escapeHtml(pkg.version)}
          </span>
        </div>
      </div>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body">

      ${score !== null ? `
      <div>
        <div class="modal-section-title">CVSS v3 Score</div>
        <div class="modal-score-big">
          <div class="score-number" style="color:${scoreColor}">${score.toFixed(1)}</div>
          <div class="score-info">
            <div class="score-severity-name" style="color:${scoreColor}">${sev}</div>
            <div class="score-scale">CVSS v3.1 Base Score (0.0 – 10.0)</div>
            ${cvss3.vectorString ? `<div class="modal-vector" style="margin-top:8px">${escapeHtml(cvss3.vectorString)}</div>` : ''}
          </div>
        </div>
      </div>` : ''}

      <div>
        <div class="modal-section-title">Description</div>
        <p class="modal-description">${escapeHtml(vuln.description || 'No description available.')}</p>
      </div>

      ${vuln.notes ? `
      <div>
        <div class="modal-section-title">Notes</div>
        <p class="modal-description">${escapeHtml(vuln.notes)}</p>
      </div>` : ''}

      ${cvss3.attackVector ? `
      <div>
        <div class="modal-section-title">CVSSv3 Attack Metrics</div>
        ${metricsHtml}
      </div>` : ''}

      ${cwesHtml ? `
      <div>
        <div class="modal-section-title">CWE Classification</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">${cwesHtml}</div>
      </div>` : ''}

      ${refsHtml ? `
      <div>
        <div class="modal-section-title">References</div>
        <div class="modal-refs">${refsHtml}</div>
      </div>` : ''}
    </div>
  `;

  modalOverlay.classList.add('open');
  document.body.style.overflow = 'hidden';
}

function metricRow(label, value) {
  return `
    <div class="cvss-metric">
      <div class="cvss-metric-label">${escapeHtml(label)}</div>
      <div class="cvss-metric-value">${escapeHtml(value || '—')}</div>
    </div>
  `;
}

function closeModal() {
  modalOverlay.classList.remove('open');
  document.body.style.overflow = '';
}

modalOverlay.addEventListener('click', (e) => {
  if (e.target === modalOverlay) closeModal();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
});

// ── Export Report ─────────────────────────
function exportReport() {
  if (!reportData) return;
  const { counts, allVulns, totalDeps } = reportData._processed;
  const projectName = reportData.projectInfo?.name || 'Unknown';

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>OWASP DC Report — ${escapeHtml(projectName)}</title>
  <style>
    body { font-family: monospace; background: #0d1421; color: #e8f0fe; padding: 2em; }
    h1 { color: #00ff88; }
    table { width:100%; border-collapse:collapse; margin-top:1em; }
    th { background:#111927; padding:8px; text-align:left; border:1px solid #1a2840; }
    td { padding:8px; border:1px solid #1a2840; font-size:0.85rem; }
    .CRITICAL { color:#ff3e6c; } .HIGH { color:#ff8c42; }
    .MEDIUM { color:#ffd166; } .LOW { color:#06d6a0; }
  </style>
</head>
<body>
  <h1>🛡 OWASP Dependency Check Report</h1>
  <p>Project: <strong>${escapeHtml(projectName)}</strong> &nbsp;|&nbsp;
     Generated: ${new Date().toLocaleString()} &nbsp;|&nbsp;
     Total deps: ${totalDeps}</p>
  <table>
    <tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Description</th></tr>
    ${allVulns.map(v => {
      const sev   = v.severity?.toUpperCase() || 'N/A';
      const score = v.cvssv3?.baseScore || v.cvssv2?.score || '—';
      const pkg   = formatPackageId(v._dep?.packages?.[0]?.id || v._dep?.fileName || '');
      return `<tr>
        <td class="${sev}">${escapeHtml(v.name)}</td>
        <td class="${sev}">${sev}</td>
        <td>${score}</td>
        <td>${escapeHtml(pkg.name)} @ ${escapeHtml(pkg.version)}</td>
        <td>${escapeHtml(truncate(v.description || '', 120))}</td>
      </tr>`;
    }).join('')}
  </table>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `owasp-report-${projectName.replace(/\s+/g, '-')}.html`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── New Scan ──────────────────────────────
function newScan() {
  dashboard.style.display = 'none';
  landing.style.display   = '';
  landing.style.opacity   = '1';
  landing.style.pointerEvents = '';
  fileInput.value = '';
  reportData = null;
  activeFilter = 'ALL';
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.querySelector('.filter-btn[data-filter="ALL"]')?.classList.add('active');
  window.scrollTo({ top: 0 });
}

// ── Helpers ───────────────────────────────
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function truncate(str, maxLen) {
  if (!str) return '';
  return str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
}

function animateCounter(id, target) {
  const el    = document.getElementById(id);
  if (!el) return;
  const dur   = 800;
  const step  = 16;
  const steps = dur / step;
  let cur     = 0;
  const inc   = target / steps;
  const timer = setInterval(() => {
    cur += inc;
    if (cur >= target) {
      el.textContent = target;
      clearInterval(timer);
    } else {
      el.textContent = Math.floor(cur);
    }
  }, step);
}

// Expose globals needed by HTML onclick handlers
window.loadDemo     = loadDemo;
window.openCveModal = openCveModal;
window.closeModal   = closeModal;
window.exportReport = exportReport;
window.newScan      = newScan;
