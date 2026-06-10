"""
app.py - Web Dashboard for NetToolkit
Run: python app.py  →  open http://localhost:5000
"""

from flask import Flask, request, jsonify, render_template_string
from src.subnet_calc import calculate_subnet, vlsm_subnets, ip_in_subnet
from src.scanner import ping_sweep, port_scan
import threading

app = Flask(__name__)

# ─── HTML Template ────────────────────────────────────────────────────────────

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetToolkit — CCNA Network Tools</title>
<style>
  :root {
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --accent:   #58a6ff;
    --green:    #3fb950;
    --yellow:   #d29922;
    --red:      #f85149;
    --text:     #c9d1d9;
    --dim:      #8b949e;
    --radius:   8px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; min-height: 100vh; }

  header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 16px 32px;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  header h1 { font-size: 1.2rem; font-weight: 700; color: var(--accent); }
  header span { color: var(--dim); font-size: 0.85rem; }

  .tabs {
    display: flex;
    gap: 4px;
    padding: 24px 32px 0;
    border-bottom: 1px solid var(--border);
    background: var(--bg);
  }
  .tab {
    padding: 10px 20px;
    border: 1px solid transparent;
    border-bottom: none;
    border-radius: var(--radius) var(--radius) 0 0;
    cursor: pointer;
    font-size: 0.9rem;
    color: var(--dim);
    background: transparent;
    transition: all .15s;
  }
  .tab:hover { color: var(--text); background: var(--surface); }
  .tab.active { color: var(--accent); background: var(--surface); border-color: var(--border); }

  .content { padding: 32px; max-width: 960px; }
  .panel { display: none; }
  .panel.active { display: block; }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    margin-bottom: 24px;
  }
  .card h2 { font-size: 1rem; color: var(--accent); margin-bottom: 16px; }

  .form-row { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
  .field { display: flex; flex-direction: column; gap: 6px; flex: 1; min-width: 180px; }
  label { font-size: 0.8rem; color: var(--dim); text-transform: uppercase; letter-spacing: .05em; }
  input {
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 9px 14px;
    border-radius: 6px;
    font-size: 0.95rem;
    font-family: 'Consolas', monospace;
    transition: border-color .15s;
  }
  input:focus { outline: none; border-color: var(--accent); }
  button.btn {
    background: var(--accent);
    color: #000;
    border: none;
    padding: 10px 24px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.9rem;
    cursor: pointer;
    white-space: nowrap;
    transition: opacity .15s;
  }
  button.btn:hover { opacity: 0.85; }
  button.btn:disabled { opacity: 0.4; cursor: not-allowed; }

  .result-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 12px;
    margin-top: 16px;
  }
  .result-item {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 16px;
  }
  .result-item .key { font-size: 0.75rem; color: var(--dim); margin-bottom: 4px; }
  .result-item .val { font-family: 'Consolas', monospace; font-size: 0.95rem; }
  .val.green { color: var(--green); }
  .val.yellow { color: var(--yellow); }
  .val.blue { color: var(--accent); }

  .binary-mask {
    font-family: 'Consolas', monospace;
    font-size: 1rem;
    letter-spacing: 1px;
    margin-top: 16px;
    padding: 12px 16px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  .bit-1 { color: var(--green); }
  .bit-0 { color: var(--red); opacity: 0.7; }

  table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 0.9rem; }
  th { text-align: left; padding: 8px 12px; color: var(--dim); border-bottom: 1px solid var(--border); font-size: 0.78rem; text-transform: uppercase; }
  td { padding: 9px 12px; border-bottom: 1px solid rgba(48,54,61,0.5); font-family: 'Consolas', monospace; }
  tr:last-child td { border-bottom: none; }
  td.open { color: var(--green); }
  td.filtered { color: var(--yellow); }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .badge.green { background: rgba(63,185,80,.15); color: var(--green); }
  .badge.red   { background: rgba(248,81,73,.15);  color: var(--red); }

  .loader { display: none; color: var(--dim); font-size: 0.9rem; margin-top: 12px; }
  .loader.show { display: block; }
  .error-msg { color: var(--red); margin-top: 12px; font-size: 0.9rem; }
  .tip { color: var(--dim); font-size: 0.82rem; margin-top: 8px; }
</style>
</head>
<body>

<header>
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
    <circle cx="14" cy="14" r="13" stroke="#58a6ff" stroke-width="1.5"/>
    <circle cx="14" cy="14" r="4" fill="#58a6ff"/>
    <line x1="14" y1="1" x2="14" y2="7" stroke="#58a6ff" stroke-width="1.5"/>
    <line x1="14" y1="21" x2="14" y2="27" stroke="#58a6ff" stroke-width="1.5"/>
    <line x1="1" y1="14" x2="7" y2="14" stroke="#58a6ff" stroke-width="1.5"/>
    <line x1="21" y1="14" x2="27" y2="14" stroke="#58a6ff" stroke-width="1.5"/>
  </svg>
  <h1>NetToolkit</h1>
  <span>CCNA Network Tools</span>
</header>

<div class="tabs">
  <button class="tab active" onclick="switchTab('subnet')">Subnet Calc</button>
  <button class="tab" onclick="switchTab('vlsm')">VLSM</button>
  <button class="tab" onclick="switchTab('check')">IP Check</button>
  <button class="tab" onclick="switchTab('scan')">Ping Sweep</button>
  <button class="tab" onclick="switchTab('ports')">Port Scan</button>
</div>

<div class="content">

  <!-- Subnet Calculator -->
  <div class="panel active" id="panel-subnet">
    <div class="card">
      <h2>Subnet Calculator</h2>
      <div class="form-row">
        <div class="field">
          <label>IP Address / CIDR</label>
          <input id="s-cidr" value="192.168.1.0/24" placeholder="e.g. 10.0.0.0/16">
        </div>
        <button class="btn" onclick="calcSubnet()">Calculate</button>
      </div>
      <p class="tip">Enter any IP with CIDR prefix. Host bits are ignored.</p>
    </div>
    <div id="subnet-result"></div>
  </div>

  <!-- VLSM -->
  <div class="panel" id="panel-vlsm">
    <div class="card">
      <h2>VLSM — Variable Length Subnet Masking</h2>
      <div class="form-row">
        <div class="field">
          <label>Base Network</label>
          <input id="v-net" value="192.168.1.0/24" placeholder="e.g. 10.0.0.0/24">
        </div>
        <div class="field">
          <label>Host Requirements (space-separated)</label>
          <input id="v-hosts" value="50 25 10 5" placeholder="e.g. 100 50 20 10">
        </div>
        <button class="btn" onclick="calcVLSM()">Allocate</button>
      </div>
      <p class="tip">Subnets are allocated largest-first (VLSM best practice).</p>
    </div>
    <div id="vlsm-result"></div>
  </div>

  <!-- IP Check -->
  <div class="panel" id="panel-check">
    <div class="card">
      <h2>IP Membership Check</h2>
      <div class="form-row">
        <div class="field">
          <label>IP Address</label>
          <input id="c-ip" value="192.168.1.45" placeholder="e.g. 10.0.0.15">
        </div>
        <div class="field">
          <label>Subnet</label>
          <input id="c-subnet" value="192.168.1.0/26" placeholder="e.g. 10.0.0.0/28">
        </div>
        <button class="btn" onclick="checkIP()">Check</button>
      </div>
    </div>
    <div id="check-result"></div>
  </div>

  <!-- Ping Sweep -->
  <div class="panel" id="panel-scan">
    <div class="card">
      <h2>Ping Sweep</h2>
      <div class="form-row">
        <div class="field">
          <label>Network CIDR (max /22)</label>
          <input id="sc-net" value="192.168.1.0/24" placeholder="e.g. 192.168.0.0/24">
        </div>
        <button class="btn" id="scan-btn" onclick="runScan()">Scan</button>
      </div>
      <p class="tip">Uses ICMP ping. Results may vary based on firewall rules.</p>
    </div>
    <div class="loader" id="scan-loader">⟳ Scanning... (this can take 30–60 seconds for /24)</div>
    <div id="scan-result"></div>
  </div>

  <!-- Port Scan -->
  <div class="panel" id="panel-ports">
    <div class="card">
      <h2>Port Scanner</h2>
      <div class="form-row">
        <div class="field">
          <label>Target IP</label>
          <input id="p-ip" value="127.0.0.1" placeholder="e.g. 192.168.1.1">
        </div>
        <div class="field">
          <label>Ports (blank = all common ports)</label>
          <input id="p-ports" placeholder="e.g. 22 80 443 8080">
        </div>
        <button class="btn" id="port-btn" onclick="runPortScan()">Scan</button>
      </div>
      <p class="tip">TCP connect scan on common CCNA-relevant ports.</p>
    </div>
    <div class="loader" id="port-loader">⟳ Scanning ports...</div>
    <div id="port-result"></div>
  </div>

</div>

<script>
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  event.target.classList.add('active');
}

async function post(endpoint, data) {
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
  });
  return r.json();
}

function binaryMask(binary, prefix) {
  let html = '<div class="binary-mask">';
  for (let i = 0; i < 32; i++) {
    if (i > 0 && i % 8 === 0) html += ' &nbsp; ';
    html += `<span class="${i < prefix ? 'bit-1' : 'bit-0'}">${binary[i]}</span>`;
  }
  html += `<span style="color:var(--dim);margin-left:12px;font-size:.8rem">  /${prefix}</span>`;
  html += '</div>';
  return html;
}

async function calcSubnet() {
  const cidr = document.getElementById('s-cidr').value.trim();
  const d = await post('/api/subnet', {cidr});
  const el = document.getElementById('subnet-result');
  if (d.error) { el.innerHTML = `<p class="error-msg">Error: ${d.error}</p>`; return; }

  const items = [
    ['Network Address',   d.network_address,   'blue'],
    ['Broadcast Address', d.broadcast_address,  'yellow'],
    ['Subnet Mask',       d.subnet_mask,         ''],
    ['Wildcard Mask',     d.wildcard_mask,       ''],
    ['Prefix Length',     '/' + d.prefix_length, ''],
    ['Total IPs',         d.total_ips.toLocaleString(), ''],
    ['Usable Hosts',      d.usable_hosts.toLocaleString(), 'green'],
    ['First Host',        d.first_host,          'green'],
    ['Last Host',         d.last_host,            'green'],
    ['Network Class',     d.network_class,        ''],
    ['Private?',          d.is_private ? 'Yes (RFC 1918)' : 'No (Public)', d.is_private ? 'green' : ''],
  ];

  el.innerHTML = `<div class="card"><h2>Results</h2>
    <div class="result-grid">
      ${items.map(([k,v,c]) => `<div class="result-item"><div class="key">${k}</div><div class="val ${c}">${v}</div></div>`).join('')}
    </div>
    ${binaryMask(d.binary_mask, d.prefix_length)}
  </div>`;
}

async function calcVLSM() {
  const network = document.getElementById('v-net').value.trim();
  const hosts = document.getElementById('v-hosts').value.trim().split(/\s+/).map(Number);
  const d = await post('/api/vlsm', {network, hosts});
  const el = document.getElementById('vlsm-result');

  if (d[0]?.error && !d[0]?.subnet) {
    el.innerHTML = `<p class="error-msg">Error: ${d[0].error}</p>`;
    return;
  }

  const rows = d.map(r => r.error && !r.subnet
    ? `<tr><td>${r.subnet_index}</td><td>${r.hosts_required}</td><td colspan="5" style="color:var(--red)">${r.error}</td></tr>`
    : `<tr>
        <td>${r.subnet_index}</td>
        <td>${r.hosts_required}</td>
        <td class="open">${r.subnet}</td>
        <td>${r.subnet_mask}</td>
        <td>${r.usable_hosts}</td>
        <td>${r.first_host}</td>
        <td>${r.broadcast}</td>
      </tr>`
  ).join('');

  el.innerHTML = `<div class="card"><h2>Allocated Subnets</h2>
    <table>
      <tr><th>#</th><th>Hosts Req</th><th>Subnet</th><th>Mask</th><th>Usable</th><th>First Host</th><th>Broadcast</th></tr>
      ${rows}
    </table>
  </div>`;
}

async function checkIP() {
  const ip = document.getElementById('c-ip').value.trim();
  const subnet = document.getElementById('c-subnet').value.trim();
  const d = await post('/api/check', {ip, subnet});
  const el = document.getElementById('check-result');

  if (d.error) { el.innerHTML = `<p class="error-msg">Error: ${d.error}</p>`; return; }

  const cls = d.belongs ? 'green' : 'red';
  const icon = d.belongs ? '✓' : '✗';
  el.innerHTML = `<div class="card">
    <span class="badge ${cls}" style="font-size:1rem;padding:8px 16px">${icon} &nbsp; ${d.reason}</span>
  </div>`;
}

async function runScan() {
  const network = document.getElementById('sc-net').value.trim();
  document.getElementById('scan-loader').classList.add('show');
  document.getElementById('scan-btn').disabled = true;
  document.getElementById('scan-result').innerHTML = '';

  const d = await post('/api/scan', {network});

  document.getElementById('scan-loader').classList.remove('show');
  document.getElementById('scan-btn').disabled = false;

  const el = document.getElementById('scan-result');
  if (d[0]?.error) { el.innerHTML = `<p class="error-msg">Error: ${d[0].error}</p>`; return; }
  if (!d.length)   { el.innerHTML = `<div class="card" style="color:var(--yellow)">No alive hosts found.</div>`; return; }

  const rows = d.map(h => `<tr>
    <td class="open">${h.ip}</td>
    <td>${h.latency ? h.latency + ' ms' : '—'}</td>
    <td>${h.hostname || '—'}</td>
  </tr>`).join('');

  el.innerHTML = `<div class="card"><h2>${d.length} Alive Host(s)</h2>
    <table>
      <tr><th>IP Address</th><th>Latency</th><th>Hostname</th></tr>
      ${rows}
    </table>
  </div>`;
}

async function runPortScan() {
  const ip = document.getElementById('p-ip').value.trim();
  const rawPorts = document.getElementById('p-ports').value.trim();
  const ports = rawPorts ? rawPorts.split(/\s+/).map(Number) : null;

  document.getElementById('port-loader').classList.add('show');
  document.getElementById('port-btn').disabled = true;
  document.getElementById('port-result').innerHTML = '';

  const d = await post('/api/ports', {ip, ports});

  document.getElementById('port-loader').classList.remove('show');
  document.getElementById('port-btn').disabled = false;

  const el = document.getElementById('port-result');
  if (d.error) { el.innerHTML = `<p class="error-msg">Error: ${d.error}</p>`; return; }

  const info = [
    ['Target',   d.target],
    ['Hostname', d.hostname],
    ['Scanned',  d.total_ports_scanned + ' ports'],
    ['Open',     d.open_count],
  ];

  const rows = (d.open_ports || []).map(p => `<tr>
    <td class="open">${p.port}</td>
    <td class="open">${p.state}</td>
    <td>${p.service}</td>
    <td style="color:var(--dim);font-size:.85rem">${p.banner || ''}</td>
  </tr>`).join('');

  el.innerHTML = `<div class="card">
    <h2>Scan Results</h2>
    <div class="result-grid" style="margin-bottom:16px">
      ${info.map(([k,v]) => `<div class="result-item"><div class="key">${k}</div><div class="val">${v}</div></div>`).join('')}
    </div>
    ${d.open_count === 0
      ? '<p style="color:var(--yellow)">No open ports found.</p>'
      : `<table>
          <tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr>
          ${rows}
        </table>`}
  </div>`;
}

// Auto-run subnet on load
calcSubnet();
</script>
</body>
</html>
"""


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/subnet", methods=["POST"])
def api_subnet():
    data = request.json
    return jsonify(calculate_subnet(data.get("cidr", "")))

@app.route("/api/vlsm", methods=["POST"])
def api_vlsm():
    data = request.json
    return jsonify(vlsm_subnets(data.get("network", ""), data.get("hosts", [])))

@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.json
    return jsonify(ip_in_subnet(data.get("ip", ""), data.get("subnet", "")))

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json
    return jsonify(ping_sweep(data.get("network", "")))

@app.route("/api/ports", methods=["POST"])
def api_ports():
    data  = request.json
    ip    = data.get("ip", "")
    ports = data.get("ports", None)
    return jsonify(port_scan(ip, ports))


if __name__ == "__main__":
    print("\n  NetToolkit Web Dashboard")
    print("  Open: http://localhost:5000\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
