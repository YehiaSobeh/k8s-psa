#!/usr/bin/env python3
"""
k8s-psa Real-Time Dashboard Server

Reads findings from /data/findings.jsonl and /data/scans.jsonl
(written by the k8s-psa DaemonSet on a shared volume) and serves:
  GET /             → HTML dashboard (auto-refreshes every 10s)
  GET /api/findings → last N findings as JSON
  GET /api/scans    → all scan summaries as JSON
  GET /api/stats    → aggregated statistics as JSON

No external dependencies — uses Python stdlib only.
"""

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import Counter
from urllib.parse import urlparse, parse_qs

DATA_DIR = os.getenv("DATA_DIR", "/data")
PORT = int(os.getenv("DASHBOARD_PORT", "8080"))


def read_jsonl(path, max_lines=5000):
    """Read an NDJSON file, return list of dicts."""
    if not os.path.exists(path):
        return []
    results = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return results[-max_lines:]
    except Exception:
        return []


def compute_stats():
    """Compute live statistics from the NDJSON files."""
    findings = read_jsonl(os.path.join(DATA_DIR, "findings.jsonl"))
    scans = read_jsonl(os.path.join(DATA_DIR, "scans.jsonl"))

    spec = [f for f in findings if f.get("type") == "spec_violation"]
    drift = [f for f in findings if f.get("type") == "drift_finding"]

    # Deduplicate
    spec_unique = {}
    for v in spec:
        key = (v.get("check_id"), v.get("pod"), v.get("namespace"))
        spec_unique[key] = v
    drift_unique = {}
    for f in drift:
        key = (f.get("field"), f.get("pod"), f.get("container"), f.get("severity"))
        drift_unique[key] = f

    return {
        "total_scans": len(scans),
        "total_findings": len(findings),
        "unique_spec_violations": len(spec_unique),
        "unique_drift_findings": len(drift_unique),
        "drift_by_severity": dict(Counter(f.get("severity") for f in drift)),
        "drift_by_field": dict(Counter(f.get("field") for f in drift)),
        "drift_by_category": dict(Counter(f.get("category") for f in drift)),
        "spec_by_check": dict(Counter(v.get("check_id") for v in spec)),
        "spec_by_severity": dict(Counter(v.get("severity") for v in spec)),
        "scans": scans[-50:],
        "unique_spec_list": list(spec_unique.values()),
        "unique_drift_list": sorted(
            drift_unique.values(),
            key=lambda x: {"critical": 0, "warning": 1, "info": 2}.get(
                x.get("severity", ""), 3
            ),
        ),
        "last_scan": scans[-1] if scans else None,
    }


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>k8s-psa Live Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}
h1{font-size:24px;font-weight:600;color:#f8fafc}
.sub{color:#94a3b8;font-size:13px;margin:4px 0 20px}
.live{display:inline-block;width:8px;height:8px;background:#22c55e;border-radius:50%;margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px}
.card .n{font-size:32px;font-weight:700}
.card .l{font-size:12px;color:#94a3b8;margin-top:2px}
.crit{color:#ef4444} .warn{color:#f59e0b} .info{color:#3b82f6} .ok{color:#22c55e}
.row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:16px 0}
.box{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px}
.box h3{font-size:14px;font-weight:500;color:#cbd5e1;margin-bottom:10px}
canvas{max-height:240px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 6px;background:#1e293b;color:#64748b;font-weight:500;border-bottom:2px solid #334155;position:sticky;top:0}
td{padding:6px;border-bottom:1px solid #1e293b;vertical-align:top}
tr:hover td{background:#1e293b}
code{background:#334155;padding:1px 5px;border-radius:3px;font-size:11px}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:500;color:#fff}
.badge-critical{background:#ef4444} .badge-warning{background:#f59e0b} .badge-info{background:#3b82f6}
.badge-high{background:#ef4444} .badge-medium{background:#f59e0b} .badge-low{background:#3b82f6}
.tw{max-height:400px;overflow-y:auto;border:1px solid #334155;border-radius:8px}
h2{font-size:16px;font-weight:500;margin:24px 0 10px;color:#f1f5f9}
@media(max-width:800px){.row{grid-template-columns:1fr}}
</style>
</head><body>

<h1><span class="live"></span> k8s-psa live dashboard</h1>
<p class="sub">Auto-refreshes every 10 seconds &middot; Last update: <span id="ts">-</span> &middot; Scans: <span id="sc">0</span></p>

<div class="cards">
  <div class="card"><div class="n ok" id="c-scans">-</div><div class="l">Scan cycles</div></div>
  <div class="card"><div class="n" id="c-spec" style="color:#e2e8f0">-</div><div class="l">Unique spec violations</div></div>
  <div class="card"><div class="n crit" id="c-crit">-</div><div class="l">Critical drift (L2)</div></div>
  <div class="card"><div class="n warn" id="c-warn">-</div><div class="l">Warning drift (L2)</div></div>
  <div class="card"><div class="n info" id="c-info">-</div><div class="l">Info drift (L2)</div></div>
  <div class="card"><div class="n ok" id="c-drift">-</div><div class="l">Unique drift findings</div></div>
</div>

<div class="row">
  <div class="box"><h3>Drift by severity</h3><canvas id="ch1"></canvas></div>
  <div class="box"><h3>Drift by security field</h3><canvas id="ch2"></canvas></div>
</div>
<div class="row">
  <div class="box"><h3>Drift by category</h3><canvas id="ch3"></canvas></div>
  <div class="box"><h3>Spec violations by check</h3><canvas id="ch4"></canvas></div>
</div>
<div class="box" style="margin:16px 0"><h3>Findings per scan cycle</h3><canvas id="ch5" style="max-height:180px"></canvas></div>

<h2>Layer 2: Unique drift findings (spec vs runtime)</h2>
<div class="tw"><table><thead><tr><th>Severity</th><th>Pod</th><th>Container</th><th>Field</th><th>Category</th><th>Description</th></tr></thead><tbody id="dt"></tbody></table></div>

<h2>Layer 1: Unique spec violations</h2>
<div class="tw"><table><thead><tr><th>Severity</th><th>Pod</th><th>Check</th><th>Message</th></tr></thead><tbody id="st"></tbody></table></div>

<script>
const SC={critical:'#ef4444',warning:'#f59e0b',info:'#3b82f6',high:'#ef4444',medium:'#f59e0b',low:'#3b82f6'};
const CC=['#8b5cf6','#06b6d4','#f97316','#ec4899','#22c55e','#eab308','#6366f1','#14b8a6'];
Chart.defaults.color='#94a3b8';Chart.defaults.borderColor='#334155';
let ch1,ch2,ch3,ch4,ch5;

function mkDoughnut(el,labels,data){
  return new Chart(el,{type:'doughnut',data:{labels,datasets:[{data,backgroundColor:labels.map(l=>SC[l]||'#888')}]},options:{plugins:{legend:{position:'bottom',labels:{boxWidth:12}}}}});
}
function mkBar(el,labels,data,color){
  return new Chart(el,{type:'bar',data:{labels,datasets:[{data,backgroundColor:color||CC}]},options:{indexAxis:'y',plugins:{legend:{display:false}}}});
}
function mkLine(el){
  return new Chart(el,{type:'line',data:{labels:[],datasets:[
    {label:'L1 violations',data:[],borderColor:'#06b6d4',tension:.3,pointRadius:1},
    {label:'L2 critical',data:[],borderColor:'#ef4444',tension:.3,pointRadius:1}
  ]},options:{plugins:{legend:{position:'bottom',labels:{boxWidth:12}}},scales:{y:{beginAtZero:true}}}});
}

function updChart(chart,labels,data,colors){
  chart.data.labels=labels;chart.data.datasets[0].data=data;
  if(colors)chart.data.datasets[0].backgroundColor=colors;
  chart.update('none');
}

async function refresh(){
  try{
    const r=await fetch('/api/stats');const d=await r.json();
    document.getElementById('ts').textContent=new Date().toLocaleTimeString();
    document.getElementById('sc').textContent=d.total_scans;
    document.getElementById('c-scans').textContent=d.total_scans;
    document.getElementById('c-spec').textContent=d.unique_spec_violations;
    document.getElementById('c-crit').textContent=d.drift_by_severity.critical||0;
    document.getElementById('c-warn').textContent=d.drift_by_severity.warning||0;
    document.getElementById('c-info').textContent=d.drift_by_severity.info||0;
    document.getElementById('c-drift').textContent=d.unique_drift_findings;

    const ds=d.drift_by_severity,df=d.drift_by_field,dc=d.drift_by_category,sc=d.spec_by_check;
    updChart(ch1,Object.keys(ds),Object.values(ds),Object.keys(ds).map(k=>SC[k]));
    updChart(ch2,Object.keys(df),Object.values(df),'#8b5cf6');
    updChart(ch3,Object.keys(dc),Object.values(dc),CC);
    updChart(ch4,Object.keys(sc),Object.values(sc),'#06b6d4');

    const scans=d.scans||[];
    ch5.data.labels=scans.map((_,i)=>'#'+(i+1));
    ch5.data.datasets[0].data=scans.map(s=>s.layer1_violations||0);
    ch5.data.datasets[1].data=scans.map(s=>s.layer2_critical||0);
    ch5.update('none');

    let dh='';
    (d.unique_drift_list||[]).forEach(f=>{
      dh+=`<tr><td><span class="badge badge-${f.severity}">${f.severity}</span></td><td>${f.namespace}/${f.pod}</td><td>${f.container}</td><td><code>${f.field}</code></td><td>${f.category}</td><td>${f.description}</td></tr>`;
    });
    document.getElementById('dt').innerHTML=dh;

    let sh='';
    (d.unique_spec_list||[]).forEach(v=>{
      sh+=`<tr><td><span class="badge badge-${v.severity}">${v.severity}</span></td><td>${v.namespace}/${v.pod}</td><td><code>${v.check_id}</code></td><td>${v.message}</td></tr>`;
    });
    document.getElementById('st').innerHTML=sh;
  }catch(e){console.error('Refresh failed:',e)}
}

ch1=mkDoughnut(document.getElementById('ch1'),[],[]);
ch2=mkBar(document.getElementById('ch2'),[],[],'#8b5cf6');
ch3=mkBar(document.getElementById('ch3'),[],[],CC);
ch4=mkBar(document.getElementById('ch4'),[],[],'#06b6d4');
ch5=mkLine(document.getElementById('ch5'));
refresh();
setInterval(refresh,10000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._respond(200, "text/html", DASHBOARD_HTML)
        elif path == "/api/stats":
            self._respond(200, "application/json", json.dumps(compute_stats()))
        elif path == "/api/findings":
            findings = read_jsonl(os.path.join(DATA_DIR, "findings.jsonl"))
            self._respond(200, "application/json", json.dumps(findings[-200:]))
        elif path == "/api/scans":
            scans = read_jsonl(os.path.join(DATA_DIR, "scans.jsonl"))
            self._respond(200, "application/json", json.dumps(scans))
        else:
            self._respond(404, "text/plain", "Not found")

    def _respond(self, code, content_type, body):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def log_message(self, fmt, *args):
        pass  # Suppress per-request logs


if __name__ == "__main__":
    print(f"Dashboard server starting on port {PORT}")
    print(f"Reading data from {DATA_DIR}")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
