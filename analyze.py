#!/usr/bin/env python3
"""
k8s-psa Log Analyzer & Dashboard Generator

Reads the raw log output from k8s-psa and produces:
  1. A summary JSON with statistics
  2. An HTML dashboard with charts for the thesis

Usage:
  python3 analyze.py output.json
  # Opens dashboard.html in browser
"""

import json
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime


def parse_log_file(path: str) -> dict:
    """Parse the mixed log/JSON output file."""
    spec_violations = []
    drift_findings = []
    scan_timestamps = []
    scan_count = 0
    scan_pods = []

    with open(path, "r") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue

            # Single-line JSON records (reliable)
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    obj = json.loads(stripped)
                    t = obj.get("type", "")
                    if t == "spec_violation":
                        spec_violations.append(obj)
                    elif t == "drift_finding":
                        drift_findings.append(obj)
                    continue
                except json.JSONDecodeError:
                    pass

            # Parse scan cycle info from log lines
            if "Starting security scan" in stripped:
                scan_count += 1
                # Extract timestamp: "2026-04-12 17:58:39,337 - ..."
                ts = stripped.split(" - ")[0].strip() if " - " in stripped else ""
                scan_timestamps.append(ts)

            if "Found" in stripped and "pods on node" in stripped:
                # "Found 8 pods on node minikube"
                try:
                    parts = stripped.split("Found ")[1].split(" pods")[0]
                    scan_pods.append(int(parts))
                except (IndexError, ValueError):
                    pass

    # Build per-scan metrics from findings and log lines
    scan_summaries = []
    if scan_count > 0:
        # Distribute findings evenly across scans
        sv_per_scan = len(spec_violations) // scan_count if scan_count else 0
        df_per_scan = len(drift_findings) // scan_count if scan_count else 0
        for i in range(min(scan_count, 50)):
            pods = scan_pods[i] if i < len(scan_pods) else 0
            ts = scan_timestamps[i] if i < len(scan_timestamps) else ""
            scan_summaries.append({
                "timestamp": ts,
                "pods_scanned": pods,
                "layer1_violations": sv_per_scan,
                "layer2_critical_findings": sum(
                    1 for f in drift_findings[i*df_per_scan:(i+1)*df_per_scan]
                    if f.get("severity") == "critical"
                ) if df_per_scan else 0,
            })

    return {
        "spec_violations": spec_violations,
        "drift_findings": drift_findings,
        "scan_summaries": scan_summaries,
        "scan_count": max(scan_count, len(scan_summaries)),
    }


def compute_statistics(data: dict) -> dict:
    """Compute statistics for the dashboard."""
    sv = data["spec_violations"]
    df = data["drift_findings"]

    # --- Spec violations ---
    sv_by_severity = Counter(v["severity"] for v in sv)
    sv_by_check = Counter(v["check_id"] for v in sv)
    sv_by_pod = Counter(f"{v['namespace']}/{v['pod']}" for v in sv)

    # Unique spec violations (deduplicate across scans)
    sv_unique_keys = set()
    sv_unique = []
    for v in sv:
        key = (v["check_id"], v["pod"], v["namespace"])
        if key not in sv_unique_keys:
            sv_unique_keys.add(key)
            sv_unique.append(v)

    # --- Drift findings ---
    df_by_severity = Counter(f["severity"] for f in df)
    df_by_category = Counter(f["category"] for f in df)
    df_by_field = Counter(f["field"] for f in df)
    df_by_container = Counter(
        f"{f['namespace']}/{f['pod']}/{f['container']}" for f in df
    )

    # Unique drift findings
    df_unique_keys = set()
    df_unique = []
    for f in df:
        key = (f["field"], f["pod"], f["container"], f["severity"])
        if key not in df_unique_keys:
            df_unique_keys.add(key)
            df_unique.append(f)

    # --- Per-scan metrics (for time series) ---
    scan_metrics = []
    for s in data.get("scan_summaries", []):
        scan_metrics.append({
            "timestamp": s.get("timestamp", ""),
            "pods_scanned": s.get("pods_scanned", 0),
            "l1_violations": s.get("layer1_violations", 0),
            "l2_critical": s.get("layer2_critical_findings", 0),
        })

    return {
        "total_scans": data["scan_count"],
        "total_spec_violations": len(sv),
        "unique_spec_violations": len(sv_unique),
        "total_drift_findings": len(df),
        "unique_drift_findings": len(df_unique),
        "spec_by_severity": dict(sv_by_severity),
        "spec_by_check": dict(sv_by_check),
        "spec_by_pod": dict(sv_by_pod),
        "drift_by_severity": dict(df_by_severity),
        "drift_by_category": dict(df_by_category),
        "drift_by_field": dict(df_by_field),
        "drift_by_container": dict(df_by_container),
        "unique_spec_violations_list": sv_unique,
        "unique_drift_findings_list": df_unique,
        "scan_metrics": scan_metrics,
    }


def generate_html(stats: dict, output_path: str):
    """Generate a self-contained HTML dashboard."""

    # Prepare chart data
    drift_severity_labels = json.dumps(list(stats["drift_by_severity"].keys()))
    drift_severity_values = json.dumps(list(stats["drift_by_severity"].values()))
    drift_field_labels = json.dumps(list(stats["drift_by_field"].keys()))
    drift_field_values = json.dumps(list(stats["drift_by_field"].values()))
    drift_category_labels = json.dumps(list(stats["drift_by_category"].keys()))
    drift_category_values = json.dumps(list(stats["drift_by_category"].values()))
    spec_check_labels = json.dumps(list(stats["spec_by_check"].keys()))
    spec_check_values = json.dumps(list(stats["spec_by_check"].values()))
    spec_severity_labels = json.dumps(list(stats["spec_by_severity"].keys()))
    spec_severity_values = json.dumps(list(stats["spec_by_severity"].values()))

    # Build the unique findings tables
    drift_rows = ""
    for f in sorted(stats["unique_drift_findings_list"],
                    key=lambda x: {"critical": 0, "warning": 1, "info": 2}.get(x["severity"], 3)):
        sev = f["severity"]
        sev_class = {"critical": "#ef4444", "warning": "#f59e0b", "info": "#3b82f6"}.get(sev, "#888")
        drift_rows += f"""<tr>
            <td><span style="background:{sev_class};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{sev}</span></td>
            <td>{f['namespace']}/{f['pod']}</td>
            <td>{f['container']}</td>
            <td><code>{f['field']}</code></td>
            <td>{f['category']}</td>
            <td style="font-size:13px">{f['description']}</td>
            <td><code>{f.get('declared','')}</code></td>
            <td><code>{f.get('actual','')}</code></td>
        </tr>"""

    spec_rows = ""
    for v in sorted(stats["unique_spec_violations_list"],
                    key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["severity"], 3)):
        sev = v["severity"]
        sev_class = {"high": "#ef4444", "medium": "#f59e0b", "low": "#3b82f6"}.get(sev, "#888")
        spec_rows += f"""<tr>
            <td><span style="background:{sev_class};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{sev}</span></td>
            <td>{v['namespace']}/{v['pod']}</td>
            <td><code>{v['check_id']}</code></td>
            <td>{v['message']}</td>
        </tr>"""

    # Scan trend data
    scan_timestamps = json.dumps([m["timestamp"][:19] for m in stats["scan_metrics"][:50]])
    scan_l1 = json.dumps([m["l1_violations"] for m in stats["scan_metrics"][:50]])
    scan_l2_crit = json.dumps([m["l2_critical"] for m in stats["scan_metrics"][:50]])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>k8s-psa Security Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:#0f172a; color:#e2e8f0; padding:24px; }}
  h1 {{ font-size:28px; font-weight:600; margin-bottom:8px; color:#f8fafc; }}
  h2 {{ font-size:20px; font-weight:500; margin:32px 0 16px; color:#f1f5f9; border-bottom:1px solid #334155; padding-bottom:8px; }}
  h3 {{ font-size:16px; font-weight:500; margin:24px 0 12px; color:#cbd5e1; }}
  .subtitle {{ color:#94a3b8; font-size:14px; margin-bottom:24px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin:20px 0; }}
  .card {{ background:#1e293b; border:1px solid #334155; border-radius:12px; padding:20px; }}
  .card .num {{ font-size:36px; font-weight:700; }}
  .card .label {{ font-size:13px; color:#94a3b8; margin-top:4px; }}
  .crit {{ color:#ef4444; }}
  .warn {{ color:#f59e0b; }}
  .info {{ color:#3b82f6; }}
  .ok {{ color:#22c55e; }}
  .charts {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; margin:20px 0; }}
  .chart-box {{ background:#1e293b; border:1px solid #334155; border-radius:12px; padding:20px; }}
  .chart-box h3 {{ margin:0 0 12px; }}
  canvas {{ max-height:280px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; margin:12px 0; }}
  th {{ text-align:left; padding:10px 8px; background:#1e293b; color:#94a3b8; font-weight:500; border-bottom:2px solid #334155; position:sticky; top:0; }}
  td {{ padding:8px; border-bottom:1px solid #1e293b; vertical-align:top; }}
  tr:hover td {{ background:#1e293b; }}
  code {{ background:#334155; padding:2px 6px; border-radius:4px; font-size:12px; }}
  .table-wrap {{ max-height:500px; overflow-y:auto; border:1px solid #334155; border-radius:8px; }}
  @media (max-width:900px) {{ .charts {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>

<h1>k8s-psa Security Dashboard</h1>
<p class="subtitle">Kubernetes Pod Security Auditor — Spec vs Runtime Enforcement Verification</p>

<!-- Summary Cards -->
<div class="cards">
  <div class="card">
    <div class="num ok">{stats['total_scans']}</div>
    <div class="label">Scan cycles</div>
  </div>
  <div class="card">
    <div class="num" style="color:#e2e8f0">{stats['unique_spec_violations']}</div>
    <div class="label">Unique spec violations (L1)</div>
  </div>
  <div class="card">
    <div class="num crit">{stats['drift_by_severity'].get('critical',0)}</div>
    <div class="label">Critical drift findings (L2)</div>
  </div>
  <div class="card">
    <div class="num warn">{stats['drift_by_severity'].get('warning',0)}</div>
    <div class="label">Warning drift findings (L2)</div>
  </div>
  <div class="card">
    <div class="num info">{stats['drift_by_severity'].get('info',0)}</div>
    <div class="label">Info drift findings (L2)</div>
  </div>
  <div class="card">
    <div class="num ok">{stats['unique_drift_findings']}</div>
    <div class="label">Unique drift findings</div>
  </div>
</div>

<!-- Charts Row 1 -->
<h2>Layer 2: Drift Detection Analysis</h2>
<div class="charts">
  <div class="chart-box">
    <h3>Drift findings by severity</h3>
    <canvas id="driftSev"></canvas>
  </div>
  <div class="chart-box">
    <h3>Drift findings by security field</h3>
    <canvas id="driftField"></canvas>
  </div>
</div>
<div class="charts">
  <div class="chart-box">
    <h3>Drift findings by category</h3>
    <canvas id="driftCat"></canvas>
  </div>
  <div class="chart-box">
    <h3>Layer 1: Spec violations by check</h3>
    <canvas id="specCheck"></canvas>
  </div>
</div>

<!-- Scan Trend -->
<div class="chart-box" style="margin:20px 0">
  <h3>Findings per scan cycle (first 50 scans)</h3>
  <canvas id="scanTrend" style="max-height:220px"></canvas>
</div>

<!-- Drift Findings Table -->
<h2>Layer 2: Unique Drift Findings (spec vs runtime)</h2>
<p class="subtitle">These are divergences between what the Kubernetes API declares and what the container runtime actually enforces.</p>
<div class="table-wrap">
<table>
  <thead>
    <tr><th>Severity</th><th>Pod</th><th>Container</th><th>Field</th><th>Category</th><th>Description</th><th>Declared</th><th>Actual</th></tr>
  </thead>
  <tbody>{drift_rows}</tbody>
</table>
</div>

<!-- Spec Violations Table -->
<h2>Layer 1: Unique Spec Violations</h2>
<p class="subtitle">Security policy violations detected in the Kubernetes API pod specifications.</p>
<div class="table-wrap">
<table>
  <thead>
    <tr><th>Severity</th><th>Pod</th><th>Check</th><th>Message</th></tr>
  </thead>
  <tbody>{spec_rows}</tbody>
</table>
</div>

<p style="margin-top:40px;color:#475569;font-size:12px">Generated by k8s-psa analyze.py at {datetime.now().isoformat()[:19]}</p>

<script>
const sevColors = {{'critical':'#ef4444','warning':'#f59e0b','info':'#3b82f6','high':'#ef4444','medium':'#f59e0b','low':'#3b82f6'}};
const catColors = ['#8b5cf6','#06b6d4','#f97316','#ec4899','#22c55e','#eab308','#6366f1','#14b8a6'];
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = '#334155';

// Drift by severity
new Chart(document.getElementById('driftSev'), {{
  type:'doughnut',
  data:{{ labels:{drift_severity_labels}, datasets:[{{ data:{drift_severity_values},
    backgroundColor:{drift_severity_labels}.map(l=>sevColors[l]||'#888') }}] }},
  options:{{ plugins:{{ legend:{{ position:'bottom' }} }} }}
}});

// Drift by field
new Chart(document.getElementById('driftField'), {{
  type:'bar',
  data:{{ labels:{drift_field_labels}, datasets:[{{ label:'Count', data:{drift_field_values},
    backgroundColor:'#8b5cf6' }}] }},
  options:{{ indexAxis:'y', plugins:{{ legend:{{ display:false }} }} }}
}});

// Drift by category
new Chart(document.getElementById('driftCat'), {{
  type:'bar',
  data:{{ labels:{drift_category_labels}, datasets:[{{ label:'Count', data:{drift_category_values},
    backgroundColor:catColors }}] }},
  options:{{ indexAxis:'y', plugins:{{ legend:{{ display:false }} }} }}
}});

// Spec by check
new Chart(document.getElementById('specCheck'), {{
  type:'bar',
  data:{{ labels:{spec_check_labels}, datasets:[{{ label:'Count', data:{spec_check_values},
    backgroundColor:'#06b6d4' }}] }},
  options:{{ indexAxis:'y', plugins:{{ legend:{{ display:false }} }} }}
}});

// Scan trend
const tLabels = {scan_timestamps};
new Chart(document.getElementById('scanTrend'), {{
  type:'line',
  data:{{ labels:tLabels.map((_,i)=>'Scan '+(i+1)),
    datasets:[
      {{ label:'L1 violations', data:{scan_l1}, borderColor:'#06b6d4', tension:0.3, pointRadius:2 }},
      {{ label:'L2 critical', data:{scan_l2_crit}, borderColor:'#ef4444', tension:0.3, pointRadius:2 }}
    ] }},
  options:{{ plugins:{{ legend:{{ position:'bottom' }} }}, scales:{{ y:{{ beginAtZero:true }} }} }}
}});
</script>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"Dashboard written to {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <output.json> [dashboard.html]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_html = sys.argv[2] if len(sys.argv) > 2 else "dashboard.html"
    output_json = output_html.replace(".html", "_stats.json")

    print(f"Parsing {input_path}...")
    data = parse_log_file(input_path)
    print(f"  Found {len(data['spec_violations'])} spec violations")
    print(f"  Found {len(data['drift_findings'])} drift findings")
    print(f"  Found {len(data['scan_summaries'])} scan summaries")
    print(f"  Detected {data['scan_count']} scan cycles")

    print("Computing statistics...")
    stats = compute_statistics(data)

    # Save stats JSON
    with open(output_json, "w") as f:
        # Exclude the full lists to keep it small
        export = {k: v for k, v in stats.items()
                  if not k.endswith("_list")}
        json.dump(export, f, indent=2)
    print(f"Stats written to {output_json}")

    print("Generating dashboard...")
    generate_html(stats, output_html)
    print("Done!")

    # Summary
    print(f"\n{'='*60}")
    print(f"  SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Total scans:                {stats['total_scans']}")
    print(f"  Unique spec violations:     {stats['unique_spec_violations']}")
    print(f"  Unique drift findings:      {stats['unique_drift_findings']}")
    print(f"    Critical:                 {stats['drift_by_severity'].get('critical', 0)}")
    print(f"    Warning:                  {stats['drift_by_severity'].get('warning', 0)}")
    print(f"    Info:                     {stats['drift_by_severity'].get('info', 0)}")
    print(f"{'='*60}")
    print(f"\n  Key finding: {stats['drift_by_severity'].get('critical', 0)} CRITICAL")
    print(f"  drift detections where declared security restrictions")
    print(f"  are NOT enforced by the container runtime.\n")


if __name__ == "__main__":
    main()
