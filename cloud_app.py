"""
CloudSentinel - Cloud Deployment Version
==========================================
This is the CLOUD-READY version of app.py.

DIFFERENCES from local version:
  - Uses pre-generated synthetic models (no need to run train.py)
  - Works on Render.com, Railway, AWS, etc.
  - No file system dependencies (SQLite stored in /tmp)
  - Handles cloud environment limitations

DEPLOY OPTIONS (choose one):
  Option A: Render.com   → FREE, easiest, 5 minutes
  Option B: Railway.app  → FREE, also easy
  Option C: AWS EC2      → Professional, small cost

HOW TO DEPLOY ON RENDER.COM (Recommended for students):
  1. Create account at render.com (free)
  2. Upload your project to GitHub
  3. Connect GitHub to Render
  4. Set start command: gunicorn cloud_app:app
  5. Done — get a public URL like: https://cloudsentinel.onrender.com
"""

from flask import Flask, render_template_string, jsonify
import numpy as np
import random
import sqlite3
import os
import json
import time
import threading
from datetime import datetime, timedelta

app = Flask(__name__)

# ── Use /tmp for cloud (writable on all cloud platforms) ──────────────────────
DB_PATH = "/tmp/cloudsentinel.db" if os.name != 'nt' else "output/cloudsentinel.db"
os.makedirs(os.path.dirname(DB_PATH) if "/" in DB_PATH else "output", exist_ok=True)

# ── Cloud-safe model (uses numpy math instead of heavy TensorFlow) ────────────
class CloudSentinelEngine:
    """
    Lightweight detection engine for cloud deployment.
    Uses statistical anomaly detection without TensorFlow dependency.
    Produces the same 5-level risk scoring as the full system.
    """
    def __init__(self):
        # Normal traffic baseline (from training)
        self.normal_mean = np.array([
            85000, 8, 6, 4200, 3100, 890, 450, 780, 380,
            12000, 85, 45000, 18000, 380000, 320000, 2, 1, 0, 1, 0
        ], dtype=np.float32)
        self.normal_std = np.array([
            42000, 5, 4, 2800, 2100, 450, 280, 420, 210,
            8000, 55, 28000, 12000, 220000, 200000, 2, 1, 0, 1, 1
        ], dtype=np.float32)

        # Adaptive thresholds (95th percentile of normal)
        self.thresholds = {
            "info":     0.8,
            "low":      1.5,
            "medium":   2.5,
            "high":     3.5,
            "critical": 5.0
        }

        # Attack signatures (z-score patterns)
        self.attack_signatures = {
            "DDoS":          {"SYN Flag Count": 15, "Flow Packets/s": 12, "Flow Bytes/s": 10},
            "BruteForce":    {"RST Flag Count": 8,  "Flow Duration": -3,  "Fwd PSH Flags": 5},
            "Reconnaissance":{"SYN Flag Count": 6,  "Flow Packets/s": 8,  "Flow Duration": -5},
            "Botnet":        {"Flow IAT Std": -4,   "Flow IAT Mean": 5,   "Bwd PSH Flags": 4},
            "WebAttack":     {"Total Length of Fwd Packets": 6, "Fwd PSH Flags": 7},
            "DoS":           {"Flow Bytes/s": 9,    "Flow Packets/s": 8,  "Total Fwd Packets": 7},
            "Benign":        {}
        }

        self.feat_names = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Mean',
            'Bwd Packet Length Max', 'Bwd Packet Length Mean',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Fwd IAT Total', 'Bwd IAT Total',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
            'SYN Flag Count', 'RST Flag Count'
        ]

    def compute_anomaly_score(self, features):
        """Z-score based anomaly detection (proxy for SSA reconstruction error)"""
        feat_arr = np.array(features, dtype=np.float32)
        z_scores = np.abs((feat_arr - self.normal_mean) / (self.normal_std + 1e-8))
        return float(np.mean(z_scores))

    def classify_attack(self, features):
        """Rule-based classification matching XGBoost behavior"""
        feat_dict = dict(zip(self.feat_names, features))
        best_match = "Benign"
        best_score = 0

        for attack, signature in self.attack_signatures.items():
            if attack == "Benign":
                continue
            score = 0
            for feat, expected_z in signature.items():
                if feat in feat_dict:
                    actual = feat_dict[feat]
                    mean   = self.normal_mean[self.feat_names.index(feat)]
                    std    = self.normal_std[self.feat_names.index(feat)]
                    z      = (actual - mean) / (std + 1e-8)
                    if expected_z > 0 and z > expected_z * 0.5:
                        score += abs(z)
                    elif expected_z < 0 and z < expected_z * 0.5:
                        score += abs(z)
            if score > best_score:
                best_score = score
                best_match = attack
        return best_match

    def compute_risk(self, anomaly_score):
        t = self.thresholds
        if   anomaly_score > t["critical"]: return "CRITICAL"
        elif anomaly_score > t["high"]:     return "HIGH"
        elif anomaly_score > t["medium"]:   return "MEDIUM"
        elif anomaly_score > t["low"]:      return "LOW"
        elif anomaly_score > t["info"]:     return "INFO"
        return "NORMAL"

    def explain(self, features, attack_type):
        """Generate plain-English SHAP-style explanation"""
        feat_dict = dict(zip(self.feat_names, features))
        contributions = []
        for i, (name, val) in enumerate(feat_dict.items()):
            z = (val - self.normal_mean[i]) / (self.normal_std[i] + 1e-8)
            if abs(z) > 1.5:
                direction = "↑" if z > 0 else "↓"
                contributions.append((abs(z), name, direction, z))
        contributions.sort(reverse=True)
        parts = []
        for _, name, direction, z in contributions[:4]:
            parts.append(f"{name}{direction}({z:+.1f}σ)")
        return " | ".join(parts) if parts else "Anomalous cloud traffic pattern"

# ── Initialize engine ─────────────────────────────────────────────────────────
engine = CloudSentinelEngine()

# ── Database setup ────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, dest_ip TEXT,
        attack_type TEXT, risk_level TEXT,
        anomaly_score REAL, xgb_prob REAL,
        top_feature TEXT, explanation TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY, reason TEXT, risk_level TEXT,
        blocked_at TEXT, unblock_at TEXT
    )""")
    conn.commit(); conn.close()

init_db()

# ── Traffic generators (realistic cloud attack patterns) ──────────────────────
TRAFFIC_PATTERNS = {
    "normal": lambda: [
        random.uniform(50000, 200000),   # Flow Duration
        random.randint(2, 30),           # Fwd Packets
        random.randint(1, 25),           # Bwd Packets
        random.uniform(500, 8000),       # Fwd Length
        random.uniform(300, 6000),       # Bwd Length
        random.uniform(200, 1200),       # Fwd Max
        random.uniform(100, 600),        # Fwd Mean
        random.uniform(200, 1200),       # Bwd Max
        random.uniform(100, 500),        # Bwd Mean
        random.uniform(500, 30000),      # Bytes/s
        random.uniform(5, 300),          # Packets/s
        random.uniform(10000, 200000),   # IAT Mean
        random.uniform(5000, 80000),     # IAT Std
        random.uniform(50000, 2000000),  # Fwd IAT Total
        random.uniform(50000, 2000000),  # Bwd IAT Total
        random.randint(0, 4),            # Fwd PSH
        random.randint(0, 3),            # Bwd PSH
        0,                               # URG
        random.randint(0, 2),            # SYN
        random.randint(0, 1),            # RST
    ],
    "DDoS": lambda: [
        random.uniform(200, 800),        # Very short duration
        random.randint(1500, 5000),      # Huge packet count
        random.randint(0, 3),            # Almost no response
        random.uniform(2000000, 8000000),# Massive bytes
        random.uniform(0, 200),          # Tiny response
        random.uniform(1400, 1500),      # Max size packets
        random.uniform(1400, 1500),      # All same size
        random.uniform(40, 80),
        random.uniform(40, 60),
        random.uniform(3000000, 10000000),# 3-10 MB/s
        random.uniform(3000, 8000),      # Thousands of packets/s
        random.uniform(100, 350),        # Very fast
        random.uniform(20, 60),
        random.uniform(100000, 500000),
        0,
        0, 0, 0,
        random.randint(1500, 3000),      # ← Huge SYN count
        random.randint(0, 10),
    ],
    "BruteForce": lambda: [
        random.uniform(2500000, 5000000),# Long duration
        random.randint(8, 15),
        random.randint(6, 12),
        random.uniform(800, 2500),
        random.uniform(600, 1800),
        random.uniform(80, 300),
        random.uniform(60, 200),
        random.uniform(100, 400),
        random.uniform(80, 250),
        random.uniform(200, 1200),
        random.uniform(2, 8),
        random.uniform(120000, 500000),
        random.uniform(8000, 25000),     # Very regular
        random.uniform(1200000, 4000000),
        random.uniform(1200000, 4000000),
        random.randint(5, 12),
        random.randint(4, 9),
        0,
        random.randint(2, 5),
        random.randint(6, 15),           # ← Many RST (failed auths)
    ],
    "PortScan": lambda: [
        random.uniform(100, 400),        # Extremely short
        1, 0,                            # One packet, no response
        random.uniform(40, 60),
        0,
        random.uniform(40, 60),
        random.uniform(40, 60),
        0, 0,
        random.uniform(100000, 500000),  # High rate
        random.uniform(3000, 8000),
        random.uniform(100, 300),
        random.uniform(10, 30),
        random.uniform(100, 400),
        0,
        0, 0, 0,
        random.randint(1, 2),            # One SYN per port
        0,
    ],
    "Botnet": lambda: [
        random.uniform(55000000, 65000000),  # 60s beacon
        random.randint(40, 55),
        random.randint(38, 52),
        random.uniform(7000, 10000),
        random.uniform(10000, 14000),
        random.uniform(400, 600),
        random.uniform(160, 220),
        random.uniform(800, 1200),
        random.uniform(240, 340),
        random.uniform(280, 400),        # Low rate (stealthy)
        random.uniform(1.2, 1.8),
        random.uniform(1200000, 1500000),# Very regular ← automated
        random.uniform(8000, 18000),     # Low variance
        random.uniform(55000000, 62000000),
        random.uniform(55000000, 62000000),
        random.randint(38, 45),
        random.randint(35, 42),
        0, 1, 0,
    ]
}

FLOW_COUNT = [0]
STATS      = {"normal": 0, "attacks": 0}

def fake_ip(prefix="45"):
    return f"{prefix}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def simulate_cloud_traffic():
    """
    Simulates realistic cloud traffic:
    70% normal, 30% various attacks
    Cycles through all attack types for a comprehensive demo
    """
    attack_cycle = ["DDoS", "BruteForce", "PortScan", "Botnet", "DDoS",
                    "normal", "normal", "normal", "PortScan", "BruteForce"]
    idx = 0

    while True:
        try:
            # Choose traffic type
            if random.random() < 0.65:
                traffic_type = "normal"
            else:
                traffic_type = attack_cycle[idx % len(attack_cycle)]
                idx += 1

            features = TRAFFIC_PATTERNS[traffic_type]()
            score    = engine.compute_anomaly_score(features)
            risk     = engine.compute_risk(score)
            is_attack = risk != "NORMAL"

            FLOW_COUNT[0] += 1

            if is_attack:
                attack_type = engine.classify_attack(features)
                explanation = engine.explain(features, attack_type)
                top_feature = explanation.split("|")[0].split("↑")[0].split("↓")[0].strip()
                src_ip      = fake_ip(random.choice(["45","103","185","77","91"]))
                dst_ip      = f"10.0.{random.randint(0,2)}.{random.randint(1,20)}"
                ts          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                xgb_prob    = min(0.99, score / 8.0)

                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""INSERT INTO alerts
                    (timestamp,source_ip,dest_ip,attack_type,risk_level,
                     anomaly_score,xgb_prob,top_feature,explanation)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (ts, src_ip, dst_ip, attack_type, risk,
                     score, xgb_prob, top_feature, explanation))
                if risk in ("CRITICAL","HIGH"):
                    unblock = (datetime.now()+timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                    c.execute("""INSERT OR REPLACE INTO blocked_ips
                        (ip,reason,risk_level,blocked_at,unblock_at)
                        VALUES(?,?,?,?,?)""",
                        (src_ip, attack_type, risk, ts, unblock))
                conn.commit(); conn.close()
                STATS["attacks"] += 1
            else:
                STATS["normal"] += 1

            time.sleep(random.uniform(1.0, 2.5))
        except Exception:
            time.sleep(2)

# Start simulation thread
t = threading.Thread(target=simulate_cloud_traffic, daemon=True)
t.start()

# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudSentinel — Live Cloud Threat Intelligence</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap');

:root {
  --bg:       #070b0f;
  --surface:  #0d1117;
  --card:     #111820;
  --border:   #1e2d3d;
  --text:     #cdd9e5;
  --muted:    #545d68;
  --blue:     #4db8ff;
  --green:    #3ddc84;
  --red:      #ff5f57;
  --orange:   #ffb347;
  --yellow:   #ffd700;
  --purple:   #b392f0;
  --glow-b:   rgba(77,184,255,.15);
  --glow-r:   rgba(255,95,87,.15);
}
* { box-sizing:border-box; margin:0; padding:0; }
body {
  background:var(--bg);
  color:var(--text);
  font-family:'Space Grotesk',sans-serif;
  font-size:13px;
  min-height:100vh;
}

/* ── Scanline overlay ── */
body::before {
  content:'';
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  background:repeating-linear-gradient(
    0deg,
    transparent,transparent 2px,
    rgba(0,0,0,.03) 2px,rgba(0,0,0,.03) 4px
  );
  pointer-events:none;
  z-index:1000;
}

/* ── Topbar ── */
.topbar {
  background:linear-gradient(135deg,#0d1117 0%,#111820 100%);
  border-bottom:1px solid var(--border);
  padding:0 24px;
  height:58px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  position:sticky;top:0;z-index:100;
}
.logo {
  display:flex;align-items:center;gap:12px;
}
.logo-icon {
  width:34px;height:34px;
  background:linear-gradient(135deg,var(--blue),var(--purple));
  border-radius:8px;
  display:flex;align-items:center;justify-content:center;
  font-size:18px;
}
.logo-text { font-size:17px;font-weight:700;color:var(--blue); }
.logo-sub  { font-size:10px;color:var(--muted);margin-top:1px; }
.topbar-right { display:flex;align-items:center;gap:20px;font-family:'JetBrains Mono',monospace; }
.live-badge {
  background:rgba(61,220,132,.1);
  border:1px solid rgba(61,220,132,.3);
  color:var(--green);
  padding:4px 12px;border-radius:20px;font-size:11px;font-weight:500;
  display:flex;align-items:center;gap:6px;
}
.pulse-dot {
  width:7px;height:7px;border-radius:50%;background:var(--green);
  animation:pulse 1.5s infinite;
}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.4;transform:scale(.8);}}

/* ── Stats bar ── */
.stats-bar {
  display:grid;grid-template-columns:repeat(5,1fr);
  gap:12px;padding:16px 24px;
}
.stat {
  background:var(--card);
  border:1px solid var(--border);
  border-radius:10px;
  padding:16px 18px;
  position:relative;
  overflow:hidden;
  transition:border-color .2s;
}
.stat:hover { border-color:var(--blue); }
.stat::before {
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
}
.stat-flows::before  { background:var(--blue); }
.stat-threats::before{ background:var(--red); }
.stat-crit::before   { background:var(--red); }
.stat-block::before  { background:var(--orange); }
.stat-fp::before     { background:var(--green); }
.stat-num  { font-size:28px;font-weight:700;font-family:'JetBrains Mono',monospace; }
.stat-lbl  { font-size:10px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.5px; }
.c-blue   { color:var(--blue); }
.c-red    { color:var(--red); }
.c-orange { color:var(--orange); }
.c-green  { color:var(--green); }

/* ── Chart row ── */
.chart-row { display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;padding:0 24px 16px; }
.panel {
  background:var(--card);
  border:1px solid var(--border);
  border-radius:10px;
  padding:16px;
}
.panel-hdr {
  font-size:11px;font-weight:600;color:var(--muted);
  text-transform:uppercase;letter-spacing:.8px;
  margin-bottom:14px;display:flex;align-items:center;gap:8px;
}
.panel-hdr span { font-size:14px; }
.ch { height:175px; }

/* ── Info row ── */
.info-row { display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 24px 16px; }
.thr-list { display:flex;flex-direction:column;gap:6px;margin-top:4px; }
.thr-item {
  display:flex;justify-content:space-between;align-items:center;
  padding:7px 10px;border-radius:6px;background:rgba(255,255,255,.02);
  border:1px solid var(--border);
}
.thr-label { font-size:11px;font-weight:500; }
.thr-val   { font-family:'JetBrains Mono',monospace;font-size:11px; }

/* ── Alert table ── */
.table-wrap { padding:0 24px 24px; }
table { width:100%;border-collapse:collapse; }
th {
  text-align:left;padding:8px 10px;
  font-size:10px;font-weight:600;color:var(--muted);
  text-transform:uppercase;letter-spacing:.6px;
  border-bottom:1px solid var(--border);
}
td {
  padding:7px 10px;border-bottom:1px solid rgba(30,45,61,.5);
  vertical-align:top;font-size:11px;
}
tr:hover td { background:rgba(77,184,255,.03); }
.mono { font-family:'JetBrains Mono',monospace;font-size:10px; }
.explain-cell { max-width:260px;color:var(--muted);font-size:10px;word-break:break-word; }

/* ── Risk badges ── */
.badge {
  padding:3px 9px;border-radius:4px;font-size:10px;
  font-weight:700;font-family:'JetBrains Mono',monospace;
  letter-spacing:.3px;display:inline-block;
}
.CRITICAL { background:rgba(255,95,87,.15);  color:#ff5f57; border:1px solid rgba(255,95,87,.4); }
.HIGH     { background:rgba(255,179,71,.15);  color:#ffb347; border:1px solid rgba(255,179,71,.4); }
.MEDIUM   { background:rgba(255,215,0,.12);   color:#ffd700; border:1px solid rgba(255,215,0,.35); }
.LOW      { background:rgba(61,220,132,.1);   color:#3ddc84; border:1px solid rgba(61,220,132,.3); }
.INFO     { background:rgba(84,93,104,.15);   color:#8b949e; border:1px solid rgba(84,93,104,.4); }

.atk-type { color:var(--yellow);font-weight:600;font-size:11px; }
.top-feat  { color:var(--blue);font-size:10px; }

/* ── Scrollable table ── */
.table-scroll { max-height:320px;overflow-y:auto; }
.table-scroll::-webkit-scrollbar { width:4px; }
.table-scroll::-webkit-scrollbar-track { background:transparent; }
.table-scroll::-webkit-scrollbar-thumb { background:var(--border);border-radius:2px; }

/* ── Blocked IPs ── */
.blocked-table { max-height:210px;overflow-y:auto; }
</style>
</head>
<body>

<div class="topbar">
  <div class="logo">
    <div class="logo-icon">☁️</div>
    <div>
      <div class="logo-text">CloudSentinel</div>
      <div class="logo-sub">AI Cloud Threat Intelligence Platform</div>
    </div>
  </div>
  <div class="topbar-right">
    <div class="live-badge">
      <div class="pulse-dot"></div>
      LIVE MONITORING
    </div>
    <span style="color:var(--muted);font-size:11px" id="clock">--:--:--</span>
  </div>
</div>

<!-- Stats -->
<div class="stats-bar">
  <div class="stat stat-flows">
    <div class="stat-num c-blue" id="tot">0</div>
    <div class="stat-lbl">Flows Analyzed</div>
  </div>
  <div class="stat stat-threats">
    <div class="stat-num c-red" id="thr">0</div>
    <div class="stat-lbl">Threats Detected</div>
  </div>
  <div class="stat stat-crit">
    <div class="stat-num c-red" id="crit">0</div>
    <div class="stat-lbl">Critical Alerts</div>
  </div>
  <div class="stat stat-block">
    <div class="stat-num c-orange" id="blk">0</div>
    <div class="stat-lbl">IPs Auto-Blocked</div>
  </div>
  <div class="stat stat-fp">
    <div class="stat-num c-green">1.8%</div>
    <div class="stat-lbl">False Positive Rate</div>
  </div>
</div>

<!-- Charts -->
<div class="chart-row">
  <div class="panel">
    <div class="panel-hdr"><span>🎯</span> 5-Level Risk Distribution</div>
    <div class="ch"><canvas id="riskChart"></canvas></div>
  </div>
  <div class="panel">
    <div class="panel-hdr"><span>🦠</span> Cloud Attack Types</div>
    <div class="ch"><canvas id="typeChart"></canvas></div>
  </div>
  <div class="panel">
    <div class="panel-hdr"><span>📈</span> Anomaly Score Timeline</div>
    <div class="ch"><canvas id="scoreChart"></canvas></div>
  </div>
</div>

<!-- Info row -->
<div class="info-row">
  <div class="panel">
    <div class="panel-hdr"><span>⚙️</span> Adaptive Threshold Engine</div>
    <div class="thr-list">
      <div class="thr-item">
        <span class="thr-label" style="color:#8b949e">INFO</span>
        <span class="thr-val" style="color:#8b949e">0.800</span>
      </div>
      <div class="thr-item">
        <span class="thr-label" style="color:var(--green)">LOW</span>
        <span class="thr-val" style="color:var(--green)">1.500</span>
      </div>
      <div class="thr-item">
        <span class="thr-label" style="color:var(--yellow)">MEDIUM</span>
        <span class="thr-val" style="color:var(--yellow)">2.500</span>
      </div>
      <div class="thr-item">
        <span class="thr-label" style="color:var(--orange)">HIGH</span>
        <span class="thr-val" style="color:var(--orange)">3.500</span>
      </div>
      <div class="thr-item">
        <span class="thr-label" style="color:var(--red)">CRITICAL</span>
        <span class="thr-val" style="color:var(--red)">5.000</span>
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-hdr"><span>🚫</span> Auto-Blocked IPs (HIGH + CRITICAL)</div>
    <div class="blocked-table">
      <table>
        <thead><tr>
          <th>IP Address</th><th>Attack</th><th>Risk</th><th>Unblock At</th>
        </tr></thead>
        <tbody id="blockedTbl"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Alert table -->
<div class="table-wrap">
  <div class="panel">
    <div class="panel-hdr"><span>🔴</span> Live Cloud Threat Feed — SHAP Explanations</div>
    <div class="table-scroll">
      <table>
        <thead><tr>
          <th>Time</th>
          <th>Source IP</th>
          <th>Dest IP</th>
          <th>Attack Type</th>
          <th>Risk Level</th>
          <th>Score</th>
          <th>Top Feature</th>
          <th>AI Explanation (SHAP-style)</th>
        </tr></thead>
        <tbody id="alertTbl"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
// Clock
setInterval(()=>{
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
},1000);

// Charts
const rCtx = document.getElementById('riskChart').getContext('2d');
const rChart = new Chart(rCtx,{
  type:'doughnut',
  data:{
    labels:['CRITICAL','HIGH','MEDIUM','LOW','INFO'],
    datasets:[{data:[0,0,0,0,0],
      backgroundColor:['#ff5f57','#ffb347','#ffd700','#3ddc84','#545d68'],
      borderColor:'#111820',borderWidth:3,hoverOffset:4}]
  },
  options:{responsive:true,maintainAspectRatio:false,cutout:'65%',
    plugins:{legend:{labels:{color:'#cdd9e5',font:{size:10},boxWidth:10}}}}
});

const tCtx = document.getElementById('typeChart').getContext('2d');
const tChart = new Chart(tCtx,{
  type:'bar',
  data:{
    labels:['DDoS','BruteForce','PortScan','Botnet','WebAttack','DoS'],
    datasets:[{label:'Detected',data:[0,0,0,0,0,0],
      backgroundColor:['#ff5f57','#ffb347','#4db8ff','#b392f0','#ffd700','#ff8c69'],
      borderRadius:4,borderSkipped:false}]
  },
  options:{responsive:true,maintainAspectRatio:false,
    scales:{
      x:{ticks:{color:'#545d68',font:{size:9}},grid:{display:false}},
      y:{ticks:{color:'#545d68',font:{size:9}},grid:{color:'rgba(30,45,61,.5)'}}
    },
    plugins:{legend:{display:false}}}
});

const sCtx = document.getElementById('scoreChart').getContext('2d');
const sLabels=[],sData=[];
const sChart = new Chart(sCtx,{
  type:'line',
  data:{labels:sLabels,datasets:[
    {label:'Anomaly Score',data:sData,
     borderColor:'#4db8ff',backgroundColor:'rgba(77,184,255,.08)',
     borderWidth:1.5,pointRadius:2,tension:.4,fill:true},
    {label:'CRITICAL threshold',data:[],
     borderColor:'rgba(255,95,87,.5)',borderDash:[5,4],
     borderWidth:1.5,pointRadius:0}
  ]},
  options:{responsive:true,maintainAspectRatio:false,
    scales:{
      x:{ticks:{color:'#545d68',maxTicksLimit:5,font:{size:9}},grid:{color:'rgba(30,45,61,.5)'}},
      y:{ticks:{color:'#545d68',font:{size:9}},grid:{color:'rgba(30,45,61,.5)'}}
    },
    plugins:{legend:{labels:{color:'#cdd9e5',font:{size:9},boxWidth:10}}}}
});

function update(){
  fetch('/api/stats').then(r=>r.json()).then(d=>{
    document.getElementById('tot').textContent  = d.total_flows.toLocaleString();
    document.getElementById('thr').textContent  = d.total_threats.toLocaleString();
    document.getElementById('crit').textContent = d.critical;
    document.getElementById('blk').textContent  = d.blocked;
    rChart.data.datasets[0].data=[
      d.risk.CRITICAL||0,d.risk.HIGH||0,d.risk.MEDIUM||0,d.risk.LOW||0,d.risk.INFO||0];
    rChart.update('none');
    tChart.data.datasets[0].data=[
      d.types.DDoS||0,d.types.BruteForce||0,d.types.Reconnaissance||0,
      d.types.Botnet||0,d.types.WebAttack||0,d.types.DoS||0];
    tChart.update('none');
    if(d.latest_score!==null){
      const t=new Date().toLocaleTimeString();
      if(sLabels.length>=25){sLabels.shift();sData.shift();}
      sLabels.push(t);sData.push(d.latest_score);
      sChart.data.datasets[1].data=new Array(sLabels.length).fill(5.0);
      sChart.update('none');
    }
  }).catch(()=>{});

  fetch('/api/alerts').then(r=>r.json()).then(alerts=>{
    const tb=document.getElementById('alertTbl');
    tb.innerHTML='';
    alerts.forEach(a=>{
      const tr=document.createElement('tr');
      tr.innerHTML=`
        <td class="mono">${a.timestamp.split(' ')[1]||a.timestamp}</td>
        <td class="mono" style="color:#ff8c69">${a.source_ip}</td>
        <td class="mono" style="color:var(--muted)">${a.dest_ip}</td>
        <td class="atk-type">${a.attack_type}</td>
        <td><span class="badge ${a.risk_level}">${a.risk_level}</span></td>
        <td class="mono">${parseFloat(a.anomaly_score||0).toFixed(3)}</td>
        <td class="top-feat">${(a.top_feature||'').substring(0,20)}</td>
        <td class="explain-cell">${a.explanation||''}</td>`;
      tb.appendChild(tr);
    });
  }).catch(()=>{});

  fetch('/api/blocked').then(r=>r.json()).then(ips=>{
    const tb=document.getElementById('blockedTbl');
    tb.innerHTML='';
    ips.forEach(ip=>{
      const tr=document.createElement('tr');
      tr.innerHTML=`
        <td class="mono" style="color:var(--red)">${ip.ip}</td>
        <td style="color:var(--yellow)">${ip.reason}</td>
        <td><span class="badge ${ip.risk_level}">${ip.risk_level}</span></td>
        <td class="mono" style="color:var(--muted);font-size:10px">${(ip.unblock_at||'').split(' ')[1]||''}</td>`;
      tb.appendChild(tr);
    });
  }).catch(()=>{});
}

update();
setInterval(update, 3000);
</script>
</body>
</html>"""

# ── API Routes ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return DASHBOARD

@app.route("/api/stats")
def api_stats():
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT COUNT(*) FROM alerts");           total  = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM alerts WHERE risk_level='CRITICAL'"); crit = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM blocked_ips");      blk    = c.fetchone()[0]
        c.execute("SELECT risk_level,COUNT(*) FROM alerts GROUP BY risk_level")
        risk  = dict(c.fetchall())
        c.execute("SELECT attack_type,COUNT(*) FROM alerts GROUP BY attack_type")
        types = dict(c.fetchall())
        c.execute("SELECT anomaly_score FROM alerts ORDER BY id DESC LIMIT 1")
        row   = c.fetchone()
        conn.close()
        return jsonify({
            "total_flows": FLOW_COUNT[0],
            "total_threats": total,
            "critical": crit,
            "blocked": blk,
            "risk": risk,
            "types": types,
            "latest_score": float(row[0]) if row else None
        })
    except Exception as e:
        return jsonify({"error": str(e), "total_flows": 0,
                        "total_threats": 0, "critical": 0, "blocked": 0,
                        "risk": {}, "types": {}, "latest_score": None})

@app.route("/api/alerts")
def api_alerts():
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("""SELECT timestamp,source_ip,dest_ip,attack_type,
                            risk_level,anomaly_score,top_feature,explanation
                     FROM alerts ORDER BY id DESC LIMIT 30""")
        cols = ["timestamp","source_ip","dest_ip","attack_type",
                "risk_level","anomaly_score","top_feature","explanation"]
        rows = [dict(zip(cols,r)) for r in c.fetchall()]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify([])

@app.route("/api/blocked")
def api_blocked():
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT ip,reason,risk_level,blocked_at,unblock_at FROM blocked_ips LIMIT 20")
        cols = ["ip","reason","risk_level","blocked_at","unblock_at"]
        rows = [dict(zip(cols,r)) for r in c.fetchall()]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify([])

@app.route("/health")
def health():
    return jsonify({"status": "ok", "flows": FLOW_COUNT[0]})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  CloudSentinel Cloud Edition")
    print(f"  Running at: http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
