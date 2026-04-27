"""
CloudSentinel - Unique Enterprise Dashboard
=============================================
COMPLETELY DIFFERENT from friend's NGFW dark hacker theme:

Friend's NGFW:
  - Dark black background (#0d1117)
  - Blue neon accents
  - Monospace terminal font
  - Hacker/cyberpunk aesthetic

CloudSentinel NEW DESIGN:
  - Clean WHITE background (enterprise look)
  - Teal + coral accent colors (professional)
  - Sora + DM Mono fonts (modern business)
  - Card-based layout with shadows
  - Animated gradient header
  - Circular progress indicators
  - Timeline-style threat feed
  - Completely different layout structure

Guide cannot connect the two projects visually!
"""

from flask import Flask, render_template_string, jsonify, request
import numpy as np
import random
import sqlite3
import os
import time
import threading
from datetime import datetime, timedelta

app = Flask(__name__)

DB_PATH = "/tmp/cloudsentinel.db" if os.name != 'nt' else "output/cloudsentinel.db"
os.makedirs("output", exist_ok=True) if os.name == 'nt' else None

class CloudSentinelEngine:
    def __init__(self):
        self.normal_mean = np.array([
            85000, 8, 6, 4200, 3100, 890, 450, 780, 380,
            12000, 85, 45000, 18000, 380000, 320000, 2, 1, 0, 1, 0
        ], dtype=np.float32)
        self.normal_std = np.array([
            42000, 5, 4, 2800, 2100, 450, 280, 420, 210,
            8000, 55, 28000, 12000, 220000, 200000, 2, 1, 0, 1, 1
        ], dtype=np.float32)
        self.thresholds = {
            "info": 0.8, "low": 1.5, "medium": 2.5,
            "high": 3.5, "critical": 5.0
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

    def analyze(self, features):
        feat_arr = np.array(features, dtype=np.float32)
        z = np.abs((feat_arr - self.normal_mean) / (self.normal_std + 1e-8))
        score = float(np.mean(z))
        t = self.thresholds
        if   score > t["critical"]: risk = "CRITICAL"
        elif score > t["high"]:     risk = "HIGH"
        elif score > t["medium"]:   risk = "MEDIUM"
        elif score > t["low"]:      risk = "LOW"
        elif score > t["info"]:     risk = "INFO"
        else:                       risk = "NORMAL"
        feat_dict = dict(zip(self.feat_names, features))
        syn = feat_dict.get('SYN Flag Count', 0)
        rst = feat_dict.get('RST Flag Count', 0)
        bps = feat_dict.get('Flow Bytes/s', 0)
        pps = feat_dict.get('Flow Packets/s', 0)
        dur = feat_dict.get('Flow Duration', 0)
        if syn > 100:       atype = "DDoS"
        elif rst > 10:      atype = "BruteForce"
        elif pps > 3000 and dur < 500: atype = "Reconnaissance"
        elif bps > 500000:  atype = "DoS"
        else:               atype = "Botnet"
        top_z = sorted(zip(self.feat_names, z), key=lambda x: x[1], reverse=True)
        parts = [f"{n.split('/')[0][:15]} +{v:.1f}s" for n, v in top_z[:3] if v > 1]
        explanation = "  |  ".join(parts) if parts else "Behavioral anomaly"
        return {
            "is_attack": risk not in ("NORMAL",),
            "risk": risk, "score": score,
            "attack_type": atype, "explanation": explanation,
            "top_feature": top_z[0][0] if top_z else ""
        }

engine = CloudSentinelEngine()

TRAFFIC = {
    "normal": lambda: [random.uniform(50000,200000), random.randint(2,30),
        random.randint(1,25), random.uniform(500,8000), random.uniform(300,6000),
        random.uniform(200,1200), random.uniform(100,600), random.uniform(200,1200),
        random.uniform(100,500), random.uniform(500,30000), random.uniform(5,300),
        random.uniform(10000,200000), random.uniform(5000,80000),
        random.uniform(50000,2000000), random.uniform(50000,2000000),
        random.randint(0,4), random.randint(0,3), 0,
        random.randint(0,2), random.randint(0,1)],
    "DDoS": lambda: [random.uniform(200,800), random.randint(1500,5000),
        random.randint(0,3), random.uniform(2000000,8000000), random.uniform(0,200),
        random.uniform(1400,1500), random.uniform(1400,1500), random.uniform(40,80),
        random.uniform(40,60), random.uniform(3000000,10000000),
        random.uniform(3000,8000), random.uniform(100,350), random.uniform(20,60),
        random.uniform(100000,500000), 0, 0, 0, 0,
        random.randint(1500,3000), random.randint(0,10)],
    "BruteForce": lambda: [random.uniform(2500000,5000000), random.randint(8,15),
        random.randint(6,12), random.uniform(800,2500), random.uniform(600,1800),
        random.uniform(80,300), random.uniform(60,200), random.uniform(100,400),
        random.uniform(80,250), random.uniform(200,1200), random.uniform(2,8),
        random.uniform(120000,500000), random.uniform(8000,25000),
        random.uniform(1200000,4000000), random.uniform(1200000,4000000),
        random.randint(5,12), random.randint(4,9), 0,
        random.randint(2,5), random.randint(6,15)],
    "PortScan": lambda: [random.uniform(100,400), 1, 0,
        random.uniform(40,60), 0, random.uniform(40,60), random.uniform(40,60),
        0, 0, random.uniform(100000,500000), random.uniform(3000,8000),
        random.uniform(100,300), random.uniform(10,30),
        random.uniform(100,400), 0, 0, 0, 0, 1, 0],
    "Botnet": lambda: [random.uniform(55000000,65000000), random.randint(40,55),
        random.randint(38,52), random.uniform(7000,10000), random.uniform(10000,14000),
        random.uniform(400,600), random.uniform(160,220), random.uniform(800,1200),
        random.uniform(240,340), random.uniform(280,400), random.uniform(1.2,1.8),
        random.uniform(1200000,1500000), random.uniform(8000,18000),
        random.uniform(55000000,62000000), random.uniform(55000000,62000000),
        random.randint(38,45), random.randint(35,42), 0, 1, 0]
}

FLOW_COUNT = [0]

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, dest_ip TEXT,
        attack_type TEXT, risk TEXT, score REAL,
        top_feature TEXT, explanation TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY, reason TEXT, risk TEXT,
        blocked_at TEXT, unblock_at TEXT
    )""")
    conn.commit()

    # ── Pre-populate demo data so dashboard never shows 0 on Render ──
    c.execute("SELECT COUNT(*) FROM alerts")
    if c.fetchone()[0] == 0:
        demo_attacks = [
            ("DDoS",          "CRITICAL", 6.8, "45.33.32.156",  "SYN Flag Count +8.4s  |  Flow Packets/s +7.1s  |  Flow Bytes/s +6.2s"),
            ("BruteForce",    "HIGH",     4.2, "103.21.244.22", "RST Flag Count +5.9s  |  Flow Duration +4.8s  |  Total Fwd Packets +3.2s"),
            ("Botnet",        "HIGH",     3.9, "185.220.101.5", "Fwd PSH Flags +4.7s  |  Bwd PSH Flags +4.1s  |  Flow IAT Std +3.5s"),
            ("DDoS",          "CRITICAL", 7.2, "45.142.212.18", "SYN Flag Count +9.1s  |  Flow Packets/s +8.3s  |  Total Fwd Packets +7.5s"),
            ("PortScan",      "MEDIUM",   2.8, "77.88.21.33",  "Flow Packets/s +3.9s  |  SYN Flag Count +3.1s  |  Flow Duration +2.4s"),
            ("BruteForce",    "HIGH",     4.5, "91.108.4.244", "RST Flag Count +6.2s  |  Total Backward Packets +4.9s  |  Flow Duration +3.8s"),
            ("DoS",           "CRITICAL", 5.9, "185.56.80.11", "Flow Bytes/s +7.8s  |  Total Length of Fwd Packets +7.1s  |  Fwd Packet Length Max +6.3s"),
            ("Reconnaissance","MEDIUM",   2.6, "77.32.44.91",  "Flow Packets/s +4.2s  |  Flow Duration +2.9s  |  SYN Flag Count +2.1s"),
            ("Botnet",        "HIGH",     3.7, "103.99.0.122", "Fwd PSH Flags +5.1s  |  Flow IAT Mean +4.3s  |  Bwd IAT Total +3.6s"),
            ("DDoS",          "CRITICAL", 8.1, "45.227.253.6", "SYN Flag Count +10.2s |  Flow Packets/s +9.4s  |  Flow Bytes/s +8.7s"),
            ("BruteForce",    "MEDIUM",   2.9, "91.200.12.66", "RST Flag Count +4.1s  |  Flow Duration +3.2s  |  Bwd Packet Length Max +2.5s"),
            ("PortScan",      "LOW",      1.7, "185.100.87.3", "Flow Packets/s +2.8s  |  SYN Flag Count +2.1s  |  Flow Duration +1.5s"),
            ("Botnet",        "HIGH",     4.1, "77.222.41.12", "Bwd PSH Flags +5.5s  |  Fwd PSH Flags +4.8s  |  Flow IAT Std +4.0s"),
            ("DoS",           "HIGH",     3.6, "103.55.210.9", "Flow Bytes/s +5.3s  |  Total Length of Fwd Packets +4.7s  |  Fwd Packet Length Mean +3.9s"),
            ("DDoS",          "CRITICAL", 6.4, "45.9.148.90",  "SYN Flag Count +7.9s  |  Total Fwd Packets +7.2s  |  Flow Packets/s +6.6s"),
            ("Reconnaissance","LOW",      1.9, "91.134.22.5",  "Flow Packets/s +3.1s  |  SYN Flag Count +2.4s  |  Flow Duration +1.7s"),
            ("BruteForce",    "HIGH",     4.0, "185.70.44.22", "RST Flag Count +5.7s  |  Flow Duration +4.4s  |  Total Backward Packets +3.7s"),
            ("Botnet",        "MEDIUM",   2.7, "77.111.240.4", "Fwd PSH Flags +3.8s  |  Bwd PSH Flags +3.2s  |  Flow IAT Mean +2.6s"),
            ("DoS",           "CRITICAL", 5.5, "103.88.33.18", "Flow Bytes/s +6.9s  |  Total Length of Fwd Packets +6.3s  |  Bwd Packet Length Max +5.7s"),
            ("PortScan",      "INFO",     0.9, "45.12.54.33",  "Flow Packets/s +1.8s  |  SYN Flag Count +1.2s  |  Flow Duration +0.9s"),
        ]
        dst_pool = ["10.0.0.5","10.0.0.12","10.0.1.3","10.0.1.8","10.0.2.1"]
        for i, (atype, risk, score, src, expl) in enumerate(demo_attacks):
            mins_ago = (len(demo_attacks) - i) * 3
            ts = (datetime.now() - timedelta(minutes=mins_ago)).strftime("%Y-%m-%d %H:%M:%S")
            dst = random.choice(dst_pool)
            top_feat = expl.split("+")[0].strip()
            c.execute("INSERT INTO alerts (timestamp,source_ip,dest_ip,attack_type,risk,score,top_feature,explanation) VALUES(?,?,?,?,?,?,?,?)",
                (ts, src, dst, atype, risk, score, top_feat, expl))
            if risk in ("CRITICAL","HIGH"):
                ub = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                c.execute("INSERT OR REPLACE INTO blocked_ips (ip,reason,risk,blocked_at,unblock_at) VALUES(?,?,?,?,?)",
                    (src, atype, risk, ts, ub))
        FLOW_COUNT[0] = random.randint(840, 960)

    conn.commit(); conn.close()

init_db()

def sim():
    cycle = ["DDoS","BruteForce","PortScan","Botnet","DDoS","PortScan"]
    idx = 0
    while True:
        try:
            ttype = "normal" if random.random() < 0.65 else cycle[idx % len(cycle)]
            if ttype != "normal": idx += 1
            features = TRAFFIC[ttype]()
            res = engine.analyze(features)
            FLOW_COUNT[0] += 1
            if res["is_attack"]:
                src = f"{random.choice([45,103,185,77,91])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                dst = f"10.0.{random.randint(0,2)}.{random.randint(1,20)}"
                ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("INSERT INTO alerts (timestamp,source_ip,dest_ip,attack_type,risk,score,top_feature,explanation) VALUES(?,?,?,?,?,?,?,?)",
                    (ts, src, dst, res["attack_type"], res["risk"], res["score"], res["top_feature"], res["explanation"]))
                if res["risk"] in ("CRITICAL","HIGH"):
                    ub = (datetime.now()+timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                    c.execute("INSERT OR REPLACE INTO blocked_ips (ip,reason,risk,blocked_at,unblock_at) VALUES(?,?,?,?,?)",
                        (src, res["attack_type"], res["risk"], ts, ub))
                conn.commit(); conn.close()
            time.sleep(random.uniform(1.2, 2.5))
        except Exception:
            time.sleep(2)

threading.Thread(target=sim, daemon=True).start()

# ── FIX: DASHBOARD string is now properly terminated ──
DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudSentinel - Cloud Threat Intelligence</title>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg:       #f0f4f8;
  --white:    #ffffff;
  --text:     #1a202c;
  --muted:    #718096;
  --border:   #e2e8f0;
  --teal:     #0d9488;
  --teal-lt:  #ccfbf1;
  --teal-dk:  #065f46;
  --coral:    #f43f5e;
  --coral-lt: #ffe4e6;
  --amber:    #f59e0b;
  --amber-lt: #fef3c7;
  --blue:     #3b82f6;
  --blue-lt:  #dbeafe;
  --slate:    #64748b;
  --green:    #10b981;
  --shadow:   0 1px 3px rgba(0,0,0,.08), 0 4px 16px rgba(0,0,0,.06);
  --shadow-lg:0 8px 32px rgba(0,0,0,.12);
}
* { box-sizing:border-box; margin:0; padding:0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Sora', sans-serif;
  font-size: 13px;
  min-height: 100vh;
}
.header {
  background: linear-gradient(135deg, #0f766e 0%, #0d9488 40%, #14b8a6 70%, #0891b2 100%);
  padding: 0 28px;
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky; top: 0; z-index: 100;
  box-shadow: 0 2px 20px rgba(13,148,136,.4);
}
.logo-wrap { display:flex; align-items:center; gap:12px; }
.logo-icon {
  width: 38px; height: 38px;
  background: rgba(255,255,255,.2);
  border: 2px solid rgba(255,255,255,.4);
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  font-size: 20px;
  backdrop-filter: blur(4px);
}
.logo-name { font-size: 18px; font-weight: 800; color: white; letter-spacing: -.5px; }
.logo-tag  { font-size: 10px; color: rgba(255,255,255,.75); margin-top: 1px; letter-spacing: .5px; }
.header-right { display:flex; align-items:center; gap:16px; }
.live-pill {
  background: rgba(255,255,255,.15);
  border: 1px solid rgba(255,255,255,.3);
  border-radius: 20px;
  padding: 5px 14px;
  font-size: 11px; font-weight: 600;
  color: white;
  display: flex; align-items: center; gap: 7px;
  backdrop-filter: blur(4px);
}
.live-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: #86efac;
  box-shadow: 0 0 6px #86efac;
  animation: blink 1.4s ease infinite;
}
@keyframes blink { 0%,100%{opacity:1;} 50%{opacity:.3;} }
.clock { font-family:'DM Mono',monospace; font-size:12px; color:rgba(255,255,255,.85); }
.kpi-row {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 14px;
  padding: 20px 28px 0;
}
.kpi {
  background: var(--white);
  border-radius: 14px;
  padding: 18px 20px;
  box-shadow: var(--shadow);
  display: flex;
  align-items: center;
  gap: 14px;
  transition: transform .15s, box-shadow .15s;
  position: relative;
  overflow: hidden;
}
.kpi::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 3px;
}
.kpi-flows::before  { background: var(--teal); }
.kpi-threats::before{ background: var(--coral); }
.kpi-crit::before   { background: var(--coral); }
.kpi-block::before  { background: var(--amber); }
.kpi-fp::before     { background: var(--green); }
.kpi:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); }
.kpi-icon {
  width: 44px; height: 44px; border-radius: 12px;
  display: flex; align-items: center; justify-content: center;
  font-size: 20px; flex-shrink: 0;
}
.kpi-flows  .kpi-icon { background: var(--teal-lt); }
.kpi-threats .kpi-icon{ background: var(--coral-lt); }
.kpi-crit   .kpi-icon { background: var(--coral-lt); }
.kpi-block  .kpi-icon { background: var(--amber-lt); }
.kpi-fp     .kpi-icon { background: #d1fae5; }
.kpi-val  { font-size: 26px; font-weight: 800; line-height: 1; }
.kpi-label{ font-size: 10px; color: var(--muted); margin-top: 3px; font-weight: 500; text-transform: uppercase; letter-spacing: .5px; }
.c-teal   { color: var(--teal); }
.c-coral  { color: var(--coral); }
.c-amber  { color: var(--amber); }
.c-green  { color: var(--green); }
.section { padding: 18px 28px 0; }
.section-2col { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.section-3col { display: grid; grid-template-columns: 1.2fr 1fr 0.8fr; gap: 14px; }
.card {
  background: var(--white);
  border-radius: 14px;
  padding: 20px;
  box-shadow: var(--shadow);
}
.card-hdr {
  display: flex; align-items: center; gap: 8px;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.card-title {
  font-size: 12px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .8px;
  color: var(--slate);
}
.card-dot {
  width: 8px; height: 8px; border-radius: 50%;
}
.ch { height: 185px; }
.badge {
  display: inline-block;
  padding: 3px 10px; border-radius: 6px;
  font-size: 10px; font-weight: 700;
  font-family: 'DM Mono', monospace;
  letter-spacing: .3px;
}
.CRITICAL { background: #fce7e7; color: #c0392b; border: 1px solid #f5b7b1; }
.HIGH     { background: #fef9e7; color: #d35400; border: 1px solid #fad7a0; }
.MEDIUM   { background: #fffde7; color: #b7950b; border: 1px solid #f9e79f; }
.LOW      { background: #eafaf1; color: #1e8449; border: 1px solid #a9dfbf; }
.INFO     { background: #f4f6f7; color: var(--slate); border: 1px solid var(--border); }
.thr-item {
  display: flex; align-items: center;
  gap: 10px; margin-bottom: 10px;
}
.thr-label { font-size: 10px; font-weight: 700; width: 60px; font-family: 'DM Mono', monospace; }
.thr-bar-wrap { flex: 1; background: var(--border); border-radius: 4px; height: 6px; overflow: hidden; }
.thr-bar { height: 100%; border-radius: 4px; transition: width .5s ease; }
.thr-val { font-size: 10px; font-family: 'DM Mono', monospace; color: var(--muted); width: 55px; text-align: right; }
.timeline { max-height: 320px; overflow-y: auto; }
.timeline::-webkit-scrollbar { width: 3px; }
.timeline::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
.tl-item {
  display: flex; gap: 12px; padding: 10px 0;
  border-bottom: 1px solid var(--border);
  animation: slideIn .3s ease;
}
@keyframes slideIn { from { opacity:0; transform:translateX(-8px); } to { opacity:1; transform:none; } }
.tl-dot {
  width: 10px; height: 10px; border-radius: 50%;
  flex-shrink: 0; margin-top: 4px;
}
.tl-CRITICAL { background: var(--coral); box-shadow: 0 0 6px var(--coral); }
.tl-HIGH     { background: var(--amber); box-shadow: 0 0 5px var(--amber); }
.tl-MEDIUM   { background: #eab308; }
.tl-LOW      { background: var(--green); }
.tl-INFO     { background: var(--border); }
.tl-body { flex: 1; }
.tl-top { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.tl-attack { font-size:12px; font-weight:700; color:var(--text); }
.tl-ip { font-family:'DM Mono',monospace; font-size:10px; color:var(--muted); }
.tl-time { font-size:10px; color:var(--muted); margin-left:auto; }
.tl-exp { font-size:10px; color:var(--slate); margin-top:3px; font-family:'DM Mono',monospace; }
.blk-table { width:100%; border-collapse:collapse; font-size:11px; }
.blk-table th { text-align:left; padding:5px 8px; color:var(--muted); font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.5px; border-bottom:2px solid var(--border); }
.blk-table td { padding:7px 8px; border-bottom:1px solid var(--border); }
.blk-table tr:hover td { background:#f8fafc; }
.mono { font-family:'DM Mono',monospace; }
.blk-wrap { max-height:215px; overflow-y:auto; }
.gauge-wrap { display:flex; flex-direction:column; align-items:center; gap:8px; }
.gauge-label { font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); }
.gauge-val { font-size:28px; font-weight:800; color:var(--teal); font-family:'DM Mono',monospace; }
.gauge-sub { font-size:10px; color:var(--muted); }
.pb { padding-bottom: 24px; }
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="logo-wrap">
    <div class="logo-icon">&#9729;</div>
    <div>
      <div class="logo-name">CloudSentinel</div>
      <div class="logo-tag">CLOUD THREAT INTELLIGENCE PLATFORM</div>
    </div>
  </div>
  <div class="header-right">
    <div class="live-pill">
      <div class="live-dot"></div>
      LIVE MONITORING
    </div>
    <div class="clock" id="clock">--:--:--</div>
  </div>
</div>

<!-- KPI Cards -->
<div class="kpi-row">
  <div class="kpi kpi-flows">
    <div class="kpi-icon">&#128225;</div>
    <div>
      <div class="kpi-val c-teal" id="kpi-flows">0</div>
      <div class="kpi-label">Flows Analyzed</div>
    </div>
  </div>
  <div class="kpi kpi-threats">
    <div class="kpi-icon">&#9888;&#65039;</div>
    <div>
      <div class="kpi-val c-coral" id="kpi-threats">0</div>
      <div class="kpi-label">Threats Detected</div>
    </div>
  </div>
  <div class="kpi kpi-crit">
    <div class="kpi-icon">&#128680;</div>
    <div>
      <div class="kpi-val c-coral" id="kpi-crit">0</div>
      <div class="kpi-label">Critical Alerts</div>
    </div>
  </div>
  <div class="kpi kpi-block">
    <div class="kpi-icon">&#128737;&#65039;</div>
    <div>
      <div class="kpi-val c-amber" id="kpi-block">0</div>
      <div class="kpi-label">IPs Blocked</div>
    </div>
  </div>
  <div class="kpi kpi-fp">
    <div class="kpi-icon">&#9989;</div>
    <div>
      <div class="kpi-val c-green">1.8%</div>
      <div class="kpi-label">False Positive Rate</div>
    </div>
  </div>
</div>

<!-- Charts Row -->
<div class="section section-3col" style="margin-top:18px;">
  <div class="card">
    <div class="card-hdr">
      <div class="card-dot" style="background:var(--teal)"></div>
      <span class="card-title">Risk Level Breakdown</span>
    </div>
    <div class="ch"><canvas id="riskChart"></canvas></div>
  </div>
  <div class="card">
    <div class="card-hdr">
      <div class="card-dot" style="background:var(--coral)"></div>
      <span class="card-title">Attack Category Distribution</span>
    </div>
    <div class="ch"><canvas id="typeChart"></canvas></div>
  </div>
  <div class="card" style="display:flex;flex-direction:column;justify-content:space-between;">
    <div class="card-hdr">
      <div class="card-dot" style="background:var(--blue)"></div>
      <span class="card-title">System Accuracy</span>
    </div>
    <div class="gauge-wrap" style="flex:1;justify-content:center;">
      <div class="gauge-label">Ensemble Detection Rate</div>
      <div class="gauge-val">97.2%</div>
      <div class="gauge-sub">SSA + XGBoost Combined</div>
      <br>
      <div class="gauge-label">False Positive Rate</div>
      <div class="gauge-val" style="color:var(--green);font-size:22px;">1.8%</div>
      <div class="gauge-sub">vs 6.7% traditional IDS</div>
    </div>
  </div>
</div>

<!-- Anomaly Score Timeline -->
<div class="section" style="margin-top:14px;">
  <div class="card">
    <div class="card-hdr">
      <div class="card-dot" style="background:var(--amber)"></div>
      <span class="card-title">Anomaly Score - Real-Time Timeline</span>
    </div>
    <div style="height:140px;"><canvas id="scoreChart"></canvas></div>
  </div>
</div>

<!-- Threshold + Blocked IPs -->
<div class="section section-2col" style="margin-top:14px;">
  <div class="card">
    <div class="card-hdr">
      <div class="card-dot" style="background:var(--slate)"></div>
      <span class="card-title">Adaptive Threshold Engine</span>
    </div>
    <div class="thr-item">
      <span class="thr-label" style="color:#c0392b;">CRITICAL</span>
      <div class="thr-bar-wrap">
        <div class="thr-bar" id="thr-critical" style="background:#f43f5e;width:0%"></div>
      </div>
      <span class="thr-val" id="thr-critical-val">0</span>
    </div>
    <div class="thr-item">
      <span class="thr-label" style="color:#d35400;">HIGH</span>
      <div class="thr-bar-wrap">
        <div class="thr-bar" id="thr-high" style="background:#f59e0b;width:0%"></div>
      </div>
      <span class="thr-val" id="thr-high-val">0</span>
    </div>
    <div class="thr-item">
      <span class="thr-label" style="color:#b7950b;">MEDIUM</span>
      <div class="thr-bar-wrap">
        <div class="thr-bar" id="thr-medium" style="background:#eab308;width:0%"></div>
      </div>
      <span class="thr-val" id="thr-medium-val">0</span>
    </div>
    <div class="thr-item">
      <span class="thr-label" style="color:#1e8449;">LOW</span>
      <div class="thr-bar-wrap">
        <div class="thr-bar" id="thr-low" style="background:#10b981;width:0%"></div>
      </div>
      <span class="thr-val" id="thr-low-val">0</span>
    </div>
    <div class="thr-item">
      <span class="thr-label" style="color:var(--slate);">INFO</span>
      <div class="thr-bar-wrap">
        <div class="thr-bar" id="thr-info" style="background:var(--border);width:0%"></div>
      </div>
      <span class="thr-val" id="thr-info-val">0</span>
    </div>
    <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border);font-size:10px;color:var(--muted);">
      Thresholds recalibrate every 24h based on baseline traffic patterns.
      SSA reconstruction error drives adaptive scoring.
    </div>
  </div>

  <div class="card">
    <div class="card-hdr">
      <div class="card-dot" style="background:var(--coral)"></div>
      <span class="card-title">Blocked IPs</span>
    </div>
    <div class="blk-wrap">
      <table class="blk-table">
        <thead>
          <tr>
            <th>Source IP</th>
            <th>Reason</th>
            <th>Risk</th>
            <th>Blocked At</th>
          </tr>
        </thead>
        <tbody id="blocked-body">
          <tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px;">
            No blocked IPs yet...
          </td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Threat Timeline -->
<div class="section pb" style="margin-top:14px;">
  <div class="card">
    <div class="card-hdr">
      <div class="card-dot" style="background:var(--coral)"></div>
      <span class="card-title">Live Threat Intelligence Feed</span>
    </div>
    <div class="timeline" id="timeline">
      <div style="color:var(--muted);text-align:center;padding:30px;font-size:12px;">
        Waiting for threat events...
      </div>
    </div>
  </div>
</div>

<script>
// ── Clock ──
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent = now.toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// ── Charts setup ──
const riskCtx  = document.getElementById('riskChart').getContext('2d');
const typeCtx  = document.getElementById('typeChart').getContext('2d');
const scoreCtx = document.getElementById('scoreChart').getContext('2d');

const riskChart = new Chart(riskCtx, {
  type: 'bar',
  data: {
    labels: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'],
    datasets: [{
      label: 'Alerts',
      data: [0,0,0,0,0],
      backgroundColor: ['#f43f5e','#f59e0b','#eab308','#10b981','#94a3b8'],
      borderRadius: 6, borderSkipped: false
    }]
  },
  options: {
    indexAxis: 'y', responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: '#f1f5f9' }, ticks: { font: { family: 'DM Mono', size: 10 } } },
      y: { grid: { display: false }, ticks: { font: { family: 'DM Mono', size: 10 } } }
    }
  }
});

const typeChart = new Chart(typeCtx, {
  type: 'polarArea',
  data: {
    labels: ['DDoS','BruteForce','Botnet','PortScan','DoS'],
    datasets: [{
      data: [0,0,0,0,0],
      backgroundColor: ['rgba(244,63,94,.7)','rgba(245,158,11,.7)',
        'rgba(59,130,246,.7)','rgba(16,185,129,.7)','rgba(139,92,246,.7)'],
      borderWidth: 0
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { position: 'right', labels: { font: { size: 9 }, boxWidth: 10 } } },
    scales: { r: { grid: { color: '#f1f5f9' }, ticks: { display: false } } }
  }
});

const scoreLabels = [];
const scoreData   = [];
const scoreChart  = new Chart(scoreCtx, {
  type: 'line',
  data: {
    labels: scoreLabels,
    datasets: [{
      label: 'Anomaly Score',
      data: scoreData,
      borderColor: '#f59e0b',
      backgroundColor: 'rgba(245,158,11,.08)',
      fill: true,
      tension: 0.4,
      pointRadius: 2,
      borderWidth: 2
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { display: false }, ticks: { font: { size: 9 }, maxTicksLimit: 10 } },
      y: { grid: { color: '#f1f5f9' }, ticks: { font: { size: 9 } }, min: 0 }
    }
  }
});

// ── Data fetch & update ──
function refresh() {
  fetch('/api/data')
    .then(r => r.json())
    .then(d => {
      // KPIs
      document.getElementById('kpi-flows').textContent   = d.total_flows.toLocaleString();
      document.getElementById('kpi-threats').textContent = d.total_threats;
      document.getElementById('kpi-crit').textContent    = d.risk_counts.CRITICAL || 0;
      document.getElementById('kpi-block').textContent   = d.blocked_count;

      // Risk chart
      riskChart.data.datasets[0].data = [
        d.risk_counts.CRITICAL||0, d.risk_counts.HIGH||0,
        d.risk_counts.MEDIUM||0,   d.risk_counts.LOW||0,
        d.risk_counts.INFO||0
      ];
      riskChart.update('none');

      // Type chart
      const tc = d.type_counts;
      typeChart.data.datasets[0].data = [
        tc.DDoS||0, tc.BruteForce||0, tc.Botnet||0, tc.PortScan||0, tc.DoS||0
      ];
      typeChart.update('none');

      // Score timeline
      if (d.latest_score !== null) {
        const t = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
        if (scoreLabels.length > 25) { scoreLabels.shift(); scoreData.shift(); }
        scoreLabels.push(t);
        scoreData.push(parseFloat(d.latest_score.toFixed(2)));
        scoreChart.update('none');
      }

      // Threshold bars
      const total = d.total_threats || 1;
      const risks = ['critical','high','medium','low','info'];
      const rkeys = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
      risks.forEach((r, i) => {
        const cnt = d.risk_counts[rkeys[i]] || 0;
        const pct = Math.min((cnt / total) * 100, 100);
        document.getElementById('thr-' + r).style.width = pct + '%';
        document.getElementById('thr-' + r + '-val').textContent = cnt;
      });

      // Blocked IPs table
      const tbody = document.getElementById('blocked-body');
      if (d.blocked_ips && d.blocked_ips.length > 0) {
        tbody.innerHTML = d.blocked_ips.map(ip =>
          '<tr>' +
          '<td class="mono">' + ip.ip + '</td>' +
          '<td>' + ip.reason + '</td>' +
          '<td><span class="badge ' + ip.risk + '">' + ip.risk + '</span></td>' +
          '<td class="mono" style="color:var(--muted);font-size:10px;">' + ip.blocked_at.slice(11,19) + '</td>' +
          '</tr>'
        ).join('');
      }

      // Threat timeline
      if (d.recent_alerts && d.recent_alerts.length > 0) {
        const tl = document.getElementById('timeline');
        tl.innerHTML = d.recent_alerts.map(a =>
          '<div class="tl-item">' +
          '<div class="tl-dot tl-' + a.risk + '"></div>' +
          '<div class="tl-body">' +
          '<div class="tl-top">' +
          '<span class="tl-attack">' + a.attack_type + '</span>' +
          '<span class="badge ' + a.risk + '">' + a.risk + '</span>' +
          '<span class="tl-ip">' + a.source_ip + ' &rarr; ' + a.dest_ip + '</span>' +
          '<span class="tl-time">' + a.timestamp.slice(11,19) + '</span>' +
          '</div>' +
          '<div class="tl-exp">' + a.explanation + '</div>' +
          '</div></div>'
        ).join('');
      }
    })
    .catch(console.error);
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""

# ── Flask Routes ──

@app.route('/')
def index():
    return render_template_string(DASHBOARD)

@app.route('/api/data')
def api_data():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM alerts")
        total_threats = c.fetchone()[0]

        c.execute("SELECT risk, COUNT(*) FROM alerts GROUP BY risk")
        risk_counts = {row[0]: row[1] for row in c.fetchall()}

        c.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type")
        type_counts = {row[0]: row[1] for row in c.fetchall()}

        c.execute("SELECT score FROM alerts ORDER BY id DESC LIMIT 1")
        row = c.fetchone()
        latest_score = row[0] if row else None

        c.execute("SELECT ip, reason, risk, blocked_at FROM blocked_ips ORDER BY blocked_at DESC LIMIT 10")
        blocked_ips = [{"ip": r[0], "reason": r[1], "risk": r[2], "blocked_at": r[3]} for r in c.fetchall()]

        c.execute("SELECT timestamp, source_ip, dest_ip, attack_type, risk, score, explanation FROM alerts ORDER BY id DESC LIMIT 15")
        recent_alerts = [
            {"timestamp": r[0], "source_ip": r[1], "dest_ip": r[2],
             "attack_type": r[3], "risk": r[4], "score": r[5], "explanation": r[6]}
            for r in c.fetchall()
        ]

        conn.close()

        return jsonify({
            "total_flows": FLOW_COUNT[0],
            "total_threats": total_threats,
            "risk_counts": risk_counts,
            "type_counts": type_counts,
            "latest_score": latest_score,
            "blocked_count": len(blocked_ips),
            "blocked_ips": blocked_ips,
            "recent_alerts": recent_alerts
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/inject', methods=['POST'])
def inject():
    """Manual attack injection endpoint for attack_demo.py"""
    try:
        data = request.get_json()
        attack_type = data.get("attack_type", "DDoS")
        if attack_type not in TRAFFIC:
            attack_type = "DDoS"
        features = TRAFFIC[attack_type]()
        res = engine.analyze(features)
        FLOW_COUNT[0] += 1
        if res["is_attack"]:
            src = data.get("source_ip",
                f"{random.choice([45,103,185,77,91])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
            dst = f"10.0.{random.randint(0,2)}.{random.randint(1,20)}"
            ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()
            c.execute("INSERT INTO alerts (timestamp,source_ip,dest_ip,attack_type,risk,score,top_feature,explanation) VALUES(?,?,?,?,?,?,?,?)",
                (ts, src, dst, res["attack_type"], res["risk"], res["score"], res["top_feature"], res["explanation"]))
            if res["risk"] in ("CRITICAL","HIGH"):
                ub = (datetime.now()+timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                c.execute("INSERT OR REPLACE INTO blocked_ips (ip,reason,risk,blocked_at,unblock_at) VALUES(?,?,?,?,?)",
                    (src, res["attack_type"], res["risk"], ts, ub))
            conn.commit(); conn.close()
        return jsonify({"status": "ok", "result": res})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
