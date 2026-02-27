"""
=============================================================================
PacketVista — Flask Backend Server
=============================================================================
Duration is passed as ?duration=N from index.html — server reads it
from the query string and uses it for the capture window.

Usage:
    pip install flask flask-cors
    python server.py   (same folder as packetvista.py)

Endpoint: GET /capture-logs?duration=5
=============================================================================
"""

import os
import sys
import queue
import time
import threading
import types
import importlib.util
from datetime import datetime
from flask import Flask, Response, request
from flask_cors import CORS

# =============================================================================
# IMPORT DIRECTLY FROM packetvista.py (headless — no GUI launch)
# =============================================================================
for _mod in ["tkinter", "tkinter.ttk", "tkinter.scrolledtext", "tkinter.messagebox"]:
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

_pv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packetvista.py")
_spec    = importlib.util.spec_from_file_location("packetvista", _pv_path)
pv       = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pv)

SimEngine        = pv.SimEngine
DetectionEngine  = pv.DetectionEngine
SUSPICIOUS_PORTS = pv.SUSPICIOUS_PORTS

# =============================================================================
app = Flask(__name__)

# Explicit CORS — allow all origins, expose headers the browser needs
CORS(app, resources={r"/*": {"origins": "*"}},
     expose_headers=["Content-Disposition"],
     allow_headers=["Content-Type"],
     methods=["GET", "OPTIONS"])

DEFAULT_DURATION = 30
MAX_DURATION     = 60


# Explicit OPTIONS handler so preflight never blocks the duration param
@app.route("/capture-logs", methods=["OPTIONS"])
def capture_logs_preflight():
    resp = Response("")
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp, 204


# =============================================================================
# /capture-logs
# =============================================================================

@app.route("/capture-logs", methods=["GET"])
def capture_logs():
    # ── Read ?duration=N — with full debug print so you can see it in logs ───
    raw = request.args.get("duration", "")
    print(f"[PacketVista] Received request | raw duration param: '{raw}'", flush=True)

    try:
        duration = int(raw)
        duration = max(1, min(duration, MAX_DURATION))
    except (ValueError, TypeError):
        duration = DEFAULT_DURATION

    print(f"[PacketVista] Using duration: {duration}s", flush=True)

    pkt_q       = queue.Queue(maxsize=10000)
    log_lines   = []
    alert_lines = []
    lock        = threading.Lock()

    def on_alert(atype, src, detail):
        now  = time.time()
        line = f"[{datetime.now().strftime('%H:%M:%S')}] [{atype}]  {detail}"
        with lock:
            log_lines.append(("alert", now, line))
            alert_lines.append(line)

    engine   = DetectionEngine(on_alert)
    sim      = SimEngine(pkt_q)
    stop_evt = threading.Event()

    def consumer():
        while not stop_evt.is_set() or not pkt_q.empty():
            try:
                item = pkt_q.get(timeout=0.05)
            except queue.Empty:
                continue

            now    = time.time()
            src    = item["src"]
            dst    = item["dst"]
            proto  = item["proto"]
            sp     = item["sp"]
            dp     = item["dp"]
            fl     = item.get("fl", "")
            blen   = item.get("len", 0)
            ts_str = datetime.now().strftime("%H:%M:%S")

            alert_text = ("SUSPICIOUS: " + SUSPICIOUS_PORTS[dp]) if dp in SUSPICIOUS_PORTS else ""
            sport_str  = str(sp) if sp else ""
            dport_str  = str(dp) if dp else ""

            line = (
                f"{ts_str:<10}  "
                f"{src:<18}  {dst:<18}  "
                f"{proto:<5}  "
                f"{sport_str:>6} -> {dport_str:<6}  "
                f"flags={fl:<4}  "
                f"bytes={blen:<5}"
                + (f"  ⚠  {alert_text}" if alert_text else "")
            )

            with lock:
                log_lines.append(("pkt", now, line))

            engine.process(src, dst, proto, sp, dp, fl)

    t = threading.Thread(target=consumer, daemon=True)
    t.start()

    sim.start()
    time.sleep(duration)
    sim.stop()
    time.sleep(0.5)
    stop_evt.set()
    t.join(timeout=3)

    with lock:
        sorted_lines = sorted(log_lines, key=lambda x: x[1])

    pkt_rows  = [l for k, _, l in sorted_lines if k == "pkt"]
    alrt_rows = [l for k, _, l in sorted_lines if k == "alert"]
    scan_c, syn_c, susp_c, rep_c = engine.counters()

    S = "=" * 80
    s = "-" * 80

    table_hdr = (
        f"{'Time':<10}  {'Source IP':<18}  {'Dest IP':<18}  "
        f"{'Proto':<5}  {'SrcPort':>6}    {'DstPort':<6}  "
        f"{'Flags':<9}  {'Bytes':<8}  Alert"
    )

    report = "\n".join([
        S,
        "  PACKET VISTA — RUNTIME CAPTURE REPORT",
        f"  Duration  : {duration} seconds",
        f"  Generated : {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}",
        f"  Mode      : Simulation",
        S,
        "",
        "  ATTACK COUNTERS",
        s,
        f"  Port Scans Detected  : {scan_c}",
        f"  SYN Floods Detected  : {syn_c}",
        f"  Suspicious Port Hits : {susp_c}",
        f"  Repeat Conn Alerts   : {rep_c}",
        "",
        f"  Total Packets  : {len(pkt_rows)}",
        f"  Total Alerts   : {len(alrt_rows)}",
        "",
        S,
        "  ALERT LOG",
        s,
        "",
        ("\n".join(alrt_rows) if alrt_rows else "  (no alerts)"),
        "",
        S,
        "  LIVE PACKET FEED",
        s,
        "",
        table_hdr,
        s,
        ("\n".join(pkt_rows) if pkt_rows else "  (no packets)"),
        "",
        S,
        "  END OF REPORT — Packet Vista v1.0",
        S,
    ])

    filename = f"packetvista_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    resp = Response(
        report,
        mimetype="text/plain",
        headers={
            "Content-Disposition":        f'attachment; filename="{filename}"',
            "Content-Type":               "text/plain; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "Content-Disposition",
        }
    )
    return resp


@app.route("/")
def index():
    return (
        "<h2>PacketVista backend running.</h2>"
        "<p>Endpoint: <code>GET /capture-logs?duration=5</code></p>"
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 60)
    print(f"  PacketVista Backend  →  http://localhost:{port}")
    print(f"  Capture endpoint     →  /capture-logs?duration=5")
    print(f"  Default duration     :  {DEFAULT_DURATION}s  (max {MAX_DURATION}s)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=False)
