"""
=============================================================================
PacketVista — Flask Backend Server
=============================================================================
Directly imports packetvista.py's own SimEngine, DetectionEngine, and
SUSPICIOUS_PORTS — produces output in the EXACT same format as the GUI:

  PACKET TABLE  →  Time | Src | Dst | Proto | SrcPort | DstPort | Flags | Bytes | Alert
  ALERT LOG     →  [HH:MM:SS] [ALERT_TYPE]  detail

Usage:
    pip install flask flask-cors
    python server.py          # must be in the same folder as packetvista.py

Endpoint: GET /capture-logs  →  downloads packetvista_logs_<timestamp>.txt
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
from flask import Flask, Response
from flask_cors import CORS

# =============================================================================
# IMPORT DIRECTLY FROM packetvista.py (headless — no GUI launch)
# =============================================================================
# Stub tkinter so the module loads fine on servers without a display
for _mod in ["tkinter", "tkinter.ttk", "tkinter.scrolledtext", "tkinter.messagebox"]:
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

_pv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packetvista.py")
_spec    = importlib.util.spec_from_file_location("packetvista", _pv_path)
pv       = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pv)   # runs module body but NOT __main__ block

SimEngine        = pv.SimEngine
DetectionEngine  = pv.DetectionEngine
SUSPICIOUS_PORTS = pv.SUSPICIOUS_PORTS

# =============================================================================
app = Flask(__name__)
CORS(app)

CAPTURE_DURATION = 5   # seconds


# =============================================================================
# /capture-logs
# =============================================================================

@app.route("/capture-logs")
def capture_logs():
    pkt_q      = queue.Queue(maxsize=10000)
    log_lines  = []    # tuples: (kind, timestamp_float, text)
    alert_lines = []
    lock        = threading.Lock()

    # Alert callback — mirrors _handle_alert() in the GUI
    def on_alert(atype, src, detail):
        now  = time.time()
        line = f"[{datetime.now().strftime('%H:%M:%S')}] [{atype}]  {detail}"
        with lock:
            log_lines.append(("alert", now, line))
            alert_lines.append(line)

    engine = DetectionEngine(on_alert)
    sim    = SimEngine(pkt_q)
    stop_evt = threading.Event()

    # Consumer thread — mirrors _handle_pkt() in the GUI
    def consumer():
        while not stop_evt.is_set() or not pkt_q.empty():
            try:
                item = pkt_q.get(timeout=0.05)
            except queue.Empty:
                continue

            now   = time.time()
            src   = item["src"]
            dst   = item["dst"]
            proto = item["proto"]
            sp    = item["sp"]
            dp    = item["dp"]
            fl    = item.get("fl", "")
            blen  = item.get("len", 0)
            ts_str = datetime.now().strftime("%H:%M:%S")

            # Same alert logic as GUI _handle_pkt()
            alert_text = ("SUSPICIOUS: " + SUSPICIOUS_PORTS[dp]) if dp in SUSPICIOUS_PORTS else ""

            sport_str = str(sp) if sp else ""
            dport_str = str(dp) if dp else ""

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
    time.sleep(CAPTURE_DURATION)
    sim.stop()
    time.sleep(0.5)      # drain tail
    stop_evt.set()
    t.join(timeout=3)

    # Sort chronologically
    with lock:
        sorted_lines = sorted(log_lines, key=lambda x: x[1])

    pkt_rows   = [l for k, _, l in sorted_lines if k == "pkt"]
    alrt_rows  = [l for k, _, l in sorted_lines if k == "alert"]
    scan_c, syn_c, susp_c, rep_c = engine.counters()

    S  = "=" * 80
    s  = "-" * 80

    table_hdr = (
        f"{'Time':<10}  {'Source IP':<18}  {'Dest IP':<18}  "
        f"{'Proto':<5}  {'SrcPort':>6}    {'DstPort':<6}  "
        f"{'Flags':<9}  {'Bytes':<8}  Alert"
    )

    report = "\n".join([
        S,
        "  PACKET VISTA — RUNTIME CAPTURE REPORT",
        f"  Duration  : {CAPTURE_DURATION} seconds",
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
    return Response(
        report,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "text/plain; charset=utf-8",
        }
    )


@app.route("/")
def index():
    return "<h2>PacketVista backend running. GET /capture-logs to capture.</h2>"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 60)
    print(f"  PacketVista Backend  →  http://localhost:{port}")
    print(f"  Capture endpoint     →  GET /capture-logs")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=False)
