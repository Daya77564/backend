"""
=============================================================================
PacketVista — Flask Backend Server
=============================================================================
Runs the PacketVista simulation engine for 5 seconds, captures all
packet/alert output, and returns it as a downloadable .txt file.

Usage:
    pip install flask
    python server.py

The server listens on http://localhost:5000
Endpoint: GET /capture-logs  →  downloads packetvista_logs_<timestamp>.txt
=============================================================================
"""

from flask import Flask, Response
from flask_cors import CORS
import queue
import time
import random
import threading
import ipaddress
from collections import defaultdict, deque
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Allow requests from the HTML page (file:// or any host)


# =============================================================================
# CONSTANTS (mirrored from packetvista.py)
# =============================================================================

SUSPICIOUS_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5900: "VNC", 6667: "IRC",
}

PS_PORTS  = 12
PS_WINDOW = 10
SF_COUNT  = 40
SF_WINDOW = 5
RC_COUNT  = 15
RC_WINDOW = 5

CAPTURE_DURATION = 5  # seconds


# =============================================================================
# INLINE SIMULATION ENGINE (headless — no tkinter / GUI)
# =============================================================================

class DetectionEngine:
    def __init__(self, alert_cb):
        self._cb   = alert_cb
        self._lock = threading.Lock()
        self._scan_dq   = defaultdict(deque)
        self._syn_dq    = defaultdict(deque)
        self._rep_dq    = defaultdict(deque)
        self._alerted_scan = set()
        self._alerted_syn  = set()
        self._alerted_rep  = set()
        self.c_scan = self.c_syn = self.c_susp = self.c_rep = 0

    def process(self, src, dst, proto, sport, dport, flags):
        now = time.time()
        with self._lock:
            self._susp(src, dst, dport)
            if proto == "TCP":
                self._syn_flood(src, flags, now)
                self._port_scan(src, dport, now)
                self._repeat(src, dport, now)

    def counters(self):
        with self._lock:
            return (self.c_scan, self.c_syn, self.c_susp, self.c_rep)

    def _susp(self, src, dst, port):
        if port in SUSPICIOUS_PORTS:
            self.c_susp += 1
            self._cb("SUSPICIOUS PORT", src,
                     f"Port {port} ({SUSPICIOUS_PORTS[port]})  {src} -> {dst}")

    def _syn_flood(self, src, flags, now):
        if "S" not in str(flags):
            return
        dq = self._syn_dq[src]
        dq.append(now)
        cut = now - SF_WINDOW
        while dq and dq[0] < cut:
            dq.popleft()
        if len(dq) >= SF_COUNT:
            if src not in self._alerted_syn:
                self._alerted_syn.add(src)
                self.c_syn += 1
                self._cb("SYN FLOOD", src,
                         f"{len(dq)} SYN pkts from {src} in {SF_WINDOW}s")
        else:
            self._alerted_syn.discard(src)

    def _port_scan(self, src, port, now):
        dq = self._scan_dq[src]
        dq.append((now, port))
        cut = now - PS_WINDOW
        while dq and dq[0][0] < cut:
            dq.popleft()
        distinct = len({p for _, p in dq})
        if distinct >= PS_PORTS:
            if src not in self._alerted_scan:
                self._alerted_scan.add(src)
                self.c_scan += 1
                self._cb("PORT SCAN", src,
                         f"{src} hit {distinct} ports in {PS_WINDOW}s")
        else:
            self._alerted_scan.discard(src)

    def _repeat(self, src, port, now):
        key = (src, port)
        dq  = self._rep_dq[key]
        dq.append(now)
        cut = now - RC_WINDOW
        while dq and dq[0] < cut:
            dq.popleft()
        if len(dq) >= RC_COUNT:
            if key not in self._alerted_rep:
                self._alerted_rep.add(key)
                self.c_rep += 1
                self._cb("REPEAT CONN", src,
                         f"{src} -> port {port}  x{len(dq)} in {RC_WINDOW}s")
        else:
            self._alerted_rep.discard(key)


class SimEngine:
    _SRCS = [
        "203.0.113.10", "198.51.100.5", "185.220.101.34",
        "91.108.4.200",  "104.21.30.1",  "45.33.32.156",
        "192.0.2.77",    "8.8.8.8",      "1.1.1.1",
    ]
    _DSTS = ["10.0.0.1", "10.0.0.2", "192.168.1.100"]

    def __init__(self, pkt_q):
        self._q    = pkt_q
        self._stop = threading.Event()
        self._tick = 0

    def start(self):
        self._stop.clear()
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            self._tick += 1
            for _ in range(random.randint(3, 8)):
                self._normal()
            if self._tick % 5  == 0: self._inject_susp_port()
            if self._tick % 7  == 0: self._inject_port_scan()
            if self._tick % 10 == 0: self._inject_syn_flood()
            if self._tick % 8  == 0: self._inject_repeat()
            time.sleep(0.3)

    def _emit(self, src, dst, proto, sp, dp, fl=""):
        try:
            self._q.put_nowait({
                "src": src, "dst": dst,
                "proto": proto, "sp": sp, "dp": dp,
                "fl": fl, "len": random.randint(40, 1500),
            })
        except queue.Full:
            pass

    def _normal(self):
        src   = random.choice(self._SRCS)
        dst   = random.choice(self._DSTS)
        proto = random.choice(["TCP", "TCP", "UDP", "ICMP"])
        if proto == "TCP":
            self._emit(src, dst, "TCP",
                       random.randint(1024, 65535),
                       random.choice([80, 443, 8080, 53, 8443]), "PA")
        elif proto == "UDP":
            self._emit(src, dst, "UDP",
                       random.randint(1024, 65535),
                       random.choice([53, 123, 161, 5353]))
        else:
            self._emit(src, dst, "ICMP", 0, 0)

    def _inject_susp_port(self):
        src  = random.choice(self._SRCS)
        dst  = random.choice(self._DSTS)
        port = random.choice(list(SUSPICIOUS_PORTS.keys()))
        self._emit(src, dst, "TCP", random.randint(1024, 65535), port, "S")

    def _inject_port_scan(self):
        src   = random.choice(self._SRCS)
        dst   = self._DSTS[0]
        ports = random.sample(range(1, 1025), PS_PORTS + 3)
        for p in ports:
            self._emit(src, dst, "TCP", random.randint(1024, 65535), p, "S")

    def _inject_syn_flood(self):
        src = random.choice(self._SRCS)
        dst = self._DSTS[1]
        for _ in range(SF_COUNT + 15):
            self._emit(src, dst, "TCP", random.randint(1024, 65535), 80, "S")

    def _inject_repeat(self):
        src = random.choice(self._SRCS)
        dst = self._DSTS[2]
        for _ in range(RC_COUNT + 5):
            self._emit(src, dst, "TCP", random.randint(1024, 65535), 443, "S")


# =============================================================================
# CAPTURE ENDPOINT
# =============================================================================

@app.route("/capture-logs")
def capture_logs():
    """
    Runs the PacketVista simulation for CAPTURE_DURATION seconds,
    collects all packet and alert lines, then returns a .txt download.
    """
    pkt_q    = queue.Queue(maxsize=5000)
    log_q    = queue.Queue()       # collects formatted log lines
    alerts   = []                  # alert lines (prefixed *** ALERT ***)

    # ── Alert callback (called from DetectionEngine) ──────────────────────────
    def on_alert(alert_type, src, detail):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        line = f"[{ts}] *** ALERT *** [{alert_type}]  {detail}"
        log_q.put(line)
        alerts.append(line)

    engine = DetectionEngine(on_alert)
    sim    = SimEngine(pkt_q)

    # ── Consumer thread: drain pkt_q → format → push to log_q ───────────────
    def consumer():
        while True:
            try:
                pkt = pkt_q.get(timeout=0.1)
            except queue.Empty:
                if stop_evt.is_set():
                    break
                continue

            ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            proto = pkt["proto"]
            src   = pkt["src"]
            dst   = pkt["dst"]
            sp    = pkt["sp"]
            dp    = pkt["dp"]
            fl    = pkt["fl"]
            length = pkt["len"]

            if proto == "TCP":
                line = (f"[{ts}] TCP  {src}:{sp:>5} -> {dst}:{dp:<5}  "
                        f"flags={fl:<4}  len={length}")
            elif proto == "UDP":
                line = (f"[{ts}] UDP  {src}:{sp:>5} -> {dst}:{dp:<5}  "
                        f"len={length}")
            else:
                line = (f"[{ts}] {proto:<5}{src}           -> {dst}  "
                        f"len={length}")

            log_q.put(line)
            engine.process(src, dst, proto, sp, dp, fl)

    stop_evt = threading.Event()
    t_consumer = threading.Thread(target=consumer, daemon=True)
    t_consumer.start()

    # ── Run simulation for CAPTURE_DURATION seconds ───────────────────────────
    sim.start()
    time.sleep(CAPTURE_DURATION)
    sim.stop()

    # Give consumer a moment to drain remaining items
    time.sleep(0.4)
    stop_evt.set()
    t_consumer.join(timeout=2)

    # ── Drain log_q into ordered list ────────────────────────────────────────
    lines = []
    while not log_q.empty():
        lines.append(log_q.get_nowait())

    # Sort by timestamp prefix so alerts intersperse correctly
    lines.sort()

    # ── Build report ─────────────────────────────────────────────────────────
    scan_c, syn_c, susp_c, rep_c = engine.counters()
    total_pkts = sum(1 for l in lines if "ALERT" not in l)
    total_alerts = len(alerts)

    header = "\n".join([
        "=" * 72,
        "  PACKET VISTA — CAPTURE REPORT",
        f"  Capture duration : {CAPTURE_DURATION} seconds",
        f"  Generated at     : {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}",
        f"  Mode             : Simulation",
        "=" * 72,
        "",
        "  SUMMARY",
        "  ─────────────────────────────────────────",
        f"  Total packets captured : {total_pkts}",
        f"  Total alerts fired     : {total_alerts}",
        f"    Port scan detections : {scan_c}",
        f"    SYN flood detections : {syn_c}",
        f"    Suspicious ports     : {susp_c}",
        f"    Repeat connections   : {rep_c}",
        "",
        "  TRAFFIC LOG  (chronological)",
        "  ─────────────────────────────────────────",
        "",
    ])

    footer = "\n".join([
        "",
        "=" * 72,
        "  END OF REPORT",
        "=" * 72,
    ])

    report_text = header + "\n".join(lines) + footer

    # ── Stream as downloadable file ───────────────────────────────────────────
    ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"packetvista_logs_{ts_str}.txt"

    return Response(
        report_text,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "text/plain; charset=utf-8",
        }
    )


@app.route("/")
def index():
    return "<h2>PacketVista backend is running. Use <code>/capture-logs</code> to capture.</h2>"


if __name__ == "__main__":
    print("=" * 60)
    print("  PacketVista Backend  →  http://localhost:5000")
    print("  Capture endpoint     →  GET /capture-logs")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)

import os
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)