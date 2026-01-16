#!/usr/bin/env python3
# NetMini

import argparse, os, sys, time, queue, tkinter as tk
from tkinter import ttk
from collections import defaultdict, deque, Counter
from scapy.all import AsyncSniffer, IP, TCP, UDP

# [REQ: constants / casting targets] detection thresholds are constants; casting occurs at dport int()
WINDOW_SECS = 60
PORT_SCAN_MIN_UNIQUE = 15
MIN_PPS = 1.0

__version__ = "3.0.0-final"  # [REQ: versioning optional but used with sys]

# [PHASE 3] Port-to-service mapping for analysis
COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

# ---- minimal live capture ----
class LiveCapture:
    """[REQ: classes] Encapsulates packet capture and pushes tuples into a thread-safe queue."""
    def __init__(self, iface="eth1", bpf="ip and (tcp or udp)", qmax=5000):
        self.iface, self.bpf = iface, bpf
        self.q = queue.Queue(maxsize=qmax)
        self.sniffer = None

    def _on_pkt(self, pkt):
        """[REQ: functions] Per-packet callback; performs [REQ: casting] on destination ports."""
        try:
            if IP in pkt:
                # [REQ: casting] ensure port is an int for downstream math/display
                d = (TCP in pkt and int(pkt[TCP].dport)) or (UDP in pkt and int(pkt[UDP].dport)) or None
                if d is not None:
                    self.q.put_nowait((time.time(), pkt[IP].src, d))
        except queue.Full:
            pass

    def start(self):
        """[REQ: functions] Starts async sniffer."""
        if self.sniffer:
            return
        self.sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, prn=self._on_pkt, store=False)
        self.sniffer.start()

    def stop(self):
        """[REQ: functions] Stops sniffer safely."""
        s, self.sniffer = self.sniffer, None
        if s:
            try:
                s.stop()
            except Exception:
                pass
            try:
                s.join()
            except Exception:
                pass

# ---- sliding window stats ----
class SlidingWindow:
    """[REQ: classes] Maintains a time-bounded window and produces per-source stats."""
    def __init__(self, seconds=WINDOW_SECS):
        self.seconds = seconds
        self.events = defaultdict(lambda: {"t": deque(), "p": deque()})

    def add(self, ts, src, dport):
        """[REQ: functions] Insert one event into the current window."""
        e = self.events[src]
        e["t"].append(ts)
        e["p"].append(dport)

    def stats(self, now):
        "[REQ: functions] Emit per-source metrics for the current window."
        cutoff, out, dead = now - self.seconds, {}, []
        for src, e in self.events.items():
            t, p = e["t"], e["p"]
            while t and t[0] < cutoff:
                t.popleft()
                p.popleft()
            n = len(t)
            if not n:
                dead.append(src)
                continue
            u = len(set(p))
            out[src] = {
                "u": u,
                "pps": n / self.seconds,
                "rat": (u / n) * 100,
                "fp": list(p)[:6],
                "all_ports": list(p),  # [PHASE 3] store all ports for analysis
            }
        for src in dead:
            del self.events[src]
        return out

# [PHASE 3] Helper functions for enhanced report analysis
def classify_scan_type(ports) -> str:
    """[REQ: functions] Classify horizontal vs vertical scan based on port patterns."""
    unique = len(set(ports))
    total = len(ports)
    if unique >= 20:
        return "Vertical (many ports on one/few hosts)"
    elif unique < 5 and total > 20:
        return "Horizontal (few ports on many hosts)"
    else:
        return "Mixed"

def get_service_analysis(ports):
    """[REQ: functions] Map ports to common services."""
    port_counts = Counter(ports)
    services = []
    for port, count in port_counts.most_common(10):
        svc = COMMON_PORTS.get(port, f"Port-{port}")
        services.append(f"{svc}:{port} ({count}x)")
    return services

def generate_timeline_ascii(rows):
    """[REQ: functions] Create simple ASCII timeline of activity."""
    if not rows:
        return "No activity detected"
    timeline = []
    for r in rows[:10]:  # Last 10 entries
        bar_len = min(int(r.get("unique_ports", 0)), 50)
        bar = "█" * bar_len
        timeline.append(f"{r.get('time', '')} {r.get('src', '')[:15]:15} {bar} ({r.get('unique_ports', 0)} ports)")
    return "\n".join(timeline)

# [REQ: file handling] Write an enhanced HTML report with Phase 3 features
def write_report(rows, outdir="reports"):
    """[REQ: functions] [PHASE 3] Writes comprehensive HTML with executive summary, stats, graphs, and recommendations."""
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"report_{int(time.time())}.html")
    
    # [PHASE 3] Calculate aggregate statistics
    total_sources = len(rows)
    port_scanners = sum(1 for r in rows if r.get("type") == "port_scan")
    total_unique_ports = sum(r.get("unique_ports", 0) for r in rows)
    avg_pps = sum(float(r.get("pps", 0)) for r in rows) / max(total_sources, 1)
    
    # [PHASE 3] Determine highest risk source
    high_risk = max(rows, key=lambda r: r.get("unique_ports", 0)) if rows else None
    
    cols = ("time", "src", "type", "scan_pattern", "unique_ports", "pps", "ratio", "top_services")
    
    head = (
        "<!doctype html><meta charset='utf-8'><title>NetMini Phase 3 Report</title>"
        "<style>"
        "body{font:14px system-ui;margin:20px;background:#f5f7fa}"
        ".section{background:white;margin:20px 0;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}"
        "h1{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px}"
        "h2{color:#34495e;margin-top:0}"
        ".exec-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin:20px 0}"
        ".stat-box{background:#ecf0f1;padding:15px;border-radius:5px;text-align:center}"
        ".stat-num{font-size:32px;font-weight:bold;color:#e74c3c}"
        ".stat-label{color:#7f8c8d;font-size:12px;text-transform:uppercase}"
        "table{border-collapse:collapse;width:100%;margin:15px 0}"
        "th,td{border:1px solid #bdc3c7;padding:8px;text-align:center}"
        "th{background:#34495e;color:white}"
        ".alert{background:#e74c3c;color:white;padding:15px;border-radius:5px;margin:15px 0}"
        ".timeline{background:#2c3e50;color:#ecf0f1;padding:15px;border-radius:5px;font-family:monospace;font-size:11px;overflow-x:auto}"
        ".rec{background:#d5f4e6;border-left:4px solid #27ae60;padding:12px;margin:8px 0}"
        "</style>"
    )
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(head)
        f.write(f"<h1>🔒 NetMini — Port-Scan Detection Report</h1>")
        f.write(f"<p style='color:#7f8c8d'>Generated: {time.strftime('%F %T')}</p>")
        
        # [PHASE 3] Executive Summary Section
        f.write("<div class='section'><h2>📊 Executive Summary</h2>")
        f.write("<div class='exec-grid'>")
        f.write(f"<div class='stat-box'><div class='stat-num'>{total_sources}</div><div class='stat-label'>Sources Detected</div></div>")
        f.write(f"<div class='stat-box'><div class='stat-num'>{port_scanners}</div><div class='stat-label'>Port Scanners</div></div>")
        f.write(f"<div class='stat-box'><div class='stat-num'>{total_unique_ports}</div><div class='stat-label'>Total Unique Ports</div></div>")
        f.write(f"<div class='stat-box'><div class='stat-num'>{avg_pps:.1f}</div><div class='stat-label'>Avg PPS</div></div>")
        f.write("</div>")
        
        if high_risk:
            f.write(f"<div class='alert'>⚠️ <strong>Highest Risk Source:</strong> {high_risk.get('src')} "
                   f"targeted {high_risk.get('unique_ports')} unique ports</div>")
        f.write("</div>")
        
        # [PHASE 3] Detailed Statistical Breakdown
        f.write("<div class='section'><h2>📈 Statistical Breakdown</h2>")
        if rows:
            scan_types = Counter(r.get("scan_pattern", "Unknown") for r in rows)
            f.write("<table><tr><th>Metric</th><th>Value</th></tr>")
            f.write(f"<tr><td>Total Detection Events</td><td>{len(rows)}</td></tr>")
            f.write(f"<tr><td>Unique Source IPs</td><td>{total_sources}</td></tr>")
            f.write(f"<tr><td>Confirmed Port Scans</td><td>{port_scanners} ({100*port_scanners/max(total_sources,1):.0f}%)</td></tr>")
            for pattern, count in scan_types.items():
                f.write(f"<tr><td>{pattern} Scan Pattern</td><td>{count}</td></tr>")
            f.write("</table>")
        f.write("</div>")
        
        # [PHASE 3] Visual Timeline
        f.write("<div class='section'><h2>📅 Activity Timeline</h2>")
        f.write(f"<div class='timeline'>{generate_timeline_ascii(rows)}</div>")
        f.write("</div>")
        
        # [PHASE 3] Detailed Detection Table with Service Analysis
        f.write("<div class='section'><h2>🔍 Detailed Detection Results</h2>")
        f.write("<table><tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr>")
        if not rows:
            f.write("<tr><td colspan='8' style='color:#95a5a6'>No detections recorded</td></tr>")
        for r in rows:
            f.write("<tr>" + "".join(f"<td>{r.get(k,'')}</td>" for k in cols) + "</tr>")
        f.write("</table></div>")
        
        # [PHASE 3] Security Recommendations
        f.write("<div class='section'><h2>🛡️ Security Recommendations</h2>")
        if port_scanners > 0:
            f.write("<div class='rec'>🚨 <strong>Immediate:</strong> Block or investigate sources flagged as port scanners</div>")
            f.write("<div class='rec'>🔒 <strong>Firewall:</strong> Implement rate limiting on commonly scanned ports</div>")
            f.write("<div class='rec'>📝 <strong>Logging:</strong> Enable detailed connection logs for forensic analysis</div>")
            f.write("<div class='rec'>🔔 <strong>Alerting:</strong> Configure real-time alerts for port scan detection</div>")
        else:
            f.write("<div class='rec'>✅ <strong>Status:</strong> No malicious port scanning detected during monitoring period</div>")
            f.write("<div class='rec'>📊 <strong>Recommendation:</strong> Continue regular monitoring for anomalous patterns</div>")
        f.write("</div>")
        
    print(f"[NetMini] Report generated: {path}")
    return path

# ---- GUI ----
class LiveWindow:
    """[REQ: classes] Tkinter UI that shows live stats and can export enhanced report."""
    def __init__(self, iface, bpf, window_secs):
        self.iface, self.bpf, self.window_secs = iface, bpf, window_secs
        self.cap = LiveCapture(iface=iface, bpf=bpf)
        self.sw = SlidingWindow(seconds=window_secs)
        self.rows = {}
        self.total_seen = 0

        self.root = tk.Tk()
        self.root.title("NetMini — Port-Scan Monitor")
        self.root.geometry("1100x540")
        self.root.resizable(False, False)

        top = ttk.Frame(self.root, padding=6); top.pack(fill="x")
        self.summary = tk.StringVar(value=f"iface={iface} | window={window_secs}")
        ttk.Label(top, textvariable=self.summary).pack(anchor="w")

        # [PHASE 3] Updated columns to show scan patterns
        cols = ("time", "src", "type", "pattern", "unique_ports", "pps", "ratio", "preview")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=18)
        for c in cols:
            w = 120 if c != "preview" else 200
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="center")
        self.tree.pack(fill="both", expand=True)

        btns = ttk.Frame(self.root, padding=6); btns.pack(fill="x")
        ttk.Button(btns, text="Start", command=self.start).pack(side="left", padx=4)
        ttk.Button(btns, text="Stop", command=self.stop).pack(side="left", padx=4)
        ttk.Button(btns, text="Export Report", command=self.export).pack(side="left", padx=4)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Escape>", lambda e: self.on_close())

        self.cap.start()
        self.root.after(100, self.pump)

    def start(self):
        try:
            self.cap.start()
        except Exception:
            pass

    def stop(self):
        try:
            self.cap.stop()
        except Exception:
            pass

    def export(self):
        """[PHASE 3] Collect stats and write HTML report with new features."""
        now = int(time.time())
        stats = self.sw.stats(time.time())
        rows = []
        for src, s in stats.items():
            is_scan = (s["u"] >= PORT_SCAN_MIN_UNIQUE and s["pps"] > MIN_PPS)
            # [PHASE 3] Add scan pattern classification and service analysis
            scan_pattern = classify_scan_type(s["all_ports"])
            services = get_service_analysis(s["all_ports"])
            rows.append({
                "time": now,
                "src": src,
                "type": "port_scan" if is_scan else "normal",
                "scan_pattern": scan_pattern,
                "unique_ports": s["u"],
                "pps": f"{s['pps']:.1f}",
                "ratio": f"{s['rat']:.0f}",
                "top_services": ", ".join(services[:3]),
            })
        write_report(rows)

    def pump(self):
        for _ in range(200):
            try:
                ts, src, dport = self.cap.q.get_nowait()
            except Exception:
                break
            self.sw.add(ts, src, dport)
            self.total_seen += 1

        now = time.time()
        stats = self.sw.stats(now)
        for src, s in stats.items():
            u, pps, rat = s["u"], s["pps"], s["rat"]
            is_scan = (u >= PORT_SCAN_MIN_UNIQUE and pps > MIN_PPS)
            # [PHASE 3] Show scan pattern in live GUI
            pattern = classify_scan_type(s["all_ports"])
            row = (
                int(now),
                src,
                "port_scan" if is_scan else "normal",
                pattern,
                u,
                f"{pps:.1f}",
                f"{rat:.0f}",
                ",".join(map(str, s["fp"][:3])),
            )
            self.upsert(src, row)

        packets = sum(len(v["t"]) for v in self.sw.events.values())
        sources = len(self.sw.events)
        self.summary.set(
            f"iface={self.iface} | window={self.window_secs}s (sliding detection window) | "
            f"sources:{sources} | packets:{packets} | seen:{self.total_seen}"
        )
        self.root.after(100, self.pump)

    def upsert(self, key, values):
        iid = self.rows.get(key)
        if iid is None:
            self.rows[key] = self.tree.insert("", "end", values=values)
        else:
            self.tree.item(iid, values=values)

    def on_close(self):
        try:
            self.stop()
        finally:
            self.root.destroy()

def main():
    """[REQ: functions] Argument parsing (includes [REQ: casting] for --window -> int)."""
    ap = argparse.ArgumentParser(description="NetMini — Real-time Port-Scan Detection")
    ap.add_argument("--version", action="store_true", help="print version and exit")
    ap.add_argument("--iface", default="eth1")
    ap.add_argument("--bpf", default="ip and (tcp or udp)")
    ap.add_argument("--window", type=int, default=WINDOW_SECS)
    args = ap.parse_args()

    if args.version:
        sys.stdout.write(f"NetMini {__version__}\n")
        sys.exit(0)

    try:
        LiveWindow(args.iface, args.bpf, args.window).root.mainloop()
    except KeyboardInterrupt:
        sys.exit(130)

if __name__ == "__main__":
    main()
