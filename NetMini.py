#!/usr/bin/env python3
"""NetMini - Real-time Port Scan Detection Tool"""

import argparse
import os
import sys
import time
import queue
import tkinter as tk
from tkinter import ttk
from collections import defaultdict, deque, Counter
from scapy.all import AsyncSniffer, IP, TCP, UDP

# Configuration
WINDOW_SECS = 60
PORT_SCAN_MIN_UNIQUE = 15
MIN_PPS = 1.0
__version__ = "3.0.0-simplified"

COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}


class LiveCapture:
    """Captures packets and pushes them to a queue for processing"""
    
    def __init__(self, iface="eth1", bpf="ip and (tcp or udp)", qmax=5000):
        self.iface = iface
        self.bpf = bpf
        self.q = queue.Queue(maxsize=qmax)
        self.sniffer = None

    def _on_pkt(self, pkt):
        """Process each packet and extract source IP and destination port"""
        try:
            if IP not in pkt:
                return
            
            dport = None
            if TCP in pkt:
                dport = int(pkt[TCP].dport)
            elif UDP in pkt:
                dport = int(pkt[UDP].dport)
            
            if dport:
                self.q.put_nowait((time.time(), pkt[IP].src, dport))
        except queue.Full:
            pass

    def start(self):
        """Start packet capture"""
        if not self.sniffer:
            self.sniffer = AsyncSniffer(
                iface=self.iface,
                filter=self.bpf,
                prn=self._on_pkt,
                store=False
            )
            self.sniffer.start()

    def stop(self):
        """Stop packet capture safely"""
        if self.sniffer:
            try:
                self.sniffer.stop()
                self.sniffer.join()
            except Exception:
                pass
            finally:
                self.sniffer = None


class SlidingWindow:
    """Maintains time-bounded sliding window for packet statistics"""
    
    def __init__(self, seconds=WINDOW_SECS):
        self.seconds = seconds
        self.events = defaultdict(lambda: {"times": deque(), "ports": deque()})

    def add(self, timestamp, src_ip, dest_port):
        """Add packet event to the window"""
        event = self.events[src_ip]
        event["times"].append(timestamp)
        event["ports"].append(dest_port)

    def stats(self, now):
        """Calculate statistics for current window"""
        cutoff = now - self.seconds
        results = {}
        expired = []
        
        for src_ip, event in self.events.items():
            times, ports = event["times"], event["ports"]
            
            # Remove expired events
            while times and times[0] < cutoff:
                times.popleft()
                ports.popleft()
            
            if not times:
                expired.append(src_ip)
                continue
            
            unique_ports = len(set(ports))
            results[src_ip] = {
                "unique": unique_ports,
                "pps": len(times) / self.seconds,
                "ratio": (unique_ports / len(times)) * 100,
                "preview": list(ports)[:6],
                "all_ports": list(ports)
            }
        
        # Clean up expired sources
        for src_ip in expired:
            del self.events[src_ip]
        
        return results


def classify_scan_type(ports):
    """Classify port scan as vertical, horizontal, or mixed"""
    unique = len(set(ports))
    total = len(ports)
    
    if unique >= 20:
        return "Vertical"
    elif unique < 5 and total > 20:
        return "Horizontal"
    return "Mixed"


def get_top_services(ports, limit=3):
    """Get most frequently targeted services"""
    port_counts = Counter(ports)
    services = []
    
    for port, count in port_counts.most_common(limit):
        service = COMMON_PORTS.get(port, f"Port-{port}")
        services.append(f"{service}:{port}({count}x)")
    
    return ", ".join(services)


def generate_html_report(rows, outdir="reports"):
    """Generate comprehensive HTML security report"""
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"report_{int(time.time())}.html")
    
    # Calculate statistics
    total_sources = len(rows)
    port_scanners = sum(1 for r in rows if r["type"] == "port_scan")
    total_ports = sum(r["unique_ports"] for r in rows)
    avg_pps = sum(r["pps"] for r in rows) / max(total_sources, 1)
    high_risk = max(rows, key=lambda r: r["unique_ports"]) if rows else None
    
    # Build HTML
    html = f"""<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>NetMini Security Report</title>
    <style>
        body {{ font: 14px system-ui; margin: 20px; background: #f5f7fa; }}
        .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 0; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-num {{ font-size: 32px; font-weight: bold; color: #e74c3c; }}
        .stat-label {{ color: #7f8c8d; font-size: 12px; text-transform: uppercase; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #bdc3c7; padding: 8px; text-align: center; }}
        th {{ background: #34495e; color: white; }}
        .alert {{ background: #e74c3c; color: white; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        .rec {{ background: #d5f4e6; border-left: 4px solid #27ae60; padding: 12px; margin: 8px 0; }}
    </style>
</head>
<body>
    <h1>🔒 NetMini — Port Scan Detection Report</h1>
    <p style="color: #7f8c8d">Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div class="stats">
            <div class="stat-box"><div class="stat-num">{total_sources}</div><div class="stat-label">Sources</div></div>
            <div class="stat-box"><div class="stat-num">{port_scanners}</div><div class="stat-label">Scanners</div></div>
            <div class="stat-box"><div class="stat-num">{total_ports}</div><div class="stat-label">Ports</div></div>
            <div class="stat-box"><div class="stat-num">{avg_pps:.1f}</div><div class="stat-label">Avg PPS</div></div>
        </div>
"""
    
    if high_risk:
        html += f"""        <div class="alert">⚠️ <strong>Highest Risk:</strong> {high_risk['src']} 
                   targeted {high_risk['unique_ports']} unique ports</div>
"""
    
    html += """    </div>
    
    <div class="section">
        <h2>🔍 Detection Results</h2>
        <table>
            <tr>
                <th>Time</th><th>Source IP</th><th>Type</th><th>Pattern</th>
                <th>Unique Ports</th><th>PPS</th><th>Ratio</th><th>Top Services</th>
            </tr>
"""
    
    if rows:
        for r in rows:
            html += f"""            <tr>
                <td>{r['time']}</td><td>{r['src']}</td><td>{r['type']}</td><td>{r['pattern']}</td>
                <td>{r['unique_ports']}</td><td>{r['pps']:.1f}</td><td>{r['ratio']:.0f}</td><td>{r['services']}</td>
            </tr>
"""
    else:
        html += """            <tr><td colspan="8">No detections recorded</td></tr>
"""
    
    html += """        </table>
    </div>
    
    <div class="section">
        <h2>🛡️ Recommendations</h2>
"""
    
    if port_scanners > 0:
        html += """        <div class="rec">🚨 Block or investigate flagged port scanners</div>
        <div class="rec">🔒 Implement rate limiting on commonly scanned ports</div>
        <div class="rec">📝 Enable detailed connection logs</div>
        <div class="rec">🔔 Configure real-time alerts</div>
"""
    else:
        html += """        <div class="rec">✅ No malicious scanning detected</div>
        <div class="rec">📊 Continue regular monitoring</div>
"""
    
    html += """    </div>
</body>
</html>"""
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    
    print(f"[NetMini] Report saved: {path}")
    return path


class LiveWindow:
    """Tkinter GUI for real-time port scan monitoring"""
    
    def __init__(self, iface, bpf, window_secs):
        self.iface = iface
        self.window_secs = window_secs
        self.cap = LiveCapture(iface=iface, bpf=bpf)
        self.sw = SlidingWindow(seconds=window_secs)
        self.rows = {}
        self.total_seen = 0
        
        # Build GUI
        self.root = tk.Tk()
        self.root.title("NetMini — Port Scan Monitor")
        self.root.geometry("1100x540")
        self.root.resizable(False, False)
        
        # Top info bar
        top = ttk.Frame(self.root, padding=6)
        top.pack(fill="x")
        self.summary = tk.StringVar(value=f"Interface: {iface} | Window: {window_secs}s")
        ttk.Label(top, textvariable=self.summary).pack(anchor="w")
        
        # Results table
        columns = ("time", "src", "type", "pattern", "unique_ports", "pps", "ratio", "preview")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=18)
        for col in columns:
            width = 200 if col == "preview" else 120
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center")
        self.tree.pack(fill="both", expand=True)
        
        # Control buttons
        buttons = ttk.Frame(self.root, padding=6)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Start", command=self.start_capture).pack(side="left", padx=4)
        ttk.Button(buttons, text="Stop", command=self.stop_capture).pack(side="left", padx=4)
        ttk.Button(buttons, text="Export Report", command=self.export_report).pack(side="left", padx=4)
        
        # Window close handling
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Escape>", lambda e: self.on_close())
        
        # Start capture and GUI update loop
        self.cap.start()
        self.root.after(100, self.update_display)

    def start_capture(self):
        """Start packet capture"""
        try:
            self.cap.start()
        except Exception:
            pass

    def stop_capture(self):
        """Stop packet capture"""
        try:
            self.cap.stop()
        except Exception:
            pass

    def export_report(self):
        """Generate and save HTML report"""
        stats = self.sw.stats(time.time())
        rows = []
        
        for src_ip, s in stats.items():
            is_scan = (s["unique"] >= PORT_SCAN_MIN_UNIQUE and s["pps"] > MIN_PPS)
            rows.append({
                "time": int(time.time()),
                "src": src_ip,
                "type": "port_scan" if is_scan else "normal",
                "pattern": classify_scan_type(s["all_ports"]),
                "unique_ports": s["unique"],
                "pps": s["pps"],
                "ratio": s["ratio"],
                "services": get_top_services(s["all_ports"])
            })
        
        generate_html_report(rows)

    def update_display(self):
        """Process packets and update GUI display"""
        # Process up to 200 packets per update
        for _ in range(200):
            try:
                timestamp, src_ip, dest_port = self.cap.q.get_nowait()
                self.sw.add(timestamp, src_ip, dest_port)
                self.total_seen += 1
            except Exception:
                break
        
        # Update display with current stats
        now = time.time()
        stats = self.sw.stats(now)
        
        for src_ip, s in stats.items():
            is_scan = (s["unique"] >= PORT_SCAN_MIN_UNIQUE and s["pps"] > MIN_PPS)
            row_data = (
                int(now),
                src_ip,
                "port_scan" if is_scan else "normal",
                classify_scan_type(s["all_ports"]),
                s["unique"],
                f"{s['pps']:.1f}",
                f"{s['ratio']:.0f}",
                ",".join(map(str, s["preview"][:3]))
            )
            self.upsert_row(src_ip, row_data)
        
        # Update summary
        total_packets = sum(len(e["times"]) for e in self.sw.events.values())
        total_sources = len(self.sw.events)
        self.summary.set(
            f"Interface: {self.iface} | Window: {self.window_secs}s | "
            f"Sources: {total_sources} | Packets: {total_packets} | Total Seen: {self.total_seen}"
        )
        
        # Schedule next update
        self.root.after(100, self.update_display)

    def upsert_row(self, key, values):
        """Insert or update a row in the tree view"""
        if key in self.rows:
            self.tree.item(self.rows[key], values=values)
        else:
            self.rows[key] = self.tree.insert("", "end", values=values)

    def on_close(self):
        """Handle window close event"""
        try:
            self.stop_capture()
        finally:
            self.root.destroy()


def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(description="NetMini — Real-time Port Scan Detection")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    parser.add_argument("--iface", default="eth1", help="Network interface to monitor")
    parser.add_argument("--bpf", default="ip and (tcp or udp)", help="BPF filter")
    parser.add_argument("--window", type=int, default=WINDOW_SECS, help="Sliding window size in seconds")
    args = parser.parse_args()
    
    if args.version:
        print(f"NetMini {__version__}")
        sys.exit(0)
    
    try:
        LiveWindow(args.iface, args.bpf, args.window).root.mainloop()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()