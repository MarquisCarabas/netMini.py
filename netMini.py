#!/usr/bin/env python3
# NetMini

import argparse, os, sys, time, queue, tkinter as tk
from tkinter import ttk
from collections import defaultdict, deque
from scapy.all import AsyncSniffer, IP, TCP, UDP

# [REQ: constants / casting targets] detection thresholds are constants; casting occurs at dport int()
WINDOW_SECS = 60
PORT_SCAN_MIN_UNIQUE = 15
MIN_PPS = 1.0

__version__ = "3.0.0-final"  # [REQ: versioning optional but used with sys]

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
            # non-fatal drop if GUI/pump is momentarily behind
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
            # evict old entries
            while t and t[0] < cutoff:
                t.popleft()
                p.popleft()
            n = len(t)
            if not n:
                dead.append(src)
                continue
            u = len(set(p))                         # unique destination ports in window
            out[src] = {
                "u": u,
                "pps": n / self.seconds,            # packets per second in window
                "rat": (u / n) * 100,               # unique/total ratio (%)
                "fp": list(p)[:6],                  # preview of first ports
            }
        for src in dead:
            del self.events[src]
        return out

# [REQ: file handling] Write an HTML report to disk using os.path + open()
def write_report(rows, outdir="reports"):
    """Writes an HTML table of current rows. [REQ: modules(os)] os.makedirs/join; [REQ: file handling] open/write."""
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"report_{int(time.time())}.html")
    cols = ("time", "src", "type", "unique_ports", "pps", "ratio", "first_ports")
    head = (
        "<!doctype html><meta charset='utf-8'><title>NetMini Report</title>"
        "<style>body{font:14px system-ui;margin:20px}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:6px;text-align:center}th{background:#f6f8ff}</style>"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(head)
        f.write(f"<h1>NetMini – Live Report</h1><p>Generated {time.strftime('%F %T')}</p>")
        f.write("<table><tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr>")
        if not rows:
            f.write("<tr><td colspan='7' style='color:#777'>No rows</td></tr>")
        for r in rows:
            f.write("<tr>" + "".join(f"<td>{r.get(k,'')}</td>" for k in cols) + "</tr>")
        f.write("</table>")
    print(f"[NetMini] wrote report: {path}")
    return path

# ---- GUI ----
class LiveWindow:
    """[REQ: classes] Tkinter UI that shows live stats and can export a report."""
    def __init__(self, iface, bpf, window_secs):
        self.iface, self.bpf, self.window_secs = iface, bpf, window_secs
        self.cap = LiveCapture(iface=iface, bpf=bpf)
        self.sw = SlidingWindow(seconds=window_secs)
        self.rows = {}   # src -> Treeview item id
        self.total_seen = 0

        # [REQ: UI/structure] top-level window
        self.root = tk.Tk()
        self.root.title("NetMini – Live Port-Scan Monitor")
        self.root.geometry("940x540")
        self.root.resizable(False, False)

        # summary line
        top = ttk.Frame(self.root, padding=6); top.pack(fill="x")
        self.summary = tk.StringVar(value=f"iface={iface} | window={window_secs}s")
        ttk.Label(top, textvariable=self.summary).pack(anchor="w")

        # table
        cols = ("time", "src", "type", "unique_ports", "pps", "ratio", "first_ports")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=120 if c != "first_ports" else 260, anchor="center")
        self.tree.pack(fill="both", expand=True)

        # buttons
        btns = ttk.Frame(self.root, padding=6); btns.pack(fill="x")
        ttk.Button(btns, text="Start", command=self.start).pack(side="left", padx=4)
        ttk.Button(btns, text="Stop", command=self.stop).pack(side="left", padx=4)
        ttk.Button(btns, text="Export Report", command=self.export).pack(side="left", padx=4)

        # window protocol & hotkey
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Escape>", lambda e: self.on_close())

        # begin capture + schedule UI pump
        self.cap.start()
        self.root.after(100, self.pump)

    # [REQ: functions] control handlers
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
        """Collect current stats and write an HTML report. [REQ: file handling]"""
        now = int(time.time())
        stats = self.sw.stats(time.time())
        rows = []
        for src, s in stats.items():
            scan = "port_scan" if (s["u"] >= PORT_SCAN_MIN_UNIQUE and s["pps"] > MIN_PPS) else "normal"
            rows.append({
                "time": now,
                "src": src,
                "type": scan,
                "unique_ports": s["u"],
                "pps": f"{s['pps']:.1f}",
                "ratio": f"{s['rat']:.0f}",
                "first_ports": ",".join(map(str, s["fp"][:5])),
            })
        write_report(rows)

    # [REQ: functions] UI loop / pump to drain capture queue and refresh table
    def pump(self):
        # drain up to N items fast to keep UI responsive
        for _ in range(200):
            try:
                ts, src, dport = self.cap.q.get_nowait()
            except Exception:
                break
            self.sw.add(ts, src, dport)
            self.total_seen += 1

        # recompute stats and upsert rows
        now = time.time()
        stats = self.sw.stats(now)
        for src, s in stats.items():
            u, pps, rat = s["u"], s["pps"], s["rat"]
            row = (
                int(now),
                src,
                "port_scan" if (u >= PORT_SCAN_MIN_UNIQUE and pps > MIN_PPS) else "normal",
                u,
                f"{pps:.1f}",
                f"{rat:.0f}",
                ",".join(map(str, s["fp"][:3])),
            )
            self.upsert(src, row)

        # update summary
        packets = sum(len(v["t"]) for v in self.sw.events.values())
        sources = len(self.sw.events)
        self.summary.set(
            f"iface={self.iface} | bpf={self.bpf} | window={self.window_secs}s | "
            f"sources:{sources} | pkt_window:{packets} | seen:{self.total_seen}"
        )
        self.root.after(100, self.pump)

    # [REQ: functions] helper updates/inserts a row in the Treeview
    def upsert(self, key, values):
        iid = self.rows.get(key)
        if iid is None:
            self.rows[key] = self.tree.insert("", "end", values=values)
        else:
            self.tree.item(iid, values=values)

    # [REQ: functions] cleanup handler. Uses sys.exit in main() to demonstrate sys usage.
    def on_close(self):
        try:
            self.stop()
        finally:
            self.root.destroy()

def main():
    """[REQ: functions] Argument parsing (includes [REQ: casting] for --window -> int)."""
    ap = argparse.ArgumentParser(description="NetMini – live-only")
    ap.add_argument("--version", action="store_true", help="print version and exit")  # [REQ: modules(sys)]
    ap.add_argument("--iface", default="eth1")
    ap.add_argument("--bpf", default="ip and (tcp or udp)")
    ap.add_argument("--window", type=int, default=WINDOW_SECS)  # [REQ: casting]
    args = ap.parse_args()

    if args.version:
        # [REQ: modules(sys)] demonstrate sys usage
        sys.stdout.write(f"NetMini {__version__}\n")
        sys.exit(0)

    try:
        LiveWindow(args.iface, args.bpf, args.window).root.mainloop()
    except KeyboardInterrupt:
        sys.exit(130)  # [REQ: modules(sys)] graceful exit on Ctrl+C

if __name__ == "__main__":
    main()
