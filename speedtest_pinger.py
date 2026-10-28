import ctypes
from ctypes import wintypes
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk
import urllib.request
import ssl
from collections import deque
from datetime import datetime


class MIB_IFROW(ctypes.Structure):
    _fields_ = [
        ("wszName", wintypes.WCHAR * 256),
        ("dwIndex", wintypes.DWORD),
        ("dwType", wintypes.DWORD),
        ("dwMtu", wintypes.DWORD),
        ("dwSpeed", wintypes.DWORD),
        ("dwPhysAddrLen", wintypes.DWORD),
        ("bPhysAddr", ctypes.c_ubyte * 8),
        ("dwAdminStatus", wintypes.DWORD),
        ("dwOperStatus", wintypes.DWORD),
        ("dwLastChange", wintypes.DWORD),
        ("dwInOctets", wintypes.DWORD),
        ("dwInUcastPkts", wintypes.DWORD),
        ("dwInNUcastPkts", wintypes.DWORD),
        ("dwInDiscards", wintypes.DWORD),
        ("dwInErrors", wintypes.DWORD),
        ("dwInUnknownProtos", wintypes.DWORD),
        ("dwOutOctets", wintypes.DWORD),
        ("dwOutUcastPkts", wintypes.DWORD),
        ("dwOutNUcastPkts", wintypes.DWORD),
        ("dwOutDiscards", wintypes.DWORD),
        ("dwOutErrors", wintypes.DWORD),
        ("dwOutQLen", wintypes.DWORD),
        ("dwDescrLen", wintypes.DWORD),
        ("bDescr", ctypes.c_char * 256),
    ]


class MIB_IFTABLE(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_IFROW * 128),
    ]


class WindowsNetMonitor:
    """Reads real-time total bytes received across physical network adapters."""

    def __init__(self):
        self.iphlpapi = ctypes.windll.iphlpapi
        self.prev_octets = {}
        self.prev_time = time.perf_counter()
        self._snapshot_interfaces()

    def _snapshot_interfaces(self):
        table = MIB_IFTABLE()
        size = wintypes.ULONG(ctypes.sizeof(table))
        res = self.iphlpapi.GetIfTable(ctypes.byref(table), ctypes.byref(size), False)
        if res != 0:
            return {}

        # Deduplicate NDIS filter rows that share the same physical MAC address
        mac_octets = {}
        for i in range(min(table.dwNumEntries, 128)):
            row = table.table[i]
            # Skip loopback (24) and tunnel (131) interfaces
            if row.dwType in (24, 131) or row.dwPhysAddrLen == 0:
                continue
            mac = bytes(row.bPhysAddr[: row.dwPhysAddrLen])
            if mac == b"\x00" * len(mac):
                continue
            # Keep the maximum counter value reported for this physical MAC
            in_octets = int(row.dwInOctets)
            if mac not in mac_octets or in_octets > mac_octets[mac]:
                mac_octets[mac] = in_octets

        return mac_octets

    def get_speed_mbps(self):
        """Returns current system-wide download speed in Mbps."""
        now = time.perf_counter()
        dt = now - self.prev_time
        if dt <= 0.05:
            return 0.0

        curr_octets = self._snapshot_interfaces()
        total_delta_bytes = 0

        for mac, curr_val in curr_octets.items():
            if mac in self.prev_octets:
                prev_val = self.prev_octets[mac]
                # Handle 32-bit DWORD wrap-around seamlessly
                delta = (curr_val - prev_val) & 0xFFFFFFFF
                # Ignore implausible spikes (> 10 Gbps per interface)
                if delta < 1_250_000_000 * dt:
                    total_delta_bytes += delta

        self.prev_octets = curr_octets
        self.prev_time = now

        bits_per_sec = (total_delta_bytes * 8.0) / dt
        return bits_per_sec / 1_000_000.0



class SpeedtestPingerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Speedtest Pinger & Real Download Monitor")
        self.root.geometry("680x660")
        self.root.minsize(640, 620)
        self.root.configure(bg="#12141c")

        # State variables
        self.net_monitor = WindowsNetMonitor()
        self.live_history = deque(maxlen=4)  # Last 4 seconds of live speed
        self.current_live_mbps = 0.0

        self.auto_ping_running = False
        self.ping_count = 0
        self.next_ping_at = 0.0
        self.ping_in_progress = False
        self.benchmark_in_progress = False

        # Live NIC Before/After tracking
        self.live_before_mbps = None
        self.live_after_mbps = None

        # Active Benchmark Before/After tracking
        self.bench_before_mbps = None
        self.bench_after_mbps = None

        self._build_ui()
        self._start_background_loops()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Header
        header_frame = tk.Frame(self.root, bg="#12141c", padx=18, pady=12)
        header_frame.pack(fill="x")

        tk.Label(
            header_frame,
            text="SPEEDTEST.NET PINGER & SPEED MONITOR",
            font=("Segoe UI", 14, "bold"),
            fg="#f8fafc",
            bg="#12141c",
        ).pack(anchor="w")

        tk.Label(
            header_frame,
            text="Lightweight periodic pinger + real system download speed comparator (Before vs. After Ping)",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#12141c",
        ).pack(anchor="w", pady=(2, 0))

        
        # 1. Auto-Pinger Controls Card
        
        ping_card = tk.Frame(
            self.root, bg="#1e2230", highlightbackground="#2e3446", highlightthickness=1, padx=16, pady=12
        )
        ping_card.pack(fill="x", padx=18, pady=(0, 10))

        top_row = tk.Frame(ping_card, bg="#1e2230")
        top_row.pack(fill="x")

        tk.Label(
            top_row,
            text="1. Speedtest.net Pinger",
            font=("Segoe UI", 11, "bold"),
            fg="#38bdf8",
            bg="#1e2230",
        ).pack(side="left")

        self.status_badge = tk.Label(
            top_row,
            text=" ● STOPPED ",
            font=("Segoe UI", 9, "bold"),
            fg="#f87171",
            bg="#2d1f24",
            padx=8,
            pady=2,
        )
        self.status_badge.pack(side="right")

        # Controls Row
        ctrl_row = tk.Frame(ping_card, bg="#1e2230", pady=8)
        ctrl_row.pack(fill="x")

        tk.Label(ctrl_row, text="Interval:", font=("Segoe UI", 9), fg="#cbd5e1", bg="#1e2230").pack(
            side="left", padx=(0, 6)
        )

        self.interval_var = tk.StringVar(value="15")
        self.interval_combo = ttk.Combobox(
            ctrl_row,
            textvariable=self.interval_var,
            values=["5", "10", "15", "30", "60"],
            width=5,
            state="readonly",
        )
        self.interval_combo.pack(side="left", padx=(0, 6))
        tk.Label(ctrl_row, text="sec", font=("Segoe UI", 9), fg="#94a3b8", bg="#1e2230").pack(
            side="left", padx=(0, 16)
        )

        self.https_sni_var = tk.BooleanVar(value=True)
        self.https_chk = tk.Checkbutton(
            ctrl_row,
            text="Include HTTPS Request (Triggers SNI/DPI)",
            variable=self.https_sni_var,
            font=("Segoe UI", 9),
            fg="#cbd5e1",
            bg="#1e2230",
            selectcolor="#12141c",
            activebackground="#1e2230",
            activeforeground="#ffffff",
        )
        self.https_chk.pack(side="left")

        # Buttons + Stats Row
        btn_row = tk.Frame(ping_card, bg="#1e2230")
        btn_row.pack(fill="x", pady=(4, 0))

        self.toggle_btn = tk.Button(
            btn_row,
            text="▶ Start Auto-Ping",
            command=self.toggle_auto_ping,
            font=("Segoe UI", 9, "bold"),
            bg="#0284c7",
            fg="#ffffff",
            activebackground="#0369a1",
            activeforeground="#ffffff",
            relief="flat",
            padx=14,
            pady=5,
            cursor="hand2",
        )
        self.toggle_btn.pack(side="left", padx=(0, 8))

        self.ping_now_btn = tk.Button(
            btn_row,
            text="⚡ Ping Speedtest.net Now",
            command=self.trigger_manual_ping,
            font=("Segoe UI", 9),
            bg="#334155",
            fg="#f8fafc",
            activebackground="#475569",
            activeforeground="#ffffff",
            relief="flat",
            padx=12,
            pady=5,
            cursor="hand2",
        )
        self.ping_now_btn.pack(side="left")

        self.ping_stats_lbl = tk.Label(
            btn_row,
            text="Pings: 0  |  Last Latency: -- ms  |  Next: --",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#1e2230",
        )
        self.ping_stats_lbl.pack(side="right")

        
        # 2. Live System Download Monitor (Windows NIC Counter)
        
        live_card = tk.Frame(
            self.root, bg="#1e2230", highlightbackground="#2e3446", highlightthickness=1, padx=16, pady=12
        )
        live_card.pack(fill="x", padx=18, pady=(0, 10))

        live_header = tk.Frame(live_card, bg="#1e2230")
        live_header.pack(fill="x")

        tk.Label(
            live_header,
            text="2. Real-Time PC Download Monitor (System Network Adapter)",
            font=("Segoe UI", 11, "bold"),
            fg="#34d399",
            bg="#1e2230",
        ).pack(side="left")

        self.live_speed_lbl = tk.Label(
            live_header,
            text="0.00 Mbps (0.00 MB/s)",
            font=("Consolas", 12, "bold"),
            fg="#34d399",
            bg="#1e2230",
        )
        self.live_speed_lbl.pack(side="right")

        tk.Label(
            live_card,
            text="Measures actual live traffic coming into your PC (e.g. while downloading a game/file) before & after pinging:",
            font=("Segoe UI", 8),
            fg="#94a3b8",
            bg="#1e2230",
        ).pack(anchor="w", pady=(2, 8))

        live_grid = tk.Frame(live_card, bg="#1e2230")
        live_grid.pack(fill="x")
        live_grid.columnconfigure(0, weight=1)
        live_grid.columnconfigure(1, weight=1)
        live_grid.columnconfigure(2, weight=1)

        self.live_before_val = self._create_metric_box(
            live_grid, 0, "BEFORE SPEEDTEST PING", "-- Mbps", "3s avg before ping"
        )
        self.live_after_val = self._create_metric_box(
            live_grid, 1, "AFTER SPEEDTEST PING", "-- Mbps", "3s avg after ping"
        )
        self.live_delta_val = self._create_metric_box(
            live_grid, 2, "LIVE SPEED CHANGE", "--", "After vs. Before"
        )

        
        # 3. Built-in Real Download Speed Benchmark (Before vs. After)
       
        bench_card = tk.Frame(
            self.root, bg="#1e2230", highlightbackground="#2e3446", highlightthickness=1, padx=16, pady=12
        )
        bench_card.pack(fill="x", padx=18, pady=(0, 10))

        bench_header = tk.Frame(bench_card, bg="#1e2230")
        bench_header.pack(fill="x")

        tk.Label(
            bench_header,
            text="3. Active Real Download Test (Before vs. After Speedtest Ping)",
            font=("Segoe UI", 11, "bold"),
            fg="#c084fc",
            bg="#1e2230",
        ).pack(side="left")

        self.bench_btn = tk.Button(
            bench_header,
            text="🚀 Run Before/After Speed Test",
            command=self.start_before_after_benchmark,
            font=("Segoe UI", 9, "bold"),
            bg="#7c3aed",
            fg="#ffffff",
            activebackground="#6d28d9",
            activeforeground="#ffffff",
            relief="flat",
            padx=12,
            pady=4,
            cursor="hand2",
        )
        self.bench_btn.pack(side="right")

        self.bench_status_lbl = tk.Label(
            bench_card,
            text="Downloads a test stream from an independent CDN (Cloudflare), pings Speedtest.net, and re-tests immediately.",
            font=("Segoe UI", 8),
            fg="#94a3b8",
            bg="#1e2230",
        )
        self.bench_status_lbl.pack(anchor="w", pady=(2, 8))

        bench_grid = tk.Frame(bench_card, bg="#1e2230")
        bench_grid.pack(fill="x")
        bench_grid.columnconfigure(0, weight=1)
        bench_grid.columnconfigure(1, weight=1)
        bench_grid.columnconfigure(2, weight=1)

        self.bench_before_val = self._create_metric_box(
            bench_grid, 0, "BEFORE SPEEDTEST PING", "-- Mbps", "Independent CDN download"
        )
        self.bench_after_val = self._create_metric_box(
            bench_grid, 1, "AFTER SPEEDTEST PING", "-- Mbps", "Right after Speedtest ping"
        )
        self.bench_delta_val = self._create_metric_box(
            bench_grid, 2, "BENCHMARK DIFFERENCE", "--", "Net speed difference"
        )

       
        # 4. Event Log
        
        log_frame = tk.Frame(
            self.root, bg="#1e2230", highlightbackground="#2e3446", highlightthickness=1, padx=12, pady=8
        )
        log_frame.pack(fill="both", expand=True, padx=18, pady=(0, 14))

        log_top = tk.Frame(log_frame, bg="#1e2230")
        log_top.pack(fill="x", pady=(0, 4))

        tk.Label(log_top, text="Activity Log", font=("Segoe UI", 9, "bold"), fg="#cbd5e1", bg="#1e2230").pack(
            side="left"
        )

        tk.Button(
            log_top,
            text="Clear",
            command=self.clear_log,
            font=("Segoe UI", 8),
            bg="#2e3446",
            fg="#cbd5e1",
            relief="flat",
            padx=8,
            pady=1,
            cursor="hand2",
        ).pack(side="right")

        self.log_text = tk.Text(
            log_frame,
            height=6,
            bg="#12141c",
            fg="#94a3b8",
            font=("Consolas", 9),
            relief="flat",
            padx=8,
            pady=6,
            state="disabled",
        )
        self.log_text.pack(fill="both", expand=True)

        self.log("Ready. Monitoring system network adapter in real time.")

    def _create_metric_box(self, parent, col, title, default_val, subtitle):
        box = tk.Frame(parent, bg="#141722", padx=10, pady=8, highlightbackground="#262b3d", highlightthickness=1)
        box.grid(row=0, column=col, sticky="ew", padx=4)

        tk.Label(box, text=title, font=("Segoe UI", 8, "bold"), fg="#94a3b8", bg="#141722").pack(anchor="w")
        val_lbl = tk.Label(box, text=default_val, font=("Consolas", 13, "bold"), fg="#f8fafc", bg="#141722")
        val_lbl.pack(anchor="w", pady=(2, 2))
        tk.Label(box, text=subtitle, font=("Segoe UI", 7), fg="#64748b", bg="#141722").pack(anchor="w")
        return val_lbl

   
    # Logging & Helpers
   
    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"

        def _append():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        self.root.after(0, _append)

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    @staticmethod
    def _format_delta(before: float, after: float):
        diff = after - before
        sign = "+" if diff >= 0 else ""
        if before > 0.1:
            pct = (diff / before) * 100.0
            text = f"{sign}{diff:.2f} Mbps ({sign}{pct:.1f}%)"
        else:
            text = f"{sign}{diff:.2f} Mbps"

        if diff > 0.5:
            color = "#4ade80"  # Green boost
        elif diff < -0.5:
            color = "#f87171"  # Red drop
        else:
            color = "#e2e8f0"  # Neutral
        return text, color

   
    # Background Loops (1s Live Speed Ticker & Auto-Ping Scheduler)
  

    def _start_background_loops(self):
        self._tick_live_monitor()

    def _tick_live_monitor(self):
        # 1. Read real-time system download speed
        mbps = self.net_monitor.get_speed_mbps()
        self.current_live_mbps = mbps
        self.live_history.append(mbps)
        mbs = mbps / 8.0
        self.live_speed_lbl.configure(text=f"{mbps:6.2f} Mbps ({mbs:5.2f} MB/s)")

        # 2. Check Auto-Ping countdown
        if self.auto_ping_running and not self.ping_in_progress:
            remaining = max(0, int(round(self.next_ping_at - time.time())))
            self._update_ping_stats_label(next_sec=remaining)
            if time.time() >= self.next_ping_at:
                self._launch_ping_sequence()

        self.root.after(1000, self._tick_live_monitor)

    def _update_ping_stats_label(self, latency_str=None, next_sec=None):
        if latency_str is not None:
            self._last_latency_str = latency_str
        lat = getattr(self, "_last_latency_str", "-- ms")
        nxt = f"{next_sec}s" if (self.auto_ping_running and next_sec is not None) else "--"
        self.ping_stats_lbl.configure(text=f"Pings: {self.ping_count}  |  Last Latency: {lat}  |  Next: {nxt}")

    
    # Speedtest.net Pinger Logic
   

    def toggle_auto_ping(self):
        self.auto_ping_running = not self.auto_ping_running
        if self.auto_ping_running:
            self.status_badge.configure(text=" ● ACTIVE ", fg="#4ade80", bg="#162d24")
            self.toggle_btn.configure(text="⏹ Stop Auto-Ping", bg="#dc2626", activebackground="#b91c1c")
            interval = int(self.interval_var.get())
            self.log(f"Auto-Ping started (every {interval} seconds).")
            self._launch_ping_sequence()
        else:
            self.status_badge.configure(text=" ● STOPPED ", fg="#f87171", bg="#2d1f24")
            self.toggle_btn.configure(text="▶ Start Auto-Ping", bg="#0284c7", activebackground="#0369a1")
            self._update_ping_stats_label(next_sec=None)
            self.log("Auto-Ping stopped.")

    def trigger_manual_ping(self):
        if self.ping_in_progress:
            return
        self._launch_ping_sequence()

    def _launch_ping_sequence(self):
        if self.ping_in_progress:
            return
        self.ping_in_progress = True
        threading.Thread(target=self._ping_worker, daemon=True).start()

    def _execute_speedtest_ping(self):
        """Sends ICMP ping + optional HTTPS request to speedtest.net and returns latency in ms."""
        include_https = self.https_sni_var.get()
        latency_ms = None

        # 1. Windows ICMP Ping (hidden console window)
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            t0 = time.perf_counter()
            proc = subprocess.run(
                ["ping", "-n", "1", "-w", "2500", "www.speedtest.net"],
                capture_output=True,
                text=True,
                startupinfo=startupinfo,
                timeout=4,
            )
            dt_ms = (time.perf_counter() - t0) * 1000.0
            out = proc.stdout
            for token in out.replace("=", " ").replace("<", " ").split():
                if token.endswith("ms") and token[:-2].isdigit():
                    latency_ms = int(token[:-2])
                    break
            if latency_ms is None and proc.returncode == 0:
                latency_ms = int(dt_ms)
        except Exception:
            pass

        # 2. Lightweight HTTPS request to trigger SNI / DPI detection for speedtest.net
        if include_https:
            ctx = ssl.create_default_context()
            for url in (
                "https://www.speedtest.net/favicon.ico",
                "https://c.speedtest.net/speedtest-servers-static.php",
            ):
                try:
                    req = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpeedtestPinger/1.0",
                            "Cache-Control": "no-cache",
                        },
                    )
                    t0 = time.perf_counter()
                    with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                        resp.read(512)
                    if latency_ms is None:
                        latency_ms = int((time.perf_counter() - t0) * 1000.0)
                    break
                except Exception:
                    continue

        return latency_ms

    def _ping_worker(self):
        try:
            # Snapshot Live NIC speed BEFORE ping (average of recent samples)
            before_samples = list(self.live_history)
            before_avg = sum(before_samples) / len(before_samples) if before_samples else self.current_live_mbps
            self.live_before_mbps = before_avg

            self.root.after(
                0,
                lambda: self.live_before_val.configure(text=f"{before_avg:.2f} Mbps", fg="#f8fafc"),
            )

            # Perform the ping to speedtest.net
            latency_ms = self._execute_speedtest_ping()
            self.ping_count += 1

            lat_text = f"{latency_ms} ms" if latency_ms is not None else "Timeout"
            mode_tag = "ICMP+HTTPS" if self.https_sni_var.get() else "ICMP"
            self.log(f"Ping #{self.ping_count} -> speedtest.net ({mode_tag}): {lat_text}")

            # Wait 3 seconds to capture the AFTER live download speed
            time.sleep(3.0)
            after_samples = list(self.live_history)
            after_avg = sum(after_samples) / len(after_samples) if after_samples else self.current_live_mbps
            self.live_after_mbps = after_avg

            delta_text, delta_color = self._format_delta(before_avg, after_avg)

            def _update_ui():
                self.live_after_val.configure(text=f"{after_avg:.2f} Mbps", fg="#f8fafc")
                self.live_delta_val.configure(text=delta_text, fg=delta_color)
                interval = int(self.interval_var.get())
                self.next_ping_at = time.time() + interval
                self._update_ping_stats_label(latency_str=lat_text, next_sec=interval)

            self.root.after(0, _update_ui)
        finally:
            self.ping_in_progress = False

   
    # Active Real Download Benchmark (Before vs. After Speedtest Ping)
  

    def start_before_after_benchmark(self):
        if self.benchmark_in_progress:
            return
        self.benchmark_in_progress = True
        self.bench_btn.configure(state="disabled", text="⏳ Testing...")
        threading.Thread(target=self._benchmark_worker, daemon=True).start()

    def _measure_real_download_speed(self, duration_sec=4.0) -> float:
        """
        Measures real achievable download speed in Mbps by streaming payload data
        from independent non-Speedtest CDNs (Cloudflare / Tele2 / Hetzner) while
        also cross-checking the system NIC hardware counter.
        """
        test_urls = [
            "https://speed.cloudflare.com/__down?bytes=25000000",
            "http://speedtest.tele2.net/10MB.zip",
            "https://nbg1-speed.hetzner.com/100MB.bin",
        ]
        ctx = ssl.create_default_context()

        for url in test_urls:
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "Cache-Control": "no-cache",
                    },
                )
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    t_start = time.perf_counter()
                    total_bytes = 0
                    # Warmup 0.3s so TCP slow-start stabilizes
                    warmup_done = False
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        now = time.perf_counter()
                        if not warmup_done and (now - t_start) >= 0.35:
                            warmup_done = True
                            t_start = now
                            total_bytes = 0
                        else:
                            total_bytes += len(chunk)

                        if warmup_done and (now - t_start) >= duration_sec:
                            break

                    elapsed = max(0.05, time.perf_counter() - t_start)
                    http_mbps = (total_bytes * 8.0) / (elapsed * 1_000_000.0)
                    # Also check peak live NIC speed during the test window
                    nic_peak = max(list(self.live_history) + [http_mbps])
                    return max(http_mbps, nic_peak)
            except Exception:
                continue
        return 0.0

    def _benchmark_worker(self):
        try:
            # Step 1: Measure BEFORE Speedtest Ping
            self.root.after(
                0,
                lambda: self.bench_status_lbl.configure(
                    text="Step 1/3: Measuring real download speed BEFORE Speedtest.net ping...", fg="#fbbf24"
                ),
            )
            self.log("Benchmark started: Measuring real download speed BEFORE Speedtest ping...")
            before_mbps = self._measure_real_download_speed(duration_sec=3.5)
            self.bench_before_mbps = before_mbps

            self.root.after(
                0,
                lambda: self.bench_before_val.configure(text=f"{before_mbps:.2f} Mbps", fg="#f8fafc"),
            )
            self.log(f"Result BEFORE Speedtest Ping: {before_mbps:.2f} Mbps ({before_mbps / 8:.2f} MB/s)")

            # Step 2: Ping Speedtest.net (ICMP + HTTPS SNI burst)
            self.root.after(
                0,
                lambda: self.bench_status_lbl.configure(
                    text="Step 2/3: Sending ICMP + HTTPS SNI packets to Speedtest.net...", fg="#38bdf8"
                ),
            )
            lat = self._execute_speedtest_ping()
            self.ping_count += 1
            lat_text = f"{lat} ms" if lat is not None else "OK"
            self.log(f"Triggered Speedtest.net ping + HTTPS handshake ({lat_text}).")
            time.sleep(0.5)

            # Step 3: Measure AFTER Speedtest Ping
            self.root.after(
                0,
                lambda: self.bench_status_lbl.configure(
                    text="Step 3/3: Measuring real download speed AFTER Speedtest.net ping...", fg="#34d399"
                ),
            )
            after_mbps = self._measure_real_download_speed(duration_sec=3.5)
            self.bench_after_mbps = after_mbps

            delta_text, delta_color = self._format_delta(before_mbps, after_mbps)
            self.log(
                f"Result AFTER Speedtest Ping: {after_mbps:.2f} Mbps ({after_mbps / 8:.2f} MB/s) -> {delta_text}"
            )

            def _finish_ui():
                self.bench_after_val.configure(text=f"{after_mbps:.2f} Mbps", fg="#f8fafc")
                self.bench_delta_val.configure(text=delta_text, fg=delta_color)
                self.bench_status_lbl.configure(
                    text="Benchmark complete! Compare 'Before' and 'After' values below.", fg="#4ade80"
                )
                self._update_ping_stats_label(latency_str=lat_text)

            self.root.after(0, _finish_ui)
        finally:
            self.benchmark_in_progress = False
            self.root.after(
                0,
                lambda: self.bench_btn.configure(state="normal", text="🚀 Run Before/After Speed Test"),
            )


if __name__ == "__main__":
    root = tk.Tk()
    app = SpeedtestPingerApp(root)
    root.mainloop()
